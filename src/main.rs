use std::{
    collections::HashMap,
    path::PathBuf,
    process::exit,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use clap::{arg, value_parser, Command};
use tracing::{error, info, warn};

use crate::{
    manifest::{load_manifest, write_manifest},
    pointer::Oid,
    worker::{audit_object, enumerate_cache_objects, smudge_file},
};

mod hash;
mod manifest;
mod pointer;
mod recover;
mod usn;
mod verify;
mod worker;

// Exit codes used to signal failures to callers (CI pipelines, etc.).
// 0/1 keep the standard meanings (success / generic / panic).
pub(crate) const EXIT_INTEGRITY_FAILURE: i32 = 10;
pub(crate) const EXIT_RECOVERY_FAILED: i32 = 11;

#[derive(Clone, Copy)]
pub(crate) struct Options {
    pub(crate) verbose: bool,
    pub(crate) dry_run: bool,
    pub(crate) verify_size: bool,
    pub(crate) verify_hash: bool,
    pub(crate) verify_usn: bool,
    pub(crate) read_only: bool,
    pub(crate) verify_cache: bool,
    pub(crate) recover: bool,
}

// Per-run worker outcome tallies. Workers fetch_add their bucket; main reads
// after the JoinSet drains and emits a structured summary event.
#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) processed: AtomicU64,
    pub(crate) relinked: AtomicU64,
    pub(crate) skipped_already_linked: AtomicU64,
    pub(crate) recovered: AtomicU64,
    pub(crate) usn_read_failed: AtomicU64,
    pub(crate) integrity_failures: AtomicU64,
}

fn cli() -> Command {
    Command::new("git-lfs-cheap-checkout")
        .about("Smudge git-lfs files with hard links")
        .arg(arg!(-v --verbose "Show verbose output"))
        .arg(arg!(-d --dry_run "Dry run"))
        .arg(arg!(-s --verify_size "Verify the size of cached objects matches the pointer"))
        .arg(arg!(-r --read_only "Set the read-only attribute on cached objects after linking"))
        .arg(arg!(-u --verify_usn "Detect cached-object tampering via the NTFS USN journal (Windows only)"))
        .arg(arg!(-c --verify_hash "Re-hash cached objects (SHA-256) and verify against the pointer OID"))
        .arg(arg!(-a --verify_cache "Audit every object in the LFS cache directory; implies --verify_hash if no check is set"))
        .arg(arg!(-R --recover "On smudge-mode integrity failure, repopulate the cache via `git lfs smudge` (audit mode never recovers)"))
        .arg(
            arg!(-w --workdir <WORKDIR> "Git checkout to use")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
}

// Parse one line of `git lfs ls-files -l` output: "<64-hex-oid> <* or -> <path>".
// `*` means the object is present in the local LFS cache and `-` that it isn't;
// the flag is unused here (we verify the cache object directly), but we still
// consume it so the path doesn't accidentally absorb it. Returns None for empty,
// non-UTF-8, or malformed lines — caller logs and skips.
fn parse_ls_files_line(bytes: &[u8]) -> Option<(Oid, String)> {
    let line = std::str::from_utf8(bytes).ok()?;
    let mut parts = line.splitn(3, ' ');
    let oid_str = parts.next()?;
    let _flag = parts.next()?;
    let path = parts.next()?;
    if oid_str.len() != 64 || !oid_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if path.is_empty() {
        return None;
    }
    Some((Oid(oid_str.to_string()), path.to_string()))
}

// Subscriber routes to JSON when stderr isn't a TTY (argo pipelines, captured
// logs); pretty otherwise (interactive runs). `-v` sets the default level to
// debug; RUST_LOG overrides for scoped debugging
// (e.g. `RUST_LOG=git_lfs_cheap_checkout::worker=debug`).
fn init_tracing(verbose: bool) {
    use std::io::IsTerminal;
    use tracing_subscriber::{fmt, EnvFilter};

    let default_level = if verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    let base = fmt().with_env_filter(filter).with_target(false);
    if std::io::stderr().is_terminal() {
        base.init();
    } else {
        base.json().flatten_event(true).init();
    }
}

#[tokio::main]
async fn main() {
    let total_start = Instant::now();
    let matches = cli().get_matches();
    let mut opts = Options {
        verbose: matches.get_flag("verbose"),
        dry_run: matches.get_flag("dry_run"),
        verify_size: matches.get_flag("verify_size"),
        verify_hash: matches.get_flag("verify_hash"),
        verify_usn: matches.get_flag("verify_usn"),
        read_only: matches.get_flag("read_only"),
        verify_cache: matches.get_flag("verify_cache"),
        recover: matches.get_flag("recover"),
    };

    if opts.verify_cache && !opts.verify_hash && !opts.verify_usn {
        // Audit with no checks set defaults to hash — it's the only check
        // that's self-contained (doesn't need a pre-existing manifest).
        opts.verify_hash = true;
    }

    init_tracing(opts.verbose);

    if opts.verify_usn && !cfg!(windows) {
        error!("--verify_usn is only supported on Windows/NTFS");
        exit(1);
    }

    // Move to a git repo, if we're called outside of it with an arg
    if let Some(workdir) = matches.get_one::<PathBuf>("workdir") {
        std::env::set_current_dir(workdir).expect("failed to set workdir");
    }

    // Get the LFS storage directory and repo root from git-lfs env
    let env = std::process::Command::new("git-lfs")
        .arg("env")
        .output()
        .expect("failed to execute git-lfs env");

    // This is the LFS storage dir, which contains the LFS objects named by their hash/OID.
    // ex. <object_dir>/ff/01/ff01f714b73af49cfa2a5837e08f36559a8b1af37928351f7e750204d632bfc0
    let mut object_dir = PathBuf::new();
    for line in env.stdout.split(|&c| c == b'\n') {
        let line = std::str::from_utf8(line).expect("could not convert to utf8 from env");
        // Workdir is the root of the git repo
        if line.starts_with("LocalWorkingDir") {
            let workdir = line
                .split("=")
                .nth(1)
                .expect("could not extract value from env");
            std::env::set_current_dir(workdir).expect("failed to set workdir");
        }
        // Mediadir is the LFS storage dir
        if line.starts_with("LocalMediaDir") {
            object_dir.push(line.split("=").nth(1).expect("failed to get object dir"));
        }
    }

    // Load the prior USN manifest if we're going to verify against it
    let manifest_path = object_dir.join(".cheap-checkout-manifest");
    let expected = Arc::new(if opts.verify_usn {
        load_manifest(&manifest_path).await
    } else {
        HashMap::new()
    });

    info!(
        mode = if opts.verify_cache { "audit" } else { "smudge" },
        object_dir = %object_dir.display(),
        manifest_entries = expected.len(),
        verify_size = opts.verify_size,
        verify_hash = opts.verify_hash,
        verify_usn = opts.verify_usn,
        recover = opts.recover,
        read_only = opts.read_only,
        dry_run = opts.dry_run,
        "starting",
    );

    let counters: Arc<Counters> = Arc::new(Counters::default());
    let work_start = Instant::now();

    // Dispatch: audit walks the cache, otherwise we smudge each tracked file
    let mut handles = tokio::task::JoinSet::new();
    if opts.verify_cache {
        let enum_start = Instant::now();
        let objects = enumerate_cache_objects(&object_dir)
            .await
            .expect("failed to enumerate cache directory");
        info!(
            count = objects.len(),
            duration_ms = enum_start.elapsed().as_millis() as u64,
            "enumerated cache objects",
        );
        for (cache_path, oid) in objects {
            let expected = expected.clone();
            let counters = counters.clone();
            handles.spawn(
                async move { audit_object(cache_path, oid, expected, counters, opts).await },
            );
        }
    } else {
        // `ls-files -l` gives us "<64-hex-oid> <* or -> <path>" per tracked LFS
        // file. We need the OID up front so already-smudged files (worktree
        // file > pointer-size) still get their cache object verified — the
        // pointer is no longer in the worktree to parse.
        let ls_start = Instant::now();
        let files = std::process::Command::new("git-lfs")
            .arg("ls-files")
            .arg("-l")
            .output()
            .expect("failed to execute git-lfs ls-files");
        let mut spawned = 0u64;
        for line in files.stdout.split(|&c| c == b'\n') {
            if line.is_empty() {
                continue;
            }
            let (oid_from_index, local_file) = match parse_ls_files_line(line) {
                Some(parsed) => parsed,
                None => {
                    warn!(line = %String::from_utf8_lossy(line), "skipping unparseable ls-files line");
                    continue;
                }
            };
            let local_object_dir = object_dir.clone();
            let expected = expected.clone();
            let counters = counters.clone();
            handles.spawn(async move {
                smudge_file(
                    local_file,
                    oid_from_index,
                    local_object_dir,
                    expected,
                    counters,
                    opts,
                )
                .await
            });
            spawned += 1;
        }
        info!(
            count = spawned,
            duration_ms = ls_start.elapsed().as_millis() as u64,
            "ls-files complete",
        );
    }

    // Collect updated USN observations and rewrite the manifest
    let mut new_manifest: HashMap<String, i64> = (*expected).clone();
    while let Some(result) = handles.join_next().await {
        if let Some((oid, usn)) = result.expect("worker task panicked") {
            new_manifest.insert(oid, usn);
        }
    }

    info!(
        processed = counters.processed.load(Ordering::Relaxed),
        relinked = counters.relinked.load(Ordering::Relaxed),
        skipped_already_linked = counters.skipped_already_linked.load(Ordering::Relaxed),
        recovered = counters.recovered.load(Ordering::Relaxed),
        usn_read_failed = counters.usn_read_failed.load(Ordering::Relaxed),
        integrity_failures = counters.integrity_failures.load(Ordering::Relaxed),
        duration_ms = work_start.elapsed().as_millis() as u64,
        "workers complete",
    );

    if opts.verify_usn && !opts.dry_run {
        let manifest_start = Instant::now();
        write_manifest(&manifest_path, &new_manifest).await;
        info!(
            entries = new_manifest.len(),
            duration_ms = manifest_start.elapsed().as_millis() as u64,
            "manifest written",
        );
    }

    info!(
        total_duration_ms = total_start.elapsed().as_millis() as u64,
        "done",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID: &str = "0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc";

    #[test]
    fn parse_ls_files_line_object_present() {
        let line = format!("{} * Content/Foo.uasset", OID);
        let (oid, path) = parse_ls_files_line(line.as_bytes()).unwrap();
        assert_eq!(oid.0, OID);
        assert_eq!(path, "Content/Foo.uasset");
    }

    #[test]
    fn parse_ls_files_line_object_missing() {
        // git-lfs uses '-' when the object isn't in the local cache.
        let line = format!("{} - Content/Foo.uasset", OID);
        let (oid, path) = parse_ls_files_line(line.as_bytes()).unwrap();
        assert_eq!(oid.0, OID);
        assert_eq!(path, "Content/Foo.uasset");
    }

    #[test]
    fn parse_ls_files_line_path_with_spaces() {
        // splitn(3, ' ') keeps everything after the flag in the path field,
        // so paths containing spaces survive parsing.
        let line = format!("{} * Content/Some Folder/With Spaces.uasset", OID);
        let (_, path) = parse_ls_files_line(line.as_bytes()).unwrap();
        assert_eq!(path, "Content/Some Folder/With Spaces.uasset");
    }

    #[test]
    fn parse_ls_files_line_rejects_short_oid() {
        let line = "0926abcd * Content/Foo.uasset";
        assert!(parse_ls_files_line(line.as_bytes()).is_none());
    }

    #[test]
    fn parse_ls_files_line_rejects_non_hex_oid() {
        // 64 chars but contains 'Z'.
        let bad = "Z926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc";
        let line = format!("{} * Content/Foo.uasset", bad);
        assert!(parse_ls_files_line(line.as_bytes()).is_none());
    }

    #[test]
    fn parse_ls_files_line_rejects_missing_path() {
        let line = format!("{} *", OID);
        assert!(parse_ls_files_line(line.as_bytes()).is_none());
    }

    #[test]
    fn parse_ls_files_line_rejects_missing_flag() {
        let line = OID.to_string();
        assert!(parse_ls_files_line(line.as_bytes()).is_none());
    }

    #[test]
    fn parse_ls_files_line_rejects_empty() {
        assert!(parse_ls_files_line(b"").is_none());
    }

    #[test]
    fn parse_ls_files_line_rejects_non_utf8() {
        // 0xFF / 0xFE are not valid UTF-8 start bytes.
        let bytes = b"\xff\xfe garbage line";
        assert!(parse_ls_files_line(bytes).is_none());
    }

    #[test]
    fn parse_ls_files_line_rejects_empty_path_field() {
        // splitn could give us a trailing space then empty string.
        let line = format!("{} * ", OID);
        assert!(parse_ls_files_line(line.as_bytes()).is_none());
    }
}
