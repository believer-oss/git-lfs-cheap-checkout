use std::{collections::HashMap, path::PathBuf, process::exit, sync::Arc};

use clap::{arg, value_parser, Command};

use crate::{
    manifest::{load_manifest, write_manifest},
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

#[tokio::main]
async fn main() {
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

    if opts.verify_usn && !cfg!(windows) {
        eprintln!("--verify_usn is only supported on Windows/NTFS");
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

    // Dispatch: audit walks the cache, otherwise we smudge each tracked file
    let mut handles = tokio::task::JoinSet::new();
    if opts.verify_cache {
        let objects = enumerate_cache_objects(&object_dir)
            .await
            .expect("failed to enumerate cache directory");
        for (cache_path, oid) in objects {
            let expected = expected.clone();
            handles.spawn(async move { audit_object(cache_path, oid, expected, opts).await });
        }
    } else {
        // Get list of files from ls-files
        let files = std::process::Command::new("git-lfs")
            .arg("ls-files")
            .arg("--name-only")
            .output()
            .expect("failed to execute git-lfs ls-files");
        // Loop through the files and smudge them if necessary
        for file in files.stdout.split(|&c| c == b'\n') {
            if file.is_empty() {
                continue;
            }
            let local_object_dir = object_dir.clone();
            let local_file = std::str::from_utf8(file)
                .expect("could not convert to utf8 from pointer")
                .to_string();
            let expected = expected.clone();
            handles.spawn(async move {
                smudge_file(local_file, local_object_dir, expected, opts).await
            });
        }
    }

    // Collect updated USN observations and rewrite the manifest
    let mut new_manifest: HashMap<String, i64> = (*expected).clone();
    while let Some(result) = handles.join_next().await {
        if let Some((oid, usn)) = result.expect("worker task panicked") {
            new_manifest.insert(oid, usn);
        }
    }

    if opts.verify_usn && !opts.dry_run {
        write_manifest(&manifest_path, &new_manifest).await;
    }
}
