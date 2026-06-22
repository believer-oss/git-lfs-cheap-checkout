use std::path::Path;

use crate::{
    hash::compute_sha256, pointer::Oid, recover::recover_object, usn::read_usn, Options,
    EXIT_INTEGRITY_FAILURE, EXIT_RECOVERY_FAILED,
};

// Snapshot of everything we can cheaply log about an object on mismatch.
struct ObjectState {
    size: Option<u64>,
    modified: Option<std::time::SystemTime>,
    readonly: Option<bool>,
    usn: Option<i64>,
}

async fn snapshot_state(path: &Path) -> ObjectState {
    let meta = tokio::fs::metadata(path).await.ok();
    let usn = if cfg!(windows) {
        read_usn(path).await.ok()
    } else {
        None
    };
    ObjectState {
        size: meta.as_ref().map(|m| m.len()),
        modified: meta.as_ref().and_then(|m| m.modified().ok()),
        readonly: meta.as_ref().map(|m| m.permissions().readonly()),
        usn,
    }
}

fn log_object_state(label: &str, path: &Path, state: &ObjectState) {
    eprintln!("  {} path: {}", label, path.display());
    if let Some(s) = state.size {
        eprintln!("  {} size: {}", label, s);
    }
    if let Some(m) = state.modified {
        eprintln!("  {} modified: {:?}", label, m);
    }
    if let Some(ro) = state.readonly {
        eprintln!("  {} read-only: {}", label, ro);
    }
    if let Some(usn) = state.usn {
        eprintln!("  {} usn: {}", label, usn);
    }
}

// Individual check operations. Each returns Ok(()) on pass and an Err string
// describing the failure for the central reporter to log.

async fn check_size(cache_path: &Path, expected: u64) -> Result<(), String> {
    let meta = tokio::fs::metadata(cache_path)
        .await
        .map_err(|e| format!("size check: failed to stat {}: {}", cache_path.display(), e))?;
    if meta.len() != expected {
        return Err(format!(
            "size mismatch (expected {}, got {})",
            expected,
            meta.len()
        ));
    }
    Ok(())
}

async fn check_hash(cache_path: &Path, oid: &Oid) -> Result<(), String> {
    let hex = compute_sha256(cache_path)
        .await
        .map_err(|e| format!("hash check: failed to read {}: {}", cache_path.display(), e))?;
    if hex != oid.0 {
        return Err(format!(
            "hash mismatch (expected sha256:{}, got sha256:{})",
            oid.0, hex
        ));
    }
    Ok(())
}

// USN check with built-in hash fallback. The USN journal records every change
// to a file, so a USN bump alone is just "something touched this" — not
// necessarily content modification. On drift we hash the object to decide.
enum UsnResult {
    Ok(i64),
    DriftHashOk(i64, String),
    Failure(String),
}

async fn usn_with_hash_fallback(
    cache_path: &Path,
    oid: &Oid,
    expected: Option<i64>,
) -> UsnResult {
    let usn = match read_usn(cache_path).await {
        Ok(u) => u,
        Err(e) => {
            return UsnResult::Failure(format!(
                "usn check: failed to read usn of {}: {}",
                cache_path.display(),
                e
            ));
        }
    };
    let exp = match expected {
        Some(e) => e,
        None => return UsnResult::Ok(usn),
    };
    if usn == exp {
        return UsnResult::Ok(usn);
    }
    let reason = format!("USN drift (expected {}, got {})", exp, usn);
    match check_hash(cache_path, oid).await {
        Ok(()) => UsnResult::DriftHashOk(usn, reason),
        Err(hash_reason) => UsnResult::Failure(format!("{}; {}", reason, hash_reason)),
    }
}

// Outcome of verifying a cache object: Continue with the current USN (if
// known) for manifest updates, or exit with the given code.
pub(crate) enum VerifyOutcome {
    Continue(Option<i64>),
    Fatal(i32),
}

// Single failure exit: log full context (path, size, mtime, ro, usn,
// expected oid, computed hash), then either recover or return Fatal. Recovery
// requires a pointer size (only present in smudge mode); audit mode always
// returns Fatal and relies on the pipeline to repopulate.
async fn report_failure(
    reason: &str,
    working_path: Option<&str>,
    cache_path: &Path,
    oid: &Oid,
    pointer_size: Option<u64>,
    opts: Options,
) -> VerifyOutcome {
    eprintln!("{}", reason);
    if let Some(p) = working_path {
        eprintln!("  working path: {}", p);
    }
    let state = snapshot_state(cache_path).await;
    log_object_state("cache", cache_path, &state);
    eprintln!("  expected oid: sha256:{}", oid.0);
    match compute_sha256(cache_path).await {
        Ok(h) => eprintln!("  computed hash: sha256:{}", h),
        Err(e) => eprintln!("  computed hash: <failed: {}>", e),
    }

    if let (true, Some(size)) = (opts.recover, pointer_size) {
        eprintln!("attempting recovery via `git lfs smudge` for sha256:{}", oid.0);
        match recover_object(cache_path, oid, size).await {
            Ok(()) => {
                eprintln!("recovery succeeded");
                // Caller will re-read USN after any final modifications.
                return VerifyOutcome::Continue(None);
            }
            Err(e) => {
                eprintln!("recovery failed: {}", e);
                return VerifyOutcome::Fatal(EXIT_RECOVERY_FAILED);
            }
        }
    }

    VerifyOutcome::Fatal(EXIT_INTEGRITY_FAILURE)
}

// Apply configured verification checks. Control flow is a flat sequence of
// "run check; on failure delegate to report_failure" with one exception: USN
// drift falls back to a hash check, since a USN bump alone doesn't imply
// content modification.
pub(crate) async fn verify_object(
    working_path: Option<&str>,
    cache_path: &Path,
    pointer_size: Option<u64>,
    oid: &Oid,
    expected: Option<i64>,
    opts: Options,
) -> VerifyOutcome {
    if opts.verify_size {
        if let Some(size) = pointer_size {
            if let Err(reason) = check_size(cache_path, size).await {
                return report_failure(&reason, working_path, cache_path, oid, pointer_size, opts)
                    .await;
            }
        }
    }

    let mut current_usn = None;
    let mut hash_already_verified = false;

    if opts.verify_usn {
        match usn_with_hash_fallback(cache_path, oid, expected).await {
            UsnResult::Ok(usn) => current_usn = Some(usn),
            UsnResult::DriftHashOk(usn, reason) => {
                eprintln!("{}", reason);
                eprintln!("  content hash matches oid; refreshing manifest baseline");
                current_usn = Some(usn);
                hash_already_verified = true;
            }
            UsnResult::Failure(reason) => {
                return report_failure(&reason, working_path, cache_path, oid, pointer_size, opts)
                    .await;
            }
        }
    }

    if opts.verify_hash && !hash_already_verified {
        if let Err(reason) = check_hash(cache_path, oid).await {
            return report_failure(&reason, working_path, cache_path, oid, pointer_size, opts)
                .await;
        }
    }

    VerifyOutcome::Continue(current_usn)
}
