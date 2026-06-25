use std::{
    collections::HashMap,
    path::PathBuf,
    process::exit,
    sync::{atomic::Ordering, Arc},
};

use tracing::{debug, warn};

use crate::{
    pointer::{check_pointer, path_from_oid, Oid, PointerCheck},
    usn::{read_usn, same_file_id},
    verify::{verify_object, VerifyOutcome},
    Counters, Options,
};

// Smudge-mode worker. Verifies the cache object for one tracked LFS file
// (`local_file` from `git lfs ls-files`, `oid_from_index` from the same call's
// `-l` output) and, when needed, links the worktree file at the cache object.
// Returns Some((oid, new_usn)) if verify_usn ran and the manifest should be
// updated; None otherwise.
pub(crate) async fn smudge_file(
    local_file: String,
    oid_from_index: Oid,
    local_object_dir: PathBuf,
    expected: Arc<HashMap<String, i64>>,
    counters: Arc<Counters>,
    opts: Options,
) -> Option<(String, i64)> {
    counters.processed.fetch_add(1, Ordering::Relaxed);

    // Missing in the worktree -- can happen if `git lfs ls-files` lists a path
    // that wasn't checked out (sparse / partial checkout). Log and skip so one
    // missing path can't panic the runtime via JoinError and abort the scan.
    let meta = match tokio::fs::metadata(&local_file).await {
        Ok(m) => m,
        Err(e) => {
            warn!(file = %local_file, error = %e, "skipping (worktree metadata failed)");
            return None;
        }
    };

    let obj = path_from_oid(local_object_dir, &oid_from_index);

    // Compute hardlink state up front and reuse it for both the verify-path
    // dispatch and the relink decision below. `same_file_id` failure (cache
    // path missing on first run, etc.) is treated as "not linked" so the size
    // branch handles those cases normally.
    let already_linked = same_file_id(local_file.as_ref(), &obj)
        .await
        .unwrap_or(false);

    // Three worktree shapes feed the same verify path:
    //  - already-hardlinked to the cache object (any size): trust ls-files
    //    OID, use the on-disk size. This branch is what saves a small smudged
    //    LFS file from being misclassified by `check_pointer` as NotPointer
    //    on the binary content of an already-linked cache object.
    //  - pointer-shaped, not yet linked (<=1024 bytes): parse the pointer for
    //    its size field.
    //  - already-smudged, not yet linked (>1024 bytes): trust the ls-files
    //    OID and use the on-disk size as the verification target. This covers
    //    the case where someone (or `git lfs checkout`) materialized the
    //    content before cheap-checkout ran.
    let pointer_size = if already_linked {
        Some(meta.len())
    } else if meta.len() <= 1024 {
        let bytes = match tokio::fs::read(&local_file).await {
            Ok(b) => b,
            Err(e) => {
                warn!(file = %local_file, error = %e, "skipping (worktree read failed)");
                return None;
            }
        };
        match check_pointer(&bytes) {
            PointerCheck::NotPointer => return None,
            PointerCheck::Malformed(e) => {
                warn!(file = %local_file, error = %e, "skipping (malformed pointer)");
                return None;
            }
            PointerCheck::Valid(p) => {
                // Defensive: ls-files (git tree) is the source of truth, but a
                // worktree pointer that disagrees is anomalous enough to log.
                if p.oid != oid_from_index {
                    warn!(
                        file = %local_file,
                        pointer_oid = %p.oid.0,
                        index_oid = %oid_from_index.0,
                        "worktree pointer OID disagrees with ls-files; using ls-files OID",
                    );
                }
                Some(p.size)
            }
        }
    } else {
        Some(meta.len())
    };

    debug!(file = %local_file, oid = %oid_from_index.0, size = ?pointer_size, "smudge_file");

    let outcome = verify_object(
        Some(&local_file),
        &obj,
        pointer_size,
        &oid_from_index,
        expected.get(&oid_from_index.0).copied(),
        opts,
    )
    .await;
    let recovered = match outcome {
        VerifyOutcome::Recovered => {
            counters.recovered.fetch_add(1, Ordering::Relaxed);
            true
        }
        VerifyOutcome::Continue(_) => false,
        VerifyOutcome::Fatal(code) => {
            counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
            exit(code);
        }
    };

    // Relink policy:
    //   - recovered: cache file was deleted+recreated by recover_object, so the
    //     prior worktree hardlink (if any) now points at an orphaned MFT entry
    //     holding the pre-recovery (damaged) bytes. Must relink.
    //   - !already_linked: worktree path doesn't share the cache object's MFT
    //     entry yet (pointer-shaped or smudged-but-not-linked). Link it.
    //   - otherwise: already-linked. Skip the redundant remove+hard_link.
    let need_relink = !opts.dry_run && (recovered || !already_linked);
    if need_relink {
        tokio::fs::remove_file(&local_file)
            .await
            .expect("failed to remove file");
        tokio::fs::hard_link(&obj, &local_file)
            .await
            .expect("failed to hard link");
        counters.relinked.fetch_add(1, Ordering::Relaxed);
    } else if !opts.dry_run {
        counters
            .skipped_already_linked
            .fetch_add(1, Ordering::Relaxed);
    }

    if opts.read_only && !opts.dry_run {
        let mut perms = tokio::fs::metadata(&obj)
            .await
            .expect("failed to get metadata for readonly set")
            .permissions();
        perms.set_readonly(true);
        tokio::fs::set_permissions(&obj, perms)
            .await
            .expect("failed to set readonly");
    }

    if opts.verify_usn && !opts.dry_run {
        match read_usn(&obj).await {
            Ok(usn) => Some((oid_from_index.0, usn)),
            Err(e) => {
                counters.usn_read_failed.fetch_add(1, Ordering::Relaxed);
                warn!(file = %local_file, obj = %obj.display(), error = %e, "USN read failed");
                None
            }
        }
    } else {
        None
    }
}

// Audit-mode worker for a single cache object. The OID comes from the
// filename. Audit never recovers — we don't have the original pointer size
// here, and recovery is the pipeline's job at this altitude.
pub(crate) async fn audit_object(
    cache_path: PathBuf,
    oid: Oid,
    expected: Arc<HashMap<String, i64>>,
    counters: Arc<Counters>,
    opts: Options,
) -> Option<(String, i64)> {
    counters.processed.fetch_add(1, Ordering::Relaxed);
    debug!(cache_path = %cache_path.display(), oid = %oid.0, "audit_object");
    match verify_object(
        None,
        &cache_path,
        None,
        &oid,
        expected.get(&oid.0).copied(),
        opts,
    )
    .await
    {
        VerifyOutcome::Continue(usn) => {
            if opts.verify_usn {
                let usn = match usn {
                    Some(u) => u,
                    None => match read_usn(&cache_path).await {
                        Ok(u) => u,
                        Err(e) => {
                            counters.usn_read_failed.fetch_add(1, Ordering::Relaxed);
                            warn!(obj = %cache_path.display(), error = %e, "USN read failed (audit)");
                            return None;
                        }
                    },
                };
                Some((oid.0, usn))
            } else {
                None
            }
        }
        // Audit mode passes pointer_size = None into verify_object, which
        // gates the recovery branch in report_failure. Recovery is the
        // pipeline's job at this altitude.
        VerifyOutcome::Recovered => unreachable!("audit mode never recovers"),
        VerifyOutcome::Fatal(code) => {
            counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
            exit(code);
        }
    }
}

// Walk the cache `<aa>/<bb>/<oid>` tree and return the leaf paths.
pub(crate) async fn enumerate_cache_objects(
    object_dir: &std::path::Path,
) -> std::io::Result<Vec<(PathBuf, Oid)>> {
    fn is_hex2(s: &str) -> bool {
        s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
    let mut out = Vec::new();
    let mut top = tokio::fs::read_dir(object_dir).await?;
    while let Some(entry) = top.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !is_hex2(&name_str) {
            continue;
        }
        let mut mid = tokio::fs::read_dir(entry.path()).await?;
        while let Some(sub) = mid.next_entry().await? {
            let sub_name = sub.file_name();
            let sub_str = sub_name.to_string_lossy();
            if !is_hex2(&sub_str) {
                continue;
            }
            let mut leaves = tokio::fs::read_dir(sub.path()).await?;
            while let Some(leaf) = leaves.next_entry().await? {
                let leaf_name = leaf.file_name();
                let leaf_str = leaf_name.to_string_lossy();
                if leaf_str.len() == 64 && leaf_str.chars().all(|c| c.is_ascii_hexdigit()) {
                    out.push((leaf.path(), Oid(leaf_str.into_owned())));
                }
            }
        }
    }
    Ok(out)
}
