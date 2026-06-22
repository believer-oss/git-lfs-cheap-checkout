use std::{collections::HashMap, path::PathBuf, process::exit, sync::Arc};

use crate::{
    pointer::{parse_pointer, path_from_oid, Oid},
    usn::read_usn,
    verify::{verify_object, VerifyOutcome},
    Options,
};

// Smudge-mode worker. Returns Some((oid, new_usn)) if verify_usn ran and the
// manifest should be updated; None otherwise.
pub(crate) async fn smudge_file(
    local_file: String,
    local_object_dir: PathBuf,
    expected: Arc<HashMap<String, i64>>,
    opts: Options,
) -> Option<(String, i64)> {
    let meta = tokio::fs::metadata(&local_file)
        .await
        .expect("failed to get metadata for pointer file");
    // Pointer files must be < 1024. Larger means already smudged.
    if meta.len() > 1024 {
        return None;
    }

    let contents = tokio::fs::read_to_string(&local_file).await;
    let pointer = match contents {
        Ok(c) => parse_pointer(&c).expect("failed to parse pointer"),
        Err(e) => {
            eprintln!("{}: {}", local_file, e);
            return None;
        }
    };

    if opts.verbose {
        println!("{}: {:?}", &local_file, pointer);
    }

    let obj = path_from_oid(local_object_dir, &pointer.oid);

    match verify_object(
        Some(&local_file),
        &obj,
        Some(pointer.size),
        &pointer.oid,
        expected.get(&pointer.oid.0).copied(),
        opts,
    )
    .await
    {
        VerifyOutcome::Continue(_) => {}
        VerifyOutcome::Fatal(code) => exit(code),
    }

    if !opts.dry_run {
        tokio::fs::remove_file(&local_file)
            .await
            .expect("failed to remove file");
        tokio::fs::hard_link(&obj, &local_file)
            .await
            .expect("failed to hard link");
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
        let usn = read_usn(&obj).await.expect("failed to re-read USN");
        Some((pointer.oid.0, usn))
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
    opts: Options,
) -> Option<(String, i64)> {
    if opts.verbose {
        println!("auditing {}", cache_path.display());
    }
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
                    None => read_usn(&cache_path).await.ok()?,
                };
                Some((oid.0, usn))
            } else {
                None
            }
        }
        VerifyOutcome::Fatal(code) => exit(code),
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
