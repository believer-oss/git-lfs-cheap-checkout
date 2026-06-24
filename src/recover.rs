use std::path::Path;

use tokio::io::AsyncWriteExt;

use crate::{
    hash::compute_sha256,
    pointer::{Oid, LFS_POINTER_VERSION_LINE},
};

// Re-fetch a single corrupt LFS object via `git lfs smudge`. We construct a
// pointer from the OID and size already known to the caller, pipe it to
// smudge's stdin, capture the smudged content from stdout, and write it
// into the cache ourselves. Reuses git-lfs's transfer/credential plumbing
// without depending on the current ref or any path-to-OID mapping.
pub(crate) async fn recover_object(cache_path: &Path, oid: &Oid, size: u64) -> Result<(), String> {
    if cache_path.exists() {
        // Required on Windows so remove_file isn't blocked by
        // FILE_ATTRIBUTE_READONLY. Unix deletes by directory write
        // permission, so the dance is unnecessary there.
        #[cfg(windows)]
        if let Ok(meta) = tokio::fs::metadata(cache_path).await {
            if meta.permissions().readonly() {
                let mut perms = meta.permissions();
                perms.set_readonly(false);
                tokio::fs::set_permissions(cache_path, perms)
                    .await
                    .map_err(|e| format!("failed to clear read-only on cache: {}", e))?;
            }
        }
        tokio::fs::remove_file(cache_path)
            .await
            .map_err(|e| format!("failed to remove corrupt cache object: {}", e))?;
    }

    let pointer = format!(
        "{}\noid sha256:{}\nsize {}\n",
        LFS_POINTER_VERSION_LINE, oid.0, size
    );

    let mut child = tokio::process::Command::new("git-lfs")
        .arg("smudge")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn git-lfs smudge: {}", e))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .expect("git-lfs smudge stdin was configured as piped");
        stdin
            .write_all(pointer.as_bytes())
            .await
            .map_err(|e| format!("failed to write pointer to git-lfs smudge: {}", e))?;
        // Drop closes stdin and signals EOF to smudge.
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("failed to wait for git-lfs smudge: {}", e))?;
    if !output.status.success() {
        return Err(format!(
            "git-lfs smudge failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    // Cheap length sanity-check before paying the SHA-256 cost.
    if (output.stdout.len() as u64) != size {
        return Err(format!(
            "smudge produced wrong size (expected {}, got {})",
            size,
            output.stdout.len()
        ));
    }
    tokio::fs::write(cache_path, &output.stdout)
        .await
        .map_err(|e| format!("failed to write recovered cache object: {}", e))?;

    let hex = compute_sha256(cache_path)
        .await
        .map_err(|e| format!("re-hash after smudge failed: {}", e))?;
    if hex != oid.0 {
        return Err(format!(
            "re-fetched object still mismatches oid (expected sha256:{}, got sha256:{})",
            oid.0, hex
        ));
    }
    Ok(())
}
