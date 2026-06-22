use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

// Stream the file through SHA-256 and return the lowercase hex digest.
pub(crate) async fn compute_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sha256_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        tokio::fs::write(&empty, b"").await.unwrap();
        assert_eq!(
            compute_sha256(&empty).await.unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = dir.path().join("abc");
        tokio::fs::write(&abc, b"abc").await.unwrap();
        assert_eq!(
            compute_sha256(&abc).await.unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
