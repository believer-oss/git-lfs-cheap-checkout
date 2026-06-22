use std::{collections::HashMap, path::Path};

// Manifest format: `<oid> <usn>` per line, sorted by OID. Stored in the LFS
// object dir alongside the `aa/bb/<oid>` tree — safe because git-lfs only
// walks two-character hex subdirectories.
pub(crate) async fn load_manifest(path: &Path) -> HashMap<String, i64> {
    let contents = match tokio::fs::read_to_string(path).await {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };
    parse_manifest(&contents)
}

pub(crate) fn parse_manifest(contents: &str) -> HashMap<String, i64> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let oid = match parts.next() {
            Some(o) => o,
            None => continue,
        };
        let usn: i64 = match parts.next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        map.insert(oid.to_string(), usn);
    }
    map
}

pub(crate) fn format_manifest(manifest: &HashMap<String, i64>) -> String {
    let mut entries: Vec<_> = manifest.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = String::with_capacity(entries.len() * 80);
    for (oid, usn) in entries {
        out.push_str(oid);
        out.push(' ');
        out.push_str(&usn.to_string());
        out.push('\n');
    }
    out
}

pub(crate) async fn write_manifest(path: &Path, manifest: &HashMap<String, i64>) {
    tokio::fs::write(path, format_manifest(manifest))
        .await
        .expect("failed to write manifest");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let mut m = HashMap::new();
        m.insert("aa".repeat(32), 12345i64);
        m.insert("bb".repeat(32), -1i64);
        let serialized = format_manifest(&m);
        // Output should be sorted, so "aa..." precedes "bb...".
        assert!(serialized.starts_with(&"aa".repeat(32)));
        let parsed = parse_manifest(&serialized);
        assert_eq!(parsed, m);
    }

    #[test]
    fn manifest_skips_garbage_lines() {
        // Comments, blank lines, and entries with non-numeric USN are ignored;
        // trailing fields beyond `<oid> <usn>` are also tolerated.
        let input = "# header\n\
            \n\
            aa11 not-a-number\n\
            cc22 100\n\
            dd33 200 ignored-trailing-field\n";
        let parsed = parse_manifest(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["cc22"], 100);
        assert_eq!(parsed["dd33"], 200);
    }
}
