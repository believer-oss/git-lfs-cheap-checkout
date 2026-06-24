use std::{fmt, path::PathBuf};

// The exact first line of an LFS v1 pointer file. Shared by the parser, the
// quick "is this a pointer?" check, and the smudge-recovery pointer builder
// so the version literal lives in one place.
pub(crate) const LFS_POINTER_VERSION_LINE: &str = "version https://git-lfs.github.com/spec/v1";

#[derive(Debug)]
pub(crate) struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParseError: {}", self.0)
    }
}

#[derive(Debug)]
pub(crate) struct GitLfsPointer {
    pub(crate) oid: Oid,
    pub(crate) size: u64,
}

// Three-way classification of a file's bytes against the LFS pointer spec.
// Callers use this instead of `parse_pointer` directly so that "this isn't
// a pointer" (a legitimate state for content under an `lfs` gitattribute --
// pre-LFS-conversion files, incidentally-matched non-LFS content, etc.) is
// distinguished from "this looks like a pointer but is corrupt" (a real
// data issue worth surfacing).
#[derive(Debug)]
pub(crate) enum PointerCheck {
    NotPointer,            // not LFS content -- caller should silent-skip
    Malformed(ParseError), // has the version header but oid/size broken
    Valid(GitLfsPointer),
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Oid(pub(crate) String);

// Convenience constructor for tests; assumes a well-formed `sha256:<hex>`
// input. Production parsing uses `strip_prefix` in `parse_pointer` instead so
// malformed inputs surface as ParseError rather than a panic.
impl From<&str> for Oid {
    fn from(s: &str) -> Self {
        let sha256 = s.split(':').nth(1).expect("could not find :").to_string();
        Oid(sha256)
    }
}

pub(crate) fn parse_pointer(contents: &str) -> Result<GitLfsPointer, ParseError> {
    let mut oid: Option<Oid> = None;
    let mut size = 0;
    let mut version_ok = false;

    for line in contents.lines() {
        if line == LFS_POINTER_VERSION_LINE {
            version_ok = true;
        } else if line.starts_with("oid") {
            let token = line
                .split_whitespace()
                .nth(1)
                .ok_or(ParseError("oid not found".to_string()))?;
            let sha = token
                .strip_prefix("sha256:")
                .ok_or(ParseError("oid missing sha256: prefix".to_string()))?;
            oid = Some(Oid(sha.to_string()));
        } else if line.starts_with("size") {
            size = line
                .split_whitespace()
                .nth(1)
                .ok_or(ParseError("size not found".to_string()))?
                .parse()
                .map_err(|_| ParseError("size not parsed".to_string()))?;
        }
    }

    if !version_ok {
        return Err(ParseError("version not found".to_string()));
    }
    if size == 0 {
        return Err(ParseError("size not found".to_string()));
    }
    match oid {
        None => Err(ParseError("oid not found".to_string())),
        Some(oid) => {
            if oid.0.len() != 64 {
                return Err(ParseError("oid not 64 characters".to_string()));
            }
            Ok(GitLfsPointer { oid, size })
        }
    }
}

// Entry point for "is this file an LFS pointer?". UTF-8 failure or a missing
// version header both classify as NotPointer (silent-skip in the caller);
// only a present-but-corrupt pointer surfaces as Malformed.
pub(crate) fn check_pointer(bytes: &[u8]) -> PointerCheck {
    let contents = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return PointerCheck::NotPointer,
    };
    if !contents.starts_with(LFS_POINTER_VERSION_LINE) {
        return PointerCheck::NotPointer;
    }
    match parse_pointer(contents) {
        Ok(p) => PointerCheck::Valid(p),
        Err(e) => PointerCheck::Malformed(e),
    }
}

// convert an object to it's path
// ex. ff/01/ff01f714b73af49cfa2a5837e08f36559a8b1af37928351f7e750204d632bfc0
pub(crate) fn path_from_oid(mut base_path: PathBuf, oid: &Oid) -> PathBuf {
    let oid_bytes = oid.0.as_bytes();
    base_path.push(std::str::from_utf8(&oid_bytes[0..2]).expect("missing first two bytes"));
    base_path.push(std::str::from_utf8(&oid_bytes[2..4]).expect("missing second two bytes"));
    base_path.push(std::str::from_utf8(oid_bytes).expect("failed to convert oid"));
    base_path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_correct() {
        let contents = "version https://git-lfs.github.com/spec/v1\n\
            oid sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size 12345\n\
        ";

        let i = parse_pointer(contents).unwrap();
        println!("{:?}", i);
        assert_eq!(
            i.oid,
            "sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc".into()
        );
        assert_eq!(i.size, 12345);
    }

    #[test]
    fn parse_incorrect() {
        let contents: Vec<&str> = vec![
            "version wrong\n\
            oid sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size 12345\n\
            ",
            "version https://git-lfs.github.com/spec/v1\n\
            oid sha256:0926726201de4dbfeb2\n\
            size 12345\n\
            ",
            "version https://git-lfs.github.com/spec/v1\n\
            oid sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size abc\n\
            ",
            // oid token without `sha256:` prefix — would have panicked
            // via `Oid::from`'s `.expect("could not find :")` before the fix.
            "version https://git-lfs.github.com/spec/v1\n\
            oid 0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size 12345\n\
            ",
        ];

        for content in contents {
            println!("{}", content);
            let i = parse_pointer(content);
            assert!(i.is_err());
        }
    }

    #[test]
    fn check_pointer_classifies_three_outcomes() {
        // NotPointer: non-UTF-8 bytes (e.g. a small binary file with an LFS-matching
        // extension that pre-dates LFS conversion).
        let non_utf8: &[u8] = &[0xFF, 0xFE, 0x00, 0x01, 0x02];
        assert!(matches!(check_pointer(non_utf8), PointerCheck::NotPointer));

        // NotPointer: UTF-8 but no version header. Could be JSON, plain text,
        // anything that incidentally matches an `lfs` gitattribute pattern.
        let plain_text = b"this is not a pointer file\n";
        assert!(matches!(
            check_pointer(plain_text),
            PointerCheck::NotPointer
        ));

        // NotPointer: UTF-8 with a different/old version line.
        let wrong_version = b"version https://git-lfs.github.com/spec/v0\n\
            oid sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size 12345\n";
        assert!(matches!(
            check_pointer(wrong_version),
            PointerCheck::NotPointer
        ));

        // Malformed: header present, but oid too short. This is a real data issue.
        let malformed_oid = b"version https://git-lfs.github.com/spec/v1\n\
            oid sha256:0926726201de4dbfeb2\n\
            size 12345\n";
        assert!(matches!(
            check_pointer(malformed_oid),
            PointerCheck::Malformed(_)
        ));

        // Malformed: header present, but size not parseable.
        let malformed_size = b"version https://git-lfs.github.com/spec/v1\n\
            oid sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size abc\n";
        assert!(matches!(
            check_pointer(malformed_size),
            PointerCheck::Malformed(_)
        ));

        // Valid: well-formed pointer; oid + size match the expected fields.
        let good = b"version https://git-lfs.github.com/spec/v1\n\
            oid sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc\n\
            size 12345\n";
        match check_pointer(good) {
            PointerCheck::Valid(p) => {
                assert_eq!(
                    p.oid.0,
                    "0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc"
                );
                assert_eq!(p.size, 12345);
            }
            other => panic!("expected Valid, got {:?}", other),
        }
    }

    #[test]
    fn path_from_oid() {
        let path = super::path_from_oid(
            "".into(),
            &"sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc".into(),
        );
        assert_eq!(
            path,
            PathBuf::from("09/26/0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc")
        );
    }
}
