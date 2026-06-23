use std::{fmt, path::PathBuf};

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

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Oid(pub(crate) String);

impl From<&str> for Oid {
    fn from(s: &str) -> Self {
        let sha256 = s.split(':').nth(1).expect("could not find :").to_string();
        Oid(sha256)
    }
}

pub(crate) fn parse_pointer(contents: &str) -> Result<GitLfsPointer, ParseError> {
    let mut oid: Option<Oid> = None;
    let mut size = 0;
    let mut version = String::new();

    for line in contents.lines() {
        if line.starts_with("oid") {
            oid = Some(
                line.split_whitespace()
                    .nth(1)
                    .ok_or(ParseError("oid not found".to_string()))?
                    .into(),
            );
        } else if line.starts_with("size") {
            size = line
                .split_whitespace()
                .nth(1)
                .ok_or(ParseError("size not found".to_string()))?
                .parse()
                .map_err(|_| ParseError("size not parsed".to_string()))?;
        } else if line.starts_with("version") {
            version = line
                .split_whitespace()
                .nth(1)
                .ok_or(ParseError("version not found".to_string()))?
                .to_string();
        }
    }

    if version != "https://git-lfs.github.com/spec/v1" {
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
        ];

        for content in contents {
            println!("{}", content);
            let i = parse_pointer(content);
            assert!(i.is_err());
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
