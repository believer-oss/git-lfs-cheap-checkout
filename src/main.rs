use std::{fmt, path::PathBuf, process::exit};

use clap::{arg, value_parser, Command};

#[derive(Debug)]
struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParseError: {}", self.0)
    }
}

#[derive(Debug)]
struct GitLfsPointer {
    oid: Oid,
    size: u64,
}

#[derive(Debug, PartialEq)]
struct Oid(String);

impl From<&str> for Oid {
    fn from(s: &str) -> Self {
        let sha256 = s.split(':').nth(1).expect("could not find :").to_string();
        Oid(sha256)
    }
}

fn parse_pointer(contents: &str) -> Result<GitLfsPointer, ParseError> {
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
fn path_from_oid(mut base_path: PathBuf, oid: &Oid) -> PathBuf {
    let oid = oid.0.as_bytes();
    base_path.push(std::str::from_utf8(&oid[0..2]).expect("missing first two bytes"));
    base_path.push(std::str::from_utf8(&oid[2..4]).expect("missing second two bytes"));
    base_path.push(std::str::from_utf8(oid).expect("failed to convert oid"));
    base_path
}

fn cli() -> Command {
    Command::new("git-lfs-cheap-checkout")
        .about("Smudge git-lfs files with hard links")
        .arg(arg!(-v --verbose "Show verbose output"))
        .arg(arg!(-d --dry_run "Dry run"))
        .arg(arg!(-s --verify_size "Verify the size of objects"))
        .arg(
            arg!(-w --workdir <WORKDIR> "Git checkout to use")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
}

#[tokio::main]
async fn main() {
    let matches = cli().get_matches();
    let dry_run = matches.get_flag("dry_run");
    let verbose = matches.get_flag("verbose");
    let verify_size = matches.get_flag("verify_size");

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

    // Get list of files from ls-files
    let files = std::process::Command::new("git-lfs")
        .arg("ls-files")
        .arg("--name-only")
        .output()
        .expect("failed to execute git-lfs ls-files");

    // Loop through the files and smudge them if necessary
    let mut handles = tokio::task::JoinSet::new();
    for file in files.stdout.split(|&c| c == b'\n') {
        if file.is_empty() {
            continue;
        }

        let local_object_dir = object_dir.clone();
        let local_file = std::str::from_utf8(file)
            .expect("could not convert to utf8 from pointer")
            .to_string();

        handles.spawn(async move {
            // Pointer files must be < 1024. If the file is larger, don't bother reading it - we
            // assume it's already been smudged to match upstream behavior.
            // https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md
            let meta = tokio::fs::metadata(&local_file)
                .await
                .expect("failed to get metadata for pointer file");
            if meta.len() > 1024 {
                return;
            }

            let contents = tokio::fs::read_to_string(&local_file).await;

            // We only care if the pointer hasn't been smudged already
            let pointer = match contents {
                Ok(contents) => parse_pointer(&contents).expect("failed to parse pointer"),
                Err(e) => {
                    eprintln!("{}: {}", local_file, e);
                    return;
                }
            };

            if verbose {
                println!("{}: {:?}", &local_file, pointer);
            }

            let obj = path_from_oid(local_object_dir, &pointer.oid);

            // Ensure that the object size matches what the pointer file says
            if verify_size {
                let meta = tokio::fs::metadata(&obj)
                    .await
                    .expect("failed to get metadata");
                if meta.len() != pointer.size {
                    eprintln!("{}: size mismatch", local_file);
                    exit(1);
                }
            }

            // If we're not in a dry run, remove the pointer and hard link the object
            if !dry_run {
                tokio::fs::remove_file(&local_file)
                    .await
                    .expect("failed to remove file");
                tokio::fs::hard_link(obj, local_file)
                    .await
                    .expect("failed to hard link");
            }
        });
    }
    handles.join_all().await;
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use crate::parse_pointer;

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
        let path = crate::path_from_oid(
            "".into(),
            &"sha256:0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc".into(),
        );
        assert_eq!(
            path,
            PathBuf::from("09/26/0926726201de4dbfeb2c4565a64bb3ce54dac189c7cab192bd515caf50c556dc")
        );
    }
}
