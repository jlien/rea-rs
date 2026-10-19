//! Search rpath and runpath directories for a library file name.
//!
//! `$ORIGIN`, `${ORIGIN}`, `@loader_path`, and `@executable_path` expand to the
//! directory that contains the loaded file. A missing directory is a miss, not an error.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PathHit {
    pub name: String,
    pub directory: String,
    /// Absolute path when that file exists.
    pub found: Option<String>,
}

/// Look up each file name in each directory. At most 64 pairs.
pub fn search(dirs: &[String], names: &[String], origin: Option<&Path>) -> Vec<PathHit> {
    let mut out = Vec::new();
    for dir in dirs {
        if out.len() >= 64 {
            break;
        }
        let expanded = expand(dir, origin);
        for name in names {
            if out.len() >= 64 {
                break;
            }
            let file = file_name(name);
            if file.is_empty() || file == "self" {
                continue;
            }
            let candidate = PathBuf::from(&expanded).join(&file);
            let found = candidate.is_file().then(|| candidate.display().to_string());
            out.push(PathHit {
                name: file,
                directory: expanded.clone(),
                found,
            });
        }
    }
    out
}

fn file_name(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn expand(dir: &str, origin: Option<&Path>) -> String {
    let Some(origin) = origin else {
        return dir.to_string();
    };
    let base = origin
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| origin.display().to_string());
    dir.replace("${ORIGIN}", &base)
        .replace("$ORIGIN", &base)
        .replace("@loader_path", &base)
        .replace("@executable_path", &base)
}

#[cfg(test)]
mod tests {
    use super::search;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn origin_token_finds_a_library_and_a_miss_stays_empty() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rea-rpath-{stamp}"));
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let origin = bin.join("tool");
        fs::write(&origin, b"x").unwrap();
        fs::write(bin.join("libdemo.so"), b"lib").unwrap();
        let hits = search(
            &["$ORIGIN".into(), "/no/such".into()],
            &["libdemo.so".into(), "libmissing.so".into()],
            Some(&origin),
        );
        assert_eq!(hits.len(), 4);
        assert_eq!(hits[0].name, "libdemo.so");
        assert!(hits[0].found.as_ref().unwrap().ends_with("libdemo.so"));
        assert_eq!(hits[1].found, None);
        assert_eq!(hits[2].found, None);
        let _ = fs::remove_dir_all(&root);
    }
}
