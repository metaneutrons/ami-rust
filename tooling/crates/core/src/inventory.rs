//! Read-only complete component inventory verification under a retained root.
//!
//! The caller authenticates the inventory first. Success means byte/type/link
//! consistency, not publisher authentication or installation ownership. Empty
//! extra directories remain allowed, as in the historical component verifier.

use crate::{
    Refusal, Result, digest::is_sha256_digest, directory::Directory,
    files::validate_relative_inventory_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsStr,
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    /// Some historical component inventories omit mode. When supplied, all
    /// permission/special bits must match; file type is checked separately.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkIdentity {
    pub path: String,
    pub target: String,
}

/// Host operation bounds from the selected component/resource profile. They
/// do not impose an executable-size or allocation quota on AROS applications.
#[derive(Clone, Copy, Debug)]
pub struct InventoryLimits {
    pub max_tree_entries: usize,
    pub max_link_resolution_steps: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Measurement {
    pub files: usize,
    pub symlinks: usize,
    pub directories: usize,
    pub file_bytes: u64,
}

#[derive(Clone, Copy)]
enum Expected<'a> {
    File(&'a FileIdentity),
    Link(&'a LinkIdentity),
}
#[derive(Clone, Copy)]
enum Actual<'a> {
    File,
    Directory,
    Link(&'a str),
}

pub fn verify_complete(
    root: &Path,
    files: &[FileIdentity],
    links: &[LinkIdentity],
    limits: InventoryLimits,
) -> Result<Measurement> {
    let mut expected = BTreeMap::new();
    let mut expected_bytes = 0_u64;
    for file in files {
        validate_relative_inventory_path(&file.path)?;
        if !is_sha256_digest(&file.sha256) || file.mode.is_some_and(|mode| mode & !0o7777 != 0) {
            return Err(Refusal::new("invalid inventory digest or permission mode"));
        }
        expected_bytes = expected_bytes
            .checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("inventory byte total overflow"))?;
        if expected
            .insert(file.path.as_str(), Expected::File(file))
            .is_some()
        {
            return Err(Refusal::new("duplicate inventory identity"));
        }
    }
    for link in links {
        validate_relative_inventory_path(&link.path)?;
        validate_target(&link.target)?;
        if expected
            .insert(link.path.as_str(), Expected::Link(link))
            .is_some()
        {
            return Err(Refusal::new("duplicate file or symlink identity"));
        }
    }
    if expected.len() > limits.max_tree_entries {
        return Err(Refusal::new("inventory exceeds tree entry bound"));
    }
    // A leaf can never also be another member's directory ancestor.
    for path in expected.keys() {
        for (offset, _) in path.match_indices('/') {
            if expected.contains_key(&path[..offset]) {
                return Err(Refusal::new("inventory leaf is also a directory ancestor"));
            }
        }
    }

    let root = Directory::open(root)?;
    let mut actual = BTreeMap::from([(String::new(), Actual::Directory)]);
    let mut visited = BTreeSet::new();
    let mut pending = vec![String::new()];
    let mut entries = 0_usize;
    let mut directories = 0_usize;
    while let Some(prefix) = pending.pop() {
        let directory = root.relative_directory(&prefix)?;
        for name in directory.names(limits.max_tree_entries - entries)? {
            entries = entries
                .checked_add(1)
                .ok_or_else(|| Refusal::new("tree count overflow"))?;
            if entries > limits.max_tree_entries {
                return Err(Refusal::new("component tree exceeds entry bound"));
            }
            let name = name
                .to_str()
                .ok_or_else(|| Refusal::new("component entry name is not UTF-8"))?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            validate_relative_inventory_path(&path)?;
            match expected.get(path.as_str()) {
                Some(Expected::File(file)) => {
                    verify_file(&directory, name, file)?;
                    actual.insert(path.clone(), Actual::File);
                    visited.insert(path);
                }
                Some(Expected::Link(link)) => {
                    let target = directory.link_target(OsStr::new(name), link.target.len())?;
                    if target.as_bytes() != link.target.as_bytes() {
                        return Err(Refusal::new(
                            "component symlink target differs from inventory",
                        ));
                    }
                    actual.insert(path.clone(), Actual::Link(&link.target));
                    visited.insert(path);
                }
                None => {
                    // Only real directories may be absent from files/symlinks.
                    directory.child(OsStr::new(name))?;
                    actual.insert(path.clone(), Actual::Directory);
                    directories += 1;
                    pending.push(path);
                }
            }
        }
    }
    if visited.len() != expected.len() {
        return Err(Refusal::new("component inventory has missing entries"));
    }
    for link in links {
        resolve_link(link, &actual, limits.max_link_resolution_steps)?;
    }
    Ok(Measurement {
        files: files.len(),
        symlinks: links.len(),
        directories,
        file_bytes: expected_bytes,
    })
}

fn verify_file(directory: &Directory, name: &str, expected: &FileIdentity) -> Result<()> {
    let mut file = directory.regular(OsStr::new(name))?;
    let metadata = file
        .metadata()
        .map_err(|e| Refusal::new(format!("could not inspect inventory file: {e}")))?;
    if metadata.len() != expected.bytes
        || expected
            .mode
            .is_some_and(|mode| metadata.permissions().mode() & 0o7777 != mode)
    {
        return Err(Refusal::new(
            "component size or mode differs from inventory",
        ));
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        // Never hash an unbounded growing file. Read at most one excess byte.
        let remaining = expected.bytes - total;
        let amount = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let amount = if amount < buffer.len() {
            amount + 1
        } else {
            amount
        };
        let count = match file.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Refusal::new(format!("could not hash inventory file: {e}"))),
        };
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Refusal::new("file byte count overflow"))?;
        if total > expected.bytes {
            return Err(Refusal::new("inventory file grew beyond its declared size"));
        }
        digest.update(&buffer[..count]);
    }
    let digest: [u8; 32] = digest.finalize().into();
    let measured = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if total != expected.bytes || measured != expected.sha256 {
        return Err(Refusal::new("component file identity mismatch"));
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains(['\\', ':'])
        || target.bytes().any(|byte| byte < 32 || byte == 127)
    {
        return Err(Refusal::new(
            "component link target must be portable and relative",
        ));
    }
    Ok(())
}

fn resolve_link(
    link: &LinkIdentity,
    actual: &BTreeMap<String, Actual<'_>>,
    maximum: usize,
) -> Result<()> {
    let mut current: Vec<&str> = link
        .path
        .rsplit_once('/')
        .map_or_else(Vec::new, |(parent, _)| parent.split('/').collect());
    let mut pending: VecDeque<&str> = link.target.split('/').collect();
    let mut steps = 0_usize;
    while let Some(part) = pending.pop_front() {
        if steps == maximum {
            return Err(Refusal::new("component link resolution exceeds work bound"));
        }
        steps += 1;
        match part {
            "" | "." => continue,
            ".." => {
                if current.pop().is_none() {
                    return Err(Refusal::new("component link escapes root"));
                }
            }
            part => {
                current.push(part);
                match actual.get(&current.join("/")) {
                    Some(Actual::Directory) => {}
                    Some(Actual::File) if pending.is_empty() => {}
                    Some(Actual::Link(target)) => {
                        current.pop();
                        for part in target.split('/').rev() {
                            pending.push_front(part);
                        }
                    }
                    _ => {
                        return Err(Refusal::new(
                            "component link is broken or traverses a non-directory",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_bytes;
    use std::{
        fs,
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".ami-inventory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn limits() -> InventoryLimits {
        InventoryLimits {
            max_tree_entries: 20,
            max_link_resolution_steps: 40,
        }
    }
    fn file(path: &str, contents: &[u8]) -> FileIdentity {
        FileIdentity {
            path: path.into(),
            bytes: contents.len() as u64,
            sha256: sha256_bytes(contents),
            mode: Some(0o644),
        }
    }
    fn write(root: &Path, path: &str, contents: &[u8]) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn exact_tree_bytes_modes_links_and_empty_directories_are_verified() {
        let root = Fixture::new();
        write(&root.0, "bin/tool", b"executable");
        fs::create_dir(root.0.join("empty")).unwrap();
        symlink("bin/tool", root.0.join("tool")).unwrap();
        let files = [file("bin/tool", b"executable")];
        let links = [LinkIdentity {
            path: "tool".into(),
            target: "bin/tool".into(),
        }];
        assert_eq!(
            verify_complete(&root.0, &files, &links, limits()).unwrap(),
            Measurement {
                files: 1,
                symlinks: 1,
                directories: 2,
                file_bytes: 10
            }
        );
        fs::set_permissions(root.0.join("bin/tool"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_complete(&root.0, &files, &links, limits()).is_err());
    }

    #[test]
    fn changed_missing_extra_and_link_substituted_files_refuse() {
        let root = Fixture::new();
        write(&root.0, "file", b"original");
        let rows = [file("file", b"original")];
        write(&root.0, "file", b"changed!");
        assert!(verify_complete(&root.0, &rows, &[], limits()).is_err());
        fs::remove_file(root.0.join("file")).unwrap();
        assert!(verify_complete(&root.0, &rows, &[], limits()).is_err());
        write(&root.0, "file", b"original");
        write(&root.0, "extra", b"extra");
        assert!(verify_complete(&root.0, &rows, &[], limits()).is_err());
        fs::remove_file(root.0.join("extra")).unwrap();
        fs::rename(root.0.join("file"), root.0.join("real")).unwrap();
        symlink("real", root.0.join("file")).unwrap();
        assert!(verify_complete(&root.0, &rows, &[], limits()).is_err());
    }

    #[test]
    fn links_must_match_remain_inside_resolve_and_stay_within_work_bound() {
        for target in ["../outside", "missing", "a"] {
            let root = Fixture::new();
            symlink(target, root.0.join("a")).unwrap();
            assert!(
                verify_complete(
                    &root.0,
                    &[],
                    &[LinkIdentity {
                        path: "a".into(),
                        target: target.into()
                    }],
                    limits()
                )
                .is_err()
            );
        }
        let root = Fixture::new();
        write(&root.0, "dir/file", b"data");
        symlink("dir", root.0.join("a")).unwrap();
        symlink("a/file", root.0.join("b")).unwrap();
        let links = [
            LinkIdentity {
                path: "a".into(),
                target: "dir".into(),
            },
            LinkIdentity {
                path: "b".into(),
                target: "a/file".into(),
            },
        ];
        verify_complete(&root.0, &[file("dir/file", b"data")], &links, limits()).unwrap();
        assert!(
            verify_complete(
                &root.0,
                &[file("dir/file", b"data")],
                &links,
                InventoryLimits {
                    max_link_resolution_steps: 1,
                    ..limits()
                }
            )
            .is_err()
        );
        assert!(
            verify_complete(
                &root.0,
                &[file("dir/file", b"data")],
                &[LinkIdentity {
                    path: "a".into(),
                    target: "different".into()
                }],
                limits()
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_unsafe_overlapping_rows_and_tree_bounds_refuse() {
        let root = Fixture::new();
        write(&root.0, "file", b"data");
        let row = file("file", b"data");
        assert!(verify_complete(&root.0, &[row.clone(), row.clone()], &[], limits()).is_err());
        assert!(
            verify_complete(
                &root.0,
                &[row.clone(), file("file/child", b"")],
                &[],
                limits()
            )
            .is_err()
        );
        assert!(verify_complete(&root.0, &[file("../file", b"data")], &[], limits()).is_err());
        assert!(
            verify_complete(
                &root.0,
                &[row],
                &[],
                InventoryLimits {
                    max_tree_entries: 0,
                    ..limits()
                }
            )
            .is_err()
        );
    }
}
