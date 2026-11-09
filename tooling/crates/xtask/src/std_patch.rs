//! Strict application of the `std` for AROS patch to a staged `rust-src`.
//!
//! The patch is a git-style unified diff of whole text files. It is applied in
//! process, without fuzz and without an external `patch`, and every file must
//! match the digests of `host/std-aros/source.json`: the file before the patch
//! (when it exists) and the file after it. A patch that touches any other file
//! than the ones that `source.json` lists, or that does not apply exactly, is
//! refused.

use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const NEW_FILE_MODE: u32 = 0o644;

/// One file as it is after the patch, with the inventory path relative to the
/// root that the patch was applied in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PatchedFile {
    pub(super) path: String,
    pub(super) bytes: u64,
    pub(super) sha256: String,
    pub(super) mode: u32,
    pub(super) created: bool,
}

struct Hunk<'a> {
    old_start: usize,
    old_count: usize,
    new_count: usize,
    lines: Vec<(u8, &'a [u8])>,
}

struct FileDiff<'a> {
    path: String,
    created: bool,
    hunks: Vec<Hunk<'a>>,
}

struct Expected {
    before: Option<String>,
    after: String,
}

/// Apply `patch` below `root` (the directory that holds `library/`), and
/// return the identity of every file it wrote, sorted by path. `prefix` is put
/// before each path so that the rows fit the inventory of the whole stage.
pub(super) fn apply(
    patch: &[u8],
    source_json: &[u8],
    root: &Path,
    prefix: &str,
) -> Result<Vec<PatchedFile>> {
    if patch.is_empty() || patch.len() > MAX_PATCH_BYTES {
        return Err(Refusal::new("std patch size is outside its bound"));
    }
    let (patch_sha256, expected) = read_source(source_json)?;
    if sha256_bytes(patch) != patch_sha256 {
        return Err(Refusal::new(
            "std patch differs from the digest in its source record",
        ));
    }
    let diffs = parse(patch)?;
    let listed = diffs
        .iter()
        .map(|diff| diff.path.as_str())
        .collect::<BTreeSet<_>>();
    if listed.len() != diffs.len()
        || listed != expected.keys().map(String::as_str).collect::<BTreeSet<_>>()
    {
        return Err(Refusal::new(
            "std patch files differ from the files in its source record",
        ));
    }

    // Everything is computed in memory first; nothing is written when one file fails.
    let mut results = Vec::with_capacity(diffs.len());
    let mut writes = Vec::with_capacity(diffs.len());
    for diff in &diffs {
        let expected = &expected[&diff.path];
        let destination = root.join(&diff.path);
        let (original, mode) = if diff.created {
            if expected.before.is_some() {
                return Err(Refusal::new(
                    "std patch creates a file that its source record expects to exist",
                ));
            }
            if fs::symlink_metadata(&destination).is_ok() {
                return Err(Refusal::new("std patch would overwrite an existing file"));
            }
            (Vec::new(), NEW_FILE_MODE)
        } else {
            let before = expected.before.as_deref().ok_or_else(|| {
                Refusal::new("std patch changes a file that its source record expects to be new")
            })?;
            let metadata = fs::symlink_metadata(&destination)
                .map_err(|_| Refusal::new(format!("std patch input is missing: {}", diff.path)))?;
            if !metadata.file_type().is_file() || metadata.len() as usize > MAX_FILE_BYTES {
                return Err(Refusal::new(format!(
                    "std patch input is not a bounded regular file: {}",
                    diff.path
                )));
            }
            let original = fs::read(&destination)?;
            if sha256_bytes(&original) != before {
                return Err(Refusal::new(format!(
                    "std patch input differs from the pinned source: {}",
                    diff.path
                )));
            }
            (original, metadata.permissions().mode() & 0o7777)
        };
        let patched = apply_hunks(&original, &diff.hunks, diff.created)
            .map_err(|reason| Refusal::new(format!("{reason}: {}", diff.path)))?;
        if patched.len() > MAX_FILE_BYTES || sha256_bytes(&patched) != expected.after {
            return Err(Refusal::new(format!(
                "std patch result differs from its source record: {}",
                diff.path
            )));
        }
        results.push(PatchedFile {
            path: format!("{prefix}{}", diff.path),
            bytes: patched.len() as u64,
            sha256: expected.after.clone(),
            mode,
            created: diff.created,
        });
        writes.push((destination, patched, mode, diff.created));
    }

    for (destination, patched, mode, created) in writes {
        if created {
            fs::create_dir_all(
                destination
                    .parent()
                    .ok_or_else(|| Refusal::new("std patch destination has no parent"))?,
            )?;
        } else {
            fs::remove_file(&destination)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&destination)?;
        file.write_all(&patched)?;
        file.sync_all()?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(mode))?;
    }
    results.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(results)
}

fn read_source(source_json: &[u8]) -> Result<(String, BTreeMap<String, Expected>)> {
    let source: Value = serde_json::from_slice(source_json)
        .map_err(|error| Refusal::new(format!("std source record is not JSON: {error}")))?;
    if source.get("schema").and_then(Value::as_str) != Some("ami-rust-std-aros-source-v1") {
        return Err(Refusal::new("std source record has an unexpected schema"));
    }
    let patch = source
        .get("patch")
        .ok_or_else(|| Refusal::new("std source record lacks the patch row"))?;
    if patch.get("strip").and_then(Value::as_u64) != Some(1)
        || patch.get("apply_in").and_then(Value::as_str) != Some("lib/rustlib/src/rust")
    {
        return Err(Refusal::new(
            "std source record applies the patch somewhere else than the pinned source root",
        ));
    }
    let patch_sha256 = digest(patch.get("sha256"))?
        .ok_or_else(|| Refusal::new("std source record lacks the patch digest"))?;
    let mut expected = BTreeMap::new();
    for row in source
        .get("changed_files")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("std source record lacks the changed files"))?
    {
        let path = row
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("std source record has a row without a path"))?;
        if !path.starts_with("library/std/src/")
            || path.contains("..")
            || path.contains("//")
            || path.starts_with('/')
        {
            return Err(Refusal::new(
                "std source record names a path outside library/std/src",
            ));
        }
        let before = digest(row.get("before_sha256"))?;
        let after = digest(row.get("after_sha256"))?
            .ok_or_else(|| Refusal::new("std source record lacks an after digest"))?;
        if expected
            .insert(path.to_owned(), Expected { before, after })
            .is_some()
        {
            return Err(Refusal::new("std source record repeats a path"));
        }
    }
    if expected.is_empty() {
        return Err(Refusal::new("std source record lists no file"));
    }
    Ok((patch_sha256, expected))
}

fn digest(value: Option<&Value>) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if is_sha256_digest(text) => Ok(Some(text.clone())),
        Some(_) => Err(Refusal::new("std source record has a malformed digest")),
    }
}

fn parse(patch: &[u8]) -> Result<Vec<FileDiff<'_>>> {
    let malformed = |what: &str| Refusal::new(format!("std patch is malformed: {what}"));
    let lines = patch.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    // A well-formed patch ends with a newline, so the last piece is empty.
    if lines.last() != Some(&&b""[..]) {
        return Err(malformed("it does not end with a newline"));
    }
    let lines = &lines[..lines.len() - 1];
    let mut diffs: Vec<FileDiff<'_>> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let header = std::str::from_utf8(lines[index])
            .map_err(|_| malformed("a header is not UTF-8"))?
            .to_owned();
        let Some(names) = header.strip_prefix("diff --git a/") else {
            return Err(malformed("expected a diff header"));
        };
        let (old, new) = names
            .split_once(" b/")
            .ok_or_else(|| malformed("the diff header names no second path"))?;
        if old != new {
            return Err(malformed("a rename or copy"));
        }
        index += 1;
        let mut created = false;
        while index < lines.len() && !lines[index].starts_with(b"--- ") {
            let line = lines[index];
            if line == b"new file mode 100644" {
                created = true;
            } else if !line.starts_with(b"index ") {
                return Err(malformed(
                    "extended header other than a plain new file or change",
                ));
            }
            index += 1;
        }
        let old_header = lines
            .get(index)
            .ok_or_else(|| malformed("missing --- line"))?;
        let new_header = lines
            .get(index + 1)
            .ok_or_else(|| malformed("missing +++ line"))?;
        let want_old = if created {
            b"--- /dev/null".to_vec()
        } else {
            format!("--- a/{old}").into_bytes()
        };
        if **old_header != want_old[..] || **new_header != *format!("+++ b/{new}").as_bytes() {
            return Err(malformed("file header lines do not match the diff header"));
        }
        index += 2;
        let mut hunks = Vec::new();
        while index < lines.len() && lines[index].starts_with(b"@@ ") {
            let head = std::str::from_utf8(lines[index])
                .map_err(|_| malformed("a hunk header is not UTF-8"))?;
            let ranges = head
                .strip_prefix("@@ -")
                .and_then(|rest| rest.split_once(" @@"))
                .map(|(ranges, _)| ranges)
                .ok_or_else(|| malformed("hunk header"))?;
            let (old_range, new_range) = ranges
                .split_once(" +")
                .ok_or_else(|| malformed("hunk header ranges"))?;
            let parse_range = |range: &str| -> Result<(usize, usize)> {
                let (start, count) = match range.split_once(',') {
                    Some((start, count)) => (start, count),
                    None => (range, "1"),
                };
                Ok((
                    start.parse().map_err(|_| malformed("hunk start"))?,
                    count.parse().map_err(|_| malformed("hunk count"))?,
                ))
            };
            let (old_start, old_count) = parse_range(old_range)?;
            let (_, new_count) = parse_range(new_range)?;
            index += 1;
            let mut body = Vec::new();
            let (mut seen_old, mut seen_new) = (0, 0);
            while (seen_old < old_count || seen_new < new_count) && index < lines.len() {
                let line = lines[index];
                match line.first() {
                    Some(b' ') => {
                        seen_old += 1;
                        seen_new += 1;
                        body.push((b' ', &line[1..]));
                    }
                    Some(b'-') => {
                        seen_old += 1;
                        body.push((b'-', &line[1..]));
                    }
                    Some(b'+') => {
                        seen_new += 1;
                        body.push((b'+', &line[1..]));
                    }
                    None => {
                        // An empty line is a context line whose blank was trimmed.
                        seen_old += 1;
                        seen_new += 1;
                        body.push((b' ', &line[..0]));
                    }
                    _ => return Err(malformed("a hunk line starts with an unknown marker")),
                }
                index += 1;
            }
            if seen_old != old_count || seen_new != new_count {
                return Err(malformed("a hunk is shorter than its header says"));
            }
            if lines.get(index).is_some_and(|line| line.starts_with(b"\\")) {
                return Err(malformed("a file without a final newline"));
            }
            hunks.push(Hunk {
                old_start,
                old_count,
                new_count,
                lines: body,
            });
        }
        if hunks.is_empty() {
            return Err(malformed("a file section without hunks"));
        }
        diffs.push(FileDiff {
            path: new.to_owned(),
            created,
            hunks,
        });
    }
    if diffs.is_empty() {
        return Err(malformed("no file"));
    }
    Ok(diffs)
}

fn apply_hunks(
    original: &[u8],
    hunks: &[Hunk<'_>],
    created: bool,
) -> std::result::Result<Vec<u8>, &'static str> {
    let mut old = original.split(|byte| *byte == b'\n').collect::<Vec<_>>();
    if created {
        old.clear();
    } else {
        if old.last() != Some(&&b""[..]) {
            return Err("std patch input has no final newline");
        }
        old.pop();
    }
    let mut output: Vec<&[u8]> = Vec::with_capacity(old.len());
    let mut cursor = 0_usize;
    for hunk in hunks {
        // A hunk with no old lines names the line after which it inserts.
        let start = if hunk.old_count == 0 {
            hunk.old_start
        } else {
            hunk.old_start
                .checked_sub(1)
                .ok_or("std patch hunk starts at line 0")?
        };
        if start < cursor || start > old.len() {
            return Err("std patch hunks overlap or lie outside the file");
        }
        output.extend_from_slice(&old[cursor..start]);
        cursor = start;
        let (mut taken, mut added) = (0, 0);
        for (marker, text) in &hunk.lines {
            match marker {
                b' ' | b'-' => {
                    if old.get(cursor) != Some(text) {
                        return Err("std patch does not apply: a line differs");
                    }
                    cursor += 1;
                    taken += 1;
                    if *marker == b' ' {
                        output.push(text);
                        added += 1;
                    }
                }
                _ => {
                    output.push(text);
                    added += 1;
                }
            }
        }
        if taken != hunk.old_count || added != hunk.new_count {
            return Err("std patch hunk counts are inconsistent");
        }
    }
    output.extend_from_slice(&old[cursor..]);
    let mut bytes = Vec::with_capacity(original.len() + 1024);
    for line in output {
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temporary_root;

    const BEFORE: &[u8] = b"one\ntwo\nthree\nfour\n";
    const AFTER: &[u8] = b"one\nTWO\nthree\nfour\n";
    const PATCH: &[u8] = b"diff --git a/library/std/src/a.rs b/library/std/src/a.rs\nindex 1..2 100644\n--- a/library/std/src/a.rs\n+++ b/library/std/src/a.rs\n@@ -1,4 +1,4 @@\n one\n-two\n+TWO\n three\n four\ndiff --git a/library/std/src/new/b.rs b/library/std/src/new/b.rs\nnew file mode 100644\nindex 0000000..3\n--- /dev/null\n+++ b/library/std/src/new/b.rs\n@@ -0,0 +1,2 @@\n+x\n+y\n";

    fn source(patch: &[u8], rows: &[(&str, Option<&[u8]>, &[u8])]) -> Vec<u8> {
        let changed = rows
            .iter()
            .map(|(path, before, after)| {
                serde_json::json!({
                    "path": path,
                    "before_sha256": before.map(sha256_bytes),
                    "after_sha256": sha256_bytes(after),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({
            "schema": "ami-rust-std-aros-source-v1",
            "patch": {"sha256": sha256_bytes(patch), "strip": 1, "apply_in": "lib/rustlib/src/rust"},
            "changed_files": changed,
        }))
        .unwrap()
    }

    fn good_source() -> Vec<u8> {
        source(
            PATCH,
            &[
                ("library/std/src/a.rs", Some(BEFORE), AFTER),
                ("library/std/src/new/b.rs", None, b"x\ny\n"),
            ],
        )
    }

    fn tree(label: &str) -> std::path::PathBuf {
        let root = temporary_root(label);
        fs::create_dir_all(root.join("library/std/src")).unwrap();
        fs::write(root.join("library/std/src/a.rs"), BEFORE).unwrap();
        root
    }

    #[test]
    fn applies_a_change_and_a_new_file_and_reports_their_identities() {
        let root = tree("std-patch-ok");
        let files = apply(PATCH, &good_source(), &root, "pre/").unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "pre/library/std/src/a.rs");
        assert!(!files[0].created && files[1].created);
        assert_eq!(files[1].mode, 0o644);
        assert_eq!(files[0].sha256, sha256_bytes(AFTER));
        assert_eq!(fs::read(root.join("library/std/src/a.rs")).unwrap(), AFTER);
        assert_eq!(
            fs::read(root.join("library/std/src/new/b.rs")).unwrap(),
            b"x\ny\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_without_writing_when_one_input_differs_from_the_pinned_source() {
        let root = tree("std-patch-drift");
        fs::write(
            root.join("library/std/src/a.rs"),
            b"one\ntwo!\nthree\nfour\n",
        )
        .unwrap();
        assert!(apply(PATCH, &good_source(), &root, "").is_err());
        assert!(!root.join("library/std/src/new/b.rs").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_a_patch_whose_digest_or_file_set_differs_from_the_source_record() {
        let root = tree("std-patch-set");
        let mut changed = PATCH.to_vec();
        changed[10] = b'X';
        assert!(apply(&changed, &good_source(), &root, "").is_err());
        let fewer = source(PATCH, &[("library/std/src/a.rs", Some(BEFORE), AFTER)]);
        assert!(apply(PATCH, &fewer, &root, "").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_a_result_that_differs_from_the_recorded_after_digest() {
        let root = tree("std-patch-after");
        let src = source(
            PATCH,
            &[
                (
                    "library/std/src/a.rs",
                    Some(BEFORE),
                    b"one\nOTHER\nthree\nfour\n",
                ),
                ("library/std/src/new/b.rs", None, b"x\ny\n"),
            ],
        );
        assert!(apply(PATCH, &src, &root, "").is_err());
        assert_eq!(fs::read(root.join("library/std/src/a.rs")).unwrap(), BEFORE);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_renames_and_paths_outside_the_std_sources() {
        let root = tree("std-patch-rename");
        let rename = b"diff --git a/library/std/src/a.rs b/library/std/src/c.rs\nsimilarity index 100%\nrename from library/std/src/a.rs\nrename to library/std/src/c.rs\n";
        let src = source(rename, &[("library/std/src/c.rs", None, b"")]);
        assert!(apply(rename, &src, &root, "").is_err());
        let outside = source(PATCH, &[("library/core/src/a.rs", None, b"x")]);
        assert!(apply(PATCH, &outside, &root, "").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_committed_patch_matches_its_source_record() {
        let patch = include_bytes!("../../../../host/std-aros/std-aros.patch");
        let source = include_bytes!("../../../../host/std-aros/source.json");
        let (digest, expected) = read_source(source).unwrap();
        assert_eq!(digest, sha256_bytes(patch));
        let diffs = parse(patch).unwrap();
        assert_eq!(diffs.len(), expected.len());
        assert!(diffs.iter().all(|diff| expected.contains_key(&diff.path)));
    }
}
