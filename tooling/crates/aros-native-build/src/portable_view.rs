//! Pure transformation from an authenticated composed file inventory to a
//! regular-file-only portable view.
//!
//! This module derives identities only. It does not authenticate its inputs,
//! read or write a filesystem, or establish compatibility with an SDK consumer.

use crate::{Refusal, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const PORTABLE_VIEW_JSON: &str = include_str!("../pins/portable-view-v2.json");

pub const COLLECTOR_SOURCE_PATH: &str = "bin/collect-aros";
pub const COLLECTOR_DESTINATION_PATH: &str = "libexec/aros/llvm/bin/collect-aros-sdk";

const ADMINISTRATIVE_FILES: [&str; 2] = [
    "lib/rustlib/components",
    "lib/rustlib/rust-installer-version",
];
/// Historical convenience aliases are not compiler inputs. Copying their
/// executable bytes to the root would change LLVM's loader-relative library
/// lookup. Retain the complete tools at the canonical LLVM component location.
pub const OMITTED_ROOT_TOOL_ALIASES: [(&str, &str); 5] = [
    ("bin/llvm-objdump", "../libexec/aros/llvm/bin/llvm-objdump"),
    ("bin/llvm-nm", "../libexec/aros/llvm/bin/llvm-nm"),
    ("bin/llvm-ar", "../libexec/aros/llvm/bin/llvm-ar"),
    ("bin/llvm-strip", "../libexec/aros/llvm/bin/llvm-strip"),
    ("bin/ld.lld", "../libexec/aros/llvm/bin/ld.lld"),
];
const MAX_LINK_SEGMENTS: usize = 4096;

/// One regular-file identity from the already-authenticated composed view.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub mode: Option<u32>,
}

/// One original relative symbolic-link entry from the composed view.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableLink {
    pub path: String,
    pub target: String,
}

/// Records an original link and its canonical regular-file identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedLink {
    pub original: PortableLink,
    pub resolved_file: PortableFile,
}

/// A content-preserving placement change required by executable-relative lookup.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelocatedFile {
    pub original: PortableFile,
    pub destination: String,
}

/// A regular-file-only view plus link provenance and the two omitted rows.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableInventory {
    pub files: Vec<PortableFile>,
    pub materialized_links: Vec<ResolvedLink>,
    pub omitted_files: Vec<PortableFile>,
    pub omitted_generated_aliases: Vec<ResolvedLink>,
    pub relocated_files: Vec<RelocatedFile>,
}

/// Derive a portable regular-file view from an authenticated composed inventory.
///
/// The caller must authenticate `files` and `links` before calling this
/// function. This transformation preserves every regular-file byte identity except the two
/// exact Rust installer bookkeeping files, and materializes each link as a
/// copy of its resolved regular-file bytes. Output permissions use the explicit
/// owner-derived rustup policy; provenance retains original modes.
pub fn derive_portable_inventory(
    files: &[PortableFile],
    links: &[PortableLink],
) -> Result<PortableInventory> {
    validate_embedded_policy()?;
    let resolver = Resolver::new(files, links)?;
    if matches!(
        resolver.entries.get(COLLECTOR_SOURCE_PATH),
        Some(Entry::Link(_))
    ) {
        return Err(Refusal::new(
            "collector relocation source must be a regular file",
        ));
    }

    let mut omitted_files = Vec::with_capacity(ADMINISTRATIVE_FILES.len());
    for path in ADMINISTRATIVE_FILES {
        match resolver.entries.get(path) {
            Some(Entry::File(file)) => omitted_files.push((*file).clone()),
            _ => {
                return Err(Refusal::new(
                    "portable inventory is missing a required administrative regular file",
                ));
            }
        }
    }

    let mut output_files = Vec::with_capacity(files.len() + links.len());
    let mut omitted_generated_aliases = Vec::new();
    let mut relocated_files = Vec::new();
    for file in files {
        if OMITTED_ROOT_TOOL_ALIASES
            .iter()
            .any(|(path, _)| *path == file.path)
        {
            return Err(Refusal::new(
                "omitted root LLVM alias is a regular input file",
            ));
        }
        if !ADMINISTRATIVE_FILES.contains(&file.path.as_str()) {
            let mut output = file.clone();
            if file.path == COLLECTOR_SOURCE_PATH {
                output.path = COLLECTOR_DESTINATION_PATH.to_owned();
                relocated_files.push(RelocatedFile {
                    original: file.clone(),
                    destination: output.path.clone(),
                });
            }
            output.mode = output.mode.map(normalize_portable_mode);
            output_files.push(output);
        }
    }

    let mut ordered_links: Vec<&PortableLink> = links.iter().collect();
    ordered_links.sort_by(|left, right| left.path.cmp(&right.path));
    let mut materialized_links = Vec::with_capacity(ordered_links.len());
    for link in ordered_links {
        let resolved = resolver.resolve_link(&link.path)?;
        let ResolvedNode::File { file } = resolved else {
            return Err(Refusal::new(
                "portable inventory link resolves to a directory rather than a regular file",
            ));
        };
        if ADMINISTRATIVE_FILES.contains(&file.path.as_str()) {
            return Err(Refusal::new(
                "portable inventory link aliases an omitted administrative file",
            ));
        }

        let resolved_file = (*file).clone();
        if let Some((_, expected_target)) = OMITTED_ROOT_TOOL_ALIASES
            .iter()
            .find(|(path, _)| *path == link.path)
        {
            if link.target != *expected_target {
                return Err(Refusal::new(
                    "omitted root LLVM alias has unexpected original target text",
                ));
            }
            omitted_generated_aliases.push(ResolvedLink {
                original: link.clone(),
                resolved_file,
            });
            continue;
        }

        output_files.push(PortableFile {
            path: link.path.clone(),
            bytes: resolved_file.bytes,
            sha256: resolved_file.sha256.clone(),
            mode: resolved_file.mode.map(normalize_portable_mode),
        });
        materialized_links.push(ResolvedLink {
            original: link.clone(),
            resolved_file,
        });
    }

    output_files.sort_by(|left, right| left.path.cmp(&right.path));
    omitted_files.sort_by(|left, right| left.path.cmp(&right.path));
    // A relocation can introduce a new collision even when the original
    // authenticated namespace was valid. Validate the complete derived tree.
    Resolver::new(&output_files, &[])?;

    Ok(PortableInventory {
        files: output_files,
        materialized_links,
        omitted_files,
        omitted_generated_aliases,
        relocated_files,
    })
}

/// The unmodified rustup installer derives group/other read/execute bits from
/// owner permissions. Apply this declared output policy before packaging so all
/// distribution channels install identical modes; original source modes remain
/// part of the derivation record. This never changes file contents.
pub fn normalize_portable_mode(mode: u32) -> u32 {
    let owner = mode & 0o700;
    let group = (owner & 0o500) >> 3;
    owner | group | (group >> 3)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    parent_view: String,
    links: String,
    permissions: String,
    omitted_installer_files: Vec<String>,
    omitted_root_tool_aliases: Vec<PortableLink>,
    relocated_files: Vec<PolicyRelocation>,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PolicyRelocation {
    path: String,
    destination: String,
}

fn validate_embedded_policy() -> Result<()> {
    let policy: Policy = serde_json::from_str(PORTABLE_VIEW_JSON)
        .map_err(|error| Refusal::new(format!("invalid embedded portable-view policy: {error}")))?;
    if policy.schema != "ami-rust-portable-view-v2"
        || policy.parent_view != "ami-rust-public-sdk-exclusion-policy-v1"
        || policy.links != "copy-resolved-regular-file"
        || policy.permissions != "owner-derived-rustup-permissions-v1"
        || policy.omitted_installer_files != ADMINISTRATIVE_FILES
        || policy.omitted_root_tool_aliases
            != OMITTED_ROOT_TOOL_ALIASES
                .iter()
                .map(|(path, target)| PortableLink {
                    path: (*path).into(),
                    target: (*target).into(),
                })
                .collect::<Vec<_>>()
        || policy.relocated_files
            != vec![PolicyRelocation {
                path: COLLECTOR_SOURCE_PATH.to_owned(),
                destination: COLLECTOR_DESTINATION_PATH.to_owned(),
            }]
    {
        return Err(Refusal::new("unsupported embedded portable-view policy"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Entry<'a> {
    File(&'a PortableFile),
    Link(&'a PortableLink),
}

enum WorkItem {
    Segment(String),
    EndLink(String),
}

enum NodeKind<'a> {
    Missing,
    Directory,
    File(&'a PortableFile),
    Link(&'a PortableLink),
}

enum ResolvedNode<'a> {
    Directory,
    File { file: &'a PortableFile },
}

struct Resolver<'a> {
    entries: BTreeMap<String, Entry<'a>>,
    directories: BTreeSet<String>,
}

impl<'a> Resolver<'a> {
    fn new(files: &'a [PortableFile], links: &'a [PortableLink]) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for file in files {
            validate_inventory_path(&file.path)?;
            if !is_lowercase_sha256(&file.sha256) {
                return Err(Refusal::new(
                    "portable inventory contains an invalid lowercase SHA-256 digest",
                ));
            }
            if matches!(file.mode, Some(mode) if mode > 0o7777) {
                return Err(Refusal::new(
                    "portable inventory contains a file mode above 07777",
                ));
            }
            if entries
                .insert(file.path.clone(), Entry::File(file))
                .is_some()
            {
                return Err(Refusal::new(
                    "portable inventory contains duplicate or overlapping file and link paths",
                ));
            }
        }

        for link in links {
            validate_inventory_path(&link.path)?;
            validate_link_target(&link.target)?;
            if entries
                .insert(link.path.clone(), Entry::Link(link))
                .is_some()
            {
                return Err(Refusal::new(
                    "portable inventory contains duplicate or overlapping file and link paths",
                ));
            }
        }

        for path in entries.keys() {
            let mut prefix_end = path.len();
            while let Some(slash) = path[..prefix_end].rfind('/') {
                let prefix = &path[..slash];
                if entries.contains_key(prefix) {
                    return Err(Refusal::new(
                        "portable inventory entry is an ancestor of another file or link path",
                    ));
                }
                prefix_end = slash;
            }
        }

        let mut directories = BTreeSet::new();
        for path in entries.keys() {
            for (slash, _) in path.match_indices('/') {
                directories.insert(path[..slash].to_owned());
            }
        }

        Ok(Self {
            entries,
            directories,
        })
    }

    fn resolve_link(&self, link_path: &str) -> Result<ResolvedNode<'a>> {
        let link = match self.entries.get(link_path) {
            Some(Entry::Link(link)) => *link,
            _ => {
                return Err(Refusal::new(
                    "portable inventory link path does not name an original link",
                ));
            }
        };

        let mut current = parent_components(link_path);
        let mut pending = VecDeque::new();
        let mut active_links = BTreeSet::new();
        let mut segment_work = 0;
        self.enqueue_link(link_path, link, &mut pending, &mut active_links)?;

        while let Some(item) = pending.pop_front() {
            match item {
                WorkItem::EndLink(path) => {
                    if !active_links.remove(&path) {
                        return Err(Refusal::new(
                            "portable inventory link resolution has an invalid traversal state",
                        ));
                    }
                }
                WorkItem::Segment(segment) => {
                    segment_work += 1;
                    if segment_work > MAX_LINK_SEGMENTS {
                        return Err(Refusal::new(
                            "portable inventory link resolution exceeds 4096 path segments",
                        ));
                    }

                    match self.kind_at(&current) {
                        NodeKind::Directory => {}
                        NodeKind::File(_) => {
                            return Err(Refusal::new(
                                "portable inventory link traverses through a regular file",
                            ));
                        }
                        NodeKind::Missing => {
                            return Err(Refusal::new(
                                "portable inventory link traverses a missing path",
                            ));
                        }
                        NodeKind::Link(_) => {
                            return Err(Refusal::new(
                                "portable inventory link resolution reached an unexpanded link",
                            ));
                        }
                    }

                    match segment.as_str() {
                        "." => {}
                        ".." => {
                            if current.pop().is_none() {
                                return Err(Refusal::new(
                                    "portable inventory link target escapes the virtual root",
                                ));
                            }
                        }
                        name => {
                            let mut candidate = current.clone();
                            candidate.push(name.to_owned());
                            match self.kind_at(&candidate) {
                                NodeKind::Directory | NodeKind::File(_) => current = candidate,
                                NodeKind::Link(link) => {
                                    let path = candidate.join("/");
                                    self.enqueue_link(
                                        &path,
                                        link,
                                        &mut pending,
                                        &mut active_links,
                                    )?;
                                }
                                NodeKind::Missing => {
                                    return Err(Refusal::new(
                                        "portable inventory link target is broken",
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        match self.kind_at(&current) {
            NodeKind::File(file) => Ok(ResolvedNode::File { file }),
            NodeKind::Directory => Ok(ResolvedNode::Directory),
            NodeKind::Missing => Err(Refusal::new("portable inventory link target is broken")),
            NodeKind::Link(_) => Err(Refusal::new(
                "portable inventory link resolution ended at an unexpanded link",
            )),
        }
    }

    fn enqueue_link(
        &self,
        link_path: &str,
        link: &'a PortableLink,
        pending: &mut VecDeque<WorkItem>,
        active_links: &mut BTreeSet<String>,
    ) -> Result<()> {
        if !active_links.insert(link_path.to_owned()) {
            return Err(Refusal::new(
                "portable inventory contains a cyclic symbolic link",
            ));
        }

        let mut expanded: VecDeque<WorkItem> = parse_link_target(&link.target)?
            .into_iter()
            .map(WorkItem::Segment)
            .collect();
        expanded.push_back(WorkItem::EndLink(link_path.to_owned()));
        expanded.append(pending);
        *pending = expanded;
        Ok(())
    }

    fn kind_at(&self, path: &[String]) -> NodeKind<'a> {
        if path.is_empty() {
            return NodeKind::Directory;
        }
        let path = path.join("/");
        match self.entries.get(&path) {
            Some(Entry::File(file)) => NodeKind::File(file),
            Some(Entry::Link(link)) => NodeKind::Link(link),
            None if self.directories.contains(&path) => NodeKind::Directory,
            None => NodeKind::Missing,
        }
    }
}

fn validate_inventory_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || has_drive_prefix(path)
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Refusal::new(
            "portable inventory contains an unsafe relative path",
        ));
    }
    Ok(())
}

fn validate_link_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.starts_with('/')
        || has_drive_prefix(target)
        || target.contains('\\')
        || target.chars().any(char::is_control)
        || target.split('/').any(str::is_empty)
    {
        return Err(Refusal::new(
            "portable inventory contains an unsafe or absolute link target",
        ));
    }
    Ok(())
}

fn parse_link_target(target: &str) -> Result<VecDeque<String>> {
    validate_link_target(target)?;
    Ok(target.split('/').map(str::to_owned).collect())
}

fn has_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parent_components(path: &str) -> Vec<String> {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.split('/').map(str::to_owned).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{PortableFile, PortableLink, derive_portable_inventory};

    fn file(path: &str, bytes: u64, digest: u64, mode: Option<u32>) -> PortableFile {
        PortableFile {
            path: path.to_owned(),
            bytes,
            sha256: format!("{digest:064x}"),
            mode,
        }
    }

    fn link(path: &str, target: &str) -> PortableLink {
        PortableLink {
            path: path.to_owned(),
            target: target.to_owned(),
        }
    }

    fn administrative_files() -> Vec<PortableFile> {
        vec![
            file("lib/rustlib/components", 9, 9, Some(0o644)),
            file("lib/rustlib/rust-installer-version", 10, 10, Some(0o644)),
        ]
    }

    #[test]
    fn relocates_collector_bytes_next_to_its_fixed_llvm_siblings() {
        let mut files = administrative_files();
        let collector = file(super::COLLECTOR_SOURCE_PATH, 17, 42, Some(0o775));
        files.push(collector.clone());
        files.push(file("libexec/aros/llvm/bin/ld.lld", 19, 43, Some(0o755)));
        let view = derive_portable_inventory(&files, &[]).unwrap();
        assert_eq!(view.relocated_files.len(), 1);
        assert_eq!(view.relocated_files[0].original, collector);
        assert_eq!(
            view.relocated_files[0].destination,
            super::COLLECTOR_DESTINATION_PATH
        );
        assert!(
            !view
                .files
                .iter()
                .any(|row| row.path == super::COLLECTOR_SOURCE_PATH)
        );
        let output = view
            .files
            .iter()
            .find(|row| row.path == super::COLLECTOR_DESTINATION_PATH)
            .unwrap();
        assert_eq!(output.bytes, collector.bytes);
        assert_eq!(output.sha256, collector.sha256);
        assert_eq!(output.mode, Some(0o755));
    }

    #[test]
    fn refuses_collector_relocation_collisions_and_symlink_sources() {
        let descendant = format!("{}/child", super::COLLECTOR_DESTINATION_PATH);
        for collision in [
            super::COLLECTOR_DESTINATION_PATH,
            descendant.as_str(),
            "libexec/aros/llvm",
        ] {
            let mut files = administrative_files();
            files.push(file(super::COLLECTOR_SOURCE_PATH, 17, 42, Some(0o755)));
            files.push(file(collision, 1, 1, None));
            assert!(derive_portable_inventory(&files, &[]).is_err());
        }
        let mut files = administrative_files();
        files.push(file("bin/elsewhere", 17, 42, Some(0o755)));
        assert!(
            derive_portable_inventory(&files, &[link(super::COLLECTOR_SOURCE_PATH, "elsewhere")])
                .is_err()
        );
        files.push(file(super::COLLECTOR_SOURCE_PATH, 17, 42, Some(0o755)));
        assert!(
            derive_portable_inventory(
                &files,
                &[link(
                    super::COLLECTOR_DESTINATION_PATH,
                    "../../../../bin/elsewhere"
                )]
            )
            .is_err()
        );
    }

    #[test]
    fn resolves_link_chain_and_dotdot_preserving_bytes_and_declaring_output_modes() {
        let source = file("libexec/rust/bin/rustc", 4096, 123, Some(0o751));
        let mut files = administrative_files();
        files.push(source.clone());
        let links = vec![
            link("libexec/rust/current", "bin/../bin/rustc"),
            link("bin/rustc", "../libexec/rust/current"),
        ];

        let result = derive_portable_inventory(&files, &links).expect("valid view should derive");
        assert_eq!(result.omitted_files, administrative_files());
        assert_eq!(result.materialized_links.len(), 2);
        for path in ["bin/rustc", "libexec/rust/current"] {
            let copy = result.files.iter().find(|row| row.path == path).unwrap();
            assert_eq!(copy.bytes, source.bytes);
            assert_eq!(copy.sha256, source.sha256);
            assert_eq!(copy.mode, source.mode.map(super::normalize_portable_mode));
        }
        assert!(
            result
                .materialized_links
                .iter()
                .all(|row| row.resolved_file.path == source.path)
        );
        assert!(result.files.iter().all(|row| {
            row.path != "lib/rustlib/components" && row.path != "lib/rustlib/rust-installer-version"
        }));
    }

    #[test]
    fn output_is_deterministic_for_shuffled_input_rows() {
        let mut files = administrative_files();
        files.push(file("bin/one", 1, 11, Some(0o755)));
        files.push(file("lib/two", 2, 22, None));
        let links = vec![
            link("bin/alias-two", "../lib/two"),
            link("bin/alias-one", "one"),
        ];
        let mut shuffled_files = files.clone();
        shuffled_files.reverse();
        let mut shuffled_links = links.clone();
        shuffled_links.reverse();

        let first = derive_portable_inventory(&files, &links).expect("first view should derive");
        let second = derive_portable_inventory(&shuffled_files, &shuffled_links)
            .expect("shuffled view should derive");
        assert_eq!(first, second);
    }

    #[test]
    fn changing_a_virtual_target_changes_only_the_link_copy_and_resolution_record() {
        let mut files = administrative_files();
        files.push(file("bin/one", 1, 11, Some(0o755)));
        files.push(file("lib/two", 2, 22, Some(0o640)));
        files.push(file("share/keep", 3, 33, None));
        let first = derive_portable_inventory(&files, &[link("bin/alias", "one")])
            .expect("first target should derive");
        let second = derive_portable_inventory(&files, &[link("bin/alias", "../lib/two")])
            .expect("second target should derive");

        let first_copy = first
            .files
            .iter()
            .find(|row| row.path == "bin/alias")
            .unwrap();
        let second_copy = second
            .files
            .iter()
            .find(|row| row.path == "bin/alias")
            .unwrap();
        assert_ne!(first_copy, second_copy);
        assert_eq!(
            first
                .files
                .iter()
                .filter(|row| row.path != "bin/alias")
                .collect::<Vec<_>>(),
            second
                .files
                .iter()
                .filter(|row| row.path != "bin/alias")
                .collect::<Vec<_>>()
        );
        assert_eq!(first.materialized_links[0].resolved_file.path, "bin/one");
        assert_eq!(second.materialized_links[0].resolved_file.path, "lib/two");
        assert_eq!(first.omitted_files, second.omitted_files);
    }

    #[test]
    fn refuses_outside_broken_and_directory_targets() {
        let mut files = administrative_files();
        files.push(file("dir/member", 1, 1, None));
        assert!(derive_portable_inventory(&files, &[link("alias", "../outside")]).is_err());
        for target in ["missing", "dir"] {
            assert!(derive_portable_inventory(&files, &[link("alias", target)]).is_err());
        }
    }

    #[test]
    fn refuses_direct_and_indirect_link_cycles() {
        let files = administrative_files();
        assert!(derive_portable_inventory(&files, &[link("a", "a")]).is_err());
        assert!(derive_portable_inventory(&files, &[link("a", "b"), link("b", "a")]).is_err());
    }

    #[test]
    fn refuses_file_then_parent_or_child_traversal() {
        let mut files = administrative_files();
        files.push(file("node", 1, 1, None));
        for target in ["node/..", "node/child", "node/."] {
            assert!(derive_portable_inventory(&files, &[link("alias", target)]).is_err());
        }
    }

    #[test]
    fn refuses_missing_administrative_files_and_aliases_to_omitted_files() {
        let mut files = administrative_files();
        files.remove(0);
        assert!(derive_portable_inventory(&files, &[]).is_err());

        let files = administrative_files();
        assert!(
            derive_portable_inventory(
                &files,
                &[link("bin/components", "../lib/rustlib/components")]
            )
            .is_err()
        );
    }

    #[test]
    fn refuses_path_collisions_unsafe_paths_and_invalid_identities() {
        let mut files = administrative_files();
        files.push(file("bin/one", 1, 1, None));
        files.push(file("bin/one", 2, 2, None));
        assert!(derive_portable_inventory(&files, &[]).is_err());

        let mut files = administrative_files();
        files.push(file("node", 1, 1, None));
        files.push(file("node/child", 1, 1, None));
        assert!(derive_portable_inventory(&files, &[]).is_err());

        for path in [
            "../escape",
            "/absolute",
            "a//b",
            "a/./b",
            "a\\b",
            "bad\nname",
        ] {
            let mut files = administrative_files();
            files.push(file(path, 1, 1, None));
            assert!(derive_portable_inventory(&files, &[]).is_err());
        }
        for target in ["", "/absolute", "C:/outside", "a//b", "a\\b", "bad\nname"] {
            let files = administrative_files();
            assert!(derive_portable_inventory(&files, &[link("alias", target)]).is_err());
        }

        let mut files = administrative_files();
        files.push(PortableFile {
            path: "bin/bad-digest".to_owned(),
            bytes: 1,
            sha256: "A".repeat(64),
            mode: None,
        });
        assert!(derive_portable_inventory(&files, &[]).is_err());

        let mut files = administrative_files();
        files.push(file("bin/bad-mode", 1, 1, Some(0o10000)));
        assert!(derive_portable_inventory(&files, &[]).is_err());
    }

    #[test]
    fn rejects_link_path_overlap_and_targets_over_the_segment_limit() {
        let mut files = administrative_files();
        files.push(file("bin/same", 1, 1, None));
        assert!(derive_portable_inventory(&files, &[link("bin/same", "same")]).is_err());

        let files = administrative_files();
        let long_target = std::iter::repeat_n(".", 4097).collect::<Vec<_>>().join("/");
        assert!(derive_portable_inventory(&files, &[link("alias", &long_target)]).is_err());
    }
    #[test]
    fn accepts_unicode_names_and_refuses_traversal_through_a_file_alias() {
        let mut files = administrative_files();
        files.push(file("büro/datei", 7, 99, Some(0o644)));
        files.push(file("bin/exe", 9, 98, Some(0o755)));
        let links = [
            link("büro/kopie", "datei"),
            link("again", "bin/exe"),
            link("twice", "again/../again"),
        ];
        // The second traversal is invalid because `again` is a regular file;
        // completion of a link is not permission to traverse that file as a directory.
        assert!(derive_portable_inventory(&files, &links).is_err());
        let view = derive_portable_inventory(&files, &links[..2]).unwrap();
        assert_eq!(
            view.files
                .iter()
                .find(|f| f.path == "büro/kopie")
                .unwrap()
                .sha256,
            files[2].sha256
        );
    }
    #[test]
    fn permission_policy_is_explicit_and_idempotent_for_every_unix_mode() {
        for original in 0..=0o7777 {
            let derived = super::normalize_portable_mode(original);
            assert_eq!(derived & 0o700, original & 0o700);
            assert_eq!(super::normalize_portable_mode(derived), derived);
            assert_eq!(derived & 0o7022, 0);
        }
        assert_eq!(super::normalize_portable_mode(0o664), 0o644);
        assert_eq!(super::normalize_portable_mode(0o775), 0o755);
        assert_eq!(super::normalize_portable_mode(0o600), 0o644);
        assert_eq!(super::normalize_portable_mode(0o751), 0o755);
    }
    #[test]
    fn omits_only_exact_generated_root_aliases_and_retains_canonical_tools() {
        let mut files = administrative_files();
        files.push(file("libexec/aros/llvm/bin/llvm-ar", 1024, 88, Some(0o755)));
        let original = link("bin/llvm-ar", "../libexec/aros/llvm/bin/llvm-ar");
        let view = derive_portable_inventory(&files, std::slice::from_ref(&original)).unwrap();
        assert_eq!(view.omitted_generated_aliases.len(), 1);
        assert_eq!(view.omitted_generated_aliases[0].original, original);
        assert!(
            view.files
                .iter()
                .any(|row| row.path == "libexec/aros/llvm/bin/llvm-ar")
        );
        assert!(!view.files.iter().any(|row| row.path == "bin/llvm-ar"));
        assert!(derive_portable_inventory(&files, &[link("bin/llvm-ar", "other")]).is_err());
        files.push(file("bin/llvm-ar", 1024, 88, Some(0o755)));
        assert!(derive_portable_inventory(&files, &[]).is_err());
    }
}
