use super::{
    CsdkSourceFilePin, CsdkSourceMaterializationReceipt, CsdkSourceMaterializationRequest,
    materialize_csdk_source,
};
use flate2::{Compression, write::GzEncoder};
use lzma_rust2::{XzOptions, XzWriter};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tar::{Builder, EntryType, Header};

const CAPSULE_SCHEMA: &str = "ami-rust-csdk-corresponding-source-capsule-v1";
const NESTED_ARCHIVE_PATH: &str = "vendor/libaom/original/libaom-3.12.1.tar.gz";
const GENERATOR_SUFFIX: &str = "build/cmake/pkg_config.cmake";
const GENERATOR_BYTES: &[u8] = b"set(PKG_CONFIG \"configured\")\n";

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
enum Record {
    Directory {
        path: String,
        mode: u32,
    },
    File {
        path: String,
        bytes: Vec<u8>,
        mode: u32,
    },
    Symlink {
        path: String,
        target: String,
    },
}

impl Record {
    fn path(&self) -> &str {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } | Self::Symlink { path, .. } => {
                path
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CapsuleEdit {
    None,
    CorruptUnselected,
    UnsafePath,
    UnknownMember,
    DuplicateMember,
    MissingMember,
    SymlinkInsteadOfFile,
    DirectoryInsteadOfFile,
    WrongSize,
}

#[derive(Clone, Copy, Debug)]
enum NestedEdit {
    Valid,
    WrongGeneratorBytes,
    DuplicateGenerator,
    MissingGenerator,
    SymlinkGenerator,
}

#[derive(Clone, Copy, Debug)]
enum XzEdit {
    Valid,
    Truncated,
    DamagedFooter,
}

struct Fixture {
    root: PathBuf,
    capsule_path: PathBuf,
    manifest_path: PathBuf,
    destination: PathBuf,
    capsule_pin: CsdkSourceFilePin,
    manifest_pin: CsdkSourceFilePin,
    nested_archive_sha256: [u8; 32],
}

impl Fixture {
    fn new(
        capsule_edit: CapsuleEdit,
        nested_edit: NestedEdit,
        xz_edit: XzEdit,
        trailing_decoded_bytes: bool,
    ) -> Self {
        let root = unique_directory();
        let nested_archive = nested_archive(nested_edit);
        let expected_records = baseline_records(&nested_archive);
        let actual_records = edit_capsule_records(&expected_records, capsule_edit);
        let mut decoded_tar = tar_bytes(&actual_records);
        if trailing_decoded_bytes {
            decoded_tar.extend_from_slice(b"nonzero trailing decoded bytes");
        }
        let mut capsule_bytes = xz_bytes(&decoded_tar);
        match xz_edit {
            XzEdit::Valid => {}
            XzEdit::Truncated => {
                capsule_bytes.truncate(capsule_bytes.len().saturating_sub(5));
            }
            XzEdit::DamagedFooter => {
                let footer_crc_offset = capsule_bytes
                    .len()
                    .checked_sub(8)
                    .expect("XZ fixture has a footer");
                capsule_bytes[footer_crc_offset] ^= 0x80;
            }
        }

        let capsule_pin = CsdkSourceFilePin {
            bytes: capsule_bytes.len() as u64,
            sha256: sha256(&capsule_bytes),
        };
        let regular_member_bytes: u64 = expected_records
            .iter()
            .filter_map(|record| match record {
                Record::File { bytes, .. } => Some(bytes.len() as u64),
                Record::Directory { .. } | Record::Symlink { .. } => None,
            })
            .sum();
        let mut inventory = expected_records
            .iter()
            .map(inventory_row)
            .collect::<Vec<_>>();
        // Real source rows include optional Git provenance; generated rows do not.
        inventory
            .iter_mut()
            .find(|row| row["path"] == "sources/AROS-NX/readme.txt")
            .expect("tracked source fixture")["git_oid"] =
            json!("e76376eeb6fb7b2ec8a73777cc7eaa31f872dd46");
        let manifest_value = json!({
            "schema": CAPSULE_SCHEMA,
            "capsule": {
                "bytes": capsule_pin.bytes,
                "path": "csdk-corresponding-source.tar.xz",
                "sha256": hex(&capsule_pin.sha256)
            },
            "capsule_member_count": inventory.len(),
            "regular_member_bytes": regular_member_bytes,
            "inventory": inventory
        });
        let manifest_bytes =
            serde_json::to_vec(&manifest_value).expect("serialize fixture manifest");
        let manifest_pin = CsdkSourceFilePin {
            bytes: manifest_bytes.len() as u64,
            sha256: sha256(&manifest_bytes),
        };

        let capsule_path = root.join("csdk-corresponding-source.tar.xz");
        let manifest_path = root.join("spec.json");
        fs::write(&capsule_path, &capsule_bytes).expect("write source capsule fixture");
        fs::write(&manifest_path, manifest_bytes).expect("write source manifest fixture");

        Self {
            destination: root.join("materialized"),
            root,
            capsule_path,
            manifest_path,
            capsule_pin,
            manifest_pin,
            nested_archive_sha256: sha256(&nested_archive),
        }
    }

    fn request(&self) -> CsdkSourceMaterializationRequest {
        CsdkSourceMaterializationRequest {
            capsule: self.capsule_path.clone(),
            manifest: self.manifest_path.clone(),
            destination: self.destination.clone(),
            capsule_pin: self.capsule_pin,
            manifest_pin: self.manifest_pin,
            nested_archive_sha256: self.nested_archive_sha256,
            nested_generator_path: GENERATOR_SUFFIX.to_owned(),
            nested_generator_sha256: sha256(GENERATOR_BYTES),
        }
    }

    fn materialize(&self) -> crate::Result<CsdkSourceMaterializationReceipt> {
        materialize_csdk_source(self.request(), |_| Ok(()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove C-SDK source fixture");
    }
}

fn unique_directory() -> PathBuf {
    let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
    for _ in 0..100 {
        let number = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            ".ami-rust-csdk-source-test-{}-{number}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("secure fixture directory");
                return path;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("could not create C-SDK source fixture: {error}"),
        }
    }
    panic!("could not allocate a unique C-SDK source fixture");
}

fn baseline_records(nested_archive: &[u8]) -> Vec<Record> {
    let mut records = [
        "sources",
        "sources/AROS-NX",
        "sources/aros-tools",
        "sources/libaom",
        "generated",
        "recipes",
        "vendor",
        "vendor/libaom",
        "vendor/libaom/original",
        "evidence",
    ]
    .into_iter()
    .map(|path| Record::Directory {
        path: path.to_owned(),
        mode: 0o755,
    })
    .collect::<Vec<_>>();
    records.extend([
        file("sources/AROS-NX/readme.txt", b"AROS-NX source\n", 0o751),
        file("sources/aros-tools/build.sh", b"#!/bin/sh\n", 0o755),
        file("sources/libaom/seed.c", b"int seed;\n", 0o644),
        file("generated/autogen.h", b"#define GENERATED 1\n", 0o644),
        file("recipes/build.json", b"{\"step\":1}\n", 0o644),
        file(
            "evidence/unselected.bin",
            b"inventory says this is not selected\n",
            0o644,
        ),
        Record::File {
            path: NESTED_ARCHIVE_PATH.to_owned(),
            bytes: nested_archive.to_vec(),
            mode: 0o644,
        },
    ]);
    records
}

fn file(path: &str, bytes: &[u8], mode: u32) -> Record {
    Record::File {
        path: path.to_owned(),
        bytes: bytes.to_vec(),
        mode,
    }
}

fn edit_capsule_records(records: &[Record], edit: CapsuleEdit) -> Vec<Record> {
    let mut result = records.to_vec();
    match edit {
        CapsuleEdit::None => {}
        CapsuleEdit::CorruptUnselected => {
            let target = result
                .iter_mut()
                .find(|record| record.path() == "evidence/unselected.bin")
                .expect("unselected fixture member");
            let Record::File { bytes, .. } = target else {
                panic!("fixture evidence member is regular");
            };
            bytes[0] ^= 1;
        }
        CapsuleEdit::UnsafePath => result.push(file("../escape", b"outside", 0o644)),
        CapsuleEdit::UnknownMember => {
            result.push(file("evidence/unlisted.bin", b"unlisted", 0o644));
        }
        CapsuleEdit::DuplicateMember => {
            let duplicate = result
                .iter()
                .find(|record| record.path() == "sources/AROS-NX/readme.txt")
                .expect("selected fixture member")
                .clone();
            result.push(duplicate);
        }
        CapsuleEdit::MissingMember => {
            result.retain(|record| record.path() != "recipes/build.json");
        }
        CapsuleEdit::SymlinkInsteadOfFile => {
            replace_record(
                &mut result,
                "sources/AROS-NX/readme.txt",
                Record::Symlink {
                    path: "sources/AROS-NX/readme.txt".to_owned(),
                    target: "readme-target".to_owned(),
                },
            );
        }
        CapsuleEdit::DirectoryInsteadOfFile => {
            replace_record(
                &mut result,
                "sources/AROS-NX/readme.txt",
                Record::Directory {
                    path: "sources/AROS-NX/readme.txt".to_owned(),
                    mode: 0o755,
                },
            );
        }
        CapsuleEdit::WrongSize => {
            replace_record(
                &mut result,
                "sources/AROS-NX/readme.txt",
                file("sources/AROS-NX/readme.txt", b"x", 0o751),
            );
        }
    }
    result
}

fn replace_record(records: &mut [Record], path: &str, replacement: Record) {
    let slot = records
        .iter_mut()
        .find(|record| record.path() == path)
        .expect("fixture member to replace");
    *slot = replacement;
}

fn nested_archive(edit: NestedEdit) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    append_record(
        &mut builder,
        &file("libaom-3.12.1/README.md", b"nested unselected\n", 0o644),
    );
    match edit {
        NestedEdit::Valid | NestedEdit::DuplicateGenerator | NestedEdit::WrongGeneratorBytes => {
            let bytes = if matches!(edit, NestedEdit::WrongGeneratorBytes) {
                b"set(PKG_CONFIG \"wrong\")\n".as_slice()
            } else {
                GENERATOR_BYTES
            };
            append_record(
                &mut builder,
                &file(&format!("libaom-3.12.1/{GENERATOR_SUFFIX}"), bytes, 0o644),
            );
            if matches!(edit, NestedEdit::DuplicateGenerator) {
                append_record(
                    &mut builder,
                    &file(
                        &format!("libaom-3.12.1/{GENERATOR_SUFFIX}"),
                        GENERATOR_BYTES,
                        0o644,
                    ),
                );
            }
        }
        NestedEdit::MissingGenerator => {}
        NestedEdit::SymlinkGenerator => append_record(
            &mut builder,
            &Record::Symlink {
                path: format!("libaom-3.12.1/{GENERATOR_SUFFIX}"),
                target: "other.cmake".to_owned(),
            },
        ),
    }
    let tar_bytes = builder.into_inner().expect("finish nested libaom TAR");
    gzip_bytes(&tar_bytes)
}

fn tar_bytes(records: &[Record]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    for record in records {
        append_record(&mut builder, record);
    }
    builder.into_inner().expect("finish source capsule TAR")
}

fn append_record(builder: &mut Builder<Vec<u8>>, record: &Record) {
    match record {
        Record::Directory { path, mode } => {
            let mut header = header(*mode, 0, EntryType::Directory);
            builder
                .append_data(&mut header, format!("{path}/"), Cursor::new([]))
                .expect("append fixture directory");
        }
        Record::File { path, bytes, mode } if path == "../escape" => {
            let mut header = header(*mode, bytes.len() as u64, EntryType::Regular);
            let raw = header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..9].copy_from_slice(b"../escape");
            header.set_cksum();
            builder
                .append(&header, Cursor::new(bytes))
                .expect("append unsafe fixture path");
        }
        Record::File { path, bytes, mode } => {
            let mut header = header(*mode, bytes.len() as u64, EntryType::Regular);
            builder
                .append_data(&mut header, path, Cursor::new(bytes))
                .expect("append fixture file");
        }
        Record::Symlink { path, target } => {
            let mut header = header(0o777, 0, EntryType::Symlink);
            header
                .set_link_name(target)
                .expect("set fixture link target");
            builder
                .append_data(&mut header, path, Cursor::new([]))
                .expect("append fixture symbolic link");
        }
    }
}

fn header(mode: u32, size: u64, kind: EntryType) -> Header {
    let mut header = Header::new_gnu();
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1_700_000_000);
    header.set_size(size);
    header.set_entry_type(kind);
    header.set_cksum();
    header
}

fn inventory_row(record: &Record) -> Value {
    match record {
        Record::Directory { path, mode } => json!({
            "bytes": 0,
            "mode": mode,
            "origin": "synthetic-tree",
            "path": path,
            "type": "directory"
        }),
        Record::File { path, bytes, mode } => json!({
            "bytes": bytes.len(),
            "mode": mode,
            "origin": "synthetic-tree",
            "path": path,
            "sha256": hex(&sha256(bytes)),
            "type": "file"
        }),
        Record::Symlink { .. } => panic!("baseline inventory contains no links"),
    }
}

fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .expect("compress nested fixture TAR");
    encoder.finish().expect("finish nested gzip fixture")
}

fn xz_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut encoder =
        XzWriter::new(Vec::new(), XzOptions::with_preset(1)).expect("create fixture XZ encoder");
    encoder
        .write_all(bytes)
        .expect("compress source fixture TAR");
    encoder.finish().expect("finish source fixture XZ")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn selected_regular_bytes(records: &[Record]) -> u64 {
    records
        .iter()
        .filter_map(|record| match record {
            Record::File { path, bytes, .. }
                if path.starts_with("sources/")
                    || path.starts_with("generated/")
                    || path.starts_with("recipes/")
                    || path == NESTED_ARCHIVE_PATH =>
            {
                Some(bytes.len() as u64)
            }
            Record::Directory { .. } | Record::File { .. } | Record::Symlink { .. } => None,
        })
        .sum()
}

#[test]
fn materializes_selected_sources_and_nested_generator_with_declared_modes() {
    let fixture = Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, false);
    let expected_records = baseline_records(&nested_archive(NestedEdit::Valid));
    let receipt = fixture.materialize().expect("materialize valid fixture");

    assert_eq!(
        fs::read(fixture.destination.join("sources/AROS-NX/readme.txt")).unwrap(),
        b"AROS-NX source\n"
    );
    assert_eq!(
        fs::metadata(fixture.destination.join("sources/AROS-NX/readme.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o751
    );
    assert_eq!(
        fs::read(fixture.destination.join("generated/autogen.h")).unwrap(),
        b"#define GENERATED 1\n"
    );
    assert_eq!(
        fs::read(fixture.destination.join("recipes/build.json")).unwrap(),
        b"{\"step\":1}\n"
    );
    assert_eq!(
        fs::read(
            fixture
                .destination
                .join(format!("sources/libaom/{GENERATOR_SUFFIX}"))
        )
        .unwrap(),
        GENERATOR_BYTES
    );
    assert!(!fixture.destination.join("evidence/unselected.bin").exists());
    assert!(fixture.destination.join(NESTED_ARCHIVE_PATH).is_file());
    assert_eq!(
        receipt.roots.aros_nx,
        fixture.destination.join("sources/AROS-NX")
    );
    assert_eq!(
        receipt.roots.aros_tools,
        fixture.destination.join("sources/aros-tools")
    );
    assert_eq!(
        receipt.roots.libaom,
        fixture.destination.join("sources/libaom")
    );
    assert_eq!(
        receipt.receipt_value["all_capsule_members_verified"],
        expected_records.len()
    );
    assert_eq!(
        receipt.receipt_value["selected_regular_bytes"],
        selected_regular_bytes(&expected_records)
    );
}

#[test]
fn wrong_capsule_and_manifest_pins_refuse_before_destination_creation() {
    let fixture = Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, false);
    let mut wrong_capsule = fixture.request();
    wrong_capsule.capsule_pin.sha256[0] ^= 1;
    assert!(materialize_csdk_source(wrong_capsule, |_| Ok(())).is_err());
    assert!(!fixture.destination.exists());

    let mut wrong_manifest = fixture.request();
    wrong_manifest.manifest_pin.sha256[0] ^= 1;
    assert!(materialize_csdk_source(wrong_manifest, |_| Ok(())).is_err());
    assert!(!fixture.destination.exists());
}

#[test]
fn corrupt_unselected_member_is_checked_and_partial_tree_is_retained() {
    let fixture = Fixture::new(
        CapsuleEdit::CorruptUnselected,
        NestedEdit::Valid,
        XzEdit::Valid,
        false,
    );
    let error = fixture
        .materialize()
        .expect_err("corrupt member must refuse");
    assert!(error.to_string().contains("hash differs"));
    assert!(fixture.destination.is_dir());
    assert!(
        error
            .to_string()
            .contains(&fixture.destination.display().to_string())
    );
}

#[test]
fn unsafe_unknown_duplicate_and_missing_capsule_members_refuse() {
    for edit in [
        CapsuleEdit::UnsafePath,
        CapsuleEdit::UnknownMember,
        CapsuleEdit::DuplicateMember,
        CapsuleEdit::MissingMember,
    ] {
        let fixture = Fixture::new(edit, NestedEdit::Valid, XzEdit::Valid, false);
        assert!(
            fixture.materialize().is_err(),
            "capsule edit {edit:?} unexpectedly succeeded"
        );
        assert!(fixture.destination.is_dir());
    }
}

#[test]
fn linked_wrong_type_and_wrong_size_capsule_members_refuse() {
    for edit in [
        CapsuleEdit::SymlinkInsteadOfFile,
        CapsuleEdit::DirectoryInsteadOfFile,
        CapsuleEdit::WrongSize,
    ] {
        let fixture = Fixture::new(edit, NestedEdit::Valid, XzEdit::Valid, false);
        assert!(
            fixture.materialize().is_err(),
            "capsule edit {edit:?} unexpectedly succeeded"
        );
        assert!(fixture.destination.is_dir());
    }
}

#[test]
fn nested_archive_and_generator_pins_and_members_are_enforced() {
    let archive_pin_fixture =
        Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, false);
    let mut wrong_archive_pin = archive_pin_fixture.request();
    wrong_archive_pin.nested_archive_sha256[0] ^= 1;
    assert!(materialize_csdk_source(wrong_archive_pin, |_| Ok(())).is_err());
    assert!(!archive_pin_fixture.destination.exists());

    let generator_pin_fixture =
        Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, false);
    let mut wrong_generator_pin = generator_pin_fixture.request();
    wrong_generator_pin.nested_generator_sha256[0] ^= 1;
    assert!(materialize_csdk_source(wrong_generator_pin, |_| Ok(())).is_err());
    assert!(generator_pin_fixture.destination.is_dir());

    for edit in [
        NestedEdit::WrongGeneratorBytes,
        NestedEdit::DuplicateGenerator,
        NestedEdit::MissingGenerator,
        NestedEdit::SymlinkGenerator,
    ] {
        let fixture = Fixture::new(CapsuleEdit::None, edit, XzEdit::Valid, false);
        assert!(
            fixture.materialize().is_err(),
            "nested edit {edit:?} unexpectedly succeeded"
        );
        assert!(fixture.destination.is_dir());
    }
}

#[test]
fn cancellation_refuses_and_leaves_private_partial_root_for_recovery() {
    let fixture = Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, false);
    let mut member_checkpoints = 0;
    let error = materialize_csdk_source(fixture.request(), |label| {
        if label == "before source capsule member" {
            member_checkpoints += 1;
            if member_checkpoints == 12 {
                return Err(crate::Refusal::new("synthetic cancellation"));
            }
        }
        Ok(())
    })
    .expect_err("cancellation must stop materialization");
    assert!(error.to_string().contains("synthetic cancellation"));
    assert!(fixture.destination.is_dir());
    assert!(
        fixture
            .destination
            .join("sources/AROS-NX/readme.txt")
            .is_file()
    );
    assert!(
        error
            .to_string()
            .contains(&fixture.destination.display().to_string())
    );
}

#[test]
fn truncated_and_checksum_damaged_xz_streams_refuse() {
    for edit in [XzEdit::Truncated, XzEdit::DamagedFooter] {
        let fixture = Fixture::new(CapsuleEdit::None, NestedEdit::Valid, edit, false);
        assert!(fixture.materialize().is_err(), "XZ edit {edit:?} succeeded");
        assert!(fixture.destination.is_dir());
    }
}

#[test]
fn nonzero_decoded_content_after_tar_end_marker_refuses() {
    let fixture = Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, true);
    assert!(fixture.materialize().is_err());
    assert!(fixture.destination.is_dir());
}

#[test]
fn malformed_optional_git_provenance_refuses_before_output_creation() {
    let fixture = Fixture::new(CapsuleEdit::None, NestedEdit::Valid, XzEdit::Valid, false);
    let mut value: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest_path).unwrap()).unwrap();
    value["inventory"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["path"] == "sources/AROS-NX/readme.txt")
        .unwrap()["git_oid"] = json!("invalid");
    let raw = serde_json::to_vec(&value).unwrap();
    fs::write(&fixture.manifest_path, &raw).unwrap();
    let mut request = fixture.request();
    request.manifest_pin = CsdkSourceFilePin {
        bytes: raw.len() as u64,
        sha256: sha256(&raw),
    };
    let error = materialize_csdk_source(request, |_| Ok(())).unwrap_err();
    assert!(error.to_string().contains("Git object identity is invalid"));
    assert!(!fixture.destination.exists());
}
