use super::{CsdkStagingReceipt, CsdkStagingRequest, stage_original_csdk};
use crate::{
    Refusal, component_archive::ArchiveLimits, csdk_source::CsdkSourceFilePin,
    digest::sha256_bytes, inventory::FileIdentity,
};
use lzma_rust2::{XzOptions, XzWriter};
use std::{
    fs,
    io::{Cursor, Write},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tar::{Builder, EntryType, Header};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let base = std::env::current_dir().expect("test working directory");
        for _ in 0..100 {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                ".ami-rust-csdk-staging-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("set fixture mode");
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create staging fixture: {error}"),
            }
        }
        panic!("could not allocate a unique staging fixture");
    }

    fn request(
        &self,
        name: &str,
        compressed_archive: &[u8],
        profile: Vec<FileIdentity>,
    ) -> CsdkStagingRequest {
        let archive = self.0.join(format!("{name}.txz"));
        fs::write(&archive, compressed_archive).expect("write XZ archive fixture");
        let digest = sha256_bytes(compressed_archive);
        let sha256 = (0..32)
            .map(|index| u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        CsdkStagingRequest {
            archive,
            archive_pin: CsdkSourceFilePin {
                bytes: compressed_archive.len() as u64,
                sha256: sha256.try_into().expect("SHA-256 has 32 bytes"),
            },
            profile,
            destination: self.0.join(name),
            limits: limits(compressed_archive.len() as u64),
        }
    }

    fn stage(
        &self,
        name: &str,
        compressed_archive: &[u8],
        profile: Vec<FileIdentity>,
    ) -> crate::Result<CsdkStagingReceipt> {
        stage_original_csdk(self.request(name, compressed_archive, profile), |_| Ok(()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove staging fixture");
    }
}

fn limits(compressed_bytes: u64) -> ArchiveLimits {
    ArchiveLimits {
        max_compressed_bytes: compressed_bytes.max(1),
        max_decoded_tar_bytes: 8 * 1024 * 1024,
        max_expanded_bytes: 4 * 1024 * 1024,
        max_file_bytes: 2 * 1024 * 1024,
        max_members: 128,
        max_index_bytes: 1024 * 1024,
        max_path_bytes: 1024,
        max_path_components: 32,
        max_extension_bytes: 64 * 1024,
        current_workspace_bytes: 0,
        max_workspace_bytes: 16 * 1024 * 1024,
        xz_memory_limit_kib: 64 * 1024,
    }
}

fn identity(path: &str, bytes: &[u8]) -> FileIdentity {
    let digest = sha256_bytes(bytes);
    FileIdentity {
        path: path.to_owned(),
        bytes: bytes.len() as u64,
        sha256: digest,
        mode: None,
    }
}

fn file_record(builder: &mut Builder<Vec<u8>>, path: &str, bytes: &[u8], mode: u32) {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_entry_type(EntryType::Regular);
    builder
        .append_data(&mut header, path, Cursor::new(bytes))
        .expect("append regular C-SDK fixture file");
}

fn link_record(builder: &mut Builder<Vec<u8>>, path: &str, target: &str, kind: EntryType) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(kind);
    header
        .set_link_name(target)
        .expect("set fixture link target");
    builder
        .append_data(&mut header, path, Cursor::new([]))
        .expect("append C-SDK fixture link");
}

fn archive(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    for (path, bytes, mode) in files {
        file_record(&mut builder, path, bytes, *mode);
    }
    builder.into_inner().expect("finish fixture TAR")
}

fn xz(tar: &[u8]) -> Vec<u8> {
    let mut writer =
        XzWriter::new(Vec::new(), XzOptions::with_preset(1)).expect("create XZ fixture encoder");
    writer.write_all(tar).expect("write TAR into XZ fixture");
    writer.finish().expect("finish XZ fixture")
}

fn assert_retained_failure(result: crate::Result<CsdkStagingReceipt>, destination: &Path) {
    let error = result.expect_err("staging should be rejected").to_string();
    assert!(error.contains("unaccepted original C-SDK staging container"));
    assert!(error.contains(&destination.display().to_string()));
    assert!(destination.is_dir(), "failed staging container is retained");
}

#[test]
fn extracts_exact_xz_profile_and_preserves_original_file_modes() {
    let fixture = Fixture::new();
    let tar = archive(&[
        ("Developer/include/sample.h", b"header\n", 0o640),
        ("Developer/bin/tool", b"binary\0data", 0o751),
    ]);
    let compressed = xz(&tar);
    let profile = vec![
        identity("include/sample.h", b"header\n"),
        identity("bin/tool", b"binary\0data"),
    ];
    let receipt = fixture
        .stage("valid", &compressed, profile)
        .expect("valid original C-SDK should stage");
    let expected_developer = fixture.0.join("valid/archive/Developer");
    assert_eq!(receipt.developer, expected_developer);
    assert_eq!(receipt.files, 2);
    assert_eq!(receipt.file_bytes, 18);
    assert_eq!(receipt.modes.get("include/sample.h"), Some(&0o640));
    assert_eq!(receipt.modes.get("bin/tool"), Some(&0o751));
    assert_eq!(
        fs::read(receipt.developer.join("include/sample.h")).unwrap(),
        b"header\n"
    );
    assert_eq!(
        fs::read(receipt.developer.join("bin/tool")).unwrap(),
        b"binary\0data"
    );
    assert_eq!(
        fs::metadata(receipt.developer.join("include/sample.h"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(receipt.developer.join("bin/tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o751
    );
    assert!(!fixture.0.join("valid/Developer").exists());
}

#[test]
fn rejects_altered_missing_and_extra_profile_rows_and_retains_extracted_output() {
    let fixture = Fixture::new();
    let tar = archive(&[
        ("Developer/a", b"alpha", 0o644),
        ("Developer/sub/b", b"beta", 0o600),
    ]);
    let compressed = xz(&tar);
    let valid_a = identity("a", b"alpha");
    let valid_b = identity("sub/b", b"beta");

    let mut altered = valid_a.clone();
    altered.sha256 = sha256_bytes(b"other");
    let destination = fixture.0.join("altered");
    assert_retained_failure(
        fixture.stage("altered", &compressed, vec![altered, valid_b.clone()]),
        &destination,
    );
    assert!(destination.join("archive/Developer/a").is_file());

    let destination = fixture.0.join("missing");
    assert_retained_failure(
        fixture.stage("missing", &compressed, vec![valid_a.clone()]),
        &destination,
    );

    let destination = fixture.0.join("extra");
    assert_retained_failure(
        fixture.stage(
            "extra",
            &compressed,
            vec![valid_a, valid_b, identity("ghost", b"none")],
        ),
        &destination,
    );
}

#[test]
fn rejects_unsafe_duplicate_ancestor_and_mode_bearing_profiles_before_staging() {
    let fixture = Fixture::new();
    let compressed = xz(&archive(&[("Developer/a", b"a", 0o644)]));

    let mut request = fixture.request(
        "unsafe-profile",
        &compressed,
        vec![identity("../escape", b"a")],
    );
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());

    let row = identity("a", b"a");
    request = fixture.request("duplicate-profile", &compressed, vec![row.clone(), row]);
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());

    request = fixture.request(
        "ancestor-profile",
        &compressed,
        vec![
            identity("include", b"file"),
            identity("include/a.h", b"header"),
        ],
    );
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());

    let mut row = identity("a", b"a");
    row.mode = Some(0o644);
    request = fixture.request("mode-profile", &compressed, vec![row]);
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());
}

#[test]
fn rejects_wrong_archive_pin_and_wrong_root_with_retained_path_diagnostics() {
    let fixture = Fixture::new();
    let compressed = xz(&archive(&[("Developer/a", b"a", 0o644)]));
    let mut request = fixture.request("wrong-pin", &compressed, vec![identity("a", b"a")]);
    request.archive_pin.sha256 = [0; 32];
    let destination = request.destination.clone();
    assert_retained_failure(stage_original_csdk(request, |_| Ok(())), &destination);

    let wrong_root = xz(&archive(&[("Other/a", b"a", 0o644)]));
    let destination = fixture.0.join("wrong-root");
    assert_retained_failure(
        fixture.stage("wrong-root", &wrong_root, vec![identity("a", b"a")]),
        &destination,
    );
    assert!(destination.join("archive/Other/a").is_file());
}

#[test]
fn rejects_symlinks_and_hardlinks_in_the_original_profile_tree() {
    let fixture = Fixture::new();
    let mut builder = Builder::new(Vec::new());
    file_record(&mut builder, "Developer/a", b"same", 0o644);
    link_record(&mut builder, "Developer/alias", "a", EntryType::Symlink);
    let compressed = xz(&builder.into_inner().unwrap());
    let destination = fixture.0.join("symlink");
    assert_retained_failure(
        fixture.stage("symlink", &compressed, vec![identity("a", b"same")]),
        &destination,
    );

    let mut builder = Builder::new(Vec::new());
    file_record(&mut builder, "Developer/a", b"same", 0o644);
    link_record(&mut builder, "Developer/b", "Developer/a", EntryType::Link);
    let compressed = xz(&builder.into_inner().unwrap());
    let destination = fixture.0.join("hardlink");
    assert_retained_failure(
        fixture.stage(
            "hardlink",
            &compressed,
            vec![identity("a", b"same"), identity("b", b"same")],
        ),
        &destination,
    );
}

#[test]
fn preserves_an_existing_destination_and_its_contents() {
    let fixture = Fixture::new();
    let compressed = xz(&archive(&[("Developer/a", b"a", 0o644)]));
    let request = fixture.request("occupied", &compressed, vec![identity("a", b"a")]);
    fs::create_dir(&request.destination).unwrap();
    fs::write(request.destination.join("marker"), b"keep").unwrap();

    let error = stage_original_csdk(request, |_| Ok(())).unwrap_err();
    assert!(
        !error
            .to_string()
            .contains("unaccepted original C-SDK staging container")
    );
    assert_eq!(
        fs::read(fixture.0.join("occupied/marker")).unwrap(),
        b"keep"
    );
    assert!(!fixture.0.join("occupied/archive").exists());
}

#[test]
fn rejects_relative_parent_and_symlinked_input_paths() {
    let fixture = Fixture::new();
    let compressed = xz(&archive(&[("Developer/a", b"a", 0o644)]));

    let mut request = fixture.request("relative-input", &compressed, vec![identity("a", b"a")]);
    request.archive = PathBuf::from("relative.txz");
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());

    let mut request = fixture.request("parent-input", &compressed, vec![identity("a", b"a")]);
    request.archive = fixture.0.join("../parent.txz");
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());

    let mut request = fixture.request("symlink-input", &compressed, vec![identity("a", b"a")]);
    let linked_archive = fixture.0.join("linked.txz");
    symlink(&request.archive, &linked_archive).unwrap();
    request.archive = linked_archive;
    let destination = request.destination.clone();
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!destination.exists());

    let mut request = fixture.request("symlink-parent", &compressed, vec![identity("a", b"a")]);
    let linked_parent = fixture.0.join("linked-parent");
    symlink(&fixture.0, &linked_parent).unwrap();
    request.destination = linked_parent.join("stage");
    assert!(stage_original_csdk(request, |_| Ok(())).is_err());
    assert!(!fixture.0.join("stage").exists());
}

#[test]
fn cancellation_and_path_replacement_refuse_unaccepted_output() {
    let fixture = Fixture::new();
    let compressed = xz(&archive(&[("Developer/a", b"a", 0o644)]));
    let request = fixture.request("cancelled", &compressed, vec![identity("a", b"a")]);
    let destination = request.destination.clone();
    let result = stage_original_csdk(request, |label| {
        if label == "verifying original C-SDK file profile" {
            Err(Refusal::new("cancelled by test"))
        } else {
            Ok(())
        }
    });
    assert_retained_failure(result, &destination);
    assert!(destination.join("archive/Developer/a").is_file());

    let request = fixture.request("replaced", &compressed, vec![identity("a", b"a")]);
    let destination = request.destination.clone();
    let moved = fixture.0.join("replaced-retained");
    let result = stage_original_csdk(request, |label| {
        if label == "finishing original C-SDK staging" {
            fs::rename(&destination, &moved).expect("move staged container during checkpoint");
            fs::create_dir(&destination).expect("install replacement at staging path");
        }
        Ok(())
    });
    let error = result
        .expect_err("path replacement must prevent a receipt")
        .to_string();
    assert!(error.contains("retained unaccepted C-SDK staging no longer matches its path"));
    assert!(error.contains(&destination.display().to_string()));
    assert!(moved.join("archive/Developer/a").is_file());
}
