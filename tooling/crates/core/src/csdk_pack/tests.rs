use super::{CsdkPackLimits, CsdkPackRequest, pack_csdk};
use crate::{Refusal, digest::sha256_bytes, inventory::FileIdentity};
use lzma_rust2::XzReader;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let base = std::env::current_dir().expect("test working directory");
        for _ in 0..100 {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                ".ami-rust-csdk-pack-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        .expect("set fixture mode");
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create C-SDK pack fixture: {error}"),
            }
        }
        panic!("could not allocate a unique C-SDK pack fixture");
    }

    fn developer(&self) -> PathBuf {
        let developer = self.0.join("Developer");
        fs::create_dir_all(developer.join("include")).expect("create include directory");
        fs::create_dir_all(developer.join("lib")).expect("create lib directory");
        fs::write(developer.join("include/a.h"), b"#define A 1\n").expect("write header");
        fs::write(developer.join("lib/tool"), b"\0tool-binary").expect("write tool");
        fs::set_permissions(
            developer.join("include/a.h"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("set header mode");
        fs::set_permissions(
            developer.join("lib/tool"),
            fs::Permissions::from_mode(0o755),
        )
        .expect("set tool mode");
        developer
    }

    fn request(&self, name: &str) -> CsdkPackRequest {
        let developer = self.developer();
        request_for(&developer, self.0.join(name))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove C-SDK pack fixture");
    }
}

fn request_for(developer: &Path, destination: PathBuf) -> CsdkPackRequest {
    let header = b"#define A 1\n";
    let tool = b"\0tool-binary";
    CsdkPackRequest {
        developer: developer.to_owned(),
        destination,
        profile: vec![identity("include/a.h", header), identity("lib/tool", tool)],
        modes: BTreeMap::from([
            ("include/a.h".to_owned(), 0o644),
            ("lib/tool".to_owned(), 0o755),
        ]),
        limits: limits(),
    }
}

fn identity(path: &str, bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        path: path.to_owned(),
        bytes: bytes.len() as u64,
        sha256: sha256_bytes(bytes),
        mode: None,
    }
}

fn limits() -> CsdkPackLimits {
    CsdkPackLimits {
        max_files: 16,
        max_file_bytes: 1024 * 1024,
        max_payload_bytes: 2 * 1024 * 1024,
        max_tar_bytes: 64 * 1024,
        max_archive_bytes: 2 * 1024 * 1024,
    }
}

fn pack(request: CsdkPackRequest) -> crate::Result<super::CsdkPackReceipt> {
    pack_csdk(request, |_| Ok(()))
}

fn assert_refused_before_output(request: CsdkPackRequest) {
    let destination = request.destination.clone();
    assert!(pack(request).is_err());
    assert!(
        !destination.exists(),
        "preflight refusal created an archive"
    );
}

fn decode(path: &Path) -> Vec<u8> {
    let input = fs::File::open(path).expect("open produced archive");
    let mut xz = XzReader::new_mem_limit(input, true, 64 * 1024);
    let mut decoded = Vec::new();
    xz.read_to_end(&mut decoded).expect("decode produced XZ");
    decoded
}

fn assert_retained_refusal(result: crate::Result<super::CsdkPackReceipt>, path: &Path) {
    let error = result
        .expect_err("producer should refuse the request")
        .to_string();
    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(
        error.contains("unaccepted C-SDK archive retained"),
        "{error}"
    );
    assert!(
        path.exists(),
        "unaccepted archive remains at its exact path"
    );
}

#[test]
fn writes_sorted_regular_ustar_members_with_original_modes_and_record_padding() {
    let fixture = Fixture::new();
    let mut request = fixture.request("result.tar.xz");
    request.profile.reverse();
    let output = request.destination.clone();
    let receipt = pack(request).expect("produce canonical C-SDK archive");
    let decoded = decode(&output);
    let compressed = fs::read(&output).expect("read produced archive bytes");

    assert_eq!(receipt.archive.bytes, compressed.len() as u64);
    let archive_sha256: [u8; 32] = Sha256::digest(&compressed).into();
    assert_eq!(receipt.archive.sha256, archive_sha256);
    assert_eq!(receipt.files, 2);
    assert_eq!(
        receipt.file_bytes,
        b"#define A 1\n".len() as u64 + b"\0tool-binary".len() as u64
    );
    assert_eq!(receipt.decoded_tar.bytes, decoded.len() as u64);
    let decoded_sha256: [u8; 32] = Sha256::digest(&decoded).into();
    assert_eq!(receipt.decoded_tar.sha256, decoded_sha256);
    assert_eq!(decoded.len() as u64 % 10_240, 0);

    let mut archive = tar::Archive::new(Cursor::new(decoded.as_slice()));
    let mut members = Vec::new();
    let mut offset = 0_usize;
    for entry in archive.entries().expect("read produced TAR entries") {
        assert_eq!(decoded[offset + 156], b'0');
        let mut entry = entry.expect("read TAR entry");
        let header = entry.header();
        let raw = header.as_bytes();
        assert!(
            raw[148..154]
                .iter()
                .all(|byte| (b'0'..=b'7').contains(byte))
        );
        assert_eq!(&raw[154..156], b"\0 ");
        assert_eq!(raw[156], b'0');
        assert_eq!(&raw[257..263], b"ustar\0");
        assert_eq!(&raw[263..265], b"00");
        assert!(raw[157..257].iter().all(|byte| *byte == 0));
        assert!(raw[265..329].iter().all(|byte| *byte == 0));
        assert!(raw[345..512].iter().all(|byte| *byte == 0));
        assert_eq!(header.uid().expect("read member UID"), 0);
        assert_eq!(header.gid().expect("read member GID"), 0);
        assert_eq!(header.mtime().expect("read member mtime"), 0);
        assert!(raw[329..345].iter().all(|byte| *byte == 0));
        assert_eq!(header.entry_type(), tar::EntryType::Regular);
        let path = entry
            .path()
            .expect("decode USTAR path")
            .to_str()
            .expect("ASCII path")
            .to_owned();
        let mode = header.mode().expect("read member mode");

        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("read member payload");
        let data_start = offset + 512;
        let padded_data_end = data_start + bytes.len().div_ceil(512) * 512;
        assert!(
            decoded[data_start + bytes.len()..padded_data_end]
                .iter()
                .all(|byte| *byte == 0)
        );
        members.push((path, mode, bytes));
        offset = padded_data_end;
    }
    assert_eq!(
        members,
        vec![
            (
                "Developer/include/a.h".to_owned(),
                0o644,
                b"#define A 1\n".to_vec()
            ),
            (
                "Developer/lib/tool".to_owned(),
                0o755,
                b"\0tool-binary".to_vec()
            )
        ]
    );
    assert!(decoded[offset..].len() >= 2 * 512);
    assert!(decoded[offset..].iter().all(|byte| *byte == 0));
}

#[test]
fn does_not_add_an_extra_record_when_two_end_blocks_already_align() {
    let fixture = Fixture::new();
    let developer = fixture.path().join("Developer");
    fs::create_dir(&developer).unwrap();
    let payload = vec![b'x'; 17 * 512];
    fs::write(developer.join("body"), &payload).unwrap();
    fs::set_permissions(developer.join("body"), fs::Permissions::from_mode(0o644)).unwrap();
    let output = fixture.path().join("aligned.tar.xz");
    let receipt = pack(CsdkPackRequest {
        developer,
        destination: output.clone(),
        profile: vec![identity("body", &payload)],
        modes: BTreeMap::from([("body".to_owned(), 0o644)]),
        limits: limits(),
    })
    .unwrap();
    let decoded = decode(&output);
    assert_eq!(receipt.decoded_tar.bytes, 10_240);
    assert_eq!(decoded.len(), 10_240);
    assert!(decoded[18 * 512..].iter().all(|byte| *byte == 0));
}

#[test]
fn identical_inputs_in_two_roots_produce_identical_archive_bytes() {
    let first = Fixture::new();
    let second = Fixture::new();
    let first_request = first.request("first.tar.xz");
    let second_request = second.request("second.tar.xz");
    let first_output = first_request.destination.clone();
    let second_output = second_request.destination.clone();

    pack(first_request).expect("produce first archive");
    pack(second_request).expect("produce second archive");

    assert_eq!(
        fs::read(first_output).expect("read first archive"),
        fs::read(second_output).expect("read second archive")
    );
}

#[test]
fn refuses_altered_missing_extra_and_wrong_mode_inputs_before_output() {
    let fixture = Fixture::new();
    let mut altered = fixture.request("altered.tar.xz");
    altered.profile[0].sha256 = sha256_bytes(b"different");
    assert_refused_before_output(altered);

    let missing = Fixture::new();
    let request = missing.request("missing.tar.xz");
    fs::remove_file(request.developer.join("include/a.h")).expect("remove profile file");
    assert_refused_before_output(request);

    let extra = Fixture::new();
    let request = extra.request("extra.tar.xz");
    fs::write(request.developer.join("extra"), b"unlisted").expect("write extra file");
    assert_refused_before_output(request);

    let wrong_mode = Fixture::new();
    let mut request = wrong_mode.request("mode.tar.xz");
    request.modes.insert("include/a.h".to_owned(), 0o600);
    assert_refused_before_output(request);

    let missing_mode = Fixture::new();
    let mut request = missing_mode.request("missing-mode.tar.xz");
    request.modes.remove("include/a.h");
    assert_refused_before_output(request);

    let extra_mode = Fixture::new();
    let mut request = extra_mode.request("extra-mode.tar.xz");
    request.modes.insert("unlisted".to_owned(), 0o644);
    assert_refused_before_output(request);
}

#[test]
fn refuses_unsafe_long_and_non_ascii_profile_paths() {
    let fixture = Fixture::new();
    let mut non_ascii = fixture.request("non-ascii.tar.xz");
    non_ascii.profile[0].path = "include/résumé.h".to_owned();
    non_ascii.modes.clear();
    non_ascii.modes.insert("include/résumé.h".to_owned(), 0o644);
    assert_refused_before_output(non_ascii);

    let long = Fixture::new();
    let mut request = long.request("long.tar.xz");
    request.profile[0].path = format!("include/{}", "x".repeat(100));
    request.modes.clear();
    request.modes.insert(request.profile[0].path.clone(), 0o644);
    assert_refused_before_output(request);

    let unsafe_path = Fixture::new();
    let mut request = unsafe_path.request("unsafe.tar.xz");
    request.profile[0].path = "../escape".to_owned();
    request.modes.clear();
    request.modes.insert("../escape".to_owned(), 0o644);
    assert_refused_before_output(request);
}

#[test]
fn refuses_source_symlinks_and_hardlinked_regular_files() {
    let symlink_fixture = Fixture::new();
    let symlink_request = symlink_fixture.request("symlink.tar.xz");
    fs::remove_file(symlink_request.developer.join("include/a.h")).expect("remove regular file");
    symlink("lib/tool", symlink_request.developer.join("include/a.h"))
        .expect("create source symlink");
    assert_refused_before_output(symlink_request);

    let hardlink_fixture = Fixture::new();
    let mut hardlink_request = hardlink_fixture.request("hardlink.tar.xz");
    fs::remove_file(hardlink_request.developer.join("include/a.h")).expect("remove header");
    fs::hard_link(
        hardlink_request.developer.join("lib/tool"),
        hardlink_request.developer.join("include/a.h"),
    )
    .expect("create hardlinked profile file");
    hardlink_request.profile[0] = identity("include/a.h", b"\0tool-binary");
    hardlink_request
        .modes
        .insert("include/a.h".to_owned(), 0o755);
    assert_refused_before_output(hardlink_request);
}

#[test]
fn refuses_overlapping_or_existing_destination_without_replacing_it() {
    let overlap = Fixture::new();
    let developer = overlap.developer();
    let request = request_for(&developer, developer.join("archive.tar.xz"));
    assert_refused_before_output(request);

    let existing = Fixture::new();
    let request = existing.request("existing.tar.xz");
    fs::write(&request.destination, b"preserve existing").expect("create existing output");
    let destination = request.destination.clone();
    assert!(pack(request).is_err());
    assert_eq!(
        fs::read(destination).expect("read existing output"),
        b"preserve existing"
    );
}

#[test]
fn retains_output_on_cancellation_and_archive_byte_bound_failure() {
    let cancelled = Fixture::new();
    let request = cancelled.request("cancelled.tar.xz");
    let destination = request.destination.clone();
    let result = pack_csdk(request, |label| {
        if label == "writing decoded C-SDK TAR" {
            Err(Refusal::new("cancelled by test"))
        } else {
            Ok(())
        }
    });
    assert_retained_refusal(result, &destination);

    let bounded = Fixture::new();
    let mut request = bounded.request("bounded.tar.xz");
    request.limits.max_archive_bytes = 1;
    let destination = request.destination.clone();
    assert_retained_refusal(pack(request), &destination);

    let tar_bounded = Fixture::new();
    let mut request = tar_bounded.request("tar-bounded.tar.xz");
    request.limits.max_tar_bytes = 1;
    let destination = request.destination.clone();
    assert_retained_refusal(pack(request), &destination);
}

#[test]
fn refuses_source_and_output_pathname_replacement_before_receipt() {
    let replaced_source = Fixture::new();
    let request = replaced_source.request("source-replaced.tar.xz");
    let developer = request.developer.clone();
    let moved_developer = replaced_source.path().join("Developer-retained");
    let result = pack_csdk(request, |label| {
        if label == "final C-SDK identity checkpoint" {
            fs::rename(&developer, &moved_developer)
                .map_err(|error| Refusal::new(format!("could not move source fixture: {error}")))?;
            fs::create_dir(&developer).map_err(|error| {
                Refusal::new(format!("could not replace source fixture: {error}"))
            })?;
        }
        Ok(())
    });
    assert_retained_refusal(
        result,
        &replaced_source.path().join("source-replaced.tar.xz"),
    );

    let replaced_output = Fixture::new();
    let request = replaced_output.request("output-replaced.tar.xz");
    let destination = request.destination.clone();
    let moved_output = replaced_output.path().join("archive-retained.tar.xz");
    let mut replaced = false;
    let result = pack_csdk(request, |label| {
        if label == "final C-SDK identity checkpoint" && !replaced {
            fs::rename(&destination, &moved_output).map_err(|error| {
                Refusal::new(format!("could not move archive fixture: {error}"))
            })?;
            fs::write(&destination, b"replacement").map_err(|error| {
                Refusal::new(format!("could not replace archive fixture: {error}"))
            })?;
            replaced = true;
        }
        Ok(())
    });
    assert_retained_refusal(result, &destination);
    assert!(moved_output.exists());
}

#[test]
fn enforces_profile_count_file_and_payload_limits_before_output() {
    let fixture = Fixture::new();
    let mut too_many = fixture.request("too-many.tar.xz");
    too_many.limits.max_files = 1;
    assert_refused_before_output(too_many);

    let per_file = Fixture::new();
    let mut too_large = per_file.request("per-file.tar.xz");
    too_large.limits.max_file_bytes = 1;
    assert_refused_before_output(too_large);

    let payload = Fixture::new();
    let mut too_much_payload = payload.request("payload.tar.xz");
    too_much_payload.limits.max_payload_bytes = 1;
    assert_refused_before_output(too_much_payload);
}

#[test]
fn refuses_same_length_output_rewrite_at_final_checkpoint() {
    let fixture = Fixture::new();
    let request = fixture.request("same-inode-rewrite.tar.xz");
    let destination = request.destination.clone();
    let mut rewritten = false;
    let result = pack_csdk(request, |label| {
        if label == "final C-SDK identity checkpoint" {
            let mut bytes = fs::read(&destination)?;
            assert!(!bytes.is_empty());
            bytes[0] ^= 1;
            fs::write(&destination, bytes)?;
            rewritten = true;
        }
        Ok(())
    });
    assert!(rewritten, "the counter must reach the completed output");
    let error = result.expect_err("changed output must not receive an old identity");
    assert!(
        error
            .to_string()
            .contains("archive bytes changed after production")
    );
    assert!(
        error
            .to_string()
            .contains("unaccepted C-SDK archive retained")
    );
    assert!(destination.is_file());
}
