use super::*;
use crate::{
    digest::sha256_bytes,
    publisher_metadata::{AuthenticationMetadata, DeclaredWorkflowRun},
    publisher_policy::parse_publisher_policy,
    records::Host,
    release_manifest::{parse_native_release_manifest, parse_release_manifest},
    workflow_counter::PositiveCounter,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureDir(PathBuf);

impl FixtureDir {
    fn new() -> Self {
        let cwd = fs::canonicalize(std::env::current_dir().expect("current directory"))
            .expect("canonical current directory");
        for _ in 0..100 {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = cwd.join(format!(
                ".ami-rust-publisher-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, Permissions::from_mode(0o700))
                        .expect("make fixture directory private");
                    assert_eq!(
                        fs::metadata(&path).expect("fixture metadata").mode() & 0o7777,
                        0o700
                    );
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create publisher fixture directory: {error}"),
            }
        }
        panic!("could not allocate a unique publisher fixture directory");
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn subdir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir(&path).expect("create fixture subdirectory");
        fs::set_permissions(&path, Permissions::from_mode(0o700))
            .expect("make fixture subdirectory private");
        path
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove publisher fixture directory");
    }
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create publisher fixture file");
    file.write_all(bytes).expect("write publisher fixture file");
    drop(file);
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("set fixture file mode");
}

fn replace_file(path: &Path, bytes: &[u8], mode: u32) {
    let current = fs::metadata(path)
        .expect("inspect fixture file")
        .permissions();
    fs::set_permissions(path, Permissions::from_mode(current.mode() | 0o200))
        .expect("temporarily make fixture file writable");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open publisher fixture file");
    file.write_all(bytes)
        .expect("replace publisher fixture bytes");
    drop(file);
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("set fixture file mode");
}

fn policy_document(pins: [(&Path, &str); 4]) -> Value {
    let [
        (gh, gh_digest),
        (cosign, cosign_digest),
        (gh_roots, gh_roots_digest),
        (cosign_root, cosign_root_digest),
    ] = pins;
    let pinned = |path: &Path, digest: &str| {
        json!({
            "path": path.to_str().expect("UTF-8 fixture path"),
            "sha256": digest,
        })
    };
    json!({
        "schema": "ami-rust-publisher-trust-v2",
        "repository": "metaneutrons/ami-rust",
        "workflow": ".github/workflows/sdk-qualify.yml",
        "workflow_sha": "1".repeat(40),
        "source_sha": "2".repeat(40),
        "source_ref": "refs/heads/main",
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "cert_identity": "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main",
        "inputs_manifest_sha256": "f".repeat(64),
        "allowed_host_profiles": ["linux-x86_64", "macos-aarch64"],
        "gh": pinned(gh, gh_digest),
        "cosign": pinned(cosign, cosign_digest),
        "gh_trusted_roots": pinned(gh_roots, gh_roots_digest),
        "cosign_trusted_root": pinned(cosign_root, cosign_root_digest),
    })
}

fn policy_value(gh: &Path, cosign: &Path, gh_roots: &Path, cosign_root: &Path) -> PublisherPolicy {
    let value = policy_document([
        (gh, &"a".repeat(64)),
        (cosign, &"b".repeat(64)),
        (gh_roots, &"c".repeat(64)),
        (cosign_root, &"d".repeat(64)),
    ]);
    parse_publisher_policy(&serde_json::to_vec(&value).expect("encode policy fixture"))
        .expect("parse policy fixture")
}

fn metadata_fixture() -> AuthenticationMetadata {
    let subjects = ["release.json", "sdk.tar.xz", "SHAUTIL"];
    AuthenticationMetadata {
        declared_run: DeclaredWorkflowRun {
            run_id: PositiveCounter::parse("987654321").expect("run ID"),
            run_attempt: PositiveCounter::parse("3").expect("run attempt"),
            host_profile: Host::LinuxX86_64,
        },
        gh_bundles: subjects
            .iter()
            .map(|subject| {
                (
                    (*subject).to_owned(),
                    format!(".auth/gh/{subject}.bundle.json"),
                )
            })
            .collect(),
        cosign_bundles: subjects
            .iter()
            .map(|subject| {
                (
                    (*subject).to_owned(),
                    format!(".auth/cosign/{subject}.bundle.json"),
                )
            })
            .collect(),
        expected_files: BTreeSet::new(),
        allowed_directories: BTreeSet::new(),
    }
}

fn policy_for_arguments(root: &Path) -> PublisherPolicy {
    policy_value(
        &root.join("gh"),
        &root.join("cosign"),
        &root.join("gh-roots.jsonl"),
        &root.join("cosign-root.json"),
    )
}

fn strings(args: Vec<OsString>) -> Vec<String> {
    args.into_iter()
        .map(|argument| argument.into_string().expect("UTF-8 argv fixture"))
        .collect()
}

#[test]
fn gh_arguments_are_exact_for_all_three_authenticated_subjects() {
    let fixture = FixtureDir::new();
    let bundle = fixture.path().join("bundle");
    let policy = policy_for_arguments(fixture.path());
    let metadata = metadata_fixture();

    for subject in SUBJECTS {
        let expected = vec![
            "attestation".to_owned(),
            "verify".to_owned(),
            bundle.join(subject).display().to_string(),
            "--repo".to_owned(),
            "metaneutrons/ami-rust".to_owned(),
            "--bundle".to_owned(),
            bundle
                .join(&metadata.gh_bundles[subject])
                .display()
                .to_string(),
            "--custom-trusted-root".to_owned(),
            policy.gh_trusted_roots.path.clone(),
            "--signer-digest".to_owned(),
            "1".repeat(40),
            "--source-digest".to_owned(),
            "2".repeat(40),
            "--source-ref".to_owned(),
            "refs/heads/main".to_owned(),
            "--deny-self-hosted-runners".to_owned(),
            "--predicate-type".to_owned(),
            "https://slsa.dev/provenance/v1".to_owned(),
            "--cert-identity".to_owned(),
            "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main"
                .to_owned(),
            "--cert-oidc-issuer".to_owned(),
            "https://token.actions.githubusercontent.com".to_owned(),
            "--format=json".to_owned(),
        ];
        assert_eq!(
            strings(gh_arguments(&bundle, subject, &metadata, &policy)),
            expected,
            "GH argv for {subject}"
        );
    }
}

#[test]
fn cosign_arguments_are_exact_for_all_three_authenticated_subjects() {
    let fixture = FixtureDir::new();
    let bundle = fixture.path().join("bundle");
    let policy = policy_for_arguments(fixture.path());
    let metadata = metadata_fixture();

    for subject in ["release.json", "sdk.tar.xz", "SHAUTIL"] {
        let expected = vec![
            "verify-blob".to_owned(),
            bundle.join(subject).display().to_string(),
            "--bundle".to_owned(),
            bundle
                .join(&metadata.cosign_bundles[subject])
                .display()
                .to_string(),
            "--trusted-root".to_owned(),
            policy.cosign_trusted_root.path.clone(),
            "--certificate-identity".to_owned(),
            "https://github.com/metaneutrons/ami-rust/.github/workflows/sdk-qualify.yml@refs/heads/main"
                .to_owned(),
            "--certificate-oidc-issuer".to_owned(),
            "https://token.actions.githubusercontent.com".to_owned(),
            "--certificate-github-workflow-repository".to_owned(),
            "metaneutrons/ami-rust".to_owned(),
            "--certificate-github-workflow-ref".to_owned(),
            "refs/heads/main".to_owned(),
            "--certificate-github-workflow-sha".to_owned(),
            "1".repeat(40),
            "--certificate-github-workflow-trigger".to_owned(),
            "workflow_dispatch".to_owned(),
        ];
        assert_eq!(
            strings(cosign_arguments(&bundle, subject, &metadata, &policy)),
            expected,
            "Cosign argv for {subject}"
        );
    }
}

#[test]
fn verifier_environment_is_an_exact_replacement_with_private_absolute_home() {
    let fixture = FixtureDir::new();
    let home = fixture.path().join("verifier-home");
    let environment = verifier_environment(&home);
    let names: BTreeSet<String> = environment
        .keys()
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = [
        "PATH",
        "LC_ALL",
        "LANG",
        "GH_PROMPT_DISABLED",
        "NO_COLOR",
        "COSIGN_EXPERIMENTAL",
        "HOME",
        "GH_CONFIG_DIR",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(names, expected);
    assert!(home.is_absolute());
    assert_eq!(
        PathBuf::from(environment[&OsString::from("HOME")].clone()),
        home
    );
    assert_eq!(
        PathBuf::from(environment[&OsString::from("GH_CONFIG_DIR")].clone()),
        home.join("gh")
    );
    for credential_name in [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "COSIGN_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
    ] {
        assert!(!names.contains(credential_name));
    }
    assert_eq!(
        environment.get(&OsString::from("PATH")),
        Some(&OsString::from("/bin:/usr/bin"))
    );
    assert_eq!(
        environment.get(&OsString::from("GH_PROMPT_DISABLED")),
        Some(&OsString::from("1"))
    );
    assert_eq!(
        environment.get(&OsString::from("COSIGN_EXPERIMENTAL")),
        Some(&OsString::from("0"))
    );
}

#[test]
fn trusted_roots_accept_object_jsonl_and_reject_empty_nonobject_or_duplicate_json() {
    let fixture = FixtureDir::new();
    let gh_tool = fixture.path().join("gh");
    let cosign_tool = fixture.path().join("cosign");
    let gh_roots = fixture.path().join("gh-roots.jsonl");
    let cosign_root = fixture.path().join("cosign-root.json");
    write_file(&gh_roots, b"{\"key\":1}\n\n {\"key\":2}\n", 0o600);
    write_file(&cosign_root, b"{\"version\":1}\n", 0o600);
    let policy = policy_value(&gh_tool, &cosign_tool, &gh_roots, &cosign_root);
    check_trusted_roots(&policy).expect("object-valued GH JSONL and Cosign root");
    replace_file(&gh_roots, b"{\"key\":1}\r{\"key\":2}\r\n", 0o600);
    check_trusted_roots(&policy).expect("historical bare-CR and CRLF line splitting");

    for invalid in [
        b"".as_slice(),
        b"  \n".as_slice(),
        b"[]\n".as_slice(),
        b"{\"k\":1,\"k\":2}\n".as_slice(),
        "{\"key\":1}\n\u{85}\n".as_bytes(),
    ] {
        replace_file(&gh_roots, invalid, 0o600);
        assert!(
            check_trusted_roots(&policy).is_err(),
            "invalid GitHub trusted roots were accepted: {invalid:?}"
        );
    }
    replace_file(&gh_roots, b"{\"key\":1}\n", 0o600);
    for invalid in [
        b"".as_slice(),
        b"[]".as_slice(),
        b"{\"k\":1,\"k\":2}".as_slice(),
    ] {
        replace_file(&cosign_root, invalid, 0o600);
        assert!(
            check_trusted_roots(&policy).is_err(),
            "invalid Sigstore root was accepted: {invalid:?}"
        );
    }
}

fn check_exec_pin(path: &Path, digest: &str) -> Result<()> {
    let pin = PinnedPolicyFile {
        path: path.to_str().expect("UTF-8 fixture path").to_owned(),
        sha256: parse_digest(digest)?,
    };
    let mut not_cancelled = || false;
    let mut observer = Observation {
        started: Instant::now(),
        cancelled: &mut not_cancelled,
    };
    check_pin(&pin, true, &mut observer)
}

#[test]
fn pinned_executable_hash_and_permission_checks_refuse_mutation_and_unsafe_modes() {
    let fixture = FixtureDir::new();
    let path = fixture.path().join("pinned-verifier");
    let original = b"#!/bin/sh\nexit 0\n";
    write_file(&path, original, 0o500);
    check_exec_pin(&path, &sha256_bytes(original)).expect("matching immutable executable pin");

    replace_file(&path, b"altered verifier bytes!!!!!!!!!", 0o500);
    let error = check_exec_pin(&path, &sha256_bytes(original)).unwrap_err();
    assert!(error.to_string().contains("digest mismatch"));

    replace_file(&path, original, 0o502);
    assert!(check_exec_pin(&path, &sha256_bytes(original)).is_err());

    replace_file(&path, original, 0o4500);
    assert_ne!(fs::metadata(&path).unwrap().mode() & 0o6000, 0);
    assert!(check_exec_pin(&path, &sha256_bytes(original)).is_err());
}

#[test]
fn pinned_executable_rejects_sparse_oversize_before_streaming_contents() {
    let fixture = FixtureDir::new();
    let path = fixture.path().join("oversize-sparse-verifier");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create sparse executable fixture");
    file.set_len(513 * 1024 * 1024)
        .expect("size sparse executable fixture");
    drop(file);
    fs::set_permissions(&path, Permissions::from_mode(0o500))
        .expect("make sparse executable fixture executable");

    let error = check_exec_pin(&path, &"0".repeat(64)).unwrap_err();
    assert!(error.to_string().contains("exceeds its byte profile"));
}

#[test]
fn observation_checks_cancellation_and_deadline_without_sleeping() {
    let mut cancelled = || true;
    let mut cancellation_observation = Observation {
        started: Instant::now(),
        cancelled: &mut cancelled,
    };
    assert_eq!(
        cancellation_observation.check().unwrap_err().to_string(),
        "publisher verification cancelled"
    );

    let mut not_cancelled = || false;
    let mut deadline_observation = Observation {
        started: Instant::now() - TOTAL_TIMEOUT - Duration::from_secs(1),
        cancelled: &mut not_cancelled,
    };
    assert_eq!(
        deadline_observation.check().unwrap_err().to_string(),
        "publisher verification deadline expired"
    );
}

fn native_fixture_from_legacy(raw: &[u8]) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(raw).expect("legacy fixture JSON");
    value["schema"] = json!("ami-rust-release-v2");
    value
        .as_object_mut()
        .expect("legacy fixture object")
        .remove("host_interpreters");
    value["assets"] = json!([
        {"path":"sdk.tar.xz", "bytes":3, "sha256":"b".repeat(64)},
        {"path":"bin/ami-rust-linux", "bytes":4, "sha256":"c".repeat(64)},
        {"path":"bin/ami-rust-macos", "bytes":5, "sha256":"d".repeat(64)}
    ]);
    value["host_launchers"] = json!({
        "linux-x86_64": {"path":"bin/ami-rust-linux", "bytes":4, "sha256":"c".repeat(64)},
        "macos-aarch64": {"path":"bin/ami-rust-macos", "bytes":5, "sha256":"d".repeat(64)}
    });
    serde_json::to_vec(&value).expect("native fixture JSON")
}

#[test]
fn legacy_and_native_release_flavors_are_explicit_and_qualification_only_is_retained() {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/release-manifests/inputs/valid-qualification-route.json");
    let legacy_raw = fs::read(fixture_path).expect("pinned legacy qualification fixture");
    let legacy = parse_release_manifest(&legacy_raw, true).expect("legacy flavor");
    assert!(legacy.qualification_only);
    assert!(parse_native_release_manifest(&legacy_raw, true).is_err());

    let native_raw = native_fixture_from_legacy(&legacy_raw);
    let native = parse_native_release_manifest(&native_raw, true).expect("native flavor");
    assert!(native.qualification_only);
    assert!(parse_release_manifest(&native_raw, true).is_err());

    let legacy_verified = ParsedManifest::Legacy(legacy);
    let native_verified = ParsedManifest::Native(native);
    assert!(legacy_verified.qualification_only());
    assert!(native_verified.qualification_only());
}

fn qualification_bundle_fixture(legacy: bool) -> (FixtureDir, PathBuf, PathBuf) {
    let fixture = FixtureDir::new();
    let bundle = fixture.subdir("bundle");
    let tools = fixture.subdir("tools");
    let roots = fixture.subdir("roots");

    let gh = tools.join("gh-verifier");
    let cosign = tools.join("cosign-verifier");
    let gh_bytes = b"this pinned test fixture is deliberately not executable content\n";
    let cosign_bytes = b"this pinned test fixture is deliberately not executable content\n";
    write_file(&gh, gh_bytes, 0o500);
    write_file(&cosign, cosign_bytes, 0o500);

    let gh_roots = roots.join("gh-roots.jsonl");
    let cosign_root = roots.join("cosign-root.json");
    let gh_roots_bytes = b"{\"roots\":[]}\n";
    let cosign_root_bytes = b"{\"version\":1}\n";
    write_file(&gh_roots, gh_roots_bytes, 0o600);
    write_file(&cosign_root, cosign_root_bytes, 0o600);

    let policy = policy_document([
        (&gh, &sha256_bytes(gh_bytes)),
        (&cosign, &sha256_bytes(cosign_bytes)),
        (&gh_roots, &sha256_bytes(gh_roots_bytes)),
        (&cosign_root, &sha256_bytes(cosign_root_bytes)),
    ]);
    let policy_path = fixture.path().join("publisher-policy.json");
    write_file(
        &policy_path,
        &serde_json::to_vec(&policy).expect("encode publisher policy"),
        0o600,
    );

    let legacy_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/release-manifests/inputs/valid-qualification-route.json");
    let legacy_bytes = fs::read(legacy_path).expect("pinned legacy qualification fixture");
    let manifest = if legacy {
        legacy_bytes
    } else {
        native_fixture_from_legacy(&legacy_bytes)
    };
    write_file(&bundle.join("release.json"), &manifest, 0o600);
    (fixture, bundle, policy_path)
}

#[test]
fn qualification_only_bundle_is_rejected_before_verifier_launch_for_both_flavors() {
    for legacy in [false, true] {
        let (_fixture, bundle, policy_path) = qualification_bundle_fixture(legacy);
        let error = if legacy {
            inspect_legacy_publisher_bundle(&bundle, &policy_path, || false)
                .unwrap_err()
                .to_string()
        } else {
            verify_publisher_bundle(&bundle, &policy_path, || false)
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            error,
            "publisher verification requires a production release"
        );
        assert!(!bundle.join(".auth").exists());
    }
}
