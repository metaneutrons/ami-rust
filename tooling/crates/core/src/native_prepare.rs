//! Explicit cold preparation: retain, acquire, authenticate, provision, READY.
//! No source helper or interpreter is invoked by this orchestration.
use crate::{
    Refusal, Result,
    acquisition::CurlExecutablePin,
    baseline::InitialBaseline,
    consumer_session::ConsumerSession,
    digest::sha256_bytes,
    directory::Directory,
    native_install::CheckedNativeInstallation,
    ownership,
    package::{CheckedNativePackage, PackageRuntime, check_native_package_root},
    publisher::outer::verify_outer_package_in_workspace,
    records::{parse_package_state, parse_selection},
    signals::SigtermGuard,
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Serialize)]
pub struct PreparedState {
    schema: &'static str,
    pub status: &'static str,
    pub state: PathBuf,
    pub retained_launcher: PathBuf,
    pub sdk_version: String,
    pub package_version: String,
    pub receipt_sha256: String,
}

pub fn prepare(package: &CheckedNativePackage, state_path: &Path) -> Result<PreparedState> {
    let host = crate::host_platform::supported_host()?;
    if package.pins().host != host || package.pins().cli_version != env!("CARGO_PKG_VERSION") {
        return Err(Refusal::new(
            "prepare package differs from the executing native host/CLI",
        ));
    }
    ownership::validate_state_package_separation(state_path, package.path(), true)?;
    let target = ownership::fresh_private_state(state_path)?;
    if state_path.to_str().is_none() {
        return Err(Refusal::new(
            "prepare state must be representable by the publisher policy's UTF-8 paths",
        ));
    }
    let signals = SigtermGuard::acquire()?;
    let mut created = false;
    let mut installation_publication_failure = false;
    let state = target
        .parent()
        .mkdir_new_tracked(target.name(), 0o700, || created = true);
    let result = match state {
        Ok(state) => prepare_created(
            package,
            state_path,
            &state,
            &signals,
            &mut installation_publication_failure,
        ),
        Err(error) => Err(Refusal::new(format!(
            "prepare state creation failed: {error}; state_created={created}"
        ))),
    };
    match (result, signals.finish_requested()) {
        // Only the typed installation failure can retain publication recovery
        // status 1. An ordinary child exit 1 must not mask our own SIGTERM.
        (Err(error), Ok(true)) if installation_publication_failure => Err(error),
        (result, Ok(true)) => {
            let message = match result {
                Err(error) => format!("prepare interrupted by SIGTERM: {error}"),
                Ok(_) => format!(
                    "SIGTERM requested after preparation; private state retained: {}",
                    state_path.display()
                ),
            };
            Err(Refusal::new(message).with_exit_code(143))
        }
        (Ok(state), Ok(false)) => Ok(state),
        (Err(error), Ok(false)) => Err(error),
        (Ok(_), Err(error)) => Err(Refusal::new(format!(
            "state was prepared but signal restoration failed: {error}; retained state: {}",
            state_path.display()
        ))),
        (Err(error), Err(restore)) => Err(Refusal::new(format!(
            "{error}; signal restoration also failed: {restore}"
        ))
        .with_exit_code(error.exit_code())),
    }
}

fn prepare_created(
    package: &CheckedNativePackage,
    state_path: &Path,
    state: &Directory,
    signals: &SigtermGuard,
    installation_publication_failure: &mut bool,
) -> Result<PreparedState> {
    let mut phase = "retain-package";
    let result = (|| -> Result<PreparedState> {
        signals.check()?;
        let retained = retain_package(package, state, state_path, signals)?;
        let mut session = ConsumerSession::new(state_path, signals)?;
        phase = "source-checkout";
        #[cfg(test)]
        test_interrupt_after_retained_session(signals)?;
        let source =
            crate::consumer_source::checkout_package_source(&mut session, retained.pins())?;
        let baseline = InitialBaseline::load()?;
        // The OS supplies this bootstrap utility and TLS roots. Its identity is
        // retained and rechecked; it is not represented as a publisher pin.
        let curl_path = Path::new("/usr/bin/curl");
        let curl_raw = crate::publisher_files::read_open_regular(
            ownership::protected_regular_file(curl_path, true)?,
            256 * 1024 * 1024,
        )?;
        let curl_sha = sha256_bytes(&curl_raw);
        write_json(
            state,
            "bootstrap-system-tool.json",
            &serde_json::json!({
                "schema":"ami-rust-os-bootstrap-tool-v1", "path":"/usr/bin/curl",
                "sha256":curl_sha, "bytes":curl_raw.len(), "trust":"supported host operating system",
            }),
        )?;
        let curl = CurlExecutablePin::new(curl_path, curl_sha)?;
        phase = "publisher-bootstrap";
        let bootstrap = crate::verifier_bootstrap::bootstrap_verifiers(
            &mut session,
            &source,
            retained.pins(),
            &baseline,
            &curl,
            signals,
        )?;
        phase = "outer-publisher-authentication";
        let outer = verify_outer_package_in_workspace(
            &retained,
            &bootstrap.policy_path,
            &bootstrap.inputs,
            state_path,
            || signals.requested(),
        )?;
        write_json(
            state,
            "outer-authentication.json",
            &serde_json::json!({
                "schema":"ami-rust-native-outer-authentication-v1", "authenticated":true,
                "selected_proofs":outer.selected_proofs(), "ignored_proofs":outer.ignored_proofs(),
                "predicate":outer.predicate(), "resource_reports":outer.resource_reports(),
                "installed":false, "r1_accepted":false, "publication_authorized":false,
            }),
        )?;
        phase = "outer-transport-extraction";
        let archive_name = "authenticated-capsule.tar.xz";
        write_bytes(state, archive_name, outer.archive(), 0o600)?;
        let unpacked_name = "ami-rust-public-authenticated-bundle";
        crate::public_transport::unpack_native_transport(
            state.regular(OsStr::new(archive_name))?,
            &outer.record().archive.name,
            state,
            unpacked_name,
            outer.record(),
            || signals.requested(),
        )?;
        state.unlink_entry(OsStr::new(archive_name))?;
        let bundle_path = state_path.join(unpacked_name);
        phase = "inner-publisher-authentication";
        let inner = crate::publisher::verify_publisher_bundle_in_workspace(
            &bundle_path,
            &bootstrap.policy_path,
            state_path,
            || signals.requested(),
        )?;
        let inner = outer.bind_inner(inner)?;
        phase = "sdk-installation";
        let pins = retained.pins();
        let prefix = crate::ready_state::installed_prefix(state_path, &pins.sdk_version)?;
        let published = crate::native_install::install_verified_guarded(
            &inner,
            &bundle_path,
            &prefix,
            Some(&state_path.join("receipt.sha256")),
            pins.host,
            signals,
        )
        .map_err(|error| {
            *installation_publication_failure = error.published.is_some();
            // InstallFailure::exit_code is defined to return only 1 or 2.
            Refusal::new(format!("native SDK install failed: {error:?}"))
                .with_exit_code(error.exit_code() as u8)
        })?;
        let installation = CheckedNativeInstallation::open(&prefix, &published.receipt_sha256)?;
        phase = "component-provisioning";
        let components = crate::consumer_provision::provision_native_consumer_components(
            &installation,
            &baseline,
            pins.host,
            &source,
            &mut session,
            &curl,
            signals,
        )?;
        let selection_value = serde_json::json!({
            "schema":"ami-rust-selection-v2", "host":pins.host,
            "install_receipt_sha256":published.receipt_sha256, "components":components.roots,
        });
        let selection_raw = encode_json(&selection_value)?;
        let selection = parse_selection(&selection_raw)?;
        crate::selected_inputs::verify_selection(&installation, &selection)?;
        phase = "ready-publication";
        session.recheck_root()?;
        installation.recheck()?;
        write_bytes(state, "selection.json", &selection_raw, 0o600)?;
        let ready_value = serde_json::json!({
            "schema":"ami-rust-package-state-v2", "status":"READY", "host":pins.host,
            "sdk_version":pins.sdk_version, "package_version":pins.package_version,
            "source_commit":pins.source_commit, "manifest_sha256":pins.manifest_sha256,
            "install_receipt_sha256":published.receipt_sha256,
            "cli_sha256":pins.launchers["ami-rust"].sha256, "core_sha256":pins.core_sha256,
        });
        let ready_raw = encode_json(&ready_value)?;
        parse_package_state(&ready_raw)?;
        signals.check()?;
        write_bytes(state, "ready.json", &ready_raw, 0o600)?;
        if let Err(error) = crate::ready_state::ReadyInputs::open(state_path, &retained) {
            if let Err(cleanup) = state.unlink_entry(OsStr::new("ready.json")) {
                return Err(Refusal::new(format!(
                    "final state verification failed: {error}; invalid READY record could not be removed: {cleanup}"
                )));
            }
            return Err(error);
        }
        Ok(PreparedState {
            schema: "ami-rust-prepare-result-v2",
            status: "READY",
            state: state_path.to_path_buf(),
            retained_launcher: state_path.join("retained/bin/ami-rust"),
            sdk_version: pins.sdk_version.clone(),
            package_version: pins.package_version.clone(),
            receipt_sha256: published.receipt_sha256,
        })
    })();
    match result {
        Ok(result) => Ok(result),
        Err(error) => {
            let failure = serde_json::json!({"schema":"ami-rust-prepare-failure-v1", "phase":phase,
                "ready":false, "reason":error.to_string(), "state_retained":true});
            let evidence = write_json(state, "prepare-failure.json", &failure);
            Err(Refusal::new(match evidence {
                Ok(()) => format!(
                    "prepare failed in {phase}: {error}; private state retained: {}",
                    state_path.display()
                ),
                Err(evidence) => format!(
                    "prepare failed in {phase}: {error}; failure record also failed: {evidence}; private state retained: {}",
                    state_path.display()
                ),
            }).with_exit_code(error.exit_code()))
        }
    }
}

fn retain_package(
    package: &CheckedNativePackage,
    state: &Directory,
    state_path: &Path,
    signals: &SigtermGuard,
) -> Result<CheckedNativePackage> {
    let retained = state.mkdir_new(OsStr::new("retained"), 0o700)?;
    let bin = retained.mkdir_new(OsStr::new("bin"), 0o755)?;
    let libexec = retained.mkdir_new(OsStr::new("libexec"), 0o755)?;
    let ami_rust = libexec.mkdir_new(OsStr::new("ami-rust"), 0o755)?;
    let version = &package.pins().package_version;
    crate::files::validate_relative_inventory_path(version)?;
    if version.contains('/') {
        return Err(Refusal::new(
            "package version cannot select a retained path",
        ));
    }
    let destination = ami_rust.mkdir_new(OsStr::new(version), 0o755)?;
    let mut directories = BTreeSet::new();
    for row in &package.inventory().files {
        signals.check()?;
        let (parent, leaf) = row.path.rsplit_once('/').unwrap_or(("", &row.path));
        let mut prefix = String::new();
        for part in parent.split('/').filter(|part| !part.is_empty()) {
            let base = destination.relative_directory(&prefix)?;
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if directories.insert(prefix.clone()) {
                base.mkdir_new(OsStr::new(part), 0o755)?;
            }
        }
        let raw = package.read_file(&row.path)?;
        write_bytes(
            &destination.relative_directory(parent)?,
            leaf,
            &raw,
            row.mode
                .ok_or_else(|| Refusal::new("retained package file has no fixed mode"))?,
        )?;
    }
    write_bytes(
        &destination,
        "inventory.json",
        package.raw_inventory(),
        0o644,
    )?;
    let path = state_path.join("retained/libexec/ami-rust").join(version);
    let checked = check_native_package_root(
        &path,
        PackageRuntime {
            host: package.pins().host,
            cli_version: &package.pins().cli_version,
        },
    )?;
    for name in ["ami-rust", "cargo-ami"] {
        let target = format!("../libexec/ami-rust/{version}/bin/{name}");
        symlink_new(&bin, name, &target)?;
    }
    Ok(checked)
}

#[allow(unsafe_code)]
fn symlink_new(parent: &Directory, name: &str, target: &str) -> Result<()> {
    let name =
        std::ffi::CString::new(name).map_err(|_| Refusal::new("invalid retained launcher name"))?;
    let target = std::ffi::CString::new(target)
        .map_err(|_| Refusal::new("invalid retained launcher target"))?;
    // SAFETY: live NUL-terminated relative strings and a retained directory;
    // symlinkat creates exclusively and never replaces an existing name.
    if unsafe { libc::symlinkat(target.as_ptr(), parent.raw_fd(), name.as_ptr()) } != 0 {
        return Err(Refusal::new(format!(
            "cannot publish retained launcher alias: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn encode_json(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| Refusal::new(e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn write_json(root: &Directory, name: &str, value: &serde_json::Value) -> Result<()> {
    write_bytes(root, name, &encode_json(value)?, 0o600)
}
fn write_bytes(root: &Directory, name: &str, raw: &[u8], mode: u32) -> Result<()> {
    let mut file = root.create_new_file(OsStr::new(name), mode)?;
    file.write_all(raw)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
static INTERRUPT_AFTER_RETAINED_SESSION: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_SIGTERM_OBSERVED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "The isolated test sends SIGTERM to its own test process."
)]
fn test_interrupt_after_retained_session(signals: &SigtermGuard) -> Result<()> {
    if !INTERRUPT_AFTER_RETAINED_SESSION.swap(false, Ordering::AcqRel) {
        return Ok(());
    }
    // SAFETY: raise has no pointer arguments and delivers the signal to this
    // calling test thread. The real cooperative handler is installed by prepare.
    let status = unsafe { libc::raise(libc::SIGTERM) };
    if status != 0 {
        return Err(Refusal::new(format!(
            "test could not deliver SIGTERM to its own process: {}",
            std::io::Error::last_os_error()
        )));
    }
    if !signals.requested() {
        return Err(Refusal::new(
            "test SIGTERM was not observed by the active installer guard",
        ));
    }
    TEST_SIGTERM_OBSERVED.store(true, Ordering::Release);
    signals.check()
}

#[cfg(test)]
mod interruption_tests {
    use super::{INTERRUPT_AFTER_RETAINED_SESSION, TEST_SIGTERM_OBSERVED, prepare};
    use crate::{
        digest::sha256_bytes,
        host_platform::supported_host,
        package::{PackageRuntime, check_native_package_root},
    };
    use serde_json::{Value, json};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        sync::atomic::Ordering,
    };

    fn hash_file(path: &Path) -> String {
        sha256_bytes(&fs::read(path).expect("read evidence file"))
    }

    fn collect(root: &Path, current: &Path, rows: &mut Vec<Value>) {
        let mut children = fs::read_dir(current)
            .expect("read state directory")
            .map(|entry| entry.expect("read state entry").path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            let metadata = fs::symlink_metadata(&child).expect("read entry metadata");
            let relative = child.strip_prefix(root).expect("state-relative entry");
            let mode = metadata.mode() & 0o7777;
            let mut row = json!({
                "path": relative.to_string_lossy(),
                "uid": metadata.uid(),
                "gid": metadata.gid(),
                "mode": mode,
            });
            if metadata.file_type().is_dir() {
                row["kind"] = json!("directory");
                collect(root, &child, rows);
            } else if metadata.file_type().is_file() {
                row["kind"] = json!("file");
                row["bytes"] = json!(metadata.len());
                row["sha256"] = json!(hash_file(&child));
            } else if metadata.file_type().is_symlink() {
                row["kind"] = json!("symlink");
                row["target"] = json!(
                    fs::read_link(&child)
                        .expect("read symlink target")
                        .to_string_lossy()
                );
            } else {
                panic!(
                    "unexpected special entry in retained state: {}",
                    child.display()
                );
            }
            rows.push(row);
        }
    }

    #[allow(
        unsafe_code,
        reason = "The test reads its own uid and gid for private-state checks."
    )]
    fn state_snapshot(root: &Path) -> Vec<Value> {
        let metadata = fs::symlink_metadata(root).expect("state root metadata");
        assert!(metadata.file_type().is_dir());
        let mut rows = vec![json!({
            "path": ".",
            "kind": "directory",
            "uid": metadata.uid(),
            "gid": metadata.gid(),
            "mode": metadata.mode() & 0o7777,
        })];
        collect(root, root, &mut rows);
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        for row in &rows {
            assert_eq!(row["uid"].as_u64(), Some(u64::from(uid)));
            assert_eq!(row["gid"].as_u64(), Some(u64::from(gid)));
            if row["kind"] == "directory" || row["kind"] == "file" {
                assert_eq!(row["mode"].as_u64().unwrap() & 0o022, 0, "{}", row["path"]);
            }
        }
        assert_eq!(rows[0]["mode"], json!(0o700));
        rows
    }

    fn snapshot_hash(rows: &[Value]) -> String {
        sha256_bytes(&serde_json::to_vec(rows).expect("serialize state snapshot"))
    }

    fn write_report(path: &Path, report: &Value) {
        let bytes = serde_json::to_vec_pretty(report).expect("serialize test report");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create private test report");
        file.write_all(&bytes).expect("write private test report");
        file.write_all(b"\n")
            .expect("terminate private test report");
        file.sync_all().expect("sync private test report");
    }

    #[test]
    #[ignore = "requires the pinned signed native package and writes retained private state"]
    #[allow(
        unsafe_code,
        reason = "The test checks current-user ownership on the isolated state."
    )]
    fn interrupted_prepare_retains_state_and_retry_refuses_without_mutation() {
        assert_eq!(
            std::env::var("AMI_RUST_TEST_INTERRUPT_PREPARE").as_deref(),
            Ok("1")
        );
        let package_path = PathBuf::from(
            std::env::var_os("AMI_RUST_TEST_NATIVE_PACKAGE").expect("pinned package path"),
        );
        let state_path =
            PathBuf::from(std::env::var_os("AMI_RUST_TEST_STATE").expect("fresh state path"));
        let report_path =
            PathBuf::from(std::env::var_os("AMI_RUST_TEST_REPORT").expect("test report path"));
        let state_parent = state_path.parent().expect("state parent");
        assert!(!state_path.exists());
        let parent_metadata = fs::symlink_metadata(state_parent).expect("state parent exists");
        assert!(parent_metadata.file_type().is_dir());
        assert_eq!(parent_metadata.uid(), unsafe { libc::getuid() });
        assert_eq!(parent_metadata.gid(), unsafe { libc::getgid() });
        assert_eq!(parent_metadata.mode() & 0o7777, 0o700);

        let sibling = state_parent.join("unrelated-user-data.bin");
        let sibling_bytes = b"preserve unrelated data through interrupted prepare and refusal\n";
        let mut sibling_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&sibling)
            .expect("create unrelated sibling file");
        sibling_file.write_all(sibling_bytes).unwrap();
        sibling_file.sync_all().unwrap();
        let sibling_sha_before = hash_file(&sibling);

        let package = check_native_package_root(
            &package_path,
            PackageRuntime {
                host: supported_host().expect("supported native host"),
                cli_version: env!("CARGO_PKG_VERSION"),
            },
        )
        .expect("checked native package");
        INTERRUPT_AFTER_RETAINED_SESSION.store(true, Ordering::Release);
        let error = match prepare(&package, &state_path) {
            Ok(_) => panic!("test SIGTERM must interrupt prepare"),
            Err(error) => error,
        };
        assert!(TEST_SIGTERM_OBSERVED.swap(false, Ordering::AcqRel));
        assert_eq!(error.exit_code(), 143);
        assert!(
            error
                .to_string()
                .contains("prepare failed in source-checkout")
        );
        assert!(
            error
                .to_string()
                .contains("SIGTERM requested; installer must stop safely")
        );
        assert!(state_path.is_dir());
        assert!(!state_path.join("ready.json").exists());
        assert!(!state_path.join("source").exists());

        let failure: Value = serde_json::from_slice(
            &fs::read(state_path.join("prepare-failure.json")).expect("failure record"),
        )
        .unwrap();
        assert_eq!(failure["phase"], "source-checkout");
        assert_eq!(failure["ready"], false);
        assert_eq!(failure["state_retained"], true);
        assert!(failure["reason"].as_str().unwrap().contains("SIGTERM"));

        let retained_path = state_path
            .join("retained/libexec/ami-rust")
            .join(&package.pins().package_version);
        let retained = check_native_package_root(
            &retained_path,
            PackageRuntime {
                host: package.pins().host,
                cli_version: &package.pins().cli_version,
            },
        )
        .expect("retained package is still complete and internally consistent");
        assert_eq!(retained.raw_inventory(), package.raw_inventory());
        for name in ["ami-rust", "cargo-ami"] {
            let alias = state_path.join("retained/bin").join(name);
            assert!(
                fs::symlink_metadata(&alias)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert!(alias.is_file());
            assert_eq!(
                fs::read_link(alias).unwrap(),
                PathBuf::from("../libexec/ami-rust")
                    .join(&package.pins().package_version)
                    .join("bin")
                    .join(name)
            );
        }
        let commands = fs::read_dir(state_path.join("commands"))
            .expect("consumer session command root")
            .count();
        assert_eq!(commands, 0, "SIGTERM must occur before any child command");

        let before_retry = state_snapshot(&state_path);
        let retry_error = match prepare(&package, &state_path) {
            Ok(_) => panic!("partial state must refuse retry"),
            Err(error) => error,
        };
        assert!(retry_error.to_string().contains("state path must be fresh"));
        assert_eq!(before_retry, state_snapshot(&state_path));
        assert_eq!(fs::read(&sibling).unwrap(), sibling_bytes);
        let sibling_sha_after = hash_file(&sibling);
        assert_eq!(sibling_sha_before, sibling_sha_after);

        let report = json!({
            "schema": "ami-rust-native-test-interrupted-prepare-v1",
            "status": "PASS_TEST_ONLY_REAL_SIGTERM_BEFORE_SOURCE_CHECKOUT",
            "process_id": std::process::id(),
            "self_sigterm_delivered_to_active_guard": true,
            "native_prepare_exit_code": error.exit_code(),
            "prepare_error": error.to_string(),
            "failure_record": failure,
            "state_path": state_path.to_string_lossy(),
            "state_entries": before_retry.len(),
            "state_sha256_before_retry": snapshot_hash(&before_retry),
            "state_sha256_after_retry": snapshot_hash(&state_snapshot(&state_path)),
            "retained_package_inventory_sha256": hash_file(&retained_path.join("inventory.json")),
            "retained_package_consistency_rechecked": true,
            "retained_launcher_aliases": ["ami-rust", "cargo-ami"],
            "consumer_commands": commands,
            "ready_present": state_path.join("ready.json").exists(),
            "source_present": state_path.join("source").exists(),
            "retry_refusal": retry_error.to_string(),
            "retry_state_unchanged": true,
            "unrelated_sibling_sha256_before": sibling_sha_before,
            "unrelated_sibling_sha256_after": sibling_sha_after,
        });
        write_report(&report_path, &report);
    }
}
