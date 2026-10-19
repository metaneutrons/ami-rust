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
    let state = target
        .parent()
        .mkdir_new_tracked(target.name(), 0o700, || created = true);
    let result = match state {
        Ok(state) => prepare_created(package, state_path, &state, &signals),
        Err(error) => Err(Refusal::new(format!(
            "prepare state creation failed: {error}; state_created={created}"
        ))),
    };
    match (result, signals.finish()) {
        (Ok(state), Ok(())) => Ok(state),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(Refusal::new(format!(
            "state was prepared but signal restoration failed: {error}; retained state: {}",
            state_path.display()
        ))),
        (Err(error), Err(restore)) => Err(Refusal::new(format!(
            "{error}; signal restoration also failed: {restore}"
        ))),
    }
}

fn prepare_created(
    package: &CheckedNativePackage,
    state_path: &Path,
    state: &Directory,
    signals: &SigtermGuard,
) -> Result<PreparedState> {
    let mut phase = "retain-package";
    let result = (|| -> Result<PreparedState> {
        signals.check()?;
        let retained = retain_package(package, state, state_path, signals)?;
        let mut session = ConsumerSession::new(state_path, signals)?;
        phase = "source-checkout";
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
        .map_err(|error| Refusal::new(format!("native SDK install failed: {error:?}")))?;
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
