//! The two executable names enter this same parser and dispatcher.
use crate::{Refusal, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::{
    ffi::OsString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

/// The unimplemented entries are migration debt, never successful no-op commands.
pub struct Capability {
    pub name: &'static str,
    pub command: &'static str,
    pub implemented: bool,
}

pub const CAPABILITIES: &[Capability] = &[
    Capability {
        name: "version",
        command: "--version",
        implemented: true,
    },
    Capability {
        name: "verify package",
        command: "verify-package",
        implemented: true,
    },
    Capability {
        name: "prepare",
        command: "prepare",
        implemented: true,
    },
    Capability {
        name: "new project",
        command: "new",
        implemented: true,
    },
    Capability {
        name: "build project",
        command: "build",
        implemented: true,
    },
    Capability {
        name: "check inputs",
        command: "check-inputs",
        implemented: true,
    },
    Capability {
        name: "verify SDK lock",
        command: "verify",
        implemented: true,
    },
    Capability {
        name: "build with SDK lock",
        command: "build",
        implemented: true,
    },
    Capability {
        name: "verify release",
        command: "verify",
        implemented: true,
    },
    Capability {
        name: "install release",
        command: "install",
        implemented: true,
    },
    Capability {
        name: "lock project",
        command: "lock",
        implemented: true,
    },
    Capability {
        name: "uninstall",
        command: "uninstall",
        implemented: true,
    },
    Capability {
        name: "inspect or migrate",
        command: "migrate",
        implemented: true,
    },
];

#[derive(Debug, Eq, PartialEq)]
pub enum Invocation {
    Help,
    Version,
    VerifyPackage,
    InspectMigration {
        project: PathBuf,
    },
    MigrateProject {
        project: PathBuf,
        from_lock: PathBuf,
        prefix: PathBuf,
        receipt_sha256: String,
        output: PathBuf,
    },
    Prepare {
        state: PathBuf,
    },
    CheckInputs {
        state: PathBuf,
    },
    NewProject {
        state: PathBuf,
        project: PathBuf,
    },
    VerifyLock {
        sdk_lock: PathBuf,
    },
    LockProject {
        prefix: PathBuf,
        selection: PathBuf,
        project: PathBuf,
        output: PathBuf,
    },
    BuildLock {
        sdk_lock: PathBuf,
        output: PathBuf,
        cargo: crate::native_recipe::CargoBuildOptions,
    },
    BuildProject {
        state: PathBuf,
        project: PathBuf,
        output: PathBuf,
        cargo: crate::native_recipe::CargoBuildOptions,
    },
    VerifyRelease {
        bundle: PathBuf,
        policy: PathBuf,
    },
    InstallRelease {
        bundle: PathBuf,
        policy: PathBuf,
        prefix: PathBuf,
        receipt_pin: Option<PathBuf>,
    },
    Uninstall {
        prefix: PathBuf,
        receipt_sha256: String,
    },
}

pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub exit_code: u8,
}

impl CommandOutput {
    fn success(stdout: Vec<u8>) -> Self {
        Self {
            stdout,
            exit_code: 0,
        }
    }
}

/// Preserve OS path arguments. Cargo injects `ami` only for the plugin name.
pub fn parse(executable: &Path, arguments: &[OsString]) -> Result<Invocation> {
    let plugin = executable
        .file_name()
        .is_some_and(|name| name == "cargo-ami");
    let args = if plugin && arguments.first().is_some_and(|arg| arg == "ami") {
        &arguments[1..]
    } else {
        arguments
    };
    if args.len() == 1 {
        if args[0] == "--version" {
            return Ok(Invocation::Version);
        }
        if args[0] == "--help" || args[0] == "-h" {
            return Ok(Invocation::Help);
        }
    }
    if args.len() == 1 && args[0] == "verify-package" {
        return Ok(Invocation::VerifyPackage);
    }
    for (command, prepare) in [("prepare", true), ("check-inputs", false)] {
        if args.first().is_some_and(|arg| arg == command) {
            let mut options = parse_path_options(&args[1..], &["--state"], command)?;
            let state = options
                .remove("--state")
                .ok_or_else(|| Refusal::new(format!("{command} requires --state PATH")))?;
            return Ok(if prepare {
                Invocation::Prepare { state }
            } else {
                Invocation::CheckInputs { state }
            });
        }
    }
    if args.first().is_some_and(|arg| arg == "verify") {
        return parse_verify_release(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "new") {
        let mut options = parse_path_options(&args[1..], &["--state", "--project"], "new")?;
        let project = take_path(&mut options, "--project", "new")?;
        if !project.is_absolute() {
            return Err(Refusal::new(
                "new requires an explicit absolute project path",
            ));
        }
        return Ok(Invocation::NewProject {
            state: take_path(&mut options, "--state", "new")?,
            project,
        });
    }
    if args.first().is_some_and(|arg| arg == "build") {
        return parse_build(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "lock") {
        let mut options = parse_path_options(
            &args[1..],
            &["--prefix", "--selection", "--project", "--output"],
            "lock",
        )?;
        return Ok(Invocation::LockProject {
            prefix: take_path(&mut options, "--prefix", "lock")?,
            selection: take_path(&mut options, "--selection", "lock")?,
            project: take_path(&mut options, "--project", "lock")?,
            output: take_path(&mut options, "--output", "lock")?,
        });
    }
    if args.first().is_some_and(|arg| arg == "install") {
        return parse_install_release(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "uninstall") {
        return parse_uninstall(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "migrate") {
        return parse_migrate(&args[1..]);
    }
    if let Some(arg) = args.first()
        && CAPABILITIES.iter().any(|item| {
            !item.implemented
                && arg == item.command
                && !CAPABILITIES
                    .iter()
                    .any(|candidate| candidate.command == item.command && candidate.implemented)
        })
    {
        return Err(Refusal::new(
            "command is not implemented in this development build",
        ));
    }
    Err(Refusal::new("unsupported command or arguments; see --help"))
}

fn parse_build(arguments: &[OsString]) -> Result<Invocation> {
    let divider = arguments.iter().position(|argument| argument == "--");
    let (outer, forwarded) = match divider {
        Some(index) => (&arguments[..index], &arguments[index + 1..]),
        None => (arguments, &[][..]),
    };
    if outer.iter().any(|argument| argument == "--sdk-lock") {
        if divider.is_none() || forwarded.is_empty() {
            return Err(Refusal::new(
                "direct build requires -- before explicit Cargo arguments",
            ));
        }
        let mut options = parse_path_options(outer, &["--sdk-lock", "--output-dir"], "build")?;
        return Ok(Invocation::BuildLock {
            sdk_lock: take_path(&mut options, "--sdk-lock", "build")?,
            output: take_path(&mut options, "--output-dir", "build")?,
            cargo: crate::native_recipe::parse_cargo_options(forwarded)?,
        });
    }
    let mut options = parse_path_options(
        outer,
        &["--state", "--project", "--output-dir", "--package"],
        "build",
    )?;
    let state = take_path(&mut options, "--state", "build")?;
    let project = take_path(&mut options, "--project", "build")?;
    if !project.is_absolute() {
        return Err(Refusal::new(
            "build requires an explicit absolute project path",
        ));
    }
    let output = take_path(&mut options, "--output-dir", "build")?;
    let package = options
        .remove("--package")
        .map_or_else(|| OsString::from("hello-aros"), PathBuf::into_os_string);
    let mut cargo = vec![
        OsString::from("build"),
        OsString::from("--manifest-path"),
        project.join("Cargo.toml").into_os_string(),
        OsString::from("--package"),
        package,
        OsString::from("--release"),
        OsString::from("--locked"),
        OsString::from("--offline"),
    ];
    cargo.extend_from_slice(forwarded);
    Ok(Invocation::BuildProject {
        state,
        project,
        output,
        cargo: crate::native_recipe::parse_cargo_options(&cargo)?,
    })
}

fn parse_verify_release(arguments: &[OsString]) -> Result<Invocation> {
    if arguments.iter().any(|arg| arg == "--sdk-lock") {
        let mut options = parse_path_options(arguments, &["--sdk-lock"], "verify SDK lock")?;
        return Ok(Invocation::VerifyLock {
            sdk_lock: take_path(&mut options, "--sdk-lock", "verify SDK lock")?,
        });
    }
    let mut options = parse_path_options(arguments, &["--bundle", "--policy"], "verify")?;
    let bundle = options
        .remove("--bundle")
        .ok_or_else(|| Refusal::new("verify requires --bundle PATH"))?;
    let policy = options
        .remove("--policy")
        .ok_or_else(|| Refusal::new("verify requires --policy PATH"))?;
    Ok(Invocation::VerifyRelease { bundle, policy })
}

fn take_path(
    options: &mut BTreeMap<String, PathBuf>,
    option: &str,
    command: &str,
) -> Result<PathBuf> {
    options
        .remove(option)
        .ok_or_else(|| Refusal::new(format!("{command} requires {option} PATH")))
}

fn parse_install_release(arguments: &[OsString]) -> Result<Invocation> {
    let mut options = parse_path_options(
        arguments,
        &["--bundle", "--policy", "--prefix", "--receipt-pin"],
        "install",
    )?;
    let bundle = options
        .remove("--bundle")
        .ok_or_else(|| Refusal::new("install requires --bundle PATH"))?;
    let policy = options
        .remove("--policy")
        .ok_or_else(|| Refusal::new("install requires --policy PATH"))?;
    let prefix = options
        .remove("--prefix")
        .ok_or_else(|| Refusal::new("install requires --prefix FRESH_PREFIX"))?;
    let receipt_pin = options.remove("--receipt-pin");
    Ok(Invocation::InstallRelease {
        bundle,
        policy,
        prefix,
        receipt_pin,
    })
}

fn parse_uninstall(arguments: &[OsString]) -> Result<Invocation> {
    let mut options =
        parse_path_options(arguments, &["--prefix", "--receipt-sha256"], "uninstall")?;
    let prefix = options
        .remove("--prefix")
        .ok_or_else(|| Refusal::new("uninstall requires --prefix PATH"))?;
    let receipt_sha256 = options
        .remove("--receipt-sha256")
        .ok_or_else(|| Refusal::new("uninstall requires --receipt-sha256 SHA256"))?;
    let receipt_sha256 = receipt_sha256
        .to_str()
        .filter(|value| crate::digest::is_sha256_digest(value))
        .ok_or_else(|| Refusal::new("receipt SHA-256 must be 64 lowercase hexadecimal digits"))?
        .to_owned();
    Ok(Invocation::Uninstall {
        prefix,
        receipt_sha256,
    })
}

fn parse_migrate(arguments: &[OsString]) -> Result<Invocation> {
    let dry_run_count = arguments.iter().filter(|arg| *arg == "--dry-run").count();
    if dry_run_count > 1 {
        return Err(Refusal::new("--dry-run may be supplied only once"));
    }
    let mut paths = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--dry-run" {
            index += 1;
        } else {
            paths.push(arguments[index].clone());
            if let Some(value) = arguments.get(index + 1) {
                paths.push(value.clone());
            }
            index += 2;
        }
    }
    let mut options = parse_path_options(
        &paths,
        &[
            "--project",
            "--from-lock",
            "--install-prefix",
            "--receipt-sha256",
            "--output",
        ],
        "migrate",
    )?;
    let project = take_path(&mut options, "--project", "migrate")?;
    if options.is_empty() {
        return Ok(Invocation::InspectMigration { project });
    }
    if dry_run_count != 0 {
        return Err(Refusal::new("migration dry-run accepts only --project"));
    }
    let from_lock = take_path(&mut options, "--from-lock", "migrate")?;
    let prefix = take_path(&mut options, "--install-prefix", "migrate")?;
    let receipt_sha256 = take_path(&mut options, "--receipt-sha256", "migrate")?;
    let receipt_sha256 = receipt_sha256
        .to_str()
        .filter(|value| crate::digest::is_sha256_digest(value))
        .ok_or_else(|| Refusal::new("receipt SHA-256 must be 64 lowercase hexadecimal digits"))?
        .to_owned();
    let output = take_path(&mut options, "--output", "migrate")?;
    Ok(Invocation::MigrateProject {
        project,
        from_lock,
        prefix,
        receipt_sha256,
        output,
    })
}

fn parse_path_options(
    arguments: &[OsString],
    accepted: &[&str],
    command: &str,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut options = BTreeMap::new();
    let mut index = 0;
    while index < arguments.len() {
        let option = arguments[index]
            .to_str()
            .filter(|value| accepted.contains(value))
            .ok_or_else(|| {
                Refusal::new(format!("{command} accepts only {}", accepted.join(" and ")))
            })?;
        if options.contains_key(option) {
            return Err(Refusal::new(format!(
                "{command} options may be supplied only once"
            )));
        }
        index += 1;
        let value = arguments
            .get(index)
            .filter(|value| !value.as_bytes().starts_with(b"-"))
            .ok_or_else(|| Refusal::new(format!("{option} requires an argument")))?;
        options.insert(option.to_owned(), PathBuf::from(value.as_os_str()));
        index += 1;
    }
    Ok(options)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Version<'a> {
    schema: &'a str,
    cli_version: &'a str,
    sdk_version: &'a str,
    packaging_revision: u32,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct VerifyReleaseOutput<'a> {
    schema: &'static str,
    status: &'static str,
    verification_scope: &'static str,
    publisher: &'a crate::receipts::Authentication,
    release_cosign_bundle: ArtifactIdentity,
    manifest: ManifestSummary<'a>,
    sdk: &'a crate::sdk::VerifiedSdkV2Summary,
    resource_reports: &'a [crate::resource_capture::ResourceReport],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    bytes: usize,
    sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestSummary<'a> {
    schema: &'static str,
    version: &'a str,
    qualification_only: bool,
    sdk_archive: &'a str,
    sdk_manifest_sha256: &'a crate::records::Sha256,
    manifest_sha256: String,
    assets: Vec<AssetSummary<'a>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AssetSummary<'a> {
    path: &'a str,
    bytes: u64,
    sha256: &'a crate::records::Sha256,
}

#[derive(Serialize)]
#[serde(untagged)]
enum OutputPath<'a> {
    Utf8(&'a str),
    UnixBytes {
        encoding: &'static str,
        bytes: &'a [u8],
    },
}

impl<'a> OutputPath<'a> {
    fn from_path(path: &'a Path) -> Self {
        match path.to_str() {
            Some(path) => Self::Utf8(path),
            None => Self::UnixBytes {
                encoding: "unix-path-bytes-v1",
                bytes: path.as_os_str().as_bytes(),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InstallResult<'a> {
    schema: &'static str,
    status: &'static str,
    prefix: OutputPath<'a>,
    receipt_sha256: &'a str,
    receipt_pin: Option<OutputPath<'a>>,
    reason: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UninstallResult<'a> {
    schema: &'static str,
    status: &'static str,
    prefix: OutputPath<'a>,
    receipt_sha256: &'a str,
}

pub fn render(invocation: Invocation) -> Result<CommandOutput> {
    match invocation {
        Invocation::Help => Ok(CommandOutput::success(b"ami-rust native host tooling\n\nUsage:\n  ami-rust verify-package\n  ami-rust prepare --state FRESH_PRIVATE_PATH\n  ami-rust check-inputs --state PRIVATE_PATH\n  ami-rust new --state PRIVATE_PATH --project FRESH_PROJECT\n  ami-rust verify --sdk-lock FILE\n  ami-rust build --sdk-lock FILE --output-dir FRESH -- build --manifest-path PATH --package NAME --release --locked --offline\n  ami-rust build --state PRIVATE_PATH --project ABSOLUTE_PROJECT --output-dir FRESH [--package NAME] [-- CARGO_OPTIONS]\n  ami-rust lock --prefix PREFIX --selection FILE --project PROJECT --output FRESH_LOCK\n  ami-rust --version\n  ami-rust --help\n  ami-rust verify --bundle PATH --policy EXTERNAL_POLICY\n  ami-rust install --bundle BUNDLE --policy EXTERNAL_POLICY --prefix FRESH_PREFIX [--receipt-pin FRESH_EXTERNAL_FILE]\n  ami-rust uninstall --prefix PREFIX --receipt-sha256 SHA256\n  ami-rust migrate [--dry-run] --project PROJECT\n  ami-rust migrate --project PROJECT --from-lock OLD --install-prefix PREFIX --receipt-sha256 SHA256 --output FRESH_LOCK\n\nRelease verification authenticates the publisher and checks SDK-v2 structure; it does not claim R1 acceptance or native build qualification.\n".to_vec())),
        Invocation::Version => {
            let package = optional_executing_package()?;
            let mut output = serde_json::to_vec(&Version {
                schema: "ami-rust-version-v1",
                cli_version: env!("CARGO_PKG_VERSION"),
                // This bare development binary references the immutable SDK;
                // revision zero means no package adapter is installed by it.
                sdk_version: package.as_ref().map_or("0.1.0", |package| package.pins().sdk_version.as_str()),
                packaging_revision: package.as_ref().map_or(0, |package| package.pins().packaging_revision),
            }).map_err(|error| Refusal::new(format!("cannot encode version: {error}")))?;
            output.push(b'\n');
            Ok(CommandOutput::success(output))
        }
        Invocation::VerifyPackage => {
            let package = executing_package()?;
            let value = serde_json::json!({"schema":"ami-rust-package-verification-v2", "status":"VERIFIED",
                "cli_version":package.pins().cli_version,"sdk_version":package.pins().sdk_version,
                "package_version":package.pins().package_version,"host":package.pins().host,
                "verified_files":package.measurement().files,"verified_bytes":package.measurement().file_bytes});
            json_output(&value).map(CommandOutput::success)
        }
        Invocation::InspectMigration { project } => with_signals(|signals| {
            let report = crate::native_migrate::dry_run(&project, signals)?;
            encode_json_line(&report).map(CommandOutput::success)
        }),
        Invocation::MigrateProject { project, from_lock, prefix, receipt_sha256, output } => with_signals(|signals| {
            let report = crate::native_migrate::migrate(
                &project, &from_lock, &prefix, &receipt_sha256, &output, signals,
            )?;
            encode_json_line(&report).map(CommandOutput::success)
        }),
        Invocation::Prepare { state } => {
            let package = executing_package()?;
            let prepared = crate::native_prepare::prepare(&package, &state)?;
            let value = serde_json::to_value(prepared).map_err(|e| Refusal::new(e.to_string()))?;
            json_output(&value).map(CommandOutput::success)
        }
        Invocation::CheckInputs { state } => {
            let package = executing_package()?;
            let inputs = crate::ready_state::ReadyInputs::open(&state, &package)?;
            let value = serde_json::json!({"schema":"ami-rust-input-verification-v2", "status":"VERIFIED",
                "host":inputs.state.host,"sdk_version":inputs.state.sdk_version,
                "package_version":inputs.state.package_version,"components":6});
            json_output(&value).map(CommandOutput::success)
        }
        Invocation::NewProject { state, project } => with_signals(|signals| {
            let package = executing_package()?;
            let ready = crate::ready_state::ReadyInputs::open(&state, &package)?;
            let result = crate::native_project::create_project(&ready, &project, signals)?;
            encode_json_line(&result).map(CommandOutput::success)
        }),
        Invocation::VerifyLock { sdk_lock } => with_signals(|signals| {
            let checked = crate::native_project::verify_project_lock(&sdk_lock)?;
            signals.check()?;
            json_output(&serde_json::json!({
                "schema":"ami-rust-sdk-lock-verification-v2", "status":"VERIFIED",
                "host":checked.lock.host.platform,
                "sdk_manifest_sha256":checked.lock.sdk.manifest_sha256,
                "receipt_sha256":checked.installation.receipt_digest(),
                "claim":"receipt-owned native SDK and six local component inventories checked; Cargo inputs are checked by build, and publisher provenance is not re-established"
            })).map(CommandOutput::success)
        }),
        Invocation::BuildLock { sdk_lock, output, cargo } => with_build_signals(|signals| {
            let checked = crate::native_project::verify_project_lock(&sdk_lock)?;
            render_build(&checked, cargo, &output, signals)
        }),
        Invocation::BuildProject { state, project, output, cargo } => with_build_signals(|signals| {
            let package = executing_package()?;
            let ready = crate::ready_state::ReadyInputs::open(&state, &package)?;
            let checked = crate::native_project::verify_project_lock(&project.join("ami-rust.lock.json"))?;
            if checked.installation.path() != ready.installation.path()
                || checked.installation.receipt_digest() != ready.installation.receipt_digest()
            {
                return Err(Refusal::new("project lock belongs to another prepared SDK state"));
            }
            for name in ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"] {
                if checked.selected_inputs.component(name)?.path() != ready.selected.component(name)?.path() {
                    return Err(Refusal::new("project components differ from the explicit prepared state"));
                }
            }
            render_build(&checked, cargo, &output, signals)
        }),
        Invocation::LockProject { prefix, selection, project, output } => with_signals(|signals| {
            let file = crate::ownership::protected_regular_file(&selection, false)?;
            let raw = crate::publisher_files::read_open_regular(
                file, crate::json::JsonProfile::PackageMetadataStateSelection.max_bytes(),
            )?;
            let selection = crate::records::parse_selection(&raw)?;
            let installation = crate::native_install::CheckedNativeInstallation::open(
                &prefix, selection.install_receipt_sha256.as_str(),
            )?;
            let result = crate::native_project::lock_project(
                &installation, &selection, &project, &output, signals,
            )?;
            encode_json_line(&result).map(CommandOutput::success)
        }),
        Invocation::VerifyRelease { bundle, policy } => {
            render_verify_release(&bundle, &policy).map(CommandOutput::success)
        }
        Invocation::InstallRelease {
            bundle,
            policy,
            prefix,
            receipt_pin,
        } => render_install_release(&bundle, &policy, &prefix, receipt_pin.as_deref()),
        Invocation::Uninstall {
            prefix,
            receipt_sha256,
        } => render_uninstall(&prefix, &receipt_sha256).map(CommandOutput::success),
    }
}

fn render_build(
    checked: &crate::native_project::CheckedProject,
    cargo: crate::native_recipe::CargoBuildOptions,
    output: &Path,
    signals: &crate::signals::SigtermGuard,
) -> Result<CommandOutput> {
    let result = crate::native_build::run_build(checked, cargo, output, signals)?;
    if result.exit_code != 0 {
        return Err(Refusal::new(format!(
            "native build failed; command evidence retained at {}",
            output.display()
        ))
        .with_exit_code(result.exit_code));
    }
    json_output(&serde_json::json!({
        "status":"PASS", "native_executable":result.native_executable,
        "receipt":result.receipt,
    }))
    .map(CommandOutput::success)
}

fn with_signals<T>(
    operation: impl FnOnce(&crate::signals::SigtermGuard) -> Result<T>,
) -> Result<T> {
    with_signal_status(operation, false)
}

fn with_build_signals<T>(
    operation: impl FnOnce(&crate::signals::SigtermGuard) -> Result<T>,
) -> Result<T> {
    with_signal_status(operation, true)
}

fn with_signal_status<T>(
    operation: impl FnOnce(&crate::signals::SigtermGuard) -> Result<T>,
    direct_build: bool,
) -> Result<T> {
    let signals = crate::signals::SigtermGuard::acquire()?;
    let result = signals.check().and_then(|()| operation(&signals));
    let finished = if direct_build {
        signals.finish_requested()
    } else {
        signals.finish().map(|()| false)
    };
    match (result, finished) {
        (result, Ok(true)) => {
            let message = match result {
                Err(error) => format!("native build interrupted by SIGTERM: {error}"),
                Ok(_) => {
                    "SIGTERM requested after native build completion; output retained".to_owned()
                }
            };
            Err(Refusal::new(message).with_exit_code(143))
        }
        (Ok(value), Ok(false)) => Ok(value),
        (Err(error), Ok(false)) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(restore)) => Err(Refusal::new(format!(
            "{error}; SIGTERM restoration also failed: {restore}"
        ))
        .with_exit_code(error.exit_code())),
    }
}

fn optional_executing_package() -> Result<Option<crate::package::CheckedNativePackage>> {
    let executable = std::env::current_exe().map_err(|e| Refusal::new(e.to_string()))?;
    let Some(bin) = executable
        .parent()
        .filter(|path| path.file_name() == Some(std::ffi::OsStr::new("bin")))
    else {
        return Ok(None);
    };
    let Some(root) = bin.parent() else {
        return Ok(None);
    };
    // Standalone development binaries have no package claims. Once either
    // metadata file is present, incomplete/changed package data must refuse.
    if root.join("pins.json").try_exists()? || root.join("inventory.json").try_exists()? {
        executing_package().map(Some)
    } else {
        Ok(None)
    }
}

fn executing_package() -> Result<crate::package::CheckedNativePackage> {
    let executable = std::env::current_exe()
        .map_err(|e| Refusal::new(format!("cannot locate executing native package: {e}")))?;
    crate::package::package_from_executable(
        &executable,
        crate::package::PackageRuntime {
            host: crate::host_platform::supported_host()?,
            cli_version: env!("CARGO_PKG_VERSION"),
        },
    )
}

fn json_output(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_vec(value).map_err(|e| Refusal::new(e.to_string()))?;
    raw.push(b'\n');
    Ok(raw)
}

fn render_install_release(
    bundle_path: &Path,
    policy_path: &Path,
    prefix: &Path,
    receipt_pin: Option<&Path>,
) -> Result<CommandOutput> {
    let bundle_path = std::fs::canonicalize(bundle_path)
        .map_err(|error| Refusal::new(format!("could not resolve release bundle: {error}")))?;
    let policy_path = std::fs::canonicalize(policy_path)
        .map_err(|error| Refusal::new(format!("could not resolve external policy: {error}")))?;
    match crate::native_install::install(&bundle_path, &policy_path, prefix, receipt_pin) {
        Ok(published) => {
            let receipt_pin = published
                .receipt_pin
                .as_ref()
                .map(|path| OutputPath::from_path(path));
            let output = InstallResult {
                schema: "ami-rust-install-result-v1",
                status: "installed",
                prefix: OutputPath::from_path(&published.prefix),
                receipt_sha256: &published.receipt_sha256,
                receipt_pin,
                reason: None,
            };
            Ok(CommandOutput::success(encode_json_line(&output)?))
        }
        Err(failure) => {
            let crate::native_install::InstallFailure {
                reason,
                published,
                recovery,
            } = failure;
            if let Some(published) = published {
                let receipt_pin = published
                    .receipt_pin
                    .as_ref()
                    .map(|path| OutputPath::from_path(path));
                let reason = reason.to_string();
                let output = InstallResult {
                    schema: "ami-rust-install-result-v1",
                    status: "installed_with_error",
                    prefix: OutputPath::from_path(&published.prefix),
                    receipt_sha256: &published.receipt_sha256,
                    receipt_pin,
                    reason: Some(&reason),
                };
                Ok(CommandOutput {
                    stdout: encode_json_line(&output)?,
                    exit_code: 1,
                })
            } else {
                Err(recovery_refusal(reason, recovery.as_deref(), "staging"))
            }
        }
    }
}

fn render_uninstall(prefix: &Path, receipt_sha256: &str) -> Result<Vec<u8>> {
    crate::native_install::uninstall(prefix, receipt_sha256).map_err(|failure| {
        recovery_refusal(failure.reason, failure.recovery.as_deref(), "tombstone")
    })?;
    encode_json_line(&UninstallResult {
        schema: "ami-rust-uninstall-result-v1",
        status: "uninstalled",
        prefix: OutputPath::from_path(prefix),
        receipt_sha256,
    })
}

fn recovery_refusal(
    reason: impl std::fmt::Display,
    recovery: Option<&crate::transaction::RecoveryLocation>,
    label: &str,
) -> Refusal {
    match recovery {
        Some(recovery) => Refusal::new(format!(
            "{reason}; retained {label} entry {:?} under {:?} (parent identity {:?}, verified path {:?})",
            recovery.entry_name,
            recovery.last_known_parent,
            recovery.parent_identity,
            recovery.verified_path,
        )),
        None => Refusal::new(reason.to_string()),
    }
}

fn encode_json_line(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut output = serde_json::to_vec(value)
        .map_err(|error| Refusal::new(format!("cannot encode command result: {error}")))?;
    output.push(b'\n');
    Ok(output)
}

fn render_verify_release(bundle_path: &Path, policy_path: &Path) -> Result<Vec<u8>> {
    let guard = crate::signals::SigtermGuard::acquire()?;
    let result = (|| {
        guard.check()?;
        let bundle_path = std::fs::canonicalize(bundle_path)
            .map_err(|error| Refusal::new(format!("could not resolve release bundle: {error}")))?;
        let policy_path = std::fs::canonicalize(policy_path)
            .map_err(|error| Refusal::new(format!("could not resolve external policy: {error}")))?;
        guard.check()?;
        let verified =
            crate::publisher::verify_publisher_bundle(&bundle_path, &policy_path, || {
                guard.requested()
            })?;
        guard.check()?;
        let sdk = crate::sdk::compose_verified_sdk_v2(&verified)?;
        guard.check()?;

        let manifest = verified.manifest();
        let assets = manifest
            .assets
            .iter()
            .map(|asset| AssetSummary {
                path: &asset.path,
                bytes: asset.bytes,
                sha256: &asset.sha256,
            })
            .collect();
        let signature = verified.release_signature();
        let output = VerifyReleaseOutput {
            schema: "ami-rust-release-verification-v1",
            status: "verified",
            verification_scope: "publisher authentication and SDK-v2 structural verification only; R1 acceptance and native build qualification were not assessed",
            publisher: verified.authentication(),
            release_cosign_bundle: ArtifactIdentity {
                bytes: signature.len(),
                sha256: crate::digest::sha256_bytes(signature),
            },
            manifest: ManifestSummary {
                schema: "ami-rust-release-v2",
                version: &manifest.version,
                qualification_only: manifest.qualification_only,
                sdk_archive: &manifest.sdk_archive,
                sdk_manifest_sha256: &manifest.sdk_manifest_sha256,
                manifest_sha256: crate::digest::sha256_bytes(verified.raw_manifest()),
                assets,
            },
            sdk: &sdk,
            resource_reports: verified.resource_reports(),
        };
        let mut bytes = serde_json::to_vec(&output)
            .map_err(|error| Refusal::new(format!("cannot encode verification result: {error}")))?;
        bytes.push(b'\n');
        Ok(bytes)
    })();
    let finish = guard.finish();
    match (result, finish) {
        (Err(error), Err(cleanup)) => Err(Refusal::new(format!(
            "{error}; SIGTERM handler restoration also failed: {cleanup}"
        ))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(output), Ok(())) => Ok(output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::ffi::OsStringExt;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn build_signal_status_classification_is_isolated_in_a_child() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "frontend::tests::build_signal_status_child",
                "--ignored",
            ])
            .env("AMI_RUST_BUILD_SIGNAL_CHILD", "run")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run only through the isolated child-process parent"]
    fn build_signal_status_child() {
        assert_eq!(
            std::env::var("AMI_RUST_BUILD_SIGNAL_CHILD").as_deref(),
            Ok("run")
        );
        assert_eq!(with_build_signals(|_| Ok(17)).unwrap(), 17);
        let child_only =
            with_build_signals::<()>(
                |_| Err(Refusal::new("Cargo interrupted").with_exit_code(130)),
            )
            .unwrap_err();
        assert_eq!(child_only.exit_code(), 130);
        for prior_error in [false, true] {
            let own_signal = with_build_signals(|_| {
                send_build_fixture_sigterm();
                if prior_error {
                    Err(Refusal::new("Cargo cleanup completed").with_exit_code(130))
                } else {
                    Ok(17)
                }
            })
            .unwrap_err();
            assert_eq!(own_signal.exit_code(), 143);
        }
    }

    #[allow(
        unsafe_code,
        reason = "The isolated fixture synchronously raises SIGTERM on its own thread."
    )]
    fn send_build_fixture_sigterm() {
        // SAFETY: raise targets the calling fixture thread; its live guard has
        // installed the cooperative handler and SIGTERM is a valid signal.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    }

    #[test]
    fn builds_preserve_the_direct_recipe_and_package_defaults_on_both_frontends() {
        let direct = args(&[
            "build",
            "--sdk-lock",
            "lock.json",
            "--output-dir",
            "/out",
            "--",
            "build",
            "--manifest-path",
            "/project/Cargo.toml",
            "-p",
            "application",
            "--release",
            "--locked",
            "--offline",
        ]);
        let package = args(&[
            "build",
            "--state",
            "/state",
            "--project",
            "/project",
            "--output-dir",
            "/out",
            "--",
            "--features",
            "extra",
        ]);
        for argv in [direct, package] {
            let expected = parse(Path::new("ami-rust"), &argv).unwrap();
            let mut plugin = args(&["ami"]);
            plugin.extend(argv);
            assert_eq!(parse(Path::new("cargo-ami"), &plugin).unwrap(), expected);
            if let Invocation::BuildProject { cargo, .. } = expected {
                assert_eq!(cargo.package, "hello-aros");
                assert_eq!(
                    cargo.features.as_deref(),
                    Some(std::ffi::OsStr::new("extra"))
                );
            }
        }
        for invalid in [
            args(&["build", "--sdk-lock", "lock", "--output-dir", "/out"]),
            args(&[
                "build",
                "--sdk-lock",
                "lock",
                "--output-dir",
                "/out",
                "--",
                "build",
            ]),
            args(&[
                "build",
                "--state",
                "/state",
                "--sdk-lock",
                "lock",
                "--output-dir",
                "/out",
                "--",
                "build",
            ]),
            args(&[
                "build",
                "--state",
                "/state",
                "--project",
                "/p",
                "--output-dir",
                "/out",
                "--",
                "--target",
                "other",
            ]),
            args(&[
                "build",
                "--state",
                "/state",
                "--project",
                "/p",
                "--output-dir",
                "/out",
                "--",
                "--release",
            ]),
            args(&["new", "--state", "/state", "--project", "relative"]),
        ] {
            assert!(
                parse(Path::new("ami-rust"), &invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn both_names_share_parser_and_exact_separator_rules() {
        for (argv, expected) in [
            (args(&["--version"]), Some(Invocation::Version)),
            (args(&["--help"]), Some(Invocation::Help)),
            (args(&["-h"]), Some(Invocation::Help)),
            (args(&[]), None),
            (args(&["--version", "--version"]), None),
            (args(&["--version", "extra"]), None),
            (args(&["--", "--version"]), None),
            (args(&["unknown"]), None),
            (args(&["ami", "--version"]), None),
        ] {
            assert_eq!(parse(Path::new("ami-rust"), &argv).ok(), expected);
            // Cargo's token is prepended once, then removed once.
            let mut injected = args(&["ami"]);
            injected.extend(argv.clone());
            assert_eq!(parse(Path::new("cargo-ami"), &injected).ok(), expected);
        }
        assert_eq!(
            parse(Path::new("cargo-ami"), &args(&["--version"])).unwrap(),
            Invocation::Version
        );
    }

    #[test]
    fn project_commands_share_exact_options_and_refuse_mixed_modes() {
        let cases = [
            (
                args(&["new", "--project", "/new project", "--state", "/state"]),
                Invocation::NewProject {
                    state: PathBuf::from("/state"),
                    project: PathBuf::from("/new project"),
                },
            ),
            (
                args(&[
                    "lock",
                    "--prefix",
                    "/sdk",
                    "--project",
                    "/project",
                    "--selection",
                    "selection.json",
                    "--output",
                    "lock.json",
                ]),
                Invocation::LockProject {
                    prefix: PathBuf::from("/sdk"),
                    project: PathBuf::from("/project"),
                    selection: PathBuf::from("selection.json"),
                    output: PathBuf::from("lock.json"),
                },
            ),
            (
                args(&["verify", "--sdk-lock", "lock.json"]),
                Invocation::VerifyLock {
                    sdk_lock: PathBuf::from("lock.json"),
                },
            ),
        ];
        for (argv, expected) in cases {
            assert_eq!(parse(Path::new("ami-rust"), &argv).unwrap(), expected);
            let mut plugin = args(&["ami"]);
            plugin.extend(argv);
            assert_eq!(parse(Path::new("cargo-ami"), &plugin).unwrap(), expected);
        }
        for invalid in [
            args(&["new", "--state", "/state"]),
            args(&[
                "new",
                "--state",
                "/state",
                "--project",
                "/a",
                "--project",
                "/b",
            ]),
            args(&[
                "lock",
                "--prefix",
                "/sdk",
                "--selection",
                "sel",
                "--project",
                "/p",
            ]),
            args(&[
                "lock",
                "--prefix",
                "/sdk",
                "--selection",
                "sel",
                "--project",
                "/p",
                "--output",
                "o",
                "--python",
                "p",
            ]),
            args(&["verify", "--sdk-lock", "a", "--sdk-lock", "b"]),
            args(&[
                "verify",
                "--bundle",
                "b",
                "--sdk-lock",
                "a",
                "--policy",
                "p",
            ]),
        ] {
            assert!(
                parse(Path::new("ami-rust"), &invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn verify_release_requires_one_bundle_and_policy_in_either_order() {
        let expected = Invocation::VerifyRelease {
            bundle: PathBuf::from("bundle-dir"),
            policy: PathBuf::from("policy.json"),
        };
        for argv in [
            args(&[
                "verify",
                "--bundle",
                "bundle-dir",
                "--policy",
                "policy.json",
            ]),
            args(&[
                "verify",
                "--policy",
                "policy.json",
                "--bundle",
                "bundle-dir",
            ]),
        ] {
            assert_eq!(parse(Path::new("ami-rust"), &argv).unwrap(), expected);
            let mut injected = args(&["ami"]);
            injected.extend(argv);
            assert_eq!(parse(Path::new("cargo-ami"), &injected).unwrap(), expected);
        }
    }

    #[test]
    fn verify_release_preserves_non_utf8_paths_and_refuses_ambiguous_arguments() {
        let bundle = OsString::from_vec(b"bundle-\xff".to_vec());
        let parsed = parse(
            Path::new("ami-rust"),
            &[
                OsString::from("verify"),
                OsString::from("--bundle"),
                bundle.clone(),
                OsString::from("--policy"),
                OsString::from("policy.json"),
            ],
        )
        .unwrap();
        assert_eq!(
            parsed,
            Invocation::VerifyRelease {
                bundle: PathBuf::from(bundle),
                policy: PathBuf::from("policy.json"),
            }
        );

        for argv in [
            args(&["verify"]),
            args(&["verify", "--bundle"]),
            args(&["verify", "--bundle", "bundle-dir"]),
            args(&[
                "verify",
                "--bundle",
                "bundle-dir",
                "--bundle",
                "other-dir",
                "--policy",
                "policy.json",
            ]),
            args(&[
                "verify",
                "--bundle",
                "bundle-dir",
                "--policy",
                "policy.json",
                "--policy",
                "other.json",
            ]),
            args(&["verify", "--bundle", "--policy", "policy.json"]),
            args(&["verify", "--bundle", "--unknown", "--policy", "policy.json"]),
            args(&["verify", "--unknown", "value"]),
            args(&["verify", "bundle-dir", "--policy", "policy.json"]),
            args(&[
                "verify",
                "--sdk-lock",
                "lock.json",
                "--bundle",
                "bundle-dir",
            ]),
        ] {
            assert!(parse(Path::new("ami-rust"), &argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn install_and_uninstall_parse_exact_paths_and_receipt_digest() {
        let expected = Invocation::InstallRelease {
            bundle: PathBuf::from("bundle"),
            policy: PathBuf::from("policy.json"),
            prefix: PathBuf::from("/opt/ami-rust"),
            receipt_pin: Some(PathBuf::from("/tmp/receipt.pin")),
        };
        for argv in [
            args(&[
                "install",
                "--bundle",
                "bundle",
                "--policy",
                "policy.json",
                "--prefix",
                "/opt/ami-rust",
                "--receipt-pin",
                "/tmp/receipt.pin",
            ]),
            args(&[
                "install",
                "--receipt-pin",
                "/tmp/receipt.pin",
                "--prefix",
                "/opt/ami-rust",
                "--policy",
                "policy.json",
                "--bundle",
                "bundle",
            ]),
        ] {
            assert_eq!(parse(Path::new("ami-rust"), &argv).unwrap(), expected);
        }

        let digest = "a".repeat(64);
        let upper_digest = "A".repeat(64);
        assert_eq!(
            parse(
                Path::new("ami-rust"),
                &args(&[
                    "uninstall",
                    "--prefix",
                    "/opt/ami-rust",
                    "--receipt-sha256",
                    &digest,
                ])
            )
            .unwrap(),
            Invocation::Uninstall {
                prefix: PathBuf::from("/opt/ami-rust"),
                receipt_sha256: digest.clone(),
            }
        );

        for argv in [
            args(&["install"]),
            args(&["install", "--bundle", "bundle", "--policy", "policy.json"]),
            args(&[
                "install",
                "--bundle",
                "bundle",
                "--policy",
                "policy.json",
                "--prefix",
                "/opt/ami-rust",
                "--prefix",
                "/opt/other",
            ]),
            args(&[
                "install",
                "--bundle",
                "bundle",
                "--policy",
                "policy.json",
                "--prefix",
                "/opt/ami-rust",
                "--other",
                "value",
            ]),
            args(&[
                "install",
                "--bundle",
                "bundle",
                "--policy",
                "policy.json",
                "--prefix",
                "/opt/ami-rust",
                "--receipt-pin",
                "/tmp/receipt.pin",
                "--receipt-pin",
                "/tmp/other.pin",
            ]),
            args(&["uninstall", "--prefix", "/opt/ami-rust"]),
            args(&[
                "uninstall",
                "--prefix",
                "/opt/ami-rust",
                "--receipt-sha256",
                upper_digest.as_str(),
            ]),
            args(&[
                "uninstall",
                "--prefix",
                "/opt/ami-rust",
                "--receipt-sha256",
                digest.as_str(),
                "--unknown",
                "value",
            ]),
        ] {
            assert!(parse(Path::new("ami-rust"), &argv).is_err(), "{argv:?}");
        }
    }

    #[test]
    fn result_paths_preserve_non_utf8_unix_bytes_and_keep_utf8_as_strings() {
        let utf8_path = Path::new("/opt/ami-rust");
        assert_eq!(
            serde_json::to_value(OutputPath::from_path(utf8_path)).unwrap(),
            serde_json::json!("/opt/ami-rust")
        );

        let raw_prefix = b"/tmp/ami-prefix-\xff";
        let prefix = PathBuf::from(OsString::from_vec(raw_prefix.to_vec()));
        assert_eq!(prefix.as_os_str().as_bytes(), raw_prefix);
        let raw_pin = b"/tmp/ami-pin-\xfe";
        let pin = PathBuf::from(OsString::from_vec(raw_pin.to_vec()));
        assert_eq!(pin.as_os_str().as_bytes(), raw_pin);

        let install = InstallResult {
            schema: "ami-rust-install-result-v1",
            status: "installed",
            prefix: OutputPath::from_path(&prefix),
            receipt_sha256: "aabb",
            receipt_pin: Some(OutputPath::from_path(&pin)),
            reason: None,
        };
        let install_json = serde_json::to_value(install).unwrap();
        let expected_prefix = serde_json::json!({
            "encoding": "unix-path-bytes-v1",
            "bytes": raw_prefix,
        });
        let expected_pin = serde_json::json!({
            "encoding": "unix-path-bytes-v1",
            "bytes": raw_pin,
        });
        assert_eq!(install_json["prefix"], expected_prefix);
        assert_eq!(install_json["receipt_pin"], expected_pin);

        let uninstall = UninstallResult {
            schema: "ami-rust-uninstall-result-v1",
            status: "uninstalled",
            prefix: OutputPath::from_path(&prefix),
            receipt_sha256: "aabb",
        };
        let uninstall_json = serde_json::to_value(uninstall).unwrap();
        assert_eq!(uninstall_json["prefix"], expected_prefix);
    }

    #[test]
    fn native_package_commands_share_exact_state_options_on_both_frontends() {
        for binary in ["ami-rust", "cargo-ami"] {
            let executable = Path::new(binary);
            assert_eq!(
                parse(executable, &args(&["verify-package"])).unwrap(),
                Invocation::VerifyPackage
            );
            assert_eq!(
                parse(executable, &args(&["prepare", "--state", "/private/state"])).unwrap(),
                Invocation::Prepare {
                    state: PathBuf::from("/private/state")
                }
            );
            assert_eq!(
                parse(
                    executable,
                    &args(&["check-inputs", "--state", "/private/state"])
                )
                .unwrap(),
                Invocation::CheckInputs {
                    state: PathBuf::from("/private/state")
                }
            );
            for invalid in [
                args(&["prepare"]),
                args(&["prepare", "--state"]),
                args(&["prepare", "--state", "/one", "--state", "/two"]),
                args(&["check-inputs", "--project", "/one"]),
                args(&["verify-package", "extra"]),
            ] {
                assert!(parse(executable, &invalid).is_err());
            }
        }
    }

    #[test]
    fn capability_ledger_matches_normative_contract_and_refuses_pending_work() {
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/rust-cli-migration/contracts-v1.json"
        ))
        .unwrap();
        let expected: BTreeSet<_> = contract["future_frontend_contract"]["capability_matrix"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["capability"].as_str().unwrap())
            .collect();
        let actual: BTreeSet<_> = CAPABILITIES.iter().map(|item| item.name).collect();
        assert_eq!(actual.len(), CAPABILITIES.len());
        assert_eq!(actual, expected);
        assert_eq!(
            CAPABILITIES.iter().filter(|item| item.implemented).count(),
            13
        );
        assert!(CAPABILITIES.iter().any(|item| {
            item.name == "verify release" && item.command == "verify" && item.implemented
        }));
        assert!(CAPABILITIES.iter().any(|item| {
            item.name == "verify SDK lock" && item.command == "verify" && item.implemented
        }));
        assert!(CAPABILITIES.iter().any(|item| {
            item.name == "install release" && item.command == "install" && item.implemented
        }));
        assert!(CAPABILITIES.iter().any(|item| {
            item.name == "uninstall" && item.command == "uninstall" && item.implemented
        }));
        assert_eq!(
            parse(
                Path::new("ami-rust"),
                &args(&["verify", "--sdk-lock", "lock.json"])
            )
            .unwrap(),
            Invocation::VerifyLock {
                sdk_lock: PathBuf::from("lock.json")
            }
        );
        for item in CAPABILITIES.iter().filter(|item| !item.implemented) {
            if CAPABILITIES
                .iter()
                .any(|candidate| candidate.command == item.command && candidate.implemented)
            {
                continue;
            }
            let error = parse(Path::new("ami-rust"), &args(&[item.command])).unwrap_err();
            assert!(error.to_string().contains("not implemented"));
        }
    }

    #[test]
    fn migration_is_read_only_by_default_and_requires_complete_explicit_write_options() {
        for binary in ["ami-rust", "cargo-ami"] {
            for arguments in [
                args(&["migrate", "--project", "/project"]),
                args(&["migrate", "--dry-run", "--project", "/project"]),
                args(&["migrate", "--project", "/project", "--dry-run"]),
            ] {
                assert_eq!(
                    parse(Path::new(binary), &arguments).unwrap(),
                    Invocation::InspectMigration {
                        project: PathBuf::from("/project")
                    }
                );
            }
            let digest = "a".repeat(64);
            let write = args(&[
                "migrate",
                "--project",
                "/project",
                "--from-lock",
                "/old.json",
                "--install-prefix",
                "/sdk",
                "--receipt-sha256",
                &digest,
                "--output",
                "/new.json",
            ]);
            assert_eq!(
                parse(Path::new(binary), &write).unwrap(),
                Invocation::MigrateProject {
                    project: "/project".into(),
                    from_lock: "/old.json".into(),
                    prefix: "/sdk".into(),
                    receipt_sha256: digest,
                    output: "/new.json".into(),
                }
            );
            for invalid in [
                args(&["migrate"]),
                args(&["migrate", "--project", "--dry-run", "/project"]),
                args(&["migrate", "--project", "/p", "--dry-run", "--dry-run"]),
                args(&["migrate", "--project", "/p", "--output", "/new"]),
                args(&[
                    "migrate",
                    "--project",
                    "/p",
                    "--dry-run",
                    "--output",
                    "/new",
                ]),
                args(&[
                    "migrate",
                    "--project",
                    "/p",
                    "--from-lock",
                    "/old",
                    "--install-prefix",
                    "/sdk",
                    "--receipt-sha256",
                    "bad",
                    "--output",
                    "/new",
                ]),
            ] {
                assert!(parse(Path::new(binary), &invalid).is_err());
            }
        }
    }
}
