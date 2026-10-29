//! Protected acquisition of the pinned inputs consumed by the Rust capsule builder.
//!
//! This is deliberately a maintainer operation.  It prepares local, unsigned
//! material only; the following capsule command owns archive composition.

use ami_rust_core::{
    Refusal, Result,
    acquisition::{
        AcquisitionObservationConfig, CurlExecutablePin, DownloadLimits, DownloadPin,
        HttpsOrigin, acquire_pinned_download,
    },
    directory::Directory,
    digest::{is_sha256_digest, sha256_file},
    ownership,
    process_capture::{self, CaptureLimits, CommandSpec},
    resource_capture::{ResourceLimits, SampleLimits},
    workspace_accounting::ScanLimits,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MANIFEST_PATH: &str = "release/toolchain-source-inputs.json";
const MANIFEST_SCHEMA: &str = "ami-rust-toolchain-capsule-inputs-v1";
const REQUEST_SCHEMA: &str = "ami-rust-toolchain-capsule-request-v1";
const RESULT_SCHEMA: &str = "ami-rust-toolchain-capsule-input-acquisition-v1";
const SUCCESS_STATUS: &str = "CAPSULE_INPUTS_PREPARED_LOCAL_ONLY";
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(1_200);
const COMMAND_STDOUT_BYTES: usize = 2 * 1024 * 1024;
const COMMAND_STDERR_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    source_inputs: Vec<SourceInput>,
    vendor_inputs: Vec<RepositoryInput>,
    source_scope: String,
    distributed_rust_source_commit: String,
    cargo_source_commit: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SourceInput {
    Download(DownloadInput),
    Repository(RepositorySourceInput),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadInput {
    role: String,
    filename: String,
    bytes: u64,
    sha256: String,
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositorySourceInput {
    role: String,
    filename: String,
    bytes: u64,
    sha256: String,
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryInput {
    role: String,
    path: String,
    bytes: u64,
    sha256: String,
}

struct Options {
    source_root: PathBuf,
    version: String,
    output: PathBuf,
    curl: PathBuf,
}

pub fn run(arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let options = parse_options(arguments)?;
    let result = acquire(options)?;
    println!("{}", serde_json::to_string(&result).map_err(|error| Refusal::new(error.to_string()))?);
    Ok(())
}

fn parse_options(mut arguments: impl Iterator<Item = OsString>) -> Result<Options> {
    let mut source_root = None;
    let mut version = None;
    let mut output = None;
    let mut curl = None;
    while let Some(key) = arguments.next() {
        let value = arguments.next().ok_or_else(usage)?;
        match key.to_str() {
            Some("--source-root") => {
                if source_root.replace(PathBuf::from(value)).is_some() { return Err(usage()); }
            }
            Some("--version") => {
                if version.replace(value).is_some() { return Err(usage()); }
            }
            Some("--output") => {
                if output.replace(PathBuf::from(value)).is_some() { return Err(usage()); }
            }
            Some("--curl") => {
                if curl.replace(PathBuf::from(value)).is_some() { return Err(usage()); }
            }
            _ => return Err(usage()),
        }
    }
    Ok(Options {
        source_root: source_root.ok_or_else(usage)?,
        version: version
            .ok_or_else(usage)?
            .into_string()
            .map_err(|_| Refusal::new("version must be UTF-8"))?,
        output: output.ok_or_else(usage)?,
        curl: curl.ok_or_else(usage)?,
    })
}

fn acquire(options: Options) -> Result<Value> {
    let started = Instant::now();
    validate_context()?;
    validate_version(&options.version)?;
    let source = canonical_directory(&options.source_root, "source_root")?;
    let output = fresh_directory(&options.output, "acquisition output")?;
    if overlaps(&source, &output) {
        return Err(Refusal::new("acquisition output must be disjoint from the source checkout"));
    }
    let git = resolve_executable("git")?;
    let identity = source_identity(&git, &source, started)?;
    let manifest_path = local_file(&source, MANIFEST_PATH)?;
    let manifest_raw = read_regular(&manifest_path, MAX_JSON_BYTES)?;
    verify_git_blob(&git, &source, MANIFEST_PATH, &manifest_raw, started)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_raw)
        .map_err(|error| Refusal::new(format!("source input manifest has an invalid shape: {error}")))?;
    validate_manifest(&manifest)?;

    let parent = output.parent().ok_or_else(|| Refusal::new("acquisition output has no parent"))?;
    let parent_directory = Directory::open(parent)?;
    let stage = fresh_stage(
        parent,
        output
            .file_name()
            .ok_or_else(|| Refusal::new("acquisition output has no name"))?,
    )?;
    let result = (|| {
        let downloads = stage.join("downloads");
        fs::create_dir(&downloads)?;
        let curl = pinned_curl(&options.curl)?;
        let mut source_rows = Vec::new();
        let mut vendor_rows = Vec::new();
        let mut result_source = Vec::new();
        let mut result_vendor = Vec::new();
        let mut transfers = Vec::new();

        for input in &manifest.source_inputs {
            check_deadline(started)?;
            match input {
                SourceInput::Download(row) => {
                    let role = checked_component(&row.role, "material role")?;
                    checked_component(&row.filename, "material filename")?;
                    validate_identity(row.bytes, &row.sha256, &role)?;
                    let destination_dir = downloads.join(&role);
                    fs::create_dir(&destination_dir)?;
                    let destination = destination_dir.join(&row.filename);
                    let target = ownership::fresh_output(&destination)?;
                    let pin = DownloadPin::new(
                        &row.url,
                        row.bytes,
                        &row.sha256,
                        url_origin(&row.url)?,
                        redirect_origins(&row.url)?,
                    )?;
                    let observation = observation(&stage);
                    let acquired = acquire_pinned_download(
                        &pin,
                        &curl,
                        &target,
                        DownloadLimits {
                            max_bytes: row.bytes,
                            total_timeout: Duration::from_secs(180),
                            per_hop_timeout: Duration::from_secs(30),
                            termination_grace: Duration::from_secs(2),
                            max_redirects: 3,
                            max_header_bytes: 64 * 1024,
                            max_stderr_bytes: 64 * 1024,
                        },
                        &observation,
                        || started.elapsed() >= DEADLINE,
                    )?;
                    if acquired.bytes != row.bytes || acquired.sha256 != row.sha256 {
                        return Err(Refusal::new("download result differs from its pin"));
                    }
                    let target_path = output.join("downloads").join(&role).join(&row.filename);
                    source_rows.push(json!({"role":role,"path":target_path,"bytes":row.bytes,"sha256":row.sha256}));
                    result_source.push(json!({"role":row.role,"path":format!("downloads/{}/{}", row.role, row.filename),"origin":row.url,"bytes":row.bytes,"sha256":row.sha256}));
                    transfers.push(json!({"role":row.role,"url":row.url,"resource_reports":acquired.resource_reports}));
                }
                SourceInput::Repository(row) => {
                    let path = repository_material(&git, &source, &row.role, &row.path, row.bytes, &row.sha256, started)?;
                    if Path::new(&row.path).file_name().and_then(|value| value.to_str()) != Some(row.filename.as_str()) {
                        return Err(Refusal::new("repository source filename differs from its path basename"));
                    }
                    source_rows.push(json!({"role":row.role,"path":path,"bytes":row.bytes,"sha256":row.sha256}));
                    result_source.push(json!({"role":row.role,"path":row.path,"origin":"repository Git blob","bytes":row.bytes,"sha256":row.sha256}));
                }
            }
        }
        for row in &manifest.vendor_inputs {
            let path = repository_material(&git, &source, &row.role, &row.path, row.bytes, &row.sha256, started)?;
            vendor_rows.push(json!({"role":row.role,"path":path,"bytes":row.bytes,"sha256":row.sha256}));
            result_vendor.push(json!({"role":row.role,"path":row.path,"origin":"repository Git blob","bytes":row.bytes,"sha256":row.sha256}));
        }
        let request = json!({
            "schema":REQUEST_SCHEMA, "version":options.version, "source":identity,
            "source_root":source, "source_inputs":source_rows, "vendor_inputs":vendor_rows,
            "output":output.join("capsules"),
        });
        let request_raw = canonical_json(&request)?;
        write_new(&stage.join("capsule-request.json"), &request_raw)?;
        write_new(&stage.join("source-input-manifest.json"), &manifest_raw)?;
        let result = json!({
            "schema":RESULT_SCHEMA, "status":SUCCESS_STATUS,
            "claim":"Pinned source/vendor inputs and a local Rust capsule request were prepared. This result does not authenticate the workflow or inputs, execute the Rust capsule builder, establish completeness or legal sufficiency, or sign, publish, qualify, or accept RC3.",
            "version":options.version, "source":identity,
            "workflow_context":{"repository":"metaneutrons/ami-rust","ref":"refs/heads/main","event_name":"workflow_dispatch","protected":true},
            "manifest":{"source_path":MANIFEST_PATH,"output_path":"source-input-manifest.json","bytes":manifest_raw.len(),"sha256":ami_rust_core::digest::sha256_bytes(&manifest_raw)},
            "source_scope":manifest.source_scope, "distributed_rust_source_commit":manifest.distributed_rust_source_commit,
            "cargo_source_commit":manifest.cargo_source_commit, "source_inputs":result_source,
            "vendor_inputs":result_vendor, "transfers":transfers,
            "capsule_request":{"path":"capsule-request.json","bytes":request_raw.len(),"sha256":ami_rust_core::digest::sha256_bytes(&request_raw)},
            "capsule_output_path":output.join("capsules"),
        });
        write_new(&stage.join("acquisition-result.json"), &canonical_json(&result)?)?;
        verify_git_blob(&git, &source, MANIFEST_PATH, &manifest_raw, started)?;
        for input in &manifest.source_inputs {
            if let SourceInput::Repository(row) = input {
                repository_material(&git, &source, &row.role, &row.path, row.bytes, &row.sha256, started)?;
            }
        }
        for row in &manifest.vendor_inputs {
            repository_material(&git, &source, &row.role, &row.path, row.bytes, &row.sha256, started)?;
        }
        source_identity(&git, &source, started)?;
        Ok(result)
    })();
    match result {
        Ok(result) => {
            if fs::symlink_metadata(&output).is_ok() {
                let refusal = Refusal::new("acquisition output appeared during preparation");
                retain_failure(&stage, &refusal)?;
                return Err(Refusal::new(format!(
                    "{refusal}; acquisition work retained at {}",
                    stage.display()
                )));
            }
            let stage_name = stage.file_name().expect("fresh stage has a basename");
            let output_name = output.file_name().expect("fresh output has a basename");
            if let Err(error) = parent_directory.rename_no_replace(stage_name, &parent_directory, output_name) {
                let refusal = Refusal::new(format!(
                    "could not atomically publish prepared capsule inputs: {error}"
                ));
                retain_failure(&stage, &refusal)?;
                return Err(Refusal::new(format!(
                    "{refusal}; acquisition work retained at {}",
                    stage.display()
                )));
            }
            Ok(result)
        }
        Err(error) => {
            retain_failure(&stage, &error)?;
            Err(Refusal::new(format!(
                "{error}; acquisition work retained at {}",
                stage.display()
            )))
        }
    }
}

fn validate_context() -> Result<()> {
    for (key, expected) in [("GITHUB_REPOSITORY", "metaneutrons/ami-rust"), ("GITHUB_REF", "refs/heads/main"), ("GITHUB_EVENT_NAME", "workflow_dispatch"), ("NATIVE_REF_PROTECTED", "true")] {
        if env::var(key).ok().as_deref() != Some(expected) { return Err(Refusal::new("acquisition requires protected metaneutrons/ami-rust main workflow_dispatch context")); }
    }
    let sha = env::var("GITHUB_SHA").unwrap_or_default();
    if !git_id(&sha) { return Err(Refusal::new("GITHUB_SHA must be a lowercase full Git object ID")); }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.schema != MANIFEST_SCHEMA || manifest.source_inputs.is_empty() || manifest.vendor_inputs.is_empty() || manifest.source_scope.trim().is_empty() || !git_id(&manifest.distributed_rust_source_commit) || !git_id(&manifest.cargo_source_commit) {
        return Err(Refusal::new("source input manifest has an unsupported closed schema"));
    }
    let mut roles = BTreeSet::new();
    for row in &manifest.source_inputs {
        match row {
            SourceInput::Download(row) => { checked_component(&row.role, "material role")?; checked_component(&row.filename, "material filename")?; validate_identity(row.bytes, &row.sha256, &row.role)?; if url_origin(&row.url).is_err() { return Err(Refusal::new("source input URL is not a permitted pinned HTTPS origin")); } if !roles.insert(row.role.as_str()) { return Err(Refusal::new("material role is duplicated")); } }
            SourceInput::Repository(row) => { checked_component(&row.role, "material role")?; checked_component(&row.filename, "material filename")?; validate_identity(row.bytes, &row.sha256, &row.role)?; repository_path(&row.path)?; if !roles.insert(row.role.as_str()) { return Err(Refusal::new("material role is duplicated")); } }
        }
    }
    for row in &manifest.vendor_inputs { checked_component(&row.role, "material role")?; validate_identity(row.bytes, &row.sha256, &row.role)?; repository_path(&row.path)?; if !roles.insert(row.role.as_str()) { return Err(Refusal::new("material role is duplicated")); } }
    Ok(())
}

fn repository_material(git: &Path, source: &Path, role: &str, relative: &str, bytes: u64, sha256: &str, started: Instant) -> Result<PathBuf> {
    checked_component(role, "material role")?;
    validate_identity(bytes, sha256, role)?;
    repository_path(relative)?;
    let path = local_file(source, relative)?;
    let raw = read_regular(&path, usize::try_from(bytes).map_err(|_| Refusal::new("material is too large"))?)?;
    if raw.len() as u64 != bytes || ami_rust_core::digest::sha256_bytes(&raw) != sha256 { return Err(Refusal::new("repository material differs from its pinned bytes")); }
    verify_git_blob(git, source, relative, &raw, started)?;
    Ok(path)
}

fn source_identity(git: &Path, source: &Path, started: Instant) -> Result<Value> {
    let root = git_output(git, source, &["rev-parse", "--show-toplevel"], started)?;
    if PathBuf::from(text(&root)?).as_path() != source { return Err(Refusal::new("source_root is not the exact canonical Git repository root")); }
    let commit = text(&git_output(git, source, &["rev-parse", "--verify", "HEAD"], started)?)?;
    let tree = text(&git_output(git, source, &["rev-parse", "--verify", "HEAD^{tree}"], started)?)?;
    let epoch: u64 = text(&git_output(git, source, &["show", "-s", "--format=%ct", "HEAD"], started)?)?.parse().map_err(|_| Refusal::new("source commit timestamp is invalid"))?;
    let status = git_output(git, source, &["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"], started)?;
    if !git_id(&commit) || !git_id(&tree) || epoch == 0 || !status.is_empty() || env::var("GITHUB_SHA").ok().as_deref() != Some(&commit) { return Err(Refusal::new("source checkout is not clean at the exact GITHUB_SHA commit/tree")); }
    Ok(json!({"commit":commit,"tree":tree,"epoch":epoch}))
}

fn verify_git_blob(git: &Path, source: &Path, relative: &str, expected: &[u8], started: Instant) -> Result<()> {
    let committed = text(&git_output(
        git,
        source,
        &["rev-parse", &format!("HEAD:{relative}")],
        started,
    )?)?;
    let checked_out = text(&git_output(
        git,
        source,
        &["hash-object", "--no-filters", "--", relative],
        started,
    )?)?;
    if !git_id(&committed)
        || committed != checked_out
        || ami_rust_core::digest::sha256_bytes(expected)
            != ami_rust_core::digest::sha256_file(&source.join(relative))?
    {
        return Err(Refusal::new(
            "repository material differs from its pinned Git bytes",
        ));
    }
    Ok(())
}

fn git_output(git: &Path, source: &Path, arguments: &[&str], started: Instant) -> Result<Vec<u8>> {
    let mut command_arguments = vec![
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-C"),
        source.as_os_str().to_owned(),
    ];
    command_arguments.extend(arguments.iter().map(OsString::from));
    let command = CommandSpec::new(
        git.as_os_str(),
        command_arguments,
        source,
        git_environment(),
    );
    let captured = process_capture::capture(
        &command,
        CaptureLimits {
            timeout: remaining(started)?,
            stdout_bytes: COMMAND_STDOUT_BYTES,
            stderr_bytes: COMMAND_STDERR_BYTES,
            termination_grace: Duration::from_secs(2),
        },
        || started.elapsed() >= DEADLINE,
    )
    .map_err(|error| Refusal::new(format!("bounded Git source inspection failed: {error}")))?;
    if captured.exit_code() != Some(0) || captured.stdout.len() > MAX_JSON_BYTES {
        return Err(Refusal::new("Git source inspection failed"));
    }
    Ok(captured.stdout)
}

fn pinned_curl(path: &Path) -> Result<CurlExecutablePin> {
    let path = fs::canonicalize(path).map_err(|error| Refusal::new(format!("curl executable is unavailable: {error}")))?;
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 { return Err(Refusal::new("curl executable must be an executable regular file")); }
    Ok(CurlExecutablePin::new(&path, sha256_file(&path)?)?)
}

fn observation(root: &Path) -> AcquisitionObservationConfig {
    AcquisitionObservationConfig { resource_limits: ResourceLimits { max_visible_rss_bytes: 4 * 1024 * 1024 * 1024, max_workspace_bytes: 12 * 1024 * 1024 * 1024, max_log_bytes: 16 * 1024 * 1024 }, sample_limits: SampleLimits { max_ps_bytes: 2 * 1024 * 1024, max_ps_rows: 32_768, max_history_entries: 131_072, max_roots: 1, scan: ScanLimits { max_entries: 100_000, max_work_units: 200_001 } }, required_roots: vec![root.to_path_buf()] }
}

fn url_origin(url: &str) -> Result<HttpsOrigin> {
    if !url.is_ascii() || url.contains('?') || url.contains('#') || url.contains('%') || url.contains(' ') { return Err(Refusal::new("source input URL has unsupported syntax")); }
    if url.starts_with("https://static.rust-lang.org/") { Ok(HttpsOrigin::StaticRustLang) } else if url.starts_with("https://github.com/") { Ok(HttpsOrigin::Github) } else if url.starts_with("https://raw.githubusercontent.com/") { Ok(HttpsOrigin::RawGithub) } else { Err(Refusal::new("source input URL is not a permitted pinned HTTPS origin")) }
}

fn redirect_origins(url: &str) -> Result<Vec<HttpsOrigin>> { Ok(if matches!(url_origin(url)?, HttpsOrigin::Github) { vec![HttpsOrigin::GithubReleaseAssets, HttpsOrigin::GithubObjects] } else { Vec::new() }) }

fn fresh_stage(parent: &Path, output_name: &OsStr) -> Result<PathBuf> {
    let parent = canonical_directory(parent, "acquisition output parent")?;
    for index in 0..1_000_u32 {
        let path = parent.join(format!(
            ".{}.capsule-inputs-{}-{index}.work",
            output_name.to_string_lossy(),
            std::process::id()
        ));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not create private acquisition staging: {error}"
                )));
            }
        }
    }
    Err(Refusal::new("could not allocate fresh acquisition staging directory"))
}
fn fresh_directory(path: &Path, label: &str) -> Result<PathBuf> { if !path.is_absolute() { return Err(Refusal::new(format!("{label} must be absolute"))); } let parent = canonical_directory(path.parent().ok_or_else(|| Refusal::new(format!("{label} has no parent")))?, label)?; let output = parent.join(path.file_name().ok_or_else(|| Refusal::new(format!("{label} has no name")))?); if fs::symlink_metadata(&output).is_ok() { return Err(Refusal::new(format!("{label} must not already exist"))); } Ok(output) }
fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> { let value = fs::canonicalize(path).map_err(|error| Refusal::new(format!("{label} is unavailable: {error}")))?; if value != path || !value.is_dir() { return Err(Refusal::new(format!("{label} must be a canonical directory"))); } Ok(value) }
fn local_file(root: &Path, relative: &str) -> Result<PathBuf> { repository_path(relative)?; let path = root.join(relative); let canonical = fs::canonicalize(&path).map_err(|_| Refusal::new("repository material is missing"))?; if canonical != path || !canonical.is_file() { return Err(Refusal::new("repository material is not a canonical regular file")); } Ok(canonical) }
fn repository_path(value: &str) -> Result<()> { if !value.is_ascii() || value.is_empty() || value.contains('\\') || value.contains(':') || value.starts_with('/') || value.split('/').any(|part| part.is_empty() || part == "." || part == ".." || part.ends_with('.') || part.ends_with(' ')) { return Err(Refusal::new("repository material path must be a safe relative Git path")); } Ok(()) }
fn checked_component(value: &str, label: &str) -> Result<String> { if value.is_empty() || !value.is_ascii() || value == "." || value == ".." || value.ends_with('.') || value.ends_with(' ') || value.bytes().any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))) { return Err(Refusal::new(format!("{label} is not a safe portable filename component"))); } Ok(value.to_owned()) }
fn validate_identity(bytes: u64, sha256: &str, _role: &str) -> Result<()> { if bytes == 0 || bytes > MAX_FILE_BYTES || !is_sha256_digest(sha256) { return Err(Refusal::new("material size or SHA-256 is invalid")); } Ok(()) }
fn validate_version(value: &str) -> Result<()> {
    let mut parts = value.split('.');
    let parsed = [parts.next(), parts.next(), parts.next()];
    if parts.next().is_some()
        || parsed.iter().any(|part| {
            part.is_none_or(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
                    || (part.len() > 1 && part.starts_with('0'))
                    || part.parse::<u64>().is_err()
            })
        })
    {
        return Err(Refusal::new(
            "version must be a canonical stable x.y.z string at least 0.1.0",
        ));
    }
    let version = [
        parsed[0]
            .expect("validated component")
            .parse::<u64>()
            .expect("validated component"),
        parsed[1]
            .expect("validated component")
            .parse::<u64>()
            .expect("validated component"),
        parsed[2]
            .expect("validated component")
            .parse::<u64>()
            .expect("validated component"),
    ];
    if version < [0, 1, 0] {
        return Err(Refusal::new("version must be at least 0.1.0"));
    }
    Ok(())
}
fn git_id(value: &str) -> bool { (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')) }
fn text(raw: &[u8]) -> Result<String> { let text = std::str::from_utf8(raw).map_err(|_| Refusal::new("Git output is not UTF-8"))?.trim(); Ok(text.to_owned()) }
fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> { let metadata = fs::symlink_metadata(path)?; if !metadata.file_type().is_file() || metadata.len() > limit as u64 { return Err(Refusal::new("regular input exceeds its bound")); } let mut raw = Vec::with_capacity(metadata.len() as usize); File::open(path)?.read_to_end(&mut raw)?; if raw.len() > limit { return Err(Refusal::new("regular input exceeds its bound")); } Ok(raw) }
fn write_new(path: &Path, raw: &[u8]) -> Result<()> { let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?; file.write_all(raw)?; file.sync_all()?; Ok(()) }
fn canonical_json(value: &Value) -> Result<Vec<u8>> { let mut raw = serde_json::to_vec(value).map_err(|error| Refusal::new(error.to_string()))?; raw.push(b'\n'); Ok(raw) }
fn git_environment() -> BTreeMap<OsString, OsString> { let mut environment = BTreeMap::new(); if let Some(path) = env::var_os("PATH") { environment.insert(OsString::from("PATH"), path); } for (key, value) in [("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_CONFIG_GLOBAL", "/dev/null"), ("GIT_NO_REPLACE_OBJECTS", "1"), ("GIT_TERMINAL_PROMPT", "0"), ("GIT_OPTIONAL_LOCKS", "0"), ("LC_ALL", "C")] { environment.insert(OsString::from(key), OsString::from(value)); } environment }
fn resolve_executable(name: &str) -> Result<PathBuf> { for directory in env::split_paths(&env::var_os("PATH").unwrap_or_default()) { let candidate = directory.join(name); if let Ok(metadata) = fs::metadata(&candidate) && metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 { if let Ok(path) = fs::canonicalize(candidate) { return Ok(path); } } } Err(Refusal::new(format!("could not resolve {name} from PATH"))) }
fn overlaps(left: &Path, right: &Path) -> bool { left == right || left.starts_with(right) || right.starts_with(left) }
fn retain_failure(stage: &Path, error: &Refusal) -> Result<()> { write_new(&stage.join("acquisition-failure.json"), &canonical_json(&json!({"schema":RESULT_SCHEMA,"status":"CAPSULE_INPUT_ACQUISITION_FAILED","failure":error.to_string(),"success_claimed":false}))?) }
fn remaining(started: Instant) -> Result<Duration> { DEADLINE.checked_sub(started.elapsed()).ok_or_else(|| Refusal::new("capsule input acquisition exceeded its 1200-second deadline")) }
fn check_deadline(started: Instant) -> Result<()> { if started.elapsed() >= DEADLINE { Err(Refusal::new("capsule input acquisition exceeded its 1200-second deadline")) } else { Ok(()) } }
fn usage() -> Refusal { Refusal::new("usage: ami-rust-xtask toolchain-capsule-acquire --source-root DIR --version X.Y.Z --output DIR --curl FILE") }

#[cfg(test)]
mod tests {
    use super::validate_version;

    #[test]
    fn initial_release_is_a_valid_acquisition_version() {
        assert!(validate_version("0.1.0").is_ok());
        assert!(validate_version("0.0.0").is_err());
    }
}
