//! Rebuild and audit the pinned relocatable libaom pkg-config metadata.
//!
//! The caller authenticates the source archive, tool identities, and original
//! pkg-config file, and owns process execution, resource accounting, and
//! cancellation. This module performs typed argv calls and retains partial
//! private output and any materialized version inputs after a failure.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("AOM metadata generation is supported on macOS and Linux only");

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use flate2::read::MultiGzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::{
    Refusal, Result,
    csdk_source::CsdkSourceFilePin,
    digest::{encode_hex, sha256_bytes},
    directory::Directory,
    files::{open_regular_nofollow, validate_relative_inventory_path},
    process_capture::CommandSpec,
};

const ARCHIVE_BYTES: u64 = 5_497_367;
const ARCHIVE_SHA256: &str = "9e9775180dec7dfd61a79e00bda3809d43891aee6b2e331ff7f26986207ea22e";
const PATCHED_SCRIPT_SHA256: &str =
    "8833578cfd9807ade9540afd2680bd32002e655eefc8e5446245a0e784ce2708";
const ORIGINAL_SCRIPT_SHA256: &str =
    "64cf5b1270215adcca2304a89244adfcd3bda77400b1adc3fc69a8308a59725e";
const GENERATED_PC_SHA256: &str =
    "44e60ded4d7fa63dceeca042abfca86b841632586aaba5437c45fa96a99f5de7";
const ARCHIVE_LIMIT: u64 = 64 * 1024 * 1024;
const DECODED_TAR_LIMIT: u64 = 512 * 1024 * 1024;
const MEMBER_LIMIT: u64 = 1024 * 1024;
const MAX_ARCHIVE_MEMBERS: usize = 100_000;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_TOKENIZER_INPUT: usize = 1024 * 1024;
const MAX_TOKENIZER_TOKENS: usize = 65_536;
const LIBAOM_PREFIX: &[u8] = b"libaom-3.12.1/";
const ARCHIVE_MEMBERS: [&str; 5] = [
    "build/cmake/util.cmake",
    "build/cmake/version.cmake",
    "build/cmake/version.pl",
    "CHANGELOG",
    "build/cmake/pkg_config.cmake",
];
const PKG_ENV_KEYS: [&str; 3] = [
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_SYSROOT_DIR",
];

type CheckFn<'a> = Rc<RefCell<dyn FnMut(&str) -> Result<()> + 'a>>;
type CallbackFailure = Rc<RefCell<Option<Refusal>>>;
type ArchiveMembers = HashMap<String, Vec<u8>>;

/// One caller-resolved, caller-pinned executable used by the metadata probe.
#[derive(Clone, Debug)]
pub struct CsdkMetadataTool {
    pub path: PathBuf,
    pub pin: CsdkSourceFilePin,
}

/// The four tools required by libaom's metadata generators and controls.
#[derive(Clone, Debug)]
pub struct CsdkMetadataTools {
    pub cmake: CsdkMetadataTool,
    pub pkg_config: CsdkMetadataTool,
    pub perl: CsdkMetadataTool,
    pub git: CsdkMetadataTool,
}

/// Authenticated source, archive, tool, and environment inputs for one probe.
pub struct CsdkMetadataRequest {
    pub source: PathBuf,
    pub original_archive: PathBuf,
    pub destination: PathBuf,
    pub archive_pin: CsdkSourceFilePin,
    pub original_pc: Vec<u8>,
    pub tools: CsdkMetadataTools,
    pub base_env: BTreeMap<OsString, OsString>,
    pub label_prefix: String,
}

/// Captured stdout and the supervisor-owned record for one direct child.
pub struct CsdkMetadataRunOutput {
    pub stdout: Vec<u8>,
    pub process_record: Value,
}

/// Generate and validate relocatable AOM metadata in two fresh roots, then
/// exercise the historical unpatched-generator and original-PC controls.
///
/// The callback is the only command execution path. Every command receives a
/// complete cloned environment; only the four pkg-config calls override the
/// three `PKG_CONFIG_*` keys. This function does not own a process supervisor
/// or global resource summary.
pub fn generate_aom_metadata(
    request: CsdkMetadataRequest,
    mut run: impl FnMut(&CommandSpec, &str, Duration) -> Result<CsdkMetadataRunOutput>,
    cancellation_check: impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    let checker: CheckFn<'_> = Rc::new(RefCell::new(cancellation_check));
    let callback_failure: CallbackFailure = Rc::new(RefCell::new(None));
    validate_label(&request.label_prefix)?;

    let source = canonical_directory(&request.source, "libaom source")?;
    let source_directory = Directory::open(&source)?;
    let archive_path =
        canonical_regular_path(&request.original_archive, "original libaom archive")?;
    let (destination_parent_path, destination_name) =
        destination_parent_and_name(&request.destination)?;
    let resolved_parent = resolve_non_strict(destination_parent_path)?;
    let requested_destination_path = resolved_parent.join(destination_name);
    validate_cmake_path(&source, "libaom source root")?;
    validate_cmake_path(&requested_destination_path, "AOM metadata destination")?;
    if paths_overlap(&source, &requested_destination_path) {
        return Err(Refusal::new(
            "AOM metadata source and destination must be disjoint",
        ));
    }
    require_fresh_destination(&requested_destination_path)?;
    let destination_parent = open_or_create_directory(destination_parent_path)?;
    let destination_parent_path = fs::canonicalize(destination_parent_path).map_err(|error| {
        Refusal::new(format!(
            "could not resolve AOM metadata destination parent: {error}"
        ))
    })?;
    let destination_path = destination_parent_path.join(destination_name);
    validate_cmake_path(&destination_path, "AOM metadata destination")?;
    require_fresh_destination(&destination_path)?;
    validate_archive_pin(request.archive_pin)?;
    let (expected_pc, original_prefix) = rewrite_prefix(&request.original_pc)?;
    if sha256_bytes(&expected_pc) != GENERATED_PC_SHA256 {
        return Err(Refusal::new(
            "prefix-only aom.pc result differs from its expected identity",
        ));
    }
    if expected_pc
        .windows(b"Libs.private: -lm\n".len())
        .any(|window| window == b"Libs.private: -lm\n")
    {
        return Err(Refusal::new(
            "relocatable AROS aom.pc unexpectedly links a standalone libm",
        ));
    }

    let tools = canonical_tools(&request.tools)?;
    let mut tool_pins_before = BTreeMap::new();
    for (name, tool) in &tools {
        checkpoint(&checker, "prechecking AOM metadata tool")?;
        verify_tool(tool, &checker, name)?;
        tool_pins_before.insert(name.to_string(), tool.pin);
    }

    checkpoint(&checker, "prehashing original libaom archive")?;
    let mut archive = open_regular_nofollow(&archive_path)?;
    validate_file_length(
        &archive,
        request.archive_pin.bytes,
        "original libaom archive",
    )?;
    hash_pinned_file(
        &mut archive,
        request.archive_pin,
        &checker,
        "prehashing original libaom archive",
    )?;
    archive.seek(SeekFrom::Start(0))?;

    let mut root_created = false;
    let root = match destination_parent.mkdir_new_tracked(destination_name, 0o700, || {
        root_created = true;
    }) {
        Ok(root) => root,
        Err(error) if root_created => return Err(recovery_refusal(error, &destination_path)),
        Err(error) => return Err(error),
    };

    let result = generate_after_root(
        &request,
        &source,
        archive,
        &destination_path,
        &root,
        &source_directory,
        &tools,
        &expected_pc,
        &original_prefix,
        &checker,
        &callback_failure,
        &mut run,
    );
    let archive_after = verify_archive_path(&archive_path, request.archive_pin, &checker);
    let mut tool_pins_after = BTreeMap::new();
    let mut tool_after_result = None;
    for (name, tool) in &tools {
        match verify_tool(tool, &checker, name) {
            Ok(()) => {
                tool_pins_after.insert(name.to_string(), tool.pin);
            }
            Err(error) if tool_after_result.is_none() => tool_after_result = Some(error),
            Err(_) => {}
        }
    }

    let mut result = match result {
        Ok(value) => value,
        Err(error) => return Err(recovery_refusal(error, &destination_path)),
    };
    archive_after.map_err(|error| recovery_refusal(error, &destination_path))?;
    if let Some(error) = tool_after_result {
        return Err(recovery_refusal(error, &destination_path));
    }
    if tool_pins_before != tool_pins_after {
        return Err(recovery_refusal(
            Refusal::new("metadata tool identity changed during generation"),
            &destination_path,
        ));
    }

    let tool_records = tools
        .iter()
        .map(|(name, tool)| {
            let pin = tool.pin;
            Ok((
                name.to_string(),
                json!({
                    "path": path_text(&tool.path, "metadata tool path")?,
                    "sha256_before": encode_hex(&pin.sha256),
                    "sha256_after": encode_hex(&pin.sha256),
                }),
            ))
        })
        .collect::<Result<serde_json::Map<String, Value>>>()?;
    result["tools"] = Value::Object(tool_records);
    result["aom_pc_sha256"] = Value::String(sha256_bytes(&expected_pc));
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn generate_after_root(
    request: &CsdkMetadataRequest,
    source_path: &Path,
    mut archive_file: File,
    destination_path: &Path,
    root: &Directory,
    source: &Directory,
    tools: &BTreeMap<&'static str, CsdkMetadataTool>,
    expected_pc: &[u8],
    original_prefix: &str,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
    run: &mut impl FnMut(&CommandSpec, &str, Duration) -> Result<CsdkMetadataRunOutput>,
) -> Result<Value> {
    checkpoint(checker, "after creating private AOM metadata root")?;
    ensure_directory_matches(source_path, source, "libaom source")?;
    ensure_directory_matches(destination_path, root, "AOM metadata root")?;
    let (members, original_script) = scan_archive(
        &mut archive_file,
        request.archive_pin,
        checker,
        callback_failure,
    )?;
    let source_inputs = materialize_version_inputs(source, &members, checker)?;
    let patched_script = read_relative_file(
        source,
        "build/cmake/pkg_config.cmake",
        MEMBER_LIMIT as usize,
        checker,
        "checking patched AOM metadata generator",
    )?;
    if sha256_bytes(&patched_script) != PATCHED_SCRIPT_SHA256 {
        return Err(Refusal::new(
            "patched libaom metadata generator differs from its pin",
        ));
    }

    let result = run_generation(
        request,
        source_path,
        destination_path,
        root,
        source,
        tools,
        expected_pc,
        original_prefix,
        &original_script,
        source_inputs,
        checker,
        run,
    )?;
    ensure_directory_matches(source_path, source, "libaom source")?;
    ensure_directory_matches(destination_path, root, "AOM metadata root")?;
    let patched_after = read_relative_file(
        source,
        "build/cmake/pkg_config.cmake",
        MEMBER_LIMIT as usize,
        checker,
        "checking patched AOM metadata generator after execution",
    )?;
    if sha256_bytes(&patched_after) != PATCHED_SCRIPT_SHA256 {
        return Err(Refusal::new(
            "patched libaom metadata generator changed during generation",
        ));
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn run_generation(
    request: &CsdkMetadataRequest,
    source_path: &Path,
    destination_path: &Path,
    destination: &Directory,
    source: &Directory,
    tools: &BTreeMap<&'static str, CsdkMetadataTool>,
    expected_pc: &[u8],
    original_prefix: &str,
    original_script: &[u8],
    source_inputs: Vec<Value>,
    checker: &CheckFn<'_>,
    run: &mut impl FnMut(&CommandSpec, &str, Duration) -> Result<CsdkMetadataRunOutput>,
) -> Result<Value> {
    let mut command_records = Vec::with_capacity(10);
    let mut roots = Vec::with_capacity(2);
    let mut generated = Vec::with_capacity(2);
    let mut relocation = Vec::with_capacity(2);

    for (index, name) in ["metadata-a", "different metadata b"]
        .into_iter()
        .enumerate()
    {
        checkpoint(checker, "before creating AOM metadata root")?;
        let root = destination.mkdir_new(OsStr::new(name), 0o700)?;
        let root_path = destination_path.join(name);
        validate_cmake_path(&root_path, "metadata root")?;
        let config = root.mkdir_new(OsStr::new("config"), 0o700)?;
        let config_path = root_path.join("config");
        let config_config = config.mkdir_new(OsStr::new("config"), 0o700)?;

        let version_args = vec![
            cmake_argument("AOM_ROOT", source_path)?,
            cmake_argument("AOM_CONFIG_DIR", &config_path)?,
            cmake_argument("GIT_EXECUTABLE", &tools["git"].path)?,
            cmake_argument("PERL_EXECUTABLE", &tools["perl"].path)?,
            OsString::from("-P"),
            path_os_string(
                &source_path.join("build/cmake/version.cmake"),
                "version script",
            )?,
        ];
        let version = invoke(
            tools["cmake"].path.as_os_str(),
            version_args,
            &root_path,
            request,
            &format!("{}-version-{index}", request.label_prefix),
            Duration::from_secs(60),
            &root,
            destination_path,
            destination,
            source_path,
            checker,
            run,
            &mut command_records,
            source,
        )?;
        let version_header = config_config.regular(OsStr::new("aom_version.h"))?;
        let _ = version_header;

        let developer = root.mkdir_new(OsStr::new("Developer"), 0o700)?;
        let developer_path = root_path.join("Developer");
        let developer_lib = developer.mkdir_new(OsStr::new("lib"), 0o700)?;
        let pkgdir = developer_lib.mkdir_new(OsStr::new("pkgconfig"), 0o700)?;
        let include = developer.mkdir_new(OsStr::new("include"), 0o700)?;
        let _ = include;
        let wrapper_path = root_path.join("target-metadata.cmake");
        let wrapper = cmake_wrapper(source_path.join("build/cmake/pkg_config.cmake"))?;
        write_new_file(
            &root,
            OsStr::new("target-metadata.cmake"),
            &wrapper,
            checker,
        )?;

        let pkg_args =
            pkg_config_generator_args(source_path, &config_path, &developer_path, &wrapper_path)?;
        let pkg = invoke(
            tools["cmake"].path.as_os_str(),
            pkg_args,
            &root_path,
            request,
            &format!("{}-pkgconfig-{index}", request.label_prefix),
            Duration::from_secs(60),
            &root,
            destination_path,
            destination,
            source_path,
            checker,
            run,
            &mut command_records,
            source,
        )?;
        let pc = read_relative_file(
            &root,
            "config/aom.pc",
            MEMBER_LIMIT as usize,
            checker,
            "reading generated aom.pc",
        )?;
        if pc != expected_pc || sha256_bytes(&pc) != GENERATED_PC_SHA256 {
            return Err(Refusal::new(
                "generated aom.pc changed outside its prefix line",
            ));
        }
        generated.push(pc.clone());
        write_new_file(&pkgdir, OsStr::new("aom.pc"), &pc, checker)?;

        root.rename_no_replace(
            OsStr::new("Developer"),
            &root,
            OsStr::new("relocated Developer"),
        )?;
        let moved_path = root_path.join("relocated Developer");
        let _moved = root.child(OsStr::new("relocated Developer"))?;
        let env_libdir = moved_path.join("lib/pkgconfig");
        let prefix_result = invoke_with_pkg_env(
            tools["pkg-config"].path.as_os_str(),
            vec![OsString::from("--variable=prefix"), OsString::from("aom")],
            &root_path,
            request,
            &env_libdir,
            &format!("{}-relocated-prefix-{index}", request.label_prefix),
            Duration::from_secs(30),
            &root,
            destination_path,
            destination,
            source_path,
            checker,
            run,
            &mut command_records,
            source,
        )?;
        let flags_result = invoke_with_pkg_env(
            tools["pkg-config"].path.as_os_str(),
            vec![
                OsString::from("--cflags"),
                OsString::from("--libs"),
                OsString::from("aom"),
            ],
            &root_path,
            request,
            &env_libdir,
            &format!("{}-relocated-flags-{index}", request.label_prefix),
            Duration::from_secs(30),
            &root,
            destination_path,
            destination,
            source_path,
            checker,
            run,
            &mut command_records,
            source,
        )?;
        let prefix_output = stdout_text(&prefix_result.stdout, "pkg-config prefix")?;
        let flags_output = stdout_text(&flags_result.stdout, "pkg-config flags")?;
        let reported = reported_prefix(prefix_output.trim(), &moved_path)?;
        if resolve_non_strict(Path::new(&reported))? != resolve_non_strict(&moved_path)? {
            return Err(Refusal::new(
                "pkg-config prefix does not resolve to relocated Developer",
            ));
        }
        let flags = flags_output.trim();
        let flag_tokens = posix_tokens(flags)?;
        validate_relocated_flags(&flag_tokens, &moved_path)?;
        relocation.push(json!({
            "prefix_resolves_to_relocated_Developer": true,
            "flags": flags,
        }));
        roots.push(json!({
            "name": name,
            "version_process": version.process_record,
            "pkgconfig_process": pkg.process_record,
        }));
    }

    if generated.len() != 2 || generated[0] != generated[1] {
        return Err(Refusal::new(
            "aom.pc differs between two separate metadata roots",
        ));
    }

    let counter = destination.mkdir_new(OsStr::new("unpatched-target-counter"), 0o700)?;
    let counter_path = destination_path.join("unpatched-target-counter");
    let counter_config = counter.mkdir_new(OsStr::new("config"), 0o700)?;
    let counter_config_path = counter_path.join("config");
    let counter_config_config = counter_config.mkdir_new(OsStr::new("config"), 0o700)?;
    let version_source = destination
        .child(OsStr::new("metadata-a"))?
        .relative_directory("config/config")?
        .regular(OsStr::new("aom_version.h"))?;
    let mut version_target =
        counter_config_config.create_new_file(OsStr::new("aom_version.h"), 0o600)?;
    copy_with_checkpoints(
        version_source,
        &mut version_target,
        checker,
        "copying AOM version header",
    )?;
    let counter_developer = counter_config_path.join("Developer");
    let counter_wrapper = destination_path.join("original-target-metadata.cmake");
    let counter_script =
        destination.create_new_file(OsStr::new("original-pkg_config.cmake"), 0o600)?;
    let mut counter_script = counter_script;
    counter_script.write_all(original_script)?;
    counter_script.flush()?;
    let wrapper_bytes = cmake_wrapper(destination_path.join("original-pkg_config.cmake"))?;
    let mut wrapper_file =
        destination.create_new_file(OsStr::new("original-target-metadata.cmake"), 0o600)?;
    wrapper_file.write_all(&wrapper_bytes)?;
    wrapper_file.flush()?;
    let counter_args = pkg_config_generator_args(
        source_path,
        &counter_config_path,
        &counter_developer,
        &counter_wrapper,
    )?;
    let _counter_result = invoke(
        tools["cmake"].path.as_os_str(),
        counter_args,
        &counter_path,
        request,
        &format!("{}-unpatched-target-counter", request.label_prefix),
        Duration::from_secs(60),
        &counter,
        destination_path,
        destination,
        source_path,
        checker,
        run,
        &mut command_records,
        source,
    )?;
    let counter_pc = read_relative_file(
        &counter,
        "config/aom.pc",
        MEMBER_LIMIT as usize,
        checker,
        "reading unpatched counter-case aom.pc",
    )?;
    if !counter_pc
        .windows(b"Libs.private: -lm\n".len())
        .any(|window| window == b"Libs.private: -lm\n")
        || !counter_pc
            .windows(counter_config_path.as_os_str().as_bytes().len())
            .any(|window| window == counter_config_path.as_os_str().as_bytes())
    {
        return Err(Refusal::new(
            "unpatched target counter-case did not expose -lm and an absolute prefix",
        ));
    }

    let original_control = destination.mkdir_new(OsStr::new("original-pc-counter"), 0o700)?;
    let original_control_path = destination_path.join("original-pc-counter");
    let original_lib = original_control.mkdir_new(OsStr::new("lib"), 0o700)?;
    let original_pkgdir = original_lib.mkdir_new(OsStr::new("pkgconfig"), 0o700)?;
    write_new_file(
        &original_pkgdir,
        OsStr::new("aom.pc"),
        &request.original_pc,
        checker,
    )?;
    let original_prefix_result = invoke_with_pkg_env(
        tools["pkg-config"].path.as_os_str(),
        vec![OsString::from("--variable=prefix"), OsString::from("aom")],
        destination_path,
        request,
        &original_control_path.join("lib/pkgconfig"),
        &format!("{}-original-prefix-counter", request.label_prefix),
        Duration::from_secs(30),
        destination,
        destination_path,
        destination,
        source_path,
        checker,
        run,
        &mut command_records,
        source,
    )?;
    let output = stdout_text(&original_prefix_result.stdout, "original pkg-config prefix")?;
    let observed_original_prefix = reported_prefix(output.trim(), Path::new(original_prefix))?;
    if resolve_non_strict(Path::new(&observed_original_prefix))?
        == resolve_non_strict(&original_control_path)?
    {
        return Err(Refusal::new(
            "original aom.pc counter-case did not expose its embedded absolute prefix",
        ));
    }

    let patched_script_sha256 = sha256_bytes(&read_relative_file(
        source,
        "build/cmake/pkg_config.cmake",
        MEMBER_LIMIT as usize,
        checker,
        "recording patched AOM metadata generator identity",
    )?);
    Ok(json!({
        "schema": "ami-rust-aom-metadata-v1",
        "status": "PASS_AOM_METADATA_ONLY",
        "source_inputs": source_inputs,
        "patched_script_sha256": patched_script_sha256,
        "unpatched_script_sha256": sha256_bytes(original_script),
        "two_roots_byte_identical": true,
        "only_prefix_changed": true,
        "generated_pc_path": destination_path.join("metadata-a/config/aom.pc").to_string_lossy(),
        "aom_pc_sha256": sha256_bytes(&generated[0]),
        "relocation": relocation,
        "counter_cases": {
            "unpatched_target": {
                "status": "EXPECTED_ABSOLUTE_PREFIX_AND_NONEXISTENT_LIBM_DETECTED",
                "absolute_prefix_detected": true,
                "standalone_libm_detected": true,
            },
            "original_pc": {
                "status": "EXPECTED_ORIGINAL_ABSOLUTE_PREFIX_DETECTED",
                "absolute_prefix_detected": true,
                "embedded_prefix": original_prefix,
            },
        },
        "target_metadata_platform": {"CMAKE_SYSTEM_NAME": "AROS", "APPLE": false, "WIN32": false},
        "commands": command_records,
        "roots": roots,
        "baseline_changed": false,
        "full_CSDK_or_R1_accepted": false,
    }))
}

#[allow(clippy::too_many_arguments)]
fn invoke(
    program: &OsStr,
    args: Vec<OsString>,
    cwd: &Path,
    request: &CsdkMetadataRequest,
    label: &str,
    timeout: Duration,
    current_root: &Directory,
    destination_path: &Path,
    destination: &Directory,
    source_path: &Path,
    checker: &CheckFn<'_>,
    run: &mut impl FnMut(&CommandSpec, &str, Duration) -> Result<CsdkMetadataRunOutput>,
    command_records: &mut Vec<Value>,
    source: &Directory,
) -> Result<CsdkMetadataRunOutput> {
    let mut env = request.base_env.clone();
    let spec = CommandSpec::new(program, args, cwd, std::mem::take(&mut env));
    invoke_spec(
        spec,
        label,
        timeout,
        current_root,
        destination_path,
        destination,
        source_path,
        checker,
        run,
        command_records,
        source,
    )
}

#[allow(clippy::too_many_arguments)]
fn invoke_with_pkg_env(
    program: &OsStr,
    args: Vec<OsString>,
    cwd: &Path,
    request: &CsdkMetadataRequest,
    pkgdir: &Path,
    label: &str,
    timeout: Duration,
    current_root: &Directory,
    destination_path: &Path,
    destination: &Directory,
    source_path: &Path,
    checker: &CheckFn<'_>,
    run: &mut impl FnMut(&CommandSpec, &str, Duration) -> Result<CsdkMetadataRunOutput>,
    command_records: &mut Vec<Value>,
    source: &Directory,
) -> Result<CsdkMetadataRunOutput> {
    let mut env = request.base_env.clone();
    env.insert(
        OsString::from(PKG_ENV_KEYS[0]),
        pkgdir.as_os_str().to_os_string(),
    );
    env.insert(OsString::from(PKG_ENV_KEYS[1]), OsString::new());
    env.insert(OsString::from(PKG_ENV_KEYS[2]), OsString::new());
    invoke_spec(
        CommandSpec::new(program, args, cwd, env),
        label,
        timeout,
        current_root,
        destination_path,
        destination,
        source_path,
        checker,
        run,
        command_records,
        source,
    )
}

#[allow(clippy::too_many_arguments)]
fn invoke_spec(
    spec: CommandSpec,
    label: &str,
    timeout: Duration,
    current_root: &Directory,
    destination_path: &Path,
    destination: &Directory,
    source_path: &Path,
    checker: &CheckFn<'_>,
    run: &mut impl FnMut(&CommandSpec, &str, Duration) -> Result<CsdkMetadataRunOutput>,
    command_records: &mut Vec<Value>,
    source: &Directory,
) -> Result<CsdkMetadataRunOutput> {
    checkpoint(checker, "before supervised AOM metadata command")?;
    ensure_directory_matches(destination_path, destination, "AOM metadata root")?;
    ensure_directory_matches(&spec.cwd, current_root, "AOM metadata command root")?;
    ensure_directory_matches(source_path, source, "libaom source")?;
    let result = run(&spec, label, timeout)?;
    ensure_directory_matches(destination_path, destination, "AOM metadata root")?;
    ensure_directory_matches(&spec.cwd, current_root, "AOM metadata command root")?;
    ensure_directory_matches(source_path, source, "libaom source")?;
    command_records.push(result.process_record.clone());
    checkpoint(checker, "after supervised AOM metadata command")?;
    Ok(result)
}

fn scan_archive(
    archive_file: &mut File,
    pin: CsdkSourceFilePin,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
) -> Result<(ArchiveMembers, Vec<u8>)> {
    archive_file.seek(SeekFrom::Start(0))?;
    let input = HashingInput::new(
        archive_file.try_clone()?,
        pin,
        Rc::clone(checker),
        Rc::clone(callback_failure),
        "streaming original libaom archive",
    );
    let decoded = BoundedDecodedReader::new(MultiGzDecoder::new(input), DECODED_TAR_LIMIT);
    let mut archive = Archive::new(decoded);
    let mut entries = archive.entries().map_err(|error| {
        callback_or_io(
            callback_failure,
            "could not begin original libaom TAR",
            error,
        )
    })?;
    let mut found = HashMap::<String, Vec<u8>>::new();
    let mut count = 0_usize;

    loop {
        checkpoint(checker, "before original libaom TAR member")?;
        let Some(next) = entries.next() else {
            break;
        };
        let mut entry = next.map_err(|error| {
            callback_or_io(
                callback_failure,
                "could not read original libaom TAR",
                error,
            )
        })?;
        if count == MAX_ARCHIVE_MEMBERS {
            return Err(Refusal::new(
                "original libaom archive exceeds its member-count bound",
            ));
        }
        count += 1;
        let path_bytes = entry.path_bytes();
        let Some(relative) = path_bytes.as_ref().strip_prefix(LIBAOM_PREFIX) else {
            continue;
        };
        let Some(relative) = ARCHIVE_MEMBERS
            .iter()
            .copied()
            .find(|candidate| relative == candidate.as_bytes())
        else {
            continue;
        };
        if found.contains_key(relative) {
            return Err(Refusal::new(format!(
                "duplicate pinned libaom archive member: {relative}"
            )));
        }
        let size = entry.size();
        if !entry.header().entry_type().is_file() || size > MEMBER_LIMIT {
            return Err(Refusal::new(format!(
                "unexpected type or size for pinned libaom member: {relative}"
            )));
        }
        let capacity = usize::try_from(size)
            .map_err(|_| Refusal::new("pinned libaom member size is not representable"))?;
        let mut contents = Vec::new();
        contents
            .try_reserve_exact(capacity)
            .map_err(|_| Refusal::new("could not allocate pinned libaom member buffer"))?;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            checkpoint(checker, "reading pinned libaom TAR member")?;
            match entry.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if contents
                        .len()
                        .checked_add(read)
                        .is_none_or(|length| length > MEMBER_LIMIT as usize)
                    {
                        return Err(Refusal::new(
                            "pinned libaom TAR member exceeds its byte bound",
                        ));
                    }
                    contents.extend_from_slice(&buffer[..read]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(callback_or_io(
                        callback_failure,
                        "could not read pinned libaom TAR member",
                        error,
                    ));
                }
            }
        }
        if contents.len() as u64 != size {
            return Err(Refusal::new(format!(
                "pinned libaom archive member size differs: {relative}"
            )));
        }
        found.insert(relative.to_owned(), contents);
    }
    let mut decoded = archive.into_inner();
    drain_zero_padding(&mut decoded, checker, callback_failure)?;
    let gzip = decoded.into_inner();
    let mut compressed = gzip.into_inner();
    drain_input(&mut compressed, checker, callback_failure)?;
    let (_file, bytes, sha256) = compressed.finish();
    if bytes != pin.bytes || sha256 != pin.sha256 {
        return Err(Refusal::new(
            "original libaom archive changed while its TAR was scanned",
        ));
    }
    if found.len() != ARCHIVE_MEMBERS.len() {
        let missing = ARCHIVE_MEMBERS
            .iter()
            .filter(|name| !found.contains_key(**name))
            .copied()
            .collect::<Vec<_>>();
        return Err(Refusal::new(format!(
            "pinned libaom archive members are incomplete: {}",
            missing.join(", ")
        )));
    }
    let original_script = found
        .get(ARCHIVE_MEMBERS[4])
        .expect("all pinned archive members were checked")
        .clone();
    if sha256_bytes(&original_script) != ORIGINAL_SCRIPT_SHA256 {
        return Err(Refusal::new(
            "unpatched libaom metadata generator differs from its pin",
        ));
    }
    Ok((found, original_script))
}

fn materialize_version_inputs(
    source: &Directory,
    members: &HashMap<String, Vec<u8>>,
    checker: &CheckFn<'_>,
) -> Result<Vec<Value>> {
    let mut rows = Vec::with_capacity(4);
    for relative in &ARCHIVE_MEMBERS[..4] {
        checkpoint(checker, "materializing libaom version input")?;
        let contents = members
            .get(*relative)
            .ok_or_else(|| Refusal::new("pinned libaom archive member is missing"))?;
        let (parent, basename) = source_parent(source, relative, true)?;
        match parent.regular(basename) {
            Ok(file) => {
                let existing = read_file_bounded(
                    file,
                    MEMBER_LIMIT as usize,
                    checker,
                    "checking retained libaom source input",
                )?;
                if existing != *contents {
                    return Err(Refusal::new(format!(
                        "retained libaom source input differs from original archive: {relative}"
                    )));
                }
            }
            Err(_) => write_new_file(&parent, basename, contents, checker)?,
        }
        rows.push(json!({
            "path": relative,
            "bytes": contents.len(),
            "sha256": sha256_bytes(contents),
        }));
    }
    let patched = read_relative_file(
        source,
        ARCHIVE_MEMBERS[4],
        MEMBER_LIMIT as usize,
        checker,
        "checking patched libaom metadata generator",
    )?;
    if sha256_bytes(&patched) != PATCHED_SCRIPT_SHA256 {
        return Err(Refusal::new(
            "patched libaom metadata generator differs from its pin",
        ));
    }
    Ok(rows)
}

fn rewrite_prefix(original_pc: &[u8]) -> Result<(Vec<u8>, String)> {
    if original_pc.is_empty() || original_pc.len() > MEMBER_LIMIT as usize {
        return Err(Refusal::new(
            "original aom.pc must be nonempty bounded bytes",
        ));
    }
    let lines = split_bytes_lines(original_pc);
    let matches = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| line.starts_with(b"prefix=").then_some(index))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Refusal::new(
            "original aom.pc must contain exactly one prefix line",
        ));
    }
    let index = matches[0];
    let old_line = lines[index];
    let value = trim_crlf(&old_line[b"prefix=".len()..]);
    if value.is_empty() || value.contains(&0) {
        return Err(Refusal::new(
            "original aom.pc prefix is not a filesystem path",
        ));
    }
    let prefix = std::str::from_utf8(value)
        .map_err(|_| Refusal::new("original aom.pc prefix is not a UTF-8 path"))?;
    let path = Path::new(prefix);
    if !path.is_absolute()
        || prefix
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        return Err(Refusal::new(
            "original aom.pc must expose an absolute prefix",
        ));
    }
    let ending = if old_line.ends_with(b"\r\n") {
        b"\r\n".as_slice()
    } else if old_line.ends_with(b"\n") {
        b"\n".as_slice()
    } else {
        b"".as_slice()
    };
    let mut rewritten = Vec::with_capacity(original_pc.len() + b"${pcfiledir}/../..".len());
    for (line_index, line) in lines.iter().enumerate() {
        if line_index == index {
            rewritten.extend_from_slice(b"prefix=${pcfiledir}/../..");
            rewritten.extend_from_slice(ending);
        } else {
            rewritten.extend_from_slice(line);
        }
    }
    Ok((rewritten, prefix.to_owned()))
}

fn trim_crlf(value: &[u8]) -> &[u8] {
    let mut end = value.len();
    while end > 0 && matches!(value[end - 1], b'\r' | b'\n') {
        end -= 1;
    }
    &value[..end]
}

fn split_bytes_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if matches!(
            bytes[index],
            b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1e | 0x85
        ) {
            let mut end = index + 1;
            if bytes[index] == b'\r' && end < bytes.len() && bytes[end] == b'\n' {
                end += 1;
            }
            lines.push(&bytes[start..end]);
            start = end;
            index = end;
        } else {
            index += 1;
        }
    }
    if start < bytes.len() {
        lines.push(&bytes[start..]);
    }
    lines
}

fn reported_prefix(output: &str, expected: &Path) -> Result<String> {
    let raw = output.trim();
    if raw.is_empty() {
        return Err(Refusal::new("pkg-config returned an empty prefix"));
    }
    let mut candidates = vec![raw.to_owned()];
    if let Ok(decoded) = posix_tokens(raw)
        && decoded.len() == 1
        && decoded[0] != raw
    {
        candidates.push(decoded[0].clone());
    }
    let expected_path = resolve_non_strict(expected)?;
    for candidate in candidates {
        let path = Path::new(&candidate);
        if path.is_absolute() && resolve_non_strict(path).is_ok_and(|value| value == expected_path)
        {
            return Ok(candidate);
        }
    }
    Err(Refusal::new(
        "pkg-config prefix does not resolve to the expected absolute path",
    ))
}

fn posix_tokens(input: &str) -> Result<Vec<String>> {
    if input.len() > MAX_TOKENIZER_INPUT {
        return Err(Refusal::new(
            "pkg-config output exceeds the tokenizer bound",
        ));
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }
    let chars = input.chars().collect::<Vec<_>>();
    let mut output = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = Quote::None;
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        match quote {
            Quote::Single => {
                if character == '\'' {
                    quote = Quote::None;
                } else {
                    token.push(character);
                }
                index += 1;
            }
            Quote::Double => {
                if character == '"' {
                    quote = Quote::None;
                    index += 1;
                } else if character == '\\' {
                    if let Some(next) = chars.get(index + 1).copied() {
                        if matches!(next, '"' | '\\') {
                            token.push(next);
                            index += 2;
                        } else if next == '\n' {
                            index += 2;
                        } else {
                            token.push('\\');
                            index += 1;
                        }
                    } else {
                        return Err(Refusal::new("pkg-config output ends with an escape"));
                    }
                } else {
                    token.push(character);
                    index += 1;
                }
            }
            Quote::None => {
                if matches!(character, ' ' | '\t' | '\r' | '\n') {
                    if token_started {
                        push_token(&mut output, &mut token)?;
                        token_started = false;
                    }
                    index += 1;
                } else if character == '\'' {
                    quote = Quote::Single;
                    token_started = true;
                    index += 1;
                } else if character == '"' {
                    quote = Quote::Double;
                    token_started = true;
                    index += 1;
                } else if character == '\\' {
                    let Some(next) = chars.get(index + 1).copied() else {
                        return Err(Refusal::new("pkg-config output ends with an escape"));
                    };
                    token_started = true;
                    if next != '\n' {
                        token.push(next);
                    }
                    index += 2;
                } else {
                    token_started = true;
                    token.push(character);
                    index += 1;
                }
            }
        }
        if token.len() > MAX_TOKENIZER_INPUT {
            return Err(Refusal::new("pkg-config token exceeds its byte bound"));
        }
    }
    if quote != Quote::None {
        return Err(Refusal::new("pkg-config output has an unclosed quote"));
    }
    if token_started {
        push_token(&mut output, &mut token)?;
    }
    Ok(output)
}

fn push_token(output: &mut Vec<String>, token: &mut String) -> Result<()> {
    if output.len() == MAX_TOKENIZER_TOKENS {
        return Err(Refusal::new("pkg-config output has too many tokens"));
    }
    output.push(std::mem::take(token));
    Ok(())
}

fn validate_relocated_flags(tokens: &[String], moved: &Path) -> Result<()> {
    if tokens.len() != 3 {
        return Err(Refusal::new(
            "pkg-config flags contain unexpected tokens after relocation",
        ));
    }
    let includes = tokens
        .iter()
        .filter_map(|token| token.strip_prefix("-I"))
        .map(|path| resolve_non_strict(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;
    let libraries = tokens
        .iter()
        .filter_map(|token| token.strip_prefix("-L"))
        .map(|path| resolve_non_strict(Path::new(path)))
        .collect::<Result<Vec<_>>>()?;
    let expected_include = resolve_non_strict(&moved.join("include"))?;
    let expected_library = resolve_non_strict(&moved.join("lib"))?;
    if includes.as_slice() != std::slice::from_ref(&expected_include)
        || libraries.as_slice() != std::slice::from_ref(&expected_library)
        || tokens
            .iter()
            .filter(|token| token.as_str() == "-laom")
            .count()
            != 1
    {
        return Err(Refusal::new(
            "pkg-config failed after relocating the Developer tree",
        ));
    }
    Ok(())
}

fn resolve_non_strict(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(
            "pkg-config returned a relative filesystem path",
        ));
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) => {
                return Err(Refusal::new("path prefix is not supported on this host"));
            }
        }
    }
    let mut ancestor = normalized.clone();
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(&ancestor) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| Refusal::new("could not resolve absolute filesystem path"))?
                    .to_os_string();
                missing.push(name);
                if !ancestor.pop() {
                    return Err(Refusal::new("could not resolve absolute filesystem path"));
                }
            }
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not resolve filesystem path: {error}"
                )));
            }
        }
    }
}

fn pkg_config_generator_args(
    source: &Path,
    config: &Path,
    install_prefix: &Path,
    wrapper: &Path,
) -> Result<Vec<OsString>> {
    Ok(vec![
        cmake_argument("AOM_ROOT", source)?,
        cmake_argument("AOM_CONFIG_DIR", config)?,
        cmake_argument("CMAKE_INSTALL_PREFIX", install_prefix)?,
        OsString::from("-DCMAKE_INSTALL_BINDIR=bin"),
        OsString::from("-DCMAKE_INSTALL_INCLUDEDIR=include"),
        OsString::from("-DCMAKE_INSTALL_LIBDIR=lib"),
        OsString::from("-DCMAKE_PROJECT_NAME=AOM"),
        OsString::from("-DCMAKE_SYSTEM_NAME=AROS"),
        OsString::from("-DAPPLE=FALSE"),
        OsString::from("-DWIN32=FALSE"),
        OsString::from("-DCONFIG_MULTITHREAD=0"),
        OsString::from("-DCONFIG_TUNE_VMAF=0"),
        OsString::from("-DCONFIG_TUNE_BUTTERAUGLI=0"),
        OsString::from("-DCONFIG_SALIENCY_MAP=0"),
        OsString::from("-DCONFIG_TFLITE=0"),
        OsString::from("-P"),
        path_os_string(wrapper, "CMake wrapper")?,
    ])
}

fn cmake_wrapper(include: PathBuf) -> Result<Vec<u8>> {
    let text = format!(
        "set(CMAKE_SYSTEM_NAME \"AROS\")\nset(APPLE FALSE)\nset(WIN32 FALSE)\ninclude({})\n",
        quote_cmake_path(&include, "CMake include path")?
    );
    Ok(text.into_bytes())
}

fn cmake_argument(name: &str, value: &Path) -> Result<OsString> {
    Ok(OsString::from(format!(
        "-D{name}={}",
        safe_cmake_path(value, name)?
    )))
}

fn quote_cmake_path(value: &Path, label: &str) -> Result<String> {
    Ok(format!("\"{}\"", safe_cmake_path(value, label)?))
}

fn safe_cmake_path(value: &Path, label: &str) -> Result<String> {
    let text = path_text(value, label)?;
    if text.is_empty()
        || text
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\' | '$' | ';'))
    {
        return Err(Refusal::new(format!(
            "{label} contains unsafe CMake syntax or control characters"
        )));
    }
    Ok(text)
}

fn validate_cmake_path(value: &Path, label: &str) -> Result<()> {
    safe_cmake_path(value, label).map(|_| ())
}

fn path_text(value: &Path, label: &str) -> Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new(format!("{label} is not a UTF-8 path")))
}

fn path_os_string(value: &Path, label: &str) -> Result<OsString> {
    path_text(value, label)?;
    Ok(value.as_os_str().to_os_string())
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    validate_absolute_path(path, label)?;
    let _directory = Directory::open(path)?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))?;
    if !canonical.is_dir() {
        return Err(Refusal::new(format!("{label} is not a directory")));
    }
    Ok(canonical)
}

fn open_or_create_directory(path: &Path) -> Result<Directory> {
    validate_absolute_path(path, "AOM metadata destination parent")?;
    let mut current = Directory::open(Path::new("/"))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = match current.child(name) {
                    Ok(directory) => directory,
                    Err(_) => current.mkdir_new(name, 0o755)?,
                };
            }
            _ => {
                return Err(Refusal::new(
                    "AOM metadata destination parent path is not normalized",
                ));
            }
        }
    }
    Ok(current)
}

fn canonical_regular_path(path: &Path, label: &str) -> Result<PathBuf> {
    validate_absolute_path(path, label)?;
    let file = open_regular_nofollow(path)?;
    if file.metadata()?.len() > ARCHIVE_LIMIT {
        return Err(Refusal::new(format!("{label} exceeds its byte bound")));
    }
    fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))
}

fn canonical_tools(tools: &CsdkMetadataTools) -> Result<BTreeMap<&'static str, CsdkMetadataTool>> {
    let raw = [
        ("cmake", &tools.cmake),
        ("pkg-config", &tools.pkg_config),
        ("perl", &tools.perl),
        ("git", &tools.git),
    ];
    let mut result = BTreeMap::new();
    for (name, tool) in raw {
        validate_absolute_path(&tool.path, "metadata tool")?;
        let file = open_regular_nofollow(&tool.path)?;
        if file.metadata()?.mode() & 0o111 == 0 {
            return Err(Refusal::new(format!(
                "metadata tool is not executable: {name}"
            )));
        }
        let path = fs::canonicalize(&tool.path).map_err(|error| {
            Refusal::new(format!("could not resolve metadata tool {name}: {error}"))
        })?;
        if path != tool.path {
            return Err(Refusal::new(format!(
                "metadata tool path is not resolved: {name}"
            )));
        }
        validate_cmake_path(&path, "metadata tool path")?;
        result.insert(
            name,
            CsdkMetadataTool {
                path,
                pin: tool.pin,
            },
        );
    }
    Ok(result)
}

fn verify_tool(tool: &CsdkMetadataTool, checker: &CheckFn<'_>, name: &str) -> Result<()> {
    let mut file = open_regular_nofollow(&tool.path)?;
    let metadata = file.metadata()?;
    if metadata.mode() & 0o111 == 0 || metadata.len() != tool.pin.bytes {
        return Err(Refusal::new(format!(
            "metadata tool type, executable mode, or length differs from its pin: {name}"
        )));
    }
    hash_pinned_file(&mut file, tool.pin, checker, "hashing metadata tool")
}

fn validate_archive_pin(pin: CsdkSourceFilePin) -> Result<()> {
    if pin.bytes != ARCHIVE_BYTES || encode_hex(&pin.sha256) != ARCHIVE_SHA256 {
        return Err(Refusal::new(
            "original libaom archive pin differs from the required release identity",
        ));
    }
    if pin.bytes > ARCHIVE_LIMIT {
        return Err(Refusal::new(
            "original libaom archive exceeds its byte bound",
        ));
    }
    Ok(())
}

fn verify_archive_path(path: &Path, pin: CsdkSourceFilePin, checker: &CheckFn<'_>) -> Result<()> {
    let mut file = open_regular_nofollow(path)?;
    validate_file_length(&file, pin.bytes, "original libaom archive")?;
    hash_pinned_file(
        &mut file,
        pin,
        checker,
        "rehashing original libaom archive after generation",
    )
}

fn source_parent(
    root: &Directory,
    relative: &str,
    create_parents: bool,
) -> Result<(Directory, &'static OsStr)> {
    validate_relative_inventory_path(relative)?;
    let basename = match relative {
        "build/cmake/util.cmake" => OsStr::new("util.cmake"),
        "build/cmake/version.cmake" => OsStr::new("version.cmake"),
        "build/cmake/version.pl" => OsStr::new("version.pl"),
        "CHANGELOG" => OsStr::new("CHANGELOG"),
        "build/cmake/pkg_config.cmake" => OsStr::new("pkg_config.cmake"),
        _ => return Err(Refusal::new("unexpected libaom source input path")),
    };
    let mut current = root.relative_directory("")?;
    if let Some(parent) = Path::new(relative).parent() {
        let parent = parent
            .to_str()
            .ok_or_else(|| Refusal::new("libaom source path is not UTF-8"))?;
        if !parent.is_empty() && parent != "." {
            for component in parent.split('/') {
                current = match current.child(OsStr::new(component)) {
                    Ok(directory) => directory,
                    Err(_) if create_parents => current.mkdir_new(OsStr::new(component), 0o755)?,
                    Err(error) => return Err(error),
                };
            }
        }
    }
    Ok((current, basename))
}

fn read_relative_file(
    root: &Directory,
    relative: &str,
    limit: usize,
    checker: &CheckFn<'_>,
    label: &str,
) -> Result<Vec<u8>> {
    validate_relative_inventory_path(relative)?;
    let path = Path::new(relative);
    let basename = path
        .file_name()
        .ok_or_else(|| Refusal::new("relative file path has no basename"))?;
    let parent = match path.parent().and_then(Path::to_str) {
        Some(parent) if !parent.is_empty() && parent != "." => root.relative_directory(parent)?,
        _ => root.relative_directory("")?,
    };
    read_file_bounded(parent.regular(basename)?, limit, checker, label)
}

fn read_file_bounded(
    mut file: File,
    limit: usize,
    checker: &CheckFn<'_>,
    label: &str,
) -> Result<Vec<u8>> {
    let limit_u64 =
        u64::try_from(limit).map_err(|_| Refusal::new("file bound is not representable"))?;
    if file.metadata()?.len() > limit_u64 {
        return Err(Refusal::new(format!("{label} exceeds its byte bound")));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, label)?;
        match file.read(&mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                if bytes
                    .len()
                    .checked_add(read)
                    .is_none_or(|length| length > limit)
                {
                    return Err(Refusal::new(format!("{label} exceeds its byte bound")));
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not read {label}: {error}"))),
        }
    }
}

fn write_new_file(
    directory: &Directory,
    name: &OsStr,
    bytes: &[u8],
    checker: &CheckFn<'_>,
) -> Result<()> {
    let mut file = directory.create_new_file(name, 0o600)?;
    for chunk in bytes.chunks(COPY_BUFFER_BYTES) {
        checkpoint(checker, "writing private AOM metadata input")?;
        file.write_all(chunk)?;
    }
    file.flush()?;
    Ok(())
}

fn copy_with_checkpoints(
    mut source: File,
    destination: &mut File,
    checker: &CheckFn<'_>,
    label: &str,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, label)?;
        match source.read(&mut buffer) {
            Ok(0) => return destination.flush().map_err(Refusal::from),
            Ok(read) => destination.write_all(&buffer[..read])?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not copy {label}: {error}"))),
        }
    }
}

fn stdout_text(bytes: &[u8], label: &str) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Refusal::new(format!("{label} output is not valid UTF-8")))
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} path must be absolute")));
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err(Refusal::new(format!("{label} path is not normalized"))),
        }
    }
    Ok(())
}

fn destination_parent_and_name(destination: &Path) -> Result<(&Path, &OsStr)> {
    validate_absolute_path(destination, "AOM metadata destination")?;
    let name = destination
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| Refusal::new("fresh AOM metadata destination required"))?;
    let parent = destination
        .parent()
        .ok_or_else(|| Refusal::new("AOM metadata destination must have a parent"))?;
    Ok((parent, name))
}

fn require_fresh_destination(destination: &Path) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(Refusal::new("fresh AOM metadata destination required")),
    }
}

fn ensure_directory_matches(path: &Path, expected: &Directory, label: &str) -> Result<()> {
    let observed = Directory::open(path)?;
    let expected_metadata = expected.metadata()?;
    let observed_metadata = observed.metadata()?;
    if expected_metadata.dev() != observed_metadata.dev()
        || expected_metadata.ino() != observed_metadata.ino()
    {
        return Err(Refusal::new(format!(
            "{label} changed during metadata generation"
        )));
    }
    Ok(())
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

fn validate_label(label: &str) -> Result<()> {
    if label.is_empty()
        || label.len() > 128
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Refusal::new("AOM metadata label prefix is invalid"));
    }
    Ok(())
}

fn validate_file_length(file: &File, expected: u64, label: &str) -> Result<()> {
    let actual = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?
        .len();
    if actual > ARCHIVE_LIMIT {
        return Err(Refusal::new(format!("{label} exceeds its byte bound")));
    }
    if actual != expected {
        return Err(Refusal::new(format!("{label} length differs from its pin")));
    }
    Ok(())
}

fn hash_pinned_file(
    file: &mut File,
    pin: CsdkSourceFilePin,
    checker: &CheckFn<'_>,
    label: &str,
) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, label)?;
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                bytes = bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| Refusal::new("pinned input byte count overflow"))?;
                hasher.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not hash {label}: {error}"))),
        }
    }
    let sha256: [u8; 32] = hasher.finalize().into();
    if bytes != pin.bytes || sha256 != pin.sha256 {
        return Err(Refusal::new(format!("{label} differs from its pin")));
    }
    Ok(())
}

struct HashingInput<'a> {
    inner: File,
    expected: CsdkSourceFilePin,
    bytes: u64,
    hasher: Sha256,
    checker: CheckFn<'a>,
    callback_failure: CallbackFailure,
    label: &'static str,
}

impl<'a> HashingInput<'a> {
    fn new(
        inner: File,
        expected: CsdkSourceFilePin,
        checker: CheckFn<'a>,
        callback_failure: CallbackFailure,
        label: &'static str,
    ) -> Self {
        Self {
            inner,
            expected,
            bytes: 0,
            hasher: Sha256::new(),
            checker,
            callback_failure,
            label,
        }
    }

    fn finish(self) -> (File, u64, [u8; 32]) {
        (self.inner, self.bytes, self.hasher.finalize().into())
    }
}

impl Read for HashingInput<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.callback_failure.borrow().is_some() {
            return Err(io::Error::other("checkpoint callback previously refused"));
        }
        if let Err(error) = checkpoint(&self.checker, self.label) {
            *self.callback_failure.borrow_mut() = Some(error);
            return Err(io::Error::other("checkpoint callback refused"));
        }
        if self.bytes == self.expected.bytes {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pinned archive exceeds its byte length",
                )),
            };
        }
        let remaining = self.expected.bytes - self.bytes;
        let limit = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..limit])?;
        self.bytes = self.bytes.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "archive byte count overflow")
        })?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

struct BoundedDecodedReader<R> {
    inner: R,
    maximum: u64,
    bytes: u64,
}

impl<R> BoundedDecodedReader<R> {
    fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            maximum,
            bytes: 0,
        }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BoundedDecodedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes == self.maximum {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decoded TAR exceeds its byte bound",
                )),
            };
        }
        let remaining = self.maximum - self.bytes;
        let limit = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..limit])?;
        self.bytes = self.bytes.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded TAR byte count overflow",
            )
        })?;
        Ok(read)
    }
}

fn drain_zero_padding<R: Read>(
    reader: &mut R,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, "draining complete decoded AOM TAR stream")?;
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) if buffer[..read].iter().all(|byte| *byte == 0) => {}
            Ok(_) => return Err(Refusal::new("nonzero data follows the AOM TAR end marker")),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(callback_or_io(
                    callback_failure,
                    "could not drain decoded AOM TAR",
                    error,
                ));
            }
        }
    }
}

fn drain_input<R: Read>(
    reader: &mut R,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, "finishing original libaom archive stream")?;
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(callback_or_io(
                    callback_failure,
                    "could not finish AOM archive",
                    error,
                ));
            }
        }
    }
}

fn callback_or_io(callback_failure: &CallbackFailure, context: &str, error: io::Error) -> Refusal {
    callback_failure
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Refusal::new(format!("{context}: {error}")))
}

fn checkpoint(checker: &CheckFn<'_>, label: &str) -> Result<()> {
    (checker.borrow_mut())(label)
}

fn recovery_refusal(error: Refusal, destination: &Path) -> Refusal {
    Refusal::new(format!(
        "{error}; partial AOM metadata output retained at {}; materialized version inputs remain in the source tree",
        destination.display()
    ))
}

#[cfg(test)]
mod tests;
