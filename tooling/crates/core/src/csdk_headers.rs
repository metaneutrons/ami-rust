//! Rebuild and audit the pinned public C-SDK headers with a native host compiler.
//!
//! The caller authenticates recipes and source inputs, supervises every
//! process, and owns aggregate limits and cancellation. This module performs
//! only typed argv calls and writes beneath a fresh private destination.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("public C-SDK header generation is supported on macOS and Linux only");

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Refusal, Result,
    csdk_source::CsdkSourceFilePin,
    digest::{encode_hex, sha256_bytes},
    directory::Directory,
    files::{open_regular_nofollow, validate_relative_inventory_path},
};

const HEADER_RECIPE_COUNT: usize = 106;
const GENERATOR_SOURCE_COUNT: usize = 27;
const PUBLIC_HEADER_COUNT: usize = 530;
const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024 * 1024;
const MAX_VERSION_BYTES: usize = 64 * 1024;
const MESA_PATCH_PATH: &str = "workbench/libs/mesa/mesa-20.0.8-aros.diff";
const MESA_CONFIG_PATH: &str = "build/pc-x86_64/Ports/mesa/mesa-20.0.8/mesa3dgl.conf";
const MESA_DIFF_HEADER: &[u8] =
    b"diff -ruN mesa-20.0.8/mesa3dgl.conf mesa-20.0.8.aros/mesa3dgl.conf\n";
const SOURCE_GENERATOR_PREFIX: &str = "tools/genmodule/";
const ORIGINAL_GENERATOR: &str = "AROS-NX/build/pc-x86_64/hosttools/genmodule";
const ORIGINAL_SOURCE_PREFIX: &str = "AROS-NX/";
const ORIGINAL_BUILD_PREFIX: &str = "AROS-NX/build/pc-x86_64/";

/// The caller supplies authenticated recipes, source identities, and a host C
/// compiler identity. The compiler is the native host compiler from ci_sdk's
/// tools["cc"], not the target LLVM toolchain.
pub struct CsdkHeadersRequest {
    pub source: PathBuf,
    pub frozen_include: PathBuf,
    pub header_recipes: Vec<Value>,
    pub generator_recipe: Value,
    pub destination: PathBuf,
    pub compiler: PathBuf,
    pub compiler_pin: CsdkSourceFilePin,
    pub mesa_patch_sha256: [u8; 32],
    pub forbidden_path_prefixes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct HeaderRecipe {
    config: String,
    outputs: Vec<String>,
    generator_args: Vec<String>,
    has_mesa_override: bool,
}

struct PreparedInputs {
    recipes: Vec<HeaderRecipe>,
    generator_sources: Vec<String>,
    configs: BTreeMap<String, Vec<u8>>,
    mesa_fragment: Vec<u8>,
}

/// Rebuild all 530 public headers in two separate source roots, then require a
/// positive absolute-config control case. Process execution is delegated to
/// the caller and never enters a shell.
pub fn generate_public_headers(
    request: CsdkHeadersRequest,
    mut run: impl FnMut(&[OsString], &Path, &str, Duration) -> Result<Value>,
    mut checkpoint: impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    let prepared = preflight(&request, &mut checkpoint)?;
    let (parent_path, destination_name) = destination_parent_and_name(&request.destination)?;
    let parent = Directory::open(parent_path)?;
    let root = parent.mkdir_new(destination_name, 0o700)?;
    let result = generate_after_root(
        &request,
        &prepared,
        &parent,
        parent_path,
        &root,
        &mut run,
        &mut checkpoint,
    );
    result.map_err(|error| {
        Refusal::new(format!(
            "{error}; partial public-header root retained at {}",
            request.destination.display()
        ))
    })
}

fn preflight(
    request: &CsdkHeadersRequest,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<PreparedInputs> {
    validate_absolute_path(&request.source, "C-SDK source")?;
    validate_absolute_path(&request.frozen_include, "frozen SDK include")?;
    validate_absolute_path(&request.destination, "public-header destination")?;
    validate_absolute_path(&request.compiler, "native host C compiler")?;
    let (destination_parent, _) = destination_parent_and_name(&request.destination)?;
    let _destination_parent = Directory::open(destination_parent)?;
    require_fresh_destination(&request.destination)?;
    if request.forbidden_path_prefixes.iter().any(Vec::is_empty) {
        return Err(Refusal::new("forbidden path prefixes must be nonempty"));
    }

    checkpoint("before opening public-header inputs")?;
    let source = Directory::open(&request.source)?;
    let frozen = Directory::open(&request.frozen_include)?;

    let generator_sources = validate_generator_recipe(&request.generator_recipe)?;
    let (recipes, outputs) = validate_header_recipes(&request.header_recipes)?;
    validate_complete_coverage(recipes.len(), generator_sources.len(), outputs.len())?;

    // Prove every declared compiler input and frozen comparison file is an
    // ordinary regular file before any private output is created.
    for source_path in &generator_sources {
        let _file = open_relative_file(&source, source_path)?;
    }
    let mut configs = BTreeMap::new();
    for recipe in &recipes {
        if !configs.contains_key(&recipe.config) {
            checkpoint("prechecking a frozen public-header config")?;
            let bytes = read_relative_file(&source, &recipe.config, MAX_CONFIG_BYTES)?;
            configs.insert(recipe.config.clone(), bytes);
        }
        for output in &recipe.outputs {
            let _file = open_relative_file(&frozen, output)?;
        }
    }

    checkpoint("prechecking the Mesa public-header override")?;
    let patch_bytes = read_relative_file(&source, MESA_PATCH_PATH, MAX_PATCH_BYTES)?;
    let mesa_fragment = mesa_added_config_patch(&patch_bytes, &request.mesa_patch_sha256)?;
    verify_compiler_pin(&request.compiler, request.compiler_pin)?;
    ensure_directory_matches(&request.source, &source, "C-SDK source")?;
    ensure_directory_matches(&request.frozen_include, &frozen, "frozen SDK include")?;
    checkpoint("after prechecking public-header inputs")?;

    Ok(PreparedInputs {
        recipes,
        generator_sources,
        configs,
        mesa_fragment,
    })
}

fn generate_after_root(
    request: &CsdkHeadersRequest,
    prepared: &PreparedInputs,
    parent: &Directory,
    parent_path: &Path,
    root: &Directory,
    run: &mut impl FnMut(&[OsString], &Path, &str, Duration) -> Result<Value>,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<Value> {
    checkpoint("after creating the private public-header root")?;
    ensure_directory_matches(&request.destination, root, "public-header root")?;
    ensure_directory_matches(parent_path, parent, "public-header destination parent")?;
    let source = Directory::open(&request.source)?;
    let frozen = Directory::open(&request.frozen_include)?;
    let compiler_sha256 = verify_compiler_pin(&request.compiler, request.compiler_pin)?;

    let version_argv = vec![
        request.compiler.as_os_str().to_os_string(),
        OsString::from("--version"),
    ];
    checkpoint("before native compiler version query")?;
    let version_process = run(
        &version_argv,
        &request.destination,
        "header-native-compiler-version",
        Duration::from_secs(30),
    )?;
    ensure_directory_matches(&request.destination, root, "public-header root")?;
    ensure_directory_matches(&request.source, &source, "C-SDK source")?;
    let compiler_version = version_stdout(&version_process)?;
    if verify_compiler_pin(&request.compiler, request.compiler_pin)? != compiler_sha256 {
        return Err(Refusal::new(
            "native host C compiler changed during its version query",
        ));
    }

    let generator_path = request.destination.join("genmodule");
    let mut compile_argv = Vec::with_capacity(prepared.generator_sources.len() + 7);
    compile_argv.push(request.compiler.as_os_str().to_os_string());
    compile_argv.push(OsString::from("-O2"));
    compile_argv.push(OsString::from("-w"));
    let mut include_flag = OsString::from("-I");
    include_flag.push(request.source.join("tools/genmodule").as_os_str());
    compile_argv.push(include_flag);
    for source_path in &prepared.generator_sources {
        compile_argv.push(request.source.join(source_path).into_os_string());
    }
    compile_argv.push(OsString::from("-o"));
    compile_argv.push(generator_path.as_os_str().to_os_string());
    checkpoint("before building classic genmodule")?;
    if verify_compiler_pin(&request.compiler, request.compiler_pin)? != compiler_sha256 {
        return Err(Refusal::new(
            "native host C compiler changed before genmodule production",
        ));
    }
    let _compile_process = run(
        &compile_argv,
        &request.destination,
        "build-classic-genmodule",
        Duration::from_secs(1200),
    )?;
    ensure_directory_matches(&request.destination, root, "public-header root")?;
    ensure_directory_matches(&request.source, &source, "C-SDK source")?;
    if verify_compiler_pin(&request.compiler, request.compiler_pin)? != compiler_sha256 {
        return Err(Refusal::new(
            "native host C compiler changed during genmodule production",
        ));
    }
    let generator_file = open_relative_file(root, "genmodule")?;
    if generator_file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect generated genmodule: {error}")))?
        .mode()
        & 0o111
        == 0
    {
        return Err(Refusal::new("generated genmodule is not executable"));
    }
    let generator_sha256 = hash_open_file(generator_file, None)?.1;
    let generator = generator_path.as_os_str().to_os_string();

    let mesa_override = materialize_mesa_override(request, prepared, root, run, checkpoint)?;
    let mesa_override_sha256 = hash_relative_file(root, "mesa-override/mesa3dgl.conf")?;

    let mut root_receipts = Vec::with_capacity(2);
    let mut first_outputs = BTreeMap::<String, String>::new();
    for root_number in 0..2 {
        checkpoint("before preparing a source-root header reproduction")?;
        ensure_directory_matches(&request.destination, root, "public-header root")?;
        let checkout_name = if root_number == 0 {
            "source-a"
        } else {
            "different source b"
        };
        let checkout_path = request.destination.join(checkout_name);
        let checkout = root.mkdir_new(OsStr::new(checkout_name), 0o700)?;
        let mut created_directories = HashSet::new();
        for (config, contents) in &prepared.configs {
            write_relative_new(
                &checkout_path,
                &checkout,
                config,
                contents,
                &mut created_directories,
            )?;
        }

        let mut headers = Map::new();
        for (index, recipe) in prepared.recipes.iter().enumerate() {
            checkpoint("before generating one public-header group")?;
            let headers_root_name = format!("headers-{root_number}");
            let headers_root_path = request.destination.join(&headers_root_name);
            let headers_root = if index == 0 {
                root.mkdir_new(OsStr::new(&headers_root_name), 0o700)?
            } else {
                root.child(OsStr::new(&headers_root_name))?
            };
            let group_name = index.to_string();
            let group_path = headers_root_path.join(&group_name);
            let group = headers_root.mkdir_new(OsStr::new(&group_name), 0o700)?;
            for category in ["clib", "defines", "inline", "proto", "interface"] {
                group.mkdir_new(OsStr::new(category), 0o700)?;
            }

            let mut args = recipe
                .generator_args
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            replace_option_value(&mut args, "-c", OsString::from(recipe.config.as_str()))?;
            // Classic genmodule builds output filenames in a fixed buffer.
            // Both directories are owned siblings beneath the destination;
            // keep its argument independent of the checkout's absolute length.
            let relative_group = format!("../{headers_root_name}/{group_name}");
            replace_option_value(&mut args, "-d", OsString::from(relative_group))?;
            if recipe.has_mesa_override {
                replace_option_value(&mut args, "-o", mesa_override.as_os_str().to_os_string())?;
            }
            let mut argv = Vec::with_capacity(args.len() + 1);
            argv.push(generator.clone());
            argv.extend(args);

            checkpoint("before invoking public-header generator")?;
            let _process = run(
                &argv,
                &checkout_path,
                &format!("headers-{root_number}-{index}"),
                Duration::from_secs(60),
            )?;
            ensure_directory_matches(&request.destination, root, "public-header root")?;
            ensure_directory_matches(&checkout_path, &checkout, "public-header source root")?;
            ensure_directory_matches(&group_path, &group, "public-header output directory")?;

            for output in &recipe.outputs {
                let generated = read_relative_file(&group, output, MAX_HEADER_BYTES)?;
                let original = read_relative_file(&frozen, output, MAX_HEADER_BYTES)?;
                let expected = rewrite_provenance_banner(&original, &recipe.config)?;
                validate_header_bytes(
                    &generated,
                    &expected,
                    &request.forbidden_path_prefixes,
                    output,
                )?;
                let root_relative = format!("{headers_root_name}/{group_name}/{output}");
                if root_number == 0 {
                    first_outputs.insert(output.clone(), root_relative);
                } else {
                    let previous_path = first_outputs.get(output).ok_or_else(|| {
                        Refusal::new("second source-root output has no first-root counterpart")
                    })?;
                    let previous = read_relative_file(root, previous_path, MAX_HEADER_BYTES)?;
                    if previous != generated {
                        return Err(Refusal::new(format!(
                            "public header differs between source roots: {output}"
                        )));
                    }
                }
                headers.insert(output.clone(), header_record(&generated)?);
            }
        }
        if headers.len() != PUBLIC_HEADER_COUNT {
            return Err(Refusal::new(
                "public-header reproduction did not produce the complete output map",
            ));
        }
        root_receipts.push(Value::Object(headers));
    }
    if root_receipts.len() != 2 || root_receipts[0] != root_receipts[1] {
        return Err(Refusal::new(
            "public headers differ between the two source roots",
        ));
    }

    checkpoint("before absolute-config counter-case")?;
    let control_name = "absolute-control";
    let control_path = request.destination.join(control_name);
    let control = root.mkdir_new(OsStr::new(control_name), 0o700)?;
    for category in ["clib", "defines", "inline", "proto", "interface"] {
        control.mkdir_new(OsStr::new(category), 0o700)?;
    }
    let first_recipe = prepared
        .recipes
        .first()
        .ok_or_else(|| Refusal::new("public-header recipe set is empty"))?;
    let mut control_args = first_recipe
        .generator_args
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    replace_option_value(
        &mut control_args,
        "-c",
        request.source.join(&first_recipe.config).into_os_string(),
    )?;
    replace_option_value(&mut control_args, "-d", OsString::from(control_name))?;
    if first_recipe.has_mesa_override {
        replace_option_value(
            &mut control_args,
            "-o",
            mesa_override.as_os_str().to_os_string(),
        )?;
    }
    let mut control_argv = Vec::with_capacity(control_args.len() + 1);
    control_argv.push(generator);
    control_argv.extend(control_args);
    let _control_process = run(
        &control_argv,
        &request.destination,
        "headers-absolute-counter",
        Duration::from_secs(60),
    )?;
    ensure_directory_matches(&request.destination, root, "public-header root")?;
    ensure_directory_matches(&control_path, &control, "absolute-config output directory")?;
    let source_prefix = request.source.as_os_str().as_bytes();
    for output in &first_recipe.outputs {
        let bytes = read_relative_file(&control, output, MAX_HEADER_BYTES)?;
        if !contains_bytes(&bytes, source_prefix) {
            return Err(Refusal::new(
                "absolute config counter-case did not expose the source prefix",
            ));
        }
    }

    // Applying the Mesa fragment must never alter the authenticated source
    // patch. Re-hash it after all generator calls as an explicit invariant.
    let current_patch = read_relative_file(&source, MESA_PATCH_PATH, MAX_PATCH_BYTES)?;
    if digest_array(&current_patch) != request.mesa_patch_sha256 {
        return Err(Refusal::new(
            "Mesa source patch changed during public-header reproduction",
        ));
    }
    ensure_directory_matches(&request.destination, root, "public-header root")?;
    ensure_directory_matches(parent_path, parent, "public-header destination parent")?;

    Ok(json!({
        "status": header_status(),
        "headers": root_receipts[0],
        "two_roots_byte_identical": true,
        "only_provenance_paths_changed": true,
        "absolute_config_counter_case": "EXPECTED_LOCAL_PREFIX_DETECTED",
        "native_compiler": {
            "sha256": encode_hex(&request.compiler_pin.sha256),
            "version": compiler_version,
        },
        "generator_sha256": generator_sha256,
        "generator_sources": prepared.generator_sources,
        "mesa_override_sha256": mesa_override_sha256,
    }))
}

fn materialize_mesa_override(
    request: &CsdkHeadersRequest,
    prepared: &PreparedInputs,
    root: &Directory,
    run: &mut impl FnMut(&[OsString], &Path, &str, Duration) -> Result<Value>,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<PathBuf> {
    let override_name = "mesa-override";
    let override_path = request.destination.join(override_name);
    let override_root = root.mkdir_new(OsStr::new(override_name), 0o700)?;
    let fragment_path = override_path.join("mesa-config.patch");
    let mut fragment = override_root.create_new_file(OsStr::new("mesa-config.patch"), 0o600)?;
    fragment
        .write_all(&prepared.mesa_fragment)
        .map_err(|error| {
            Refusal::new(format!(
                "could not write Mesa config patch fragment: {error}"
            ))
        })?;

    let patch_path = Path::new("/usr/bin/patch");
    let argv = vec![
        patch_path.as_os_str().to_os_string(),
        OsString::from("--batch"),
        OsString::from("--fuzz=0"),
        OsString::from("-p1"),
        OsString::from("-i"),
        fragment_path.as_os_str().to_os_string(),
    ];
    checkpoint("before applying the Mesa added-config fragment")?;
    let _process = run(
        &argv,
        &override_path,
        "mesa-header-config",
        Duration::from_secs(30),
    )?;
    ensure_directory_matches(&override_path, &override_root, "Mesa override directory")?;
    let config = override_root
        .regular(OsStr::new("mesa3dgl.conf"))
        .map_err(|_| {
            Refusal::new("Mesa header override did not produce a regular mesa3dgl.conf")
        })?;
    drop(config);
    let source = Directory::open(&request.source)?;
    let patch_bytes = read_relative_file(&source, MESA_PATCH_PATH, MAX_PATCH_BYTES)?;
    if digest_array(&patch_bytes) != request.mesa_patch_sha256 {
        return Err(Refusal::new(
            "Mesa source patch changed while applying the header override",
        ));
    }
    Ok(override_path.join("mesa3dgl.conf"))
}

fn validate_generator_recipe(recipe: &Value) -> Result<Vec<String>> {
    if optional_string(recipe, "compiler")?.is_some_and(|cc| cc != "cc") {
        return Err(Refusal::new("classic genmodule recipe compiler must be cc"));
    }
    let sources = recipe
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("classic genmodule recipe must contain a sources array"))?;
    if sources.len() != GENERATOR_SOURCE_COUNT {
        return Err(Refusal::new(
            "incomplete frozen public-header generator source coverage",
        ));
    }
    let mut result = Vec::with_capacity(sources.len());
    let mut seen = HashSet::with_capacity(sources.len());
    for value in sources {
        let raw = value
            .as_str()
            .ok_or_else(|| Refusal::new("classic genmodule source path must be a string"))?;
        validate_relative_inventory_path(raw)?;
        if !raw.starts_with(SOURCE_GENERATOR_PREFIX) || !raw.ends_with(".c") {
            return Err(Refusal::new(
                "classic genmodule source is outside tools/genmodule or is not C",
            ));
        }
        if !seen.insert(raw.to_owned()) {
            return Err(Refusal::new(
                "classic genmodule recipe contains duplicate source files",
            ));
        }
        result.push(raw.to_owned());
    }
    if let Some(flags) = recipe.get("flags") {
        let flags = flags
            .as_array()
            .ok_or_else(|| Refusal::new("classic genmodule flags must be an array"))?;
        if flags.len() != 3
            || flags[0].as_str() != Some("-O2")
            || flags[1].as_str() != Some("-w")
            || flags[2].as_str() != Some("-IAROS-NX/tools/genmodule")
        {
            return Err(Refusal::new(
                "classic genmodule flags differ from the frozen host-tool recipe",
            ));
        }
    }
    if let Some(output) = optional_string(recipe, "output")?
        && output != "build/pc-x86_64/hosttools/genmodule"
    {
        return Err(Refusal::new(
            "classic genmodule output differs from its declared host tool",
        ));
    }
    if let Some(cwd) = optional_string(recipe, "cwd")?
        && cwd != "build/pc-x86_64"
    {
        return Err(Refusal::new(
            "classic genmodule recipe has an unexpected working directory",
        ));
    }
    if let Some(original_cwd) = optional_string(recipe, "original_cwd")?
        && original_cwd != "AROS-NX/build/pc-x86_64"
    {
        return Err(Refusal::new(
            "classic genmodule recipe has an unexpected original working directory",
        ));
    }
    if let Some(argv_value) = recipe.get("argv") {
        let argv = argv_value
            .as_array()
            .ok_or_else(|| Refusal::new("classic genmodule argv must be an array"))?;
        let mut expected = vec![
            "cc".to_owned(),
            "-O2".to_owned(),
            "-w".to_owned(),
            "-IAROS-NX/tools/genmodule".to_owned(),
        ];
        expected.extend(result.iter().map(|source| format!("AROS-NX/{source}")));
        expected.push("-o".to_owned());
        expected.push("AROS-NX/build/pc-x86_64/hosttools/genmodule".to_owned());
        if argv.len() != expected.len()
            || argv
                .iter()
                .zip(expected)
                .any(|(actual, expected)| actual.as_str() != Some(expected.as_str()))
        {
            return Err(Refusal::new(
                "classic genmodule argv differs from its frozen source recipe",
            ));
        }
    }
    Ok(result)
}

fn validate_header_recipes(values: &[Value]) -> Result<(Vec<HeaderRecipe>, Vec<String>)> {
    if values.len() != HEADER_RECIPE_COUNT {
        return Err(Refusal::new(
            "incomplete frozen public-header recipe coverage",
        ));
    }
    let mut recipes = Vec::with_capacity(values.len());
    let mut outputs = Vec::with_capacity(PUBLIC_HEADER_COUNT);
    let mut seen_outputs = HashSet::with_capacity(PUBLIC_HEADER_COUNT);
    for value in values {
        let recipe = parse_header_recipe(value)?;
        for output in &recipe.outputs {
            insert_unique_output(output, &mut seen_outputs)?;
            outputs.push(output.clone());
        }
        recipes.push(recipe);
    }
    Ok((recipes, outputs))
}

fn insert_unique_output(output: &str, seen: &mut HashSet<String>) -> Result<()> {
    if !seen.insert(output.to_owned()) {
        return Err(Refusal::new(format!(
            "duplicate public SDK header output: {output}"
        )));
    }
    Ok(())
}

fn parse_header_recipe(value: &Value) -> Result<HeaderRecipe> {
    let config = required_string(value, "config", "public-header config")?;
    validate_relative_inventory_path(config)?;
    let module = required_string(value, "module", "public-header module")?;
    if !is_simple_token(module) {
        return Err(Refusal::new(
            "public-header module name is not a simple token",
        ));
    }
    let module_type = required_string(value, "module_type", "public-header module type")?;
    if module_type != "library" && module_type != "resource" {
        return Err(Refusal::new(
            "public-header module type must be library or resource",
        ));
    }
    let output_values = value
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("public-header recipe must contain an outputs array"))?;
    if output_values.len() != 5 {
        return Err(Refusal::new(
            "public-header recipe must declare exactly five outputs",
        ));
    }
    let mut outputs = Vec::with_capacity(5);
    for output in output_values {
        let output = output
            .as_str()
            .ok_or_else(|| Refusal::new("public-header output path must be a string"))?;
        validate_relative_inventory_path(output)?;
        outputs.push(output.to_owned());
    }
    let expected = expected_header_group(module);
    let observed: BTreeSet<&str> = outputs.iter().map(String::as_str).collect();
    if observed.len() != 5 || observed != expected.iter().map(String::as_str).collect() {
        return Err(Refusal::new(
            "public-header outputs do not match their generator module",
        ));
    }

    let generator_args = string_array(value, "generator_args", "public-header argv")?;
    let parsed = parse_generator_args(&generator_args)?;
    if parsed.config != format!("{ORIGINAL_SOURCE_PREFIX}{config}") {
        return Err(Refusal::new(
            "public-header generator config differs from its recipe",
        ));
    }
    if parsed.module != module || parsed.module_type != module_type {
        return Err(Refusal::new(
            "public-header generator module differs from its recipe",
        ));
    }
    if let Some(output_directory) = optional_string(value, "output_directory")?
        && output_directory != parsed.output_directory
    {
        return Err(Refusal::new(
            "public-header output directory differs from its generator argv",
        ));
    }
    if let Some(argv_value) = value.get("argv") {
        let argv = argv_value
            .as_array()
            .ok_or_else(|| Refusal::new("public-header full argv field must be an array"))?;
        if argv.len() != generator_args.len() + 1
            || argv.first().and_then(Value::as_str) != Some(ORIGINAL_GENERATOR)
            || argv[1..]
                .iter()
                .zip(&generator_args)
                .any(|(item, expected)| item.as_str() != Some(expected.as_str()))
        {
            return Err(Refusal::new(
                "public-header full argv differs from generator_args",
            ));
        }
    }
    if let Some(cwd) = optional_string(value, "cwd")?
        && cwd != "build/pc-x86_64"
    {
        return Err(Refusal::new(
            "public-header recipe has an unexpected generator cwd",
        ));
    }
    if let Some(original_cwd) = optional_string(value, "original_cwd")?
        && original_cwd != "AROS-NX/build/pc-x86_64"
    {
        return Err(Refusal::new(
            "public-header recipe has an unexpected original generator cwd",
        ));
    }

    let has_mesa_override = parsed.output_override.is_some();
    match value.get("output_override") {
        Some(Value::Null) | None if !has_mesa_override => {}
        Some(override_value) if has_mesa_override => {
            if override_value.get("kind").and_then(Value::as_str) != Some("build")
                || override_value.get("path").and_then(Value::as_str) != Some(MESA_CONFIG_PATH)
                || parsed.output_override.as_deref() != Some(MESA_CONFIG_PATH)
            {
                return Err(Refusal::new("unexpected public-header output override"));
            }
        }
        _ => {
            return Err(Refusal::new(
                "public-header output override is inconsistent",
            ));
        }
    }
    match (value.get("module_suffix"), parsed.module_suffix.as_deref()) {
        (Some(Value::Null) | None, None) => {}
        (Some(Value::String(observed)), Some(expected)) if observed == expected => {}
        _ => {
            return Err(Refusal::new(
                "public-header module suffix differs from generator argv",
            ));
        }
    }
    Ok(HeaderRecipe {
        config: config.to_owned(),
        outputs,
        generator_args,
        has_mesa_override,
    })
}

struct ParsedGeneratorArgs {
    config: String,
    output_directory: String,
    output_override: Option<String>,
    module_suffix: Option<String>,
    module: String,
    module_type: String,
}

fn parse_generator_args(args: &[String]) -> Result<ParsedGeneratorArgs> {
    let mut options = BTreeMap::<&str, &str>::new();
    let mut index = 0;
    while index < args.len() && args[index].starts_with('-') {
        let option = args[index].as_str();
        if !["-c", "-d", "-o", "-s"].contains(&option)
            || options.contains_key(option)
            || index + 1 >= args.len()
        {
            return Err(Refusal::new(format!(
                "unexpected or incomplete public-header generator option: {option}"
            )));
        }
        options.insert(option, args[index + 1].as_str());
        index += 2;
    }
    if args.get(index).map(String::as_str) != Some("writeincludes") || args.len() != index + 3 {
        return Err(Refusal::new(
            "public-header generator must use writeincludes with one module and type",
        ));
    }
    let config = *options
        .get("-c")
        .ok_or_else(|| Refusal::new("public-header generator is missing -c"))?;
    let output_directory = options
        .get("-d")
        .ok_or_else(|| Refusal::new("public-header generator is missing -d"))?;
    let config_suffix = config.strip_prefix(ORIGINAL_SOURCE_PREFIX).ok_or_else(|| {
        Refusal::new("public-header generator config is outside the source prefix")
    })?;
    validate_relative_inventory_path(config_suffix)?;
    let output_directory = build_relative(output_directory)?;
    let output_override = options
        .get("-o")
        .map(|raw| build_relative(raw))
        .transpose()?;
    let module_suffix = options.get("-s").map(|value| (*value).to_owned());
    if module_suffix
        .as_deref()
        .is_some_and(|suffix| !is_simple_token(suffix))
    {
        return Err(Refusal::new(
            "public-header module suffix is not a simple token",
        ));
    }
    let module = args[index + 1].as_str();
    if !is_simple_token(module) {
        return Err(Refusal::new(
            "public-header module name is not a simple token",
        ));
    }
    let module_type = args[index + 2].as_str();
    if module_type != "library" && module_type != "resource" {
        return Err(Refusal::new(
            "public-header module type must be library or resource",
        ));
    }
    Ok(ParsedGeneratorArgs {
        config: config.to_owned(),
        output_directory,
        output_override,
        module_suffix,
        module: module.to_owned(),
        module_type: module_type.to_owned(),
    })
}

fn expected_header_group(module: &str) -> BTreeSet<String> {
    [
        format!("clib/{module}_protos.h"),
        format!("inline/{module}.h"),
        format!("defines/{module}.h"),
        format!("defines/{module}_LVO.h"),
        format!("proto/{module}.h"),
    ]
    .into_iter()
    .collect()
}

fn build_relative(value: &str) -> Result<String> {
    if value == "AROS-NX/build/pc-x86_64" {
        return Ok("build/pc-x86_64".to_owned());
    }
    let suffix = value.strip_prefix(ORIGINAL_BUILD_PREFIX).ok_or_else(|| {
        Refusal::new("public-header build path is outside the declared pc-x86_64 root")
    })?;
    validate_relative_inventory_path(suffix)?;
    Ok(format!("build/pc-x86_64/{suffix}"))
}

fn validate_complete_coverage(
    header_recipe_count: usize,
    generator_source_count: usize,
    output_count: usize,
) -> Result<()> {
    if header_recipe_count != HEADER_RECIPE_COUNT
        || generator_source_count != GENERATOR_SOURCE_COUNT
        || output_count != PUBLIC_HEADER_COUNT
    {
        return Err(Refusal::new(
            "incomplete public-header recipes, generator sources, or outputs",
        ));
    }
    Ok(())
}

fn is_simple_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
        })
}

fn required_string<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{label} must be a string")))
}

fn optional_string<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>> {
    match value.get(field) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(Refusal::new(format!("{field} must be a string or null"))),
    }
}

fn string_array(value: &Value, field: &str, label: &str) -> Result<Vec<String>> {
    let array = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new(format!("{label} must be an array")))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Refusal::new(format!("{label} entries must be strings")))
        })
        .collect()
}

/// Select the unique Mesa added-file diff and verify both its complete hunk
/// shape and the caller's authenticated archive-manifest digest.
fn mesa_added_config_patch(patch: &[u8], expected_sha256: &[u8; 32]) -> Result<Vec<u8>> {
    if digest_array(patch) != *expected_sha256 {
        return Err(Refusal::new(
            "Mesa header override port patch differs from its authenticated pin",
        ));
    }
    let lines = byte_lines(patch);
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            (strip_line_ending(line)
                == MESA_DIFF_HEADER
                    .strip_suffix(b"\n")
                    .unwrap_or(MESA_DIFF_HEADER))
            .then_some(index)
        })
        .collect();
    if starts.len() != 1 {
        return Err(Refusal::new(
            "Mesa public-header patch must contain one exact mesa3dgl.conf diff block",
        ));
    }
    let start_line = starts[0];
    let start_offset = line_offset(&lines, start_line)?;
    let end_line = lines
        .iter()
        .enumerate()
        .skip(start_line + 1)
        .find_map(|(index, line)| line.starts_with(b"diff -ruN ").then_some(index))
        .unwrap_or(lines.len());
    let end_offset = if end_line == lines.len() {
        patch.len()
    } else {
        line_offset(&lines, end_line)?
    };
    let block = &patch[start_offset..end_offset];
    validate_complete_added_file_block(block)?;
    Ok(block.to_vec())
}

fn validate_complete_added_file_block(block: &[u8]) -> Result<()> {
    let lines = byte_lines(block);
    if lines.len() < 4
        || strip_line_ending(lines[0])
            != b"diff -ruN mesa-20.0.8/mesa3dgl.conf mesa-20.0.8.aros/mesa3dgl.conf"
        || !patch_file_line_matches(
            strip_line_ending(lines[1]),
            b"--- mesa-20.0.8/mesa3dgl.conf",
        )
        || !patch_file_line_matches(
            strip_line_ending(lines[2]),
            b"+++ mesa-20.0.8.aros/mesa3dgl.conf",
        )
    {
        return Err(Refusal::new(
            "Mesa config diff is not a complete added-file patch",
        ));
    }
    let added_lines = parse_added_hunk_header(strip_line_ending(lines[3]))?;
    let mut observed_added_lines = 0_usize;
    let mut saw_no_newline_marker = false;
    for (index, line) in lines.iter().enumerate().skip(4) {
        let line = strip_line_ending(line);
        if line == b"\\ No newline at end of file" {
            if saw_no_newline_marker || index + 1 != lines.len() {
                return Err(Refusal::new(
                    "Mesa added-file hunk has an unexpected no-newline marker",
                ));
            }
            saw_no_newline_marker = true;
            continue;
        }
        if !line.starts_with(b"+") {
            return Err(Refusal::new(
                "Mesa added-file hunk contains a non-addition line",
            ));
        }
        observed_added_lines = observed_added_lines
            .checked_add(1)
            .ok_or_else(|| Refusal::new("Mesa added-file line count overflow"))?;
    }
    if observed_added_lines != added_lines || observed_added_lines == 0 {
        return Err(Refusal::new(
            "Mesa added-file hunk is incomplete or has an incorrect line count",
        ));
    }
    Ok(())
}

fn patch_file_line_matches(line: &[u8], expected: &[u8]) -> bool {
    line.strip_prefix(expected)
        .is_some_and(|tail| tail.is_empty() || tail.starts_with(b" ") || tail.starts_with(b"\t"))
}

fn parse_added_hunk_header(line: &[u8]) -> Result<usize> {
    let suffix = line
        .strip_prefix(b"@@ -0,0 +1,")
        .ok_or_else(|| Refusal::new("Mesa config patch must use one complete added-file hunk"))?;
    let close = suffix
        .windows(3)
        .position(|window| window == b" @@")
        .ok_or_else(|| Refusal::new("Mesa added-file hunk header is malformed"))?;
    let count = &suffix[..close];
    if count.is_empty() || !count.iter().all(u8::is_ascii_digit) || &suffix[close..] != b" @@" {
        return Err(Refusal::new("Mesa added-file hunk header is malformed"));
    }
    let count = std::str::from_utf8(count)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| Refusal::new("Mesa added-file hunk line count is invalid"))?;
    Ok(count)
}

fn byte_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    if start < bytes.len() {
        lines.push(&bytes[start..]);
    }
    lines
}

fn line_offset(lines: &[&[u8]], line_index: usize) -> Result<usize> {
    lines
        .iter()
        .take(line_index)
        .try_fold(0_usize, |offset, line| {
            offset
                .checked_add(line.len())
                .ok_or_else(|| Refusal::new("patch line offset overflow"))
        })
}

fn strip_line_ending(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n")
        .unwrap_or(line)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line))
}

/// Replace only the unique complete provenance banner with the relative config
/// path. Every other byte remains unchanged.
fn rewrite_provenance_banner(original: &[u8], config: &str) -> Result<Vec<u8>> {
    const PREFIX: &[u8] = b"Automatically generated from '";
    let starts: Vec<usize> = original
        .windows(PREFIX.len())
        .enumerate()
        .filter_map(|(index, window)| (window == PREFIX).then_some(index))
        .collect();
    if starts.len() != 1 {
        return Err(Refusal::new(
            "frozen header must contain exactly one complete provenance banner",
        ));
    }
    let start = starts[0];
    let value_start = start + PREFIX.len();
    let line_end = original[value_start..]
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .map(|offset| value_start + offset)
        .unwrap_or(original.len());
    let terminator = original[value_start..line_end]
        .windows(2)
        .position(|window| window == b"'.")
        .map(|offset| value_start + offset)
        .ok_or_else(|| Refusal::new("frozen header provenance banner is incomplete"))?;
    let old_path = &original[value_start..terminator];
    let suffix = format!("/{config}");
    if !old_path.starts_with(b"/")
        || old_path.contains(&b'\'')
        || !old_path.ends_with(suffix.as_bytes())
    {
        return Err(Refusal::new(
            "frozen header provenance does not end in its declared absolute config path",
        ));
    }
    let mut normalized = Vec::with_capacity(
        original
            .len()
            .saturating_sub(old_path.len())
            .saturating_add(config.len()),
    );
    normalized.extend_from_slice(&original[..value_start]);
    normalized.extend_from_slice(config.as_bytes());
    normalized.extend_from_slice(&original[terminator..]);
    Ok(normalized)
}

fn validate_header_bytes(
    generated: &[u8],
    expected: &[u8],
    forbidden_path_prefixes: &[Vec<u8>],
    output: &str,
) -> Result<()> {
    if generated != expected {
        return Err(Refusal::new(format!(
            "public header differs outside its provenance path: {output}"
        )));
    }
    if forbidden_path_prefixes
        .iter()
        .any(|prefix| contains_bytes(generated, prefix))
    {
        return Err(Refusal::new(format!(
            "public header contains a forbidden path prefix: {output}"
        )));
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn header_record(bytes: &[u8]) -> Result<Value> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| Refusal::new("public header length cannot fit in a receipt"))?;
    Ok(json!({"bytes": length, "sha256": sha256_bytes(bytes)}))
}

fn replace_option_value(args: &mut [OsString], option: &str, value: OsString) -> Result<()> {
    let matches: Vec<usize> = args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (arg.as_os_str() == OsStr::new(option)).then_some(index))
        .collect();
    if matches.len() != 1 || matches[0] + 1 >= args.len() {
        return Err(Refusal::new(format!(
            "public-header generator must contain one complete {option} option"
        )));
    }
    args[matches[0] + 1] = value;
    Ok(())
}

fn version_stdout(process: &Value) -> Result<String> {
    let stdout = process
        .get("stdout")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Refusal::new("native compiler version evidence must contain UTF-8 stdout")
        })?;
    if stdout.is_empty() || stdout.len() > MAX_VERSION_BYTES {
        return Err(Refusal::new(
            "native compiler version output is empty or exceeds its byte bound",
        ));
    }
    Ok(stdout.to_owned())
}

fn verify_compiler_pin(path: &Path, pin: CsdkSourceFilePin) -> Result<String> {
    let file = open_regular_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect native compiler: {error}")))?;
    if metadata.len() != pin.bytes || metadata.mode() & 0o111 == 0 {
        return Err(Refusal::new(
            "native host C compiler size or executable mode differs from its pin",
        ));
    }
    let (bytes, sha256) = hash_open_file(file, Some(pin.bytes))?;
    if bytes != pin.bytes || sha256 != encode_hex(&pin.sha256) {
        return Err(Refusal::new(
            "native host C compiler differs from its authenticated identity",
        ));
    }
    Ok(sha256)
}

fn hash_open_file(mut file: File, expected_length: Option<u64>) -> Result<(u64, String)> {
    let initial_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect opened file: {error}")))?
        .len();
    if expected_length.is_some_and(|expected| expected != initial_length) {
        return Err(Refusal::new(
            "opened file length changed from its expected identity",
        ));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not hash opened file: {error}"))),
        };
        total = total
            .checked_add(u64::try_from(count).map_err(|_| Refusal::new("file length overflow"))?)
            .ok_or_else(|| Refusal::new("file length overflow"))?;
        hasher.update(&buffer[..count]);
    }
    if total != initial_length {
        return Err(Refusal::new("file changed while its digest was computed"));
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((total, encode_hex(&digest)))
}

fn digest_array(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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
    let name = destination
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| {
            Refusal::new("public-header destination must name a fresh directory below its parent")
        })?;
    let parent = destination
        .parent()
        .ok_or_else(|| Refusal::new("public-header destination must have a parent directory"))?;
    Ok((parent, name))
}

fn require_fresh_destination(destination: &Path) -> Result<()> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(Refusal::new(
            "fresh public-header reproduction root required",
        )),
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
            "{label} changed during header reproduction"
        )));
    }
    Ok(())
}

fn open_relative_file(root: &Directory, relative: &str) -> Result<File> {
    validate_relative_inventory_path(relative)?;
    let path = Path::new(relative);
    let name = path
        .file_name()
        .ok_or_else(|| Refusal::new("relative file path has no basename"))?;
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => root
            .relative_directory(
                parent
                    .to_str()
                    .ok_or_else(|| Refusal::new("relative inventory path is not UTF-8"))?,
            )?
            .regular(name),
        _ => root.regular(name),
    }
}

fn read_relative_file(root: &Directory, relative: &str, maximum: usize) -> Result<Vec<u8>> {
    let file = open_relative_file(root, relative)?;
    read_bounded(file, maximum)
}

fn read_bounded(mut file: File, maximum: usize) -> Result<Vec<u8>> {
    let initial_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect input file: {error}")))?
        .len();
    let maximum_u64 =
        u64::try_from(maximum).map_err(|_| Refusal::new("file limit cannot fit in a length"))?;
    if initial_length > maximum_u64 {
        return Err(Refusal::new("input file exceeds its byte bound"));
    }
    let capacity = usize::try_from(initial_length)
        .map_err(|_| Refusal::new("input file length cannot fit in memory"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| Refusal::new(format!("could not allocate input buffer: {error}")))?;
    let over_limit = maximum
        .checked_add(1)
        .ok_or_else(|| Refusal::new("input file bound overflow"))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = over_limit.saturating_sub(bytes.len());
        let read_limit = buffer.len().min(remaining);
        if read_limit == 0 {
            return Err(Refusal::new("input file exceeds its byte bound"));
        }
        let count = match file.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not read input file: {error}"))),
        };
        bytes
            .try_reserve(count)
            .map_err(|error| Refusal::new(format!("could not grow input buffer: {error}")))?;
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > maximum {
            return Err(Refusal::new("input file exceeds its byte bound"));
        }
    }
    if u64::try_from(bytes.len()).ok() != Some(initial_length) {
        return Err(Refusal::new("input file changed while it was read"));
    }
    Ok(bytes)
}

fn hash_relative_file(root: &Directory, relative: &str) -> Result<String> {
    let file = open_relative_file(root, relative)?;
    Ok(hash_open_file(file, None)?.1)
}

fn write_relative_new(
    root_path: &Path,
    root: &Directory,
    relative: &str,
    bytes: &[u8],
    created_directories: &mut HashSet<String>,
) -> Result<()> {
    validate_relative_inventory_path(relative)?;
    let path = Path::new(relative);
    let name = path
        .file_name()
        .ok_or_else(|| Refusal::new("relative output path has no basename"))?;
    let parent = match path.parent() {
        Some(parent) => parent
            .to_str()
            .ok_or_else(|| Refusal::new("relative output parent is not UTF-8"))?,
        None => "",
    };
    let directory = if parent.is_empty() {
        open_owned_root(root_path, root)?
    } else {
        create_owned_directory(root_path, root, parent, created_directories)?
    };
    let mut file = directory.create_new_file(name, 0o600)?;
    file.write_all(bytes)
        .map_err(|error| Refusal::new(format!("could not write private config copy: {error}")))
}

fn open_owned_root(root_path: &Path, root: &Directory) -> Result<Directory> {
    let opened = Directory::open(root_path)?;
    let expected = root.metadata()?;
    let observed = opened.metadata()?;
    if expected.dev() != observed.dev() || expected.ino() != observed.ino() {
        return Err(Refusal::new(
            "private source root changed during header reproduction",
        ));
    }
    Ok(opened)
}

fn create_owned_directory(
    root_path: &Path,
    root: &Directory,
    relative: &str,
    created_directories: &mut HashSet<String>,
) -> Result<Directory> {
    validate_relative_inventory_path(relative)?;
    let mut current = open_owned_root(root_path, root)?;
    let mut prefix = String::new();
    for component in relative.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        let child = if created_directories.contains(&prefix) {
            current.child(OsStr::new(component))?
        } else {
            let child = current.mkdir_new(OsStr::new(component), 0o700)?;
            created_directories.insert(prefix.clone());
            child
        };
        current = child;
    }
    Ok(current)
}

fn header_status() -> &'static str {
    if cfg!(target_os = "macos") {
        "PASS_MACOS_HEADERS_ONLY"
    } else {
        "PASS_LINUX_HEADERS_ONLY"
    }
}

#[cfg(test)]
#[path = "csdk_headers/tests.rs"]
mod tests;
