//! Planner and bounded compiler executor for the frozen Nouveau C recipe.
//!
//! The planner maps the existing 825 compile records and their Ninja archive
//! order into concrete paths. The executor rebuilds the plan from authenticated
//! recipe values before validating outputs and directly supervising clang.
//! Neither path invokes Ninja or a shell command.

mod execution;
pub use execution::{NouveauCompileRequest, compile_nouveau, compile_nouveau_with_prefix};

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    ffi::OsStr,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use serde_json::{Value, json};

use crate::{Refusal, Result};

const EXPECTED_OBJECTS: usize = 825;
const ARCHIVE_OUTPUT: &str = "SYS/Developer/lib/libdrm_nouveau.a";
const ARCHIVE_RULE: &str = "C_STATIC_LIBRARY_LINKER__hidd-nouveau-drm_Release";
const COMPILER_RELATIVE: &str = "bin/clang-11";
const SCHEMA: &str = "ami-rust-nouveau-compile-plan-v1";
const MAX_RECIPE_BYTES: usize = 80 * 1024 * 1024;
const SOURCE_PREFIX: &str = "AROS-NX/";
const BUILD_PREFIX: &str = "AROS-NX/build/pc-x86_64/";
const BUILD_ROOT: &str = "AROS-NX/build/pc-x86_64";
const NOUVEAU_OBJECT_PREFIX: &str =
    "AROS-NX/build/pc-x86_64/CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/";
const FROZEN_COMPILER_PREFIX: &str = concat!(
    "$",
    "{CROSS_TOOLCHAIN_ROOT}/v0.1.4/macos-aarch64/pc-x86_64/"
);
const FROZEN_COMPILER_SUFFIX: &str = "/toolchain/bin/clang";

fn fail(message: impl Into<String>) -> Refusal {
    Refusal::new(message)
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn path_string(path: &Path, label: &str) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        fail(format!(
            "{label} cannot be represented as a UTF-8 JSON string: {}",
            display_path(path)
        ))
    })
}

/// Match pathlib.Path normalization for absolute Unix roots while retaining
/// its special exactly-two-leading-slash form.
fn normalized_absolute_root(value: &Path, label: &str) -> Result<PathBuf> {
    if !value.is_absolute() {
        return Err(fail(format!("{label} must be absolute")));
    }
    if value
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(fail(format!("{label} must not contain parent traversal")));
    }

    let bytes = value.as_os_str().as_bytes();
    let anchor = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
        "//"
    } else {
        "/"
    };
    let mut normalized = PathBuf::from(anchor);
    for component in value.components() {
        if let Component::Normal(part) = component {
            normalized.push(part);
        }
    }
    Ok(normalized)
}

/// Read metadata for each component without opening directories or files.
/// This rejects symlinks in the path, but the checks are not a snapshot against
/// concurrent filesystem changes; any future compiler execution must revalidate.
fn metadata_without_symlink_components(path: &Path, label: &str) -> Result<fs::Metadata> {
    let path = normalized_absolute_root(path, label)?;
    let bytes = path.as_os_str().as_bytes();
    let anchor = if bytes.starts_with(b"//") && !bytes.starts_with(b"///") {
        "//"
    } else {
        "/"
    };
    let mut cursor = PathBuf::from(anchor);
    let mut metadata = fs::symlink_metadata(&cursor)
        .map_err(|error| fail(format!("{label} cannot be inspected: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(fail(format!(
            "{label} traverses a symlink: {}",
            display_path(&cursor)
        )));
    }
    for component in path.components() {
        if let Component::Normal(part) = component {
            cursor.push(part);
            metadata = fs::symlink_metadata(&cursor).map_err(|error| {
                fail(format!(
                    "{label} cannot be inspected at {}: {error}",
                    display_path(&cursor)
                ))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(fail(format!(
                    "{label} traverses a symlink: {}",
                    display_path(&cursor)
                )));
            }
        }
    }
    Ok(metadata)
}

fn require_directory(value: &Path, label: &str) -> Result<PathBuf> {
    let path = normalized_absolute_root(value, label)?;
    path_string(&path, label)?;
    let metadata = metadata_without_symlink_components(&path, label).map_err(|error| {
        fail(format!(
            "{label} is not an existing directory or traverses a symlink: {}: {error}",
            display_path(&path)
        ))
    })?;
    if !metadata.is_dir() {
        return Err(fail(format!(
            "{label} is not an existing directory: {}",
            display_path(&path)
        )));
    }
    Ok(path)
}

fn intersects(left: &Path, right: &Path) -> bool {
    left == right || left.strip_prefix(right).is_ok() || right.strip_prefix(left).is_ok()
}

fn require_disjoint(left: &Path, right: &Path, label: &str) -> Result<()> {
    if intersects(left, right) {
        return Err(fail(format!(
            "{label} paths overlap: {} and {}",
            display_path(left),
            display_path(right)
        )));
    }
    Ok(())
}

fn safe_relative(value: &str, label: &str) -> Result<PathBuf> {
    if value.is_empty() || value.contains('\\') || value.contains('\0') || value.contains(':') {
        return Err(fail(format!("{label} is not a portable relative path")));
    }
    if value.starts_with('/') {
        return Err(fail(format!("{label} is not normalized: {value}")));
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(fail(format!("{label} is not normalized: {value}")));
    }
    Ok(PathBuf::from(value))
}

fn under(path: &Path, root: &Path, label: &str) -> Result<()> {
    if path.strip_prefix(root).is_err() {
        return Err(fail(format!(
            "{label} escapes its declared root: {}",
            display_path(path)
        )));
    }
    Ok(())
}

fn recipe_path(value: &str, source_root: &Path, build_root: &Path, label: &str) -> Result<PathBuf> {
    if value == BUILD_ROOT {
        return Ok(build_root.to_path_buf());
    }
    if let Some(relative) = value.strip_prefix(BUILD_PREFIX) {
        return Ok(build_root.join(safe_relative(relative, label)?));
    }
    if let Some(relative) = value.strip_prefix(SOURCE_PREFIX) {
        return Ok(source_root.join(safe_relative(relative, label)?));
    }
    Err(fail(format!(
        "{label} is outside the declared source/build prefixes: {value}"
    )))
}

fn output_path(value: &str, build_root: &Path, label: &str) -> Result<PathBuf> {
    Ok(build_root.join(safe_relative(value, label)?))
}

fn archive_members(ninja_text: &str) -> Result<Vec<String>> {
    let matches: Vec<_> = crate::csdk_recipes::ninja_edges(ninja_text)?
        .into_iter()
        .filter(|edge| edge.outputs.iter().any(|output| output == ARCHIVE_OUTPUT))
        .collect();
    if matches.len() != 1
        || matches[0].outputs.len() != 1
        || matches[0].outputs[0] != ARCHIVE_OUTPUT
    {
        return Err(fail(
            "Ninja must declare one unambiguous Nouveau DRM archive edge",
        ));
    }
    let dependencies = &matches[0].dependencies;
    if dependencies.first().map(String::as_str) != Some(ARCHIVE_RULE) {
        return Err(fail("Nouveau DRM archive edge uses an unexpected rule"));
    }
    let tokens = &dependencies[1..];
    let boundary = tokens
        .iter()
        .position(|token| token == "|" || token == "||")
        .unwrap_or(tokens.len());
    let members = &tokens[..boundary];
    if members.len() != EXPECTED_OBJECTS
        || members.iter().collect::<HashSet<_>>().len() != EXPECTED_OBJECTS
    {
        return Err(fail(
            "Nouveau DRM archive must list exactly 825 unique object members",
        ));
    }
    let member_prefix = NOUVEAU_OBJECT_PREFIX
        .strip_prefix(BUILD_PREFIX)
        .expect("Nouveau member prefix starts with the frozen build prefix");
    for member in members {
        if !member.starts_with(member_prefix) || !member.ends_with(".c.obj") {
            return Err(fail(
                "Nouveau DRM archive contains a non-Nouveau object member",
            ));
        }
        safe_relative(member, "Nouveau DRM archive member")?;
    }
    Ok(members.to_vec())
}

fn frozen_compiler(value: &str) -> bool {
    value
        .strip_prefix(FROZEN_COMPILER_PREFIX)
        .and_then(|tail| tail.strip_suffix(FROZEN_COMPILER_SUFFIX))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn map_path_operand(
    value: &str,
    source_root: &Path,
    build_root: &Path,
    label: &str,
) -> Result<PathBuf> {
    let path = recipe_path(value, source_root, build_root, label)?;
    if !path.is_absolute() {
        return Err(fail(format!("{label} did not map to an absolute path")));
    }
    Ok(path)
}

fn has_unknown_absolute_or_placeholder(token: &str) -> bool {
    let bytes = token.as_bytes();
    let windows_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\');
    token.starts_with('/')
        || windows_absolute
        || bytes.iter().enumerate().any(|(index, byte)| {
            *byte == b'/' && (index == 0 || bytes[index - 1] == b'=' || bytes[index - 1] == b',')
        })
        || token.contains('$')
        || token.contains("AROS-NX/")
        || token.contains("CMakeFiles/")
}

struct MappedCompile {
    argv: Vec<String>,
    source: PathBuf,
    output: PathBuf,
    include_paths: Vec<PathBuf>,
}

fn map_argv(
    raw_argv: &[Value],
    record: &Value,
    source_root: &Path,
    build_root: &Path,
    compiler: &Path,
) -> Result<MappedCompile> {
    if raw_argv.is_empty() || raw_argv.iter().any(|item| !item.is_string()) {
        return Err(fail("Nouveau compile record has an invalid argv"));
    }
    let raw_argv: Vec<String> = raw_argv
        .iter()
        .map(|item| {
            item.as_str()
                .expect("argv strings checked above")
                .to_owned()
        })
        .collect();
    if !frozen_compiler(&raw_argv[0]) {
        return Err(fail(
            "Nouveau compile record uses an unknown compiler placeholder",
        ));
    }

    let source_value = record
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("Nouveau source is not a portable relative path"))?;
    let source_relative = safe_relative(source_value, "Nouveau source")?;
    if !source_value.starts_with("workbench/hidds/nouveau/")
        || source_relative.extension() != Some(OsStr::new("c"))
    {
        return Err(fail(
            "Nouveau compile source is outside its direct C source subtree",
        ));
    }
    let source = source_root.join(source_relative);

    let object_value = record
        .get("object")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("Nouveau compile object is outside the declared build prefix"))?;
    let object_prefix = "build/pc-x86_64/";
    let object_suffix = object_value
        .strip_prefix(object_prefix)
        .ok_or_else(|| fail("Nouveau compile object is outside the declared build prefix"))?;
    let output = build_root.join(safe_relative(object_suffix, "Nouveau object output")?);

    if raw_argv.iter().filter(|item| item.as_str() == "-o").count() != 1
        || raw_argv.iter().filter(|item| item.as_str() == "-c").count() != 1
    {
        return Err(fail(
            "Nouveau compile argv must have exactly one -o and one -c",
        ));
    }

    let mut argv = raw_argv.clone();
    argv[0] = path_string(compiler, "pinned clang-11 compiler")?;
    let mut output_seen = false;
    let mut source_seen = false;
    let mut include_paths = Vec::new();
    let mut index = 1;
    while index < argv.len() {
        let token = argv[index].clone();
        if token == "-I" || token == "-iquote" {
            if index + 1 >= argv.len() {
                return Err(fail(format!(
                    "Nouveau compile argv has an incomplete {token}"
                )));
            }
            let mapped = map_path_operand(
                &argv[index + 1],
                source_root,
                build_root,
                &format!("{token} operand"),
            )?;
            include_paths.push(mapped.clone());
            argv[index + 1] = path_string(&mapped, "Nouveau include path")?;
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("-iquote").filter(|_| token != "-iquote") {
            let mapped = map_path_operand(value, source_root, build_root, "-iquote operand")?;
            include_paths.push(mapped.clone());
            argv[index] = format!("-iquote{}", path_string(&mapped, "Nouveau include path")?);
            index += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("-I").filter(|_| token != "-I") {
            let mapped = map_path_operand(value, source_root, build_root, "-I operand")?;
            include_paths.push(mapped.clone());
            argv[index] = format!("-I{}", path_string(&mapped, "Nouveau include path")?);
            index += 1;
            continue;
        }
        if token == "--sysroot" {
            if index + 1 >= argv.len() {
                return Err(fail("Nouveau compile argv has an incomplete --sysroot"));
            }
            let mapped = map_path_operand(
                &argv[index + 1],
                source_root,
                build_root,
                "--sysroot operand",
            )?;
            include_paths.push(mapped.clone());
            argv[index + 1] = path_string(&mapped, "Nouveau sysroot")?;
            index += 2;
            continue;
        }
        if let Some(value) = token.strip_prefix("--sysroot=") {
            let mapped = map_path_operand(value, source_root, build_root, "--sysroot operand")?;
            include_paths.push(mapped.clone());
            argv[index] = format!("--sysroot={}", path_string(&mapped, "Nouveau sysroot")?);
            index += 1;
            continue;
        }
        if token == "-o" {
            if index + 1 >= argv.len() {
                return Err(fail("Nouveau compile argv has an incomplete -o"));
            }
            let mapped = output_path(&argv[index + 1], build_root, "Nouveau -o operand")?;
            if mapped != output {
                return Err(fail(
                    "Nouveau -o operand differs from the compilation database object",
                ));
            }
            argv[index + 1] = path_string(&mapped, "Nouveau object output")?;
            output_seen = true;
            index += 2;
            continue;
        }
        if token == "-c" {
            if index + 1 >= argv.len() {
                return Err(fail("Nouveau compile argv has an incomplete -c"));
            }
            let mapped = map_path_operand(
                &argv[index + 1],
                source_root,
                build_root,
                "Nouveau -c operand",
            )?;
            if mapped != source {
                return Err(fail(
                    "Nouveau -c operand differs from the compilation database source",
                ));
            }
            argv[index + 1] = path_string(&mapped, "Nouveau source")?;
            source_seen = true;
            index += 2;
            continue;
        }

        if has_unknown_absolute_or_placeholder(&token) {
            return Err(fail(format!(
                "Nouveau compile argv contains an unmapped path or placeholder: {token}"
            )));
        }
        index += 1;
    }

    if !output_seen || !source_seen {
        return Err(fail(
            "Nouveau compile argv is missing its mapped source or output",
        ));
    }
    argv.push(format!(
        "-ffile-prefix-map={}=.",
        path_string(source_root, "source root")?
    ));
    Ok(MappedCompile {
        argv,
        source,
        output,
        include_paths,
    })
}

fn require_input_directory(path: &Path) -> Result<()> {
    let metadata = metadata_without_symlink_components(path, "Nouveau input directory").map_err(
        |error| {
            fail(format!(
                "Nouveau include or sysroot directory is missing or traverses a symlink: {}: {error}",
                display_path(path)
            ))
        },
    )?;
    if !metadata.is_dir() {
        return Err(fail(format!(
            "Nouveau include or sysroot directory is missing or is not a directory: {}",
            display_path(path)
        )));
    }
    Ok(())
}

fn require_source_file(path: &Path) -> Result<()> {
    let inspect = || -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| fail("source path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| fail("source path has no file name"))?;
        let parent_metadata = metadata_without_symlink_components(parent, "Nouveau source parent")?;
        if !parent_metadata.is_dir() {
            return Err(fail("source parent is not a directory"));
        }
        let source_path = parent.join(name);
        let source_metadata = metadata_without_symlink_components(&source_path, "Nouveau source")?;
        if !source_metadata.is_file() {
            return Err(fail("source entry is not a regular file"));
        }
        Ok(())
    };
    inspect().map_err(|error| {
        fail(format!(
            "Nouveau source file is missing, non-regular, or traverses a symlink: {}: {error}",
            display_path(path)
        ))
    })
}

/// Create a bounded, read-only plan for the frozen 825-object Nouveau archive.
///
/// Records are the parsed compilation-database values. The raw argument
/// vector is copied exactly as provided; the mapped vector contains the
/// concrete compiler and source/build operands followed by the source prefix
/// map. All returned filesystem paths must be UTF-8 JSON strings.
pub fn plan_nouveau(
    records: &[Value],
    ninja_text: &str,
    source_root: &Path,
    build_root: &Path,
    toolchain_root: &Path,
) -> Result<Value> {
    if records.len() != EXPECTED_OBJECTS {
        return Err(fail(
            "Nouveau compile plan requires exactly 825 parsed records",
        ));
    }
    if ninja_text.len() > MAX_RECIPE_BYTES {
        return Err(fail(format!(
            "Ninja input exceeds the {MAX_RECIPE_BYTES} byte limit"
        )));
    }

    let source_root = require_directory(source_root, "source root")?;
    let build_root = require_directory(build_root, "build root")?;
    let toolchain_root = require_directory(toolchain_root, "toolchain root")?;
    require_disjoint(&source_root, &build_root, "source/build")?;
    require_disjoint(&source_root, &toolchain_root, "source/toolchain")?;
    require_disjoint(&build_root, &toolchain_root, "build/toolchain")?;

    let members = archive_members(ninja_text)?;
    let mut by_object: HashMap<String, &Value> = HashMap::new();
    let mut by_source = HashSet::new();
    for row in records {
        if !row.is_object() {
            return Err(fail("Nouveau compile record must be an object"));
        }
        let object_value = row
            .get("object")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("Nouveau compile record is missing its object path"))?;
        safe_relative(object_value, "Nouveau compile object")?;
        if by_object.contains_key(object_value) {
            return Err(fail(format!(
                "duplicate Nouveau compile object: {object_value}"
            )));
        }
        let source_value = row
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("Nouveau source is not a portable relative path"))?;
        safe_relative(source_value, "Nouveau compile source")?;
        if !by_source.insert(source_value.to_owned()) {
            return Err(fail(format!(
                "duplicate Nouveau compile source: {source_value}"
            )));
        }
        by_object.insert(object_value.to_owned(), row);
    }
    if by_object.len() != EXPECTED_OBJECTS {
        return Err(fail("Nouveau compile object set is incomplete"));
    }

    let compiler = toolchain_root.join(COMPILER_RELATIVE);
    let mut ordered_objects = Vec::with_capacity(EXPECTED_OBJECTS);
    let mut ordered_object_strings = Vec::with_capacity(EXPECTED_OBJECTS);
    let mut member_basenames = Vec::with_capacity(EXPECTED_OBJECTS);
    let mut commands = Vec::with_capacity(EXPECTED_OBJECTS);
    for ninja_member in &members {
        let object_value = format!("build/pc-x86_64/{ninja_member}");
        let row = by_object.get(&object_value).ok_or_else(|| {
            fail(format!(
                "Ninja archive object is absent from the compile database: {ninja_member}"
            ))
        })?;
        let raw_argv = row
            .get("argv")
            .and_then(Value::as_array)
            .ok_or_else(|| fail("Nouveau compile record has an invalid argv"))?;
        let MappedCompile {
            argv,
            source,
            output,
            include_paths,
        } = map_argv(raw_argv, row, &source_root, &build_root, &compiler)?;
        under(&source, &source_root, "Nouveau source")?;
        under(&output, &build_root, "Nouveau object output")?;
        if intersects(&source, &output) {
            return Err(fail("Nouveau object output overlaps a source file"));
        }

        let source_string = path_string(&source, "Nouveau source")?;
        let output_string = path_string(&output, "Nouveau object output")?;
        let member_basename = ninja_member
            .rsplit('/')
            .next()
            .expect("validated Ninja member has a final component")
            .to_owned();
        let include_strings = include_paths
            .iter()
            .map(|path| path_string(path, "Nouveau include path"))
            .collect::<Result<Vec<_>>>()?;
        let raw_argv = raw_argv
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| fail("Nouveau compile record has an invalid argv"))
            })
            .collect::<Result<Vec<_>>>()?;

        ordered_objects.push(output);
        ordered_object_strings.push(output_string.clone());
        member_basenames.push(member_basename.clone());
        commands.push(json!({
            "source": source_string,
            "object": output_string,
            "member_basename": member_basename,
            "raw_argv": raw_argv,
            "argv": argv,
            "include_paths": include_strings,
        }));
    }

    let ninja_set: HashSet<&str> = members.iter().map(String::as_str).collect();
    let record_set: HashSet<String> = by_object
        .keys()
        .filter_map(|object_key| object_key.strip_prefix("build/pc-x86_64/"))
        .map(str::to_owned)
        .collect();
    let expected_set: HashSet<String> = ninja_set
        .iter()
        .map(|member| (*member).to_owned())
        .collect();
    if record_set.len() != EXPECTED_OBJECTS || record_set != expected_set {
        return Err(fail(
            "Ninja archive object set differs from the 825 parsed compile records",
        ));
    }
    if ordered_objects.len() != EXPECTED_OBJECTS
        || ordered_objects.iter().collect::<HashSet<_>>().len() != EXPECTED_OBJECTS
    {
        return Err(fail(
            "mapped Nouveau object outputs are not 825 unique paths",
        ));
    }

    let mut required_directories = BTreeSet::new();
    required_directories.insert(source_root.clone());
    required_directories.insert(build_root.clone());
    required_directories.insert(toolchain_root.clone());
    for command in &commands {
        for include_path in command["include_paths"]
            .as_array()
            .expect("planner emits an include path array")
        {
            let include_path = include_path
                .as_str()
                .expect("planner emits include path strings");
            required_directories.insert(PathBuf::from(include_path));
        }
    }
    for directory in &required_directories {
        require_input_directory(directory)?;
    }
    for command in &commands {
        let source = Path::new(
            command["source"]
                .as_str()
                .expect("planner emits source strings"),
        );
        require_source_file(source)?;
    }

    let compiler_string = path_string(&compiler, "pinned clang-11 compiler")?;
    let toolchain_root_string = path_string(&toolchain_root, "toolchain root")?;
    let source_root_string = path_string(&source_root, "source root")?;
    let build_root_string = path_string(&build_root, "build root")?;
    let archive_output = path_string(&build_root.join(ARCHIVE_OUTPUT), "Nouveau archive output")?;

    Ok(json!({
        "schema": SCHEMA,
        "status": "PLANNED",
        "compiler": compiler_string,
        "toolchain_root": toolchain_root_string,
        "source_root": source_root_string,
        "build_root": build_root_string,
        "working_directory": build_root_string,
        "object_count": EXPECTED_OBJECTS,
        "archive_output": archive_output,
        "ordered_object_paths": ordered_object_strings,
        "member_basenames": member_basenames,
        "commands": commands,
    }))
}

#[cfg(test)]
mod tests {
    use super::{ARCHIVE_OUTPUT, ARCHIVE_RULE, EXPECTED_OBJECTS, plan_nouveau};
    use serde_json::{Value, json};
    use std::{
        collections::HashSet,
        ffi::OsString,
        fs,
        os::unix::{ffi::OsStringExt, fs::symlink},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    const MEMBER_PREFIX: &str =
        "CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/testsrc/";
    const SOURCE_PREFIX: &str = "workbench/hidds/nouveau/testsrc/";
    const FROZEN_PREFIX: &str = concat!(
        "$",
        "{CROSS_TOOLCHAIN_ROOT}/v0.1.4/macos-aarch64/pc-x86_64/"
    );
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::current_dir().expect("current directory"))
                .expect("canonicalize current directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    ".csdk-nouveau-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create unique test directory: {error}"),
                }
            }
            panic!("could not allocate a unique test directory");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    struct Fixture {
        temporary: TempDir,
        source_root: PathBuf,
        build_root: PathBuf,
        toolchain_root: PathBuf,
        source_directory: PathBuf,
        include_directory: PathBuf,
        sdk_include: PathBuf,
        sysroot: PathBuf,
        records: Vec<Value>,
        ninja_text: String,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = TempDir::new();
            let root = temporary.path();
            let source_root = root.join("source");
            let build_root = root.join("build/pc-x86_64");
            let toolchain_root = root.join("toolchain");
            let source_directory = source_root.join("workbench/hidds/nouveau/testsrc");
            let include_directory = source_root.join("workbench/hidds/nouveau/include");
            let sdk_include = build_root.join("SDK/include");
            let sysroot = build_root.join("SYS/Developer");
            for directory in [
                &source_directory,
                &include_directory,
                &sdk_include,
                &sysroot,
                &toolchain_root,
            ] {
                fs::create_dir_all(directory).expect("create fixture directory");
            }

            let compiler = FROZEN_PREFIX.to_owned() + &"9".repeat(64) + "/toolchain/bin/clang";
            let records = (0..EXPECTED_OBJECTS)
                .map(|index| {
                    let source = format!("{SOURCE_PREFIX}file{index:04}.c");
                    let member = object_member(index);
                    fs::write(
                        source_directory.join(format!("file{index:04}.c")),
                        b"int x;\n",
                    )
                    .expect("write synthetic source");
                    json!({
                        "source": source,
                        "object": format!("build/pc-x86_64/{member}"),
                        "argv": [
                            compiler,
                            "--target=x86_64-unknown-aros",
                            "-DTEST_DEFINE=1",
                            "-IAROS-NX/build/pc-x86_64/SDK/include",
                            "-iquoteAROS-NX/workbench/hidds/nouveau/include",
                            "--sysroot=AROS-NX/build/pc-x86_64/SYS/Developer",
                            "-O2",
                            "-o",
                            member,
                            "-c",
                            format!("AROS-NX/{source}"),
                        ],
                    })
                })
                .collect::<Vec<_>>();
            let ninja_text = ninja_text(&(0..EXPECTED_OBJECTS).collect::<Vec<_>>());
            Self {
                temporary,
                source_root,
                build_root,
                toolchain_root,
                source_directory,
                include_directory,
                sdk_include,
                sysroot,
                records,
                ninja_text,
            }
        }

        fn plan(&self, records: &[Value], ninja_text: &str) -> crate::Result<Value> {
            plan_nouveau(
                records,
                ninja_text,
                &self.source_root,
                &self.build_root,
                &self.toolchain_root,
            )
        }

        fn default_plan(&self) -> crate::Result<Value> {
            self.plan(&self.records, &self.ninja_text)
        }
    }

    fn object_name(index: usize) -> String {
        format!("file{index:04}.c.obj")
    }

    fn object_member(index: usize) -> String {
        MEMBER_PREFIX.to_owned() + &object_name(index)
    }

    fn ninja_text(order: &[usize]) -> String {
        let members = order
            .iter()
            .map(|index| object_member(*index))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "build {ARCHIVE_OUTPUT}: {ARCHIVE_RULE} {members} || aros-genmodule-public-includes\n"
        )
    }

    fn assert_error_contains<T: std::fmt::Debug>(result: crate::Result<T>, expected: &str) {
        let error = result.expect_err("operation should be refused");
        assert!(
            error.to_string().contains(expected),
            "expected error containing {expected:?}, got {error}"
        );
    }

    #[test]
    fn maps_paths_preserves_raw_argv_and_emits_expected_plan_fields() {
        let fixture = Fixture::new();
        let plan = fixture.default_plan().expect("plan fixture");
        let command = &plan["commands"][0];
        let raw = command["raw_argv"].as_array().expect("raw argv");
        let argv = command["argv"].as_array().expect("mapped argv");

        assert_eq!(plan["schema"], "ami-rust-nouveau-compile-plan-v1");
        assert_eq!(plan["status"], "PLANNED");
        assert_eq!(plan["object_count"], EXPECTED_OBJECTS);
        assert_eq!(
            argv[0],
            fixture
                .toolchain_root
                .join("bin/clang-11")
                .to_str()
                .unwrap()
        );
        assert_eq!(argv[1], raw[1]);
        assert_eq!(argv[2], raw[2]);
        assert_eq!(argv[3], format!("-I{}", fixture.sdk_include.display()));
        assert_eq!(
            argv[4],
            format!("-iquote{}", fixture.include_directory.display())
        );
        assert_eq!(argv[5], format!("--sysroot={}", fixture.sysroot.display()));
        assert_eq!(argv[6], "-O2");
        assert_eq!(argv[7], "-o");
        assert_eq!(argv[8], command["object"]);
        assert_eq!(argv[9], "-c");
        assert_eq!(argv[10], command["source"]);
        assert_eq!(
            argv[11],
            format!("-ffile-prefix-map={}=.", fixture.source_root.display()),
        );
        assert_eq!(
            raw[0],
            FROZEN_PREFIX.to_owned() + &"9".repeat(64) + "/toolchain/bin/clang"
        );
        assert_eq!(
            plan["ordered_object_paths"].as_array().unwrap().len(),
            EXPECTED_OBJECTS
        );
        assert_eq!(
            plan["member_basenames"].as_array().unwrap()[0],
            object_name(0)
        );
    }

    #[test]
    fn ninja_order_is_independent_of_database_record_order() {
        let fixture = Fixture::new();
        let order = [1, 0]
            .into_iter()
            .chain(2..EXPECTED_OBJECTS)
            .collect::<Vec<_>>();
        let mut records = fixture.records.clone();
        records.reverse();
        let plan = fixture
            .plan(&records, &ninja_text(&order))
            .expect("plan reversed database");
        assert_eq!(plan["member_basenames"][0], object_name(1));
        assert_eq!(
            plan["ordered_object_paths"][0],
            fixture.build_root.join(object_member(1)).to_str().unwrap()
        );
        assert_eq!(
            plan["commands"][0]["object"],
            plan["ordered_object_paths"][0]
        );
        assert_eq!(
            plan["ordered_object_paths"]
                .as_array()
                .unwrap()
                .iter()
                .collect::<HashSet<_>>()
                .len(),
            EXPECTED_OBJECTS
        );
    }

    #[test]
    fn maps_separate_and_joined_include_sysroot_forms_in_order() {
        let fixture = Fixture::new();
        let mut records = fixture.records.clone();
        records[0]["argv"] = json!([
            FROZEN_PREFIX.to_owned() + &"9".repeat(64) + "/toolchain/bin/clang",
            "-I",
            "AROS-NX/build/pc-x86_64/SDK/include",
            "-IAROS-NX/workbench/hidds/nouveau/include",
            "-iquote",
            "AROS-NX/workbench/hidds/nouveau/include",
            "-iquoteAROS-NX/build/pc-x86_64/SYS/Developer",
            "--sysroot",
            "AROS-NX/build/pc-x86_64/SYS/Developer",
            "--sysroot=AROS-NX/build/pc-x86_64/SDK/include",
            "-O2",
            "-o",
            object_member(0),
            "-c",
            "AROS-NX/workbench/hidds/nouveau/testsrc/file0000.c",
        ]);
        let plan = fixture
            .plan(&records, &fixture.ninja_text)
            .expect("map all supported path forms");
        let argv = plan["commands"][0]["argv"].as_array().expect("mapped argv");
        assert_eq!(argv[1], "-I");
        assert_eq!(argv[2], fixture.sdk_include.to_str().unwrap());
        assert_eq!(
            argv[3],
            format!("-I{}", fixture.include_directory.display())
        );
        assert_eq!(argv[4], "-iquote");
        assert_eq!(argv[5], fixture.include_directory.to_str().unwrap());
        assert_eq!(argv[6], format!("-iquote{}", fixture.sysroot.display()));
        assert_eq!(argv[7], "--sysroot");
        assert_eq!(argv[8], fixture.sysroot.to_str().unwrap());
        assert_eq!(
            argv[9],
            format!("--sysroot={}", fixture.sdk_include.display())
        );
        assert_eq!(argv[10], "-O2");
        assert_eq!(
            plan["commands"][0]["include_paths"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
    }

    #[test]
    fn refuses_wrong_record_count_and_duplicate_source_or_object() {
        let fixture = Fixture::new();
        assert_error_contains(
            fixture.plan(
                &fixture.records[..EXPECTED_OBJECTS - 1],
                &fixture.ninja_text,
            ),
            "exactly 825",
        );

        let mut duplicate_object = fixture.records.clone();
        duplicate_object[1]["object"] = duplicate_object[0]["object"].clone();
        assert_error_contains(
            fixture.plan(&duplicate_object, &fixture.ninja_text),
            "duplicate Nouveau compile object",
        );

        let mut duplicate_source = fixture.records.clone();
        duplicate_source[1]["source"] = duplicate_source[0]["source"].clone();
        assert_error_contains(
            fixture.plan(&duplicate_source, &fixture.ninja_text),
            "duplicate Nouveau compile source",
        );
    }

    #[test]
    fn refuses_missing_archive_wrong_rule_duplicate_or_non_nouveau_members() {
        let fixture = Fixture::new();
        assert_error_contains(
            fixture.plan(&fixture.records, "build other: phony\n"),
            "one unambiguous",
        );

        let wrong_rule = fixture
            .ninja_text
            .replacen(ARCHIVE_RULE, "unexpected_archive_rule", 1);
        assert_error_contains(
            fixture.plan(&fixture.records, &wrong_rule),
            "unexpected rule",
        );

        let duplicate_member = fixture
            .ninja_text
            .replacen(&object_member(1), &object_member(0), 1);
        assert_error_contains(
            fixture.plan(&fixture.records, &duplicate_member),
            "825 unique object members",
        );

        let non_nouveau =
            fixture
                .ninja_text
                .replacen(&object_member(0), "CMakeFiles/other/file0000.c.obj", 1);
        assert_error_contains(
            fixture.plan(&fixture.records, &non_nouveau),
            "non-Nouveau object member",
        );

        let mut missing_record = fixture.records.clone();
        missing_record[0]["object"] =
            format!("build/pc-x86_64/{}", object_member(EXPECTED_OBJECTS)).into();
        assert_error_contains(
            fixture.plan(&missing_record, &fixture.ninja_text),
            "absent from the compile database",
        );
    }

    #[test]
    fn rejects_non_normalized_record_archive_and_flag_paths() {
        let fixture = Fixture::new();
        for (invalid, expected) in [
            ("build/pc-x86_64/../../outside.c.obj", "normalized"),
            ("build/pc-x86_64/CMakeFiles//empty.c.obj", "normalized"),
            ("build/pc-x86_64/CMakeFiles/./empty.c.obj", "normalized"),
            ("build/pc-x86_64/CMakeFiles\\empty.c.obj", "portable"),
            ("build/pc-x86_64/CMakeFiles:empty.c.obj", "portable"),
        ] {
            let mut records = fixture.records.clone();
            records[0]["object"] = json!(invalid);
            assert_error_contains(fixture.plan(&records, &fixture.ninja_text), expected);
        }

        let mut records = fixture.records.clone();
        records[0]["argv"][3] = json!("-IAROS-NX/build/pc-x86_64/SDK/../include");
        assert_error_contains(fixture.plan(&records, &fixture.ninja_text), "normalized");

        let traversal_member = fixture.ninja_text.replacen(
            &object_member(0),
            "CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/../bad.c.obj",
            1,
        );
        assert_error_contains(
            fixture.plan(&fixture.records, &traversal_member),
            "normalized",
        );
    }

    #[test]
    fn requires_exact_object_and_source_argv_mappings() {
        let fixture = Fixture::new();
        let mut wrong_output = fixture.records.clone();
        wrong_output[0]["argv"][8] = json!("CMakeFiles/other.c.obj");
        assert_error_contains(
            fixture.plan(&wrong_output, &fixture.ninja_text),
            "differs from the compilation database object",
        );

        let mut wrong_source = fixture.records.clone();
        wrong_source[0]["argv"][10] = json!("AROS-NX/workbench/hidds/nouveau/testsrc/file0001.c");
        assert_error_contains(
            fixture.plan(&wrong_source, &fixture.ninja_text),
            "differs from the compilation database source",
        );
    }

    #[test]
    fn rejects_bad_frozen_compiler_and_unknown_absolute_historical_or_placeholder_flags() {
        let fixture = Fixture::new();
        let mut bad_compiler = fixture.records.clone();
        bad_compiler[0]["argv"][0] =
            json!(FROZEN_PREFIX.to_owned() + &"A".repeat(64) + "/toolchain/bin/clang");
        assert_error_contains(
            fixture.plan(&bad_compiler, &fixture.ninja_text),
            "unknown compiler placeholder",
        );

        for argument in [
            "-include=/historical/build/header.h",
            "-DROOT=$CROSS_TOOLCHAIN_ROOT",
            "-Wl,/tmp/historical.o",
            "C:\\AROS-NX\\old\\header.h",
        ] {
            let mut records = fixture.records.clone();
            records[0]["argv"]
                .as_array_mut()
                .unwrap()
                .insert(2, json!(argument));
            assert_error_contains(
                fixture.plan(&records, &fixture.ninja_text),
                "unmapped path or placeholder",
            );
        }

        let mut historical_prefix = fixture.records.clone();
        historical_prefix[0]["argv"][3] = json!("-Iunmapped-tree/include");
        assert_error_contains(
            fixture.plan(&historical_prefix, &fixture.ninja_text),
            "outside the declared source/build prefixes",
        );
    }

    #[test]
    fn refuses_missing_source_or_include_inputs_without_creating_them() {
        let fixture = Fixture::new();
        fs::remove_file(fixture.source_directory.join("file0000.c"))
            .expect("remove synthetic source");
        assert_error_contains(fixture.default_plan(), "Nouveau source file is missing");
        assert!(!fixture.source_directory.join("file0000.c").exists());

        let fixture = Fixture::new();
        fs::remove_dir_all(&fixture.sdk_include).expect("remove SDK include fixture");
        assert_error_contains(
            fixture.default_plan(),
            "Nouveau include or sysroot directory is missing",
        );
        assert!(!fixture.sdk_include.exists());
    }

    #[test]
    fn refuses_source_symlink_and_symlinked_or_dangling_root_ancestors() {
        let fixture = Fixture::new();
        let source = fixture.source_directory.join("file0000.c");
        let external = fixture.temporary.path().join("external.c");
        fs::write(&external, b"int external;\n").expect("write external source");
        fs::remove_file(&source).expect("remove source");
        symlink(&external, &source).expect("replace source with symlink");
        assert_error_contains(fixture.default_plan(), "symlink");

        let fixture = Fixture::new();
        let actual_source_root = fixture.temporary.path().join("actual-source");
        fs::rename(&fixture.source_root, &actual_source_root).expect("move source root");
        symlink(&actual_source_root, &fixture.source_root).expect("symlink source root");
        assert_error_contains(fixture.default_plan(), "source root");

        let fixture = Fixture::new();
        let alias = fixture.temporary.path().join("source-alias");
        symlink(fixture.temporary.path(), &alias).expect("create source ancestor symlink");
        let aliased_source_root = alias.join("source");
        assert_error_contains(
            plan_nouveau(
                &fixture.records,
                &fixture.ninja_text,
                &aliased_source_root,
                &fixture.build_root,
                &fixture.toolchain_root,
            ),
            "source root",
        );

        let fixture = Fixture::new();
        let dangling = fixture.temporary.path().join("dangling");
        symlink(fixture.temporary.path().join("does-not-exist"), &dangling)
            .expect("create dangling symlink");
        assert_error_contains(
            plan_nouveau(
                &fixture.records,
                &fixture.ninja_text,
                &dangling.join("source"),
                &fixture.build_root,
                &fixture.toolchain_root,
            ),
            "source root",
        );
    }

    #[test]
    fn refuses_symlinked_include_directory_and_roots_that_overlap() {
        let fixture = Fixture::new();
        let external = fixture.temporary.path().join("external-include");
        fs::create_dir(&external).expect("create external include");
        fs::remove_dir(&fixture.sdk_include).expect("remove SDK include directory");
        symlink(&external, &fixture.sdk_include).expect("symlink SDK include directory");
        assert_error_contains(fixture.default_plan(), "symlink");

        let fixture = Fixture::new();
        assert_error_contains(
            plan_nouveau(
                &fixture.records,
                &fixture.ninja_text,
                &fixture.source_root,
                &fixture.source_root,
                &fixture.toolchain_root,
            ),
            "source/build paths overlap",
        );

        let fixture = Fixture::new();
        let nested_toolchain = fixture.build_root.join("nested-toolchain");
        fs::create_dir(&nested_toolchain).expect("create nested toolchain");
        assert_error_contains(
            plan_nouveau(
                &fixture.records,
                &fixture.ninja_text,
                &fixture.source_root,
                &fixture.build_root,
                &nested_toolchain,
            ),
            "build/toolchain paths overlap",
        );
    }

    #[test]
    fn refuses_roots_that_cannot_be_serialized_as_utf8_json() {
        let fixture = Fixture::new();
        let non_utf8 = fixture
            .temporary
            .path()
            .join(OsString::from_vec(b"source-\xff".to_vec()));
        assert_error_contains(
            plan_nouveau(
                &fixture.records,
                &fixture.ninja_text,
                &non_utf8,
                &fixture.build_root,
                &fixture.toolchain_root,
            ),
            "cannot be represented as a UTF-8 JSON string",
        );
    }

    #[test]
    fn refuses_an_archive_edge_with_an_incomplete_object_set() {
        let fixture = Fixture::new();
        let shortened = ninja_text(&(0..EXPECTED_OBJECTS - 1).collect::<Vec<_>>());
        assert_error_contains(
            fixture.plan(&fixture.records, &shortened),
            "825 unique object members",
        );
    }
    #[test]
    fn refuses_ninja_over_inherited_cli_recipe_bound() {
        let fixture = Fixture::new();
        let oversized = "x".repeat(super::MAX_RECIPE_BYTES + 1);
        assert_error_contains(fixture.plan(&fixture.records, &oversized), "byte limit");
    }

    #[test]
    fn planning_accepts_search_only_input_directories() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let directories = [
            &fixture.source_root,
            &fixture.source_directory,
            &fixture.include_directory,
            &fixture.toolchain_root,
        ];
        for directory in directories {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o111))
                .expect("remove directory read permission");
        }

        let result = fixture.default_plan();

        for directory in directories {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                .expect("restore directory permissions");
        }
        assert!(result.is_ok(), "search-only directories should be accepted");
    }

    #[test]
    fn planning_only_stats_regular_source_without_requiring_content_read_permission() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        let path = fixture.source_directory.join("file0000.c");
        fs::set_permissions(path, fs::Permissions::from_mode(0o0))
            .expect("remove content permissions");
        assert!(fixture.default_plan().is_ok());
    }
}
