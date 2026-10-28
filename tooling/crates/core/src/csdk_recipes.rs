//! Non-executing parsers for the frozen portable C-SDK build recipes.
//!
//! These functions inspect Ninja and compilation-database text as data. They
//! never invoke a shell, compiler, generator, or build tool. Filesystem reads
//! and their byte limits belong to the caller.

use std::collections::HashSet;

use serde_json::{Value, json};

use crate::{Refusal, Result, json::JsonProfile};

const SOURCE_PREFIX: &str = "AROS-NX/";
const BUILD_PREFIX: &str = "AROS-NX/build/pc-x86_64/";
const BUILD_ROOT: &str = "AROS-NX/build/pc-x86_64";
const GENMODULE: &str = "AROS-NX/build/pc-x86_64/hosttools/genmodule";
const NOUVEAU_SOURCE_PREFIX: &str = "AROS-NX/workbench/hidds/nouveau/";
const NOUVEAU_OBJECT_PREFIX: &str =
    "AROS-NX/build/pc-x86_64/CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/";
const REPO_BUILD_ROOT: &str = "build/pc-x86_64";
const NINJA_MAX_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct NinjaEdge {
    line: usize,
    pub(crate) outputs: Vec<String>,
    pub(crate) dependencies: Vec<String>,
    command: Option<String>,
}

#[derive(Debug)]
struct PublicGenerator {
    config: String,
    output_directory: String,
    output_override: Option<Value>,
    module_suffix: Option<String>,
    module: String,
    module_type: String,
}

/// Parse all five-output classic `genmodule writeincludes` recipes.
///
/// Output paths are relative to `SDK/include`, while `config` is relative to
/// the AROS-NX source root. The command is parsed as data and never executed.
pub fn public_header_recipes(ninja_text: &str) -> Result<Vec<Value>> {
    check_ninja_size(ninja_text)?;
    let mut records = Vec::new();
    let mut all_outputs = HashSet::new();
    for edge in ninja_edges(ninja_text)? {
        let sdk_outputs: Vec<String> = edge
            .outputs
            .iter()
            .filter(|item| item.starts_with("SDK/include/"))
            .cloned()
            .collect();
        if sdk_outputs.is_empty() {
            continue;
        }
        let command = edge.command.as_deref().unwrap_or("");
        let has_generator_marker = command.contains("writeincludes") || command.contains(GENMODULE);
        if !looks_like_public_header_outputs(&edge.outputs) {
            if has_generator_marker {
                return Err(Refusal::new(
                    "genmodule SDK/include edge does not declare five public headers",
                ));
            }
            continue;
        }

        let record = parse_public_edge(&edge, &sdk_outputs)?;
        let output_values = record
            .get("outputs")
            .and_then(Value::as_array)
            .expect("parser always emits an outputs array");
        for output in output_values {
            let output = output
                .as_str()
                .expect("parser always emits string output paths")
                .to_owned();
            if !all_outputs.insert(output.clone()) {
                return Err(Refusal::new(format!(
                    "duplicate public SDK header output: {output}"
                )));
            }
        }
        records.push(record);
    }
    Ok(records)
}

/// Parse the classic C `tools/genmodule` host-tool build recipe.
pub fn classic_generator_recipe(ninja_text: &str) -> Result<Value> {
    check_ninja_size(ninja_text)?;
    let edges = ninja_edges(ninja_text)?;
    let matches: Vec<&NinjaEdge> = edges
        .iter()
        .filter(|edge| {
            edge.outputs
                .iter()
                .any(|output| output == "hosttools/genmodule")
        })
        .collect();
    if matches.len() != 1 {
        return Err(Refusal::new(
            "Ninja file must declare exactly one hosttools/genmodule build edge",
        ));
    }
    let edge = matches[0];
    let command = edge
        .command
        .as_deref()
        .ok_or_else(|| Refusal::new("classic genmodule build edge has no COMMAND"))?;
    let chain = ninja_chain(command)?;
    if chain.len() != 2 || chain[0].len() != 2 || chain[0][0] != "cd" || chain[0][1] != BUILD_ROOT {
        return Err(Refusal::new(
            "classic genmodule command has unexpected shell structure",
        ));
    }
    let argv = &chain[1];
    if argv.first().map(String::as_str) != Some("cc") {
        return Err(Refusal::new("classic genmodule compiler must be cc"));
    }

    let source_args: Vec<String> = argv
        .iter()
        .filter(|item| item.starts_with("AROS-NX/tools/genmodule/") && item.ends_with(".c"))
        .cloned()
        .collect();
    if has_duplicates(&source_args) {
        return Err(Refusal::new(
            "classic genmodule command has duplicate C source inputs",
        ));
    }
    let sources: Vec<String> = source_args
        .iter()
        .map(|item| source_relative(item, "classic genmodule source"))
        .collect::<Result<_>>()?;
    if sources.is_empty()
        || sources
            .iter()
            .any(|item| !item.starts_with("tools/genmodule/") || !item.ends_with(".c"))
    {
        return Err(Refusal::new(
            "classic genmodule command has unexpected source inputs",
        ));
    }

    let dependency_sources: Vec<String> = edge
        .dependencies
        .iter()
        .filter(|item| item.starts_with("AROS-NX/tools/genmodule/") && item.ends_with(".c"))
        .cloned()
        .collect();
    if dependency_sources != source_args {
        return Err(Refusal::new(
            "classic genmodule command sources differ from Ninja build inputs",
        ));
    }
    if has_duplicates(&dependency_sources) {
        return Err(Refusal::new(
            "classic genmodule Ninja edge has duplicate C source inputs",
        ));
    }

    let output_index = argv
        .iter()
        .position(|item| item == "-o")
        .ok_or_else(|| Refusal::new("classic genmodule command is missing -o"))?;
    if argv.len() < 2
        || output_index != argv.len() - 2
        || argv.iter().filter(|item| item.as_str() == "-o").count() != 1
    {
        return Err(Refusal::new(
            "classic genmodule command has unexpected arguments after -o",
        ));
    }
    let output = build_relative(&argv[output_index + 1], "classic genmodule output")?;
    if output != "build/pc-x86_64/hosttools/genmodule" {
        return Err(Refusal::new(
            "classic genmodule output differs from declared host tool",
        ));
    }

    let first_source = argv
        .iter()
        .position(|item| item == &source_args[0])
        .expect("source_args came from argv");
    let source_end = first_source + source_args.len();
    if argv.get(first_source..source_end) != Some(source_args.as_slice())
        || output_index != source_end
    {
        return Err(Refusal::new(
            "classic genmodule sources or flags are ambiguously ordered",
        ));
    }
    let flags = &argv[1..first_source];
    if flags.len() != 3
        || flags[0] != "-O2"
        || flags[1] != "-w"
        || flags[2] != "-IAROS-NX/tools/genmodule"
    {
        return Err(Refusal::new(
            "classic genmodule flags differ from the frozen host-tool recipe",
        ));
    }

    Ok(json!({
        "compiler": argv[0],
        "flags": flags,
        "sources": sources,
        "argv": argv,
        "cwd": REPO_BUILD_ROOT,
        "original_cwd": BUILD_ROOT,
        "output": output,
        "line": edge.line,
    }))
}

/// Parse direct tracked C compile records for `hidd-nouveau-drm`.
///
/// The caller selects the frozen JSON profile that bounds this input. Every
/// compiler argument is returned in order after POSIX-style tokenization.
pub fn nouveau_compile_recipes(
    compilation_db_text: &str,
    profile: JsonProfile,
) -> Result<Vec<Value>> {
    let database = crate::json::parse_json_value(compilation_db_text.as_bytes(), profile)
        .map_err(compilation_database_error)?;
    let entries = database
        .as_array()
        .ok_or_else(|| Refusal::new("compilation database root must be an array"))?;

    let mut records = Vec::new();
    let mut seen_sources = HashSet::new();
    let mut seen_objects = HashSet::new();
    for item in entries {
        let item = item
            .as_object()
            .ok_or_else(|| Refusal::new("compilation database entry must be an object"))?;
        let file_value = item.get("file").and_then(Value::as_str);
        let output_value = item.get("output").and_then(Value::as_str);
        let source_candidate =
            file_value.is_some_and(|value| value.starts_with(NOUVEAU_SOURCE_PREFIX));
        let output_candidate =
            output_value.is_some_and(|value| value.starts_with(NOUVEAU_OBJECT_PREFIX));
        if !output_candidate {
            continue;
        }
        if !source_candidate || !output_candidate {
            return Err(Refusal::new(
                "Nouveau DRM record is not a direct source/object pair",
            ));
        }
        let file_value = file_value.expect("source_candidate was true");
        let output_value = output_value.expect("output_candidate was true");
        if file_value.ends_with('/') || !file_value.ends_with(".c") {
            return Err(Refusal::new("Nouveau DRM source is not a C file"));
        }
        let source = source_relative(file_value, "Nouveau DRM source")?;
        if !source.starts_with("workbench/hidds/nouveau/") {
            return Err(Refusal::new(
                "Nouveau DRM source is outside its tracked source subtree",
            ));
        }
        if item.get("directory").and_then(Value::as_str) != Some(BUILD_ROOT) {
            return Err(Refusal::new(
                "Nouveau DRM compilation directory is unexpected",
            ));
        }
        let object_path = build_relative(output_value, "Nouveau DRM object output")?;
        let command = item
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("Nouveau DRM compile command is missing"))?;
        let argv = literal_argv(command, "Nouveau DRM compile command")?;
        if posix_path_name(&argv[0]) != "clang" {
            return Err(Refusal::new("Nouveau DRM command does not invoke clang"));
        }
        if argv.iter().filter(|item| item.as_str() == "-o").count() != 1
            || argv.iter().filter(|item| item.as_str() == "-c").count() != 1
        {
            return Err(Refusal::new(
                "Nouveau DRM command must have one -o and one -c",
            ));
        }
        let output_index = argv
            .iter()
            .position(|item| item == "-o")
            .expect("exactly one -o was checked");
        let source_index = argv
            .iter()
            .position(|item| item == "-c")
            .expect("exactly one -c was checked");
        if output_index + 1 >= argv.len() || source_index + 1 >= argv.len() {
            return Err(Refusal::new(
                "Nouveau DRM command has an incomplete -o or -c option",
            ));
        }
        let working_object =
            build_working_relative(&argv[output_index + 1], "Nouveau DRM object argument")?;
        let command_object = build_relative(
            &format!("{BUILD_PREFIX}{working_object}"),
            "Nouveau DRM object argument",
        )?;
        if command_object != object_path {
            return Err(Refusal::new(
                "Nouveau DRM command object differs from compilation database output",
            ));
        }
        if argv[source_index + 1] != file_value {
            return Err(Refusal::new(
                "Nouveau DRM command source differs from compilation database file",
            ));
        }
        if seen_sources.contains(&source) {
            return Err(Refusal::new(format!(
                "duplicate Nouveau DRM source record: {source}"
            )));
        }
        if seen_objects.contains(&object_path) {
            return Err(Refusal::new(format!(
                "duplicate Nouveau DRM object record: {object_path}"
            )));
        }
        seen_sources.insert(source.clone());
        seen_objects.insert(object_path.clone());
        records.push(json!({
            "source": source,
            "directory": REPO_BUILD_ROOT,
            "object": object_path,
            "argv": argv,
        }));
    }
    records.sort_by(|left, right| {
        left.get("source")
            .and_then(Value::as_str)
            .cmp(&right.get("source").and_then(Value::as_str))
    });
    Ok(records)
}

fn compilation_database_error(error: Refusal) -> Refusal {
    let detail = error.to_string();
    if let Some(rest) = detail
        .split_once("duplicate JSON object key ")
        .map(|(_, rest)| rest)
    {
        let quoted_key = rest.split(" at line ").next().unwrap_or(rest).trim();
        let key = quoted_key
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(quoted_key);
        return Refusal::new(format!("duplicate JSON key: {key}"));
    }
    if detail.contains("byte limit") {
        return Refusal::new(detail);
    }
    Refusal::new("compilation database is malformed JSON")
}

pub(crate) fn ninja_edges(ninja_text: &str) -> Result<Vec<NinjaEdge>> {
    let lines = split_recipe_lines(ninja_text);
    let mut edges = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !line.starts_with("build ") {
            continue;
        }
        let (declaration, dependency_text) = line.split_once(':').ok_or_else(|| {
            Refusal::new(format!("malformed Ninja build edge at line {}", index + 1))
        })?;
        let outputs = split_recipe_whitespace(&declaration["build ".len()..]);
        if outputs.is_empty() {
            return Err(Refusal::new(format!(
                "Ninja build edge has no outputs at line {}",
                index + 1
            )));
        }
        let dependencies = split_recipe_whitespace(dependency_text);
        let mut command: Option<String> = None;
        let mut cursor = index + 1;
        while cursor < lines.len() && !trim_recipe_whitespace(&lines[cursor]).is_empty() {
            let stripped = trim_recipe_whitespace(&lines[cursor]);
            if let Some(value) = stripped.strip_prefix("COMMAND = ") {
                if command.is_some() {
                    return Err(Refusal::new("Ninja edge has multiple COMMAND assignments"));
                }
                command = Some(value.to_owned());
            }
            if lines[cursor].starts_with("build ") {
                break;
            }
            cursor += 1;
        }
        edges.push(NinjaEdge {
            line: index + 1,
            outputs,
            dependencies,
            command,
        });
    }
    Ok(edges)
}

fn check_ninja_size(ninja_text: &str) -> Result<()> {
    if ninja_text.len() > NINJA_MAX_BYTES {
        return Err(Refusal::new(format!(
            "Ninja input exceeds the {NINJA_MAX_BYTES} byte limit"
        )));
    }
    Ok(())
}

fn looks_like_public_header_outputs(outputs: &[String]) -> bool {
    let sdk_outputs: Vec<&str> = outputs
        .iter()
        .filter_map(|item| item.strip_prefix("SDK/include/"))
        .collect();
    let categories: HashSet<&str> = sdk_outputs
        .iter()
        .map(|item| item.split_once('/').map_or(*item, |(category, _)| category))
        .collect();
    sdk_outputs.len() == 5
        || ["clib", "inline", "defines", "proto"]
            .into_iter()
            .all(|category| categories.contains(category))
}

fn parse_public_edge(edge: &NinjaEdge, sdk_outputs: &[String]) -> Result<Value> {
    let command = edge
        .command
        .as_deref()
        .ok_or_else(|| Refusal::new("public-header edge has no COMMAND"))?;
    if sdk_outputs.len() != 5 || has_duplicates(sdk_outputs) {
        return Err(Refusal::new(
            "public-header edge must declare five unique SDK/include outputs",
        ));
    }
    let outputs: Vec<String> = sdk_outputs
        .iter()
        .map(|item| safe_relative(&item["SDK/include/".len()..], "SDK/include output"))
        .collect::<Result<_>>()?;
    let chain = ninja_chain(command)?;
    if chain
        .first()
        .is_none_or(|argv| argv.len() != 2 || argv[0] != "cd" || argv[1] != BUILD_ROOT)
    {
        return Err(Refusal::new(
            "public-header edge has an unexpected generator working directory",
        ));
    }
    let generator_positions: Vec<usize> = chain
        .iter()
        .enumerate()
        .filter_map(|(position, argv)| {
            argv.first().and_then(|executable| {
                (executable.ends_with("/hosttools/genmodule")
                    || executable.as_str() == "hosttools/genmodule")
                    .then_some(position)
            })
        })
        .collect();
    if generator_positions.len() != 1 {
        return Err(Refusal::new(
            "public-header edge must contain exactly one classic genmodule command",
        ));
    }
    let generator_index = generator_positions[0];

    for argv in &chain[1..generator_index] {
        if argv.len() < 4 || argv[0] != "${CMAKE}" || argv[1] != "-E" || argv[2] != "make_directory"
        {
            return Err(Refusal::new(
                "unexpected command before public-header generator",
            ));
        }
        for path in &argv[3..] {
            build_relative(path, "genmodule directory operand")?;
        }
    }
    for argv in &chain[generator_index + 1..] {
        if argv.len() < 4
            || argv[0] != "${CMAKE}"
            || argv[1] != "-E"
            || (argv[2] != "make_directory" && argv[2] != "copy_if_different")
        {
            return Err(Refusal::new(
                "unexpected command after public-header generator",
            ));
        }
        if argv[2] == "make_directory" {
            for path in &argv[3..] {
                build_relative(path, "genmodule directory operand")?;
            }
        } else {
            if argv.len() != 5 {
                return Err(Refusal::new(
                    "copy_if_different must have one source and one destination",
                ));
            }
            build_relative(&argv[3], "genmodule copy source")?;
            build_relative(&argv[4], "genmodule copy destination")?;
        }
    }

    let generator_argv = &chain[generator_index];
    let parsed = parse_public_generator(generator_argv)?;
    let expected_outputs = expected_header_group(&parsed.module);
    let actual_outputs: HashSet<&str> = outputs.iter().map(String::as_str).collect();
    if actual_outputs.len() != expected_outputs.len()
        || !expected_outputs
            .iter()
            .all(|expected| actual_outputs.contains(expected.as_str()))
    {
        return Err(Refusal::new(
            "SDK/include outputs do not match the generator module",
        ));
    }

    let mut copied_sdk_outputs = Vec::new();
    for argv in &chain[generator_index + 1..] {
        if argv.len() == 5
            && argv[0] == "${CMAKE}"
            && argv[1] == "-E"
            && argv[2] == "copy_if_different"
        {
            let destination = build_relative(&argv[4], "genmodule copy destination")?;
            if let Some(copied_output) = destination.strip_prefix("build/pc-x86_64/SDK/include/") {
                if copied_sdk_outputs.iter().any(|seen| seen == copied_output) {
                    return Err(Refusal::new("duplicate SDK/include copy destination"));
                }
                copied_sdk_outputs.push(copied_output.to_owned());
            }
        }
    }
    let copied_set: HashSet<&str> = copied_sdk_outputs.iter().map(String::as_str).collect();
    if copied_sdk_outputs.len() != 5
        || copied_set.len() != copied_sdk_outputs.len()
        || copied_set.len() != outputs.len()
        || !outputs
            .iter()
            .all(|output| copied_set.contains(output.as_str()))
    {
        return Err(Refusal::new(
            "genmodule command does not copy exactly the five declared SDK headers",
        ));
    }

    Ok(json!({
        "config": parsed.config,
        "output_directory": parsed.output_directory,
        "output_override": parsed.output_override,
        "module_suffix": parsed.module_suffix,
        "module": parsed.module,
        "module_type": parsed.module_type,
        "outputs": outputs,
        "argv": generator_argv,
        "generator_args": &generator_argv[1..],
        "cwd": REPO_BUILD_ROOT,
        "original_cwd": BUILD_ROOT,
        "command": command,
        "line": edge.line,
    }))
}

fn parse_public_generator(argv: &[String]) -> Result<PublicGenerator> {
    if argv.first().map(String::as_str) != Some(GENMODULE) {
        return Err(Refusal::new("unexpected public-header generator command"));
    }
    let mut values = std::collections::HashMap::new();
    let mut index = 1;
    while index < argv.len() && argv[index].starts_with('-') {
        let option = &argv[index];
        if !["-c", "-d", "-o", "-s"].contains(&option.as_str())
            || values.contains_key(option.as_str())
            || index + 1 >= argv.len()
        {
            return Err(Refusal::new(format!(
                "unexpected or incomplete genmodule option: {option}"
            )));
        }
        values.insert(option.as_str(), argv[index + 1].as_str());
        index += 2;
    }
    if argv.get(index).map(String::as_str) != Some("writeincludes") {
        return Err(Refusal::new(
            "public-header generator must use writeincludes",
        ));
    }
    if index + 3 != argv.len() {
        return Err(Refusal::new(
            "public-header generator has missing or extra arguments",
        ));
    }
    if !values.contains_key("-c") || !values.contains_key("-d") {
        return Err(Refusal::new(
            "public-header generator is missing -c config or -d output",
        ));
    }

    let config = source_relative(values["-c"], "genmodule config")?;
    let output_directory = build_relative(values["-d"], "genmodule output directory")?;
    let output_override = values
        .get("-o")
        .map(|value| {
            build_relative(value, "genmodule -o override")
                .map(|path| json!({"kind": "build", "path": path}))
        })
        .transpose()?;
    let module_suffix = values.get("-s").map(|value| (*value).to_owned());
    if module_suffix
        .as_deref()
        .is_some_and(|suffix| !is_simple_token(suffix))
    {
        return Err(Refusal::new("genmodule -s suffix is not a simple token"));
    }

    let module = argv[index + 1].clone();
    if !is_simple_token(&module) {
        return Err(Refusal::new("genmodule module name is not a simple token"));
    }
    let module_type = argv[index + 2].clone();
    if module_type != "library" && module_type != "resource" {
        return Err(Refusal::new(format!(
            "unexpected genmodule module type: {module_type}"
        )));
    }
    Ok(PublicGenerator {
        config,
        output_directory,
        output_override,
        module_suffix,
        module,
        module_type,
    })
}

fn expected_header_group(module: &str) -> HashSet<String> {
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

fn ninja_chain(value: &str) -> Result<Vec<Vec<String>>> {
    if value.is_empty() {
        return Err(Refusal::new("Ninja command is missing"));
    }
    let parts: Vec<&str> = value.split(" && ").collect();
    if parts
        .iter()
        .any(|part| trim_recipe_whitespace(part).is_empty())
    {
        return Err(Refusal::new("Ninja command has an empty shell segment"));
    }
    let mut result = Vec::new();
    for part in parts {
        if part.contains("&&") || part.contains("||") {
            return Err(Refusal::new(
                "Ninja command contains unexpected shell control syntax",
            ));
        }
        result.push(literal_argv(part, "Ninja command segment")?);
    }
    Ok(result)
}

fn literal_argv(value: &str, label: &str) -> Result<Vec<String>> {
    reject_shell_operators(value, label)?;
    let mut result = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = None;
    let mut escaped = false;

    for character in value.chars() {
        if escaped {
            if quote == Some('"') && character != '"' && character != '\\' {
                token.push('\\');
            }
            token.push(character);
            token_started = true;
            escaped = false;
            continue;
        }
        if quote == Some('\'') {
            if character == '\'' {
                quote = None;
            } else {
                token.push(character);
            }
            continue;
        }
        if quote == Some('"') {
            match character {
                '"' => quote = None,
                '\\' => escaped = true,
                _ => token.push(character),
            }
            continue;
        }
        match character {
            ' ' | '\t' => {
                if token_started {
                    result.push(std::mem::take(&mut token));
                    token_started = false;
                }
            }
            '\'' | '"' => {
                quote = Some(character);
                token_started = true;
            }
            '\\' => {
                escaped = true;
                token_started = true;
            }
            _ => {
                token.push(character);
                token_started = true;
            }
        }
    }
    if escaped || quote.is_some() {
        return Err(Refusal::new(format!("{label} has malformed quoting")));
    }
    if token_started {
        result.push(token);
    }
    if result.is_empty() {
        return Err(Refusal::new(format!("{label} is empty")));
    }
    Ok(result)
}

fn reject_shell_operators(value: &str, label: &str) -> Result<()> {
    if ["&&", "||", ";", "|", "<", ">", "`", "$("]
        .iter()
        .any(|marker| value.contains(marker))
    {
        return Err(Refusal::new(format!(
            "{label} contains shell control syntax"
        )));
    }
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(Refusal::new(format!(
            "{label} contains a control character"
        )));
    }
    Ok(())
}

fn safe_relative(value: &str, label: &str) -> Result<String> {
    if value.is_empty() || value.contains('\\') || value.contains('\0') || value.contains(':') {
        return Err(Refusal::new(format!(
            "{label} is not a portable relative path"
        )));
    }
    if value.starts_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Refusal::new(format!(
            "{label} is not a normalized relative path: {value}"
        )));
    }
    Ok(value.to_owned())
}

fn source_relative(value: &str, label: &str) -> Result<String> {
    let suffix = value.strip_prefix(SOURCE_PREFIX).ok_or_else(|| {
        Refusal::new(format!(
            "{label} is outside the declared AROS-NX source prefix"
        ))
    })?;
    safe_relative(suffix, label)
}

fn build_relative(value: &str, label: &str) -> Result<String> {
    if value == BUILD_ROOT {
        return Ok(REPO_BUILD_ROOT.to_owned());
    }
    let suffix = value.strip_prefix(BUILD_PREFIX).ok_or_else(|| {
        Refusal::new(format!(
            "{label} is outside the declared pc-x86_64 build prefix"
        ))
    })?;
    Ok(format!(
        "{REPO_BUILD_ROOT}/{}",
        safe_relative(suffix, label)?
    ))
}

fn build_working_relative(value: &str, label: &str) -> Result<String> {
    safe_relative(value, label)
}

fn is_simple_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-')
        })
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().any(|value| !seen.insert(value))
}

fn is_recipe_whitespace(character: char) -> bool {
    character.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&character)
}

fn trim_recipe_whitespace(value: &str) -> &str {
    value.trim_matches(is_recipe_whitespace)
}

fn split_recipe_whitespace(value: &str) -> Vec<String> {
    value
        .split(is_recipe_whitespace)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_recipe_lines(value: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut characters = value.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if !matches!(
            character,
            '\n' | '\r'
                | '\u{000b}'
                | '\u{000c}'
                | '\u{001c}'
                | '\u{001d}'
                | '\u{001e}'
                | '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            continue;
        }
        lines.push(value[start..index].to_owned());
        if character == '\r'
            && let Some((next_index, '\n')) = characters.peek().copied()
        {
            characters.next();
            start = next_index + '\n'.len_utf8();
            continue;
        }
        start = index + character.len_utf8();
    }
    if start < value.len() {
        lines.push(value[start..].to_owned());
    }
    lines
}

fn posix_path_name(value: &str) -> &str {
    value
        .split('/')
        .rev()
        .find(|component| !component.is_empty())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::{
        BUILD_ROOT, GENMODULE, NOUVEAU_OBJECT_PREFIX, NOUVEAU_SOURCE_PREFIX, REPO_BUILD_ROOT,
        build_relative, classic_generator_recipe, literal_argv, nouveau_compile_recipes,
        public_header_recipes, safe_relative,
    };
    use crate::json::JsonProfile;
    use serde_json::{Value, json};

    fn header_edge(
        module: &str,
        config: &str,
        options: &[&str],
        executable: &str,
        copy_override: Option<&str>,
    ) -> String {
        let output_suffixes = [
            format!("clib/{module}_protos.h"),
            format!("inline/{module}.h"),
            format!("defines/{module}.h"),
            format!("defines/{module}_LVO.h"),
            format!("proto/{module}.h"),
        ];
        let output_dir = format!("{BUILD_ROOT}/genmodule/{module}/include");
        let outputs = output_suffixes
            .iter()
            .map(|suffix| format!("SDK/include/{suffix}"))
            .collect::<Vec<_>>()
            .join(" ");
        let mut generator = vec![executable.to_owned(), "-c".into(), config.into()];
        generator.extend(options.iter().map(|value| (*value).to_owned()));
        generator.extend([
            "-d".into(),
            output_dir.clone(),
            "writeincludes".into(),
            module.into(),
            "library".into(),
        ]);
        let mut command = vec![
            format!("cd {BUILD_ROOT}"),
            format!("${{CMAKE}} -E make_directory {output_dir}"),
            generator.join(" "),
        ];
        for (index, suffix) in output_suffixes.iter().enumerate() {
            let destination = if index == 0 {
                copy_override.unwrap_or(suffix)
            } else {
                suffix
            };
            command.push(format!(
                "${{CMAKE}} -E copy_if_different {output_dir}/{suffix} {BUILD_ROOT}/SDK/include/{destination}"
            ));
        }
        format!(
            "build {outputs}: CUSTOM_COMMAND {config}\n  COMMAND = {}",
            command.join(" && ")
        )
    }

    fn compile_record(source: &str, object: &str, command_source: &str) -> Value {
        let object_argument = object
            .strip_prefix(&format!("{BUILD_ROOT}/"))
            .expect("object is under the build root");
        json!({
            "directory": BUILD_ROOT,
            "file": source,
            "output": object,
            "command": format!(
                "${{CROSS_TOOLCHAIN_ROOT}}/toolchain/bin/clang --target=x86_64-unknown-aros -O3 -o {object_argument} -c {command_source}"
            ),
        })
    }

    fn default_compile_record() -> Value {
        let source = format!("{NOUVEAU_SOURCE_PREFIX}drm/foo.c");
        let object = format!("{NOUVEAU_OBJECT_PREFIX}drm/foo.c");
        compile_record(&source, &object, &source)
    }

    #[test]
    fn parses_public_header_outputs_config_options_and_type() {
        let config = "AROS-NX/config/sample.conf";
        let edge = header_edge(
            "sample",
            config,
            &[
                "-s",
                "fwl",
                "-o",
                "AROS-NX/build/pc-x86_64/Ports/sample.conf",
            ],
            GENMODULE,
            None,
        );
        let records = public_header_recipes(&edge).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["config"], "config/sample.conf");
        assert_eq!(
            record["outputs"],
            json!([
                "clib/sample_protos.h",
                "inline/sample.h",
                "defines/sample.h",
                "defines/sample_LVO.h",
                "proto/sample.h"
            ])
        );
        assert_eq!(record["module"], "sample");
        assert_eq!(record["module_type"], "library");
        assert_eq!(record["module_suffix"], "fwl");
        assert_eq!(
            record["output_override"],
            json!({"kind": "build", "path": "build/pc-x86_64/Ports/sample.conf"})
        );
        assert_eq!(record["argv"][0], GENMODULE);
        assert_eq!(record["cwd"], REPO_BUILD_ROOT);
    }

    #[test]
    fn refuses_missing_config_unexpected_generator_and_shell_syntax() {
        let edge = header_edge("sample", "AROS-NX/config/sample.conf", &[], GENMODULE, None)
            .replace(" -c AROS-NX/config/sample.conf", "");
        assert!(
            public_header_recipes(&edge)
                .unwrap_err()
                .to_string()
                .contains("missing -c config")
        );

        let edge = header_edge(
            "sample",
            "AROS-NX/config/sample.conf",
            &[],
            "AROS-NX/build/pc-x86_64/hosttools/other-generator",
            None,
        );
        assert!(
            public_header_recipes(&edge)
                .unwrap_err()
                .to_string()
                .contains("classic genmodule")
        );

        let edge = format!(
            "{} ; touch /tmp/not-run",
            header_edge("sample", "AROS-NX/config/sample.conf", &[], GENMODULE, None)
        );
        assert!(
            public_header_recipes(&edge)
                .unwrap_err()
                .to_string()
                .contains("shell control syntax")
        );
    }

    #[test]
    fn refuses_ambiguous_duplicate_and_mismatched_copy_outputs() {
        let edge = header_edge("sample", "AROS-NX/config/sample.conf", &[], GENMODULE, None)
            .replace("SDK/include/inline/sample.h", "SDK/include/../sample.h");
        assert!(public_header_recipes(&edge).is_err());

        let repeated = format!(
            "{}\n\n{}",
            header_edge("sample", "AROS-NX/config/sample.conf", &[], GENMODULE, None),
            header_edge("sample", "AROS-NX/other/sample.conf", &[], GENMODULE, None)
        );
        assert!(
            public_header_recipes(&repeated)
                .unwrap_err()
                .to_string()
                .contains("duplicate public SDK header output")
        );

        let edge = header_edge(
            "sample",
            "AROS-NX/config/sample.conf",
            &[],
            GENMODULE,
            Some("clib/other.h"),
        );
        assert!(
            public_header_recipes(&edge)
                .unwrap_err()
                .to_string()
                .contains("copy exactly")
        );
    }

    #[test]
    fn parses_classic_generator_sources_and_rejects_input_mismatch() {
        let sources = [
            "AROS-NX/tools/genmodule/alpha.c",
            "AROS-NX/tools/genmodule/beta.c",
        ];
        let build_inputs = format!("{} AROS-NX/tools/genmodule/config.h", sources.join(" "));
        let command = format!(
            "cd {BUILD_ROOT} && cc -O2 -w -IAROS-NX/tools/genmodule {} -o {GENMODULE}",
            sources.join(" ")
        );
        let ninja = format!(
            "build hosttools/genmodule | ${{cmake_ninja_workdir}}hosttools/genmodule: CUSTOM_COMMAND {build_inputs}\n  COMMAND = {command}"
        );
        let record = classic_generator_recipe(&ninja).unwrap();
        assert_eq!(
            record["sources"],
            json!(["tools/genmodule/alpha.c", "tools/genmodule/beta.c"])
        );
        assert_eq!(
            record["flags"],
            json!(["-O2", "-w", "-IAROS-NX/tools/genmodule"])
        );
        assert_eq!(record["output"], "build/pc-x86_64/hosttools/genmodule");
        let decoy = format!("{ninja}\n\nbuild saved/hosttools/genmodule-copy: phony\n");
        assert_eq!(classic_generator_recipe(&decoy).unwrap(), record);
        let only_decoy = ninja.replace(
            "build hosttools/genmodule |",
            "build saved/hosttools/genmodule-copy |",
        );
        assert!(
            classic_generator_recipe(&only_decoy)
                .unwrap_err()
                .to_string()
                .contains("exactly one")
        );

        let ninja = format!(
            "build hosttools/genmodule: CUSTOM_COMMAND AROS-NX/tools/genmodule/declared.c\n  COMMAND = cd {BUILD_ROOT} && cc -O2 AROS-NX/tools/genmodule/other.c -o {GENMODULE}"
        );
        assert!(
            classic_generator_recipe(&ninja)
                .unwrap_err()
                .to_string()
                .contains("differ from Ninja build inputs")
        );
    }

    #[test]
    fn parses_nouveau_direct_records_and_ignores_other_targets() {
        let value = serde_json::to_string(&json!([default_compile_record()])).unwrap();
        let records = nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["source"], "workbench/hidds/nouveau/drm/foo.c");
        assert_eq!(records[0]["directory"], REPO_BUILD_ROOT);
        assert_eq!(
            records[0]["object"],
            "build/pc-x86_64/CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/drm/foo.c"
        );
        let argv = records[0]["argv"].as_array().unwrap();
        assert_eq!(
            &argv[argv.len() - 2..],
            &[
                json!("-c"),
                json!("AROS-NX/workbench/hidds/nouveau/drm/foo.c")
            ]
        );

        let other_object = "AROS-NX/build/pc-x86_64/CMakeFiles/hidd-nouveau.dirAROS-NX/workbench/hidds/nouveau/drm/foo.c".to_owned();
        let other = compile_record(
            "AROS-NX/workbench/hidds/nouveau/drm/foo.c",
            &other_object,
            "AROS-NX/workbench/hidds/nouveau/drm/foo.c",
        );
        let value = serde_json::to_string(&json!([other])).unwrap();
        assert!(
            nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn refuses_mismatched_nouveau_source_shell_syntax_and_duplicates() {
        let mut record = default_compile_record();
        let command = record["command"].as_str().unwrap().replace(
            " -c AROS-NX/workbench/hidds/nouveau/drm/foo.c",
            " -c AROS-NX/other.c",
        );
        record["command"] = command.into();
        let value = serde_json::to_string(&json!([record])).unwrap();
        assert!(
            nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest)
                .unwrap_err()
                .to_string()
                .contains("source differs")
        );

        let mut record = default_compile_record();
        let command = format!(
            "{} && touch /tmp/not-run",
            record["command"].as_str().unwrap()
        );
        record["command"] = command.into();
        let value = serde_json::to_string(&json!([record])).unwrap();
        assert!(
            nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest)
                .unwrap_err()
                .to_string()
                .contains("shell control syntax")
        );

        let record = default_compile_record();
        let value = serde_json::to_string(&json!([record.clone(), record])).unwrap();
        assert!(
            nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest)
                .unwrap_err()
                .to_string()
                .contains("duplicate Nouveau DRM source")
        );
    }

    #[test]
    fn rejects_duplicate_json_keys_and_duplicate_objects() {
        let error = nouveau_compile_recipes(
            r#"[{"directory":"x","directory":"y"}]"#,
            JsonProfile::SdkComponentManifest,
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate JSON key"));

        let source_a = "AROS-NX/workbench/hidds/nouveau/drm/a.c";
        let source_b = "AROS-NX/workbench/hidds/nouveau/drm/b.c";
        let object = format!("{NOUVEAU_OBJECT_PREFIX}drm/shared.o");
        let first = compile_record(source_a, &object, source_a);
        let second = compile_record(source_b, &object, source_b);
        let value = serde_json::to_string(&json!([first, second])).unwrap();
        assert!(
            nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest)
                .unwrap_err()
                .to_string()
                .contains("duplicate Nouveau DRM object")
        );
    }

    #[test]
    fn posix_tokenizer_preserves_quotes_escapes_empty_and_concatenated_words() {
        let argv = literal_argv(
            r#"cc 'two words' "" pre'fix' "literal\q" "escaped\$dollar" ${CMAKE}"tail""#,
            "test command",
        )
        .unwrap();
        assert_eq!(
            argv,
            [
                "cc",
                "two words",
                "",
                "prefix",
                r"literal\q",
                r"escaped\$dollar",
                "${CMAKE}tail"
            ]
        );
        assert!(literal_argv("cc 'unterminated", "test command").is_err());
        assert!(literal_argv("cc trailing\\", "test command").is_err());
    }

    #[test]
    fn path_validation_matches_posix_normalization_refusals() {
        assert_eq!(safe_relative("a/b.c", "path").unwrap(), "a/b.c");
        for path in [
            "",
            "/absolute",
            "a//b",
            "a/./b",
            "a/../b",
            "a/",
            "a\\b",
            "C:/a",
        ] {
            assert!(safe_relative(path, "path").is_err(), "{path:?}");
        }
        assert_eq!(build_relative(BUILD_ROOT, "path").unwrap(), REPO_BUILD_ROOT);
    }

    #[test]
    fn recognizes_extended_line_and_whitespace_separators() {
        let ninja = format!(
            "note\u{2028}{}",
            header_edge("sample", "AROS-NX/config/sample.conf", &[], GENMODULE, None)
        );
        assert_eq!(public_header_recipes(&ninja).unwrap()[0]["line"], 2);
        assert!(
            super::ninja_chain("\u{001c}")
                .unwrap_err()
                .to_string()
                .contains("empty shell segment")
        );
        assert_eq!(
            super::split_recipe_whitespace("left\u{001c}right"),
            vec!["left".to_owned(), "right".to_owned()]
        );
    }

    #[test]
    fn accepts_quoted_nouveau_paths_and_sorts_records() {
        let source_b = "AROS-NX/workbench/hidds/nouveau/drm/z file.c";
        let source_a = "AROS-NX/workbench/hidds/nouveau/drm/a file.c";
        let object_b = format!("{NOUVEAU_OBJECT_PREFIX}drm/z file.o");
        let object_a = format!("{NOUVEAU_OBJECT_PREFIX}drm/a file.o");
        let mut second = compile_record(source_b, &object_b, source_b);
        let mut first = compile_record(source_a, &object_a, source_a);
        for record in [&mut first, &mut second] {
            let source = record["file"].as_str().unwrap().to_owned();
            let object = record["output"].as_str().unwrap().to_owned();
            let object_argument = object.strip_prefix(&format!("{BUILD_ROOT}/")).unwrap();
            record["command"] = format!("clang -o \"{object_argument}\" -c \"{source}\"").into();
        }
        let value = serde_json::to_string(&json!([second, first])).unwrap();
        let records = nouveau_compile_recipes(&value, JsonProfile::SdkComponentManifest).unwrap();
        assert_eq!(records[0]["source"], "workbench/hidds/nouveau/drm/a file.c");
        assert_eq!(records[1]["source"], "workbench/hidds/nouveau/drm/z file.c");
        assert_eq!(
            records[0]["argv"][2],
            "CMakeFiles/hidd-nouveau-drm.dirAROS-NX/workbench/hidds/nouveau/drm/a file.o"
        );
    }
}
