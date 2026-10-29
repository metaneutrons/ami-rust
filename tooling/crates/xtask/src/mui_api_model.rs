use ami_rust_core::{Refusal, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

const SOURCES: &str = "bindings/mui/sources.json";
const OVERRIDES: &str = "bindings/mui/overrides.json";
const SAFE_OVERRIDES: &str = "bindings/mui/safe-overrides.json";
const MODEL: &str = "bindings/mui/api.json";
const PROVENANCE: &str = "bindings/mui/provenance.json";
const RAW_ABI1: &str = "crates/aros-mui-sys/src/generated/x86_64_abi1.rs";
const RAW_ABI11: &str = "crates/aros-mui-sys/src/generated/x86_64_abi11.rs";
const SAFE_CLASSES: &str = "crates/aros-mui/src/classes.rs";
const SAFE_ATTRIBUTES: &str = "crates/aros-mui/src/attributes.rs";
const SAFE_METHODS: &str = "crates/aros-mui/src/methods.rs";
const SAFE_VALUES: &str = "crates/aros-mui/src/values.rs";
const SAFE_MANIFEST: &str = "bindings/mui/safe-api.json";
const SAFE_DOCUMENTATION: &str = "docs/mui-safe-api.md";
const C_ORACLE_ABI1: &str = "tests/m3-runtime/native/generated_abi1.c";
const C_ORACLE_ABI11: &str = "tests/m3-runtime/native/generated_abi11.c";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    schema: String,
    inputs: Vec<SourceInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    abi: String,
    repository: String,
    commit: String,
    root: String,
    entry: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overrides {
    schema: String,
    superclasses: Vec<SuperclassOverride>,
    raw_expressions: Vec<RawExpressionOverride>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuperclassOverride {
    class: String,
    superclass: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExpressionOverride {
    symbol: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct ApiModel {
    schema: &'static str,
    generator: &'static str,
    sources: Vec<SourceInput>,
    statistics: BTreeMap<String, usize>,
    classes: Vec<Class>,
    symbols: Vec<Symbol>,
    message_structures: Vec<MessageStructure>,
    private_markers: Vec<PrivateMarker>,
}

#[derive(Debug, Serialize)]
struct Class {
    abi: String,
    name: String,
    class_id: String,
    superclass: String,
    superclass_source: Location,
    override_reason: Option<String>,
    visibility: Visibility,
    source: Location,
}

#[derive(Clone, Debug, Serialize)]
struct Symbol {
    abi: String,
    name: String,
    kind: SymbolKind,
    visibility: Visibility,
    classification: Classification,
    expression: Option<String>,
    parameters: Vec<String>,
    evaluated: Option<Evaluated>,
    unresolved_identifiers: Vec<String>,
    version: Option<u32>,
    access: Option<Access>,
    c_type: Option<String>,
    source: Location,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SymbolKind {
    Class,
    Attribute,
    Method,
    Value,
    IdentifierBase,
    Macro,
    PreprocessorGuard,
    EnumValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Visibility {
    Public,
    Private,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Classification {
    Api,
    ConvenienceMacro,
    Preprocessor,
    PrivateImplementation,
    ReviewedRawExpression,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Evaluated {
    Integer(String),
    String(String),
}

#[derive(Clone, Debug, Serialize)]
struct Access {
    init: bool,
    set: bool,
    get: bool,
    marker: String,
}

#[derive(Clone, Debug, Serialize)]
struct Location {
    path: String,
    line: usize,
}

#[derive(Debug, Serialize)]
struct MessageStructure {
    abi: String,
    name: String,
    visibility: Visibility,
    fields: Vec<MessageField>,
    source: Location,
}

#[derive(Debug, Serialize)]
struct MessageField {
    declaration: String,
    visibility: Visibility,
    line: usize,
}

#[derive(Debug, Serialize)]
struct PrivateMarker {
    abi: String,
    kind: PrivateMarkerKind,
    source: Location,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum PrivateMarkerKind {
    RegionStart,
    RegionEnd,
    Inline,
}

#[derive(Debug, Serialize)]
struct Provenance {
    schema: &'static str,
    generator: &'static str,
    sources_sha256: String,
    overrides_sha256: String,
    inputs: Vec<ProvenanceInput>,
}

#[derive(Debug, Serialize)]
struct ProvenanceInput {
    abi: String,
    repository: String,
    commit: String,
    files: Vec<FileIdentity>,
}

#[derive(Debug, Serialize)]
struct FileIdentity {
    path: String,
    role: FileRole,
    sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum FileRole {
    PublicHeader,
    ClassDescriptorSource,
}

struct Options {
    repository: PathBuf,
    source_roots: BTreeMap<String, PathBuf>,
}

struct ParsedAbi {
    symbols: Vec<Symbol>,
    messages: Vec<MessageStructure>,
    classes: Vec<Class>,
    private_markers: Vec<PrivateMarker>,
    identities: Vec<FileIdentity>,
}

#[derive(Clone)]
struct LogicalLine {
    number: usize,
    text: String,
    private_region: bool,
}

pub(super) fn run(check: bool, arguments: impl Iterator<Item = OsString>) -> Result<()> {
    run_inner(check, arguments).map_err(Refusal::new)
}

fn run_inner(
    check: bool,
    arguments: impl Iterator<Item = OsString>,
) -> std::result::Result<(), String> {
    let options = parse_options(arguments)?;
    let source_bytes = fs::read(options.repository.join(SOURCES)).map_err(display)?;
    let override_bytes = fs::read(options.repository.join(OVERRIDES)).map_err(display)?;
    let safe_override_bytes = fs::read(options.repository.join(SAFE_OVERRIDES)).map_err(display)?;
    let sources: SourceManifest = serde_json::from_slice(&source_bytes).map_err(display)?;
    let overrides: Overrides = serde_json::from_slice(&override_bytes).map_err(display)?;
    validate_configuration(&sources, &overrides, &options)?;

    let mut symbols = Vec::new();
    let mut messages = Vec::new();
    let mut classes = Vec::new();
    let mut markers = Vec::new();
    let mut provenance_inputs = Vec::new();
    for input in &sources.inputs {
        let checkout = options
            .source_roots
            .get(&input.abi)
            .ok_or_else(|| format!("no checkout supplied for {}", input.abi))?;
        let parsed = parse_abi(checkout, input, &overrides)?;
        symbols.extend(parsed.symbols);
        messages.extend(parsed.messages);
        classes.extend(parsed.classes);
        markers.extend(parsed.private_markers);
        provenance_inputs.push(ProvenanceInput {
            abi: input.abi.clone(),
            repository: input.repository.clone(),
            commit: input.commit.clone(),
            files: parsed.identities,
        });
    }
    symbols.sort_by(symbol_order);
    messages.sort_by(|left, right| {
        (&left.abi, &left.name, &left.source.path, left.source.line).cmp(&(
            &right.abi,
            &right.name,
            &right.source.path,
            right.source.line,
        ))
    });
    classes.sort_by(|left, right| (&left.abi, &left.name).cmp(&(&right.abi, &right.name)));
    markers.sort_by(|left, right| {
        (&left.abi, &left.source.path, left.source.line).cmp(&(
            &right.abi,
            &right.source.path,
            right.source.line,
        ))
    });

    let mut statistics = BTreeMap::new();
    for symbol in &symbols {
        *statistics
            .entry(format!("symbols.{}", symbol_kind_name(symbol.kind)))
            .or_insert(0) += 1;
    }
    statistics.insert("classes".to_owned(), classes.len());
    statistics.insert("message_structures".to_owned(), messages.len());
    statistics.insert("private_markers".to_owned(), markers.len());
    let model = ApiModel {
        schema: "ami-rust-mui-api-model-v1",
        generator: env!("CARGO_PKG_VERSION"),
        sources: sources.inputs,
        statistics,
        classes,
        symbols,
        message_structures: messages,
        private_markers: markers,
    };
    let provenance = Provenance {
        schema: "ami-rust-mui-provenance-v1",
        generator: env!("CARGO_PKG_VERSION"),
        sources_sha256: sha256(&source_bytes),
        overrides_sha256: sha256(&override_bytes),
        inputs: provenance_inputs,
    };
    let model_bytes = json_bytes(&model)?;
    let provenance_bytes = json_bytes(&provenance)?;
    let raw_abi1 = generate_raw_bindings(&model, "abi1")?;
    let raw_abi11 = generate_raw_bindings(&model, "abi11")?;
    let c_oracle_abi1 = generate_c_oracle(&model, "abi1")?;
    let c_oracle_abi11 = generate_c_oracle(&model, "abi11")?;
    let safe = super::mui_safe_codegen::generate(&model_bytes, &safe_override_bytes)?;
    emit(&options.repository.join(MODEL), &model_bytes, check)?;
    emit(
        &options.repository.join(PROVENANCE),
        &provenance_bytes,
        check,
    )?;
    emit(
        &options.repository.join(RAW_ABI1),
        raw_abi1.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(RAW_ABI11),
        raw_abi11.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(C_ORACLE_ABI1),
        c_oracle_abi1.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(C_ORACLE_ABI11),
        c_oracle_abi11.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(SAFE_CLASSES),
        safe.classes.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(SAFE_ATTRIBUTES),
        safe.attributes.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(SAFE_METHODS),
        safe.methods.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(SAFE_VALUES),
        safe.values.as_bytes(),
        check,
    )?;
    emit(
        &options.repository.join(SAFE_MANIFEST),
        &safe.manifest,
        check,
    )?;
    emit(
        &options.repository.join(SAFE_DOCUMENTATION),
        safe.documentation.as_bytes(),
        check,
    )?;
    Ok(())
}

fn generate_raw_bindings(model: &ApiModel, abi: &str) -> std::result::Result<String, String> {
    let mut output = String::from(
        "// Generated by `cargo xtask generate mui`. Do not edit by hand.\n\
         #![allow(non_snake_case, non_upper_case_globals, unused_parens)]\n\
         use super::{Object, Stacked};\n\
         use core::{ffi::{c_char, c_void}, mem::{align_of, offset_of, size_of}};\n\n",
    );
    let symbols: Vec<_> = model
        .symbols
        .iter()
        .filter(|symbol| {
            symbol.abi == abi
                && symbol.visibility == Visibility::Public
                && symbol.classification == Classification::Api
        })
        .collect();
    for symbol in symbols {
        match symbol.kind {
            SymbolKind::Class => {
                let Some(Evaluated::String(value)) = &symbol.evaluated else {
                    return Err(format!("{} lacks an evaluated class ID", symbol.name));
                };
                output.push_str(&format!(
                    "/// C class ID from `{}:{}`.\n\
                     pub const {}: *const c_char = concat!({value:?}, \"\\0\").as_ptr() as *const c_char;\n\n",
                    symbol.source.path, symbol.source.line, symbol.name
                ));
            }
            SymbolKind::Attribute | SymbolKind::Method | SymbolKind::IdentifierBase => {
                let value = evaluated_integer(symbol)?;
                let value = u32::try_from(value).map_err(|_| {
                    format!("{} does not fit the raw ULONG identifier type", symbol.name)
                })?;
                output.push_str(&format!(
                    "/// Raw identifier from `{}:{}`.\n\
                     pub const {}: u32 = {value};\n\n",
                    symbol.source.path, symbol.source.line, symbol.name
                ));
            }
            SymbolKind::EnumValue => {
                let value = evaluated_integer(symbol)?;
                i32::try_from(value)
                    .map_err(|_| format!("{} does not fit the C int type", symbol.name))?;
                output.push_str(&format!(
                    "/// Raw value from `{}:{}`.\n\
                     pub const {}: i32 = ({value}i128) as i32;\n\n",
                    symbol.source.path, symbol.source.line, symbol.name
                ));
            }
            SymbolKind::Value if symbol.parameters.is_empty() => {
                let value = evaluated_integer(symbol)?;
                let rust_type = raw_value_type(symbol, value)?;
                output.push_str(&format!(
                    "/// Raw value from `{}:{}`.\n\
                     pub const {}: {rust_type} = ({value}i128) as {rust_type};\n\n",
                    symbol.source.path, symbol.source.line, symbol.name
                ));
            }
            SymbolKind::Value => {
                if symbol.parameters != ["p"] {
                    return Err(format!(
                        "{} has an unsupported function-like value signature",
                        symbol.name
                    ));
                }
                let expression = symbol.expression.as_deref().ok_or_else(|| {
                    format!("{} lacks a function-like value expression", symbol.name)
                })?;
                parse_numeric(expression, &BTreeMap::from([("p".to_owned(), 0)]))?;
                output.push_str(&format!(
                    "/// Raw parameterized value from `{}:{}`.\n\
                     #[inline]\n\
                     pub const fn {}(p: i32) -> i32 {{ {expression} }}\n\n",
                    symbol.source.path, symbol.source.line, symbol.name
                ));
            }
            SymbolKind::Macro | SymbolKind::PreprocessorGuard => unreachable!(),
        }
    }

    let messages: Vec<_> = model
        .message_structures
        .iter()
        .filter(|message| message.abi == abi && message.visibility == Visibility::Public)
        .collect();
    for message in &messages {
        output.push_str(&format!(
            "/// Raw MUI method message from `{}:{}`.\n\
             #[repr(C)]\n\
             #[derive(Clone, Copy, Debug)]\n\
             pub struct {} {{\n",
            message.source.path, message.source.line, message.name
        ));
        for field in &message.fields {
            let (name, rust_type) = message_field(&field.declaration).map_err(|error| {
                format!(
                    "{}:{}: {error} in `{}`",
                    message.source.path, field.line, field.declaration
                )
            })?;
            let rust_type = if message_field_is_stacked(&field.declaration) {
                format!("Stacked<{rust_type}>")
            } else {
                rust_type
            };
            output.push_str(&format!("    pub {name}: {rust_type},\n"));
        }
        output.push_str("}\n\n");
    }
    let layout_count = messages
        .iter()
        .map(|message| 2 + message.fields.len())
        .sum::<usize>();
    output.push_str(&format!(
        "/// Number of C layout values used by the M3 qualification oracle.\n\
         #[doc(hidden)]\n\
         pub const MUI_LAYOUT_VALUE_COUNT: usize = {layout_count};\n\n\
         #[doc(hidden)]\n\
         pub const MUI_LAYOUT_VALUES: [usize; MUI_LAYOUT_VALUE_COUNT] = [\n"
    ));
    for message in messages {
        output.push_str(&format!(
            "    size_of::<{}>(), align_of::<{}>(),\n",
            message.name, message.name
        ));
        for field in &message.fields {
            let (name, _) = message_field(&field.declaration)?;
            output.push_str(&format!("    offset_of!({}, {}),\n", message.name, name));
        }
    }
    output.push_str("];\n\n");
    let constant_names = selected_constant_names(abi);
    output.push_str(&format!(
        "#[doc(hidden)]\n\
         pub const MUI_CONSTANT_VALUES: [u64; {}] = [\n",
        constant_names.len()
    ));
    for name in &constant_names {
        output.push_str(&format!("    {name} as u64,\n"));
    }
    output.push_str("];\n");
    Ok(output)
}

fn generate_c_oracle(model: &ApiModel, abi: &str) -> std::result::Result<String, String> {
    let messages: Vec<_> = model
        .message_structures
        .iter()
        .filter(|message| message.abi == abi && message.visibility == Visibility::Public)
        .collect();
    let mut output = String::from(
        "/* Generated by `cargo xtask generate mui`. Do not edit by hand. */\n\
         #include <stddef.h>\n\
         #include <stdint.h>\n\
         #define MUI_OBSOLETE 1\n\
         #include \"mui.h\"\n\n\
         const uint64_t ami_rust_boopsi_layout_values[] = {\n\
             sizeof(struct MinNode), _Alignof(struct MinNode),\n\
             offsetof(struct MinNode, mln_Succ),\n\
             offsetof(struct MinNode, mln_Pred),\n\
             sizeof(struct Hook), _Alignof(struct Hook),\n\
             offsetof(struct Hook, h_MinNode),\n\
             offsetof(struct Hook, h_Entry),\n\
             offsetof(struct Hook, h_SubEntry),\n\
             offsetof(struct Hook, h_Data),\n\
             sizeof(struct IClass), _Alignof(struct IClass),\n\
             offsetof(struct IClass, cl_Dispatcher),\n\
             offsetof(struct IClass, cl_Reserved),\n\
             offsetof(struct IClass, cl_Super),\n\
             offsetof(struct IClass, cl_ID),\n\
             offsetof(struct IClass, cl_InstOffset),\n\
             offsetof(struct IClass, cl_InstSize),\n\
             offsetof(struct IClass, cl_UserData),\n\
             offsetof(struct IClass, cl_SubclassCount),\n\
             offsetof(struct IClass, cl_ObjectCount),\n\
             offsetof(struct IClass, cl_Flags),\n\
             offsetof(struct IClass, cl_ObjectSize),\n\
             offsetof(struct IClass, cl_MemoryPool),\n\
         };\n\
         const size_t ami_rust_boopsi_layout_value_count =\n\
             sizeof(ami_rust_boopsi_layout_values) / sizeof(ami_rust_boopsi_layout_values[0]);\n\n\
         const uint64_t ami_rust_custom_class_layout_values[] = {\n\
             sizeof(struct MUI_CustomClass), _Alignof(struct MUI_CustomClass),\n\
             offsetof(struct MUI_CustomClass, mcc_UserData),\n\
             offsetof(struct MUI_CustomClass, mcc_UtilityBase),\n\
             offsetof(struct MUI_CustomClass, mcc_DOSBase),\n\
             offsetof(struct MUI_CustomClass, mcc_GfxBase),\n\
             offsetof(struct MUI_CustomClass, mcc_IntuitionBase),\n\
             offsetof(struct MUI_CustomClass, mcc_Super),\n\
             offsetof(struct MUI_CustomClass, mcc_Class),\n\
             offsetof(struct MUI_CustomClass, mcc_Module),\n\
         };\n\
         const size_t ami_rust_custom_class_layout_value_count =\n\
             sizeof(ami_rust_custom_class_layout_values) / sizeof(ami_rust_custom_class_layout_values[0]);\n\n\
         const uint64_t ami_rust_mui_layout_values[] = {\n",
    );
    for message in messages {
        output.push_str(&format!(
            "    sizeof(struct {}), _Alignof(struct {}),\n",
            message.name, message.name
        ));
        for field in &message.fields {
            let (name, _) = message_field(&field.declaration)?;
            output.push_str(&format!(
                "    offsetof(struct {}, {}),\n",
                message.name,
                name.strip_prefix("r#").unwrap_or(&name)
            ));
        }
    }
    output.push_str(
        "};\n\
         const size_t ami_rust_mui_layout_value_count =\n\
             sizeof(ami_rust_mui_layout_values) / sizeof(ami_rust_mui_layout_values[0]);\n\n\
         const uint64_t ami_rust_mui_constant_values[] = {\n",
    );
    for name in selected_constant_names(abi) {
        output.push_str(&format!("    (uint32_t)({name}),\n"));
    }
    output.push_str(
        "};\n\
         const size_t ami_rust_mui_constant_value_count =\n\
             sizeof(ami_rust_mui_constant_values) / sizeof(ami_rust_mui_constant_values[0]);\n\n\
         const char *ami_rust_mui_window_class_id(void) { return MUIC_Window; }\n",
    );
    Ok(output)
}

fn selected_constant_names(abi: &str) -> Vec<&'static str> {
    let mut names = vec![
        "MUIB_MUI",
        "MUIA_Window_Open",
        "MUIM_Notify",
        "MUIV_Application_ReturnID_Quit",
    ];
    if abi == "abi1" {
        names.push("MUIA_Panel_Padding");
    }
    names
}

fn raw_value_type(symbol: &Symbol, value: i128) -> std::result::Result<&'static str, String> {
    let expression = symbol.expression.as_deref().unwrap_or_default();
    if expression.contains("IPTR") {
        isize::try_from(value).map_err(|_| format!("{} does not fit IPTR", symbol.name))?;
        Ok("isize")
    } else if ["APTR", "STRPTR", "Object", "void *"]
        .iter()
        .any(|marker| expression.contains(marker))
    {
        isize::try_from(value)
            .map_err(|_| format!("{} does not fit a pointer-sized value", symbol.name))?;
        Ok("usize")
    } else if expression.contains("ULONG") || value > i128::from(i32::MAX) {
        u32::try_from(value.rem_euclid(1_i128 << 32))
            .map_err(|_| format!("{} does not fit ULONG", symbol.name))?;
        Ok("u32")
    } else {
        i32::try_from(value).map_err(|_| format!("{} does not fit LONG", symbol.name))?;
        Ok("i32")
    }
}

fn evaluated_integer(symbol: &Symbol) -> std::result::Result<i128, String> {
    let Some(Evaluated::Integer(value)) = &symbol.evaluated else {
        return Err(format!("{} lacks an evaluated integer value", symbol.name));
    };
    value.parse().map_err(display)
}

fn message_field(declaration: &str) -> std::result::Result<(String, String), String> {
    let declaration = declaration
        .trim()
        .strip_suffix(';')
        .ok_or_else(|| "message field lacks a semicolon".to_owned())?
        .trim();
    let declaration = declaration
        .strip_prefix("STACKED ")
        .or_else(|| declaration.strip_prefix("STACKED"))
        .unwrap_or(declaration)
        .trim();
    let declaration = declaration
        .strip_prefix("STACKULONG ")
        .map_or_else(|| declaration.to_owned(), |rest| format!("ULONG {rest}"));
    let (without_array, array) = if let Some(open) = declaration.rfind('[') {
        let close = declaration
            .strip_suffix(']')
            .ok_or_else(|| "unsupported array declaration".to_owned())?;
        let count = close[open + 1..]
            .parse::<usize>()
            .map_err(|_| "array bound is not an integer".to_owned())?;
        (&declaration[..open], Some(count))
    } else {
        (declaration.as_str(), None)
    };
    let name_start = without_array
        .rfind(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .map_or(0, |index| index + 1);
    let name = &without_array[name_start..];
    if !is_identifier(name) {
        return Err("message field name is not an identifier".to_owned());
    }
    let mut c_type = without_array[..name_start].trim().to_owned();
    let pointer_count = c_type.chars().filter(|character| *character == '*').count();
    c_type.retain(|character| character != '*');
    let c_type = c_type.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut rust_type = match c_type.as_str() {
        "APTR" => "*mut c_void".to_owned(),
        "CONST_STRPTR" => "*const c_char".to_owned(),
        "IPTR" => "isize".to_owned(),
        "LONG" => "i32".to_owned(),
        "Object" => "Object".to_owned(),
        "STRPTR" => "*mut c_char".to_owned(),
        "ULONG" => "u32".to_owned(),
        "char" => "c_char".to_owned(),
        value if value.starts_with("struct ") => "c_void".to_owned(),
        _ => return Err(format!("unsupported message field type `{c_type}`")),
    };
    for _ in 0..pointer_count {
        rust_type = format!("*mut {rust_type}");
    }
    if let Some(count) = array {
        rust_type = format!("[{rust_type}; {count}]");
    }
    let name = if [
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn",
    ]
    .contains(&name)
    {
        format!("r#{name}")
    } else {
        name.to_owned()
    };
    Ok((name, rust_type))
}

fn message_field_is_stacked(declaration: &str) -> bool {
    let declaration = declaration.trim();
    declaration.starts_with("STACKED") || declaration.starts_with("STACKULONG")
}

fn parse_options(
    mut arguments: impl Iterator<Item = OsString>,
) -> std::result::Result<Options, String> {
    let mut values = BTreeMap::new();
    while let Some(key) = arguments.next() {
        let key = key
            .into_string()
            .map_err(|_| "option names must be UTF-8".to_owned())?;
        if !["--repository", "--abi1-source", "--abi11-source"].contains(&key.as_str()) {
            return Err(format!("unknown MUI generator option {key}; {}", usage()));
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("{key} requires a path"))?;
        if values.insert(key.clone(), PathBuf::from(value)).is_some() {
            return Err(format!("{key} may be supplied only once"));
        }
    }
    let repository = values
        .remove("--repository")
        .ok_or_else(|| format!("missing --repository; {}", usage()))?;
    let abi1 = values
        .remove("--abi1-source")
        .ok_or_else(|| format!("missing --abi1-source; {}", usage()))?;
    let abi11 = values
        .remove("--abi11-source")
        .ok_or_else(|| format!("missing --abi11-source; {}", usage()))?;
    Ok(Options {
        repository,
        source_roots: BTreeMap::from([("abi1".to_owned(), abi1), ("abi11".to_owned(), abi11)]),
    })
}

fn usage() -> &'static str {
    "cargo xtask {generate|check} mui --repository PATH --abi1-source GIT --abi11-source GIT"
}

fn validate_configuration(
    sources: &SourceManifest,
    overrides: &Overrides,
    options: &Options,
) -> std::result::Result<(), String> {
    if sources.schema != "ami-rust-mui-sources-v1" {
        return Err("unsupported MUI source schema".to_owned());
    }
    if overrides.schema != "ami-rust-mui-overrides-v1" {
        return Err("unsupported MUI override schema".to_owned());
    }
    let configured: BTreeSet<_> = sources
        .inputs
        .iter()
        .map(|input| input.abi.as_str())
        .collect();
    if configured != BTreeSet::from(["abi1", "abi11"]) {
        return Err("MUI sources must define exactly abi1 and abi11".to_owned());
    }
    if options.source_roots.len() != 2 {
        return Err("exactly two MUI source checkouts are required".to_owned());
    }
    let mut overridden = BTreeSet::new();
    for item in &overrides.superclasses {
        if item.reason.trim().is_empty() || !overridden.insert(item.class.as_str()) {
            return Err(
                "superclass overrides require unique classes and non-empty reasons".to_owned(),
            );
        }
    }
    let mut raw = BTreeSet::new();
    for item in &overrides.raw_expressions {
        if item.reason.trim().is_empty() || !raw.insert(item.symbol.as_str()) {
            return Err("raw-expression overrides require unique symbols and reasons".to_owned());
        }
    }
    Ok(())
}

fn parse_abi(
    checkout: &Path,
    input: &SourceInput,
    overrides: &Overrides,
) -> std::result::Result<ParsedAbi, String> {
    verify_commit(checkout, &input.commit)?;
    let headers = public_header_closure(checkout, input)?;
    let source_paths = class_source_paths(checkout, input)?;
    let mut identities = Vec::new();
    let mut symbols = Vec::new();
    let mut messages = Vec::new();
    let mut markers = Vec::new();
    for relative in &headers {
        let path = join_source_path(&input.root, relative)?;
        let bytes = git_file(checkout, &input.commit, &path)?;
        identities.push(FileIdentity {
            path: path.clone(),
            role: FileRole::PublicHeader,
            sha256: sha256(&bytes),
        });
        parse_header(
            &input.abi,
            relative,
            &bytes,
            overrides,
            &mut symbols,
            &mut messages,
            &mut markers,
        )?;
    }
    evaluate_symbols(&mut symbols, overrides)?;

    let mut descriptors = BTreeMap::new();
    for path in &source_paths {
        let bytes = git_file(checkout, &input.commit, path)?;
        identities.push(FileIdentity {
            path: path.clone(),
            role: FileRole::ClassDescriptorSource,
            sha256: sha256(&bytes),
        });
        parse_descriptors(path, &bytes, &mut descriptors)?;
    }
    identities.sort_by(|left, right| left.path.cmp(&right.path));
    let classes = build_classes(&input.abi, &symbols, descriptors, overrides)?;
    Ok(ParsedAbi {
        symbols,
        messages,
        classes,
        private_markers: markers,
        identities,
    })
}

fn verify_commit(checkout: &Path, commit: &str) -> std::result::Result<(), String> {
    let status = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["cat-file", "-e", &format!("{commit}^{{commit}}")])
        .status()
        .map_err(display)?;
    if !status.success() {
        return Err(format!(
            "{} does not contain pinned commit {commit}",
            checkout.display()
        ));
    }
    Ok(())
}

fn public_header_closure(
    checkout: &Path,
    input: &SourceInput,
) -> std::result::Result<Vec<String>, String> {
    let mut pending = VecDeque::from([input.entry.clone()]);
    let mut selected = BTreeSet::new();
    while let Some(relative) = pending.pop_front() {
        let relative = normalize_relative(&relative)?;
        if !selected.insert(relative.clone()) {
            continue;
        }
        let path = join_source_path(&input.root, &relative)?;
        let bytes = git_file(checkout, &input.commit, &path)?;
        let text = String::from_utf8_lossy(&bytes);
        let parent = Path::new(&relative)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        for line in text.lines() {
            let trimmed = line.trim();
            let Some(include) = trimmed.strip_prefix("#include \"") else {
                continue;
            };
            let Some((include, _)) = include.split_once('"') else {
                return Err(format!("malformed quoted include in {relative}"));
            };
            let resolved = normalize_relative(&parent.join(include).to_string_lossy())?;
            if resolved.contains("_private.h") || resolved.contains("_intern.h") {
                return Err(format!(
                    "public header closure reaches private header {resolved}"
                ));
            }
            let candidate = join_source_path(&input.root, &resolved)?;
            if git_file_optional(checkout, &input.commit, &candidate)?.is_some() {
                pending.push_back(resolved);
            }
        }
    }
    Ok(selected.into_iter().collect())
}

fn class_source_paths(
    checkout: &Path,
    input: &SourceInput,
) -> std::result::Result<Vec<String>, String> {
    let prefix = format!("{}/classes", input.root.trim_end_matches('/'));
    let output = git_output(
        checkout,
        ["ls-tree", "-r", "--name-only", &input.commit, &prefix],
    )?;
    let text = String::from_utf8(output).map_err(display)?;
    let mut paths: Vec<_> = text
        .lines()
        .filter(|path| path.ends_with(".c"))
        .map(str::to_owned)
        .collect();
    paths.sort();
    if paths.is_empty() {
        return Err(format!("{} has no class descriptor sources", input.abi));
    }
    Ok(paths)
}

fn parse_header(
    abi: &str,
    path: &str,
    bytes: &[u8],
    overrides: &Overrides,
    symbols: &mut Vec<Symbol>,
    messages: &mut Vec<MessageStructure>,
    markers: &mut Vec<PrivateMarker>,
) -> std::result::Result<(), String> {
    let text = String::from_utf8_lossy(bytes);
    let lines = logical_lines(&text, abi, path, markers);
    let mut index = 0;
    while index < lines.len() {
        let line = &lines[index];
        if let Some(symbol) = parse_define(abi, path, line, overrides)? {
            symbols.push(symbol);
            index += 1;
            continue;
        }
        if let Some((message, consumed)) = parse_message_structure(abi, path, &lines[index..])? {
            messages.push(message);
            index += consumed;
            continue;
        }
        if let Some((mut values, consumed)) = parse_enum(abi, path, &lines[index..], overrides)? {
            symbols.append(&mut values);
            index += consumed;
            continue;
        }
        index += 1;
    }
    Ok(())
}

fn logical_lines(
    text: &str,
    abi: &str,
    path: &str,
    markers: &mut Vec<PrivateMarker>,
) -> Vec<LogicalLine> {
    let mut output = Vec::new();
    let mut region = false;
    let mut current = String::new();
    let mut start = 1;
    let mut current_region = false;
    for (offset, physical) in text.lines().enumerate() {
        let number = offset + 1;
        if physical.contains("START PRIV") {
            markers.push(PrivateMarker {
                abi: abi.to_owned(),
                kind: PrivateMarkerKind::RegionStart,
                source: Location {
                    path: path.to_owned(),
                    line: number,
                },
            });
            region = true;
        } else if physical.contains("END PRIV") {
            markers.push(PrivateMarker {
                abi: abi.to_owned(),
                kind: PrivateMarkerKind::RegionEnd,
                source: Location {
                    path: path.to_owned(),
                    line: number,
                },
            });
        } else if physical.contains("PRIV") {
            markers.push(PrivateMarker {
                abi: abi.to_owned(),
                kind: PrivateMarkerKind::Inline,
                source: Location {
                    path: path.to_owned(),
                    line: number,
                },
            });
        }
        if current.is_empty() {
            start = number;
            current_region = region;
        }
        let continuation = physical.trim_end().ends_with('\\');
        let part = physical.trim_end().trim_end_matches('\\').trim();
        if !current.is_empty() && !part.is_empty() {
            current.push(' ');
        }
        current.push_str(part);
        if !continuation {
            output.push(LogicalLine {
                number: start,
                text: std::mem::take(&mut current),
                private_region: current_region,
            });
        }
        if physical.contains("END PRIV") {
            region = false;
        }
    }
    if !current.is_empty() {
        output.push(LogicalLine {
            number: start,
            text: current,
            private_region: current_region,
        });
    }
    output
}

fn parse_define(
    abi: &str,
    path: &str,
    line: &LogicalLine,
    overrides: &Overrides,
) -> std::result::Result<Option<Symbol>, String> {
    let trimmed = line.text.trim_start();
    let Some(mut rest) = trimmed.strip_prefix("#define") else {
        return Ok(None);
    };
    if !rest.starts_with(char::is_whitespace) {
        return Ok(None);
    }
    rest = rest.trim_start();
    let name_end = rest
        .find(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .unwrap_or(rest.len());
    if name_end == 0 {
        return Err(format!("malformed #define at {path}:{}", line.number));
    }
    let name = &rest[..name_end];
    rest = &rest[name_end..];
    let mut parameters = Vec::new();
    if rest.starts_with('(') {
        let end = matching_paren(rest, 0)
            .ok_or_else(|| format!("unterminated macro parameters at {path}:{}", line.number))?;
        parameters = rest[1..end]
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        rest = &rest[end + 1..];
    }
    let comments = block_comments(rest);
    let expression = strip_comments(rest).trim().to_owned();
    let visibility =
        if line.private_region || comments.iter().any(|comment| comment.contains("PRIV")) {
            Visibility::Private
        } else {
            Visibility::Public
        };
    let kind = symbol_kind(name, &expression, &parameters);
    let raw_override = overrides
        .raw_expressions
        .iter()
        .find(|item| item.symbol == name);
    let classification = if visibility == Visibility::Private {
        Classification::PrivateImplementation
    } else if raw_override.is_some() {
        Classification::ReviewedRawExpression
    } else {
        match kind {
            SymbolKind::Class
            | SymbolKind::Attribute
            | SymbolKind::Method
            | SymbolKind::Value
            | SymbolKind::IdentifierBase
            | SymbolKind::EnumValue => Classification::Api,
            SymbolKind::Macro => Classification::ConvenienceMacro,
            SymbolKind::PreprocessorGuard => Classification::Preprocessor,
        }
    };
    let metadata = comments.join(" ");
    let access = parse_access(&metadata);
    let c_type = access
        .as_ref()
        .and_then(|access| type_after_access(&metadata, &access.marker));
    Ok(Some(Symbol {
        abi: abi.to_owned(),
        name: name.to_owned(),
        kind,
        visibility,
        classification,
        expression: (!expression.is_empty()).then_some(expression),
        parameters,
        evaluated: None,
        unresolved_identifiers: Vec::new(),
        version: parse_version(&metadata),
        access,
        c_type,
        source: Location {
            path: path.to_owned(),
            line: line.number,
        },
    }))
}

fn symbol_kind(name: &str, expression: &str, parameters: &[String]) -> SymbolKind {
    if name.starts_with("MUIC_") {
        SymbolKind::Class
    } else if name.starts_with("MUIA_") {
        SymbolKind::Attribute
    } else if name.starts_with("MUIM_") {
        SymbolKind::Method
    } else if name.starts_with("MUIV_") {
        SymbolKind::Value
    } else if name.starts_with("MUIB_") {
        SymbolKind::IdentifierBase
    } else if parameters.is_empty()
        && expression.is_empty()
        && (name.starts_with('_') || name.ends_with("_H"))
    {
        SymbolKind::PreprocessorGuard
    } else {
        SymbolKind::Macro
    }
}

fn parse_message_structure(
    abi: &str,
    path: &str,
    lines: &[LogicalLine],
) -> std::result::Result<Option<(MessageStructure, usize)>, String> {
    let Some(first) = lines.first() else {
        return Ok(None);
    };
    let trimmed = first.text.trim();
    let Some(rest) = trimmed.strip_prefix("struct ") else {
        return Ok(None);
    };
    let name_end = rest
        .find(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .unwrap_or(rest.len());
    let name = &rest[..name_end];
    if !name.starts_with("MUIP_") {
        return Ok(None);
    }
    let mut consumed = 1;
    let mut body_started = rest[name_end..].contains('{');
    let mut body = Vec::new();
    let visibility = if first.private_region || first.text.contains("PRIV") {
        Visibility::Private
    } else {
        Visibility::Public
    };
    while consumed <= lines.len() {
        let current = &lines[consumed - 1];
        let text = current.text.trim();
        if !body_started {
            if text.contains('{') {
                body_started = true;
            } else if text.ends_with(';') {
                return Ok(None);
            }
        } else if text.contains("};") {
            break;
        } else if consumed > 1 && !text.is_empty() && text != "{" {
            let private = current.private_region || text.contains("PRIV");
            for declaration in split_declarations(text) {
                body.push(MessageField {
                    declaration,
                    visibility: if private {
                        Visibility::Private
                    } else {
                        Visibility::Public
                    },
                    line: current.number,
                });
            }
        }
        consumed += 1;
    }
    if consumed > lines.len() || !body_started {
        return Err(format!(
            "unterminated message structure {name} at {path}:{}",
            first.number
        ));
    }
    Ok(Some((
        MessageStructure {
            abi: abi.to_owned(),
            name: name.to_owned(),
            visibility,
            fields: body,
            source: Location {
                path: path.to_owned(),
                line: first.number,
            },
        },
        consumed,
    )))
}

fn split_declarations(text: &str) -> Vec<String> {
    let clean = strip_comments(text);
    clean
        .split(';')
        .map(str::trim)
        .filter(|declaration| !declaration.is_empty())
        .map(|declaration| format!("{declaration};"))
        .collect()
}

fn parse_enum(
    abi: &str,
    path: &str,
    lines: &[LogicalLine],
    overrides: &Overrides,
) -> std::result::Result<Option<(Vec<Symbol>, usize)>, String> {
    let Some(first) = lines.first() else {
        return Ok(None);
    };
    let trimmed = strip_comments(first.text.trim());
    if !trimmed.starts_with("enum ") && !trimmed.starts_with("enum{") && trimmed != "enum" {
        return Ok(None);
    }
    let mut consumed = 1;
    let mut started = trimmed.contains('{');
    let mut body = String::new();
    while consumed <= lines.len() {
        let current = &lines[consumed - 1];
        let text = strip_comments(current.text.trim());
        if !started {
            if let Some((_, after)) = text.split_once('{') {
                started = true;
                body.push_str(after);
            } else if text.ends_with(';') {
                return Ok(None);
            }
        } else {
            let content = if consumed == 1 {
                text.split_once('{').map_or("", |(_, after)| after)
            } else {
                text.as_str()
            };
            if let Some((before, _)) = content.split_once('}') {
                body.push_str(before);
                break;
            }
            body.push_str(content);
            body.push(' ');
        }
        consumed += 1;
    }
    if consumed > lines.len() || !started {
        return Err(format!("unterminated enum at {path}:{}", first.number));
    }
    let mut values = Vec::new();
    for entry in split_top_level(&body, ',') {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let (name, expression) = entry
            .split_once('=')
            .map_or((entry, None), |(name, expression)| {
                (name.trim(), Some(expression.trim()))
            });
        if !is_identifier(name) {
            return Err(format!(
                "unsupported enum entry `{entry}` at {path}:{}",
                first.number
            ));
        }
        let raw_override = overrides
            .raw_expressions
            .iter()
            .find(|item| item.symbol == name);
        values.push(Symbol {
            abi: abi.to_owned(),
            name: name.to_owned(),
            kind: SymbolKind::EnumValue,
            visibility: if first.private_region || first.text.contains("PRIV") {
                Visibility::Private
            } else {
                Visibility::Public
            },
            classification: if raw_override.is_some() {
                Classification::ReviewedRawExpression
            } else {
                Classification::Api
            },
            expression: expression.map(str::to_owned),
            parameters: Vec::new(),
            evaluated: None,
            unresolved_identifiers: Vec::new(),
            version: None,
            access: None,
            c_type: None,
            source: Location {
                path: path.to_owned(),
                line: first.number,
            },
        });
    }
    Ok(Some((values, consumed)))
}

fn evaluate_symbols(
    symbols: &mut [Symbol],
    overrides: &Overrides,
) -> std::result::Result<(), String> {
    let raw: BTreeSet<_> = overrides
        .raw_expressions
        .iter()
        .map(|item| item.symbol.as_str())
        .collect();
    let mut values = BTreeMap::<String, i128>::from([("TAG_USER".to_owned(), 1_i128 << 31)]);
    let mut automatic_enum_value = 0_i128;
    for symbol in symbols.iter_mut() {
        if !symbol.parameters.is_empty() || raw.contains(symbol.name.as_str()) {
            continue;
        }
        let Some(expression) = symbol.expression.as_deref() else {
            if symbol.kind == SymbolKind::EnumValue {
                symbol.evaluated = Some(Evaluated::Integer(automatic_enum_value.to_string()));
                values.insert(symbol.name.clone(), automatic_enum_value);
                automatic_enum_value += 1;
            }
            continue;
        };
        if let Some(string) = parse_string_literal(expression) {
            symbol.evaluated = Some(Evaluated::String(string));
            continue;
        }
        match parse_numeric(expression, &values) {
            Ok(NumericResult { value, unresolved }) => {
                symbol.unresolved_identifiers = unresolved.into_iter().collect();
                if let Some(value) = value {
                    symbol.evaluated = Some(Evaluated::Integer(value.to_string()));
                    values.insert(symbol.name.clone(), value);
                    if symbol.kind == SymbolKind::EnumValue {
                        automatic_enum_value = value + 1;
                    }
                }
            }
            Err(error) if requires_numeric_grammar(symbol.kind) => {
                return Err(format!(
                    "unsupported expression for {} at {}:{}: {error}; add a reviewed raw-expression override only when the construct is intentionally not evaluable",
                    symbol.name, symbol.source.path, symbol.source.line
                ));
            }
            Err(_) => {}
        }
    }

    // Public headers are discovered in stable path order rather than C
    // preprocessor order. Resolve object-like definitions to a fixed point so
    // a class header may refer to identifier bases declared by mui.h later in
    // that path order.
    loop {
        let mut changed = false;
        for symbol in symbols.iter_mut() {
            if symbol.evaluated.is_some()
                || !symbol.parameters.is_empty()
                || raw.contains(symbol.name.as_str())
            {
                continue;
            }
            let Some(expression) = symbol.expression.as_deref() else {
                continue;
            };
            let Ok(result) = parse_numeric(expression, &values) else {
                continue;
            };
            symbol.unresolved_identifiers = result.unresolved.into_iter().collect();
            let Some(value) = result.value else {
                continue;
            };
            symbol.evaluated = Some(Evaluated::Integer(value.to_string()));
            values.insert(symbol.name.clone(), value);
            changed = true;
        }
        if !changed {
            break;
        }
    }
    Ok(())
}

fn requires_numeric_grammar(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Class
            | SymbolKind::Attribute
            | SymbolKind::Method
            | SymbolKind::Value
            | SymbolKind::IdentifierBase
            | SymbolKind::EnumValue
    )
}

fn symbol_kind_name(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Class => "class",
        SymbolKind::Attribute => "attribute",
        SymbolKind::Method => "method",
        SymbolKind::Value => "value",
        SymbolKind::IdentifierBase => "identifier_base",
        SymbolKind::Macro => "macro",
        SymbolKind::PreprocessorGuard => "preprocessor_guard",
        SymbolKind::EnumValue => "enum_value",
    }
}

#[derive(Debug)]
struct Descriptor {
    class_id: String,
    superclass: String,
    source: Location,
}

fn parse_descriptors(
    path: &str,
    bytes: &[u8],
    output: &mut BTreeMap<String, Descriptor>,
) -> std::result::Result<(), String> {
    let text = String::from_utf8_lossy(bytes);
    let marker = "const struct __MUIBuiltinClass _MUI_";
    let mut offset = 0;
    while let Some(found) = text[offset..].find(marker) {
        let start = offset + found;
        let after = start + marker.len();
        let Some(name_end) = text[after..].find("_desc") else {
            return Err(format!("malformed class descriptor in {path}"));
        };
        let descriptor_name = &text[after..after + name_end];
        let Some(open_rel) = text[after + name_end..].find('{') else {
            return Err(format!(
                "class descriptor {descriptor_name} has no body in {path}"
            ));
        };
        let open = after + name_end + open_rel;
        let Some(close_rel) = text[open..].find("};") else {
            return Err(format!(
                "class descriptor {descriptor_name} is unterminated in {path}"
            ));
        };
        let body = strip_comments(&text[open + 1..open + close_rel]);
        let fields: Vec<_> = split_top_level(&body, ',')
            .into_iter()
            .map(|field| field.trim().to_owned())
            .filter(|field| !field.is_empty() && !field.starts_with('#'))
            .collect();
        if fields.len() < 2 {
            return Err(format!(
                "class descriptor {descriptor_name} lacks identity fields in {path}"
            ));
        }
        let class_id = fields[0]
            .lines()
            .last()
            .unwrap_or(&fields[0])
            .trim()
            .to_owned();
        let superclass = fields[1]
            .lines()
            .last()
            .unwrap_or(&fields[1])
            .trim()
            .to_owned();
        if !class_id.starts_with("MUIC_")
            || !(superclass.starts_with("MUIC_") || superclass == "ROOTCLASS")
        {
            return Err(format!(
                "class descriptor {descriptor_name} has unsupported identity `{class_id}`, `{superclass}` in {path}"
            ));
        }
        let line = text[..start].bytes().filter(|byte| *byte == b'\n').count() + 1;
        if output
            .insert(
                class_id.clone(),
                Descriptor {
                    class_id,
                    superclass,
                    source: Location {
                        path: path.to_owned(),
                        line,
                    },
                },
            )
            .is_some()
        {
            return Err(format!("duplicate class descriptor for {descriptor_name}"));
        }
        offset = open + close_rel + 2;
    }
    Ok(())
}

fn build_classes(
    abi: &str,
    symbols: &[Symbol],
    mut descriptors: BTreeMap<String, Descriptor>,
    overrides: &Overrides,
) -> std::result::Result<Vec<Class>, String> {
    let mut classes = Vec::new();
    for symbol in symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Class)
    {
        let class_id = match &symbol.evaluated {
            Some(Evaluated::String(value)) => value.clone(),
            _ => {
                return Err(format!(
                    "class {} does not have a string class ID at {}:{}",
                    symbol.name, symbol.source.path, symbol.source.line
                ));
            }
        };
        if let Some(descriptor) = descriptors.remove(&symbol.name) {
            if descriptor.class_id != symbol.name {
                return Err(format!("descriptor identity differs for {}", symbol.name));
            }
            classes.push(Class {
                abi: abi.to_owned(),
                name: symbol.name.clone(),
                class_id,
                superclass: descriptor.superclass,
                superclass_source: descriptor.source,
                override_reason: None,
                visibility: symbol.visibility,
                source: symbol.source.clone(),
            });
            continue;
        }
        let Some(item) = overrides
            .superclasses
            .iter()
            .find(|item| item.class == symbol.name)
        else {
            return Err(format!(
                "{} has no class descriptor or reviewed superclass override",
                symbol.name
            ));
        };
        classes.push(Class {
            abi: abi.to_owned(),
            name: symbol.name.clone(),
            class_id,
            superclass: item.superclass.clone(),
            superclass_source: Location {
                path: OVERRIDES.to_owned(),
                line: 1,
            },
            override_reason: Some(item.reason.clone()),
            visibility: symbol.visibility,
            source: symbol.source.clone(),
        });
    }
    Ok(classes)
}

fn parse_access(comment: &str) -> Option<Access> {
    for raw in comment.split_whitespace() {
        let marker = raw
            .trim_matches(|character: char| !character.is_ascii_alphabetic() && character != '.');
        if marker.len() != 3 {
            continue;
        }
        let bytes = marker.as_bytes();
        let valid = matches!(bytes[0].to_ascii_lowercase(), b'i' | b'.')
            && matches!(bytes[1].to_ascii_lowercase(), b's' | b'.')
            && matches!(bytes[2].to_ascii_lowercase(), b'g' | b'.');
        if valid && bytes.iter().any(|byte| *byte != b'.') {
            return Some(Access {
                init: bytes[0].eq_ignore_ascii_case(&b'i'),
                set: bytes[1].eq_ignore_ascii_case(&b's'),
                get: bytes[2].eq_ignore_ascii_case(&b'g'),
                marker: marker.to_owned(),
            });
        }
    }
    None
}

fn type_after_access(comment: &str, marker: &str) -> Option<String> {
    let (_, rest) = comment.split_once(marker)?;
    let value = rest.split('-').next().unwrap_or(rest).trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_version(comment: &str) -> Option<u32> {
    let bytes = comment.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'V' && bytes[index] != b'v' {
            continue;
        }
        if index > 0 && bytes[index - 1].is_ascii_alphanumeric() {
            continue;
        }
        let mut end = index + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > index + 1 {
            return comment[index + 1..end].parse().ok();
        }
    }
    None
}

fn parse_string_literal(expression: &str) -> Option<String> {
    let expression = expression.trim();
    if expression.len() >= 2 && expression.starts_with('"') && expression.ends_with('"') {
        serde_json::from_str(expression).ok()
    } else {
        None
    }
}

#[derive(Debug)]
struct NumericResult {
    value: Option<i128>,
    unresolved: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Number(i128),
    Identifier(String),
    Left,
    Right,
    Operator(&'static str),
}

fn parse_numeric(
    expression: &str,
    values: &BTreeMap<String, i128>,
) -> std::result::Result<NumericResult, String> {
    let tokens = tokenize(expression)?;
    if tokens.is_empty() {
        return Err("empty expression".to_owned());
    }
    let mut parser = ExpressionParser {
        tokens: &tokens,
        position: 0,
        values,
        unresolved: BTreeSet::new(),
    };
    let value = parser.parse_binary(0)?;
    if parser.position != tokens.len() {
        return Err(format!("unexpected token {:?}", tokens[parser.position]));
    }
    Ok(NumericResult {
        value,
        unresolved: parser.unresolved,
    })
}

fn tokenize(expression: &str) -> std::result::Result<Vec<Token>, String> {
    let bytes = expression.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
        } else if byte == b'(' {
            output.push(Token::Left);
            index += 1;
        } else if byte == b')' {
            output.push(Token::Right);
            index += 1;
        } else if byte.is_ascii_digit() {
            let start = index;
            if byte == b'0' && index + 1 < bytes.len() && matches!(bytes[index + 1], b'x' | b'X') {
                index += 2;
                let digits = index;
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index += 1;
                }
                if index == digits {
                    return Err("hex literal lacks digits".to_owned());
                }
                let value =
                    i128::from_str_radix(&expression[digits..index], 16).map_err(display)?;
                output.push(Token::Number(value));
            } else {
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                let value = expression[start..index].parse::<i128>().map_err(display)?;
                output.push(Token::Number(value));
            }
            while index < bytes.len() && matches!(bytes[index], b'u' | b'U' | b'l' | b'L') {
                index += 1;
            }
        } else if byte == b'\'' {
            if index + 2 >= bytes.len() || bytes[index + 2] != b'\'' {
                return Err("only single-byte character literals are supported".to_owned());
            }
            output.push(Token::Number(i128::from(bytes[index + 1])));
            index += 3;
        } else if byte == b'_' || byte.is_ascii_alphabetic() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index] == b'_' || bytes[index].is_ascii_alphanumeric())
            {
                index += 1;
            }
            output.push(Token::Identifier(expression[start..index].to_owned()));
        } else {
            let (operator, width) = if index + 1 < bytes.len() {
                match &expression[index..index + 2] {
                    "<<" => ("<<", 2),
                    ">>" => (">>", 2),
                    _ => ("", 0),
                }
            } else {
                ("", 0)
            };
            if width > 0 {
                output.push(Token::Operator(operator));
                index += width;
                continue;
            }
            let operator = match byte {
                b'|' => "|",
                b'&' => "&",
                b'^' => "^",
                b'+' => "+",
                b'-' => "-",
                b'*' => "*",
                b'/' => "/",
                b'%' => "%",
                b'~' => "~",
                _ => return Err(format!("unsupported byte `{}`", char::from(byte))),
            };
            output.push(Token::Operator(operator));
            index += 1;
        }
    }
    Ok(output)
}

struct ExpressionParser<'a> {
    tokens: &'a [Token],
    position: usize,
    values: &'a BTreeMap<String, i128>,
    unresolved: BTreeSet<String>,
}

impl ExpressionParser<'_> {
    fn parse_binary(&mut self, minimum: u8) -> std::result::Result<Option<i128>, String> {
        let mut left = self.parse_unary()?;
        loop {
            let Some(Token::Operator(operator)) = self.tokens.get(self.position) else {
                break;
            };
            let Some((precedence, operation)) = binary_operator(operator) else {
                break;
            };
            if precedence < minimum {
                break;
            }
            self.position += 1;
            let right = self.parse_binary(precedence + 1)?;
            left = match (left, right) {
                (Some(left), Some(right)) => Some(operation(left, right)?),
                _ => None,
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> std::result::Result<Option<i128>, String> {
        if let Some(Token::Operator(operator @ ("+" | "-" | "~"))) = self.tokens.get(self.position)
        {
            let operator = *operator;
            self.position += 1;
            return Ok(self.parse_unary()?.map(|value| match operator {
                "+" => value,
                "-" => -value,
                "~" => !value,
                _ => unreachable!(),
            }));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> std::result::Result<Option<i128>, String> {
        match self.tokens.get(self.position) {
            Some(Token::Number(value)) => {
                self.position += 1;
                Ok(Some(*value))
            }
            Some(Token::Identifier(name)) => {
                self.position += 1;
                if let Some(value) = self.values.get(name) {
                    Ok(Some(*value))
                } else {
                    self.unresolved.insert(name.clone());
                    Ok(None)
                }
            }
            Some(Token::Left) if self.is_cast() => {
                self.skip_cast();
                self.parse_unary()
            }
            Some(Token::Left) => {
                self.position += 1;
                let value = self.parse_binary(0)?;
                if self.tokens.get(self.position) != Some(&Token::Right) {
                    return Err("missing closing parenthesis".to_owned());
                }
                self.position += 1;
                Ok(value)
            }
            token => Err(format!("expected numeric operand, found {token:?}")),
        }
    }

    fn is_cast(&self) -> bool {
        let Some(Token::Identifier(name)) = self.tokens.get(self.position + 1) else {
            return false;
        };
        if !is_c_type(name) {
            return false;
        }
        match self.tokens.get(self.position + 2) {
            Some(Token::Right) => true,
            Some(Token::Operator("*")) => self.tokens.get(self.position + 3) == Some(&Token::Right),
            _ => false,
        }
    }

    fn skip_cast(&mut self) {
        self.position += if self.tokens.get(self.position + 2) == Some(&Token::Right) {
            3
        } else {
            4
        };
    }
}

type BinaryOperation = fn(i128, i128) -> std::result::Result<i128, String>;

fn binary_operator(operator: &str) -> Option<(u8, BinaryOperation)> {
    Some(match operator {
        "|" => (1, |left, right| Ok(left | right)),
        "^" => (2, |left, right| Ok(left ^ right)),
        "&" => (3, |left, right| Ok(left & right)),
        "<<" => (4, |left, right| shift(left, right, true)),
        ">>" => (4, |left, right| shift(left, right, false)),
        "+" => (5, |left, right| Ok(left + right)),
        "-" => (5, |left, right| Ok(left - right)),
        "*" => (6, |left, right| Ok(left * right)),
        "/" => (6, |left, right| {
            (right != 0)
                .then(|| left / right)
                .ok_or_else(|| "division by zero".to_owned())
        }),
        "%" => (6, |left, right| {
            (right != 0)
                .then(|| left % right)
                .ok_or_else(|| "division by zero".to_owned())
        }),
        _ => return None,
    })
}

fn shift(left: i128, right: i128, leftward: bool) -> std::result::Result<i128, String> {
    let amount = u32::try_from(right).map_err(display)?;
    if amount >= 128 {
        return Err("shift count is out of range".to_owned());
    }
    Ok(if leftward {
        left << amount
    } else {
        left >> amount
    })
}

fn is_c_type(name: &str) -> bool {
    matches!(
        name,
        "APTR"
            | "BOOL"
            | "BYTE"
            | "CHAR"
            | "IPTR"
            | "LONG"
            | "Object"
            | "SHORT"
            | "STRPTR"
            | "Tag"
            | "UBYTE"
            | "ULONG"
            | "UWORD"
            | "WORD"
            | "int"
            | "long"
            | "unsigned"
            | "void"
    )
}

fn matching_paren(value: &str, open: usize) -> Option<usize> {
    let mut depth = 0;
    for (index, byte) in value.bytes().enumerate().skip(open) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level(value: &str, separator: char) -> Vec<&str> {
    let mut output = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        match character {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            _ if character == separator && depth == 0 => {
                output.push(&value[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    output.push(&value[start..]);
    output
}

fn block_comments(value: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("/*") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("*/") else {
            break;
        };
        output.push(after[..end].trim().to_owned());
        rest = &after[end + 2..];
    }
    output
}

fn strip_comments(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    loop {
        let block = rest.find("/*");
        let line = rest.find("//");
        match (block, line) {
            (None, None) => {
                output.push_str(rest);
                break;
            }
            (_, Some(line)) if block.is_none_or(|block| line < block) => {
                output.push_str(&rest[..line]);
                break;
            }
            (Some(block), _) => {
                output.push_str(&rest[..block]);
                let after = &rest[block + 2..];
                let Some(end) = after.find("*/") else {
                    break;
                };
                output.push(' ');
                rest = &after[end + 2..];
            }
            _ => unreachable!(),
        }
    }
    output
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'_' | b'a'..=b'z' | b'A'..=b'Z'))
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn normalize_relative(value: &str) -> std::result::Result<String, String> {
    let mut output = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(value) => output.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    return Err(format!("source path escapes its root: {value}"));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("source path must be relative: {value}"));
            }
        }
    }
    output
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .ok_or_else(|| "source path must be UTF-8".to_owned())
}

fn join_source_path(root: &str, relative: &str) -> std::result::Result<String, String> {
    normalize_relative(&format!("{}/{relative}", root.trim_end_matches('/')))
}

fn git_file(checkout: &Path, commit: &str, path: &str) -> std::result::Result<Vec<u8>, String> {
    git_file_optional(checkout, commit, path)?.ok_or_else(|| {
        format!(
            "pinned source lacks {}:{} in {}",
            commit,
            path,
            checkout.display()
        )
    })
}

fn git_file_optional(
    checkout: &Path,
    commit: &str,
    path: &str,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let object = format!("{commit}:{path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["show", &object])
        .output()
        .map_err(display)?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else {
        Ok(None)
    }
}

fn git_output<const N: usize>(
    checkout: &Path,
    arguments: [&str; N],
) -> std::result::Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(arguments)
        .output()
        .map_err(display)?;
    if !output.status.success() {
        return Err(format!(
            "git source query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn emit(path: &Path, expected: &[u8], check: bool) -> std::result::Result<(), String> {
    if check {
        let actual =
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if actual != expected {
            return Err(format!("generated MUI model is stale: {}", path.display()));
        }
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(display)?;
        }
        fs::write(path, expected).map_err(display)?;
    }
    Ok(())
}

fn json_bytes(value: &impl Serialize) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(display)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn symbol_order(left: &Symbol, right: &Symbol) -> std::cmp::Ordering {
    (&left.abi, &left.name, &left.source.path, left.source.line).cmp(&(
        &right.abi,
        &right.name,
        &right.source.path,
        right.source.line,
    ))
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_observed_identifier_arithmetic_and_casts() {
        let values = BTreeMap::from([("MUIB_MUI".to_owned(), 0x0042_0000)]);
        let result = parse_numeric("((ULONG)(MUIB_MUI | 0x00003ba6))", &values).unwrap();
        assert_eq!(result.value, Some(0x0042_3ba6));
        assert!(result.unresolved.is_empty());
    }

    #[test]
    fn preserves_unresolved_external_identifiers() {
        let result = parse_numeric("TAG_USER | 0x00420000", &BTreeMap::new()).unwrap();
        assert_eq!(result.value, None);
        assert_eq!(result.unresolved, BTreeSet::from(["TAG_USER".to_owned()]));
    }

    #[test]
    fn unsupported_conditional_expression_fails_explicitly() {
        let error = parse_numeric("MUIB_MUI ? 1 : 2", &BTreeMap::new()).unwrap_err();
        assert!(error.contains("unsupported byte `?`"));
    }

    #[test]
    fn stale_output_is_rejected() {
        let root = std::env::temp_dir().join(format!("ami-rust-mui-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let path = root.join("api.json");
        fs::write(&path, b"old\n").unwrap();
        let error = emit(&path, b"new\n", true).unwrap_err();
        assert!(error.contains("stale"));
        fs::remove_dir_all(root).unwrap();
    }
}
