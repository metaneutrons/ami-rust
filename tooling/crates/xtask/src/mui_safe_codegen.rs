use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Outputs {
    pub classes: String,
    pub attributes: String,
    pub methods: String,
    pub values: String,
    pub manifest: Vec<u8>,
    pub documentation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    schema: String,
    generator: String,
    sources: Vec<serde_json::Value>,
    statistics: BTreeMap<String, usize>,
    classes: Vec<ModelClass>,
    symbols: Vec<ModelSymbol>,
    message_structures: Vec<ModelMessage>,
    private_markers: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelClass {
    abi: String,
    name: String,
    class_id: String,
    superclass: String,
    superclass_source: Location,
    override_reason: Option<String>,
    visibility: String,
    source: Location,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelSymbol {
    abi: String,
    name: String,
    kind: String,
    visibility: String,
    classification: String,
    expression: Option<String>,
    parameters: Vec<String>,
    evaluated: Option<Evaluated>,
    unresolved_identifiers: Vec<String>,
    version: Option<u32>,
    access: Option<Access>,
    c_type: Option<String>,
    source: Location,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelMessage {
    abi: String,
    name: String,
    visibility: String,
    fields: Vec<serde_json::Value>,
    source: Location,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Evaluated {
    Integer(String),
    String(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    init: bool,
    set: bool,
    get: bool,
    marker: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Location {
    path: String,
    line: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SafeOverrides {
    schema: String,
    string_arrays: Vec<StringArrayOverride>,
    object_attributes: Vec<ObjectAttributeOverride>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StringArrayOverride {
    attribute: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectAttributeOverride {
    attribute: String,
    class: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Abi1,
    Abi11,
    Both,
}

impl Availability {
    fn from_abis<'a>(abis: impl Iterator<Item = &'a str>) -> Result<Self, String> {
        let set: BTreeSet<_> = abis.collect();
        match (set.contains("abi1"), set.contains("abi11"), set.len()) {
            (true, true, 2) => Ok(Self::Both),
            (true, false, 1) => Ok(Self::Abi1),
            (false, true, 1) => Ok(Self::Abi11),
            _ => Err(format!("unsupported ABI set: {set:?}")),
        }
    }

    fn cfg(self) -> Option<&'static str> {
        match self {
            Self::Abi1 => Some(
                "#[cfg(any(not(target_os = \"aros\"), target_abi = \"\", target_abi = \"abi1\"))]",
            ),
            Self::Abi11 => Some("#[cfg(all(target_os = \"aros\", target_abi = \"abi11\"))]"),
            Self::Both => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Abi1 => "ABI1",
            Self::Abi11 => "ABI11",
            Self::Both => "ABI1 + ABI11",
        }
    }
}

#[derive(Clone)]
struct ClassSpec {
    raw: String,
    rust: String,
    id: String,
    superclass: String,
    availability: Availability,
    source: Location,
}

#[derive(Clone)]
struct SymbolSpec {
    raw: String,
    rust: String,
    class: String,
    availability: Availability,
    source: Location,
    c_type: Option<String>,
    access: Option<Access>,
    parameters: Vec<String>,
    evaluated: Option<Evaluated>,
}

#[derive(Clone)]
struct EnumVariant {
    raw: String,
    rust: String,
    availability: Availability,
}

#[derive(Clone)]
struct EnumSpec {
    rust: String,
    variants: Vec<EnumVariant>,
}

#[derive(Serialize)]
struct Manifest {
    schema: &'static str,
    generator: &'static str,
    model_sha256: String,
    overrides_sha256: String,
    statistics: BTreeMap<String, usize>,
    classes: Vec<ClassRecord>,
    attributes: Vec<AttributeRecord>,
    methods: Vec<MethodRecord>,
    values: Vec<ValueRecord>,
}

#[derive(Serialize)]
struct ClassRecord {
    name: String,
    rust: String,
    availability: Availability,
    superclass: String,
    construction: String,
}

#[derive(Serialize)]
struct AttributeRecord {
    name: String,
    rust: String,
    class: String,
    availability: Availability,
    c_type: Option<String>,
    access: String,
    value: String,
    init: String,
    set: String,
    get: String,
}

#[derive(Serialize)]
struct MethodRecord {
    name: String,
    rust: String,
    class: String,
    availability: Availability,
    classification: String,
    message: Option<String>,
}

#[derive(Serialize)]
struct ValueRecord {
    name: String,
    availability: Availability,
    classification: String,
    enum_type: Option<String>,
}

pub(super) fn generate(model_bytes: &[u8], override_bytes: &[u8]) -> Result<Outputs, String> {
    let model: Model = serde_json::from_slice(model_bytes).map_err(display)?;
    if model.schema != "ami-rust-mui-api-model-v1" {
        return Err("safe generator requires the v1 MUI model".to_owned());
    }
    let overrides: SafeOverrides = serde_json::from_slice(override_bytes).map_err(display)?;
    if overrides.schema != "ami-rust-mui-safe-overrides-v1" {
        return Err("safe generator requires the v1 safe overrides".to_owned());
    }
    consume_model_metadata(&model);

    let (string_arrays, object_attributes) = validate_overrides(&model, &overrides)?;
    let classes = collect_classes(&model)?;
    let class_map: BTreeMap<_, _> = classes
        .iter()
        .map(|item| (item.raw.clone(), item.clone()))
        .collect();
    let ancestors = build_ancestors(&class_map)?;
    let attributes = collect_symbols(&model, "attribute", "MUIA_", &classes)?;
    let methods = collect_symbols(&model, "method", "MUIM_", &classes)?;
    let values = collect_values(&model)?;
    let enums = build_enums(&attributes, &values)?;
    let messages = collect_messages(&model)?;

    let classes_code = normalized_source(generate_classes(&classes, &class_map, &ancestors)?);
    let (attributes_code, attribute_records) =
        generate_attributes(&attributes, &enums, &string_arrays, &object_attributes)?;
    let attributes_code = normalized_source(attributes_code);
    let (methods_code, method_records) = generate_methods(&methods, &messages)?;
    let methods_code = normalized_source(methods_code);
    let (values_code, value_records) = generate_values(&values, &enums);
    let values_code = normalized_source(values_code);

    let class_records: Vec<_> = classes
        .iter()
        .map(|item| ClassRecord {
            name: item.raw.clone(),
            rust: item.rust.clone(),
            availability: item.availability,
            superclass: item.superclass.clone(),
            construction: "safe_fallible".to_owned(),
        })
        .collect();
    let mut statistics = BTreeMap::new();
    statistics.insert("classes".to_owned(), class_records.len());
    statistics.insert("attributes".to_owned(), attribute_records.len());
    statistics.insert("methods".to_owned(), method_records.len());
    statistics.insert("values".to_owned(), value_records.len());
    statistics.insert("safe_enums".to_owned(), enums.len());
    let manifest = Manifest {
        schema: "ami-rust-mui-safe-api-v1",
        generator: env!("CARGO_PKG_VERSION"),
        model_sha256: sha256(model_bytes),
        overrides_sha256: sha256(override_bytes),
        statistics,
        classes: class_records,
        attributes: attribute_records,
        methods: method_records,
        values: value_records,
    };
    let documentation = generate_documentation(&manifest);
    let manifest = serde_json::to_vec_pretty(&manifest).map_err(display)?;

    Ok(Outputs {
        classes: classes_code,
        attributes: attributes_code,
        methods: methods_code,
        values: values_code,
        manifest,
        documentation,
    })
}

fn normalized_source(mut source: String) -> String {
    source.truncate(source.trim_end().len());
    source.push('\n');
    source
}

fn consume_model_metadata(model: &Model) {
    let _ = (
        &model.generator,
        &model.sources,
        &model.statistics,
        &model.private_markers,
    );
}

fn validate_overrides(
    model: &Model,
    overrides: &SafeOverrides,
) -> Result<(BTreeSet<String>, BTreeMap<String, String>), String> {
    let public_attributes: BTreeSet<_> = model
        .symbols
        .iter()
        .filter(|item| public_api(item, "attribute"))
        .map(|item| item.name.as_str())
        .collect();
    let mut names = BTreeSet::new();
    for item in &overrides.string_arrays {
        if item.reason.trim().is_empty() || !names.insert(item.attribute.clone()) {
            return Err("safe string-array overrides require unique names and reasons".to_owned());
        }
        if !public_attributes.contains(item.attribute.as_str()) {
            return Err(format!(
                "safe string-array override names unknown attribute {}",
                item.attribute
            ));
        }
    }
    let public_classes: BTreeSet<_> = model
        .classes
        .iter()
        .filter(|item| item.visibility == "public")
        .map(|item| item.name.as_str())
        .collect();
    let mut objects = BTreeMap::new();
    for item in &overrides.object_attributes {
        if item.reason.trim().is_empty()
            || objects
                .insert(item.attribute.clone(), item.class.clone())
                .is_some()
        {
            return Err("safe object overrides require unique names and reasons".to_owned());
        }
        if !public_attributes.contains(item.attribute.as_str()) {
            return Err(format!(
                "safe object override names unknown attribute {}",
                item.attribute
            ));
        }
        if !public_classes.contains(item.class.as_str()) {
            return Err(format!(
                "safe object override names unknown class {}",
                item.class
            ));
        }
    }
    Ok((names, objects))
}

fn collect_classes(model: &Model) -> Result<Vec<ClassSpec>, String> {
    let mut grouped: BTreeMap<&str, Vec<&ModelClass>> = BTreeMap::new();
    for item in &model.classes {
        if item.visibility == "public" {
            grouped.entry(&item.name).or_default().push(item);
        }
    }
    let mut output = Vec::new();
    let mut rust_names = BTreeMap::new();
    for (name, entries) in grouped {
        let first = entries[0];
        for entry in &entries {
            if entry.class_id != first.class_id
                || entry.superclass != first.superclass
                || entry.source.path != first.source.path
            {
                return Err(format!("class {name} differs between ABIs"));
            }
            let _ = (&entry.superclass_source, &entry.override_reason);
        }
        let rust = type_name(name, "MUIC_")?;
        reject_collision(&mut rust_names, &rust, name)?;
        output.push(ClassSpec {
            raw: name.to_owned(),
            rust,
            id: first.class_id.clone(),
            superclass: first.superclass.clone(),
            availability: Availability::from_abis(entries.iter().map(|item| item.abi.as_str()))?,
            source: first.source.clone(),
        });
    }
    Ok(output)
}

fn build_ancestors(
    classes: &BTreeMap<String, ClassSpec>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut output = BTreeMap::new();
    for class in classes.values() {
        let mut current = class.superclass.as_str();
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        while current != "ROOTCLASS" {
            if !seen.insert(current.to_owned()) {
                return Err(format!("class hierarchy cycle at {}", class.raw));
            }
            let parent = classes
                .get(current)
                .ok_or_else(|| format!("{} has unknown superclass {current}", class.raw))?;
            chain.push(parent.raw.clone());
            current = &parent.superclass;
        }
        output.insert(class.raw.clone(), chain);
    }
    Ok(output)
}

fn collect_symbols(
    model: &Model,
    kind: &str,
    prefix: &str,
    classes: &[ClassSpec],
) -> Result<Vec<SymbolSpec>, String> {
    let mut grouped: BTreeMap<&str, Vec<&ModelSymbol>> = BTreeMap::new();
    for item in &model.symbols {
        if public_api(item, kind) {
            grouped.entry(&item.name).or_default().push(item);
        }
    }
    let mut output = Vec::new();
    let mut rust_names = BTreeMap::new();
    for (name, entries) in grouped {
        let first = entries[0];
        for entry in &entries {
            if entry.source.path != first.source.path
                || entry.c_type != first.c_type
                || access_marker(entry.access.as_ref()) != access_marker(first.access.as_ref())
            {
                return Err(format!("symbol {name} differs between ABIs"));
            }
            let _ = (
                &entry.expression,
                &entry.unresolved_identifiers,
                entry.version,
            );
        }
        let class = class_for_source(name, prefix, &first.source.path, classes)?;
        let mut rust = type_name(name, prefix)?;
        if rust_names.contains_key(&rust) {
            rust.push_str("For");
            rust.push_str(&type_name(&class, "MUIC_")?);
        }
        reject_collision(&mut rust_names, &rust, name)?;
        output.push(SymbolSpec {
            raw: name.to_owned(),
            rust,
            class,
            availability: Availability::from_abis(entries.iter().map(|item| item.abi.as_str()))?,
            source: first.source.clone(),
            c_type: first.c_type.clone(),
            access: first.access.clone(),
            parameters: first.parameters.clone(),
            evaluated: first.evaluated.clone(),
        });
    }
    Ok(output)
}

fn collect_values(model: &Model) -> Result<Vec<SymbolSpec>, String> {
    let mut grouped: BTreeMap<&str, Vec<&ModelSymbol>> = BTreeMap::new();
    for item in &model.symbols {
        if item.visibility == "public"
            && item.classification == "api"
            && (item.kind == "value" || item.kind == "enum_value")
        {
            grouped.entry(&item.name).or_default().push(item);
        }
    }
    let mut output = Vec::new();
    for (name, entries) in grouped {
        let first = entries[0];
        for entry in &entries {
            if entry.parameters != first.parameters || integer(entry) != integer(first) {
                return Err(format!("value {name} differs between ABIs"));
            }
        }
        output.push(SymbolSpec {
            raw: name.to_owned(),
            rust: type_name(name, "")?,
            class: String::new(),
            availability: Availability::from_abis(entries.iter().map(|item| item.abi.as_str()))?,
            source: first.source.clone(),
            c_type: None,
            access: None,
            parameters: first.parameters.clone(),
            evaluated: first.evaluated.clone(),
        });
    }
    Ok(output)
}

fn collect_messages(model: &Model) -> Result<BTreeMap<String, Availability>, String> {
    let mut grouped: BTreeMap<&str, Vec<&ModelMessage>> = BTreeMap::new();
    for item in &model.message_structures {
        if item.visibility == "public" {
            grouped.entry(&item.name).or_default().push(item);
        }
    }
    let mut output = BTreeMap::new();
    for (name, entries) in grouped {
        let first = entries[0];
        for entry in &entries {
            if entry.source.path != first.source.path || entry.fields.len() != first.fields.len() {
                return Err(format!("message {name} differs structurally between ABIs"));
            }
        }
        output.insert(
            name.to_owned(),
            Availability::from_abis(entries.iter().map(|item| item.abi.as_str()))?,
        );
    }
    Ok(output)
}

fn build_enums(
    attributes: &[SymbolSpec],
    values: &[SymbolSpec],
) -> Result<BTreeMap<String, EnumSpec>, String> {
    let mut output = BTreeMap::new();
    for attribute in attributes {
        let value_prefix = format!("MUIV{}_", &attribute.raw[4..]);
        let candidates = values
            .iter()
            .filter(|item| item.raw.starts_with(&value_prefix) && item.parameters.is_empty());
        let mut numbers = BTreeSet::new();
        let mut variants = Vec::new();
        let mut rust_names = BTreeMap::new();
        for item in candidates {
            let Some(number) = evaluated_integer(item) else {
                continue;
            };
            if !numbers.insert(number) {
                continue;
            }
            let suffix = &item.raw[value_prefix.len()..];
            if suffix.ends_with("Count") {
                continue;
            }
            let rust = safe_variant_name(&pascal(suffix));
            reject_collision(&mut rust_names, &rust, &item.raw)?;
            variants.push(EnumVariant {
                raw: item.raw.clone(),
                rust,
                availability: item.availability,
            });
        }
        if variants.len() >= 2 {
            output.insert(
                attribute.raw.clone(),
                EnumSpec {
                    rust: format!("{}Value", attribute.rust),
                    variants,
                },
            );
        }
    }
    Ok(output)
}

fn generate_classes(
    classes: &[ClassSpec],
    class_map: &BTreeMap<String, ClassSpec>,
    ancestors: &BTreeMap<String, Vec<String>>,
) -> Result<String, String> {
    let mut output = String::from(
        "// Generated by cargo xtask generate mui. Do not edit by hand.\n\
         #![allow(unexpected_cfgs)]\n\
         //! Complete public standard MUI class and inheritance surface.\n\n\
         use crate::class::{self, ApplicationParent, Class, FamilyParent, GroupParent, IsA, NoParent, ParentSupport, WindowParent};\n\n\
         macro_rules! class {\n\
             ($name:ident, $id:literal, $role:ty, $doc:literal) => {\n\
                 #[doc = $doc]\n\
                 #[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
                 pub struct $name;\n\n\
                 impl class::sealed::Class for $name {}\n\n\
                 impl Class for $name {\n\
                     const ID: &'static core::ffi::CStr = $id;\n\
                     type ParentRole = $role;\n\
                 }\n\
             };\n\
         }\n\n",
    );
    for item in classes {
        push_cfg(&mut output, item.availability);
        output.push_str(&format!(
            "class!({}, c{:?}, {}, {:?});\n\n",
            item.rust,
            item.id,
            parent_role(item, ancestors),
            format!(
                "{} from {}:{}.",
                item.raw, item.source.path, item.source.line
            )
        ));
    }
    for item in classes {
        let chain = ancestors
            .get(&item.raw)
            .ok_or_else(|| format!("missing ancestors for {}", item.raw))?;
        for raw_parent in chain {
            let parent = class_map
                .get(raw_parent)
                .ok_or_else(|| format!("missing class {raw_parent}"))?;
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl IsA<{}> for {} {{}}\n",
                parent.rust, item.rust
            ));
        }
    }
    output.push('\n');

    for item in classes {
        let application_attachment = if item.raw == "MUIC_Menustrip" {
            Some("class::Attachment::ApplicationMenustrip")
        } else if is_a(&item.raw, "MUIC_Window", ancestors) {
            Some("class::Attachment::ApplicationWindow")
        } else {
            None
        };
        if let Some(attachment) = application_attachment {
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl ParentSupport<{}> for ApplicationParent {{ const ATTACHMENT: class::Attachment = {}; }}\n",
                item.rust, attachment
            ));
        }
        if is_a(&item.raw, "MUIC_Area", ancestors) {
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl ParentSupport<{}> for WindowParent {{ const ATTACHMENT: class::Attachment = class::Attachment::WindowRoot; }}\n",
                item.rust
            ));
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl ParentSupport<{}> for GroupParent {{ const ATTACHMENT: class::Attachment = class::Attachment::GroupChild; }}\n",
                item.rust
            ));
        }
        if is_a(&item.raw, "MUIC_Family", ancestors) {
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl ParentSupport<{}> for FamilyParent {{ const ATTACHMENT: class::Attachment = class::Attachment::FamilyChild; }}\n",
                item.rust
            ));
        }
    }
    Ok(output)
}

fn generate_attributes(
    attributes: &[SymbolSpec],
    enums: &BTreeMap<String, EnumSpec>,
    string_arrays: &BTreeSet<String>,
    object_attributes: &BTreeMap<String, String>,
) -> Result<(String, Vec<AttributeRecord>), String> {
    let mut output = String::from(
        "// Generated by cargo xtask generate mui. Do not edit by hand.\n\
         #![allow(unexpected_cfgs)]\n\
         //! Complete typed and classified public MUI attribute surface.\n\n\
         use crate::{Attribute, BuildAttribute, Class, GetAttribute, IsA, RawAttribute, RawBuildAttribute, RawGetAttribute, RawSetAttribute, SetAttribute, attribute, value};\n\n",
    );
    let mut records = Vec::new();
    for item in attributes {
        let base = type_name(&item.class, "MUIC_")?;
        let unavailable = Access {
            init: false,
            set: false,
            get: false,
            marker: "---".to_owned(),
        };
        let access = item.access.as_ref().unwrap_or(&unavailable);
        let value = attribute_value(item, enums, string_arrays, object_attributes);
        let safe = value.is_some();
        let value_name = value.clone().unwrap_or_else(|| "raw_word".to_owned());
        let c_type_doc = item
            .c_type
            .as_deref()
            .unwrap_or("untyped")
            .replace('[', "\\[")
            .replace(']', "\\]");
        push_cfg(&mut output, item.availability);
        output.push_str(&format!(
            "/// {} ({}; {}) from {}:{}.\n#[derive(Clone, Copy, Debug)]\npub struct {};\n\n",
            item.raw,
            c_type_doc,
            access.marker,
            item.source.path,
            item.source.line,
            item.rust
        ));
        generate_raw_attribute_impls(&mut output, item, &base, access);
        if let Some(kind) = value {
            generate_safe_attribute_impls(&mut output, item, &base, access, &kind);
        }
        records.push(AttributeRecord {
            name: item.raw.clone(),
            rust: item.rust.clone(),
            class: item.class.clone(),
            availability: item.availability,
            c_type: item.c_type.clone(),
            access: access.marker.clone(),
            value: value_name,
            init: operation_classification(access.init, safe).to_owned(),
            set: operation_classification(access.set, safe).to_owned(),
            get: operation_classification(
                access.get,
                safe && !string_arrays.contains(&item.raw)
                    && !object_attributes.contains_key(&item.raw),
            )
            .to_owned(),
        });
    }
    Ok((output, records))
}

fn generate_raw_attribute_impls(
    output: &mut String,
    item: &SymbolSpec,
    base: &str,
    access: &Access,
) {
    let bound = format!("C: Class + IsA<crate::classes::{base}>");
    push_cfg(output, item.availability);
    output.push_str(&format!(
        "impl<C> attribute::sealed::RawAttribute<C> for {} where {} {{}}\n",
        item.rust, bound
    ));
    push_cfg(output, item.availability);
    output.push_str(&format!(
        "impl<C> RawAttribute<C> for {} where {} {{ const ID: u32 = aros_mui_sys::{}; const C_TYPE: &'static str = {:?}; }}\n",
        item.rust,
        bound,
        item.raw,
        item.c_type.as_deref().unwrap_or("untyped")
    ));
    for (enabled, sealed, public) in [
        (access.init, "RawBuild", "RawBuildAttribute"),
        (access.set, "RawSet", "RawSetAttribute"),
        (access.get, "RawGet", "RawGetAttribute"),
    ] {
        if enabled {
            push_cfg(output, item.availability);
            output.push_str(&format!(
                "impl<C> attribute::sealed::{sealed}<C> for {} where {} {{}}\n",
                item.rust, bound
            ));
            push_cfg(output, item.availability);
            output.push_str(&format!(
                "impl<C> {public}<C> for {} where {} {{}}\n",
                item.rust, bound
            ));
        }
    }
    output.push('\n');
}

fn generate_safe_attribute_impls(
    output: &mut String,
    item: &SymbolSpec,
    base: &str,
    access: &Access,
    value: &str,
) {
    let bound = format!("C: Class + IsA<crate::classes::{base}>");
    push_cfg(output, item.availability);
    output.push_str(&format!(
        "impl<C> attribute::sealed::Attribute<C> for {} where {} {{}}\n",
        item.rust, bound
    ));
    push_cfg(output, item.availability);
    output.push_str(&format!(
        "impl<C> Attribute<C> for {} where {} {{ type Value = {}; const ID: u32 = aros_mui_sys::{}; }}\n",
        item.rust, bound, value, item.raw
    ));
    for (enabled, sealed, public) in [
        (access.init, "Build", "BuildAttribute"),
        (access.set, "Set", "SetAttribute"),
        (
            access.get && value != "value::StringArray" && !value.starts_with("value::Object<"),
            "Get",
            "GetAttribute",
        ),
    ] {
        if enabled {
            push_cfg(output, item.availability);
            output.push_str(&format!(
                "impl<C> attribute::sealed::{sealed}<C> for {} where {} {{}}\n",
                item.rust, bound
            ));
            push_cfg(output, item.availability);
            output.push_str(&format!(
                "impl<C> {public}<C> for {} where {} {{}}\n",
                item.rust, bound
            ));
        }
    }
    output.push('\n');
}

fn generate_methods(
    methods: &[SymbolSpec],
    messages: &BTreeMap<String, Availability>,
) -> Result<(String, Vec<MethodRecord>), String> {
    let mut output = String::from(
        "// Generated by cargo xtask generate mui. Do not edit by hand.\n\
         #![allow(unexpected_cfgs)]\n\
         //! Complete classified public MUI method surface.\n\n\
         pub use crate::method::NoNotifySet;\n\
         use crate::{Class, IsA, RawMethod, method};\n\n",
    );
    let mut records = Vec::new();
    for item in methods {
        let base = type_name(&item.class, "MUIC_")?;
        let marker = if item.raw == "MUIM_NoNotifySet" {
            "NoNotifySetRaw".to_owned()
        } else {
            item.rust.clone()
        };
        let message = format!("MUIP_{}", &item.raw[5..]);
        let has_message = messages.contains_key(&message);
        push_cfg(&mut output, item.availability);
        output.push_str(&format!(
            "/// {} from {}:{}; {}.\n#[derive(Clone, Copy, Debug)]\npub struct {};\n\n",
            item.raw,
            item.source.path,
            item.source.line,
            if has_message {
                "typed unsafe message dispatch"
            } else {
                "raw-only dispatch"
            },
            marker
        ));
        if has_message {
            let bound = format!("C: Class + IsA<crate::classes::{base}>");
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl<C> method::sealed::RawMethod<C> for {marker} where {bound} {{}}\n"
            ));
            push_cfg(&mut output, item.availability);
            output.push_str(&format!(
                "impl<C> RawMethod<C> for {marker} where {bound} {{ type Message = aros_mui_sys::{message}; const ID: u32 = aros_mui_sys::{}; }}\n\n",
                item.raw
            ));
        }
        records.push(MethodRecord {
            name: item.raw.clone(),
            rust: marker,
            class: item.class.clone(),
            availability: item.availability,
            classification: if item.raw == "MUIM_NoNotifySet" {
                "safe_equivalent".to_owned()
            } else if has_message {
                "typed_unsafe".to_owned()
            } else {
                "raw".to_owned()
            },
            message: has_message.then_some(message),
        });
    }
    Ok((output, records))
}

fn generate_values(
    values: &[SymbolSpec],
    enums: &BTreeMap<String, EnumSpec>,
) -> (String, Vec<ValueRecord>) {
    let mut output = String::from(
        "// Generated by cargo xtask generate mui. Do not edit by hand.\n\
         #![allow(unexpected_cfgs)]\n\
         #![allow(non_upper_case_globals)]\n\
         #![allow(clippy::unnecessary_cast)]\n\
         //! Typed enum groups and the complete raw public value surface.\n\n\
         use crate::MuiEnum;\n\n",
    );
    let mut safe_values = BTreeMap::new();
    for spec in enums.values() {
        output.push_str(&format!(
            "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum {} {{\n",
            spec.rust
        ));
        for variant in &spec.variants {
            push_cfg_indented(&mut output, variant.availability, 4);
            output.push_str(&format!("    {},\n", variant.rust));
            safe_values.insert(variant.raw.clone(), spec.rust.clone());
        }
        output.push_str("}\n\n");
        output.push_str(&format!("impl MuiEnum for {} {{\n", spec.rust));
        output.push_str("    fn into_raw(self) -> isize {\n        match self {\n");
        for variant in &spec.variants {
            push_cfg_indented(&mut output, variant.availability, 12);
            output.push_str(&format!(
                "            Self::{} => aros_mui_sys::{} as isize,\n",
                variant.rust, variant.raw
            ));
        }
        output.push_str("        }\n    }\n\n");
        output.push_str("    fn from_raw(raw: isize) -> Option<Self> {\n        match raw {\n");
        for variant in &spec.variants {
            push_cfg_indented(&mut output, variant.availability, 12);
            output.push_str(&format!(
                "            value if value == aros_mui_sys::{} as isize => Some(Self::{}),\n",
                variant.raw, variant.rust
            ));
        }
        output.push_str("            _ => None,\n        }\n    }\n}\n\n");
    }
    output.push_str(
        "/// Raw constants and parameterized values that remain the explicit expert surface.\n\
         pub mod raw {\n",
    );
    let mut records = Vec::new();
    for item in values {
        push_cfg_indented(&mut output, item.availability, 4);
        output.push_str(&format!("    pub use aros_mui_sys::{};\n", item.raw));
        records.push(ValueRecord {
            name: item.raw.clone(),
            availability: item.availability,
            classification: if safe_values.contains_key(&item.raw) {
                "safe_enum".to_owned()
            } else {
                "raw".to_owned()
            },
            enum_type: safe_values.get(&item.raw).cloned(),
        });
    }
    output.push_str("}\n");
    (output, records)
}

fn generate_documentation(manifest: &Manifest) -> String {
    let mut output = String::from(
        "# Generated safe MUI API\n\n\
         This document is generated by cargo xtask generate mui from the pinned\n\
         canonical dual-ABI model. Do not edit it by hand. Safe operations are\n\
         available through aros-mui; typed_unsafe operations require an explicit\n\
         unsafe call with a generated marker and native message; raw operations\n\
         remain in aros-mui-sys.\n\n",
    );
    output.push_str("## Inventory\n\n");
    for (name, count) in &manifest.statistics {
        output.push_str(&format!("- {name}: {count}\n"));
    }
    output.push_str(
        "\n## Classes\n\n| Native | Rust | ABI | Superclass | Construction |\n\
         | --- | --- | --- | --- | --- |\n",
    );
    for item in &manifest.classes {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            item.name,
            item.rust,
            item.availability.label(),
            item.superclass,
            item.construction
        ));
    }
    output.push_str(
        "\n## Attributes\n\n| Native | Rust | Class | ABI | C type | Access | Init | Set | Get |\n\
         | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for item in &manifest.attributes {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            item.name,
            item.rust,
            item.class,
            item.availability.label(),
            item.c_type.as_deref().unwrap_or("untyped"),
            item.access,
            item.init,
            item.set,
            item.get
        ));
    }
    output.push_str(
        "\n## Methods\n\n| Native | Rust | Class | ABI | Classification | Message |\n\
         | --- | --- | --- | --- | --- | --- |\n",
    );
    for item in &manifest.methods {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            item.name,
            item.rust,
            item.class,
            item.availability.label(),
            item.classification,
            item.message.as_deref().unwrap_or("aros-mui-sys")
        ));
    }
    output.push_str(
        "\n## Values\n\n| Native | ABI | Classification | Safe enum |\n\
         | --- | --- | --- | --- |\n",
    );
    for item in &manifest.values {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            item.name,
            item.availability.label(),
            item.classification,
            item.enum_type.as_deref().unwrap_or("aros_mui::values::raw")
        ));
    }
    output
}

fn public_api(item: &ModelSymbol, kind: &str) -> bool {
    item.kind == kind && item.visibility == "public" && item.classification == "api"
}

fn class_for_source(
    symbol: &str,
    prefix: &str,
    path: &str,
    classes: &[ClassSpec],
) -> Result<String, String> {
    let candidates: Vec<_> = classes
        .iter()
        .filter(|item| item.source.path == path)
        .collect();
    if candidates.len() == 1 {
        return Ok(candidates[0].raw.clone());
    }
    let remainder = symbol
        .strip_prefix(prefix)
        .ok_or_else(|| format!("{symbol} lacks {prefix}"))?;
    let mut prefixed: Vec<_> = candidates
        .iter()
        .filter(|item| {
            let class = item.raw.strip_prefix("MUIC_").unwrap_or(&item.raw);
            remainder == class || remainder.starts_with(&format!("{class}_"))
        })
        .collect();
    prefixed.sort_by_key(|item| usize::MAX - item.raw.len());
    if let Some(item) = prefixed.first() {
        return Ok(item.raw.clone());
    }
    let stem = path
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".h"))
        .ok_or_else(|| format!("invalid class header path {path}"))?;
    candidates
        .into_iter()
        .find(|item| {
            item.raw
                .strip_prefix("MUIC_")
                .is_some_and(|name| name.eq_ignore_ascii_case(stem))
        })
        .map(|item| item.raw.clone())
        .ok_or_else(|| format!("cannot assign {symbol} from {path} to a class"))
}

fn parent_role(item: &ClassSpec, ancestors: &BTreeMap<String, Vec<String>>) -> &'static str {
    if item.raw == "MUIC_Application" {
        "ApplicationParent"
    } else if is_a(&item.raw, "MUIC_Window", ancestors) {
        "WindowParent"
    } else if is_a(&item.raw, "MUIC_Group", ancestors) {
        "GroupParent"
    } else if is_a(&item.raw, "MUIC_Family", ancestors) {
        "FamilyParent"
    } else {
        "NoParent"
    }
}

fn is_a(raw: &str, base: &str, ancestors: &BTreeMap<String, Vec<String>>) -> bool {
    raw == base
        || ancestors
            .get(raw)
            .is_some_and(|items| items.iter().any(|item| item == base))
}

fn attribute_value(
    item: &SymbolSpec,
    enums: &BTreeMap<String, EnumSpec>,
    string_arrays: &BTreeSet<String>,
    object_attributes: &BTreeMap<String, String>,
) -> Option<String> {
    if string_arrays.contains(&item.raw) {
        return Some("value::StringArray".to_owned());
    }
    if let Some(spec) = enums.get(&item.raw) {
        return Some(format!("value::Enumeration<crate::values::{}>", spec.rust));
    }
    if let Some(class) = object_attributes.get(&item.raw) {
        return Some(format!(
            "value::Object<crate::classes::{}>",
            type_name(class, "MUIC_").ok()?
        ));
    }
    let c_type = item.c_type.as_deref()?.trim();
    if c_type.starts_with("BOOL") {
        Some("value::Boolean".to_owned())
    } else if c_type == "LONG" {
        Some("value::Signed".to_owned())
    } else if c_type == "ULONG" || c_type == "ULONG undoc" {
        Some("value::Unsigned".to_owned())
    } else if c_type == "WORD" {
        Some("value::Short".to_owned())
    } else if c_type == "UBYTE" || c_type == "char" {
        Some("value::Byte".to_owned())
    } else if c_type == "STRPTR" || c_type == "char *" {
        Some("value::String".to_owned())
    } else {
        None
    }
}

fn operation_classification(enabled: bool, safe: bool) -> &'static str {
    if !enabled {
        "unavailable"
    } else if safe {
        "safe"
    } else {
        "typed_unsafe"
    }
}

fn type_name(raw: &str, prefix: &str) -> Result<String, String> {
    let remainder = raw
        .strip_prefix(prefix)
        .ok_or_else(|| format!("{raw} lacks prefix {prefix}"))?;
    let name = pascal(remainder);
    if name.is_empty() {
        Err(format!("{raw} produces an empty Rust name"))
    } else {
        Ok(name)
    }
}

fn pascal(value: &str) -> String {
    let mut output = String::new();
    for part in value.split('_').filter(|part| !part.is_empty()) {
        let mut characters = part.chars();
        if let Some(first) = characters.next() {
            if output.is_empty() && first.is_ascii_digit() {
                output.push('N');
            }
            output.extend(first.to_uppercase());
            output.extend(characters);
        }
    }
    output
}

fn safe_variant_name(name: &str) -> String {
    match name {
        "Self" | "Super" | "Crate" => format!("{name}Value"),
        _ => name.to_owned(),
    }
}

fn reject_collision(
    names: &mut BTreeMap<String, String>,
    rust: &str,
    raw: &str,
) -> Result<(), String> {
    if let Some(previous) = names.insert(rust.to_owned(), raw.to_owned()) {
        return Err(format!(
            "Rust name {rust} collides for {previous} and {raw}"
        ));
    }
    Ok(())
}

fn evaluated_integer(item: &SymbolSpec) -> Option<String> {
    match item.evaluated.as_ref()? {
        Evaluated::Integer(value) => value.parse::<i128>().ok().map(|value| value.to_string()),
        Evaluated::String(value) => {
            let _ = value;
            None
        }
    }
}

fn integer(item: &ModelSymbol) -> Option<&str> {
    match item.evaluated.as_ref()? {
        Evaluated::Integer(value) => Some(value),
        Evaluated::String(value) => {
            let _ = value;
            None
        }
    }
}

fn access_marker(access: Option<&Access>) -> Option<&str> {
    access.map(|item| item.marker.as_str())
}

fn push_cfg(output: &mut String, availability: Availability) {
    if let Some(cfg) = availability.cfg() {
        output.push_str(cfg);
        output.push('\n');
    }
}

fn push_cfg_indented(output: &mut String, availability: Availability, spaces: usize) {
    if let Some(cfg) = availability.cfg() {
        output.push_str(&" ".repeat(spaces));
        output.push_str(cfg);
        output.push('\n');
    }
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

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
