//! Exact-byte aggregation for retained three-host native Cargo proofs.
//!
//! This compares the already-retained proof outputs. It does not execute Cargo,
//! authenticate workflow artifacts, or extend the proof into SDK/release
//! acceptance.

use ami_rust_core::{
    digest::{is_sha256_digest, sha256_bytes},
    files::read_regular_bounded,
    json::{parse_json_value, JsonProfile},
    Refusal, Result,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

const RESULT_SCHEMA: &str = "ami-rust-native-cargo-qualification-result-v1";
const JOB_SCHEMA: &str = "ami-rust-native-cargo-consumer-job-v1";
const REQUEST_SCHEMA: &str = "ami-rust-native-cargo-qualification-request-v1";
const OUTER_REQUEST_SCHEMA: &str = "ami-rust-native-command-qualification-request-v1";
const COMMAND_RECORD_SCHEMA: &str = "ami-rust-native-command-qualification-record-v1";
const PASS_RESULT: &str = "PASS_LOCAL_NATIVE_CARGO_QUALIFICATION";
const PASS_JOB: &str = "HOST_WORKSPACE_CARGO_PROOF_ONLY";
const MAX_PER_HOST_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;

const HOSTS: [(&str, &str); 3] = [
    ("macos-aarch64", "aarch64-apple-darwin"),
    ("linux-x86_64", "x86_64-unknown-linux-gnu"),
    ("linux-aarch64", "aarch64-unknown-linux-gnu"),
];

const VARIANTS: [Variant; 5] = [
    Variant {
        key: "core",
        package: "ami-rust-minimal",
        binary: "ami-rust-minimal",
        objects: &["entry.o", "layout.o", "sdk.o", "startup.o"],
    },
    Variant {
        key: "alloc",
        package: "ami-rust-minimal",
        binary: "ami-rust-minimal",
        objects: &["entry.o", "layout.o", "sdk.o", "startup.o"],
    },
    Variant {
        key: "qualification",
        package: "ami-rust-qualification",
        binary: "ami-rust-qualification",
        objects: &["bind.o", "entry.o", "layout.o", "sdk.o", "startup.o"],
    },
    Variant {
        key: "dependencies",
        package: "ami-rust-dependencies",
        binary: "ami-rust-dependencies",
        objects: &["bind.o", "entry.o", "layout.o", "sdk.o", "startup.o"],
    },
    Variant {
        key: "sha256sum",
        package: "ami-rust-sha256sum",
        binary: "ami-rust-sha256sum",
        objects: &["entry.o", "layout.o", "sdk.o", "startup.o"],
    },
];

#[derive(Clone, Copy)]
struct Variant {
    key: &'static str,
    package: &'static str,
    binary: &'static str,
    objects: &'static [&'static str],
}

#[derive(Default)]
struct ReadBudget {
    bytes: usize,
}

impl ReadBudget {
    fn remaining(&self) -> usize {
        MAX_PER_HOST_BYTES.saturating_sub(self.bytes)
    }

    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| refusal("per-host read accounting overflowed"))?;
        if self.bytes > MAX_PER_HOST_BYTES {
            return Err(refusal(
                "retained proof exceeds the 64 MiB internal read bound",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SharedInputs {
    source_candidate: Value,
    offline_vendor: Value,
    prerequisites_manifest_sha256: String,
}

#[derive(Clone)]
struct VariantBytes {
    elf: Vec<u8>,
    objects: BTreeMap<String, Vec<u8>>,
}

struct HostProof {
    host_key: String,
    shared_inputs: SharedInputs,
    variants: BTreeMap<String, VariantBytes>,
    receipt: Value,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let options = parse_arguments(&mut arguments)?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    if !is_source_head(&options.source_head) {
        return Err(refusal(
            "source head must be exactly 40 hexadecimal characters",
        ));
    }

    let mut roots = Vec::new();
    for (expected_host, _) in HOSTS {
        let argument_path = options
            .proofs
            .get(expected_host)
            .ok_or_else(|| refusal("all three host proof roots are required"))?;
        roots.push((
            expected_host,
            existing_directory(argument_path, "proof root")?,
        ));
    }
    for first in 0..roots.len() {
        for second in first + 1..roots.len() {
            if roots[first].1 == roots[second].1
                || roots[first].1.starts_with(&roots[second].1)
                || roots[second].1.starts_with(&roots[first].1)
            {
                return Err(refusal("host proof roots must be distinct and disjoint"));
            }
        }
    }

    let output = fresh_output_path(&options.output)?;
    if roots
        .iter()
        .any(|(_, root)| output.starts_with(root) || root.starts_with(&output))
    {
        return Err(refusal("receipt path must be outside every proof root"));
    }

    let mut host_proofs = Vec::new();
    for (expected_host, root) in &roots {
        host_proofs.push(verify_host(root, expected_host, &options.source_head)?);
    }

    let shared = host_proofs
        .first()
        .ok_or_else(|| refusal("the host proof set is empty"))?
        .shared_inputs
        .clone();
    let baseline = &host_proofs[0].variants;
    for proof in &host_proofs[1..] {
        if proof.shared_inputs != shared {
            return Err(refusal(format!(
                "cross-host target, lock, vendor, or prerequisite input identity differs for {}",
                proof.host_key
            )));
        }
        compare_variants(baseline, &proof.variants, &proof.host_key)?;
    }

    let receipt = json!({
        "schema": "ami-rust-native-cargo-three-host-byte-comparison-v1",
        "status": "PASS_THREE_HOST_EXACT_NATIVE_CARGO_BYTES",
        "source_head": options.source_head,
        "shared_inputs": {
            "source_candidate": shared.source_candidate,
            "offline_vendor": shared.offline_vendor,
            "prerequisites_manifest_sha256": shared.prerequisites_manifest_sha256
        },
        "host_proofs": host_proofs.iter().map(|proof| proof.receipt.clone()).collect::<Vec<_>>(),
        "comparison": {
            "host_keys": HOSTS.iter().map(|(host, _)| *host).collect::<Vec<_>>(),
            "variants": VARIANTS.iter().map(|variant| variant.key).collect::<Vec<_>>(),
            "independent_roots": ["a", "b"],
            "root_a_equals_root_b": true,
            "cross_host_raw_elf_and_native_object_bytes_equal": true,
            "host_specific_toolchain_and_rlib_bytes_compared": false
        },
        "scope": "Exact comparison of retained local-workspace native Cargo ELFs and native C objects only; not workflow-artifact authentication, a versioned-crate proof, runtime or SDK acceptance, publication, or release acceptance"
    });
    let mut receipt_bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| refusal(format!("could not serialize comparison receipt: {error}")))?;
    receipt_bytes.push(b'\n');
    write_fresh_receipt(&output, &receipt_bytes)?;
    println!(
        "native Cargo proof comparison passed: {}",
        options.source_head
    );
    Ok(())
}

struct Options {
    source_head: String,
    proofs: BTreeMap<&'static str, PathBuf>,
    output: PathBuf,
}

fn parse_arguments(arguments: &mut impl Iterator<Item = OsString>) -> Result<Options> {
    let mut source_head = None;
    let mut proofs = BTreeMap::new();
    let mut output = None;
    while let Some(key) = arguments.next() {
        let key = key
            .to_str()
            .ok_or_else(|| refusal("native-cargo-compare option is not UTF-8"))?;
        let value = arguments
            .next()
            .ok_or_else(|| refusal(format!("{key} requires a value")))?;
        match key {
            "--source-head" => {
                let value = value
                    .into_string()
                    .map_err(|_| refusal("source head must be UTF-8"))?;
                if source_head.replace(value).is_some() {
                    return Err(refusal("--source-head may occur only once"));
                }
            }
            "--macos-proof" => insert_proof(&mut proofs, "macos-aarch64", value)?,
            "--linux-x86-proof" => insert_proof(&mut proofs, "linux-x86_64", value)?,
            "--linux-arm-proof" => insert_proof(&mut proofs, "linux-aarch64", value)?,
            "--output" => {
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err(refusal("--output may occur only once"));
                }
            }
            _ => return Err(usage()),
        }
    }
    let source_head = source_head.ok_or_else(usage)?;
    if proofs.len() != HOSTS.len() {
        return Err(usage());
    }
    let output = output.ok_or_else(usage)?;
    Ok(Options {
        source_head,
        proofs,
        output,
    })
}

fn insert_proof(
    proofs: &mut BTreeMap<&'static str, PathBuf>,
    host: &'static str,
    value: OsString,
) -> Result<()> {
    if proofs.insert(host, PathBuf::from(value)).is_some() {
        return Err(refusal(format!(
            "proof root for {host} may occur only once"
        )));
    }
    Ok(())
}

fn verify_host(root: &Path, expected_host: &str, source_head: &str) -> Result<HostProof> {
    let mut budget = ReadBudget::default();
    let (job, job_sha, _) = read_json(
        &mut budget,
        root,
        Path::new("job-result.json"),
        MAX_RECORD_BYTES,
        JsonProfile::PackageMetadataStateSelection,
    )?;
    if string(&job, "schema")? != JOB_SCHEMA
        || string(&job, "status")? != PASS_JOB
        || string(&job, "source_head")? != source_head
        || string(&job, "host_key")? != expected_host
    {
        return Err(refusal(format!(
            "{expected_host} job result has the wrong source, host, or status"
        )));
    }

    let (consumer_request, consumer_request_sha, _) = read_json(
        &mut budget,
        root,
        Path::new("consumer.request.json"),
        MAX_RECORD_BYTES,
        JsonProfile::PackageMetadataStateSelection,
    )?;
    if string(&consumer_request, "schema")? != REQUEST_SCHEMA
        || string(&consumer_request, "host_key")? != expected_host
    {
        return Err(refusal(format!(
            "{expected_host} consumer request has the wrong schema or host"
        )));
    }
    let expected_triple = host_triple(expected_host)?;
    if string(&consumer_request, "rust_host_triple")? != expected_triple {
        return Err(refusal(format!(
            "{expected_host} consumer request has the wrong Rust host triple"
        )));
    }

    let (outer_request, outer_request_sha, _) = read_json(
        &mut budget,
        root,
        Path::new("consumer.outer-request.json"),
        MAX_RECORD_BYTES,
        JsonProfile::PackageMetadataStateSelection,
    )?;
    let expected_outer = validate_outer_request(&consumer_request, &outer_request, expected_host)?;
    let (consumer_record, consumer_record_sha, _) = read_json(
        &mut budget,
        root,
        Path::new("consumer.record/result.json"),
        MAX_RECORD_BYTES,
        JsonProfile::PackageMetadataStateSelection,
    )?;
    if string(&consumer_record, "schema")? != COMMAND_RECORD_SCHEMA
        || bool_value(&consumer_record, "passed")? != Some(true)
        || bool_value(&consumer_record, "capture_complete")? != Some(true)
        || !is_null(&consumer_record, "capture_error")
        || !is_null(&consumer_record, "child_signal")
        || integer(&consumer_record, "child_exit_code")? != 0
        || !is_null(&consumer_record, "refusal")
        || string(&consumer_record, "request_sha256")? != outer_request_sha
    {
        return Err(refusal(format!(
            "{expected_host} outer consumer command did not pass cleanly"
        )));
    }
    validate_outer_command_record(&consumer_record, &expected_outer, expected_host)?;

    let (proof, proof_sha, proof_bytes) = read_json(
        &mut budget,
        root,
        Path::new("proof/result.json"),
        MAX_PER_HOST_BYTES,
        JsonProfile::CargoVendorOverlayReceipt,
    )?;
    if string(&proof, "schema")? != RESULT_SCHEMA
        || string(&proof, "status")? != PASS_RESULT
        || string(&proof, "host_key")? != expected_host
        || string(&proof, "rust_host_triple")? != expected_triple
        || string(&proof, "request_sha256")? != consumer_request_sha
    {
        return Err(refusal(format!(
            "{expected_host} qualification result has the wrong schema, status, host, or request binding"
        )));
    }
    let source_candidate = get(&proof, "source_candidate")?.clone();
    for key in [
        "inputs_rs_sha256",
        "target_libraries_sha256",
        "target_spec_sha256",
        "tooling_cargo_lock_sha256",
        "workspace_cargo_lock_sha256",
    ] {
        require_digest(string(&source_candidate, key)?, "source candidate digest")?;
    }
    let offline_vendor = get(&proof, "offline_vendor")?.clone();
    if integer(&offline_vendor, "bytes")? == 0
        || string(&offline_vendor, "path")? != "release/inputs/native-cargo-vendor.tar.xz"
        || string(&offline_vendor, "scope")?
            != "Exact 51-package registry union of the pinned application and tooling locks"
    {
        return Err(refusal(format!(
            "{expected_host} offline vendor identity is unexpected"
        )));
    }
    require_digest(string(&offline_vendor, "sha256")?, "offline vendor digest")?;
    let prerequisites_sha = string(&proof, "prerequisites_manifest_sha256")?.to_owned();
    require_digest(&prerequisites_sha, "prerequisites manifest digest")?;

    let rows = get(&proof, "matrix")?
        .as_array()
        .ok_or_else(|| refusal(format!("{expected_host} matrix is not an array")))?;
    if rows.len() != VARIANTS.len() {
        return Err(refusal(format!(
            "{expected_host} matrix must contain exactly five variants"
        )));
    }
    let mut rows_by_variant = BTreeMap::new();
    for row in rows {
        let key = string(row, "variant")?;
        if !VARIANTS.iter().any(|variant| variant.key == key)
            || rows_by_variant.insert(key.to_owned(), row).is_some()
        {
            return Err(refusal(format!(
                "{expected_host} matrix has an unknown or duplicate variant"
            )));
        }
    }
    if rows_by_variant.len() != VARIANTS.len() {
        return Err(refusal(format!(
            "{expected_host} matrix is missing a variant"
        )));
    }

    let mut expected_artifacts = BTreeSet::new();
    let mut expected_object_directories = BTreeSet::new();
    for variant in VARIANTS {
        expected_artifacts.insert(format!("root-a-{}.elf", variant.key));
        expected_artifacts.insert(format!("root-b-{}.elf", variant.key));
        expected_object_directories.insert(format!("root-a-{}", variant.key));
        expected_object_directories.insert(format!("root-b-{}", variant.key));
    }
    require_directory_below(root, Path::new("proof"), "proof directory")?;
    require_directory_entries(
        root,
        Path::new("proof/artifacts"),
        &expected_artifacts,
        EntryKind::File,
        "retained ELF artifacts",
    )?;
    require_directory_entries(
        root,
        Path::new("proof/native-objects"),
        &expected_object_directories,
        EntryKind::Directory,
        "retained native-object directories",
    )?;

    let mut variant_bytes = BTreeMap::new();
    let mut variant_receipts = Vec::new();
    for variant in VARIANTS {
        let row = rows_by_variant
            .get(variant.key)
            .ok_or_else(|| refusal("variant matrix row disappeared"))?;
        if string(row, "package")? != variant.package || string(row, "binary")? != variant.binary {
            return Err(refusal(format!(
                "{expected_host} {} package or binary changed",
                variant.key
            )));
        }

        let elf_row = get(row, "elf")?;
        let root_a_elf_name = format!("root-a-{}.elf", variant.key);
        if string(elf_row, "path")? != root_a_elf_name {
            return Err(refusal(format!(
                "{expected_host} {} ELF path is not canonical",
                variant.key
            )));
        }
        let declared_elf_bytes = integer(elf_row, "bytes")?;
        if declared_elf_bytes == 0 || declared_elf_bytes > MAX_PER_HOST_BYTES as u64 {
            return Err(refusal(format!(
                "{expected_host} {} ELF exceeds its retained bound",
                variant.key
            )));
        }
        let declared_elf_sha = string(elf_row, "sha256")?;
        require_digest(declared_elf_sha, "ELF digest")?;
        let root_a_elf = read_artifact(
            &mut budget,
            root,
            &Path::new("proof/artifacts").join(&root_a_elf_name),
        )?;
        verify_declared_identity(
            &root_a_elf,
            declared_elf_bytes,
            declared_elf_sha,
            &format!("{expected_host} {} root A ELF", variant.key),
        )?;
        let root_b_elf_name = format!("root-b-{}.elf", variant.key);
        let root_b_elf = read_artifact(
            &mut budget,
            root,
            &Path::new("proof/artifacts").join(&root_b_elf_name),
        )?;
        if root_a_elf != root_b_elf {
            return Err(refusal(format!(
                "{expected_host} {} ELF differs between the two roots",
                variant.key
            )));
        }

        let object_rows = get(row, "native_objects")?.as_array().ok_or_else(|| {
            refusal(format!(
                "{expected_host} {} native objects are not an array",
                variant.key
            ))
        })?;
        if object_rows.len() != variant.objects.len() {
            return Err(refusal(format!(
                "{expected_host} {} native-object set has the wrong size",
                variant.key
            )));
        }
        let mut declared_objects = BTreeMap::new();
        for object_row in object_rows {
            let name = string(object_row, "path")?;
            if !variant.objects.contains(&name) || declared_objects.contains_key(name) {
                return Err(refusal(format!(
                    "{expected_host} {} has an unknown or duplicate native object",
                    variant.key
                )));
            }
            let bytes = integer(object_row, "bytes")?;
            let sha = string(object_row, "sha256")?;
            if bytes == 0 || bytes > MAX_PER_HOST_BYTES as u64 {
                return Err(refusal(format!(
                    "{expected_host} {} native object exceeds its retained bound",
                    variant.key
                )));
            }
            require_digest(sha, "native-object digest")?;
            declared_objects.insert(name.to_owned(), (bytes, sha.to_owned()));
        }
        if declared_objects
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != variant.objects.iter().copied().collect::<BTreeSet<_>>()
        {
            return Err(refusal(format!(
                "{expected_host} {} native-object set is incomplete",
                variant.key
            )));
        }

        let root_a_object_dir =
            Path::new("proof/native-objects").join(format!("root-a-{}", variant.key));
        let root_b_object_dir =
            Path::new("proof/native-objects").join(format!("root-b-{}", variant.key));
        let expected_objects = variant
            .objects
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        require_directory_entries(
            root,
            &root_a_object_dir,
            &expected_objects,
            EntryKind::File,
            "root A native objects",
        )?;
        require_directory_entries(
            root,
            &root_b_object_dir,
            &expected_objects,
            EntryKind::File,
            "root B native objects",
        )?;
        let mut object_bytes = BTreeMap::new();
        let mut object_receipts = Vec::new();
        for name in variant.objects {
            let (declared_bytes, declared_sha) = declared_objects
                .get(*name)
                .ok_or_else(|| refusal("native-object identity disappeared"))?;
            let root_a_object = read_artifact(&mut budget, root, &root_a_object_dir.join(name))?;
            verify_declared_identity(
                &root_a_object,
                *declared_bytes,
                declared_sha,
                &format!("{expected_host} {} root A {name}", variant.key),
            )?;
            let root_b_object = read_artifact(&mut budget, root, &root_b_object_dir.join(name))?;
            if root_a_object != root_b_object {
                return Err(refusal(format!(
                    "{expected_host} {} native object {name} differs between the two roots",
                    variant.key
                )));
            }
            object_receipts.push(json!({
                "path": name,
                "bytes": root_a_object.len(),
                "sha256": sha256_bytes(&root_a_object),
                "root_a_equals_root_b": true
            }));
            object_bytes.insert((*name).to_owned(), root_a_object);
        }
        let elf_sha = sha256_bytes(&root_a_elf);
        variant_receipts.push(json!({
            "variant": variant.key,
            "package": variant.package,
            "binary": variant.binary,
            "elf": {
                "bytes": root_a_elf.len(),
                "sha256": elf_sha,
                "root_a_equals_root_b": true
            },
            "native_objects": object_receipts
        }));
        variant_bytes.insert(
            variant.key.to_owned(),
            VariantBytes {
                elf: root_a_elf,
                objects: object_bytes,
            },
        );
    }

    Ok(HostProof {
        host_key: expected_host.to_owned(),
        shared_inputs: SharedInputs {
            source_candidate,
            offline_vendor,
            prerequisites_manifest_sha256: prerequisites_sha,
        },
        variants: variant_bytes,
        receipt: json!({
            "host_key": expected_host,
            "rust_host_triple": expected_triple,
            "job_status": PASS_JOB,
            "qualification_status": PASS_RESULT,
            "proof_result_sha256": proof_sha,
            "proof_result_bytes": proof_bytes,
            "job_result_sha256": job_sha,
            "consumer_request_sha256": consumer_request_sha,
            "outer_request_sha256": outer_request_sha,
            "consumer_record_sha256": consumer_record_sha,
            "read_bytes_within_internal_bound": budget.bytes <= MAX_PER_HOST_BYTES,
            "variants": variant_receipts
        }),
    })
}

struct ExpectedOuterCommand {
    program: String,
    cwd: String,
    args_sha256: String,
    environment_keys: Vec<String>,
    environment_sha256: String,
}

fn validate_outer_request(
    consumer_request: &Value,
    outer_request: &Value,
    host: &str,
) -> Result<ExpectedOuterCommand> {
    if string(outer_request, "schema")? != OUTER_REQUEST_SCHEMA {
        return Err(refusal(format!(
            "{host} outer request has the wrong schema"
        )));
    }

    let managed_root = string(consumer_request, "managed_root")?;
    let root_path = Path::new(managed_root);
    if !root_path.is_absolute()
        || root_path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(refusal(format!(
            "{host} consumer request has a noncanonical managed root"
        )));
    }
    let output_root = root_path.join("proof");
    if output_root.to_str() != Some(string(consumer_request, "output_root")?) {
        return Err(refusal(format!(
            "{host} consumer request output root is not under its managed root"
        )));
    }

    let program = root_path.join("tooling-target/release/ami-rust-xtask");
    let request_path = root_path.join("consumer.request.json");
    let program = program
        .to_str()
        .ok_or_else(|| refusal(format!("{host} outer program path is not UTF-8")))?
        .to_owned();
    let request_path = request_path
        .to_str()
        .ok_or_else(|| refusal(format!("{host} inner request path is not UTF-8")))?;
    let args = ["native-cargo-qualification", "--request", request_path];
    let actual_args = get(outer_request, "args")?
        .as_array()
        .ok_or_else(|| refusal(format!("{host} outer command arguments are not an array")))?;
    if string(outer_request, "program")? != program
        || string(outer_request, "cwd")? != managed_root
        || actual_args.len() != args.len()
        || actual_args
            .iter()
            .zip(args)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(refusal(format!(
            "{host} outer command does not run native-cargo-qualification on its captured consumer request"
        )));
    }
    let args_sha256 =
        sha256_bytes(&serde_json::to_vec(&args).map_err(|error| {
            refusal(format!("could not encode {host} outer arguments: {error}"))
        })?);
    let environment_object = get(outer_request, "environment")?
        .as_object()
        .ok_or_else(|| refusal(format!("{host} outer environment is not an object")))?;
    let mut environment = BTreeMap::new();
    for (key, value) in environment_object {
        let value = value.as_str().ok_or_else(|| {
            refusal(format!(
                "{host} outer environment value for {key} is not a string"
            ))
        })?;
        environment.insert(key.clone(), value.to_owned());
    }
    let environment_keys = environment.keys().cloned().collect();
    let environment_sha256 = sha256_bytes(&serde_json::to_vec(&environment).map_err(|error| {
        refusal(format!(
            "could not encode {host} outer environment: {error}"
        ))
    })?);
    Ok(ExpectedOuterCommand {
        program,
        cwd: managed_root.to_owned(),
        args_sha256,
        environment_keys,
        environment_sha256,
    })
}

fn validate_outer_command_record(
    consumer_record: &Value,
    expected: &ExpectedOuterCommand,
    host: &str,
) -> Result<()> {
    let command = get(consumer_record, "command")?;
    let environment_keys = get(command, "environment_keys")?
        .as_array()
        .ok_or_else(|| refusal(format!("{host} command environment keys are not an array")))?
        .iter()
        .map(|key| {
            key.as_str()
                .map(str::to_owned)
                .ok_or_else(|| refusal(format!("{host} command environment key is not a string")))
        })
        .collect::<Result<Vec<_>>>()?;
    if string(command, "program")? != expected.program
        || string(command, "cwd")? != expected.cwd
        || string(command, "args_sha256")? != expected.args_sha256
        || environment_keys != expected.environment_keys
        || string(command, "environment_sha256")? != expected.environment_sha256
    {
        return Err(refusal(format!(
            "{host} outer command record does not match the expected program and arguments"
        )));
    }
    require_digest(
        string(command, "program_sha256")?,
        "outer command executable digest",
    )
}

fn compare_variants(
    baseline: &BTreeMap<String, VariantBytes>,
    candidate: &BTreeMap<String, VariantBytes>,
    host: &str,
) -> Result<()> {
    if baseline.keys().collect::<Vec<_>>() != candidate.keys().collect::<Vec<_>>() {
        return Err(refusal(format!(
            "cross-host variant sets differ for {host}"
        )));
    }
    for variant in VARIANTS {
        let left = baseline
            .get(variant.key)
            .ok_or_else(|| refusal("baseline variant disappeared"))?;
        let right = candidate
            .get(variant.key)
            .ok_or_else(|| refusal("candidate variant disappeared"))?;
        if left.elf != right.elf {
            return Err(refusal(format!(
                "cross-host {} ELF bytes differ on {host}",
                variant.key
            )));
        }
        if left.objects.keys().collect::<Vec<_>>() != right.objects.keys().collect::<Vec<_>>() {
            return Err(refusal(format!(
                "cross-host {} native-object sets differ on {host}",
                variant.key
            )));
        }
        for (name, left_bytes) in &left.objects {
            if right.objects.get(name) != Some(left_bytes) {
                return Err(refusal(format!(
                    "cross-host {} native object {name} differs on {host}",
                    variant.key
                )));
            }
        }
    }
    Ok(())
}

fn read_json(
    budget: &mut ReadBudget,
    root: &Path,
    relative: &Path,
    limit: usize,
    profile: JsonProfile,
) -> Result<(Value, String, usize)> {
    let path = path_below(root, relative)?;
    let bytes = read_regular_bounded(&path, limit.min(budget.remaining()))?;
    budget.charge(bytes.len())?;
    let digest = sha256_bytes(&bytes);
    let value = parse_json_value(&bytes, profile)?;
    Ok((value, digest, bytes.len()))
}

fn read_artifact(budget: &mut ReadBudget, root: &Path, relative: &Path) -> Result<Vec<u8>> {
    let path = path_below(root, relative)?;
    let bytes = read_regular_bounded(&path, budget.remaining())?;
    budget.charge(bytes.len())?;
    Ok(bytes)
}

fn verify_declared_identity(bytes: &[u8], length: u64, digest: &str, context: &str) -> Result<()> {
    if bytes.len() as u64 != length || sha256_bytes(bytes) != digest {
        return Err(refusal(format!(
            "{context} differs from its declared byte length or SHA-256"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum EntryKind {
    File,
    Directory,
}

fn require_directory_below(root: &Path, relative: &Path, context: &str) -> Result<()> {
    let path = path_below(root, relative)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(refusal(format!("{context} is not a regular directory")));
    }
    Ok(())
}

fn require_directory_entries(
    root: &Path,
    relative: &Path,
    expected: &BTreeSet<String>,
    kind: EntryKind,
    context: &str,
) -> Result<()> {
    require_directory_below(root, relative, context)?;
    let path = root.join(relative);
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refusal(format!("{context} contains a non-UTF-8 name")))?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(refusal(format!("{context} contains a symlink")));
        }
        let correct_kind = match kind {
            EntryKind::File => file_type.is_file(),
            EntryKind::Directory => file_type.is_dir(),
        };
        if !correct_kind || !actual.insert(name) {
            return Err(refusal(format!(
                "{context} contains a duplicate or wrong-kind entry"
            )));
        }
    }
    if &actual != expected {
        return Err(refusal(format!(
            "{context} has a missing or unexpected entry"
        )));
    }
    Ok(())
}

fn path_below(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.as_os_str().is_empty() {
        return Err(refusal("proof path must name an entry below its root"));
    }
    let components = relative.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(refusal("proof path contains a non-normal component"));
    }
    let mut path = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        path.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || (index + 1 != components.len() && !metadata.file_type().is_dir())
        {
            return Err(refusal(
                "proof path has a symlink or non-directory parent component",
            ));
        }
    }
    Ok(path)
}

fn existing_directory(path: &Path, context: &str) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                current.push(name);
                let metadata = fs::symlink_metadata(&current)?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(refusal(format!(
                        "{context} has a symlink or non-directory component"
                    )));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(refusal(format!(
                    "{context} path contains a forbidden component"
                )));
            }
        }
    }
    if !current.is_absolute() {
        return Err(refusal(format!(
            "{context} must resolve to an absolute directory"
        )));
    }
    let metadata = fs::symlink_metadata(&current)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(refusal(format!("{context} is not a regular directory")));
    }
    Ok(current)
}

fn fresh_output_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(refusal("receipt path contains a forbidden component"));
    }
    let name = absolute
        .file_name()
        .ok_or_else(|| refusal("receipt path must name a new file"))?;
    if !matches!(
        Path::new(name).components().next(),
        Some(Component::Normal(_))
    ) {
        return Err(refusal("receipt path must name a new file"));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| refusal("receipt path has no parent directory"))?;
    let parent = existing_directory(parent, "receipt parent")?;
    let output = parent.join(name);
    match fs::symlink_metadata(&output) {
        Ok(_) => return Err(refusal("comparison receipt already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(output)
}

fn write_fresh_receipt(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    Ok(())
}

fn host_triple(host: &str) -> Result<&'static str> {
    HOSTS
        .iter()
        .find_map(|(key, triple)| (*key == host).then_some(*triple))
        .ok_or_else(|| refusal("unknown host key"))
}

fn is_source_head(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_digest(value: &str, context: &str) -> Result<()> {
    if !is_sha256_digest(value) {
        return Err(refusal(format!("{context} is not a SHA-256 digest")));
    }
    Ok(())
}

fn get<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| refusal(format!("required field {key} is missing")))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    get(value, key)?
        .as_str()
        .ok_or_else(|| refusal(format!("field {key} is not a string")))
}

fn integer(value: &Value, key: &str) -> Result<u64> {
    get(value, key)?
        .as_u64()
        .ok_or_else(|| refusal(format!("field {key} is not an unsigned integer")))
}

fn bool_value(value: &Value, key: &str) -> Result<Option<bool>> {
    get(value, key)?
        .as_bool()
        .map(Some)
        .ok_or_else(|| refusal(format!("field {key} is not a boolean")))
}

fn is_null(value: &Value, key: &str) -> bool {
    value.get(key).is_some_and(Value::is_null)
}

fn refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(format!("native-cargo-compare: {}", message.into()))
}

fn usage() -> Refusal {
    refusal(
        "usage: native-cargo-compare --source-head <40-hex> --macos-proof <original-records> --linux-x86-proof <original-records> --linux-arm-proof <original-records> --output <fresh-receipt>",
    )
}

#[cfg(test)]
mod tests {
    // Synthetic bytes exercise retention and equality checks only; they are
    // deliberately not a substitute for the preceding ELF audit.
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    const SOURCE_HEAD: &str = "0123456789abcdef0123456789abcdef01234567";
    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is after Unix epoch")
                .as_nanos();
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "ami-rust-native-cargo-compare-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("fixture root created");
            Self { root }
        }

        fn proof_root(&self, host: &str) -> PathBuf {
            self.root.join(host)
        }

        fn output(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }

        fn command(&self, output: &Path) -> Result<()> {
            let arguments = vec![
                "--source-head".to_owned(),
                SOURCE_HEAD.to_owned(),
                "--macos-proof".to_owned(),
                self.proof_root(HOSTS[0].0).to_string_lossy().into_owned(),
                "--linux-x86-proof".to_owned(),
                self.proof_root(HOSTS[1].0).to_string_lossy().into_owned(),
                "--linux-arm-proof".to_owned(),
                self.proof_root(HOSTS[2].0).to_string_lossy().into_owned(),
                "--output".to_owned(),
                output.to_string_lossy().into_owned(),
            ];
            run(arguments.into_iter().map(OsString::from))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn make_fixture() -> Fixture {
        let fixture = Fixture::new();
        for (host, triple) in HOSTS {
            make_host_proof(&fixture.proof_root(host), host, triple, SOURCE_HEAD);
        }
        fixture
    }

    fn make_host_proof(root: &Path, host: &str, triple: &str, source_head: &str) {
        fs::create_dir_all(root.join("proof/artifacts")).expect("artifact directory created");
        fs::create_dir_all(root.join("proof/native-objects")).expect("object root created");
        let consumer_request = json!({
            "schema": REQUEST_SCHEMA,
            "host_key": host,
            "rust_host_triple": triple,
            "source_root": "/fixture/source",
            "managed_root": "/fixture/managed",
            "work_root": "/fixture/work",
            "output_root": "/fixture/managed/proof",
            "component_roots": {},
            "bootstrap": {}
        });
        let consumer_request_bytes =
            serde_json::to_vec(&consumer_request).expect("request serializes");
        let outer_args = [
            "native-cargo-qualification",
            "--request",
            "/fixture/managed/consumer.request.json",
        ];
        let outer_environment = BTreeMap::from([
            (
                "HOME".to_owned(),
                "/fixture/managed/bootstrap-home".to_owned(),
            ),
            ("LC_ALL".to_owned(), "C".to_owned()),
            ("TMPDIR".to_owned(), "/fixture/managed/tmp".to_owned()),
        ]);
        let outer_environment_keys = outer_environment.keys().cloned().collect::<Vec<_>>();
        let outer_environment_sha256 =
            sha256_bytes(&serde_json::to_vec(&outer_environment).unwrap());
        let outer_request = json!({
            "schema": OUTER_REQUEST_SCHEMA,
            "program": "/fixture/managed/tooling-target/release/ami-rust-xtask",
            "args": outer_args,
            "cwd": "/fixture/managed",
            "environment": outer_environment
        });
        let outer_request_bytes =
            serde_json::to_vec(&outer_request).expect("outer request serializes");
        fs::write(root.join("consumer.request.json"), &consumer_request_bytes)
            .expect("request written");
        fs::write(
            root.join("consumer.outer-request.json"),
            &outer_request_bytes,
        )
        .expect("outer request written");
        fs::create_dir_all(root.join("consumer.record")).expect("record directory created");
        fs::write(
            root.join("consumer.record/result.json"),
            serde_json::to_vec(&json!({
                "schema": COMMAND_RECORD_SCHEMA,
                "passed": true,
                "refusal": null,
                "request_sha256": sha256_bytes(&outer_request_bytes),
                "capture_complete": true,
                "capture_error": null,
                "child_exit_code": 0,
                "child_signal": null,
                "command": {
                    "program": "/fixture/managed/tooling-target/release/ami-rust-xtask",
                    "program_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "args_sha256": sha256_bytes(&serde_json::to_vec(&outer_args).unwrap()),
                    "cwd": "/fixture/managed",
                    "environment_keys": outer_environment_keys,
                    "environment_sha256": outer_environment_sha256
                }
            }))
            .expect("command record serializes"),
        )
        .expect("command record written");
        fs::write(
            root.join("job-result.json"),
            serde_json::to_vec(&json!({
                "schema": JOB_SCHEMA,
                "status": PASS_JOB,
                "source_head": source_head,
                "host_key": host,
                "campaign_elapsed_seconds": 1,
                "claim": "fixture"
            }))
            .expect("job record serializes"),
        )
        .expect("job record written");

        let mut matrix = Vec::new();
        for variant in VARIANTS {
            let elf = format!("synthetic ELF bytes for {}", variant.key).into_bytes();
            let elf_a = format!("root-a-{}.elf", variant.key);
            let elf_b = format!("root-b-{}.elf", variant.key);
            fs::write(root.join("proof/artifacts").join(&elf_a), &elf).expect("root A ELF written");
            fs::write(root.join("proof/artifacts").join(&elf_b), &elf).expect("root B ELF written");
            let obj_a_dir = root
                .join("proof/native-objects")
                .join(format!("root-a-{}", variant.key));
            let obj_b_dir = root
                .join("proof/native-objects")
                .join(format!("root-b-{}", variant.key));
            fs::create_dir_all(&obj_a_dir).expect("root A objects created");
            fs::create_dir_all(&obj_b_dir).expect("root B objects created");
            let mut object_rows = Vec::new();
            for name in variant.objects {
                let object = format!("synthetic {} {}", variant.key, name).into_bytes();
                fs::write(obj_a_dir.join(name), &object).expect("root A object written");
                fs::write(obj_b_dir.join(name), &object).expect("root B object written");
                object_rows.push(json!({
                    "path": name,
                    "bytes": object.len(),
                    "sha256": sha256_bytes(&object)
                }));
            }
            matrix.push(json!({
                "variant": variant.key,
                "package": variant.package,
                "binary": variant.binary,
                "elf_audit": {},
                "elf": {
                    "path": elf_a,
                    "bytes": elf.len(),
                    "sha256": sha256_bytes(&elf),
                    "audit": {}
                },
                "native_objects": object_rows
            }));
        }
        let proof = json!({
            "schema": RESULT_SCHEMA,
            "status": PASS_RESULT,
            "host_key": host,
            "rust_host_triple": triple,
            "request_sha256": sha256_bytes(&consumer_request_bytes),
            "source_candidate": {
                "inputs_rs_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "target_libraries_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "target_spec_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "tooling_cargo_lock_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "workspace_cargo_lock_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            },
            "offline_vendor": {
                "bytes": 10,
                "path": "release/inputs/native-cargo-vendor.tar.xz",
                "scope": "Exact 51-package registry union of the pinned application and tooling locks",
                "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            },
            "prerequisites_manifest_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "matrix": matrix
        });
        fs::write(
            root.join("proof/result.json"),
            serde_json::to_vec(&proof).expect("proof serializes"),
        )
        .expect("proof written");
    }

    fn read_proof(fixture: &Fixture, host: &str) -> Value {
        serde_json::from_slice(
            &fs::read(fixture.proof_root(host).join("proof/result.json")).expect("proof read"),
        )
        .expect("proof parses")
    }

    fn write_proof(fixture: &Fixture, host: &str, proof: &Value) {
        fs::write(
            fixture.proof_root(host).join("proof/result.json"),
            serde_json::to_vec(proof).expect("proof serializes"),
        )
        .expect("proof rewritten");
    }

    #[test]
    fn accepts_exact_three_host_two_root_fixture_and_writes_receipt() {
        let fixture = make_fixture();
        let output = fixture.output("comparison.json");
        fixture.command(&output).expect("fixture comparison passes");
        let receipt: Value = serde_json::from_slice(&fs::read(output).expect("receipt exists"))
            .expect("receipt parses");
        assert_eq!(
            receipt["status"],
            "PASS_THREE_HOST_EXACT_NATIVE_CARGO_BYTES"
        );
        assert_eq!(receipt["host_proofs"].as_array().unwrap().len(), 3);
        assert!(
            receipt["comparison"]["cross_host_raw_elf_and_native_object_bytes_equal"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn rejects_cross_host_core_elf_byte_mismatch() {
        let fixture = make_fixture();
        let root = fixture.proof_root("linux-x86_64");
        let bytes = b"different core ELF";
        for name in ["root-a-core.elf", "root-b-core.elf"] {
            fs::write(root.join("proof/artifacts").join(name), bytes).expect("ELF replaced");
        }
        let mut proof = read_proof(&fixture, "linux-x86_64");
        let core = proof["matrix"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["variant"] == "core")
            .unwrap();
        core["elf"]["bytes"] = json!(bytes.len());
        core["elf"]["sha256"] = json!(sha256_bytes(bytes));
        write_proof(&fixture, "linux-x86_64", &proof);
        assert!(fixture.command(&fixture.output("comparison.json")).is_err());
    }

    #[test]
    fn rejects_rehashed_unrelated_outer_command() {
        let fixture = make_fixture();
        let root = fixture.proof_root("macos-aarch64");
        let outer_path = root.join("consumer.outer-request.json");
        let unrelated_args = ["--version"];
        let mut unrelated: Value = serde_json::from_slice(&fs::read(&outer_path).unwrap()).unwrap();
        unrelated["program"] = json!("/fixture/managed/bootstrap/toolchain/bin/cargo");
        unrelated["args"] = json!(unrelated_args);
        let unrelated_bytes = serde_json::to_vec(&unrelated).unwrap();
        fs::write(&outer_path, &unrelated_bytes).expect("unrelated outer request written");

        let record_path = root.join("consumer.record/result.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record["request_sha256"] = json!(sha256_bytes(&unrelated_bytes));
        record["command"]["program"] = unrelated["program"].clone();
        record["command"]["args_sha256"] =
            json!(sha256_bytes(&serde_json::to_vec(&unrelated_args).unwrap()));
        record["command"]["cwd"] = unrelated["cwd"].clone();
        fs::write(record_path, serde_json::to_vec(&record).unwrap())
            .expect("coherent unrelated command record written");

        assert!(fixture
            .command(&fixture.output("unrelated-command.json"))
            .is_err());
    }

    #[test]
    fn rejects_changed_root_b_native_object() {
        let fixture = make_fixture();
        fs::write(
            fixture
                .proof_root("linux-aarch64")
                .join("proof/native-objects/root-b-alloc/entry.o"),
            b"changed object",
        )
        .expect("object changed");
        assert!(fixture.command(&fixture.output("comparison.json")).is_err());
    }

    #[test]
    fn rejects_declared_elf_hash_mismatch() {
        let fixture = make_fixture();
        let mut proof = read_proof(&fixture, "macos-aarch64");
        proof["matrix"][0]["elf"]["sha256"] =
            json!("0000000000000000000000000000000000000000000000000000000000000000");
        write_proof(&fixture, "macos-aarch64", &proof);
        assert!(fixture.command(&fixture.output("comparison.json")).is_err());
    }

    #[test]
    fn rejects_source_head_mismatch_and_invalid_source_argument() {
        let fixture = make_fixture();
        let job_path = fixture.proof_root("linux-x86_64").join("job-result.json");
        let mut job: Value =
            serde_json::from_slice(&fs::read(&job_path).expect("job read")).unwrap();
        job["source_head"] = json!("ffffffffffffffffffffffffffffffffffffffff");
        fs::write(job_path, serde_json::to_vec(&job).unwrap()).unwrap();
        assert!(fixture
            .command(&fixture.output("source-mismatch.json"))
            .is_err());

        let args = vec![
            "--source-head".to_owned(),
            "short".to_owned(),
            "--macos-proof".to_owned(),
            fixture
                .proof_root(HOSTS[0].0)
                .to_string_lossy()
                .into_owned(),
            "--linux-x86-proof".to_owned(),
            fixture
                .proof_root(HOSTS[1].0)
                .to_string_lossy()
                .into_owned(),
            "--linux-arm-proof".to_owned(),
            fixture
                .proof_root(HOSTS[2].0)
                .to_string_lossy()
                .into_owned(),
            "--output".to_owned(),
            fixture
                .output("bad-source.json")
                .to_string_lossy()
                .into_owned(),
        ];
        assert!(run(args.into_iter().map(OsString::from)).is_err());
    }

    #[test]
    fn rejects_cross_host_target_recipe_identity_mismatch() {
        let fixture = make_fixture();
        let mut proof = read_proof(&fixture, "linux-x86_64");
        proof["source_candidate"]["target_spec_sha256"] =
            json!("2222222222222222222222222222222222222222222222222222222222222222");
        write_proof(&fixture, "linux-x86_64", &proof);
        assert!(fixture
            .command(&fixture.output("input-mismatch.json"))
            .is_err());
    }

    #[test]
    fn rejects_duplicate_or_missing_variant() {
        let fixture = make_fixture();
        let mut proof = read_proof(&fixture, "macos-aarch64");
        let first = proof["matrix"][0].clone();
        proof["matrix"].as_array_mut().unwrap().push(first);
        write_proof(&fixture, "macos-aarch64", &proof);
        assert!(fixture
            .command(&fixture.output("duplicate-variant.json"))
            .is_err());

        let fixture = make_fixture();
        let mut proof = read_proof(&fixture, "linux-aarch64");
        proof["matrix"].as_array_mut().unwrap().pop();
        write_proof(&fixture, "linux-aarch64", &proof);
        assert!(fixture
            .command(&fixture.output("missing-variant.json"))
            .is_err());
    }

    #[test]
    fn rejects_duplicate_host_root_and_missing_host_argument() {
        let fixture = make_fixture();
        let output = fixture.output("duplicate-host.json");
        let duplicate_host_args = vec![
            "--source-head".to_owned(),
            SOURCE_HEAD.to_owned(),
            "--macos-proof".to_owned(),
            fixture
                .proof_root(HOSTS[0].0)
                .to_string_lossy()
                .into_owned(),
            "--linux-x86-proof".to_owned(),
            fixture
                .proof_root(HOSTS[0].0)
                .to_string_lossy()
                .into_owned(),
            "--linux-arm-proof".to_owned(),
            fixture
                .proof_root(HOSTS[2].0)
                .to_string_lossy()
                .into_owned(),
            "--output".to_owned(),
            output.to_string_lossy().into_owned(),
        ];
        assert!(run(duplicate_host_args.into_iter().map(OsString::from)).is_err());

        let missing_host_args = vec![
            "--source-head".to_owned(),
            SOURCE_HEAD.to_owned(),
            "--output".to_owned(),
            output.to_string_lossy().into_owned(),
        ];
        assert!(run(missing_host_args.into_iter().map(OsString::from)).is_err());
    }

    #[test]
    fn rejects_escaped_artifact_path_and_symlink_artifact() {
        let fixture = make_fixture();
        let mut proof = read_proof(&fixture, "linux-aarch64");
        proof["matrix"][0]["elf"]["path"] = json!("../root-a-core.elf");
        write_proof(&fixture, "linux-aarch64", &proof);
        assert!(fixture
            .command(&fixture.output("escaped-path.json"))
            .is_err());

        let fixture = make_fixture();
        let root = fixture.proof_root("linux-x86_64");
        let artifact = root.join("proof/artifacts/root-a-core.elf");
        let outside = fixture.output("outside.elf");
        fs::write(&outside, b"not an ELF").expect("outside file written");
        fs::remove_file(&artifact).expect("artifact removed");
        symlink(&outside, &artifact).expect("artifact symlink made");
        assert!(fixture.command(&fixture.output("symlink.json")).is_err());
    }

    #[test]
    fn rejects_symlinked_parent_below_proof_root() {
        let fixture = make_fixture();
        let root = fixture.proof_root("linux-x86_64");
        let record_dir = root.join("consumer.record");
        let moved_dir = fixture.output("record-dir");
        fs::rename(&record_dir, &moved_dir).expect("record directory moved outside root");
        symlink(&moved_dir, &record_dir).expect("record parent symlink made");
        assert!(fixture
            .command(&fixture.output("symlink-parent.json"))
            .is_err());
    }

    #[test]
    fn refuses_to_replace_preexisting_receipt() {
        let fixture = make_fixture();
        let output = fixture.output("already-there.json");
        fs::write(&output, b"preserve me").expect("existing receipt created");
        assert!(fixture.command(&output).is_err());
        assert_eq!(fs::read(output).unwrap(), b"preserve me");
    }
}
