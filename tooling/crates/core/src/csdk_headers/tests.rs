use super::{
    CsdkHeadersRequest, HEADER_RECIPE_COUNT, MESA_CONFIG_PATH, MESA_DIFF_HEADER,
    SOURCE_GENERATOR_PREFIX, expected_header_group, generate_public_headers, insert_unique_output,
    mesa_added_config_patch, parse_header_recipe, require_fresh_destination,
    rewrite_provenance_banner, validate_complete_added_file_block, validate_complete_coverage,
    validate_header_bytes,
};
use crate::{Refusal, Result, csdk_source::CsdkSourceFilePin, directory::Directory};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        for _ in 0..100 {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "ami-rust-csdk-headers-test-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create header test directory: {error}"),
            }
        }
        panic!("could not allocate a unique header test directory");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove header test directory");
    }
}

#[test]
fn provenance_rewrite_changes_only_the_single_banner_path() {
    let original = b"/* Automatically generated from '/old/checkout/AROS-NX/compiler/crt/posixc/posixc.conf'. */\n#define VALUE 7\n";
    let normalized =
        rewrite_provenance_banner(original, "compiler/crt/posixc/posixc.conf").unwrap();
    assert_eq!(
        normalized,
        b"/* Automatically generated from 'compiler/crt/posixc/posixc.conf'. */\n#define VALUE 7\n"
    );

    let mut changed_elsewhere = normalized.clone();
    let marker = changed_elsewhere
        .windows(b"VALUE 7".len())
        .position(|window| window == b"VALUE 7")
        .unwrap();
    changed_elsewhere[marker + b"VALUE ".len()] = b'8';
    assert!(validate_header_bytes(&changed_elsewhere, &normalized, &[], "clib/example.h").is_err());
    validate_header_bytes(&normalized, &normalized, &[], "clib/example.h").unwrap();
}

#[test]
fn provenance_banner_rejects_missing_duplicate_and_wrong_config() {
    assert!(rewrite_provenance_banner(b"/* no generator metadata */\n", "config/a.conf").is_err());
    let duplicate =
        b"Automatically generated from '/a/config/a.conf'.\nAutomatically generated from '/b/config/a.conf'.\n";
    assert!(rewrite_provenance_banner(duplicate, "config/a.conf").is_err());
    let wrong = b"Automatically generated from '/old/config/other.conf'.\n";
    assert!(rewrite_provenance_banner(wrong, "config/a.conf").is_err());
    let incomplete = b"Automatically generated from '/old/config/a.conf\n";
    assert!(rewrite_provenance_banner(incomplete, "config/a.conf").is_err());
}

#[test]
fn recipe_structure_rejects_counts_collisions_traversal_argv_and_override_mismatch() {
    assert!(validate_complete_coverage(105, 27, 530).is_err());
    assert!(validate_complete_coverage(106, 26, 530).is_err());
    assert!(validate_complete_coverage(106, 27, 529).is_err());

    let mut seen = HashSet::new();
    insert_unique_output("clib/example_protos.h", &mut seen).unwrap();
    assert!(insert_unique_output("clib/example_protos.h", &mut seen).is_err());

    let valid = test_recipe("example", "compiler/crt/example/example.conf", false);
    parse_header_recipe(&valid).unwrap();

    let traversal = test_recipe("example", "../outside.conf", false);
    assert!(parse_header_recipe(&traversal).is_err());
    let mut traversal_output = valid.clone();
    traversal_output["outputs"][0] = json!("../outside.h");
    assert!(parse_header_recipe(&traversal_output).is_err());

    let mut unknown_argv = test_recipe("example", "compiler/crt/example/example.conf", false);
    let mut args = unknown_argv["generator_args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let insertion = args
        .iter()
        .position(|item| item == "writeincludes")
        .unwrap();
    args.splice(
        insertion..insertion,
        ["--unexpected".to_owned(), "value".to_owned()],
    );
    unknown_argv["generator_args"] = json!(args.clone());
    unknown_argv["argv"] = json!(
        std::iter::once("AROS-NX/build/pc-x86_64/hosttools/genmodule".to_owned())
            .chain(args)
            .collect::<Vec<_>>()
    );
    assert!(parse_header_recipe(&unknown_argv).is_err());

    let mut wrong_override = test_recipe(
        "mesa3dgl",
        "workbench/libs/mesa/mesa-20.0.8/mesa3dgl.conf",
        true,
    );
    wrong_override["output_override"] = json!({
        "kind": "build",
        "path": "build/pc-x86_64/Ports/mesa/other.conf",
        "provenance": "accepted-extra-field",
    });
    assert!(parse_header_recipe(&wrong_override).is_err());
}

#[test]
fn header_recipe_accepts_extra_authenticated_provenance_fields() {
    let mut recipe = test_recipe("example", "compiler/crt/example/example.conf", false);
    recipe["provenance"] = json!({"input_sha256": "opaque-authenticated-value"});
    recipe["recipe_index"] = json!(17);
    parse_header_recipe(&recipe).unwrap();
}

#[test]
fn mesa_patch_selects_one_complete_added_file_and_checks_its_pin() {
    let patch = mesa_patch();
    let pin: [u8; 32] = Sha256::digest(&patch).into();
    let block = mesa_added_config_patch(&patch, &pin).unwrap();
    assert_eq!(block, patch.as_slice());
    validate_complete_added_file_block(&block).unwrap();

    let ambiguous = [patch.as_slice(), patch.as_slice()].concat();
    let ambiguous_pin: [u8; 32] = Sha256::digest(&ambiguous).into();
    assert!(mesa_added_config_patch(&ambiguous, &ambiguous_pin).is_err());

    let incomplete = mesa_patch_with_hunk_count(3);
    let incomplete_pin: [u8; 32] = Sha256::digest(&incomplete).into();
    assert!(mesa_added_config_patch(&incomplete, &incomplete_pin).is_err());
    assert!(mesa_added_config_patch(&patch, &[0; 32]).is_err());
}

#[test]
fn fresh_destination_rejects_existing_directories_and_symlinks() {
    let temp = TempDir::new();
    let existing = temp.path().join("existing");
    fs::create_dir(&existing).unwrap();
    let link = temp.path().join("destination-link");
    symlink(&existing, &link).unwrap();
    let fresh = temp.path().join("fresh");

    assert!(require_fresh_destination(&existing).is_err());
    assert!(require_fresh_destination(&link).is_err());
    require_fresh_destination(&fresh).unwrap();

    let inputs = temp.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    fs::write(inputs.join("regular.conf"), b"config").unwrap();
    symlink(inputs.join("regular.conf"), inputs.join("config-link.conf")).unwrap();
    let input_root = Directory::open(&inputs).unwrap();
    assert!(super::read_relative_file(&input_root, "config-link.conf", 64).is_err());
}

#[test]
fn malformed_recipe_is_rejected_before_destination_creation() {
    let mut fixture = ReproductionFixture::new();
    fixture.request.header_recipes[0]["generator_args"] = json!([
        "-c",
        "AROS-NX/compiler/crt/test_000/test_000.conf",
        "-d",
        "AROS-NX/build/pc-x86_64/genmodule/test_000/include",
        "--unexpected",
        "value",
        "writeincludes",
        "test_000",
        "library"
    ]);
    let destination = fixture.request.destination.clone();
    let error = generate_public_headers(
        fixture.request,
        |_argv, _cwd, _label, _timeout| -> Result<Value> {
            panic!("invalid recipe must fail before invoking the runner");
        },
        |_label| Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("unexpected or incomplete"));
    assert!(!destination.exists());
}

#[test]
fn callback_refusal_after_root_creation_retains_the_private_root() {
    let fixture = ReproductionFixture::new();
    let destination = fixture.request.destination.clone();
    let request = fixture.request;
    let error = generate_public_headers(
        request,
        |_argv, _cwd, _label, _timeout| -> Result<Value> {
            panic!("runner must not be called after a checkpoint refusal");
        },
        |label| {
            if label == "after creating the private public-header root" {
                Err(Refusal::new("test checkpoint refusal"))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("test checkpoint refusal"));
    assert!(destination.is_dir());
    assert!(
        !fs::symlink_metadata(destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn runner_refusal_after_root_creation_retains_the_private_root() {
    let fixture = ReproductionFixture::new();
    let destination = fixture.request.destination.clone();
    let request = fixture.request;
    let error = generate_public_headers(
        request,
        |argv, _cwd, label, timeout| -> Result<Value> {
            assert_eq!(label, "header-native-compiler-version");
            assert_eq!(timeout, Duration::from_secs(30));
            assert_eq!(argv.len(), 2);
            assert_eq!(argv[1], "--version");
            Err(Refusal::new("test runner refusal"))
        },
        |_label| Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("test runner refusal"));
    assert!(destination.is_dir());
    assert!(
        !fs::symlink_metadata(destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

struct ReproductionFixture {
    request: CsdkHeadersRequest,
    _temp: TempDir,
}

impl ReproductionFixture {
    fn new() -> Self {
        // This fixture reaches only preflight/refusal paths. Its fake compiler
        // bytes are not executable compiler evidence or a reproduction proof.
        let temp = TempDir::new();
        let source = temp.path().join("source");
        let frozen_include = temp.path().join("frozen-include");
        let destination = temp.path().join("headers-output");
        let compiler = temp.path().join("cc");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&frozen_include).unwrap();

        let mut recipes = Vec::with_capacity(HEADER_RECIPE_COUNT);
        for index in 0..HEADER_RECIPE_COUNT {
            let module = format!("test_{index:03}");
            let config = format!("compiler/crt/{module}/{module}.conf");
            let config_path = source.join(&config);
            fs::create_dir_all(config_path.parent().unwrap()).unwrap();
            fs::write(&config_path, format!("config for {module}\n")).unwrap();

            let recipe = test_recipe(&module, &config, false);
            for output in recipe["outputs"].as_array().unwrap() {
                let output = output.as_str().unwrap();
                let path = frozen_include.join(output);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                let banner = format!(
                    "/* Automatically generated from '/old/AROS-NX/{config}'. */\n#define TEST_VALUE {index}\n"
                );
                fs::write(path, banner).unwrap();
            }
            recipes.push(recipe);
        }

        let source_list = (0..27)
            .map(|index| format!("{SOURCE_GENERATOR_PREFIX}test_{index:02}.c"))
            .collect::<Vec<_>>();
        for source_path in &source_list {
            let path = source.join(source_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"int main(void) { return 0; }\n").unwrap();
        }

        let patch = mesa_patch();
        let patch_path = source.join("workbench/libs/mesa/mesa-20.0.8-aros.diff");
        fs::create_dir_all(patch_path.parent().unwrap()).unwrap();
        fs::write(patch_path, &patch).unwrap();
        fs::write(&compiler, b"test compiler identity").unwrap();
        let mut permissions = fs::metadata(&compiler).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&compiler, permissions).unwrap();

        let pin = CsdkSourceFilePin {
            bytes: fs::metadata(&compiler).unwrap().len(),
            sha256: Sha256::digest(fs::read(&compiler).unwrap()).into(),
        };
        let patch_pin: [u8; 32] = Sha256::digest(&patch).into();
        Self {
            request: CsdkHeadersRequest {
                source,
                frozen_include,
                header_recipes: recipes,
                generator_recipe: json!({"sources": source_list, "extra": true}),
                destination: destination.clone(),
                compiler,
                compiler_pin: pin,
                mesa_patch_sha256: patch_pin,
                forbidden_path_prefixes: vec![b"/forbidden/header/root".to_vec()],
            },
            _temp: temp,
        }
    }
}

fn test_recipe(module: &str, config: &str, mesa_override: bool) -> Value {
    let outputs: Vec<String> = expected_header_group(module).into_iter().collect();
    let output_directory = format!("AROS-NX/build/pc-x86_64/genmodule/{module}/include");
    let mut generator_args = vec![
        "-c".to_owned(),
        format!("AROS-NX/{config}"),
        "-d".to_owned(),
        output_directory.clone(),
    ];
    if mesa_override {
        generator_args.push("-o".to_owned());
        generator_args.push(format!("AROS-NX/{MESA_CONFIG_PATH}"));
    }
    generator_args.extend([
        "writeincludes".to_owned(),
        module.to_owned(),
        "library".to_owned(),
    ]);
    let argv = std::iter::once("AROS-NX/build/pc-x86_64/hosttools/genmodule".to_owned())
        .chain(generator_args.clone())
        .collect::<Vec<_>>();
    json!({
        "config": config,
        "outputs": outputs,
        "generator_args": generator_args,
        "output_directory": format!("build/pc-x86_64/genmodule/{module}/include"),
        "output_override": if mesa_override {
            json!({"kind":"build","path":MESA_CONFIG_PATH})
        } else {
            Value::Null
        },
        "module": module,
        "module_type": "library",
        "module_suffix": Value::Null,
        "argv": argv,
        "cwd": "build/pc-x86_64",
        "original_cwd": "AROS-NX/build/pc-x86_64",
        "extra_authenticated_provenance": {"source_recipe": "frozen"},
    })
}

fn mesa_patch() -> Vec<u8> {
    mesa_patch_with_hunk_count(2)
}

fn mesa_patch_with_hunk_count(count: usize) -> Vec<u8> {
    let mut patch = MESA_DIFF_HEADER.to_vec();
    patch.extend_from_slice(
        b"--- mesa-20.0.8/mesa3dgl.conf\t2020-01-01\n+++ mesa-20.0.8.aros/mesa3dgl.conf\t2020-01-01\n",
    );
    patch.extend_from_slice(format!("@@ -0,0 +1,{count} @@\n").as_bytes());
    patch.extend_from_slice(b"+first line\n+second line\n");
    patch
}
