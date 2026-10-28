use super::apply_csdk_source_patches;
use crate::{
    Refusal,
    csdk_source::{CsdkSourceFilePin, CsdkSourceRoots},
    digest::sha256_bytes,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory");
        for _ in 0..100 {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "ami-rust-csdk-patches-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create temporary root: {error}"),
            }
        }
        panic!("could not allocate a unique temporary root");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove temporary root");
    }
}

struct PatchSpec<'a> {
    component: &'a str,
    path: &'a str,
    before: &'a str,
    after: &'a str,
    patch_name: String,
    patch_text: String,
}

impl<'a> PatchSpec<'a> {
    fn new(component: &'a str, path: &'a str, before: &'a str, after: &'a str) -> Self {
        Self {
            component,
            path,
            before,
            after,
            patch_name: "change.patch".to_owned(),
            patch_text: patch_text(path),
        }
    }

    fn row(&self) -> Value {
        json!({
            "component": self.component,
            "path": self.path,
            "patch": self.patch_name,
            "before_sha256": sha256_bytes(self.before.as_bytes()),
            "after_sha256": sha256_bytes(self.after.as_bytes()),
            "patch_sha256": sha256_bytes(self.patch_text.as_bytes()),
            "base": {"revision": "provenance-only"}
        })
    }
}

struct Fixture {
    _temp: TempDir,
    roots: CsdkSourceRoots,
    patch_directory: PathBuf,
    series_pin: CsdkSourceFilePin,
    value: Value,
    specs: Vec<PatchSpec<'static>>,
}

impl Fixture {
    fn new(mut specs: Vec<PatchSpec<'static>>) -> Self {
        let temp = TempDir::new();
        let mut patch_names = std::collections::BTreeSet::new();
        for (index, spec) in specs.iter_mut().enumerate() {
            if !patch_names.insert(spec.patch_name.clone()) {
                spec.patch_name = format!("patch-{index}.patch");
                assert!(patch_names.insert(spec.patch_name.clone()));
            }
        }
        let destination = temp.path().join("materialized");
        for component in ["AROS-NX", "aros-tools", "libaom"] {
            fs::create_dir_all(destination.join("sources").join(component))
                .expect("create typed source root");
        }
        let roots = CsdkSourceRoots {
            aros_nx: destination.join("sources/AROS-NX"),
            aros_tools: destination.join("sources/aros-tools"),
            libaom: destination.join("sources/libaom"),
            destination,
        };
        let patch_directory = temp.path().join("patches");
        fs::create_dir(&patch_directory).expect("create patch directory");
        for spec in &specs {
            let target = component_root(&roots, spec.component).join(spec.path);
            fs::create_dir_all(target.parent().expect("target parent"))
                .expect("create target parent");
            fs::write(target, spec.before).expect("write target preimage");
            fs::write(patch_directory.join(&spec.patch_name), &spec.patch_text)
                .expect("write patch text");
        }
        let mut fixture = Self {
            _temp: temp,
            roots,
            patch_directory,
            series_pin: CsdkSourceFilePin {
                bytes: 0,
                sha256: [0; 32],
            },
            value: Value::Null,
            specs,
        };
        fixture.reset_series();
        fixture
    }

    fn basic() -> Self {
        Self::new(vec![PatchSpec::new(
            "aros-tools",
            "nested/source.c",
            "old source\n",
            "new source\n",
        )])
    }

    fn reset_series(&mut self) {
        self.value = json!({
            "schema": "ami-rust-portable-csdk-patches-v1",
            "revision": 2,
            "status": "PREPARED_NOT_QUALIFIED",
            "notes": ["metadata is provenance only"],
            "patches": self.specs.iter().map(|spec| spec.row()).collect::<Vec<_>>(),
        });
        self.install_value();
    }

    fn install_value(&mut self) {
        let bytes = serde_json::to_vec(&self.value).expect("encode patch series");
        self.install_bytes(&bytes);
    }

    fn install_bytes(&mut self, bytes: &[u8]) {
        fs::write(self.patch_directory.join("series.json"), bytes).expect("write patch series");
        self.series_pin = CsdkSourceFilePin {
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
        };
    }

    fn set_patch_text(&mut self, index: usize, text: String, update_pin: bool) {
        fs::write(
            self.patch_directory.join(&self.specs[index].patch_name),
            &text,
        )
        .expect("replace patch text");
        self.specs[index].patch_text = text;
        if update_pin {
            self.value["patches"][index]["patch_sha256"] =
                json!(sha256_bytes(self.specs[index].patch_text.as_bytes()));
            self.install_value();
        }
    }

    fn target(&self, index: usize) -> PathBuf {
        component_root(&self.roots, self.specs[index].component).join(self.specs[index].path)
    }

    fn run_with(
        &self,
        run: impl FnMut(&[OsString], &Path, &str, Duration) -> crate::Result<()>,
        checkpoint: impl FnMut(&str) -> crate::Result<()>,
    ) -> crate::Result<Vec<Value>> {
        apply_csdk_source_patches(
            &self.roots,
            &self.patch_directory,
            self.series_pin,
            run,
            checkpoint,
        )
    }
}

fn component_root<'a>(roots: &'a CsdkSourceRoots, component: &str) -> &'a Path {
    match component {
        "AROS-NX" => &roots.aros_nx,
        "aros-tools" => &roots.aros_tools,
        "libaom" => &roots.libaom,
        _ => panic!("unknown test component"),
    }
}

fn patch_text(path: &str) -> String {
    format!("--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old source\n+new source\n")
}

fn rejected_without_runner(fixture: &Fixture) -> String {
    let mut called = false;
    let error = fixture
        .run_with(
            |_, _, _, _| {
                called = true;
                Ok(())
            },
            |_| Ok(()),
        )
        .expect_err("invalid fixture must be refused");
    assert!(!called, "invalid input must be rejected before mutation");
    error.to_string()
}

#[test]
fn applies_with_typed_runner_contract_and_semantic_receipt() {
    // This stub proves the native callback contract and hash checks. It does not
    // prove the behavior of /usr/bin/patch; real pinned-patch checks are external.
    let fixture = Fixture::basic();
    let target = fixture.target(0);
    let patch_path = fixture.patch_directory.join("change.patch");
    let cwd = fixture.roots.aros_tools.clone();
    let mut callbacks = 0;
    let receipts = fixture
        .run_with(
            |arguments, actual_cwd, label, timeout| {
                assert_eq!(
                    arguments,
                    &[
                        OsString::from("/usr/bin/patch"),
                        OsString::from("--batch"),
                        OsString::from("--forward"),
                        OsString::from("--fuzz=0"),
                        OsString::from("-p1"),
                        OsString::from("-i"),
                        patch_path.as_os_str().to_owned(),
                    ]
                );
                assert_eq!(actual_cwd, cwd.as_path());
                assert_eq!(label, "patch-0-aros-tools");
                assert_eq!(timeout, Duration::from_secs(30));
                fs::write(&target, "new source\n").expect("simulate patch output");
                Ok(())
            },
            |_| {
                callbacks += 1;
                Ok(())
            },
        )
        .expect("valid stub patch succeeds");
    assert!(
        callbacks > 4,
        "checkpoint runs while reading and between stages"
    );
    assert_eq!(
        fs::read_to_string(target).expect("read patched source"),
        "new source\n"
    );
    assert_eq!(
        receipts,
        vec![json!({
            "component": "aros-tools",
            "path": "nested/source.c",
            "before_sha256": sha256_bytes(b"old source\n"),
            "after_sha256": sha256_bytes(b"new source\n"),
            "patch_sha256": sha256_bytes(fixture.specs[0].patch_text.as_bytes()),
        })]
    );
}

#[test]
fn rejects_a_series_that_does_not_match_its_exact_pin() {
    let mut fixture = Fixture::basic();
    fixture.series_pin.bytes += 1;
    assert!(rejected_without_runner(&fixture).contains("length differs"));

    let mut fixture = Fixture::basic();
    fixture.series_pin.sha256[0] ^= 1;
    assert!(rejected_without_runner(&fixture).contains("bytes differ from their pin"));
}

#[test]
fn rejects_malformed_and_duplicate_key_series_json() {
    for raw in [
        b"{".as_slice(),
        br#"{"schema":"ami-rust-portable-csdk-patches-v1","schema":"ami-rust-portable-csdk-patches-v1","patches":[]}"#,
    ] {
        let mut fixture = Fixture::basic();
        fixture.install_bytes(raw);
        assert!(rejected_without_runner(&fixture).contains("invalid JSON"));
    }
}

#[test]
fn rejects_unsupported_component_traversal_and_duplicate_targets() {
    let mut unsupported = Fixture::basic();
    unsupported.value["patches"][0]["component"] = json!("nxpk");
    unsupported.install_value();
    assert!(rejected_without_runner(&unsupported).contains("unsupported"));

    let mut traversal = Fixture::basic();
    traversal.value["patches"][0]["path"] = json!("../outside.c");
    traversal.install_value();
    assert!(rejected_without_runner(&traversal).contains("portable relative path"));

    let mut duplicate = Fixture::new(vec![
        PatchSpec::new("aros-tools", "one.c", "a", "b"),
        PatchSpec::new("aros-tools", "one.c", "a", "b"),
    ]);
    duplicate.specs[1].patch_name = "second.patch".to_owned();
    fs::write(
        duplicate.patch_directory.join("second.patch"),
        &duplicate.specs[1].patch_text,
    )
    .expect("write second duplicate patch");
    duplicate.reset_series();
    assert!(rejected_without_runner(&duplicate).contains("duplicate target"));
}

#[test]
fn preflights_all_rows_before_the_first_mutation() {
    let mut fixture = Fixture::new(vec![
        PatchSpec::new("aros-tools", "first.c", "one", "ONE"),
        PatchSpec::new("AROS-NX", "second.c", "two", "TWO"),
    ]);
    let second = fixture.target(1);
    fixture.value["patches"][1]["before_sha256"] = json!(sha256_bytes(b"wrong preimage"));
    fixture.install_value();
    let error = rejected_without_runner(&fixture);
    assert!(error.contains("preimage hash"));
    assert_eq!(
        fs::read_to_string(second).expect("read untouched second file"),
        "two"
    );
}

#[test]
fn rejects_wrong_preimage_patch_hash_headers_and_multiple_file_headers() {
    let mut preimage = Fixture::basic();
    preimage.value["patches"][0]["before_sha256"] = json!(sha256_bytes(b"wrong"));
    preimage.install_value();
    assert!(rejected_without_runner(&preimage).contains("preimage hash"));

    let mut patch_hash = Fixture::basic();
    patch_hash.value["patches"][0]["patch_sha256"] = json!(sha256_bytes(b"wrong patch"));
    patch_hash.install_value();
    assert!(rejected_without_runner(&patch_hash).contains("patch bytes differ"));

    let mut wrong_header = Fixture::basic();
    wrong_header.set_patch_text(0, patch_text("other.c"), true);
    assert!(rejected_without_runner(&wrong_header).contains("file headers"));

    let mut multi_file = Fixture::basic();
    let text = format!(
        "{}--- a/other.c\n+++ b/other.c\n@@ -1 +1 @@\n-old\n+new\n",
        patch_text("nested/source.c")
    );
    multi_file.set_patch_text(0, text, true);
    assert!(rejected_without_runner(&multi_file).contains("file headers"));
}

#[test]
fn refuses_symlink_targets_ancestors_and_patch_files() {
    let target = Fixture::basic();
    let outside = target._temp.path().join("outside-target");
    fs::write(&outside, "old source\n").expect("write external target");
    fs::remove_file(target.target(0)).expect("remove target");
    symlink(&outside, target.target(0)).expect("make target symlink");
    assert!(!rejected_without_runner(&target).is_empty());

    let ancestor = Fixture::basic();
    let outside_directory = ancestor._temp.path().join("outside-directory");
    fs::create_dir(&outside_directory).expect("create external directory");
    fs::write(outside_directory.join("source.c"), "old source\n").expect("write external source");
    let target_parent = ancestor
        .target(0)
        .parent()
        .expect("target parent")
        .to_path_buf();
    fs::remove_dir_all(&target_parent).expect("remove target parent");
    symlink(&outside_directory, &target_parent).expect("make ancestor symlink");
    assert!(!rejected_without_runner(&ancestor).is_empty());

    let patch = Fixture::basic();
    let outside_patch = patch._temp.path().join("outside.patch");
    fs::write(&outside_patch, &patch.specs[0].patch_text).expect("write external patch");
    fs::remove_file(patch.patch_directory.join("change.patch")).expect("remove patch");
    symlink(&outside_patch, patch.patch_directory.join("change.patch"))
        .expect("make patch symlink");
    assert!(!rejected_without_runner(&patch).is_empty());
}

#[test]
fn rejects_wrong_postimage_without_returning_a_receipt() {
    let fixture = Fixture::basic();
    let target = fixture.target(0);
    let error = fixture
        .run_with(
            |_, _, _, _| {
                fs::write(&target, "unexpected output\n").expect("write wrong output");
                Ok(())
            },
            |_| Ok(()),
        )
        .expect_err("wrong postimage must fail");
    assert!(error.to_string().contains("after-image hash"));
    assert!(error.to_string().contains("partial patch changes"));
}

#[test]
fn runner_failure_stops_later_mutations_and_keeps_staging_for_recovery() {
    let fixture = Fixture::new(vec![
        PatchSpec::new("aros-tools", "first.c", "one", "ONE"),
        PatchSpec::new("AROS-NX", "second.c", "two", "TWO"),
    ]);
    let first = fixture.target(0);
    let second = fixture.target(1);
    let mut calls = 0;
    let error = fixture
        .run_with(
            |_, _, _, _| {
                calls += 1;
                fs::write(&first, "ONE").expect("simulate partial first patch");
                Err(Refusal::new("supervised runner failed"))
            },
            |_| Ok(()),
        )
        .expect_err("runner failure must propagate");
    assert_eq!(calls, 1);
    assert_eq!(
        fs::read_to_string(&first).expect("read partial output"),
        "ONE"
    );
    assert_eq!(
        fs::read_to_string(&second).expect("read untouched output"),
        "two"
    );
    assert!(error.to_string().contains("partial patch changes"));
}

#[test]
fn checkpoint_failure_between_mutations_prevents_the_next_runner() {
    let fixture = Fixture::new(vec![
        PatchSpec::new("aros-tools", "first.c", "one", "ONE"),
        PatchSpec::new("AROS-NX", "second.c", "two", "TWO"),
    ]);
    let first = fixture.target(0);
    let second = fixture.target(1);
    let mut calls = 0;
    let error = fixture
        .run_with(
            |_, cwd, _, _| {
                calls += 1;
                let component = if cwd == fixture.roots.aros_tools.as_path() {
                    "first.c"
                } else {
                    "second.c"
                };
                fs::write(cwd.join(component), if calls == 1 { "ONE" } else { "TWO" })
                    .expect("simulate patch output");
                Ok(())
            },
            |label| {
                if label == "between C-SDK source patch mutations" {
                    Err(Refusal::new("checkpoint requested cancellation"))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("checkpoint failure must stop the sequence");
    assert_eq!(calls, 1);
    assert_eq!(
        fs::read_to_string(&first).expect("read first output"),
        "ONE"
    );
    assert_eq!(
        fs::read_to_string(&second).expect("read untouched second"),
        "two"
    );
    assert!(error.to_string().contains("partial patch changes"));
}

#[test]
fn checkpoint_failure_during_input_streaming_starts_no_runner() {
    let fixture = Fixture::basic();
    let mut calls = 0;
    let error = fixture
        .run_with(
            |_, _, _, _| {
                calls += 1;
                Ok(())
            },
            |label| {
                if label == "reading pinned C-SDK patch series" {
                    Err(Refusal::new("checkpoint failed during series read"))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("streaming checkpoint failure must propagate");
    assert_eq!(calls, 0);
    assert!(error.to_string().contains("checkpoint failed"));
}
