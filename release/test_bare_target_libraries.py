#!/usr/bin/env python3
"""Focused unit fixtures for the frozen wrapper; all bytes are UNIT_FIXTURE only."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "tools/supervise-bare-target-libraries.py"
DRIVER_SHA256 = "4a5b44aacea7ce38bdf9c5be590e87599ad7cd1128663ccd6697494dc1b67bd7"
LABELS = ("rustc-version", "rustc-sysroot", "cargo-version", "rust-objcopy-version", "source-production")
LIMITS = {"seconds": 1200, "rss_bytes": 4 * 1024**3, "workspace_bytes": 12 * 1024**3, "log_bytes": 16 * 1024**2}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
PRODUCER_SCHEMA = "ami-rust-bare-target-library-producer-v1"
PRODUCER_STATUS = "PRODUCED_BARE_TARGET_LIBRARIES_NOT_L1_OR_RC_QUALIFICATION"
RUST_COMMIT = "330d317121e16b5db8e5adc63595910528ff2ee7"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def load_driver():
    if not DRIVER_PATH.is_file() or file_digest(DRIVER_PATH) != DRIVER_SHA256:
        raise RuntimeError("the frozen A3 wrapper is missing or has changed")
    spec = importlib.util.spec_from_file_location("frozen_bare_target_wrapper", DRIVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import frozen A3 wrapper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DRIVER = load_driver()


def metadata_for_lock(lock_path: Path, repo: Path) -> dict:
    rows = tomllib.loads(lock_path.read_text(encoding="utf-8"))["package"]
    local = {row["name"]: row for row in rows if row.get("source") is None}
    packages = []
    for name in ("ami-rust-core", "ami-rust-xtask", "aros-elf"):
        version = local.get(name, {}).get("version", "0.0.0")
        manifest = repo / "tooling/crates" / name / "Cargo.toml"
        packages.append({"id": f"path+file://{manifest.parent}#{name}@{version}",
                         "name": name, "version": version, "source": None,
                         "manifest_path": str(manifest), "dependencies": [], "targets": [], "features": {}})
    for row in rows:
        source = row.get("source")
        if isinstance(source, str) and source.startswith("registry+"):
            name, version = row["name"], row["version"]
            packages.append({"id": f"{source}#{name}@{version}", "name": name, "version": version,
                             "source": source, "manifest_path": str(repo / "tooling/.cargo/registry/src/Cargo.toml"),
                             "dependencies": [], "targets": [], "features": {}})
    return {"version": 1, "workspace_root": str(repo / "tooling"),
            "workspace_members": [row["id"] for row in packages[:3]], "packages": packages}


class BareTargetWrapperFixtures(unittest.TestCase):
    """Small synthetic records exercise validators without build/delivery bytes."""

    @classmethod
    def setUpClass(cls):
        cls.repo = ROOT.resolve()
        cls.lock = cls.repo / "tooling/Cargo.lock"
        cls.registry_rows = [row for row in tomllib.loads(cls.lock.read_text(encoding="utf-8"))["package"]
                             if isinstance(row.get("source"), str) and row["source"].startswith("registry+")]
        if len(cls.registry_rows) != 29 or tuple(DRIVER.INNER_COMMAND_LABELS) != LABELS or DRIVER.INNER_LIMITS != LIMITS:
            raise RuntimeError("pinned lock or A2 fixture contract changed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bare-target-unit-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_actual_checkout_source_pins_match_all_three_hosts(self):
        for host in DRIVER.HOSTS:
            with self.subTest(host=host):
                rows = DRIVER.verify_source_inputs(self.repo, host)
                module = "tooling/crates/xtask/src/bare_target_producer.rs"
                self.assertEqual(rows[module]["sha256"], file_digest(self.repo / module))

    def test_stale_producer_source_pin_is_refused_for_all_three_hosts(self):
        old_pin = "a2fd57fec83f1d32372b4aeac0a74445ad049a57875b26da371ed139ce48e0de"
        with mock.patch.object(DRIVER, "XTASK_MODULE_SHA", old_pin):
            for host in DRIVER.HOSTS:
                with self.subTest(host=host):
                    with self.assertRaisesRegex(ValueError, "pinned source input differs: tooling/crates/xtask/src/bare_target_producer.rs"):
                        DRIVER.verify_source_inputs(self.repo, host)

    def test_stale_shared_monitor_pin_is_refused_for_all_three_hosts(self):
        old_pins = (
            ("CI_CARGO_SHA", "589a8abc9fc4b0537b4b9646d441413f4eb005288bbc3ea0220f5218ffc18da2",
             "pinned source input differs: release/ci_cargo.py"),
            ("MONITOR_SHA", "8c809ff9ab2f22b17696931f0a5731a2154616f02c9a66232947f73f3b84e0d4",
             "pinned source input differs: tools/supervise-native-cargo.py"),
        )
        for constant, old_pin, expected in old_pins:
            with self.subTest(constant=constant):
                with mock.patch.object(DRIVER, constant, old_pin):
                    for host in DRIVER.HOSTS:
                        with self.subTest(host=host):
                            with self.assertRaisesRegex(ValueError, expected):
                                DRIVER.verify_source_inputs(self.repo, host)

    def producer_fixture(self, name):
        """Build a producer-shaped receipt with tiny UNIT_FIXTURE-only files."""
        out = self.base / name / "producer"
        (out / "records").mkdir(parents=True)
        (out / "requests").mkdir()
        (out / "libraries").mkdir()
        inventory = out / "component-inventory.json"
        inventory.write_bytes(b'{"fixture":"UNIT_FIXTURE; not delivery inventory"}\n')
        cargo = b"UNIT_FIXTURE Cargo member; not executable"
        cargo_id = {"bytes": len(cargo), "sha256": digest(cargo)}
        profile_sha = digest(b"UNIT_FIXTURE profile")
        receipt = {"native_cargo": {"binary": dict(cargo_id)}}
        host = {"native_cargo": {"member": dict(cargo_id)}}
        summaries = []
        for label in LABELS:
            stdout, stderr = f"UNIT_FIXTURE {label}\n".encode(), b""
            request = {"schema": "ami-rust-native-command-qualification-request-v1",
                       "program": "/UNIT_FIXTURE/bin/tool", "args": ["--fixture", label],
                       "cwd": "/UNIT_FIXTURE/work", "environment": {"FIXTURE": "true"},
                       "required_roots": ["/UNIT_FIXTURE/work", "/UNIT_FIXTURE/output"], "limits": LIMITS}
            request_path = out / "requests" / f"{label}.json"
            write_json(request_path, request)
            request_sha = file_digest(request_path)
            record = {"schema": "ami-rust-native-command-qualification-record-v1",
                      "scope": "UNIT_FIXTURE only; no command executed", "passed": True, "refusal": None,
                      "request_sha256": request_sha, "command": {"program": request["program"],
                      "args": request["args"], "cwd": request["cwd"]}, "limits": dict(LIMITS),
                      "elapsed_nanos": 1, "capture_complete": True, "capture_error": None,
                      "child_exit_code": 0, "child_signal": None, "aggregate_peak_rss_bytes": 1024,
                      "workspace_bytes_at_finish": 512, "log_bytes_at_finish": len(stdout),
                      "stdout": {"bytes": len(stdout), "sha256": digest(stdout)},
                      "stderr": {"bytes": 0, "sha256": digest(stderr)},
                      "resource_report": {"sample_count": 1, "last_sample_complete": True,
                                          "incomplete_cleanup": False}}
            directory = out / "records" / label
            directory.mkdir()
            record_path = directory / "result.json"
            write_json(record_path, record)
            (directory / "stdout.log").write_bytes(stdout)
            (directory / "stderr.log").write_bytes(stderr)
            summaries.append({"label": label, "passed": True, "child_exit_code": 0,
                              "aggregate_peak_rss_bytes": 1024, "peak_workspace_bytes": 512,
                              "peak_log_bytes": len(stdout), "record_path": str(record_path.resolve()),
                              "request_path": str(request_path.resolve()), "request_sha256": request_sha,
                              "result_sha256": file_digest(record_path)})
        libraries = []
        for crate in ("core", "alloc", "compiler_builtins"):
            filename = f"lib{crate}-UNIT_FIXTURE.rlib"
            path = out / "libraries" / filename
            path.write_bytes(f"UNIT_FIXTURE non-delivery rlib bytes: {crate}".encode())
            libraries.append({"crate": crate, "path": filename, "bytes": path.stat().st_size,
                              "sha256": file_digest(path), "source_filename": filename})
        write_json(out / "producer.json", {"schema": PRODUCER_SCHEMA, "status": PRODUCER_STATUS,
            "target": "x86_64-aros", "rustc_commit": RUST_COMMIT, "input_profile_sha256": profile_sha,
            "native_cargo_override": cargo_id, "scoped_component_inventory_sha256": file_digest(inventory),
            "qualification_commands": summaries, "libraries": libraries})
        return out, receipt, host, profile_sha

    def validate(self, fixture):
        return DRIVER.validate_producer(*fixture)

    def mutate_record(self, fixture, label, change):
        out = fixture[0]
        path = out / "records" / label / "result.json"
        record = read_json(path)
        change(record)
        write_json(path, record)
        producer_path = out / "producer.json"
        producer = read_json(producer_path)
        next(row for row in producer["qualification_commands"] if row["label"] == label)["result_sha256"] = file_digest(path)
        write_json(producer_path, producer)

    def reject(self, fixture, phrase):
        with self.assertRaisesRegex(ValueError, phrase):
            self.validate(fixture)

    def bootstrap_fixture(self, name):
        prefix = self.base / name / "prefix"
        sysroot = prefix / "source-sysroot"
        sysroot.mkdir(parents=True)
        cargo = prefix / "native-cargo/bin/cargo"
        cargo.parent.mkdir(parents=True)
        cargo.write_bytes(b"UNIT_FIXTURE Cargo; not executable content")
        cargo.chmod(0o755)
        member = {"bytes": cargo.stat().st_size, "sha256": file_digest(cargo)}
        host_row = {"native_cargo": {"artifact_id": 123456, "member": dict(member)}}
        context = {"host_key": "macos-aarch64", "triple": "aarch64-apple-darwin",
                   "profile": "tooling/crates/aros-native-build/pins/macos-aarch64/rust.json",
                   "profile_sha": digest(b"UNIT_FIXTURE profile"), "host_row": host_row}
        receipt = {"schema": DRIVER.BOOTSTRAP_SCHEMA, "status": DRIVER.BOOTSTRAP_STATUS,
                   "host": context["host_key"], "host_triple": context["triple"],
                   "manifest_sha256": DRIVER.INPUTS_SHA,
                   "source_profile": {"path": context["profile"], "sha256": context["profile_sha"]},
                   "source_sysroot": str(sysroot),
                   "native_cargo": {"artifact_id": 123456,
                                    "binary": {"path": str(cargo), **member, "mode_octal": "0755"}},
                   "target_spec": {"path": DRIVER.TARGET_SPEC_PATH, "sha256": DRIVER.TARGET_SPEC_SHA,
                                   "staged_by_later_producer": True},
                   "target_alias": {"path": DRIVER.TARGET_ALIAS_PATH,
                                    "target": DRIVER.TARGET_ALIAS_TARGET,
                                    "materialized_by_later_producer": True}}
        return prefix, receipt, context

    def test_synthetic_bootstrap_receipt_passes_through_symlinked_parent(self):
        prefix, receipt, context = self.bootstrap_fixture("bootstrap-valid")
        alias_parent = self.base / "parent-alias"
        alias_parent.symlink_to(prefix.parent, target_is_directory=True)
        paths = DRIVER.validate_bootstrap_receipt(receipt, alias_parent / "prefix", context)
        self.assertEqual(paths["source_sysroot"], (prefix / "source-sysroot").resolve())
        self.assertEqual(paths["native_cargo"], (prefix / "native-cargo/bin/cargo").resolve())

    def test_bootstrap_projection_accepts_all_three_actual_archive_ledger_names(self):
        for host in ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
            with self.subTest(host=host):
                prefix = self.base / host / "prefix"
                records = prefix / "records"
                records.mkdir(parents=True)
                artifact = self.base / host / "artifact"
                (artifact / "input-provenance").mkdir(parents=True)
                names = {f"rustc-nightly-{host}.members.txt", f"rust-std-nightly-{host}.members.txt",
                         "rust-src-nightly.members.txt", *DRIVER.BOOTSTRAP_RECORD_NAMES}
                self.assertEqual(len(names), 6)
                for name in names:
                    (records / name).write_bytes(b"UNIT_FIXTURE archive ledger\n")
                (prefix / "downloaded-archive.tar.xz").write_bytes(b"UNIT_FIXTURE must not be retained")
                projected = DRIVER.retain_bootstrap_evidence(prefix, artifact)
                self.assertEqual({Path(row["path"]).name for row in projected["records"]}, names)
                self.assertIsNone(projected["receipt"])
                self.assertEqual(DRIVER.retain_bootstrap_evidence(prefix, artifact), projected)
                self.assertFalse(list(artifact.rglob("*.xz")))
                (records / "unexpected-archive.members.txt").write_bytes(b"UNIT_FIXTURE invalid ledger")
                with self.assertRaisesRegex(ValueError, "too many files"):
                    DRIVER.retain_bootstrap_evidence(prefix, artifact)
                (records / "unexpected-archive.members.txt").unlink()
                (records / "rust-src-nightly.members.txt").unlink()
                (records / "unexpected-archive.members.txt").write_bytes(b"UNIT_FIXTURE invalid ledger")
                with self.assertRaisesRegex(ValueError, "unexpected path"):
                    DRIVER.retain_bootstrap_evidence(prefix, artifact)

    def test_bootstrap_receipt_rejects_corrupted_identity_and_binding_fields(self):
        for field in ("schema", "status", "host", "manifest", "host_triple", "profile_sha",
                      "cargo_artifact", "cargo_sha", "cargo_bytes", "source_sysroot",
                      "profile_path", "cargo_path", "target_spec_path", "target_spec_sha",
                      "target_spec_staged", "target_alias_path", "target_alias_target", "target_alias_materialized"):
            with self.subTest(field=field):
                prefix, receipt, context = self.bootstrap_fixture("bootstrap-" + field)
                if field == "schema":
                    receipt["schema"] = "wrong"
                elif field == "status":
                    receipt["status"] = "wrong"
                elif field == "host":
                    receipt["host"] = "linux-x86_64"
                elif field == "manifest":
                    receipt["manifest_sha256"] = "0" * 64
                elif field == "host_triple":
                    receipt["host_triple"] = "wrong-triple"
                elif field == "profile_sha":
                    receipt["source_profile"]["sha256"] = "0" * 64
                elif field == "cargo_artifact":
                    receipt["native_cargo"]["artifact_id"] += 1
                elif field == "cargo_sha":
                    receipt["native_cargo"]["binary"]["sha256"] = "0" * 64
                elif field == "cargo_bytes":
                    receipt["native_cargo"]["binary"]["bytes"] += 1
                elif field == "source_sysroot":
                    wrong = prefix / "other-source-sysroot"
                    wrong.mkdir()
                    receipt["source_sysroot"] = str(wrong)
                elif field == "profile_path":
                    receipt["source_profile"]["path"] += ".wrong"
                elif field == "cargo_path":
                    wrong = prefix / "other-cargo"
                    wrong.write_bytes(b"UNIT_FIXTURE alternate Cargo")
                    wrong.chmod(0o755)
                    receipt["native_cargo"]["binary"]["path"] = str(wrong)
                elif field == "target_spec_path":
                    receipt["target_spec"]["path"] = "wrong/target.json"
                elif field == "target_spec_sha":
                    receipt["target_spec"]["sha256"] = "0" * 64
                elif field == "target_spec_staged":
                    receipt["target_spec"]["staged_by_later_producer"] = False
                elif field == "target_alias_path":
                    receipt["target_alias"]["path"] = "wrong/alias.json"
                elif field == "target_alias_target":
                    receipt["target_alias"]["target"] = "wrong.json"
                else:
                    receipt["target_alias"]["materialized_by_later_producer"] = False
                with self.assertRaisesRegex(ValueError, "A2 staging receipt"):
                    DRIVER.validate_bootstrap_receipt(receipt, prefix, context)

    def test_valid_synthetic_producer(self):
        result = self.validate(self.producer_fixture("valid"))
        self.assertEqual(result["status"], PRODUCER_STATUS)
        self.assertEqual([row["label"] for row in result["qualification_commands"]], list(LABELS))
        self.assertEqual({row["crate"] for row in result["libraries"]}, {"core", "alloc", "compiler_builtins"})

    def test_duplicate_or_missing_phase_is_rejected(self):
        for mode in ("duplicate", "missing"):
            with self.subTest(mode=mode):
                fixture = self.producer_fixture(mode)
                path = fixture[0] / "producer.json"
                producer = read_json(path)
                if mode == "duplicate":
                    producer["qualification_commands"][-1] = dict(producer["qualification_commands"][0])
                else:
                    producer["qualification_commands"].pop()
                write_json(path, producer)
                self.reject(fixture, "five retained qualified commands")

    def test_path_escape_is_rejected_with_rebound_external_hashes(self):
        fixture = self.producer_fixture("path-escape")
        out = fixture[0]
        path = out / "producer.json"
        producer = read_json(path)
        summary = producer["qualification_commands"][0]
        external = out.parent / "outside-output"
        request, record = external / "requests/rustc-version.json", external / "records/rustc-version/result.json"
        request.parent.mkdir(parents=True)
        record.parent.mkdir(parents=True)
        shutil.copyfile(summary["request_path"], request)
        shutil.copyfile(summary["record_path"], record)
        summary.update({"request_path": str(request.resolve()), "record_path": str(record.resolve()),
                        "request_sha256": file_digest(request), "result_sha256": file_digest(record)})
        write_json(path, producer)
        self.reject(fixture, "escapes output or differs from its digest")

    def test_request_digest_mismatch_is_rejected(self):
        fixture = self.producer_fixture("stale-request-hash")
        summary = read_json(fixture[0] / "producer.json")["qualification_commands"][0]
        path = Path(summary["request_path"])
        request = read_json(path)
        request["args"].append("--changed-without-rebinding")
        write_json(path, request)
        self.reject(fixture, "escapes output or differs from its digest")

    def test_semantic_record_controls_are_rejected_with_rebound_record_hash(self):
        changes = {
            "limits": (lambda row: row["limits"].update({"rss_bytes": 4096}), "pinned A4 contract"),
            "capture": (lambda row: row.update({"capture_complete": False}), "pinned A4 contract"),
            "cleanup": (lambda row: row["resource_report"].pop("incomplete_cleanup"), "incomplete"),
            "samples": (lambda row: row["resource_report"].update({"sample_count": 0}), "incomplete"),
        }
        for name, (change, phrase) in changes.items():
            with self.subTest(name=name):
                fixture = self.producer_fixture("bad-record-" + name)
                self.mutate_record(fixture, LABELS[0], change)
                self.reject(fixture, phrase)

    def test_raw_log_or_library_byte_mutation_is_rejected(self):
        fixture = self.producer_fixture("changed-log")
        (fixture[0] / "records/rustc-version/stdout.log").write_bytes(b"changed UNIT_FIXTURE log\n")
        self.reject(fixture, "raw log differs")
        fixture = self.producer_fixture("changed-library")
        (fixture[0] / "libraries/libcore-UNIT_FIXTURE.rlib").write_bytes(b"changed UNIT_FIXTURE library")
        self.reject(fixture, "library bytes/hash differ")

    def metadata_path(self, name, metadata):
        path = self.base / name
        write_json(path, metadata)
        return path

    def test_metadata_uses_version_one_registry_ids_and_lock_checksums(self):
        metadata = metadata_for_lock(self.lock, self.repo)
        self.assertTrue(all("checksum" not in row for row in metadata["packages"]))
        result = DRIVER.validate_metadata(self.metadata_path("metadata.json", metadata), self.lock, self.repo)
        self.assertEqual((result["metadata_version"], result["registry_package_count"],
                          result["lock_registry_checksum_count"]), (1, 29, 29))

    def test_metadata_rejects_wrong_version_or_registry(self):
        metadata = metadata_for_lock(self.lock, self.repo)
        metadata["version"] = 2
        with self.assertRaisesRegex(ValueError, "unexpected workspace root"):
            DRIVER.validate_metadata(self.metadata_path("version.json", metadata), self.lock, self.repo)
        metadata = metadata_for_lock(self.lock, self.repo)
        next(row for row in metadata["packages"] if row.get("source") == REGISTRY)["source"] = "registry+https://example.invalid/index"
        with self.assertRaisesRegex(ValueError, "locked crates.io closure"):
            DRIVER.validate_metadata(self.metadata_path("registry.json", metadata), self.lock, self.repo)

    def test_metadata_rejects_duplicate_or_omitted_registry_ids(self):
        for mode in ("duplicate", "omitted"):
            with self.subTest(mode=mode):
                metadata = metadata_for_lock(self.lock, self.repo)
                index = next(i for i, row in enumerate(metadata["packages"]) if row.get("source") == REGISTRY)
                if mode == "duplicate":
                    metadata["packages"].append(dict(metadata["packages"][index]))
                else:
                    metadata["packages"].pop(index)
                with self.assertRaisesRegex(ValueError, "locked crates.io closure"):
                    DRIVER.validate_metadata(self.metadata_path(mode + ".json", metadata), self.lock, self.repo)

    def test_metadata_rejects_missing_locked_registry_checksum(self):
        target = self.registry_rows[0]
        parts = self.lock.read_text(encoding="utf-8").split("[[package]]\n")
        for index, part in enumerate(parts):
            fields = {}
            for line in part.splitlines():
                key, sep, value = line.partition("=")
                if sep and key.strip() in {"name", "version", "source"}:
                    fields[key.strip()] = json.loads(value.strip())
            if all(fields.get(key) == target[key] for key in ("name", "version", "source")):
                checksum = f'checksum = "{target["checksum"]}"\n'
                parts[index] = "".join(line for line in part.splitlines(keepends=True) if line != checksum)
                break
        else:
            self.fail("could not find selected lock package")
        broken = self.base / "Cargo-without-checksum.lock"
        broken.write_text("[[package]]\n".join(parts), encoding="utf-8")
        metadata = metadata_for_lock(broken, self.repo)
        with self.assertRaisesRegex(ValueError, "lacks a SHA-256 checksum"):
            DRIVER.validate_metadata(self.metadata_path("missing-checksum.json", metadata), broken, self.repo)

    def test_source_guard_rejects_wrong_host_before_touching_paths(self):
        absent = self.base / "must-not-be-created"
        with mock.patch.dict(os.environ, {"BARE_HOST_KEY": "unit-fixture-host"}, clear=True):
            with self.assertRaisesRegex(ValueError, "unsupported host key"):
                DRIVER.verify_checkout(object(), absent / "artifact")
        self.assertFalse(absent.exists())

    def test_source_guard_rejects_unprotected_ref_before_touching_paths(self):
        absent = self.base / "must-not-be-created"
        env = {"BARE_HOST_KEY": "macos-aarch64", "BARE_HOST_TRIPLE": "aarch64-apple-darwin",
               "BARE_EVENT_NAME": "workflow_dispatch", "BARE_REPOSITORY": "metaneutrons/ami-rust",
               "BARE_REF_NAME": "refs/heads/unit-fixture-topic", "BARE_REF_PROTECTED": "true"}
        with (mock.patch.dict(os.environ, env, clear=True),
              mock.patch.object(DRIVER.platform, "system", return_value="Darwin"),
              mock.patch.object(DRIVER.platform, "machine", return_value="arm64")):
            with self.assertRaisesRegex(ValueError, "protected manual main-branch"):
                DRIVER.verify_checkout(object(), absent / "artifact")
        self.assertFalse(absent.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
