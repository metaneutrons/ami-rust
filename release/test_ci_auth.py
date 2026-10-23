"""Publisher assembly fixtures; synthetic bundles are never crypto evidence."""
import base64
import copy
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_auth as auth
import verify_publisher as verifier


def archive(files):
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(raw))
    return lzma.compress(plain.getvalue(), preset=6)


class PublisherAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.identity = {"source_sha": "a" * 40, "workflow_sha": "a" * 40,
                         "run_id": 12345, "run_attempt": 2}
        self.profile_files = {"bin/cargo": b"binary fixture", "producer.json": b'{"fixture":true}\n'}
        self.profile = {"files": self.rows(self.profile_files)}
        self.csdk_original_profile = b'{"files":[],"symlinks":[]}\n'
        self.csdk_candidate_profile = b'{"files":[{"fixture":true}],"symlinks":[]}\n'
        self.csdk_candidate_archive = b"fixture candidate C-SDK archive"
        self.csdk_original_archive = b"fixture original C-SDK archive"
        self.csdk_toolchain_profiles = {h: f"fixture {h} toolchain profile\n".encode()
                                        for h in auth.PORTABLE_CSDK_HOSTS}
        self.csdk_spec = self._make_csdk_spec(
            self.csdk_original_profile, self.csdk_candidate_profile, self.csdk_candidate_archive,
            self.csdk_original_archive, b"fixture patch series", b"fixture source capsule",
            b"fixture source manifest\n", self.csdk_toolchain_profiles)
        self.csdk_spec_bytes = auth.encoded(self.csdk_spec)
        self.write(self.source, "release/portable-csdk/spec.json", self.csdk_spec_bytes)
        self.write(self.source, "release/portable-csdk/original-profile.json", self.csdk_original_profile)
        self.write(self.source, "release/portable-csdk/profile.json", self.csdk_candidate_profile)
        self.write(self.source, "release/inputs/csdk.tar.xz", self.csdk_original_archive)
        self.write(self.source, "release/inputs/portable-csdk.tar.xz", self.csdk_candidate_archive)
        for host, profile_raw in self.csdk_toolchain_profiles.items():
            self.write(self.source, f"release/portable-csdk/toolchains/{host}.json", profile_raw)
        self.write(self.source, "release/ci-sdk-inputs.json", auth.encoded(self._csdk_ci_inputs()))
        self.sdk_files = {
            **{f"host/profiles/{h}/cargo.json": auth.encoded(self.profile) for h in auth.HOSTS},
            **{f"host/profiles/{h}/csdk.json": self.csdk_candidate_profile for h in auth.HOSTS},
        }
        sdk_profiles = {
            h: {"components": {
                "cargo": {"manifest": f"host/profiles/{h}/cargo.json",
                          "sha256": auth.sha(self.sdk_files[f"host/profiles/{h}/cargo.json"])},
                "csdk": {"manifest": f"host/profiles/{h}/csdk.json",
                         "sha256": auth.sha(self.csdk_candidate_profile)},
            }} for h in auth.HOSTS
        }
        self.contract = {"schema": "ami-rust-sdk-v1", "version": "0.1.0", "qualification_only": False,
                         "source_identity": self.identity["source_sha"], "profiles": sdk_profiles,
                         "packaging": {"portable_csdk": self._csdk_metadata()},
                         "files": self.rows(self.sdk_files)}
        self.payloads = {}
        for host in auth.HOSTS:
            p = self.root / host
            p.mkdir()
            self.payloads[host] = p
            self.write(p, "sdk-producer.json", auth.encoded(self.sdk_producer_receipt(host)))
        self.refresh_sdk_archives()
        gold = {}
        native = b"qualified fixture utility"
        for h in auth.HOSTS:
            p = self.payloads[h]
            self.write(p, "native/sha256sum.AMIRUST", native)
            self.write(p, "cargo-component.tar.xz", archive(self.profile_files))
            gold[h] = {"sha256sum": {"AMIRUST": {"bytes": len(native), "sha256": auth.sha(native)}}}
        self.write(self.source, "release/native-reference.json", auth.encoded({"hosts": gold}))
        self.write(self.source, "release/bundle-files.json", auth.encoded({
            "schema": "ami-rust-bundle-files-v1", "files": []}))
        self.write(self.source, "release/ci-python-inputs.json", auth.encoded({
            "hosts": {h: {"runtime_sha256": "b" * 64} for h in auth.HOSTS}}))
        self.output = self.root / "candidate"
        self.inputs = {"schema": "ami-rust-publisher-inputs-v1", "materials": []}

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, root, name, data):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def sdk_producer_receipt(self, host, *, status=auth.SDK_PRODUCER_RECEIPT_STATUS,
                             reference_proposal=False, receipt_host=None, source_sha=None):
        return {
            "schema": auth.SDK_PRODUCER_RECEIPT_SCHEMA,
            "status": status,
            "host": receipt_host or host,
            "reference_proposal": reference_proposal,
            "source": {"commit": source_sha or self.identity["source_sha"]},
        }

    def rows(self, files):
        return [{"path": n, "bytes": len(b), "sha256": auth.sha(b)} for n, b in sorted(files.items())]

    def _make_csdk_spec(self, original_profile, candidate_profile, candidate_archive, original_archive,
                        patch_series, capsule, source_manifest, toolchain_profiles):
        pin = lambda path, raw: {"path": path, "bytes": len(raw), "sha256": auth.sha(raw)}
        return {
            "schema": "ami-rust-portable-csdk-v1",
            "status": "PINNED_CANDIDATE_THREE_HOST_QUALIFICATION_REQUIRED",
            "original": {
                "profile": pin("release/portable-csdk/original-profile.json", original_profile),
                "archive": pin("release/inputs/csdk.tar.xz", original_archive),
            },
            "candidate": {
                "profile": pin("release/portable-csdk/profile.json", candidate_profile),
                "archive": {**pin("release/inputs/portable-csdk.tar.xz", candidate_archive),
                            "name": "csdk-component.tar.xz"},
            },
            "nouveau": {
                "archive_path": "lib/libdrm_nouveau.a", "derived_bytes": 20,
                "derived_sha256": "1" * 64, "historical_source_prefix": "/fixture/source",
                "objects": 2, "original_bytes": 21, "original_sha256": "2" * 64,
                "path_changed_members": 3, "symbols": 4, "unchanged_members": 5,
            },
            "patch_series": pin("release/patches/portable-csdk/series.json", patch_series),
            "required_counts": dict(auth.PORTABLE_CSDK_COUNTS),
            "source_capsule": pin("release/csdk-source/csdk-corresponding-source.tar.xz", capsule),
            "source_manifest": pin("release/csdk-source/manifest.json", source_manifest),
            "toolchains": {
                host: {
                    **({"archive": {"kind": "tar", "url": auth.PORTABLE_CSDK_ARM_TOOLCHAIN_ARCHIVE_URL,
                                    "bytes": 35097912, "sha256": auth.sha(b"fixture ARM LLVM archive"),
                                    "archive_root": "toolchain"}} if host == "linux-aarch64" else {}),
                    "compiler": {"path": "bin/clang-11", "bytes": 17, "sha256": "3" * 64},
                    "profile": pin(f"release/portable-csdk/toolchains/{host}.json", profile_raw),
                }
                for host, profile_raw in toolchain_profiles.items()
            },
        }

    def _csdk_ci_inputs(self):
        return {
            "shared": {"csdk": {"path": self.csdk_spec["original"]["archive"]["path"],
                                  "bytes": self.csdk_spec["original"]["archive"]["bytes"],
                                  "sha256": self.csdk_spec["original"]["archive"]["sha256"]}},
            "portable_csdk": {"path": "release/portable-csdk/spec.json",
                              "bytes": len(self.csdk_spec_bytes),
                              "sha256": auth.sha(self.csdk_spec_bytes)},
        }

    def _csdk_metadata(self):
        distribution_spec = copy.deepcopy(self.csdk_spec)
        distribution_spec["nouveau"].pop("historical_source_prefix")
        return {
            "spec_path": "release/portable-csdk/spec.json",
            "spec_bytes": len(self.csdk_spec_bytes),
            "spec_sha256": auth.sha(self.csdk_spec_bytes),
            "distribution_spec": distribution_spec,
            "candidate_archive": self.csdk_spec["candidate"]["archive"],
            "replacements": {
                host: {"manifest": f"host/profiles/{host}/csdk.json",
                       "sha256": auth.sha(self.csdk_candidate_profile)}
                for host in auth.HOSTS
            },
            "changed_profile_rows": 532,
        }

    def refresh_sdk_archives(self):
        self.sdk_files.pop("contract/sdk.json", None)
        self.contract["files"] = self.rows(self.sdk_files)
        self.sdk_files["contract/sdk.json"] = auth.encoded(self.contract)
        for host in auth.HOSTS:
            self.write(self.payloads[host], "sdk.tar.xz", archive(self.sdk_files))

    def assemble(self, output=None):
        with patch.object(auth, "context", return_value=self.identity), \
                patch.object(auth, "input_manifest", return_value=self.inputs):
            return auth.assemble(self.source, self.payloads, output or self.output)

    def test_complete_candidate_is_deterministic_and_unsigned(self):
        a = self.assemble()
        b = self.assemble(self.root / "second")
        self.assertEqual(a, b)
        first = {p.relative_to(self.output).as_posix(): p.read_bytes()
                 for p in self.output.rglob("*") if p.is_file()}
        second = {p.relative_to(self.root / "second").as_posix(): p.read_bytes()
                  for p in (self.root / "second").rglob("*") if p.is_file()}
        self.assertEqual(first, second)
        self.assertNotIn(".auth/authentication.json", first)
        manifest = json.loads(first["release.json"])
        self.assertEqual(manifest["qualification_only"], False)
        asset_names = {row["path"] for row in manifest["assets"]}
        self.assertNotIn("csdk-component.tar.xz", asset_names)
        self.assertNotIn(self.csdk_spec["candidate"]["archive"]["path"], asset_names)

    def test_input_materials_bind_tools_roots_patches_and_complete_source(self):
        pin = {"url": "https://example.test/component", "sha256": "b" * 64}
        self.write(self.source, "release/ci-bootstrap-inputs.json", auth.encoded({
            "rust": {"components": {"fixture": {k: pin for k in ("rustc", "rust-std", "cargo")}}},
            "custom_cargo": {"upstream": "https://example.test/cargo", "commit": "a" * 40}}))
        self.write(self.source, "release/ci-python-inputs.json", auth.encoded({
            "hosts": {h: pin for h in auth.HOSTS}}))
        for name in ("release/ci-resources.json", "host/cargo-repro/cargo-metadata.patch",
                     "host/cargo-repro/openssl-paths.patch"):
            self.write(self.source, name, b"fixture\n")
        root = b"synthetic trust root"
        root_name = "release/trust/root.json"
        self.write(self.source, root_name, root)
        tool_pin = {"url": "https://example.test/auth-tool", "sha256": "c" * 64}
        self.write(self.source, "release/ci-auth-tools.json", auth.encoded({
            "hosts": {h: {k: tool_pin for k in ("gh", "cosign")} for h in auth.HOSTS},
            "roots": {"fixture": {"path": root_name, "bytes": len(root), "sha256": auth.sha(root)}}}))
        patch = b"source patch fixture\n"
        patch_name = "release/patches/portable-csdk/fix.patch"
        self.write(self.source, patch_name, patch)
        capsule = b"immutable source fixture"
        capsule_name = "release/csdk-source/csdk-corresponding-source.tar.xz"
        self.write(self.source, capsule_name, capsule)
        source_manifest = auth.encoded({"capsule": {
            "path": "csdk-corresponding-source.tar.xz", "bytes": len(capsule), "sha256": auth.sha(capsule)}})
        self.write(self.source, "release/csdk-source/manifest.json", source_manifest)
        patch_series = auth.encoded({
            "original_source_capsule_sha256": auth.sha(capsule),
            "patches": [{"patch": "fix.patch", "patch_sha256": auth.sha(patch)}]})
        self.write(self.source, "release/patches/portable-csdk/series.json", patch_series)
        self.csdk_spec = self._make_csdk_spec(
            self.csdk_original_profile, self.csdk_candidate_profile, self.csdk_candidate_archive,
            self.csdk_original_archive, patch_series, capsule, source_manifest,
            self.csdk_toolchain_profiles)
        self.csdk_spec_bytes = auth.encoded(self.csdk_spec)
        self.write(self.source, "release/portable-csdk/spec.json", self.csdk_spec_bytes)
        vendor = b"fixture vendor archive"
        vendor_name = "release/inputs/vendor.tar.xz"
        self.write(self.source, vendor_name, vendor)
        sdk_inputs = {
            "channel_manifest": pin,
            "hosts": {h: {"rust": {"archives": [pin]}, "toolchain": pin, "collector": pin}
                      for h in auth.HOSTS},
            "shared": {
                "csdk": {"kind": "repository-tar", "path": "release/inputs/csdk.tar.xz",
                         "bytes": len(self.csdk_original_archive), "sha256": auth.sha(self.csdk_original_archive)},
                "vendor": {"kind": "repository-tar", "path": vendor_name,
                           "bytes": len(vendor), "sha256": auth.sha(vendor)},
            },
            "portable_csdk": {"path": "release/portable-csdk/spec.json",
                              "bytes": len(self.csdk_spec_bytes), "sha256": auth.sha(self.csdk_spec_bytes)},
        }
        ci_inputs_path = "release/ci-sdk-inputs.json"
        self.write(self.source, ci_inputs_path, auth.encoded(sdk_inputs))
        material = auth.input_manifest(self.source)
        actual = {r["uri"]: r["digest"]["sha256"] for r in material["materials"]
                  if "sha256" in r["digest"]}
        expected_materials = (
            (root_name, root), (patch_name, patch), (capsule_name, capsule),
            ("release/portable-csdk/spec.json", self.csdk_spec_bytes),
            ("release/portable-csdk/original-profile.json", self.csdk_original_profile),
            ("release/portable-csdk/profile.json", self.csdk_candidate_profile),
            ("release/inputs/portable-csdk.tar.xz", self.csdk_candidate_archive),
            ("release/inputs/csdk.tar.xz", self.csdk_original_archive),
            ("release/portable-csdk/toolchains/linux-x86_64.json",
             self.csdk_toolchain_profiles["linux-x86_64"]),
            ("release/portable-csdk/toolchains/macos-aarch64.json",
             self.csdk_toolchain_profiles["macos-aarch64"]),
            ("release/portable-csdk/toolchains/linux-aarch64.json",
             self.csdk_toolchain_profiles["linux-aarch64"]),
            (vendor_name, vendor),
        )
        for name, value in expected_materials:
            self.assertEqual(actual[f"git+https://github.com/{auth.REPO}#{name}"], auth.sha(value))
        self.assertEqual(actual[tool_pin["url"]], tool_pin["sha256"])
        arm_archive = self.csdk_spec["toolchains"]["linux-aarch64"]["archive"]
        self.assertEqual(actual[arm_archive["url"]], arm_archive["sha256"])
        inputs_tampered = dict(sdk_inputs)
        inputs_tampered["portable_csdk"] = {**sdk_inputs["portable_csdk"], "sha256": "0" * 64}
        self.write(self.source, ci_inputs_path, auth.encoded(inputs_tampered))
        with self.assertRaisesRegex(ValueError, "specification differs from its source pin"):
            auth.input_manifest(self.source)
        self.write(self.source, ci_inputs_path, auth.encoded(sdk_inputs))
        tamper_materials = expected_materials + (("release/csdk-source/manifest.json", source_manifest),)
        for name, value in tamper_materials:
            self.write(self.source, name, value + b"tampered")
            with self.assertRaises(ValueError):
                auth.input_manifest(self.source)
            self.write(self.source, name, value)

    def test_arm_toolchain_is_publisher_input_without_extending_sdk_hosts(self):
        self.assertEqual(set(auth.HOSTS), {"linux-x86_64", "macos-aarch64"})
        self.assertIn("linux-aarch64", auth.PORTABLE_CSDK_HOSTS)
        materials = {}
        def add_material(uri, algorithm, digest):
            self.assertEqual(algorithm, "sha256")
            materials[uri] = digest
        sdk_inputs = auth.parsed(auth.read(self.source / "release/ci-sdk-inputs.json"))
        auth.load_portable_csdk(self.source, sdk_inputs, add_material=add_material)
        uri = f"git+https://github.com/{auth.REPO}#release/portable-csdk/toolchains/linux-aarch64.json"
        self.assertEqual(materials[uri], auth.sha(self.csdk_toolchain_profiles["linux-aarch64"]))
        archive = self.csdk_spec["toolchains"]["linux-aarch64"]["archive"]
        self.assertEqual(materials[archive["url"]], archive["sha256"])
        missing = copy.deepcopy(self.csdk_spec)
        del missing["toolchains"]["linux-aarch64"]["archive"]
        with self.assertRaisesRegex(ValueError, "malformed portable C-SDK linux-aarch64 toolchain identity"):
            auth._validate_portable_csdk_spec(missing)
        altered = copy.deepcopy(self.csdk_spec)
        altered["toolchains"]["linux-aarch64"]["archive"]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "malformed portable C-SDK Linux/AArch64 archive pin"):
            auth._validate_portable_csdk_spec(altered)

    def test_host_disagreement_refused_before_output(self):
        (self.payloads[auth.HOSTS[0]] / "sdk.tar.xz").write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "byte-identical"):
            self.assemble()
        self.assertFalse(self.output.exists())

    def test_sdk_producer_receipts_reject_proposal_and_unbound_evidence_before_output(self):
        host = auth.HOSTS[0]
        receipt_path = self.payloads[host] / "sdk-producer.json"
        invalid_receipts = (
            self.sdk_producer_receipt(
                host, status="PRODUCED_NATIVE_REFERENCE_PROPOSAL_NOT_FOR_AUTHENTICATION",
                reference_proposal=True),
            self.sdk_producer_receipt(host, reference_proposal=True),
            self.sdk_producer_receipt(host, receipt_host=auth.HOSTS[1]),
            self.sdk_producer_receipt(host, source_sha="c" * 40),
        )
        for receipt in invalid_receipts:
            with self.subTest(receipt=receipt), self.assertRaisesRegex(ValueError, "SDK producer receipt"):
                receipt_path.write_bytes(auth.encoded(receipt))
                self.assemble()
            self.assertFalse(self.output.exists())
        receipt_path.unlink()
        with self.assertRaisesRegex(ValueError, "SDK producer receipt"):
            self.assemble()
        self.assertFalse(self.output.exists())

    def test_signer_independently_reconstructs_before_authentication(self):
        self.assemble()
        with patch.object(auth, "context", return_value=self.identity), \
                patch.object(auth, "input_manifest", return_value=self.inputs):
            result = auth.audit(self.source, self.output, self.root / "audit")
            self.assertEqual(result["owned_audit_work_remaining_bytes"], 0)
            self.assertFalse((self.root / "audit").exists())
            (self.output / "SHAUTIL").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                auth.audit(self.source, self.output, self.root / "bad-audit")

    def test_cargo_profile_bytes_and_extra_members_refused(self):
        for files in ({**self.profile_files, "bin/cargo": b"wrong"},
                      {**self.profile_files, "unexpected": b"extra"}):
            with self.assertRaises(ValueError):
                auth.cargo_matches(archive(files), self.profile)

    def test_duplicate_cargo_profile_refused(self):
        with self.assertRaises(ValueError):
            auth.cargo_matches(archive(self.profile_files), {"files": self.profile["files"] * 2})

    def test_bounded_xz_rejects_truncation_concatenation_and_expansion(self):
        raw = lzma.compress(b"abc")
        for data, ceiling in ((raw[:-1], 10), (raw + raw, 10), (raw, 2)):
            with self.assertRaises((ValueError, lzma.LZMAError)):
                auth.bounded_xz(data, ceiling)
        self.assertEqual(auth.bounded_xz(raw, 3), b"abc")

    def test_duplicate_sdk_inventory_refused(self):
        self.contract["files"] *= 2
        files = {**self.sdk_files, "contract/sdk.json": auth.encoded(self.contract)}
        with self.assertRaises(Exception):
            auth.sdk_contents(archive(files))

    def test_sdk_content_tamper_refused(self):
        files = {**self.sdk_files, f"host/profiles/{auth.HOSTS[0]}/cargo.json": b"tampered"}
        with self.assertRaises(ValueError):
            auth.sdk_contents(archive(files))

    def test_sdk_portable_csdk_metadata_must_match_source_specification(self):
        self.contract["packaging"]["portable_csdk"]["candidate_archive"]["sha256"] = "f" * 64
        self.refresh_sdk_archives()
        with self.assertRaisesRegex(ValueError, "SDK portable C-SDK metadata differs"):
            self.assemble()

    def test_sdk_cannot_describe_candidate_but_embed_original_csdk_profile(self):
        host = auth.HOSTS[0]
        name = f"host/profiles/{host}/csdk.json"
        self.sdk_files[name] = self.csdk_original_profile
        self.contract["profiles"][host]["components"]["csdk"]["sha256"] = auth.sha(
            self.csdk_original_profile)
        self.refresh_sdk_archives()
        with self.assertRaisesRegex(ValueError, "SDK host C-SDK profile differs from the source-pinned"):
            self.assemble()

    def test_actual_static_release_assets_match_the_complete_tracked_map(self):
        static = auth.static_assets(auth.ROOT)
        declared = auth.parsed(auth.read(auth.ROOT / "release/bundle-files.json"))["files"]
        self.assertEqual(set(static), {row["path"] for row in declared})
        self.assertEqual(len(static), len(declared))
        self.assertIn("COMPATIBILITY.md", static)
        self.assertIn("QUICKSTART.md", static)

    def test_static_asset_corruption_and_reserved_destination_are_rejected(self):
        raw = b"original document\n"
        self.write(self.source, "doc.md", raw)
        self.write(self.source, "release/bundle-files.json", auth.encoded({
            "schema": "ami-rust-bundle-files-v1", "files": [{
                "path": "DOC.md", "source": "doc.md", "bytes": len(raw), "sha256": auth.sha(raw)}]}))
        self.assertEqual(auth.static_assets(self.source), {"DOC.md": raw})
        with self.assertRaisesRegex(ValueError, "duplicate/reserved"):
            auth.static_assets(self.source, {"DOC.md"})
        self.write(self.source, "doc.md", b"changed document!\n")
        with self.assertRaisesRegex(ValueError, "differs from tracked"):
            auth.static_assets(self.source)

    def test_sdk_csdk_profile_reference_digest_must_match_candidate_bytes(self):
        host = auth.HOSTS[0]
        self.contract["profiles"][host]["components"]["csdk"]["sha256"] = "f" * 64
        self.refresh_sdk_archives()
        with self.assertRaisesRegex(ValueError, "SDK host C-SDK profile reference differs"):
            self.assemble()

    def test_local_and_payload_overlapping_output_refused(self):
        for output in (self.source / "output", self.payloads[auth.HOSTS[0]] / "output"):
            with self.assertRaises(ValueError):
                self.assemble(output)

    def test_symlink_payload_refused(self):
        link = self.root / "linked"
        link.symlink_to(self.payloads[auth.HOSTS[0]], target_is_directory=True)
        self.payloads[auth.HOSTS[0]] = link
        with self.assertRaises(ValueError):
            self.assemble()

    def test_predicate_exactly_matches_consumer_contract(self):
        self.assemble()
        policy = {**{k: self.identity[k] for k in ("source_sha", "workflow_sha")},
                  "inputs_manifest_sha256": auth.sha(auth.encoded(self.inputs))}
        github_env = {"GITHUB_EVENT_NAME": "workflow_dispatch",
                      "GITHUB_REPOSITORY_ID": "1421182484",
                      "GITHUB_REPOSITORY_OWNER_ID": "436979",
                      "RUNNER_ENVIRONMENT": "github-hosted"}
        for host in auth.HOSTS:
            with patch.dict(os.environ, github_env, clear=False), \
                    patch.object(auth, "context", return_value=self.identity):
                predicate = auth.predicate(self.output, host, self.source)
            statement = {"predicateType": verifier.PREDICATE_TYPE,
                         "subject": [{"name": "release.json", "digest": {"sha256": "c" * 64}}],
                         "predicate": predicate}
            self.assertEqual(set(predicate["buildDefinition"]["internalParameters"]),
                             {"github", "publisherPolicy"})
            self.assertEqual(predicate["buildDefinition"]["internalParameters"]["github"],
                             auth.GITHUB_INTERNAL_PARAMETERS)
            self.assertEqual(set(predicate["runDetails"]["metadata"]), {"invocationId"})
            verifier._check_predicate(statement, policy=policy, run=self.identity, host=host,
                                      subject_paths=["release.json"],
                                      manifest={"release.json": (1, "c" * 64)}, input_materials=[])
            statement["predicate"]["buildDefinition"]["internalParameters"]["publisherPolicy"]["sourceSha"] = "d" * 40
            with self.assertRaises(verifier.PublisherVerificationError):
                verifier._check_predicate(statement, policy=policy, run=self.identity, host=host,
                                          subject_paths=["release.json"],
                                          manifest={"release.json": (1, "c" * 64)}, input_materials=[])

    def test_auth_paths_and_exact_subject_coverage(self):
        self.assemble()
        fake = self.write(self.root, "fake.json", b'{"fixture":"not real crypto"}')
        mapping = {n: fake for n in auth.SUBJECTS}
        with self.assertRaises(ValueError):
            auth.finalize(self.output, auth.HOSTS[0], {}, mapping)
        result = auth.finalize(self.output, auth.HOSTS[0], mapping, mapping)
        paths = [r["bundle"] for key in ("gh_attestations", "cosign_bundles") for r in result[key]]
        self.assertEqual(len(set(paths)), 6)
        self.assertTrue(all(n.endswith(".json") for n in paths))
        with self.assertRaises(FileExistsError):
            auth.finalize(self.output, auth.HOSTS[0], mapping, mapping)

    def test_context_requires_protected_hosted_exact_checkout(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            auth.context(self.source)

    def test_native_finalization_uses_its_new_profile_without_relaxing_legacy(self):
        import shutil
        self.assemble()
        fake = self.write(self.root, "profile-only-fake.json", b'{"fixture":"not real crypto"}')
        mapping = {n: fake for n in auth.SUBJECTS}
        for schema, size, accepted in (("ami-rust-release-v1", 33 * 1024**2, False),
                                       ("ami-rust-release-v2", 33 * 1024**2, True),
                                       ("ami-rust-release-v2", 65 * 1024**2, False)):
            with self.subTest(schema=schema, size=size):
                case = self.root / (schema + str(size))
                shutil.copytree(self.output, case)
                manifest = auth.parsed((case / "release.json").read_bytes())
                manifest["schema"] = schema
                (case / "release.json").write_bytes(auth.encoded(manifest))
                # Sparse test data measures the finalizer's physical-file
                # length accounting, not a valid distributable asset set.
                with (case / "profile-counterprobe.bin").open("xb") as stream:
                    stream.truncate(size)
                if accepted:
                    auth.finalize(case, auth.HOSTS[0], mapping, mapping)
                else:
                    with self.assertRaisesRegex(ValueError, "retained artifact ceiling"):
                        auth.finalize(case, auth.HOSTS[0], mapping, mapping)
                    self.assertFalse((case / ".auth/authentication.json").exists())

    def test_context_binds_workflow_dispatch_and_immutable_repository_ids(self):
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": auth.REPO,
               "GITHUB_REF": "refs/heads/main", "SOURCE_IS_PROTECTED": "true",
               "PUBLISHER_ENVIRONMENT": "release", "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY_ID": "1421182484",
               "GITHUB_REPOSITORY_OWNER_ID": "436979", "GITHUB_SHA": "a" * 40,
               "GITHUB_WORKFLOW_SHA": "a" * 40,
               "GITHUB_WORKFLOW_REF": f"{auth.REPO}/{auth.WORKFLOW}@refs/heads/main",
               "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(subprocess, "check_output", return_value="a" * 40 + "\n"):
            self.assertEqual(auth.context(self.source), {"source_sha": "a" * 40,
                             "workflow_sha": "a" * 40, "run_id": 123, "run_attempt": 1})
        for name, wrong in (("GITHUB_EVENT_NAME", "push"),
                            ("GITHUB_REPOSITORY_ID", "1"),
                            ("GITHUB_REPOSITORY_OWNER_ID", "2")):
            with self.subTest(field=name), patch.dict(os.environ, {**env, name: wrong}, clear=True), \
                    patch.object(subprocess, "check_output", return_value="a" * 40 + "\n"), \
                    self.assertRaisesRegex(ValueError, "designated protected hosted"):
                auth.context(self.source)

    def test_non_sdk_preflight_binds_source_run_and_retains_provider_proof(self):
        subject = self.root / "probe.txt"
        predicate_path = self.root / "probe.json"
        output = self.root / "github-output"
        output.touch()
        bundle = self.root / "bundle.json"
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": auth.REPO,
               "GITHUB_REF": "refs/heads/main", "SOURCE_IS_PROTECTED": "true",
               "PUBLISHER_ENVIRONMENT": "release", "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY_ID": "1421182484",
               "GITHUB_REPOSITORY_OWNER_ID": "436979", "GITHUB_SHA": "a" * 40,
               "GITHUB_WORKFLOW_SHA": "a" * 40,
               "GITHUB_WORKFLOW_REF": f"{auth.REPO}/{auth.WORKFLOW}@refs/heads/main",
               "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_OUTPUT": str(output)}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(subprocess, "check_output", return_value="a" * 40 + "\n"):
            prepared = auth.preflight(self.source, subject, predicate_path)
            predicate = auth.parsed(predicate_path.read_bytes())
            self.assertEqual(predicate["buildDefinition"]["internalParameters"]["github"],
                             auth.GITHUB_INTERNAL_PARAMETERS)
            self.assertIn("not an SDK candidate", subject.read_text())
            recorded = output.read_text()
            self.assertIn("subject_sha256=" + prepared["subject_sha256"], recorded)
            self.assertIn("predicate_sha256=" + prepared["predicate_sha256"], recorded)

            statement = {
                "_type": auth.IN_TOTO_STATEMENT_V1,
                "subject": [{"name": "ami-rust-github-provenance-probe.txt",
                             "digest": {"sha256": prepared["subject_sha256"]}}],
                "predicateType": auth.SLSA_PREDICATE_TYPE,
                "predicate": predicate,
            }

            def synthetic_bundle(value):
                payload = auth.encoded(value)
                # Deliberately fake DSSE signature bytes: this tests content binding only.
                envelope = {"payloadType": auth.IN_TOTO_JSON,
                            "payload": base64.b64encode(payload).decode("ascii"),
                            "signatures": [{"sig": "synthetic-not-cryptographic", "keyid": "fixture"}]}
                return auth.encoded({"dsseEnvelope": envelope})

            bundle_raw = synthetic_bundle(statement)
            bundle.write_bytes(bundle_raw)
            result = auth.verify_preflight(
                self.source, subject, predicate_path, bundle, "123",
                "https://github.com/metaneutrons/ami-rust/attestations/123",
                prepared["subject_sha256"], prepared["predicate_sha256"])
            self.assertEqual(result["status"], "PREFLIGHT_ATTESTATION_INGESTED_NOT_SDK_AUTHENTICATION")
            self.assertEqual(result["bundle_sha256"], auth.sha(bundle_raw))
            self.assertEqual(base64.b64decode("".join(result["bundle_base64_chunks"])), bundle_raw)

            wrong_subject = copy.deepcopy(statement)
            wrong_subject["subject"][0]["name"] = "other.txt"
            wrong_digest = copy.deepcopy(statement)
            wrong_digest["subject"][0]["digest"]["sha256"] = "f" * 64
            wrong_type = copy.deepcopy(statement)
            wrong_type["predicateType"] = "https://example.invalid/predicate"
            wrong_predicate = copy.deepcopy(statement)
            wrong_predicate["predicate"]["buildDefinition"]["internalParameters"]["publisherPolicy"]["sourceSha"] = "f" * 40
            wrong_run = copy.deepcopy(statement)
            wrong_run["predicate"]["runDetails"]["metadata"]["invocationId"] = \
                "https://github.com/metaneutrons/ami-rust/actions/runs/124/attempts/1"
            malformed_base64 = {"dsseEnvelope": {"payloadType": auth.IN_TOTO_JSON,
                                                  "payload": "%%%", "signatures": [{"sig": "x"}]}}
            malformed_json = {"dsseEnvelope": {"payloadType": auth.IN_TOTO_JSON,
                                                "payload": base64.b64encode(b"{").decode("ascii"),
                                                "signatures": [{"sig": "x"}]}}
            bad_bundles = (
                ("wrong subject", synthetic_bundle(wrong_subject), "statement differs"),
                ("wrong digest", synthetic_bundle(wrong_digest), "statement differs"),
                ("wrong predicate type", synthetic_bundle(wrong_type), "statement differs"),
                ("wrong predicate", synthetic_bundle(wrong_predicate), "statement differs"),
                ("wrong run", synthetic_bundle(wrong_run), "statement differs"),
                ("malformed base64", auth.encoded(malformed_base64), "valid base64"),
                ("malformed JSON", auth.encoded(malformed_json), "JSON"),
                ("missing DSSE envelope", b'{"public_attestation_bundle":true}\n', "no in-toto DSSE envelope"),
            )
            for label, bad_raw, error in bad_bundles:
                with self.subTest(bundle=label):
                    bundle.write_bytes(bad_raw)
                    with self.assertRaisesRegex(ValueError, error):
                        auth.verify_preflight(
                            self.source, subject, predicate_path, bundle, "123",
                            "https://github.com/metaneutrons/ami-rust/attestations/123",
                            prepared["subject_sha256"], prepared["predicate_sha256"])
            bundle.write_bytes(bundle_raw)
            with self.assertRaisesRegex(ValueError, "persisted attestation identity"):
                auth.verify_preflight(self.source, subject, predicate_path, bundle, "0",
                    "https://github.com/metaneutrons/ami-rust/attestations/0",
                    prepared["subject_sha256"], prepared["predicate_sha256"])
            with self.assertRaisesRegex(ValueError, "predicate differs"):
                auth.verify_preflight(self.source, subject, predicate_path, bundle, "123",
                    "https://github.com/metaneutrons/ami-rust/attestations/123",
                    prepared["subject_sha256"], "f" * 64)

    def test_producer_path_grammar_matches_installer_boundary(self):
        for name in ("bad\nname", "é.txt", "a" * 241, "a" * 121, "CON.txt", "LPT1", "a.", "a b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                auth.rel(name)

    def test_nonfinite_json_constants_and_overflow_refused(self):
        for value in ("1e999", "-1e999", "NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                auth.parsed(('{"x":' + value + '}').encode())
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": auth.REPO,
               "GITHUB_REF": "refs/heads/main", "SOURCE_IS_PROTECTED": "true",
               "PUBLISHER_ENVIRONMENT": "release", "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY_ID": "1421182484",
               "GITHUB_REPOSITORY_OWNER_ID": "436979",
               "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "b" * 40,
               "GITHUB_WORKFLOW_REF": f"{auth.REPO}/{auth.WORKFLOW}@refs/heads/main"}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(subprocess, "check_output", return_value="a" * 40 + "\n"), \
                self.assertRaisesRegex(ValueError, "identity mismatch"):
            auth.context(self.source)


if __name__ == "__main__":
    unittest.main()
