# RC0 contract decisions for the Rust host CLI

Status: frozen RC0 design for RC1. [Acceptance and evidence](rc0-acceptance.md) reconcile the historical proposal and open gates below; those older paragraphs record the decision sequence, not current status. Original snapshot date: 2026-10-18. Machine-readable decisions: [contracts-v1.json](contracts-v1.json). The existing per-file inventory remains [python-dependencies.json](python-dependencies.json).

The revision-2 migration plan calls for one shared capability list, exact compatibility fixtures, schema migration, host Rust pins and a no-Python closure. This document specifies behavior RC1 should preserve; it does not claim RC0-A3 or RC0-A4 passed.

## Current interfaces and correction

There are three distinct current surfaces. The package launcher exposes version, package verification, preparation, project creation, build and input checking. The direct SDK CLI exposes version, lock verification and the constrained native build. Release verification, installation, lock creation and uninstall remain separate helper CLIs. Exact argv forms, option multiplicity, path constraints and exit behavior are in contracts-v1.json.

One sentence in the existing consumer survey is inaccurate: the package launcher passes through a nonnegative child status. It calls subprocess.run with check=True, catches CalledProcessError at the entry point, then exits with the child return code; a signal return code maps to min(255, 128 + signal number). The survey is corrected to match packaging/cli.py:109-111, 248-255. The direct SDK CLI has a separate mapping: it passes through a nonnegative driver status, maps a signaled driver to min(255, 128+N), and the driver maps a signaled supervised build child to 130. A monitor failure stops the process group and returns the child nonzero status if present, otherwise 1 (host/cli.py:399-413; host/build.py:198-231,302-310). Preserve those distinctions in fixtures.

Package build defaults to hello-aros and constructs build --manifest-path PROJECT/Cargo.toml --package NAME --release --locked --offline. Only one --features VALUE and one --no-default-features may be appended. The direct driver accepts the fixed recipe plus those optional features; it rejects unknown or repeated recipe options and requires a sibling Cargo.lock (host/build.py:76-103). The package launcher verifies its exact package inventory before dispatching a command (packaging/cli.py:48-85).

## Frozen state, lock, receipt, trust and ownership behavior

Preparation requires a fresh normalized absolute path with an existing parent and a non-root caller. It creates a private directory with mode 0700, retains a versioned launcher/package and leaves failed state for diagnosis. Later commands require a real directory owned by the current user with no group/world permissions; state and package trees must not overlap. The current ready record uses ami-rust-package-state-v1 and checks READY status plus host, source commit, manifest digest and SDK version; package_version is recorded but not compared by ready_state (packaging/cli.py:114-188; packaging/worker.py:60-68).

A direct build requires a fresh output path and existing parent. It creates output/build.lock exclusively, holds a non-blocking exclusive file lock, supervises commands and retains stdout, stderr and result records on failure. A PASS receipt is written only after the native artifacts are audited. The existing build receipt has no schema key and explicitly claims native build only; it does not establish runtime or release qualification (host/build.py:144-175,198-231,267-299).

The release installer receives publisher policy, verifier binaries and trust roots from outside the candidate bundle. The production policy binds repository, workflow, source and workflow commits, ref, OIDC issuer, certificate identity, input-manifest digest and allowed host profile. The verifier requires an exact policy field set and checks every executable/root against its SHA-256 pin (release/install_publisher.py:29-79; release/verify_publisher.py:222-270). Current pinned tools are gh 2.102.0 and Cosign 3.1.3; GitHub and Sigstore roots are independently hashed in release/ci-auth-tools.json. Keep that external trust boundary. Do not implement a new signature protocol or fall back to the separate legacy OpenSSH-only route.

The production installer stages the complete tree in a private sibling, records an exact file inventory and publisher authentication in ami-rust-install-receipt-v2, fsyncs and publishes by exclusive atomic rename. If external receipt-pin writing fails after publication, it returns 1 and leaves the prefix; the error contains the prefix and receipt digest. Uninstall requires that external digest, validates the receipt and complete tree, moves the prefix to a hidden tombstone and rechecks before deletion. A failed recheck rolls back the name; interruption during recursive deletion leaves the tombstone (release/install.py:870-945,1012-1085,1117-1141).

Installed prefixes, state and receipt files must be owned by the current user and not group/world writable. Prefix parents must be secure; prefix, pin and output paths are fresh and cannot be symlinked through protected boundaries. Prefixes cannot replace root, home, the current working directory or an ancestor. Archive extraction writes only under private staging, accepts the exact inventory and rejects unexpected files/directories. The project lock binds SDK manifest, host/Python, six component roots and Cargo.toml/Cargo.lock hashes, but makes a consistency claim only; it does not re-authenticate the publisher or establish R1 acceptance (release/install.py:585-621,695-818,1184-1255; host/cli.py:382-395).

Current selection.json has no schema and contains Python plus exactly six component roots. The project lock has ami-rust-project-lock-v1 and includes host Python path/hash. The current lock helper accepts prefix, selection, project and fresh output, validates the installed receipt/tree, and returns its observed receipt digest; it accepts no external expected receipt digest and establishes only project-pin consistency, not publisher trust. Proposed explicit migration therefore requires a digest from the separate pin before writing a fresh v2 record. The installer already validates exact v1/v2 receipt keys; other records have inconsistent strictness and need the explicit future rules below.

## Schema and migration decisions

All new Rust-owned records require a known schema discriminator. Reject unknown or missing versions before mutation; reject unknown fields in security-sensitive data. Parse UTF-8 JSON under the format size limit, reject duplicate keys recursively, and reject non-finite numbers. Do not deserialize an unvalidated document into a generic map first: serde_json Value is not the duplicate-key security boundary. Verify paths, exact inventories, modes and SHA strings before following them. Never rewrite a record merely because it was read. Hash the original input bytes or the exact bytes emitted by the new writer.

For new record families, exact fields are frozen in contracts-v1.json. Package-state-v2 removes Python interpreter identity and adds installed receipt, CLI and shared-core hashes. Selection-v2 adds a schema, host and receipt digest while retaining exactly six component roots. Project-lock-v2 keeps SDK/host/component/Cargo binding but replaces Python path/hash with CLI/core/receipt identity. Release-v2 replaces host_interpreters with exact per-host host_launchers. Install-receipt-v3 binds the native launcher/core. Native-build-receipt-v1 gives the schema-less build receipt a version. Any later decision-bearing field requires a new schema version. A documented extensions map is allowed only for diagnostics, never trust, ownership, selection or inventory decisions.

Historical records remain evidence. State v1 is inspection-only and never executes its retained Python launcher; prepare a fresh v2 state. The schema-less selection is accepted only by explicit migration that revalidates the installation receipt, exact inventory and component roots while preserving a consistency-only claim; never execute its Python path. Project-lock-v1 is inspection-only until explicit migration revalidates SDK, six components and project hashes, then writes a separate fresh v2 lock. Receipt v1 remains legacy qualification/inspection and exact-owner uninstall only. Receipt v2 remains the current production authentication record and may be validated for inspection/uninstall; neither is rewritten. Release-v1 is legacy qualification-only. The schema-less native build receipt is historical only. These rules prevent an old Python-bound identity from being treated as a Rust-bound one.

Migration is dry-run by default. A write requires an explicit old lock, installed prefix, receipt digest from the separate pin, project and fresh output path. It never launches Python, rewrites old state/selection/lock/receipts, changes Cargo.toml or Cargo.lock, changes global Cargo/rustup configuration or changes compiler selection. It recomputes identities against the installed receipt/inventory and current project, compares the supplied external receipt digest and retains the current pin-consistency-only claim; it does not independently reauthenticate publisher trust. Any mismatch, link, missing file, ambiguous owner or occupied output refuses without mutation. State migration creates a new v2 state rather than editing the old state.

## Shared capability matrix

Both frontends should call one parser and one shared Rust core. For equal command arguments, host and environment, results must match in status, output schema, validation order and filesystem effects. cargo-ami removes Cargo's injected command token and invokes that core. The proposed matrix in contracts-v1.json includes version, package verification, prepare, new, package build, input checking, direct SDK-lock verify/build, production release verify/install/lock/uninstall and explicit migration for both ami-rust and cargo ami. This follows the plan's future consumer commands; it does not imply those commands work now.

The build command remains the constrained locked/offline recipe. Arbitrary Cargo options, cargo test/run, unrelated targets and rust-analyzer builds are outside this freeze. Normal cargo metadata/check/build after explicit project activation is a separate RC2 capability with its own hooks and qualification; cargo-ami cannot provide them for unrelated Cargo commands (docs/rust-cli-cargo-migration-plan.md:110-139).

## Host compiler and dependency proposal

Use authenticated Rust 1.98.1 for the host core on macos-aarch64 and linux-x86_64 from the existing host bootstrap inputs. Keep the AROS target SDK on nightly-2026-09-18, rustc commit 330d317121e16b5db8e5adc63595910528ff2ee7 and LLVM 23.1.1. Host and target compiler choices are separate (release/ci-bootstrap-inputs.json:76-132; docs/compatibility.md:8-16).

Conditional exact direct-version candidates for a separate host-core workspace and lockfile; do not freeze them until the stated review gates pass:

| Crate | Pin and features | License; declared MSRV | Use and decision |
| --- | --- | --- | --- |
| serde | =1.0.228; std, derive | MIT OR Apache-2.0; 1.56 | Reuse the root lock/vendor version for typed schemas. |
| serde_json | =1.0.145; std | MIT OR Apache-2.0; 1.61 | Reuse the root lock/vendor version with a recursive duplicate-key visitor. |
| sha2 | =0.11.1; default (alloc, oid) | MIT OR Apache-2.0; 1.88 | One host-core version shared with lzma-rust2's XZ feature. Leave target sha2 0.10.9 unchanged. |
| tar | =0.4.46; default features off | MIT OR Apache-2.0; 1.63 | Streaming archive reader; no xattr. Above the fix floor for [GHSA-gchp-q4r4-x4ff](https://github.com/advisories/GHSA-gchp-q4r4-x4ff) and [GHSA-j4xf-2g29-59ph](https://github.com/advisories/GHSA-j4xf-2g29-59ph). |
| flate2 | =1.1.10; default features off, rust_backend | MIT OR Apache-2.0; 1.67 | Gzip through pure-Rust miniz_oxide, without system zlib. |
| lzma-rust2 | =0.22.0; default features off, std and xz | Apache-2.0; 1.85 | `XzReader::new_mem_limit` is present. The 0.22.0 changelog fixes allocation driven by declared dictionary and XZ index sizes. Do not enable optimization. The advisory review remains open. |

These are conditional exact direct-version candidates, not a frozen dependency selection. Versions, licenses, MSRVs and checksums were checked against local Cargo registry metadata and crates.io release records; the existing Cargo.lock already contains the reused serde pair. contracts-v1.json records every proposed checksum. Candidate pages: [serde 1.0.228](https://crates.io/crates/serde/1.0.228), [serde_json 1.0.145](https://crates.io/crates/serde_json/1.0.145), [sha2 0.11.1](https://crates.io/crates/sha2/0.11.1), [tar 0.4.46](https://crates.io/crates/tar/0.4.46), [flate2 1.1.10](https://crates.io/crates/flate2/1.1.10) and [lzma-rust2 0.22.0](https://crates.io/crates/lzma-rust2/0.22.0). The 0.22.0 source exposes `XzReader::new_mem_limit`; its changelog records fixes for allocations based on declared dictionary and XZ index sizes ([upstream changelog](https://github.com/hasenbanck/lzma-rust2/blob/master/CHANGELOG.md)). The read-only review found no API or advisory blocker for this candidate; the formal advisory check remains open. Crates.io does not declare sha2 0.10.9's MSRV; the host candidate uses 0.11.1 so XZ and application hashing can share one version, while the target graph remains unchanged. Root must create and review an exact separate host lock, its complete transitive licenses/advisories, selected APIs, and both-host builds before freezing these candidates. No project manifest or lockfile was changed. The selected features have no host-native C dependency; macos-aarch64/linux-x86_64 compilation remains unverified.

The proposed `ami-rust --version` output is one JSON object and LF using `ami-rust-version-v1`, with exactly `schema`, `cli_version`, `sdk_version` and integer `packaging_revision`; both frontends must emit byte-identical output. This is a proposed RC1 format; the current Python launchers emit text and their parity outputs remain as recorded under observed interfaces. Do not add clap for this bounded CLI. A manual parser can preserve exact separator handling, unknown/duplicate option refusal, fixed recipe and exit semantics with a smaller dependency graph. Do not add a cryptographic protocol library; retain the existing externally pinned GH/Cosign route.

## Closure gaps and removal conditions

The companion Python registry maps all 104 tracked Python files: 26 public-consumer paths to RC1 and 78 release/test/maintainer paths to RC4; each has an RC5 closure milestone, replacement and removal condition. Use that registry as the per-file source of truth. Remove public files only after their parity fixtures pass on both supported hosts and no public import/execution remains. Remove RC4 uses only after replacement behavior and the actual protected workflow pass. RC5 requires supported protected workflows to run on both hosts under a proven process-tree observer with no direct or transitive Python process.

The remaining closure questions are concrete. The public closure includes the Python package launcher/worker, CPython bootstrap, SDK CLI/build/contracts and host artifact helpers, release installer/verifier/project generator and consumer preparation. The Cargo source producer has Python overlay/producer drivers; its vendor capsule contains 3,924 entries, one Python utility, 12 build.rs files and seven process-spawn sites. Static review found no Python invocation in build.rs; execution of the utility and spawned tools remains unproven until the real process tree is observed. The C-SDK corresponding-source archive contains 33,043 entries and 71 Python sources; its archived Ninja graph has 72 Python command records: nine RUN_PYTHON, 54 PYTHON_EXECUTABLE and nine direct script calls. The prior count of 69 omitted three direct kickstart/localise-symbols.py edges. The current bounded C-SDK producer does not qualify the full Ninja graph. Resolved supported boundary: RC5 supports the existing bounded portable C-SDK derivation only. The full upstream Ninja graph and its 72 Python command records are inert corresponding-source/recipe data, excluded from active execution. Any selected interpreter-dependent edge in the bounded path remains RC4 replacement work and requires actual two-host RC5 qualification. Full Ninja execution is outside the supported producer; adding it requires a separately reviewed executable closure. Protected CI, Cargo, package, replay and SDK-qualification workflows also invoke Python production, testing or verification paths; each call must be removed or qualified under RC4/RC5.

RC0-A3 still needs a two-host Cargo-to-final-ELF design. RC0-A4 still needs ordinary passing native controls and intentional direct, shebang, absolute-path and transitive Python controls observed by a process-tree harness on both hosts. Do not infer acceptance from static inventories or this contract.

## Proposed RC1 fixtures

contracts-v1.json enumerates each fixture and result. Required coverage includes alias parity; exact parser/status behavior; nested duplicate JSON keys and non-finite values; schema negotiation; every lock identity; hostile TAR entries including PAX size conflicts; bounded XZ/gzip; external trust decoys; state/prefix owner and mode failures; build-lock contention and failure retention; receipt-pin failure after publication; uninstall tombstone recovery; dry-run and explicit v1 migration; both-host parity; and direct/transitive Python process controls.

These files record contract decisions and fixture proposals only. This contract task performed no host-core implementation, host-core build/test or qualification; dependency lock, transitive license/advisory review and both-host validation remain open.

## Concrete parser and compatibility inputs

[legacy-fixture-pins.json](legacy-fixture-pins.json) binds the 26 existing
consumer implementations and ten legacy oracle suites (145 named unittest
cases) to source `b16a025a7b3b1d072b1633e1f5cbd4d927fdd80e` and per-file
hashes. These generators define actual legacy fixtures, alongside the 17 new
contract families in contracts-v1.json. They are internal transitional oracles;
RC1 must compare Rust behavior and intentional v2 changes, and RC4 removes
active Python oracles while retaining these immutable source identities.
The two previously unselected host suites pass 50 cases locally and now run on
both release hosts in CI. Prior fixture CI remains recorded separately.

The machine contract's metadata_limits freezes JSON input bounds before RC1:
2 MiB package/state/selection metadata, 1 MiB project locks, 16 MiB SDK/component
manifests, 4 MiB release manifests/receipts, and the existing external publisher
policy/authentication/root limits. New JSON accepts at most 128 nested
containers. Each file reader must enforce size before and during reading, and
parsing rejects BOM, duplicates, trailing input and invalid/non-finite numbers.
These are untrusted format boundaries, independent of application memory policy.
Decoder/whole-archive and member limits remain format-specific; the standalone
API probes demonstrate enforcement mechanisms and do not silently replace
production archive compatibility rules. The release SDK's current strict TAR
profile refuses PAX size overrides; the prototype likewise refuses disagreement
between effective and raw header size. Upstream component archive profiles
require their own inventory-backed compatibility fixtures during RC1.

The host dependency/source/license review has selected the exact candidate
reported in [host-dependency-selection.md](host-dependency-selection.md).
The original conditional proposal above records the decision sequence; native
Linux qualification and the final RC0 acceptance record remain required before
promoting the lock to a production host core.

## Static host-core identity

The selected architecture builds one native ami-rust executable per supported
host, with the shared Rust core statically linked. cargo-ami is a byte-identical
regular-file copy; it normalizes Cargo's injected command token and calls the
same parser/dispatcher. Package and retained inventories require both paths to
match the accepted native artifact. CLI and core SHA-256 fields both identify
the exact containing executable bytes and are equal in this contract. No
separate rlib or dynamic core artifact is shipped just to populate a digest.
Any separately built linker/compiler guard has its own authenticated inventory
entry, even though it reuses the same core source. This resolves the proposed
record fields before their first implementation/publication; historical records
remain unchanged.
