# RC0-A1/A2 consumer contract and dependency survey

Snapshot: checkout d7ac89004a8f805e6f1e3efaf9242fed976803ab, 2026-10-18.

This records observed implementation contracts and open RC0 decisions. It is not a qualification result. RC0-A3 (two-host Cargo-to-final-ELF design) and RC0-A4 (process-tree/no-Python harness) were not run; no build or tests were run for this inventory. The companion [python-dependencies.json](python-dependencies.json) maps all 104 tracked Python paths to an RC1 or RC4 replacement milestone, an RC5 closure milestone, source anchor, and removal condition.

## Observed commands and exits

The package launcher currently exposes:

```text
ami-rust --version
ami-rust verify-package
ami-rust prepare --state ABSOLUTE_FRESH_STATE
ami-rust new --state STATE --project ABSOLUTE_PROJECT
ami-rust build --state STATE --project ABSOLUTE_PROJECT --output-dir FRESH [--package NAME] [-- CARGO_ARGS...]
ami-rust check-inputs --state STATE
```

Parser and dispatch: packaging/cli.py:191-242. The package build defaults --package to hello-aros and constructs a fixed Cargo build recipe: build --manifest-path PROJECT/Cargo.toml --package NAME --release --locked --offline, followed by forwarded options. host/build.py:76-103 accepts only --manifest-path, --package/-p, --release, --locked, --offline, and optionally one --features VALUE and/or --no-default-features. Unknown or duplicate options are rejected, so the facade does not expose arbitrary Cargo options.

prepare needs a fresh normalized absolute state path with an existing parent, a non-root user, and private user-owned state. It retains a versioned launcher/package, checks out the package-pinned source commit, bootstraps Python, and runs the worker. Failed state is retained for diagnosis. Other lifecycle commands require the same private state (packaging/cli.py:114-130,136-172,180-188; packaging/worker.py:20-68). Package integrity verification checks inventory, file type, modes, sizes, hashes, and assets (packaging/cli.py:48-85).

The direct SDK CLI provides:

```text
ami-rust --version
ami-rust verify --sdk-lock FILE
ami-rust build --sdk-lock FILE --output-dir FRESH -- build --manifest-path Cargo.toml --package NAME --release --locked --offline [--features VALUE] [--no-default-features]
```

Usage, option parser, dispatch, and exits: host/cli.py:322-446. verify accepts no forwarded args. build requires a fresh output directory, existing parent, and a -- plus Cargo args. The driver validates lock/SDK/component/host/Cargo identities before building. Its receipt claims native build only. The driver creates build.lock exclusively and takes a non-blocking exclusive file lock; supervised commands get logs and records with command, exit code, stop reason, elapsed time, observed peak RSS and workspace size (host/build.py:159-175,198-230). build-receipt.json currently has no schema key and records canonical artifacts, hashes, compiler/Cargo identity, arguments, command results, and capacity (host/build.py:267-299).

Release-bundle operations are separate helper CLIs, not current ami-rust subcommands:

```text
install_publisher.py verify --bundle BUNDLE --policy EXTERNAL_POLICY
install_publisher.py install --bundle BUNDLE --policy EXTERNAL_POLICY --prefix FRESH_PREFIX [--receipt-pin FRESH_EXTERNAL_FILE]
install_publisher.py uninstall --prefix PREFIX --receipt-sha256 SHA256
install_publisher.py lock --prefix PREFIX --selection SELECTION --project PROJECT --output FRESH_FILE

install.py verify --bundle BUNDLE --trust EXTERNAL_TRUST
install.py install --bundle BUNDLE --trust EXTERNAL_TRUST --prefix FRESH_PREFIX [--receipt-pin FRESH_EXTERNAL_FILE]
install.py uninstall --prefix PREFIX --receipt-sha256 SHA256
install.py lock --prefix PREFIX --selection SELECTION --project PROJECT --output FRESH_FILE
```

The production interface adds external publisher policy; the legacy offline interface instead pins an SSH key and ssh-keygen. The legacy route authenticates a signed manifest only and does not verify GitHub Actions/Cosign provenance or establish publisher identity binding/R1 qualification (release/install_publisher.py:146-195; release/install.py:311-400,1258-1266,1269-1321). The project helper is new_project.py --sdk SDK --output FRESH_PROJECT --receipt-sha256 SHA256 (release/new_project.py:254-260).

| Interface | Observed exit behavior |
| --- | --- |
| Package launcher | Success/help/version 0; argparse error 2; caught ValueError/OSError/subprocess error 2; other uncaught exception 1. Nonnegative child return codes pass through; child signal N maps to min(255,128+N) (packaging/cli.py:109-111,248-255). |
| Direct SDK CLI | Success/help/version 0; refusal or invocation error 2; non-negative build child status passes through; signal N maps to min(255,128+N) (host/cli.py:382-446). |
| Production and legacy installers | Success 0; receipt-pin failure or post-publication SIGTERM 1 with published prefix retained; verification/refusal/I/O/archive/subprocess failure 2 (release/install_publisher.py:170-195; release/install.py:1293-1321). |
| ci_verify.py helper | Success 0; caught failure writes a bounded failure record where possible and returns 1; argparse failure 2 (release/ci_verify.py:1907-1948). |

A receipt pin is an external file with the receipt SHA-256 and newline, written after publication. Installation stages a private sibling tree and uses an exclusive rename; SIGTERM is blocked around publication. Uninstall needs the external receipt digest and rechecks after moving the tree to a tombstone (release/install.py:870-931,1117-1141).

The current internal ci_verify.py commands are bootstrap-tools, qualify, prepare-inputs, and check-inputs. All require --work, --output, and --python-bootstrap-root; all but bootstrap take --bundle; prepare/check also require --source-commit and --selection, with optional --workflow-commit; bootstrap accepts optional --source-commit (release/ci_verify.py:1907-1948). The preparation record uses ami-rust-consumer-preparation-v1, includes verified roots/inventories and command records, and sets installed: false, R1_accepted: false (release/ci_verify.py:649-680).

The plan proposes a unified ami-rust verify/install/lock/uninstall surface and optional cargo ami … frontend, but neither is the current interface; no current cargo-ami executable was found. The plan labels these proposed commands future requirements (docs/rust-cli-cargo-migration-plan.md:123-139). Both frontends need one agreed capability list and parity fixtures.

## State, lock, and receipt formats

| Record | Current format and observed validation |
| --- | --- |
| Package ready.json | ami-rust-package-state-v1; status, host, SDK/package version, source commit, manifest digest. Requires READY and matching selected identity. State is fresh/private/absolute; no migration policy for future versions is recorded (packaging/worker.py:64-68; packaging/cli.py:114-128,180-188). |
| selection.json | No schema key; python plus exactly six component roots: rust, cargo, toolchain, collector, csdk, vendor. Paths are absolute/canonical; retained check compares the selection to verified roots (release/install.py:1144-1177; release/ci_verify.py:649-653). |
| consumer-preparation.json | ami-rust-consumer-preparation-v1; verified input/preparation evidence, explicitly not installed or R1 accepted (release/ci_verify.py:656-680). |
| Project ami-rust.lock.json | ami-rust-project-lock-v1: SDK root/manifest digest, host/Python digest, component roots, Cargo manifest/lock digests. Direct verifier requires the schema and validates the referenced inputs (release/install.py:1214-1222; host/cli.py:183-245; host/contracts.py:155-203). |
| Project ami-rust-sdk.json | ami-rust-project-sdk-binding-v1: version and SDK manifest digest, checked when present during lock creation (release/install.py:1195-1202). |
| Installed install-receipt.json | Offline legacy v1 and production v2. Both contain publisher, release/SDK manifest digests, version and full installed-file inventory; v2 also requires production authentication. Receipt reader enforces exact fields/schema (release/install.py:904-917,1012-1037). |
| SDK/release manifests | ami-rust-sdk-v1 and ami-rust-release-v1; bind SDK inventory and release archive/assets/producer/host interpreters (release/prepare_sdk.py:629-635; release/install.py:405-420,562). |
| Native build-receipt.json | No schema key; native-only claim, artifact hashes, command records, compiler/Cargo identity and host capacity (host/build.py:267-299). |
| Internal receipts | ami-rust-ci-auth-tool-bootstrap-v1, ami-rust-hosted-consumer-qualification-v1, and ami-rust-hosted-sdk-producer-v1. Producer status disclaims R1 acceptance/release authorization (release/ci_verify.py:33-35,482; release/ci_sdk.py:30-32,2024-2039). |

JSON readers reject duplicate keys in the relevant trust/lock paths. Exact-key enforcement varies: installer receipts enforce an exact schema/key set, while package ready-state and project lock check required identity/structure without one shared forward-compatibility policy. RC0 still needs unknown-field/schema behavior, version negotiation, upgrade/rollback rules, and a decision on which old records remain readable. Retain old records as evidence; do not silently rewrite them.

## Trust roots and provisioning

The production route uses trust material selected outside the candidate. release/ci-auth-tools.json pins host-specific gh/Cosign versions and binary/archive hashes plus GitHub/Sigstore root hashes. Its external source policy binds repository, workflow, workflow/source commits, ref, OIDC issuer/certificate identity, and input-manifest digest. The verifier requires exact policy fields and validates workflow run, attestations and Cosign bundles against the release manifest (release/ci-auth-tools.json:1-55; release/ci_verify.py:522-555; release/verify_publisher.py:222-255,363-410). Root files and pinned SHA-256 values are:

- release/trust/github-trusted-root.jsonl: 65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c.
- release/trust/sigstore-trusted-root.json: 05a094edfa2e8eb7d1b4b37244e28ffb6d86b8b86ce3eb122b644b4335ae4dc1.

The package pins source commit, release-manifest and transport identities; preparation checks out the exact commit before loading helpers; public replay requires a clean checkout at that commit (packaging/pins.json:1-24; packaging/cli.py:149-170; release/public_replay.py:274-310). The current public lifecycle downloads pinned CPython 3.12.15. APT metadata declares a Python runtime dependency; Homebrew depends on python@3.14 and rewrites the launcher shebang (release/ci-python-inputs.json:14-55; packaging/control.py:277-299; packaging/metadata.py:257-270; packaging/test_metadata.py:231-237). First-party scripts use standard-library imports and have no Python package lock; executable dependencies remain a separate closure.

## Rust/Cargo candidate and producer dependencies

Rust 1.98.1 is the host compiler candidate already recorded in the bootstrap inputs, not a new dependency selection. Host rustc/rust-std/Cargo URLs, sizes and SHA-256 pins are in release/ci-bootstrap-inputs.json:76-132; producer records identify rustc commit 48a229ceaefd4985c50990b14116b6d856af0985, LLVM 22.1.8 (release/ci-cargo-producers/linux-x86_64.json:91-92; release/ci-cargo-producers/macos-aarch64.json:91-92; release/ci_cargo.py:85-120). Upstream Cargo is pinned to commit 3efb1f477e99b42974b982d939fd100303cdf7db; its lock has 523 registry plus 27 workspace packages, lock digest b4ccfa53ccf8d7360c0359c1533d801759629f9cdd486d9a0a88e512717058d9, and patch digest 1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f (release/ci-bootstrap-inputs.json:1-29; producer record release/ci-cargo-producers/linux-x86_64.json:61-88; host/cargo-repro/produce.py:127-183).

No Rust host CLI crate or reviewed host CLI Cargo.lock exists in this inventory. Conditional direct-version candidates are recorded in the companion contract; none is frozen until an exact host lock and review gates pass. RC0-A2 must commit those choices before implementation builds. Keep host compiler choice separate from target SDK toolchain: target remains nightly-2026-09-18, rustc commit 330d317121e16b5db8e5adc63595910528ff2ee7, LLVM 23.1.1, from existing release/ci-sdk-inputs.json pins (docs/compatibility.md:13-16).

Current Cargo source production reconstructs the locked vendor tree with pinned bootstrap Cargo and builds upstream Cargo offline; driver/overlay helpers are Python and map to RC4. The distinct target vendor archive release/inputs/vendor.tar.xz is pinned by release/ci-sdk-inputs.json, SHA-256 84fb6e3e1710f13e85450cce1db541c3967520f996a3f17efbd5a7a8345b1c7e. Static inspection found 3,924 members, one Python utility (vendor/libc-0.2.189/etc/libc-util.py), 12 build.rs files with no observed Python invocation, and seven process-spawn sites. Static review does not prove whether the utility or spawned tools execute. This archive is separate from Cargo's reconstructed vendor tree.

## C-SDK archive and upstream generator closure

The corresponding-source capsule release/csdk-source/csdk-corresponding-source.tar.xz is 103,277,840 bytes, SHA-256 7e62e28fb025e31aacdd3b6a6d14cef7d76703eb59dbaca02f2e2b4de68c6914, with 33,043 members. It includes 71 Python sources: 38 AROS-NX and 33 aros-tools. This is read-only evidence; protected repositories were not edited. Identity evidence: release/portable-csdk/spec.json:49-60, release/csdk-source/manifest.json:1-16.

The current bounded producer is not a full Ninja build. It parses selected public-header writeincludes recipes and runs classic C tools/genmodule; replays exactly 825 captured Nouveau C compile records and archives with selected LLVM tools; then runs AOM CMake metadata with Perl/Git and uses pkg-config for relocation checks. It preserves 2,835 regular files and changes 530 public headers, libdrm_nouveau.a, and aom.pc (release/csdk_producer.py:224-241,265-309; release/csdk_recipes.py:265-345; release/csdk_metadata.py:284-365,472-509).

The archived recipes/build.ninja contains 72 command records routing an explicit Python runtime or generator through RUN_PYTHON, PYTHON_EXECUTABLE, or direct script calls: nine RUN_PYTHON, 54 PYTHON_EXECUTABLE and nine direct scripts. The prior count of 69 omitted three direct kickstart/localise-symbols.py edges at lines 322126, 322141 and 322156. Other examples: DOS genstrings.py at line 285467; seven Mesa gen_pack_header.py runs at 285482-285572; udis86 ud_itab.py at 285587; AboutAROS generators at 285617-285647; Mesa mesa20_generate.py and compiler/NIR/GLAPI/gallium generators at 285662-286169; symbol audits at 322539 and 322548. These line references are inside the archived Ninja file, not tracked checkout files. If the supported RC5 source-build path runs this full graph, those Python generator edges block closure until replaced or excluded by a reviewed bounded derivation, or their outputs are authenticated non-Python inputs with source obligations retained. The current bounded producer does not qualify the full graph.

## Test inventory and open decisions

The tracked Python inventory is 104 files: 14 host, 29 packaging, 59 release, 2 qualification. It contains 51 test scripts (5 host, 14 packaging, 31 release, 1 qualification). The JSON maps 26 public-consumer paths to RC1 implementation and 78 test/maintainer/release paths to RC4, with all 104 assigned RC5 closure and replacement/removal conditions. No criterion is marked passed. CI runs Python tests and protected Cargo/package/replay/SDK qualification workflows invoke current Python production or verification paths (.github/workflows/ci.yml:58-95,110-118; .github/workflows/cargo-qualify.yml:55-81; .github/workflows/packages.yml:91-192; .github/workflows/public-replay.yml:254-281; .github/workflows/sdk-qualify.yml:131-144,531-556,987-995). Tests were not run here.

Open RC0 decisions:
1. Agree one capability list for package lifecycle, direct SDK, production trust/install, legacy offline trust, and optional cargo ami; decide whether lifecycle commands remain and whether the Cargo frontend is an alias.
2. Freeze exact options, exits/status mapping, output JSON shapes, and parity fixtures, including the package facade's current child-status behavior.
3. Define schema/unknown-field compatibility, version negotiation, upgrade/rollback and readable historical state/receipts.
4. Decide host Rust 1.98.1 and commit its host-specific selection plus reviewed CLI Cargo.lock; select no dependencies by inference. Preserve target nightly and current Cargo/C-SDK pins.
5. Run RC0-A3 and RC0-A4 before implementation claims: two-host Cargo-to-final-ELF design; process-tree detector with direct/transitive Python positive and negative controls.
6. Decide whether full upstream Ninja is in the supported RC5 build closure; if it is, replace its active generators.

## Verification

The JSON parses and contains 104 unique entries matching tracked Python paths. Counts are 26 RC1 and 78 RC4 primary milestones; all entries have RC5 closure and removal conditions, and every listed path exists. No build, test, qualification, or publication was performed for this static inventory.
