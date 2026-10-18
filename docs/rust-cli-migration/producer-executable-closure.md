# RC0-A1 producer executable closure

**Disposition: OPEN; this report does not accept RC0.** This is a read-only static audit of the committed producer code and pinned archives. I did not run package/toolchain builds or tests, so the report establishes the commands the code selects and the source inputs those commands can reach; it does not claim a completed process trace on either supported runner.

The supported build hosts are macOS ARM64 and Linux x86-64; both produce the x86-64 AROS target. The current producer chain still runs Python. The relevant workflows bootstrap CPython 3.12.15, then use it for Cargo and SDK production. The full Ninja archive also contains Python 3.14 and system Python commands, but those graph edges are not selected by the bounded C-SDK producer.

## Active producer path

| Stage | Selected path and commands | Current interpreter / boundary |
|---|---|---|
| Cargo prerequisite workflow | The workflow runs system Python for artifact admission and the Python bootstrap, then invokes release/ci_cargo.py with the bootstrapped interpreter. See .github/workflows/cargo-qualify.yml:55-72. | System Python 3 starts the bootstrap; pinned CPython 3.12.15 runs the producer. |
| Cargo source and build | release/ci_cargo.py:614-656 fetches and checks out Cargo commit 3efb1f477e99b42974b982d939fd100303cdf7db, verifies its lock and patch, and calls /usr/bin/git and /usr/bin/patch. It installs pinned Rust 1.98.1 components through their install.sh scripts, then calls host/cargo-repro/produce.py for vendor provisioning and build and host/cargo-repro/prepare-overlay.py for the declared overlay: release/ci_cargo.py:763-811. | host/cargo-repro/produce.py:178-184 runs pinned Cargo vendor --locked --versioned-dirs and Cargo build --locked --offline -j 2 --bin cargo --features all-static --release. These are distinct phases; vendor provisioning does not run build.rs. |
| SDK workflow | The workflow bootstraps Python and runs release/ci_sdk.py under CPython 3.12.15. See .github/workflows/sdk-qualify.yml:127-151. | release/ci_sdk.py:1823-1828 calls ci_cargo.produce in-process. It later launches release/prepare_sdk.py and release/csdk_producer.py, verifies host/cli.py in both layouts, and launches five host/cli.py builds in each layout: release/ci_sdk.py:1870-1882, 1927-1928, 1944-1961. |
| AROS application builds | release/ci_sdk.py:1751-1763 selects the locked host CLI command. host/build.py:235-249 compiles native C sources with the pinned cross toolchain and invokes the produced Cargo with --target targets/x86_64-aros.json and the selected package/features. The five variants are declared at release/ci_sdk.py:41-46. | The host/cli.py and host/build.py Python implementation is active in the SDK producer path as well as the public consumer path. They cannot remain deferred wholesale to a later internal-tools phase. |
| C-SDK reproduction | release/ci_sdk.py:415-456 launches release/csdk_producer.py using the pinned Python runtime and supplies the native compiler, cross toolchain and explicit CMake, pkg-config, Perl and Git paths. | CSDK orchestration is Python today; the selected archived C generators are native C executables, not Python scripts. |

The Cargo prerequisite graph and the SDK workspace graph are separate. release/ci-bootstrap-inputs.json:1-29 pins upstream Cargo and its 550-package lock (523 registry packages, 27 workspace packages); Cargo's vendor tree is reconstructed at producer time. release/inputs/vendor.tar.xz is instead the target workspace vendor input, extracted later by release/ci_sdk.py:1923-1926. Treating the latter archive as the source closure for the former would be incorrect.

## Target workspace build.rs closure

The target vendor archive has 3,924 members. Intersecting its member contents with the current root Cargo.lock (47 package records) finds eight locked build.rs files. The target is explicitly x86_64 / AROS in targets/x86_64-aros.json, and host/build.py:244 passes that target to Cargo.

| Locked package and archive member | External process in the script | Applicability to x86_64 AROS |
|---|---|---|
| curve25519-dalek 4.1.3 — vendor/curve25519-dalek/build.rs:38-48 | Calls rustc_version::version_meta() and version(). The locked rustc_version 0.4.1 helper vendor/rustc_version/src/lib.rs:174-210 executes the selected rustc with -vV; version() delegates to version_meta(), so the script requests two Rust version probes. | Reachable through the dependencies variant's ed25519-dalek graph. No Python process. |
| generic-array 0.14.7 — vendor/generic-array/build.rs:1-5 | Calls version_check::is_min_version(). The locked version_check 0.9.5 helper vendor/version_check/src/lib.rs:159-161 executes rustc --verbose --version. | Reachable through the sha2 and dependency graphs. No Python process. |
| libc 0.2.190 — vendor/libc/build.rs:369-415, 533-560 | Source contains a rustc version probe and conditional freebsd-version and emcc -dumpversion probes. | Not selected for the AROS target: Cargo.lock has only cpufeatures 0.2.17 as its dependent, while vendor/cpufeatures/Cargo.toml:57-73 enables libc only for listed AArch64 or LoongArch host/target configurations, not x86_64 AROS. The FreeBSD and Emscripten branches are also inapplicable. |
| proc-macro2 1.0.107 — vendor/proc-macro2/build.rs:190, 250 | Runs rustc for a compile probe and a rustc --version probe. | Reached by procedural-macro dependencies. No Python process. |
| quote 1.0.47 — vendor/quote/build.rs:25 | Runs rustc --version. | Reached by procedural-macro dependencies. No Python process. |
| serde 1.0.228 — vendor/serde/build.rs:62 | Runs rustc --version. | Reached by the dependencies variant. No Python process. |
| serde_core 1.0.228 — vendor/serde_core/build.rs:106 | Runs rustc --version. | Reached by the dependencies variant. No Python process. |
| serde_json 1.0.145 — vendor/serde_json/build.rs | Emits cfg information; no external command. | Reached by the dependencies variant. |

These are build-script subprocesses only; Cargo also launches rustc for normal compilation. The inventory's direct Command scan names seven build.rs files: four are locked and reachable here (proc-macro2, quote, serde and serde_core), libc is locked but not selected for this target, and the old libc-0.2.189 and object-0.39.1 paths are not in Cargo.lock. That direct scan also misses the indirect rustc launches through curve25519-dalek/rustc_version and generic-array/version_check. For the selected workspace graph, the build.rs external-process family is rustc; the archive's libc probes are not on this target path.

The archive contains four additional build.rs files that do not match the current root lock: libc-0.2.189, object-0.39.1, wit-bindgen-0.57.1 and wit-bindgen-0.61.1. The only .py member is vendor/libc-0.2.189/etc/libc-util.py, whose package version is not locked. Archive-wide content search found that path only in its own documentation and libc-0.2.189/.cargo-checksum.json; no selected command or current locked package invokes it. Its presence is not evidence of runtime Python.

This target-workspace result does not close upstream Cargo's own build-script graph. The 550-package Cargo lock is pinned, and its registry checksums are checked against the reconstructed vendor source, but the tracked vendor.tar.xz is not that vendor tree and the repository does not retain an inventory of those 550 package sources or their build.rs external calls. Static inspection here therefore cannot establish the exact host Cargo build-script process tree for macOS ARM64 and Linux x86-64. RC0-A1 must add that source-level closure or other equally precise evidence; no full Cargo build is needed to identify the gap.

The AROS target build has a separate source-build-std closure. host/build.py:244 invokes Cargo with `-Zbuild-std=core,alloc` and `-Zbuild-std-features=compiler-builtins-mem`. Both supported host profiles pin the same 2026-09-18 `rust-src-nightly.tar.xz` (5,934,836 bytes, SHA-256 `8de4a7bc2ba7fd977a3ec74ae2794fee99c6f987e5f022ba2ff4b0ca8a5d1004`) in release/ci-sdk-inputs.json:50-53. Within that archive, `library/alloc/Cargo.toml:17-23` depends on source-tree `core` and `compiler_builtins`; `library/compiler-builtins/compiler-builtins/Cargo.toml:30-53` declares optional `cc` behind the `c` feature and the `mem` feature is independent. The selected build-std feature enables `mem`, not `c`. The pinned compiler-builtins build.rs (`library/compiler-builtins/compiler-builtins/build.rs`, SHA-256 `f4d089d2d5446010b91493ccf993c13bc397f407021180340d6196f3a89eb485`) only calls its C compiler helper under `cfg!(feature = "unmangled-names") && cfg!(feature = "c")` at lines 78-85; therefore the selected AROS core/alloc build has no compiler-builtins C compiler subprocess. No build.rs exists at the selected core or alloc crate roots. This closes the compiler-builtins portion statically; it does not close the distinct 550-package upstream Cargo bootstrap graph above.

## Bounded C-SDK recipe closure

release/ci_csdk.py:30-114 verifies all 33,043 members of the corresponding-source capsule, then materializes only sources/, generated/, recipes/ and the nested original libaom archive, with a 352 MiB selected-input ceiling. It does not execute the capsule's Python files. The recipe parser reads commands as data; release/csdk_recipes.py:265-355 selects public-header records and exactly one hosttools/genmodule edge, while release/csdk_recipes.py:358 onward parses the Nouveau compilation database. Static parsing selects the genmodule edge at archived recipes/build.ninja:287146, 106 public-header edges from line 287215 through line 322380, and the Nouveau archive edge at line 46765. No Ninja process is launched.

The selected command closure is:

| Selected input / output | Actual producer commands |
|---|---|
| 106 public-header Ninja edges, five outputs each | One native cc invocation builds hosttools/genmodule from exactly 27 C source inputs. The producer runs that executable once for each of 106 recipes in each of two roots, then once for the absolute-path counter: 213 genmodule invocations and 530 reproduced headers. This corrects the prior estimate of 273. See release/ci_csdk.py:219-310 and release/csdk_producer.py:236-242. |
| Four prefix-mapping probes | Four direct clang-11 compilations for the two-root comparison and two counter-cases: release/ci_csdk.py:117-161. |
| The Nouveau archive edge at recipes/build.ninja:46765 and 825 matching compile_commands.json records | The producer runs 825 direct clang-11 argv vectors and then recompiles the same 825 records for the original-prefix counter, at concurrency two. release/csdk_nouveau.py:272-325 validates the exact archive object set; :556-650 runs the direct commands with shell=False; release/csdk_producer.py:270-288 connects the selected graph and counter. |
| AOM metadata only | CMake runs version.cmake twice, patched pkg_config.cmake twice, and an unpatched target counter once. Each version.cmake run invokes the supplied Git executable and Perl version.pl; each metadata root makes two pkg-config queries, and the original-prefix counter makes one more. This path generates aom_version.h and aom.pc; it does not build libaom. See release/csdk_metadata.py:282-414,472-509. |
| Final Nouveau archive | Two deterministic archive passes each run pinned llvm-ar and llvm-ranlib: release/csdk_producer.py:291-307. |

The nested libaom archive and script are content-pinned: the archive SHA-256 is 9e9775180dec7dfd61a79e00bda3809d43891aee6b2e331ff7f26986207ea22e; build/cmake/version.cmake has SHA-256 ed976d69eece58510b9a57a780973d621c8f420724fa50a7d83fba3fdba460dc. Its Git call is at version.cmake:26-32 and Perl call at :60-66. release/csdk_metadata.py reads only its declared version inputs and pkg_config.cmake members.

The host CSDK tools cc, cmake, pkg-config, perl and git are found from the runner's ambient PATH and their digests are recorded/rechecked for the duration of a run; release/ci_sdk.py:401-412 and 420-429. They have no normative per-host digest pin in this producer path. Receipt-time hashes are useful evidence but do not freeze those external identities across the two supported hosts. The code hard-codes /usr/bin/git for Cargo source handling and /usr/bin/patch for the Cargo overlay and CSDK patch paths. RC0-A1/RC4 should either pin the intended host-tool versions and digests per host or route them through verified tool bundles.

## Full Ninja source files that are not on the selected path

The capsule manifest lists 71 Python source files, but a file count is not an execution count. I parsed the pinned recipes/build.ninja COMMAND records and separately ran the checked-in recipe parsers over recipes/build.ninja and recipes/compile_commands.json as data. The bounded producer selects 106 header records, one genmodule edge and 825 Nouveau records; it does not execute the rest of Ninja.

The full archived Ninja file has 72 Python COMMAND records: 9 set RUN_PYTHON, 54 set PYTHON_EXECUTABLE, and 9 directly invoke a Python script. Three direct scripts/kickstart/localise-symbols.py edges at lines 322126, 322141 and 322156 were omitted from the prior inventory's count of 69. The direct-script records are ud_itab.py, the three AboutAROS header scripts, three localise-symbols.py edges and two audit-symbols.py edges. RUN_PYTHON records include genstrings.py, seven Mesa gen_pack_header.py edges and the Mesa glapi generator; PYTHON_EXECUTABLE records are the other Mesa generator records. Many records refer to hard-coded /opt/homebrew Python 3.14; the direct localise/audit records use /opt/homebrew/bin/python3. They remain inert because the current producer never asks Ninja to traverse those edges.

The inventory count has been corrected to 72 in docs/rust-cli-migration/python-dependencies.json. Any later producer change that runs the full source graph must revisit every one of those 72 commands, not just the number of .py files. The source scripts remain part of the corresponding-source and notice obligations even while unexecuted.


## Subsequent exact Cargo source inventory

The initial missing-source finding above is historical. The subsequent review
reconstructed the exact upstream commit and patch and obtained all 523 registry
archives from the 550-record lock. All 523 archive SHA-256 values match their
lock checksums. Total compressed input is 81,009,371 bytes, with a 7,195,821-byte
largest archive; 393 were copied from an existing checksum-verified cache and
130 were fetched (26,262,874 bytes). The 27 path packages belong to the pinned
upstream source. [Source/input identities and selected build-script inventories](evidence/cargo-source-inventory/index.json)
are retained publicly; complete source copies remain separate from the report.

Native macOS querying selects 349 package identities and 37 build scripts.
A Linux-target query executed on macOS selects 341 identities and 36 scripts,
but this cannot prove Linux-host build-dependency selection. The new
[native Ubuntu metadata query](native-cargo-closure-query.md) resolves that
remaining selection question without running package build scripts or a full
Cargo build. Actual helper execution remains RC4 qualification work.

The inspected non-rustc helper branches in that exact graph are:

| Source anchor | Selected conditional helper family |
| --- | --- |
| Cargo `build.rs:60–85,118–135` | Git log for the checked-out commit unless CFG_OMIT_GIT_HASH disables it. |
| curl-sys `build.rs:26–52,290–301,342–365,464` | macOS force-system-lib branch; Linux vendored C build with nghttp2/OpenSSL. Source includes an ignored-status Git submodule attempt when curl/.git is absent. |
| libgit2-sys `build.rs:85–125,245–305` | Vendored C through cc, SSH/libssh2, Linux OpenSSL or macOS Secure Transport. Existing libgit2/src skips its submodule fallback. |
| libssh2-sys `build.rs:22–39,66–93,116–194` | C through cc unless explicit pkg-config override; source includes a conditional submodule attempt. |
| openssl-sys `build/main.rs:48–58,188–190`; openssl-src `src/lib.rs:157–160,637–676` | Vendored Perl Configure and make depend/build_libs/install_dev. The current overlay stages a /usr/local prefix with DESTDIR; no Python generator found in this selected route. |
| libsqlite3-sys `build.rs:52–88,103–144` | Bundled C plus pre-generated bindings; no selected bindgen execution. Explicit pkg-config environment override remains a separate branch. |
| libnghttp2-sys `build.rs:51–104` | Listed C sources through cc; no selected CMake/Perl/make route. |
| libz-sys `build.rs:16–23,33–98,101–140,221–236` | pkg-config/system -lz compiler probe, then bundled C fallback. Selected features include libc, not static/zlib-ng. Cargo's all-static flag does not make this dependency unconditionally static. |

These are source branches, not observed subprocesses. Their recorded build-script
hashes are in the selected-source inventories. The openssl-src helper preimage
is `c0f7ee0384ee12835abc6197122dc60ac75e33a3906dfe90bc378e62df56839d`;
the pinned overlay patch is
`67f92b277d2cb9508ca3d6d041ebf9feb0ddbf05e97a9419960f313344cd6de8`,
producing helper SHA-256
`992641416caf72adc67e9196ee4e452f5ba284e8586050c9d2ed8bb1d287c1a5`.
Host Git/C compiler/archive/Perl/make/pkg-config identities and branch outcomes
must be recorded in the actual RC4 producer qualification. No selected intrinsic
Python call was found in these helpers; the outer producer remains Python.

The new RC0 source-query driver/workflow use transitional internal Python.
Assign their orchestration to RC4 replacement and RC5 removal, together with
inline Python in the RC0 native Cargo workflow. The earlier 104-file `.py`
inventory is a survey of its stated base, not a claim that extensionless or
inline Python can be omitted from complete retirement.

## Work to reach RC4/RC5

1. Close the bootstrap Cargo gap with a content inventory for the exact upstream commit, patch and 550-package lock; identify every selected build.rs and its external calls under each supported host triple. Keep the bootstrap Cargo graph separate from the x86_64 AROS application graph.
2. Move the public runtime path first: replace the Python runtime bootstrap, host/cli.py and host/build.py behavior, including their imported host modules. Those entrypoints execute in release/ci_sdk.py:1944-1961, so the SDK producer cannot become Python-free while they remain. Split shared producer/consumer logic so RC1 replacement is not blocked behind the entire release producer rewrite.
3. By RC4, replace the producer stack with Rust: release/ci_cargo.py, host/cargo-repro/produce.py, host/cargo-repro/prepare-overlay.py, release/prepare_sdk.py, the producer portion of release/ci_sdk.py, release/ci_csdk.py, and active C-SDK modules release/csdk_producer.py, release/csdk_recipes.py, release/csdk_nouveau.py and release/csdk_metadata.py. Preserve the current fixed recipe selection, package/target locks, archive checks, patches, process/time/RSS/log/workspace limits and receipts. Do not replace the bounded C-SDK producer with a full Ninja build until the Python generator closure is resolved.
4. Add tests that validate the exact lock/archive membership and command plan; verify selected versus decoy Ninja edges; reject changed or duplicate recipes; and capture the process tree on macOS ARM64 and Linux x86-64. The closure check must fail on any Python interpreter, unexpected host tool or unlisted build.rs command. Compare the generated artifacts and metadata to their pinned identities.
5. At RC5, remove Python bootstrap, Python workflow steps (including cleanup), Python package/runtime requirements and active Python imports from consumer and producer paths. Keep upstream Python source in the corresponding-source capsule where licensing/source obligations require it, but do not execute it through the bounded producer.

## Evidence identities

The source revision was HEAD 5ec8d2e2cf79563a19bf7611ed8ef6a419e79960. Hashes below identify the files and archive members used for this static report.

| File or archive member | SHA-256 |
|---|---|
| release/ci_cargo.py | 589a8abc9fc4b0537b4b9646d441413f4eb005288bbc3ea0220f5218ffc18da2 |
| release/ci_python.py | b25514fbf2f11d5802dc37c2771ef68f15ece3dbd975f40838d0cd70e3cd1fb7 |
| release/prepare_sdk.py | f92e14a111f194737cebd50a095a88acf0f7f085ef692ea567375786e968163e |
| release/ci_sdk.py | 873ec820c1bb30b3751854b5526741f5d679fd9577c8964dab462ec559e6aee1 |
| host/cargo-repro/produce.py | e91757106409643855ac4053540f4d018839937eada7a24f8be504c27b1e423f |
| host/cargo-repro/prepare-overlay.py | cb2834a2c22d5b70555759c685425a4e42f5df12e2ad8ff48b63afc5836795d3 |
| host/cli.py | 9826874170599d9219f952473718be8fe5658dda4a902b77bfa546c511ee0949 |
| host/build.py | 88839d90b25c8962929501b5c97886c7531b1775c467f510b772b532578684f6 |
| targets/x86_64-aros.json | de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71 |
| release/ci-bootstrap-inputs.json | 5c3557a2696457d76562f8883efa2c7d2c4cfc583f4f5814a722907a1f639f81 |
| release/ci-sdk-inputs.json | df4494bfc3590b97c5a8d5fe126842c56d801787ffb49dead0b9e58c9a3c3ded |
| Cargo.lock | 193e4abca19f511cd264375dfdc05c915b8182988de55e60b49553140b2b1596 |
| release/ci_csdk.py | 14029eeb4123f901c58cce0c3043516186508449da4e8123ab3c081af271b9b6 |
| release/csdk_producer.py | 6ff259a32b2bb890df44540d4146f60eb49109920d6e26938ac309982c307cbd |
| release/csdk_recipes.py | 84f4c598ac4b3d50c9ea8f61a323afa8e84b5fd4fd2c941a909cee0497e3e779 |
| release/csdk_nouveau.py | 6c7cbc92b688548d736c205815b1cb5df2bb3dea5fd1c418f32ce94ec17eb9c6 |
| release/csdk_metadata.py | efbdaff73fae189a1aa59d3b9dfa5a217e9d7696db6d7e3389514adad1e6d53b |
| .github/workflows/cargo-qualify.yml | 092c7eb0ed7cd9684671b00b0737a7d8422b6425a40b74c340bf915d3adda8f0 |
| .github/workflows/sdk-qualify.yml | f54212426ede78a7daf1dee459ac4610cd580b3ab01b1f847689b8104d9cae40 |
| release/inputs/vendor.tar.xz | 84fb6e3e1710f13e85450cce1db541c3967520f996a3f17efbd5a7a8345b1c7e |
| release/csdk-source/csdk-corresponding-source.tar.xz | 7e62e28fb025e31aacdd3b6a6d14cef7d76703eb59dbaca02f2e2b4de68c6914 |
| release/csdk-source/manifest.json | 4e616c8373ac1dc36e5a109953b13e971783abcff0358f24eb49d78f606ad689 |
| release/csdk-source/recipes/build.ninja | e0e938c9aa6b894bbe67882370f485dce399264457d03ce2791ac462bb063079 |
| release/csdk-source/recipes/compile_commands.json | 73ae9e2789cdad76778c7ae0d4d627efb8f40868717000b4bf316733c16a24ca |
| release/csdk-source/vendor/libaom/original/libaom-3.12.1.tar.gz (archive member) | 9e9775180dec7dfd61a79e00bda3809d43891aee6b2e331ff7f26986207ea22e |
| release/portable-csdk/spec.json | 7cb73dd7057feac1bf1a7f1bbf2172934cc06555e2b83938a93cb1b2bfe3178f |
| release/patches/portable-csdk/series.json | 2ba73be8a78d79b471f7fafde9a43c6310a1a58efd18818e9e3d97ed7206c607 |
| docs/rust-cli-migration/python-dependencies.json (corrected counts) | 8d75938c86c03d19dcc1fbe79c4928fe502deffdd6bce2105fd15b80d173d7a7 |
| Pinned rust-src-nightly.tar.xz (release/ci-sdk-inputs.json:50-53) | 8de4a7bc2ba7fd977a3ec74ae2794fee99c6f987e5f022ba2ff4b0ca8a5d1004 |
| rust-src library/compiler-builtins/compiler-builtins/build.rs (archive member) | f4d089d2d5446010b91493ccf993c13bc397f407021180340d6196f3a89eb485 |
| rust-src library/compiler-builtins/compiler-builtins/Cargo.toml (archive member) | d89e31fed70f2cad9c6e91b787bf4c0fb680c631196b2a7215c81745aaf7fb7e |

Build-script member hashes for the target vendor archive:

| Archive member | SHA-256 |
|---|---|
| vendor/curve25519-dalek/build.rs | c479ea95fa9cac8b3374564261c15cfcb110738ddcaa5e0852644b6083bd9189 |
| vendor/generic-array/build.rs | 08fa30c4a2c1ad24fe5f987e721dfb20131f45ea5b5dc3e836dcf88a8e33248c |
| vendor/libc/build.rs | feede9bdbbcf70c6409faef8fb2f2c065e942107eb6596677bb36dce6c5075fb |
| vendor/proc-macro2/build.rs | baeb20b52f6b536be8657a566591a507bb2e34a45cf8baa42b135510a0c3c729 |
| vendor/quote/build.rs | cd6808c02e476b09a520105e2c6f6d325cccb1ecd542cbbcc836a0ae6f6fb0f1 |
| vendor/serde/build.rs | c99c25e1a11f3e51b61dd8c25bdbfbd090e43e5f1f2014f41f28e214dd8310d5 |
| vendor/serde_core/build.rs | a5fdacb9913eeede5fc08f39acbd31b2508483fdc20c79d6bc274d74407a1816 |
| vendor/serde_json/build.rs | 1630d0bbfc936b0975d840cec5cfb5910d861b6afeeeeabe11000a2c202d571d |
| vendor/libc-0.2.189/build.rs | e47f4a6762799b6e69cefc7acdb3291df828010e4de20609f7378f9c94ea29e6 |
| vendor/object-0.39.1/build.rs | ba7ab1735d3642c53562d1223a6eb54c2392e619ade3005e0deee3fc4229feea |
| vendor/wit-bindgen-0.57.1/build.rs | 99b4276049457d3ea1d304277d66b0ff1abba0b9b1f5d60a5e25bdd3fd897a91 |
| vendor/wit-bindgen-0.61.1/build.rs | 3f2a0bf44b7d9c11703c4f7cbf40eae392271f96e7b5d7928f8925733cfcfc09 |
| vendor/libc-0.2.189/etc/libc-util.py | a99fdefe6354c28c52eeac9c1e851041b69dad25b8a3b521d4f57b761517c798 |

Helper source hashes that explain indirect rustc calls:

| Archive member | SHA-256 |
|---|---|
| vendor/rustc_version/src/lib.rs | 6d0dbf7bd12ba7121e6767841a0cee23b8282cc4d7c4b778a1e33129abdd7d72 |
| vendor/version_check/src/lib.rs | 01bb86088ba281d511ae002aa939bb30b747f47ace5ea13a46de554a3117806e |
| vendor/cpufeatures/Cargo.toml | 25160ea4dfa195721d352d42827b882a41f18f4c55fff58e5c3878ecae84ca44 |
