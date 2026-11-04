---
title: "M10 qualification: ami-rust 0.2.0"
---

# M10 qualification: ami-rust 0.2.0

Status: PASS for release-candidate preparation. Publication remains a separate
maintainer decision and is not authorised by this record.

GitHub issue #62 owns the execution state. This record applies M10-A1 through
M10-A4 of `docs/plans/ami-rust-0.2.md` to the exact candidate below.

## Exact candidate

| Identity | Value |
| --- | --- |
| Version | 0.2.0 |
| Source commit | `eae5928fc01c26415641f338d9f0c775aae40890` |
| Source tree | `4797217d76218cc23eef574162413965d3908755` |
| Release epoch | `1793095486` |
| Qualification workflow | [run 41728207161, attempt 1](https://github.com/metaneutrons/ami-rust/actions/runs/41728207161) |
| Candidate artifact SHA-256 | `2a1c6a61cac174c946442de5dab1946b79bd0f44255d090b9b35894f605d58e5` |
| Production contract SHA-256 | `d0ed3dff9f8c7c5efbf93cf5958b347b2dfc16904b4e5e845a272ed3085bfc35` |
| Targets | `x86_64-unknown-aros-abi1`, `x86_64-unknown-aros-abi11` |
| Catalog workflow | [run 41789538151](https://github.com/metaneutrons/ami-rust/actions/runs/41789538151) |
| Catalog artifact SHA-256 | `a61850a75d5bc2b5306e08ed596079a5734833da62c600471b535fa76b1b7b09` |
| Catalog manifest SHA-256 | `7c1ca3c527d3bb299aca236ef8ab1cb1f2e4056ed1afb221660e52247542e264` |
| Catalog commit | `88b1c3adaac0e2eab90741d3285cce4e32bfdd64` |
| Signed-candidate workflow | [run 41791853511](https://github.com/metaneutrons/ami-rust/actions/runs/41791853511) |
| Signed artifact SHA-256 | `b50df10bb296422d6a16746d6386ebc4ef8275b71f4cf499ef98b4036c0b8064` |

The protected workflow produced the candidate independently on macOS ARM64,
Linux x86-64 and Linux ARM64. Every producer, candidate-assembly, unmodified
rustup installation, dual-target Cargo build and final admission job passed.
The only change between the qualified source and the catalog commit is the two
catalog files, and the qualified source is an ancestor of the catalog commit.

Earlier runs are not part of this record. The first (run 41597753621) built all
three producers and then stopped in the corresponding-source step, because one
pinned digest was stale; that was corrected in pull request 96. A later run
(41712738022) passed on the source with the ABI-v11 layout fix of pull request
97 and was superseded because the documentation and sources changed after it
(pull requests 98 and 99). The run above is on the final source.

## Host archives

| Host | Archive SHA-256 | Inventory SHA-256 |
| --- | --- | --- |
| macOS ARM64 | `7744550cdd9e22fce34587dd8648ee367c86f9804c7e0ed191319e334cc96f7c` | `37e98b420ef2f3c15c90071ca75a19a27d165b969699fdfff21486ffb27963b3` |
| Linux x86-64 | `8b26c8c0d3a092a72d97a8ad0c32561653048239c8c343f2ff78945807b7b6f1` | `d08d28e17992447ce5ac26b68cf2d420068b8ab9a8787ecd8f1a76eb69fb6c79` |
| Linux ARM64 | `45c98ea5d8fa6f6ed78a8d5f5e76adc5d792cd2229dafaaeefac590f2d39c1dc` | `e5ddd42a4eabc2a9088737852b28b8a007b3a9f4f524a0b86251c5ed3fad7a58` |

The installed compiler is the one of 0.1.0: Rust `1.100.0-nightly` at commit
`330d317121e16b5db8e5adc63595910528ff2ee7` with LLVM 23.1.1, and the paired
Cargo `1.100.0-nightly` at commit `495c385d0875c4ba51eb72ea0448a2d4c018b8d4`.
The boot images, firmware, emulator and the two AROS source revisions are also
unchanged from the 0.1.0 qualification.

## Crates

The release carries 13 crates, all at version 0.2.0 and all published only to
the ami-rust Cargo registry: `aros-sys`, `aros`, `aros-mui-sys`, `aros-mui`,
`aros-timer`, `aros-graphics`, `aros-intuition`, `aros-asl`, `aros-locale`,
`aros-icon`, `aros-workbench`, `aros-elf` and `aros-native-build`. Each denies
`missing_docs` and has a guide page; `tools/check-docs-policy.mjs` enforces
both. All 13 package from their own archives with the pinned host Rust, and two
packaging runs give byte-identical archives.

## Native AROS execution

The candidate's macOS ARM64 toolchain was installed from its qualification
artifact (archive above) and used to build the qualification fixture and the
example applications from the exact source commit, locked and offline, for both
targets. Every run was a cold boot under QEMU 11.1.3 with `pc-i440fx-11.1`,
`qemu64-v1`, TCG single-threaded, one vCPU, 512 MiB RAM, no network and pinned
firmware.

| Evidence | Identity |
| --- | --- |
| QEMU binary SHA-256 | `0dba441e49c3cda068f3b33916ad9d2146d173d9bb65a6a62ce2e61d3211baaf` |
| BIOS SHA-256 | `ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650` |
| VGA BIOS SHA-256 | `e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472` |
| ABI1 boot image SHA-256 | `9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1` |
| ABI11 boot image SHA-256 | `2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7` |
| ABI1 source | AROS-NX commit `e0d5e367d15cc7da4ebac8f9db17868756c79569` |
| ABI11 source | Deadwood AROS commit `fbc242c1046cffb5e5827a4626ee62bdd45664e9` (ABIv11_2026.09) |
| ABI1 target specification SHA-256 | `0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807` |
| ABI11 target specification SHA-256 | `5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9` |
| ABI1 fixture binary SHA-256 | `47bef55feaf421af5cc11dd31b64544ad95342e6afb34a74b31ae24689293a96` |
| ABI11 fixture binary SHA-256 | `b41aaa5938321bc84bd54a90b57cacf9f0646df065ff09ae746515013c58bca9` |

### Qualification fixture

The qualification fixture (`tests/qualification`) selects one mode per boot.
Each mode ran in its own boot, after the `files` set-up mode. A mode passes when
the program returns 0 and every tracked resource counter (blocks, backing
charge, files, libraries, ports, signals, messages, devices, requests,
directories, rastports, bitmaps, windows, public screens, ASL requests, locales,
catalogs, icons, Workbench ports and objects) is zero when it ends.

| Crate | Modes | ABI-v1 | ABI-v11 |
| --- | --- | --- | --- |
| `aros`, `aros-sys` | `abi`, `calibrate`, `alloc`, `args`, `callbacks`, `churn`, `cleanup`, `cwd-check`, `devices`, `devices-forgotten`, `env`, `files`, `file-protected`, `fs`, `fs-forgotten`, `libraries`, `memory-large`, `ports`, `positions`, `probes`, `registry`, `stderr` | 22 of 22 | 22 of 22 |
| `aros-timer` | `timer`, `timer-forgotten` | 2 of 2 | 2 of 2 |
| `aros-graphics` | `graphics`, `graphics-forgotten` | 2 of 2 | 2 of 2 |
| `aros-intuition` | `window`, `window-forgotten` | 2 of 2 | 2 of 2 |
| `aros-asl` | `asl`, `asl-forgotten` | 2 of 2 | 2 of 2 |
| `aros-locale` | `locale`, `locale-bounded`, `locale-forgotten` | 3 of 3 | 3 of 3 |
| `aros-icon` | `icon`, `icon-forgotten` | 2 of 2 | 2 of 2 |
| `aros-workbench` | `workbench`, `workbench-forgotten` | 2 of 2 | 2 of 2 |
| Large files on ABI-v11 | `big` on `RAM:` | not run | 1 of 1: the seek beyond 2 GiB is refused with the `Limit` error |
| Total | | 37 of 37 | 38 of 38 |

Every one of the 75 boots reached the script and returned on its first attempt;
no boot needed a repeat. The result of every boot, its attempt count, the
fixture identity and the SHA-256 of its serial capture are in
[`evidence/m10-native-matrix.tsv`](evidence/m10-native-matrix.tsv). The `-forgotten`
modes forget the handles of their kind on purpose (`mem::forget`) and check that
the runtime releases them at exit.

The `abi` and `calibrate` modes and `examples/minimal` pass on ABI-v11. Before
the layout fix of pull request 97 they returned 20 there, because `aros-sys`
declared `Library` and `MsgPort` with the ABI-v1 SMP padding on both targets.

### Example applications

| Application | Target | Binary SHA-256 | Result |
| --- | --- | --- | --- |
| `examples/minimal` | ABI1 | `244842ef381d704c030c0fab7b12c40735c49a367609e1d54cb4901c509864e6` | return 0 |
| `examples/minimal` | ABI11 | `51eb6cf336c2658ed0707dd987999b0758f3cde52fac5c4395009cc1bf75e2a4` | return 0 |
| `examples/sha256sum` | ABI1 | `bc5a80bcc3b05f0d145801f75b589812180ffaa6943e25c0df24c28382d59910` | no argument: usage, return 10; `abc\n`: the correct digest, return 0 |
| `examples/sha256sum` | ABI11 | `e8678f16a51749dc87a440ba2cf3ff93d1d5d35accbe30c6e92bb25ca3b4dd8d` | no argument: usage, return 10; `abc\n`: the correct digest, return 0 |
| `examples/mui-hello` | ABI1 | `8dedee02f0ba29c4a7a72beaff3af78631c9c3068df3c48e13fa6b82748c563f` | window with the greeting rendered (screenshot SHA-256 `3dd59991603d11ae…`) |
| `examples/mui-hello` | ABI11 | `c3c26f96e88db2bc5891a8b2df7179d1420220fe81682627b26d278b3d3b13ce` | window with the greeting rendered (screenshot SHA-256 `ef88fa8ffada8919…`) |
| `tests/m1-runtime` | ABI1 | `0f19a470861c8f9a5b8eb3f7f91a75abe6b5454e7f09aad02813953fb9d51e8f` | return 0 |
| `tests/m1-runtime` | ABI11 | `bbbd3b32041ee77333d5171c863817c2ab6f97dbb34ef4d8e6ca90e6ee00f3df` | return 0 |
| `tests/m6-interactions` | ABI1 | `f07609424fc87fc04c878954ae67cd771bac60448e6254ddab31645f84f0865a` | return 0 |
| `tests/m6-interactions` | ABI11 | `910c3adfedbd32d3a734b16d224d6977de47f376db29e7423c29ba6bd485a6f9` | return 0 |

`mui-hello` is a window that stays open until it is closed and has no return
code, so its result is the rendered window, checked on the screendump of each
boot. The digest of the `sha256sum` result was compared with the host's
`shasum -a 256` of the same bytes.

## Limitations of this evidence

- The 0.1.0 qualification applications `tests/m3-runtime`, `tests/m4-safe-runtime`
  and `tests/m5-gallery` need the explicit native objects of the 0.1.0
  qualification workflow and do not build with the 0.2.0 helper. They are not
  part of this matrix; the MUI paths are covered by `tests/m1-runtime`,
  `tests/m6-interactions` and `mui-hello`.
- The 64-bit file claim of M11 is limited, as M11-A4 allows, to the API and its
  fallback behaviour: the qualification profile could not provision a volume on
  which a write above 2 GiB can be tested. The ABI-v11 `Limit` refusal is tested.
- The ABI-v1 image has a sporadic guest page fault during boot, about once in
  forty boots, before any program of ours starts. None occurred in the 75 boots
  of this record. It is reported to the AROS-NX project as issue 122; the
  harness repeats such a boot and records the attempts.
- Physical hardware, other CPUs and emulators other than the recorded one remain
  outside the claim, as in 0.1.0.

## Documentation

The guides, the generated API reference, the ABI differences, the compatibility
page and the release pages describe the candidate. `cargo xtask check mui` and
`aros-api-gen check` pass on the exact source. All Rust examples of the guides
and of the source documentation compile for both targets with the candidate
toolchain, and all eight build messages documented in the troubleshooting page
were reproduced with it. Every published crate denies `missing_docs` and has a
guide page, enforced in CI.

## Signing and the release set

The protected signing workflow prepared Sigstore bundles for all 23 release
subjects using the workflow identity
`https://github.com/metaneutrons/ami-rust/.github/workflows/toolchain-release.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`. Local offline
verification passed for all 46 `SHA256SUMS` rows and all 23 subject and bundle
pairs, and a one-byte change to a signed file was refused. No Git tag, GitHub
Release, rustup catalog publication or registry upload was created.

## Acceptance

- M10-A1: PASS. The exact three-host, dual-target candidate was admitted.
- M10-A2: PASS. The qualification fixture of every crate and the example
  applications ran natively on both pinned baselines, with the source, toolchain,
  image, binary and evidence identities recorded above.
- M10-A3: PASS. The documentation matches the candidate; the generator checks
  pass, every example compiles, and the documentation rules are enforced.
- M10-A4: PRESERVED. Publication still requires a separate explicit maintainer
  command: the tag, the GitHub Release, the rustup catalog and the registry
  upload.
