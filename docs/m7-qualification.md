# M7 qualification: ami-rust 0.1.0

Status: PASS for release-candidate preparation. Publication remains a separate
maintainer decision and is not authorised by this record.

## Exact candidate

| Identity | Value |
| --- | --- |
| Version | 0.1.0 |
| Source commit | `95795520653aca959bb17b3b73cf025261d049a7` |
| Source tree | `cf433e66861367b2e17b30c88d2fb38a74c6350a` |
| Source epoch | `1793095486` |
| Qualification workflow | [run 40986442000, attempt 1](https://github.com/metaneutrons/ami-rust/actions/runs/40986442000) |
| Candidate artifact SHA-256 | `324a191234dbebb43e88c1c6db56cd842c62b05c944b9581ea8607c8f43b4c68` |
| Production contract SHA-256 | `d0ed3dff9f8c7c5efbf93cf5958b347b2dfc16904b4e5e845a272ed3085bfc35` |
| Targets | `x86_64-unknown-aros-abi1`, `x86_64-unknown-aros-abi11` |
| Catalog workflow | [run 40991385208](https://github.com/metaneutrons/ami-rust/actions/runs/40991385208) |
| Catalog artifact SHA-256 | `fa1b30d8bb29496bf855d01fe57463e03e186113804a6ef7efcd22f5996b970b` |
| Catalog commit | `bb5cc2e428b89685eeec2ae249701cc23fd135d7` |
| Signed-candidate workflow | [run 40994382906](https://github.com/metaneutrons/ami-rust/actions/runs/40994382906) |
| Signed artifact SHA-256 | `211e92b2a999426312fb904403c346c8698184f5296bde794e610389506fbb4e` |

The protected workflow produced the candidate independently on macOS ARM64,
Linux x86-64 and Linux ARM64. Every producer, candidate-assembly, unmodified
rustup installation, dual-target Cargo build and final admission job passed.
The admission policy retains the exact application identity for each host and
target; it does not erase legitimate host metadata differences.

## Host archives

| Host | Archive SHA-256 | Inventory SHA-256 |
| --- | --- | --- |
| macOS ARM64 | `a5486766fe9426e953d738c236a4bf6db9df300f4dbd86972f68435c5cf31c98` | `f6ed44ec4e2874880cf905c4da31ca2b9dfca5b9a777a48e8f0f783653c922f6` |
| Linux x86-64 | `64eea21eec96a527fb8a5c1c56933317db1c0dab3a376b77042a2cbe936644a5` | `67be7919b49ab1ddf607ac3f4f32abe609c1cc34b81f04e77cb91c5f528a7772` |
| Linux ARM64 | `981d92664525d941229d16f550f5478eaf8156f3b195a40b37b4301f7cd4afc7` | `af346a3cb9c4352fd5b8c993cd8307bbe2978c947502954b46e1ab6284fc2a1c` |

The installed compiler reports Rust `1.100.0-nightly` at commit
`330d317121e16b5db8e5adc63595910528ff2ee7` with LLVM 23.1.1. The paired
Cargo reports `1.100.0-nightly` at commit
`495c385d0875c4ba51eb72ea0448a2d4c018b8d4`.

## Native AROS execution

Both reference binaries were built from the exact source with the final macOS
ARM64 candidate archive and executed under QEMU 11.1.3 with
`pc-i440fx-11.1`, `qemu64-v1`, TCG single-threaded, one vCPU, 512 MiB RAM,
no network, and pinned firmware. The QEMU binary SHA-256 is
`0dba441e49c3cda068f3b33916ad9d2146d173d9bb65a6a62ce2e61d3211baaf`;
the BIOS and VGA BIOS SHA-256 values are
`ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650`
and `e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472`.

| Evidence | ABI1 | ABI11 |
| --- | --- | --- |
| Baseline ISO SHA-256 | `d981ef90144d0489c7520674def22f564cc4a79637d2ce7f42be1319d6a228a4` | `99c332be5a358799122c87d3e624d2d6e9576a721d28514a01c8b3f289d3dda4` |
| Reference binary SHA-256 | `d9ff0c4dda9f0e63fb530b3c3937681679194cadc865c6d5c198098983568126` | `a30620f7a23a546c0a97def4bd6a82d5fa629221ffbf3c5cf109505eb01a80fd` |
| Qualification ISO SHA-256 | `597fbda52ba38fe0e35e3fe483e05215e024ec9c2e7a5887b97511836475ea90` | `7734f9bb1858be62c7c79ad15e1b92b10efe542b30e814915acba45f97103b67` |
| Serial capture SHA-256 | `4810267542f06b247af6d591e34abee61a7d1ca3aa1ccd1d18f00d2ac6a1df1a` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Screenshot SHA-256 | `04ee61c23b79d3cd4786b9d788105c1364056ae952be8c30a72a9a035203d01e` | `81ab682de0b8ed73fc075dd54a9119d956a3abd4c7bcb85513844ebded274347` |
| Result | PASS, return 0 | PASS, return 0 |

ABI1 serial evidence records successful file I/O, file-error cleanup,
MUI-error cleanup, custom dispatch, callback, event-loop shutdown, interaction
cleanup and process exit. ABI11 exposes the process result on the guest screen;
the pinned image does not route these messages to the serial device. Both
screens were inspected and show `ami-rust M6 process returned 0`.

## Installation and distribution preparation

The three-host qualification installed `0.1.0-<host-triple>` through an
unmodified rustup client from the exact unpublished catalog, then built the
same locked, offline application for both targets. A separate direct archive
test extracted the macOS archive, registered its SDK prefix with
`rustup toolchain link`, and verified the exact rustc and Cargo identities.

The reviewed catalog delta consists only of:

- `distribution/rustup/0.1.0/dist/channel-rust-0.1.0.toml`;
- `distribution/rustup/0.1.0/dist/channel-rust-0.1.0.toml.sha256`.

The protected signing workflow prepared Sigstore bundles for all 23 release
subjects using the workflow identity
`https://github.com/metaneutrons/ami-rust/.github/workflows/toolchain-release.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`. Local offline
verification passed for all 46 `SHA256SUMS` rows, 47 attestation rows and 23
subject/bundle pairs. No Git tag, GitHub Release or public asset was created.

## Licence and corresponding source

The candidate licence review reports `PASS_FOR_QUALIFICATION_CANDIDATE`, no
blockers, and `release_redistribution_cleared: true`. The prepared closure is:

| Asset | SHA-256 |
| --- | --- |
| Corresponding sources | `554a05b5e2ad42bf348baa993e8f3b60e916877dc785244cba34bc8657adffc8` |
| Notices | `a08192d0447200b29adc88ded9a1c81bde25e8730053a950cea8270b5f10111f` |
| SPDX document | `09e1128f2e8e3524668e62337d0665daeb1fc19e79116aab992fdc88fbc7be58` |
| Source inventory | `6ed1f3e65caaec9d0649fd5e54fcf980c49bbf0bf76fa7d59090b594553d146b` |

The source capsule contains the exact repository tree, pinned Rust library
sources, native toolchain source archives and the applied AROS patches. The
notice capsule contains the first-party, Rust, Cargo, AROS and dependency
terms used by the shipped bytes.

## Acceptance

- M7-A1: PASS — exact three-host, dual-target candidate admitted.
- M7-A2: PASS — exact reference application completed both pinned native
  baselines, including the required positive and failure paths.
- M7-A3: PASS — source, toolchain, SDK, image, binary, evidence, licence and
  corresponding-source identities are recorded.
- M7-A4: PASS — direct and rustup installation are qualified, documentation is
  bound to the exact candidate, and signed assets are prepared but unpublished.
- M7-A5: PRESERVED — publication still requires a separate explicit maintainer
  command; project crates remain Git-delivered and unpublished on crates.io.
