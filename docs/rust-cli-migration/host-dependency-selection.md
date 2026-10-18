# RC0-A2 host dependency selection

Status: selected dependency/source/license candidate for the shared Rust host core, with native Linux/macOS API qualification completed. This is not a production lock or release acceptance. The standalone probe is `tools/host-contract-deps/`; its reviewed input records are in [evidence/host-dependencies-a2](evidence/host-dependencies-a2).

## Proposed direct pins

| Crate | Exact declaration | Selected features | Purpose and constraint |
| --- | --- | --- | --- |
| `serde` | `=1.0.228` | `derive` | Typed structures after a duplicate-rejecting `MapAccess` visitor. |
| `serde_json` | `=1.0.145` | default `std` | JSON parser and value representation; the visitor catches duplicate keys before conversion to `Value`. |
| `sha2` | `=0.11.1` | default features | SHA-256 receipts and the `lzma-rust2` XZ checksum path. |
| `tar` | `=0.4.46`, `default-features = false` | none | TAR metadata reader and builder for fixtures. Disabling defaults excludes [`xattr`](https://docs.rs/crate/tar/0.4.46/features), which otherwise is enabled by `tar`'s default feature. The inventory contract does not preserve arbitrary host extended attributes; production extraction will set accepted modes explicitly. |
| `flate2` | `=1.1.10`, `default-features = false` | `rust_backend` | Gzip/DEFLATE via the Rust `miniz_oxide` backend, without a system zlib requirement. |
| `lzma-rust2` | `=0.22.0`, `default-features = false` | `std`, `xz` | XZ reader with a per-block memory-limit constructor; the chosen feature graph excludes encoder, LZIP and optimization features. |

The candidate uses no CLI framework. For the current narrow, compatibility-driven command surface, implement parsing with `std::env::args_os` and table-driven contract tests; this avoids adding a CLI dependency before help, error, and exit behavior are frozen. Reconsider `clap` only if generated command trees, shell completion, or richer diagnostics become a requirement, and then review its full graph separately.

The exact crate archives and Cargo package metadata were available locally and their lock checksums were verified. The six packages declare Rust versions from 1.56 through 1.88; the probe itself sets `rust-version = "1.98.1"`. The original local review executed macOS `aarch64-apple-darwin` under Rust/Cargo 1.98.1. The subsequent hosted run 39172161086 passes the exact corrected thirteen-test candidate on both supported hosts ([source/lock/log identities](evidence/cargo-native-query-review/host-fixture-results.json)). The official release pages document the selected [Serde](https://docs.rs/crate/serde/1.0.228), [serde_json](https://docs.rs/crate/serde_json/1.0.145), [sha2](https://docs.rs/crate/sha2/0.11.1), [tar](https://docs.rs/crate/tar/0.4.46), [flate2](https://docs.rs/crate/flate2/1.1.10), and [lzma-rust2](https://docs.rs/crate/lzma-rust2/0.22.0) versions. The `tar` release marks `xattr` as a default feature; the [XZ reader API](https://docs.rs/lzma-rust2/0.22.0/lzma_rust2/struct.XzReader.html#method.new_mem_limit) documents its memory limit in KiB and checks the block's estimated decoder memory before dictionary allocation. `lzma-rust2` 0.23.0 appeared on the registry one day before this A2 freeze ([release list](https://docs.rs/crate/lzma-rust2/0.22.0)); it is not selected because 0.22.0 is the exact reviewed and fixture-tested candidate, not because 0.23.0 is presumed unsuitable.

## A1 to A2 lock identity

A1 remains unchanged. A2 changes only the `tar` default-feature setting; every common crate keeps the same version and registry checksum.

| Evidence | Manifest SHA-256 | Lock SHA-256 | Registry crates | Audit packages including probe root |
| --- | --- | --- | ---: | ---: |
| A1, 2026-10-18 | `e055386040661f67ff3eeaa6280c5c3c07028a4e0bc9a91a75e8c46156123375` | `894986b04175a30e555177df4028db4520c6240c4d60bc0bd01dda99c46211d7` | 36 | 37 |
| A2, 2026-10-19 | `0bcae12a8f2955b83833bc23a4d5b14bab2195af52aa9f79f8e841ed54221aea` | `cc3ac7771a692dc1c2b154ad6962285209b4d7b1eeb5c918d98ece8ac7aeee66` | 29 | 30 |

A2 removes exactly `bitflags 2.13.2`, `errno 0.3.14`, `linux-raw-sys 0.12.1`, `rustix 1.1.5`, `windows-link 0.2.1`, `windows-sys 0.61.2`, and `xattr 1.6.1`. It adds no packages and upgrades no common package. Cargo metadata resolves `tar` with no features and only `filetime` and `libc` dependencies. All 29 A2 crate archives match their lockfile checksums; the 29 common A1/A2 identities and checksums are equal.

`cargo audit 0.22.2` reported zero vulnerabilities for A2 against the local advisory database at commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b` (`2026-10-17T17:23:59+02:00`). The scan used `--no-fetch`; its raw JSON leaves database commit fields null, so `audit.json` records the commit and timestamp verified from the exact local Git checkout and labels that provenance. `cargo-audit-raw.json` preserves the unmodified tool output. A fresh production lock must receive its own audit because integrating this probe into another package changes lock identity and may change the graph.

## Build-time process and license review

All seven build scripts in A2 were read at their process call sites and hashed in `source-review.json`. A1 had an eighth script in `rustix`; it also probes `rustc`, but `rustix` and that script are absent from A2.

| A2 package | Source anchor | Observed build-time behavior |
| --- | --- | --- |
| `crc32fast 1.5.2` | `build.rs:22-34` | Runs `RUSTC --version` and emits compiler-gated cfg flags. |
| `libc 0.2.191` | `build.rs:165-226,389-414,557-600` | Runs the compiler (or configured `RUSTC_WRAPPER`) for version detection. `freebsd-version` is called only for FreeBSD when `LIBC_CI` is set; `emcc -dumpversion` only for Emscripten targets. |
| `proc-macro2 1.0.107` | `build.rs:165-205,248-257` | Runs `RUSTC --version` and compiles feature probes through configured `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER`. |
| `quote 1.0.47` | `build.rs:5-31` | Runs `RUSTC --version` to select cfg values. |
| `serde 1.0.228` | `build.rs:19-27,60-69` | Writes a generated private module under `OUT_DIR` and runs `RUSTC --version`. |
| `serde_core 1.0.228` | `build.rs:104-113` | Runs `RUSTC --version` to select cfg values. |
| `serde_json 1.0.145` | `build.rs:3-28` | Reads target architecture and pointer-width variables and emits cfg values; it creates no child process. |

The selected build scripts do not invoke Python. A source scan found no direct process API use under the selected crates' runtime `src/**/*.rs` trees. This is source review, not process-tree evidence: `RUSTC`, `RUSTC_WRAPPER`, and `RUSTC_WORKSPACE_WRAPPER` are executable inputs, and wrappers can start arbitrary children. The `libc` FreeBSD and Emscripten branches also require their named tools when their target conditions apply. The RC0-A4 no-Python gate must observe the process tree on each supported host with the compiler path and wrapper policy fixed; this document does not claim that gate passed.

Local A2 source archives contain 61 inventoried license files across 29 registry packages. Every recorded size and SHA-256 was checked against the corresponding local crate source. Direct-package license expressions in package metadata are `MIT OR Apache-2.0` for `serde`, `serde_json`, `sha2`, `tar`, and `flate2`, and `Apache-2.0` for `lzma-rust2`. The subsequent independent review checked all 29 metadata expressions and all 61 license files against their actual source bytes. The [selection decision](evidence/host-dependencies-a2/selection-review.json) approves these dependency/source/license choices for development, with MIT selected where available, Apache-2.0 for `lzma-rust2` and `ryu`, and MIT plus Unicode-3.0 for `unicode-ident`. Preserve the applicable full texts and upstream notices in the new distribution. The earlier in-progress record is retained without rewriting it; this review is not release acceptance.

## Bounded API fixtures

`tools/host-contract-deps/src/lib.rs` is a library fixture only. It does not implement an installer, CLI, filesystem extraction, or production policy.

- The recursive Serde visitor rejects duplicate keys at top level and nested objects before constructing a `serde_json::Value`; it also rejects trailing data, invalid UTF-8, malformed JSON, `NaN`, and `Infinity`.
- SHA-256 is checked against the standard `abc` test vector.
- `XzReader::new_mem_limit` decodes a valid 4 KiB-dictionary stream at a 1 MiB limit, rejects a 64 MiB dictionary under that limit, enforces the decoded-output cap, and rejects a flipped XZ CRC. The fixture passes `allow_multiple_streams = false`; concatenated-stream policy is not qualified.
- The `flate2` fixture accepts a 64 KiB gzip payload at the exact output cap and rejects it at 128 bytes. Concatenated gzip members and trailing compressed bytes remain unqualified.
- TAR metadata checks accept an ordinary relative path and contained relative symlink. They reject absolute and parent-traversal paths, duplicate paths, an escaping symlink, hard links, FIFO entries, member-count excess, per-member size excess, and aggregate expanded-size excess. No entry is extracted.

Verification on Darwin 25.5.0 arm64 with Rust 1.98.1 and Cargo 1.98.1:

```text
CARGO_TARGET_DIR=/tmp/ami-rust-host-contract-probe-target cargo +1.98.1 test --manifest-path tools/host-contract-deps/Cargo.toml --locked --offline
9 passed; 0 failed
cargo +1.98.1 fmt --manifest-path tools/host-contract-deps/Cargo.toml -- --check
passed
```

## Remaining host qualification and production integration work

1. Build and run the host fixture on the two supported release hosts, Linux x86-64 and macOS arm64. Windows is outside scope. Both supported hosts now pass the thirteen-test API candidate in run 39172161086; the remaining items below concern actual production integration.
2. Run the no-Python process observer with a pinned `RUSTC`, a sanitized `PATH`, and wrappers unset or explicitly allowlisted. Repeat for any target that activates platform tool branches.
3. Freeze compression details: XZ concatenation and complete-input behavior; gzip concatenated-member/trailing-byte behavior; compressed-input, decoded-output, and decoder-memory limits for both formats.
4. Extend archive compatibility fixtures before extraction: PAX and GNU long-name records, normalization/case collisions, symlink chains and aliases, ownership and mode policy, and extraction in a directory resistant to concurrent path substitution. [`tar`'s unpacking documentation](https://docs.rs/tar/0.4.46/tar/) describes its path checks as best effort; the probe currently only validates metadata and does not address filesystem races.
5. Implement the frozen `metadata_limits` in contracts-v1.json and exercise the full schema and migration/version policy in RC1. The probe checks duplicate handling but is not a schema validator.
6. Carry the reviewed source/license choices and notices into the actual host-core inventory, and bind the advisory scan to its final lock identity. Review any graph/feature changes rather than silently treating a different lock as covered.

The A2 candidate is ready for parent review as an input to RC0 contract work. No root manifest, lockfile, production executable, or extraction path was changed here.

## Independent API review corrections

Review found two defects in the metadata-only prototype, separate from crate
selection: raw TAR header size can differ from the PAX-resolved entry size, and
PAX/GNU extension records may be buffered by the library before member checks.
The corrected candidate uses effective-size accounting and a fail-on-overflow decoded
input reader before Archive construction, with adversarial fixtures. Independent review confirmed both repairs; all 13 tests, formatting and Clippy with warnings denied passed locally under pinned Rust 1.98.1 ([corrected source/result identities](evidence/host-dependencies-a2/corrected-api-results.json)). These
repairs do not qualify extraction, symlink-chain handling or filesystem races;
those remain production RC1 tests. Frozen A2 evidence retains the original
nine-test result; the new native CI candidate records the corrected source.
