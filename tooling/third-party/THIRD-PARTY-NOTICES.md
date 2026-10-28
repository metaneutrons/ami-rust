# Third-party notices

This directory contains the exact license-file inputs reviewed for the A2 native host dependency set. It maps 29 locked registry crates and their archive checksums to all 61 reviewed upstream license-file identities. Identical byte strings are deduplicated into 31 content-addressed files under `licenses/`; no license text was edited or normalized.

The canonical mapping is [`inventory.json`](inventory.json). Its `source_sha256` and `source_bytes` fields identify each reviewed upstream file, `source_name` preserves the upstream filename, `attribution_lines` records copyright/attribution lines from the exact file, and `copied_text_path` identifies its exact byte copy. Package author metadata and archive checksums are recorded per crate.

The A2 selection decision is development input review only; it does not establish release acceptance. The selected permission is reproduced from [`selection-review.json`](reviews/selection-review.json), while every reviewed file listed by [`dependency-review.json`](reviews/dependency-review.json) is preserved, including alternatives not selected for the crate.

## Locked crate set

| Crate | Version | Declared license | Selected permission | Upstream authors | Reviewed upstream license filenames |
| --- | --- | --- | --- | --- | --- |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | MIT | Jonas Schievink <jonasschievink@gmail.com>, oyvindln <oyvindln@users.noreply.github.com> | LICENSE-0BSD, LICENSE-APACHE, LICENSE-MIT |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | MIT | Alex Crichton <alex@alexcrichton.com> | LICENSE-APACHE, LICENSE-MIT |
| const-oid | 0.10.2 | Apache-2.0 OR MIT | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| crc32fast | 1.5.2 | MIT OR Apache-2.0 | MIT | Sam Rijs <srijs@airpost.net>, Alex Crichton <alex@alexcrichton.com> | LICENSE-APACHE, LICENSE-MIT |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| digest | 0.11.3 | MIT OR Apache-2.0 | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| filetime | 0.2.29 | MIT/Apache-2.0 | MIT | Alex Crichton <alex@alexcrichton.com> | LICENSE-APACHE, LICENSE-MIT |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | MIT | Alex Crichton <alex@alexcrichton.com>, Josh Triplett <josh@joshtriplett.org> | LICENSE-APACHE, LICENSE-MIT |
| hybrid-array | 0.4.15 | MIT OR Apache-2.0 | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| itoa | 1.0.18 | MIT OR Apache-2.0 | MIT | David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| libc | 0.2.191 | MIT OR Apache-2.0 | MIT | (none in Cargo.toml) | LICENSE-APACHE, LICENSE-MIT |
| lzma-rust2 | 0.22.0 | Apache-2.0 | Apache-2.0 | (none in Cargo.toml) | LICENSE |
| memchr | 2.8.3 | Unlicense OR MIT | MIT | Andrew Gallant <jamslam@gmail.com>, bluss | COPYING, LICENSE-MIT |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 | MIT | Frommi <daniil.liferenko@gmail.com>, oyvindln <oyvindln@users.noreply.github.com>, Rich Geldreich richgel99@gmail.com | LICENSE, LICENSE-APACHE.md, LICENSE-MIT.md, LICENSE-ZLIB.md |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | MIT | David Tolnay <dtolnay@gmail.com>, Alex Crichton <alex@alexcrichton.com> | LICENSE-APACHE, LICENSE-MIT |
| quote | 1.0.47 | MIT OR Apache-2.0 | MIT | David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 | Apache-2.0 | David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-BOOST |
| serde | 1.0.228 | MIT OR Apache-2.0 | MIT | Erick Tryzelaar <erick.tryzelaar@gmail.com>, David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| serde_core | 1.0.228 | MIT OR Apache-2.0 | MIT | Erick Tryzelaar <erick.tryzelaar@gmail.com>, David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 | MIT | Erick Tryzelaar <erick.tryzelaar@gmail.com>, David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| serde_json | 1.0.145 | MIT OR Apache-2.0 | MIT | Erick Tryzelaar <erick.tryzelaar@gmail.com>, David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| sha2 | 0.11.1 | MIT OR Apache-2.0 | MIT | RustCrypto Developers | LICENSE-APACHE, LICENSE-MIT |
| simd-adler32 | 0.3.10 | MIT | MIT | Marvin Countryman <me@maar.vin> | LICENSE.md |
| syn | 2.0.119 | MIT OR Apache-2.0 | MIT | David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT |
| tar | 0.4.46 | MIT OR Apache-2.0 | MIT | Alex Crichton <alex@alexcrichton.com> | LICENSE-APACHE, LICENSE-MIT |
| typenum | 1.20.1 | MIT OR Apache-2.0 | MIT | (none in Cargo.toml) | LICENSE, LICENSE-APACHE, LICENSE-MIT |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 | MIT AND Unicode-3.0 | David Tolnay <dtolnay@gmail.com> | LICENSE-APACHE, LICENSE-MIT, LICENSE-UNICODE |

The A2-reviewed candidate lock is [`tools/host-contract-deps/Cargo.lock`](../../tools/host-contract-deps/Cargo.lock), SHA-256 `cc3ac7771a692dc1c2b154ad6962285209b4d7b1eeb5c918d98ece8ac7aeee66`. The native producer uses [`tooling/Cargo.lock`](../Cargo.lock), SHA-256 `b825f28b7530920b0b8b9d359abad658bc52453ab6ae631b75651162928c7322`; its 29 registry crate names, versions, sources, and checksums match the reviewed candidate lock. The inventory binds every local `.crate` archive SHA-256 to that lock checksum.

## Separate pinned Rust toolchain notice scope

The host Rust 1.98.1 installation is a build input, not part of the 29-crate A2 license inventory. Its generated `share/doc/rust/COPYRIGHT-library.html` is included as an exact supplemental byte copy at [`licenses/rust-1.98.1-COPYRIGHT-library.html`](licenses/rust-1.98.1-COPYRIGHT-library.html): 1512520 bytes (SHA-256 `68129500b616d5838629e68f55ff3aed5e096dacf60ce9eb41bbe599a563afa6`), listing 142 out-of-tree crate records for the Rust standard library. This full upstream standard-library notice document is supplemental and separate from the 31 unique reviewed crate license texts. `COPYRIGHT.html` is 15380909 bytes (SHA-256 `5b0c93fc4e6d4b072eaa521b1762d1e746f4c368f65e81a0e5308e2772dac85e`) and lists 1570 toolchain records, 142 marked as present in libstd.

Those generated documents cover a broader toolchain and target set than either native application binary. Five exact crate identities overlap the reviewed standard-library document: `itoa-1.0.18`, `ryu-1.0.23`, `serde-1.0.228`, `serde_core-1.0.228`, `serde_derive-1.0.228`. The documents also record Rust standard-library in-tree notices such as Unicode-3.0 and a target-specific Fuchsia BSD-2-Clause source. Twelve of the standard-library crate records have no named notice-file block in the generated HTML. Including the full upstream document is conservative notice coverage, but it does not determine the actual linked standard-library notice set for the Linux and macOS binaries; target/link-map review and a separate notice decision remain open. No compiler/toolchain notice closure or release-acceptance claim is made here.
