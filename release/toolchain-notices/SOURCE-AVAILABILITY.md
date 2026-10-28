# Source availability

Download the source and dependency archives from the same
[GitHub release](https://github.com/metaneutrons/ami-rust/releases) as this SDK.
The signed `toolchain-release.json` identifies their exact names, hashes and
source revisions. Archive names are `ami-rust-<SDK version>-sources.tar.xz` and
`ami-rust-<SDK version>-vendor.tar.xz`. The SDK version is also its final prefix
component, `libexec/ami-rust/<SDK version>`.

The source archive contains the ami-rust repository, the original C-SDK
corresponding-source archive (including the collector source), the maintained
patches and build recipes, Cargo notices and complete source for its selected
MPL packages, Rust library sources, and the pinned LLVM 11 source archives and
AROS patches. The dependency archive keeps the current native workspace and
historical SDK vendor inputs separately identified.

The Rust library source archive is not the full Rust compiler source. Native
LLVM 11 sources are distinct from the LLVM bundled with Rust. Full upstream
Rust compiler and Cargo source identities are recorded separately in the
release's source metadata; this archive does not claim a complete offline
rebuild of those upstream tools.

Original component notices and licence terms remain applicable. See the Rust
notices under `share/doc/rust` and the additional source and licence material
under `share/doc/ami-rust`. The collector and C-SDK retain their own licences;
ami-rust's MIT OR Apache-2.0 licence does not replace them.
