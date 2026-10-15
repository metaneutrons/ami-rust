# Copyright, provenance and redistribution boundary

Original ami-rust code and documentation: Copyright (c) 2026 Fabian Schmieder,
licensed at your option under MIT OR Apache-2.0. See LICENSE-MIT,
LICENSE-APACHE and LICENSE.md. Third-party material keeps its original terms;
workspace metadata does not relicense it.

The unpublished installation candidate includes the source SDK and the exact
R3-qualified native SHA-256 utility (928144 bytes, SHA-256
`b9521e15361e26b22db49c1e8953a1d29940313a5214507d023c2d953ad4acd4`).
The utility statically incorporates Rust core/alloc/compiler-builtins and code
from AROS native startup and selected C SDK library members. It does not contain
only first-party Rust code. The exact native composition and legal review are
recorded separately; a local test signature is not release authorization.

The locked reference target Rust crates are sha2, digest, block-buffer,
crypto-common, generic-array, typenum, cfg-if and cpufeatures. Their pinned
manifest declarations and original license texts are recorded in
`licence-review.json`, `sbom.spdx.json` and `licences/` in the candidate. Other
locked crates support the SDK's dependency/qualification recipes or host build
steps; presence in Cargo.lock is not evidence that their code is in SHAUTIL.
Full Rust library attribution, including Unicode terms, and compiler-builtins
notices are preserved. No license text is stripped on an assumption that an
unresolved source subtree is unused.

The retained link map identifies 23 members from libamiga, libautoinit, libexec,
liblibinit and libstdc, plus the transformed stock startup object. AROS headers,
vector contracts, native startup and libraries originate with the AROS
Development Team and original contributors. The six ABI header translations in
aros-sys preserve their recorded upstream origin. The pinned tree uses AROS Public License 1.1 under its detached-license
clause 5.2, subject to the preserved file-level LEGAL exceptions. The source
version of AROS Covered Code and our covered modifications is available under
that license on the same media in `aros-corresponding-sources.tar.xz` and
`sdk.tar.xz`. Extract both with standard tar/xz tools. The capsule preserves
the linked C/startup sources, interface headers, generated stubs and associated
generator/configuration/build inputs; `MODIFICATIONS.md` records the original
AROS Development Team origin, dates, ABI translations, startup symbol rename
and comment-only source-path substitutions. The full APL and applicable LEGAL
texts accompany the files. This notice does not relicense third-party code.
The separately provisioned C SDK supplies its pinned external build tools.
Historical generator execution logs were not retained; no new C reproducibility
claim is made. All runtime/reproducibility claims require the qualified hashes.

The SDK source also includes source-only patches to Cargo commit
`3efb1f477e99b42974b982d939fd100303cdf7db` and openssl-src
`300.6.1+3.6.3`. The candidate preserves the corresponding original MIT/Apache
texts and Cargo third-party notices. These host-tool patches are distinct from
the target utility dependency graph; no upstream ownership is replaced.

Rust/compiler, custom Cargo, native C toolchain, collector, complete AROS C SDK
and the vendor tree are separately provisioned prerequisites. They are
inventoried by the SDK host profiles, not bundled or relicensed by the installer.
The current candidate is qualification-only, unpublished, and signed locally
only for offline test trust. Such a test signature does not establish the real
ami-rust publisher or protected build provenance.

The M0 experimental sources and instrument recipes remain reference evidence at
ami-rust-feasibility commit 54eaa17. Qualification-only measurement code is not
the default product allocator; private TLSF probes never belong in product
allocation. The complete legal evidence and remaining findings are retained in
the repository's `release/preparation/licence-inventory.json` and
`release/preparation/licence-findings.md`.
