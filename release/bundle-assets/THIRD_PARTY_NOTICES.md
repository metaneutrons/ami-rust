# Copyright, notices and corresponding source

Original ami-rust code and documentation: Copyright (c) 2026 Fabian Schmieder,
licensed at your option under MIT OR Apache-2.0. See LICENSE-MIT,
LICENSE-APACHE and LICENSE.md. Third-party material retains its original terms;
workspace metadata does not relicense it.

## Native reference and Rust target libraries

SHAUTIL statically incorporates Rust core/alloc/compiler-builtins and selected
AROS native startup and C library members. The retained R3 native reference is
928,144 bytes, SHA-256
`b9521e15361e26b22db49c1e8953a1d29940313a5214507d023c2d953ad4acd4`.
Qualification must compare the actual delivered native bytes with that reference.
The selected target crates include sha2, digest, block-buffer, crypto-common,
generic-array, typenum, cfg-if and cpufeatures. Original manifest declarations
and notices are in `licence-review.json`, `sbom.spdx.json` and `licences/`.
Other locked crates support SDK qualification recipes or host builds; a lockfile
entry alone does not establish inclusion in SHAUTIL. Rust library attribution,
Unicode terms and compiler-builtins notices remain preserved.

The retained native link map identifies 23 members from libamiga, libautoinit,
libexec, liblibinit and libstdc, plus the transformed stock startup object.
AROS headers, vector contracts, startup and libraries originate with the AROS
Development Team (Initial Developer) and original contributors. Our AROS-covered
modifications are derived from their Original Code. Applicable AROS Public
License 1.1 and per-file LEGAL exceptions remain in force.

The source version of that AROS Covered Code and covered modifications is
available under APL 1.1 on the same media in `aros-corresponding-sources.tar.xz`
and `sdk.tar.xz`. Extract both using standard tar/XZ tools. They preserve the
linked C/startup sources, interface headers, generated stubs, associated build
inputs, full APL and applicable LEGAL texts. Their `MODIFICATIONS.md` records
the original lineage, dates, ABI translations, startup symbol rename and
source-path comment changes. The historical `licence-review.json` covers that
selected runtime scope; it is not a claim to review every host-tool dependency.

## Complete C-SDK prerequisites

The complete C-SDK is a separately provisioned build prerequisite. The immutable
original archive has SHA-256
`70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87`;
the separately identified portable archive has SHA-256
`942417c7b82218f5704eba168922fc348dc0ce5c17a236139c3353775209b99b`.
The APL-covered source for both archives is available under APL 1.1 from
<https://github.com/metaneutrons/ami-rust>, at the source commit recorded by
`sdk/contract/sdk.json` after installation (or `contract/sdk.json` inside
`sdk.tar.xz`). At that exact commit obtain:

- `release/csdk-source/csdk-corresponding-source.tar.xz`, SHA-256
  `7e62e28fb025e31aacdd3b6a6d14cef7d76703eb59dbaca02f2e2b4de68c6914`;
- its complete `release/csdk-source/manifest.json` inventory;
- all four patches and `series.json` in `release/patches/portable-csdk/`;
- `release/portable-csdk/CHANGES.md`, `SOURCE-AVAILABILITY.md` and `APL-1.1.txt`.

The source capsule contains the full pinned AROS and aros-tools regular source
trees, all 18 original vendor archives, generated inputs and frozen recipes.
The dated changes identify the AROS Development Team lineage and source/build
patches for relative header provenance, compiler diagnostic prefix mapping and
relocatable libaom pkg-config metadata. The complete 2,835-file set is preserved;
no finished binary or compiler metadata is rewritten to remove paths.
All original APL, LGPL and vendor terms remain available with their sources.
The distributor remains responsible for APL section 3.2 source availability;
repository policy retains source for at least 12 months after the latest
distribution of each covered version, including if a hosting provider changes.

The FreeType components of the separately provided C-SDK are based in part on
the work of the FreeType Team. Portions are copyright © 1996–2026 The FreeType
Project (<https://freetype.org>); all rights reserved. The applicable FreeType
Project License (FTL) and original file-specific notices are preserved in the
corresponding-source capsule, including
`evidence/licence-texts/texts/vendors/by-sha256/5a5ee54c5001bbad1cdc1a57cc3dd4c42199b2da09d39c7ee41fab002d02967f.txt`.
The FTL alternative covers the original FreeType engine and demo-package files
without separate explicit terms; embedded BDF, PCF and zlib notices retain their
own scope. AROS port additions retain their applicable source-tree terms.

## Host Cargo and other prerequisites

The custom host Cargo component is a separately identified archive within the
candidate bundle, not target AROS code. It derives from Cargo commit
`3efb1f477e99b42974b982d939fd100303cdf7db` with versioned source patches;
Cargo's MIT OR Apache-2.0 terms and original third-party notices are preserved.
The OpenSSL source overlay is based on openssl-src `300.6.1+3.6.3`.

`cargo-notices-corresponding-source.tar.xz` contains notice records for all 523
locked host registry packages, complete source for the three selected MPL
packages, recovered original licence texts, and the complete lock-matched
libgit2-sys source including its libgit2 notices and linking-exception terms.
Its SHA-256 is
`a86b2e26191c7d59ed123d401de589850c5a7880de6bc09d81c6ab92c26ae6d1`.
Extract it using standard tar/XZ tools. Package declarations, source inventory
and per-component SBOM records retain their respective scopes. Actual packaged
Cargo linkage is captured separately for final distribution review on each host;
a declaration or lock entry does not itself establish static binary inclusion.

Rust/compiler, native C toolchain, collector, complete C-SDK and vendor inputs
retain their independently pinned producer/component identities. They are
verified as prerequisites rather than relicensed by the ami-rust installer.
System libraries used by the macOS or Linux host remain system prerequisites;
no Apple SDK files are distributed in this bundle.

This notice documents attribution, licences and source availability. Release
qualification and authentic publisher provenance require their own verified
records; fixture keys and signatures do not identify a release publisher.
