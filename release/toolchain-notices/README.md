# Supplemental toolchain notice inputs

This common data payload supplies original notice and selected corresponding-source
bytes for the separately identified documented SDK view. It is not an executable
component, a legal clearance record or a release signature.

`notice-input.json` uses the closed `ami-rust-toolchain-notice-input-v1` schema.
Its fifteen materials bind complete original files by byte length and SHA-256.
Each of its 2,698 file rows names the prepared destination below
`share/doc/ami-rust/`, its exact content/mode, and its original material role and
archive member. `source_member` is provenance; it is not a path in the prepared
notice tree. The same member name may occur in different source materials.

`source-map.json` records the existing repository source capsules, immutable Git
origins and locked LLVM release URLs. The original collector source is included
in the existing C-SDK corresponding-source capsule. Historical third-party
notices retain their explicitly limited C-SDK scope. Neither source availability
nor this selected inventory establishes complete binary linkage or licence
sufficiency for all redistributed host components.

The internal `toolchain_notice_inputs.rebuild_notice_inputs` API verifies every
material's complete bytes through the same file descriptor before selecting tar
members or raw files. It recreates only the selected regular files with mode
0644, refusing missing, duplicated, altered, linked or colliding inputs. The
caller authenticates the manifest and original provenance. It introduces no
consumer command or SDK manager.

`toolchain-notices-v1.tar.xz` contains the same 2,698 selected files
(20,275,809 regular bytes), under `ami-rust-toolchain-notices-v1/`.
`data-archive.json` binds the original archive, inventory, generator source,
packager implementation and deterministic epoch. Full reconstruction from all
fifteen materials and full archive/member readback passed in local development;
the source-bound evidence report records the actual checks and their limits.

The additive `SOURCE-AVAILABILITY.md` guide names the corresponding source and
vendor archives on the same authenticated release. Its addition preserves all
2,697 previous file rows and fourteen previous material rows unchanged. The
separate extension record covers this new inventory; earlier SDK-view proofs
retain their original inventories.

The additive view operation preserves every existing SDK file byte and mode;
it adds these files outside the exact LLVM, C-SDK and AROS target trees. Its own
receipt and host-v4 sidecar identify the derived view without editing the
original compose-v4 receipt or host-v3 sidecar. All final distribution formats
must package that same complete derived inventory. Protected provenance,
licence review and actual public client qualification remain release gates.

## Native build dependency source

The documentation payload includes the unchanged native Cargo vendor archive at `share/doc/ami-rust/sources/native-cargo-vendor.tar.xz` and its package index at `share/doc/ami-rust/native-build-dependencies.json`. They preserve the native application/tooling lock source closure and the Cargo-declared licence fields verbatim. Presence in this source closure does not prove inclusion in a distributed executable, and the index is not a legal clearance determination.

## Native build dependency source capsule

`release/inputs/native-cargo-vendor.tar.xz` is retained unchanged as an inert source and licence reference. `release/inputs/native-build-dependencies.json` records the 51 package identities, registry checksums, Cargo.toml hashes, and verbatim Cargo-declared licence fields represented by that vendor archive. This is a source-lock closure for the native application/tooling inputs; it does not establish which packages or files are included in any distributed binary. The recorded licence declarations are not a legal clearance determination.
