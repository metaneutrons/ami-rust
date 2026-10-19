# RC1 publisher verification

This partial [RC1 delivery](https://github.com/metaneutrons/ami-rust/issues/71)
connects strict policy, metadata and SLSA claim readers to the existing pinned
GitHub and Cosign tools. The [native verify command](native-sdk-v2.md) composes this verifier with
SDK-v2 archive admission. It does not install an SDK, qualify native builds or
accept RC1. The released 0.1.0 inputs remain
unchanged. No cryptographic verification protocol is reimplemented in Rust.

## Admission and trust boundary

The external policy fixes the repository, workflow/ref, exact source/workflow
commits, certificate identity/issuer, permitted producer hosts, inputs-manifest
digest and four external tool/root pins. Policy, tools and trust roots must be
external to the bundle. Descriptor traversal requires root/current-user-owned
ancestors and files without other-user write permission; root-owned sticky
ancestors are allowed. Verifiers require actual executable access and no set-ID
bits. Normalized symlink-free trust paths are a deliberate fail-closed tightening
relative to the historical verifier's resolved aliases. Owners select canonical
paths; neither a bundle nor its metadata can supply its own trusted verifier.

Admission binds raw release bytes, the complete bounded asset inventory,
authentication metadata, one producer run, exact subject/proof maps and the
policy-pinned material list. The producer host need not equal the consumer
host. Every declared regular file and ancestor directory must exist; extra
files/directories, links and special files refuse. Entries are classified
without opening them before regular-file access, then descriptor identities are
checked. Input reads detect ordinary size/metadata changes and enforce bounds
while reading. These source reads do not constitute a concurrent filesystem
snapshot.

All retained input bytes are copied through exclusive descriptor-relative
creation into a private temporary tree: directories mode 0700, files mode 0600.
The external tools receive only these staged subject/proof paths. Consequently,
other-user write access to the original source bundle cannot replace a file
between its validation and a verifier's pathname reopen. Staged and original
trees/bytes and external pins are checked again before success. A process with
the same UID, root or the trusted tool itself can still change private files;
those identities remain trusted. This is not a sandbox against them.

## Six required verifier calls

GitHub verification runs separately for `SHAUTIL`, `release.json` and
`sdk.tar.xz`, in that order, with the frozen offline bundle/custom-root,
repository, exact signer/source commit/ref, hosted-runner, SLSA predicate and
certificate identity/issuer arguments. Each call must exit successfully and
return exactly one verified statement. The Rust layer checks the subject/digest,
workflow, protected GitHub parameters, signed release environment/host claims,
exact source/material dependency set and run/attempt invocation identity.
Dependency order and JSON object-field order do not affect set equality.

Cosign then verifies `release.json`, `sdk.tar.xz` and `SHAUTIL`, separately,
against their bundled signatures and external trusted root, with the fixed
certificate/workflow/source/event constraints. All three must exit successfully.
The signed environment and runner assertions are SLSA claims authenticated under
the pinned workflow; they are not independent certificate fields.

Each process receives an explicit executable, private working directory, null
stdin and replacement environment containing only HOME, GH_CONFIG_DIR, PATH,
LC_ALL, LANG, GH_PROMPT_DISABLED, NO_COLOR and COSIGN_EXPERIMENTAL. No inherited
credentials or user configuration are passed. Temporary-tree cleanup is required
for success; failures preserve both the primary and cleanup error. Panic cleanup
is best effort.

## Native authorization and historical inspection

`verify_publisher_bundle` accepts only `ami-rust-release-v2` and returns a
privately constructed `VerifiedPublisherBundle` with immutable retained native
manifest/asset bytes and authentication evidence. Installation must consume
those bytes rather than reopen the source bundle. Qualification-only releases
cannot enter this production-verification path.

The separate historical inspector accepts unchanged release-v1 signatures only
as compatibility evidence. Its result exposes no installation payload or native
authentication record. It serializes as
`ami-rust-legacy-publisher-inspection-v1`, with `signaturesVerified` and explicit
`nativeInstallationAuthorized: false`; it cannot produce the native receipt's
verification schema. No Python driver or interpreter is executed by inspection.
Successful historical cryptography is not qualification of a signed native-v2
candidate.

## Profiles and remaining qualification

The frozen publisher profile remains 512 bundle files/32 MiB total, 16 MiB per
asset, 512 input materials, 512 MiB per verifier tool and 16 MiB per trust root.
JSON format bounds and 128-container depth remain explicit. Workflow integers
retain exact decimal lexemes through the historical 4,300-digit limit without
enabling global arbitrary precision. GH output has its existing 4 MiB capture
profile, independent of the 2 MiB input proof bound.

Each command allows 60 seconds, 4 MiB stdout, 64 KiB stderr and a 2-second
termination grace; the cooperative whole-verification deadline is 300 seconds.
Private cache cleanup allows 16,384 entries and reports overflow. These are host
publisher/container profiles, not AROS application quotas. The
[native integration](native-sdk-v2.md#resource-observation) now samples visible
RSS, managed workspace and aggregate logs, and refuses remaining final scope
members. Sampling is not process containment; complete host/no-Python
qualification remains required before acceptance.

Seventy inert pinned historical SLSA output fixtures cover nine accepted and
61 refused decisions, including altered identities, materials, protected claims,
subjects, duplicates, private marker objects and invalid JSON. CI consumes these
directly in Rust, without running Python or fake cryptography. Command arguments,
environment, input boundaries, special files, cancellation/deadline, private
staging and cleanup have separate controls. Real GH/Cosign execution, negative
signature controls and exact host/source identities are recorded separately from
synthetic parser tests. Both-host qualification and all RC1-A1–A4 criteria remain
open until their complete evidence is available.

The [exact-source local result](evidence/rc1-publisher-local-20261019/result.json)
passes 172 core unit tests, one actual Cargo/frontend test and one manifest
oracle integration test (174 total), formatting and Clippy with warnings denied.
The [macOS cryptographic evidence](evidence/rc1-publisher-local-20261019/crypto-verification.json)
records the unchanged released manifest, external policy, verifier/root digests,
bridge/source identities and actual exits. All six genuine signature calls pass
in the positive inspection. Independently altered GH and Cosign signatures fail
in their respective real verifiers; changed payload, inputs, tool pin and a
legacy manifest presented to native verification also refuse. Only isolated
copies were corrupted. Original release/baseline inputs remain unchanged.

The bridge uses the same 29 registry package identities as the production lock.
Its historical inspection report explicitly refuses native installation
authorization. This local proof uses transitional internal Python orchestration;
it is neither the complete consumer no-Python observation nor a network-denial
qualification. A protected signed native-v2 candidate and the Linux real-verifier
path still need their own evidence. The [development/review record](evidence/rc1-publisher-local-20261019/review-and-development-record.json)
retains resolved failures and the changes required by independent review.

[Both-host CI 39206729340](evidence/rc1-publisher-hosted-39206729340.json)
passes the same 172 core + one frontend + one manifest integration test on
Ubuntu 24.04 x86-64 and macOS 26 Apple Silicon (174 per host), formatting and
Clippy. PR #88 merged the exact candidate with unchanged compiled tooling.
Hosted checks cover deterministic fixtures, not real hosted cryptography or a
signed native-v2 release; those remaining gates are unchanged.
