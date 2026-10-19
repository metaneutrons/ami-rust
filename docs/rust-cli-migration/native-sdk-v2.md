# Native SDK-v2 and release verification

The native Rust consumer uses a separately identified `ami-rust-sdk-v2`
manifest inside `sdk.tar.xz`. Released SDK-v1 archives and their Python driver
are immutable. SDK-v1 signature inspection does not authorize execution through
the native driver. This addendum preserves every RC0–RC5 acceptance criterion.

## Explicit verification command

```sh
ami-rust verify --bundle ./authenticated-bundle --policy ./trust/publisher-policy.json
cargo ami verify --bundle ./authenticated-bundle --policy ./trust/publisher-policy.json
```

Both names enter the same parser and implementation. The two options are
required exactly once and may appear in either order. Paths retain their OS
representation and are resolved to canonical absolute paths before admission.
The policy, pinned verifier executables and trust roots must remain external
to the bundle. No ambient package lookup or SDK-lock fallback occurs.

Success first requires all six real pinned GitHub/Cosign verifier calls and
exact retained release-v2 assets. It then decodes retained `sdk.tar.xz` bytes,
verifies the complete TAR inventory and binds the inner SDK manifest to the
release's digest and file row. The source bundle is not reopened to choose
archive bytes after authentication. The authenticated release signature is
retained with the manifest for subsequent installation work.

The JSON result reports publisher authentication, the manifest and signature
identities, SDK structural summary and each verifier's sampled resources. This
command verifies distribution identity and structure. It does not establish
native compiler correctness, accepted R1 baseline equivalence, installability,
RC1 acceptance or any publication gate. These require their own evidence.

## Inner manifest contract

Required top-level keys are `schema`, `version`, `qualification_only`, `driver`,
`target`, `files`, `profiles`, `rust_commit`, `rust_llvm`, `source_date_epoch`,
`source_identity`, `build`, `host_capacity` and `application_memory_policy`.
Only `extensions` is optional; it is bounded diagnostic data with no execution
semantics. Duplicate and unknown decision keys refuse.

- `schema` is `ami-rust-sdk-v2`; `driver` is the fixed recipe identifier
  `ami-rust-native-compatibility-v1`, never an executable or arbitrary command.
- `version` and the actual boolean `qualification_only` match release-v2.
  Production verification refuses qualification-only inputs.
- `target` is `x86_64-aros`; source/compiler identities are 40 lowercase hex
  digits, `rust_llvm` is nonempty and `source_date_epoch` is a nonnegative u64
  integer. These structural checks do not prove accepted component equality.
- `files` contains exactly every non-self regular archive member, with path,
  byte count and SHA-256. The self manifest is pinned by release-v2 instead.
  Inner rows must exactly match the authenticated outer inventory; archive
  path, collision, link and special-member admission uses the shared TAR reader.
- `profiles` contains exactly `linux-x86_64` and `macos-aarch64`, with triples
  `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`. Each profile has exactly
  `rust_host`, `cargo_metadata_mode`, `cargo_binary`, `collector_binary` and
  `components`. Metadata mode is `ami-rust-reproducible-cross-v1`; executable
  paths are `bin/cargo` and `bin/aros-collect`.
- Each host names exactly six components: `rust`, `cargo`, `toolchain`,
  `collector`, `csdk` and `vendor`. Each component row has `manifest` and
  `sha256`; its fixed path is `host/profiles/HOST/COMPONENT.json`. Its digest
  must match both inventories. Role or host aliases refuse.
- `build` has exactly `jobs: 2`, `rss_bytes: 4294967296`, `seconds: 1200`,
  `workspace_bytes: 12884901888`, `log_bytes: 16777216`.
- `host_capacity` has exactly schema `ami-rust-host-capacity-v1`,
  `ram_minimum_bytes: 6442450944`, `disk_free_minimum_bytes: 25769803776`.
- `application_memory_policy` is `ami-rust-application-memory-policy-v1`.
  Host reference capacities impose no generic AROS application heap quota.

The archive profile remains 16 MiB compressed/decoded, 64 MiB XZ decoder
memory, at most 1,000 file members including the self manifest, and the shared
per-member bounds. This format does not create new compiler or ABI inputs.
Before prepare/build activation, native component profiles and the target
specification must also match the accepted R1 producer/reference identities.
A consistent self-inventory alone is insufficient.

## Resource observation

Each real verifier call uses the current host reference thresholds of 4 GiB
visible RSS, 12 GiB private workspace and 16 MiB aggregate disk/pending logs,
in addition to the existing 60-second command/300-second verification timeout,
4 MiB stdout, 64 KiB stderr and 2-second cleanup grace. These are execution
profiles, not universal application quotas or new milestone time budgets.

The observer samples `/bin/ps` using bounded output, tracks parent/group/history
linkage, and scans retained private-root descriptors with independent directory
cursors. Every required root must remain present with the retained identity.
Existing disk logs and pending captured bytes are added once. Failures retain
known peaks and identify incomplete samples. Original-group cleanup continues
to use fresh unreaped-child ownership; observed historical PIDs/groups never
grant authority to signal them.

Process tables and directory walks are samples, not atomic snapshots or
containment. Escaped or still-present non-root scope members at final sampling
refuse success. Cleanup errors remain errors. No absence-of-Python or complete
process containment claim follows from these measurements alone.

## Qualification boundary

The native verifier command is development tooling until an exact signed
native-v2 candidate passes real positive and altered-signature/payload tests on
both supported hosts. Historical release-v1 real signature evidence and
synthetic SDK-v2 composition tests remain separately identified. They cannot
substitute for that native candidate or complete RC1-A1–A4.
