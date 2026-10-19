# RC1 release manifest validation

This partial [RC1 delivery](https://github.com/metaneutrons/ami-rust/issues/71)
parses release metadata in the shared Rust core. It does not verify signatures,
provenance, actual assets, host executability or installed trees, and it does
not activate a consumer command or close RC1.

## Version boundary

The legacy `ami-rust-release-v1` reader preserves the historical qualification
and production route distinction, exact outer fields, two host interpreter
digests, SDK contract digest and complete asset/file inventory shape. Those
interpreter digests are metadata for inspection, not instructions to execute
Python. Existing released manifests remain unchanged.

The separate `ami-rust-release-v2` reader uses the frozen native contract:
`host_launchers` replaces `host_interpreters`. Both supported host entries have
exact `path`, `bytes` and `sha256` fields and must match their release asset row.
A v1 record cannot be accepted as a native v2 release by changing the caller's
route flag. Successful parsing still establishes only internal consistency;
publisher policy, authenticated bytes and actual host/tool checks are required
before installation or execution.

Inventories require nonempty, bounded regular-file rows with portable paths,
exact integer byte counts and lowercase digests. Case/file/ancestor collisions
and reserved release manifest/signature paths refuse. `sdk.tar.xz` must be an
asset, and `contract/sdk.json` must match `sdk_manifest_sha256`.

## Original bytes and JSON validation

Input is bounded at 4 MiB and 128 containers before the borrowed raw-value pass.
The legacy producer object is opaque diagnostic metadata. Its original JSON
bytes are retained, including whitespace and exact integers through the pinned
historical parser's 4,300-digit boundary. A temporary validation copy replaces
only its integer tokens with small placeholders. The complete copy still
undergoes duplicate-key, depth, finite-number, exact-schema and field checks.
Integer `-0` is normalized to zero only in that validation copy to retain the
historical inventory decision; floating `-0.0` and `-0e0` remain invalid byte
counts. No manifest, digest or compiler metadata is rewritten.

The strict JSON visitor now also exposes its validated tree directly. This
avoids a second generic deserialization pass interpreting marker-like keys in
opaque objects as serde's private raw-value envelopes. The ordinary typed API
retains the same validation path; arbitrary-precision support remains disabled.

The frozen finite-number and 128-container rules deliberately refuse inputs
that historical CPython could accept, such as an overflowing floating exponent
inside opaque producer diagnostics or deeper objects. These differences do not
grant trust or silently alter an input. Differential evidence records the old
decision separately from the new contract decision.

## Host profile and verification scope

The inherited publisher profile allows 1,000 asset rows, 16 MiB per asset and
32 MiB total assets; the decoded SDK profile allows 1,000 files and 16 MiB total.
These are release-container parsing profiles, not AROS program quotas. No
dependency or global JSON number feature is added by these readers.

Focused controls cover route/schema separation, host and inventory binding,
required/reserved/colliding paths, sizes/types, duplicates, private marker-like
objects, exact nesting and integer boundaries. Internal historical Python may
serve as an isolated oracle during RC1; it is not a consumer execution path.
Both-host integration and the later complete observed consumer/build matrix
remain separate acceptance requirements.


Independent review also found that two earlier intermediate-tree readers could
interpret a private raw-value wrapper as a valid inner state/receipt. The
[pre-fix counterprobe](evidence/rc1-manifests-local-20261019/pre-fix-wrapper-control.json)
reproduces both failures. Both readers now use the direct strict tree, and
regressions reject wrapped state, selection, project-lock and receipt roots.
These development-only library readers have not activated a public consumer
command; released 0.1.0 assets are unchanged.

The [exact-source macOS proof](evidence/rc1-manifests-local-20261019/result.json)
passes 131 core unit tests, one real Cargo/frontend case and one manifest
integration test (133 total), formatting and Clippy with warnings denied. The
integration case consumes 41 inert historical fixtures directly in Rust. The
[dynamic historical comparison](evidence/rc1-manifests-local-20261019/legacy-parser-differential.json)
uses pinned Python 3.12.15 and a native Rust bridge with all 29 registry
identities equal to the production lock. The 40 original decisions agree in 39
cases; depth 129 is the declared stricter refusal. The supplemental overflowing
float is the other explicit contract difference. Accepted semantic fields agree.
All 19 compiled core sources remain byte-identical after serial integration;
the added fixture integration test has its own current full-suite result.
Both-host CI and complete RC1 acceptance remain separate gates.
