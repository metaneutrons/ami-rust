# Target-facing Cargo metadata candidate

This is an unqualified development recipe. Current producers continue to use
`three-host-v2`. Adding this directory does not select a new SDK input, qualify
any release criterion, or change the AROS ABI/boot baseline.

The internal producer and its protected prerequisite workflow accept an explicit
`three-host-v3` recipe choice; the default remains `three-host-v2`. The selector
accepts only those two immutable source/patch pairs. Selection is forwarded
through the existing supervisor and recorded in setup bindings. The source
checkout must match every original and patched file in the selected inventory,
with no extra or missing changed paths. Existing SDK manifests and historical
producer receipts continue to bind their original v2 inputs.

The [local three-host development summary](../../../docs/evidence/rc2-local-cargo-v3-three-host-20261023.json)
records five complete AROS programs and 22 native objects per host with equal
raw bytes. It does not qualify production Cargo binaries, two-root controls or
the new programs' AROS runtime/memory behavior.

The v2 consumer run found one remaining complete-ELF mismatch: Cargo recursively
included a host-only `cpufeatures -> libc` edge on AArch64 in the target crate
identity. The edge is absent on x86-64. The same `libc` unit is already reachable
through the native build helper on both hosts. Different symbol disambiguators
changed the relative order of two function sections.

This candidate restores upstream metadata for native host units. For explicit
actual cross builds, target symbol metadata consumes the sorted set of reachable
host unit identities instead of their recursive edge topology. The projection
retains package/source/version, enabled features, profile, compilation mode,
target name/kind, compiler release and standard-library role. Target artifact
dependencies remain opaque leaves with their actual target metadata. Ordinary
target dependencies keep their recursive metadata. Target cache keys continue
to consume the full actual dependency cache identities and receive a new recipe
marker. Native compilation, including an explicit native `--target`, retains the
upstream path. Mixed native/cross target requests conservatively use the upstream
path for the whole invocation. The target fingerprint also binds the effective
symbol metadata and recipe version, including layouts without hashed filenames.

The root identity is explicit. Before projecting, Cargo checks all native host
units in the invocation for equal projected descriptors belonging to distinct
full units (including their dependency context). If a reachable descriptor is
ambiguous, the root falls back to its original native metadata under a separate
domain. This may leave a visible cross-host mismatch; it avoids merging those
crate instances. Artifact and feature-resolution roles remain in each descriptor.

This is a namespace projection, not proof that different host tools produce
equivalent output. Different reachable packages or features deliberately remain
different. Complete target ELF equality, actual build-script/proc-macro output,
native tool identities and cache behavior still require qualification.

Before selecting this recipe:

- Apply it to the exact upstream files in `source.json` and verify every digest.
- Check mode-off and implicit/explicit native behavior against upstream.
- Verify actual host metadata/cache identity, cross target metadata, package
  source/version/features/profile/role distinctions and target dependency sensitivity.
- Exercise build scripts, Serde derive, fresh roots, relocation and warm/retry
  behavior with the actual paired Cargo and Rust compiler.
- Reproduce all five native AROS variants on macOS ARM64, Linux x86-64 and Linux
  ARM64; retain full byte comparisons and requalify affected runtime outputs.
- Create new derived Cargo/producer identities and update their source/notice
  bindings through the normal reviewed integration path. Preserve v2 inputs,
  producer records and failed evidence.

No finished compiler metadata or ELF payload is rewritten by this patch.
