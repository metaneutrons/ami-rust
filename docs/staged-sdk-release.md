# SDK release staging

R1 remains unqualified. These helpers prepare and check bytes; they do not
authorize publication, authenticate a candidate, create a production tag, or
promote a release. No SDK has been published by these helpers. The protected
producer, final native qualification, actual signature verification and
independent R1-A1 through R1-A7 acceptance are still required before publication.

`release/stage_candidate.py` accepts an already authenticated and accepted
candidate directory from its caller. It checks the release version against the
canonical tag core, the complete bundle inventory and the exact declared SBOM.
It uses the same deterministic transport as the public consumer and unpacks the
result for complete byte readback. Signature files are supplied separately by
the real signer. The helper checks their JSON structure only: this is not
cryptographic verification.

The single shared `asset_names(tag)` function defines the final release set:

- `ami-rust-<core>-release.tar.xz`, its `.spdx.json` and `.sigstore.json` files;
- `ami-rust-<core>-transport.json` and its `.sigstore.json` file;
- `SHA256SUMS`, covering exactly the other five files.

The full tag remains the GitHub release identity; prerelease/build suffixes do
not become package versions or asset filenames. Finalization rejects missing,
extra, linked or modified files. Later crypto verification must use the exact
source-selected publisher identities, not identities asserted by the bundle.
The SBOM and checksums also require provenance attestations in the eventual
publication workflow. Generating a checksum file does not satisfy that gate.

`release/stage_draft.py` only uploads to an existing draft release. Production
tags and their drafts must come from release-please. Its caller independently
selects the qualified source commit; both the candidate and the peeled GitHub
tag must identify that exact commit. It uses the source-pinned GH executable
and explicitly addresses github.com, including when the environment selects a
different default GH host.

Before uploading, the controller checks the repository's reported push permission, draft status
and the complete existing asset inventory. Matching partial drafts can resume;
unknown or changed assets stop the operation. It never clobbers an asset. Each
upload has a fresh tag/source/draft check. All assets are then downloaded by
their exact provider IDs into a fresh private directory and compared byte for
byte with the candidate, including the complete checksum/inventory check. The
download file-size ceiling is the selected asset's exact size, preventing an
unexpected response from filling the disk. Failed partial drafts/readbacks are
retained for inspection.

Reported repository permission alone does not prove a token's release-writing
scope. The publication workflow must grant its token `contents: write`; every
actual upload is still authorized by GitHub and an upload error stops staging.

Its receipt explicitly records `DRAFT_BYTES_STAGED_NOT_PUBLISHED_NOT_CRYPTO_VERIFIED`.
The caller must verify real signatures and attestations against those downloaded
bytes before exposing a prerelease. Public byte verification and two-host
consumer/guest replay under R1-A8 must succeed before promotion to supported
stable/latest. A failing gate leaves the previous supported release unchanged.

## Protected complete-candidate producer

The normal protected SDK workflow adds the complete-candidate job only after
both independent consumers have succeeded. Reference-proposal runs skip it.
The job uses the freshly authenticated Linux bundle containing the common SDK
and both host-Cargo components; its signer profile does not restrict the
consumer to Linux. The external source policy permits both qualified hosts.

Before packing, `release/candidate_auth.py` re-verifies the inner publisher
evidence under the exact source-selected policy, tools and roots. The existing
deterministic staging helper then creates the payload and exact transport
inventory. Real Cosign OIDC signatures cover the payload and inventory. Four
individual GitHub provenance attestations cover payload, SBOM, inventory and
complete checksums, preserving the verifier's one-subject-per-bundle policy.
Each action bundle is copied immediately to its own path before another
attestation invocation can reuse the action output location.

The job verifies the actual cryptographic proofs against the source, workflow,
run, environment, runner and complete input-material identities. Deliberately
modified payload copies must fail both GitHub and Cosign verification; a
missing asset must fail the complete inventory check. It retains the actual
proofs, results and mutation recipe/hashes without replacing the original
payload. The transient mutated copy is outside the retained candidate tree.

The new artifact contains `candidate/` (exactly six release files) and
`metadata/` (attestations, verification and cleanup receipts). Its prospective
96 MiB retention ceiling accounts for the bounded 32 MiB transport, duplicated
SBOM and proofs with headroom. One protected admission job, before either producer starts, reserves seven
existing 32 MiB artifacts plus this 96 MiB artifact, 320 MiB in total, against
the unchanged 512 MiB provider pool. Matrix jobs do not reserve the same DAG a
second time after another producer has already uploaded. A reference proposal
reserves only its two 32 MiB producer artifacts, because the remaining jobs are
skipped and cannot upload. It remains ineligible for authentication. These are hosted retention requirements, not application
memory limits. Host RAM/build settings and the guest profile are unchanged.
Earlier source runs and their reservation records retain their original scope.

Successful output is `OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED`. A cleanup receipt
may report verification success only when the actual bounded report identifies
this exact source/run. Failed partial candidates and outcomes remain available
for diagnosis and must not be admitted as release-ready artifacts.

Actual successful protected production is still required; isolated fixtures do
not establish signing/provenance acceptance. Automated release-please dispatch,
prerelease exposure and promotion remain separate work. No stage here publishes
an SDK or replaces independent R1 acceptance and public replay.
