# Public release consumer replay

The workflow downloads a tagged public release and independently replays its consumer path on macOS ARM64 and Ubuntu x86-64. It does not publish an SDK, declare R1 acceptance, or run an AROS guest. A later primary stage must retrieve the native outputs from both host artifacts and test those bytes in the unchanged guest environment.

The preceding [candidate and draft staging helpers](staged-sdk-release.md)
manage the exact release file set and byte readback. They do not authorize
publication or replace signature verification and independent acceptance.

## Establish the four external pins

Before dispatch, record these values in the campaign evidence from sources independent of the downloaded bundle:

- `release_tag`: the approved immutable `v`-prefixed SemVer release tag.
- `publisher_source`: the exact 40-character lowercase Git commit selected for the publisher source.
- `release_manifest_sha256`: the independently recorded SHA-256 of that release's `release.json`.
- `transport_inventory_sha256`: the independently recorded SHA-256 of the public transport-inventory asset for the same tag.

The workflow downloads the exact six files named by `release/stage_candidate.py`: the release archive, its SPDX SBOM and Cosign bundle, the transport inventory and its Cosign bundle, and `SHA256SUMS`. It checks the transport inventory against the external digest and retains the files without unpacking. Do not obtain an external trust pin from the candidate itself.

Before extraction, the replay verifies GitHub attestations for the archive, SBOM, transport inventory and checksums, plus Cosign signatures for the archive and inventory. The four attestations must identify one authenticated publisher run, the selected source and the expected input materials. Only then does the transport decoder check and extract the complete regular-file inventory. The archive and unpacked regular-file bytes each have a 32 MiB bound, with at most 512 files. The inner publisher evidence, external manifest digest and tag version must also agree before installation.

Keep the release-tag, source-commit, manifest-digest, and inventory-digest evidence with the campaign record. The workflow fetches the exact tag from the designated public repository and requires its peeled commit to equal `publisher_source`. The replay independently checks that local tag and source `HEAD` against the same external commit before accessing the bundle or installing tools. Lightweight and annotated tags are supported; missing tags and tags naming another commit are rejected. A standalone replay therefore needs the exact tag fetched from the designated origin beforehand.

The authenticated manifest version must equal the selected tag's SemVer release core, excluding a prerelease suffix and build metadata. The full tag remains the download identity. The workflow report binds each host result to the four external pins, the verified `release_tag_target_commit`, the workflow-control commit, and the current GitHub run ID and attempt.

## Dispatch

Start this as part of a concrete 90-minute campaign coordinated outside this workflow. The workflow has an 80-minute job ceiling and runs its two host jobs in parallel, with the same global concurrency group as the protected SDK and Cargo builds; this keeps the shared two-job, 24 GiB hosted resource profile in force. Only `workflow_dispatch` is enabled.

Dispatch `.github/workflows/public-replay.yml` from protected `main` with the four independently approved values:

```sh
gh workflow run public-replay.yml \
  --repo metaneutrons/ami-rust \
  --ref main \
  -f release_tag=v1.2.3 \
  -f publisher_source=0123456789abcdef0123456789abcdef01234567 \
  -f release_manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -f transport_inventory_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

The example values are syntactically valid placeholders. Replace them with the four recorded pins; do not dispatch the placeholders.

## What the workflow records

Each hosted job first checks the designated repository, protected `main`, the selected ref, and exact input formats. It checks out the workflow commit identified by `github.sha`, records hashes of the tracked replay and transport controls under the checkout's `.git/ami-rust-public-controls`, then fetches the externally selected publisher commit and detaches the same checkout at that exact commit. This avoids a second checkout and keeps the private controller files out of the selected source tree. It then fetches and verifies the exact selected tag before the selected source's `release/ci_python.py` installs the pinned Python runtime.

The artifact-admission step uses `GH_TOKEN` to reserve two 32 MiB consumer outputs against the aggregate 768 MiB retention pool. The replay step also receives the read-only token solely to retrieve the public GitHub attestation bundles through the pinned GitHub CLI. It removes the token before invoking cryptographic verification or consumer commands. Release-asset downloads use no authorization headers. Job permissions are `contents: read`, `actions: read` and `attestations: read`; the job uses the `release` environment.

The frozen controls remain separately identified by their actual workflow commit and file hashes. Selected-source inputs and policies retain the publisher commit identity; copying a helper does not make its code part of that older commit. The selected publisher source supplies its pinned Python bootstrap directly.

The download receipt records all six raw asset hashes, the external inventory digest, both source identities, run IDs and download resources; it explicitly claims no authentication. The separate authentication receipt records the selected raw attestation proofs, verification commands and authenticated publisher identity. Both receipts and the selected proof snapshots are retained for review. The existing replay driver enforces its 4 GiB aggregate process-tree RSS, 12 GiB managed-workspace, 16 MiB aggregate logs, and 1,200-second command ceilings. The transport step separately records its own process peak RSS and the measured combined file footprint for the source checkout (including `.git`), pinned Python runtime, and downloaded candidate assets. These download measurements describe that step's process and managed files; they are not the replay driver's full process-tree measurements.

On success, each host artifact includes the public replay receipt, outer authentication receipt, selected attestation proof snapshots, bounded download and run receipts, and retained native AMIRUST files. On a replay failure, the workflow retains bounded failure metadata and any safe regular native files already produced. Retained files are limited to 31 MiB, at most 512 regular files with relative names of at most 240 UTF-8 bytes. This leaves 1 MiB for ZIP framing inside each existing 32 MiB artifact reservation; retention is seven days. The workflow retires only the owned temporary bundle, work, and Python runtime after replay; it leaves the private Git controls intact until the hosted job ends.

## Review the campaign result

A successful artifact reports only that one host completed the public consumer replay against the supplied pins. Compare the macOS and Linux receipts by workflow run ID, run attempt, publisher source, release-manifest digest, and transport-inventory digest. Both host receipts are required before the later primary R1 stages begin. Retrieve both hosts' native bytes into the unchanged guest qualification environment; this workflow itself does not perform that guest run or make the R1 decision.

End-to-end public replay remains pending until this workflow is dispatched with real external pins for an accepted, publicly available candidate and both host artifacts have been reviewed. Offline fixtures and syntax checks do not prove the public download or native replay.
