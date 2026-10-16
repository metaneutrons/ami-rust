# Public release consumer replay

The workflow downloads a tagged public release and independently replays its consumer path on macOS ARM64 and Ubuntu x86-64. It does not publish an SDK, declare R1 acceptance, or run an AROS guest. A later primary stage must retrieve the native outputs from both host artifacts and test those bytes in the unchanged guest environment.

## Establish the four external pins

Before dispatch, record these values in the campaign evidence from sources independent of the downloaded bundle:

- `release_tag`: the approved immutable `v`-prefixed SemVer release tag.
- `publisher_source`: the exact 40-character lowercase Git commit selected for the publisher source.
- `release_manifest_sha256`: the independently recorded SHA-256 of that release's `release.json`.
- `transport_inventory_sha256`: the independently recorded SHA-256 of the public transport-inventory asset for the same tag.

The transport inventory is downloaded from the fixed public GitHub release URL and its full SHA-256 is checked before JSON parsing. Its archive name must be `ami-rust-<version>-release.tar.xz`; the archive must be between 1 byte and 32 MiB and match the inventory's byte count and SHA-256. The transport decoder then checks each regular file against the complete inventory, with limits of 32 MiB raw file bytes and 512 files; the compressed transport archive also has a 32 MiB limit. Do not choose the inventory digest from the inventory download itself or use data from the candidate bundle alone as an external trust pin.

Keep the release-tag, source-commit, manifest-digest, and inventory-digest evidence with the campaign record. The replay rejects an authenticated manifest whose version differs from the selected tag. The workflow report binds each host result to those four values, the workflow-control commit, and the current GitHub run ID and attempt.

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

Each hosted job first checks the designated repository, protected `main`, the selected ref, and exact input formats. It checks out the workflow commit identified by `github.sha`, records hashes of the tracked replay and transport controls under the checkout's `.git/ami-rust-public-controls`, then fetches the externally selected publisher commit and detaches the same checkout at that exact commit. This avoids a second checkout and keeps the private controller files out of the selected source tree. The selected source's `release/ci_python.py` installs the pinned Python runtime.

Only the artifact-admission step receives `GH_TOKEN`; it calls `release/ci_artifact_admission.py` without `--sdk-candidate` to reserve two 32 MiB consumer outputs against the existing aggregate 512 MiB retention pool. The replay and public-download steps receive no token or authorization headers. Job permissions remain `contents: read` and `actions: read`, and the job uses the `release` environment.

The transport receipt records the external inventory digest, the verified archive and file inventory, the control and publisher source identities, run IDs, and measured transport resources. The existing replay driver enforces its 4 GiB aggregate process-tree RSS, 12 GiB managed-workspace, 16 MiB aggregate logs, and 1,200-second command ceilings. The transport step separately records its own process peak RSS and the measured combined file footprint for the source checkout (including `.git`), pinned Python runtime, and unpacked bundle. These transport measurements describe that step's process and managed files; they are not the replay driver's full process-tree measurements.

On success, each host artifact includes the public replay receipt, bounded transport and run receipts, and retained native AMIRUST files. On a replay failure, the workflow retains bounded failure metadata and any safe regular native files already produced. Retained files are limited to 31 MiB, at most 512 regular files with relative names of at most 240 UTF-8 bytes. This leaves 1 MiB for ZIP framing inside each existing 32 MiB artifact reservation; retention is seven days. The workflow retires only the owned temporary bundle, work, and Python runtime after replay; it leaves the private Git controls intact until the hosted job ends.

## Review the campaign result

A successful artifact reports only that one host completed the public consumer replay against the supplied pins. Compare the macOS and Linux receipts by workflow run ID, run attempt, publisher source, release-manifest digest, and transport-inventory digest. Both host receipts are required before the later primary R1 stages begin. Retrieve both hosts' native bytes into the unchanged guest qualification environment; this workflow itself does not perform that guest run or make the R1 decision.

End-to-end public replay remains pending until this workflow is dispatched with real external pins for an accepted, publicly available candidate and both host artifacts have been reviewed. Offline fixtures and syntax checks do not prove the public download or native replay.
