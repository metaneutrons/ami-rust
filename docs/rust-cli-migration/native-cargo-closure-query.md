# Native Linux Cargo source-graph query

This is the bounded RC0-A1 query for the upstream Cargo producer graph on the
standard `ubuntu-24.04` GitHub-hosted runner. It records the exact public source,
lock, patch, host tool identities, fetched registry archive checksums, and the
native Linux `cargo tree`/`cargo metadata` results. It does not build Cargo or
any dependency package. It does not run a package `build.rs`, and it is not
evidence that the existing producer is Python-free.

The source identity is the public pin in
[`release/ci-bootstrap-inputs.json`](../../release/ci-bootstrap-inputs.json):
upstream Cargo commit `3efb1f477e99b42974b982d939fd100303cdf7db`,
`Cargo.lock` SHA-256
`b4ccfa53ccf8d7360c0359c1533d801759629f9cdd486d9a0a88e512717058d9` (136,479
bytes; 550 lock records: 523 registry, 27 workspace path, no Git sources), and
patch SHA-256
`1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f`. The
patch targets and resulting SHA-256 values are checked against
[`host/cargo-repro/source.json`](../../host/cargo-repro/source.json):

| Patch target | Upstream SHA-256 | Patched SHA-256 |
|---|---|---|
| `src/compiler/build_runner/compilation_files.rs` | `275e1ff7e6512bbbb3b30a7f0ceb9c7d455745e6aafce0484cb73d8fe31e0e67` | `b572e74e742cca08765540aa9f611b1877defc08d146cff52fcd9b0c039106db` |
| `src/workspace/features.rs` | `2747b5598654963df7d9270b07fc7dbd80a700cf219b26db71b0d2291ea74638` | `0db8ba62877729fdee23ee8ae26f11a7b79fdd8bf086845a53c5f097eb1eacc3` |

The driver first checks these tracked pins, fetches the exact Git commit, and
checks the downloaded `Cargo.lock` bytes, digest, and package classes. It then
copies the lock into isolated good and altered files and invokes the same
script's `--verify-lock` mode on both. The good copy must exit 0; the altered
copy must exit 2 with the exact pinned-lock refusal. This mode reads the lock
only and has no network or write behavior. The counterprobe completes before
the registry fetch or Cargo graph query. The pinned host
Rust 1.98.1 and Cargo 1.98.1 are installed with
[`tools/bootstrap-host-rust.sh`](../../tools/bootstrap-host-rust.sh), which
verifies its existing archive hashes. Registry inputs are fetched into a fresh
`CARGO_HOME` with `cargo fetch --locked --target
x86_64-unknown-linux-gnu`. Every cached `.crate` archive is checked against its
`Cargo.lock` checksum; the receipt also records archive sizes and enforces the
16 MiB per-archive and 384 MiB aggregate observed-input limits. Source archives
and extracted registry sources remain in the ephemeral work directory and are
not uploaded.

With `CARGO_NET_OFFLINE=true`, the driver runs these commands against the
patched source tree:

```text
cargo tree --locked --offline --manifest-path <pinned-source>/Cargo.toml --package cargo --features all-static -e normal,build --target x86_64-unknown-linux-gnu --color never --prefix none --format '{p} {f}'
cargo metadata --locked --offline --manifest-path <pinned-source>/Cargo.toml --format-version 1 --filter-platform x86_64-unknown-linux-gnu --features all-static
```

The native runner records the package count and package/feature rows in
`locked-linux-cargo-graph.json`, along with a SHA-256 over the sorted package
identity/source set. It does not impose a package count derived from an earlier
cross-target query on macOS. Review compares the native identity/source rows
with the retained source-level build-script inventory. The complete tree
output and `cargo metadata` JSON are retained alongside the exact argv, working
directory, environment, exit status, output size and digest for each command.
This provides the native-host conditional dependency selection needed to
compare the previously inspected build-script sources with the actual Linux
host graph. The workflow does not copy that source inventory or any of the 550
Cargo source packages into the public artifact.

The receipt fingerprints the runner's `git`, `cc`, `ar`, `perl`, `make`,
`pkg-config`, and the utilities used by the bootstrap and patch steps. These
are observed host identities, not new normative version pins. The query
therefore provides the concrete inputs for deciding which conditional helper
tools the eventual native Cargo producer needs. A successful result means that
the locked metadata graph resolved on native Ubuntu with the pinned source and
toolchain; it does not establish which helper subprocesses a real Cargo build
will launch, nor does it replace RC4 producer execution and process-tree
qualification.

The workflow uses the existing CI resource validator and supervisor, with a
15-minute job/command ceiling, the current 12 GiB workspace, 4 GiB aggregate
RSS and 16 MiB log limits, and the 6 GiB RAM / 24 GiB free-disk admission
minimums. Retained output is capped below 32 MiB. It is read-only with respect
to GitHub (`contents: read`), disables checkout credential persistence, and
uploads only query metadata and supervisor logs. Its report records the
candidate PR head (or dispatch SHA) alongside the actual checked-out commit and
tree, which may be GitHub's synthetic pull-request merge checkout. No
credentials or publishing environment are provided.

The driver and workflow use inline/internal Python for orchestration and
evidence processing. This remains transitional RC4 work; it is not RC5
evidence, does not establish Python removal, and does not qualify actual Cargo
producer execution. RC4 must still observe the producer's real subprocess tree
on each supported host.

The query has not been dispatched or run on GitHub as part of this change. The
script and workflow have only received local static syntax checks. RC0 remains
open until the native Ubuntu artifact is reviewed together with the source-level
build-script evidence; RC4 must still exercise the actual producer on each
supported host.

## First native attempt and actual-output regression review

[Run 39172161134](https://github.com/metaneutrons/ami-rust/actions/runs/39172161134)
for candidate `844f52d` remains **FAIL**. All source, lock, archive, bootstrap,
Cargo-tree and metadata commands returned their expected status, but the new
checker used `format_version` instead of Cargo's actual `version` JSON field.
The checker is corrected, with pure graph parsing that can review ephemeral
runner paths after the runner has gone. Empty resolution/tree and ambiguous
package data fail closed. The complete actual native output passes locally;
eleven minimally altered real-output cases are refused before any accepted
graph report is written. These controls now run in the hosted query itself.

The actual native graph has 341 selected package identities and 36 custom-build
scripts, matching the earlier source-level identity sets. This finding comes
from native output, not an imposed package-count assertion. Native retrieval
verified 457 lock-bound registry archives, 53,297,461 bytes total. Observed RSS
was 313,122,816 bytes, workspace 1,980,939,861 bytes and logs 90,602 bytes.
[Original-attempt digests, corrected parser controls and host fixture evidence](evidence/cargo-native-query-review/first-attempt.json)
are retained. The corrected exact candidate still needs a successful hosted
query before RC0 acceptance; the original failure is not rewritten as PASS.
