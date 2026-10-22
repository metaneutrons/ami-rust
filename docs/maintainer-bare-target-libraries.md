# Bare-target Rust libraries: protected internal prerequisite

The `bare-target-libraries.yml` workflow rebuilds `core`, `alloc` and
`compiler_builtins` for the existing x86_64-aros ABI-v1 target. It uses native
macOS 26 Apple Silicon, Ubuntu 24.04 x86-64 and Ubuntu 24.04 ARM64 runners.
This is a component prerequisite for [RC4](https://github.com/metaneutrons/ami-rust/issues/74)
and [L1](https://github.com/metaneutrons/ami-rust/issues/129), not SDK acceptance.
The [migration plan](rust-cli-cargo-migration-plan.md) owns acceptance criteria.

The source-controlled `release/bare-target-libraries-inputs.json` binds the
nightly-2026-09-18 rustc, native host standard library and Rust source archives,
their unchanged full profiles, and the exact three native Cargo artifacts from
protected run 39748078466. Linux ARM64 input data remains prospective until L1.
The independently pinned Rust 1.98.1 bootstrap builds the internal xtask; it is
separate from the target compiler. All downloads are explicit before the offline
library build. Crates and ordinary application builds do not invoke this task.

After this workflow is merged into protected main, dispatch exactly:

```sh
gh workflow run bare-target-libraries.yml --repo metaneutrons/ami-rust --ref main
```

The workflow rejects other refs, repositories and host identities before checkout.
It shares the protected-build concurrency lock and runs at most two native jobs
at once. Keep terminal failures and their outputs; do not repeatedly poll or
retry terminal runs. Inspect a native run no more often than every 30 minutes.

Each host artifact retains the built internal xtask, exact source/host/input
identities, all eight outer command requests/results and raw logs, bootstrap
records, full scoped Rust inventory, and the five Rust command requests/results
and raw logs. The `producer/libraries/` files keep their original compiler names
and bytes. Partial bootstrap records are also retained on failure where present.
No downloaded archive bodies, full staging trees or compiler caches are uploaded.

The command limits remain 4 GiB aggregate RAM, 12 GiB workspace, 16 MiB raw logs
and 1,200 seconds. Each campaign has 5,400 seconds including a 300-second
finalization reserve. The active parent is measured separately and bounded;
nested Rust peaks plus that parent count against the same 4 GiB total.
Each host payload is bounded to 127 MiB before upload, with 128 MiB including
upload framing. An oversized payload is refused before upload. The shared pool
is owned by `release/ci-artifact-policy.json`; command and AROS budgets are
independent of that storage policy.

Success is explicitly `PREREQUISITE_ONLY`. Compare all original bytes of the
three target libraries across all three native hosts before adopting a new
shared target-library pin. Preserve failures and investigate differences;
never rewrite .rlib or compiler metadata. New generated recipe identities need
new input identities and subsequent application/runtime qualification. Existing
pins and historical receipts are not updated by this workflow.

The retained xtask is a possible future bootstrap seed, not an authenticated
release component. The temporary Python outer monitor remains active. This
workflow establishes neither a Python-free project nor a complete C SDK, linker,
registry package, rustup installation, application build, AROS runtime result,
L1, RC milestone or SDK publication.

The [local macOS evidence summary](evidence/rc4-bare-target-macos-20261022.json)
records a separately reviewed five-command run and its original loader-failure
counter. It is one host and does not replace the protected three-host workflow.
