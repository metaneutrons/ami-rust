# Linux no-Python enforcement probe

This standalone, standard-library-only crate tests named Linux execution and
dynamic-library loading routes on Ubuntu 24.04 x86-64. Python is used only as
an isolated detector control; the report explicitly marks the runner-installed
interpreter as outside the supported no-Python path.

Run on the native Ubuntu 24.04 x86-64 runner with Rust 1.98.1, `python3`, a C
compiler, `readelf`, `ldd`, and a dynamically loadable shared `libpython`:

```sh
rustup run 1.98.1 cargo test --locked --offline \
  --manifest-path tools/linux-no-python-probe/Cargo.toml
rustup run 1.98.1 cargo run --locked --offline \
  --manifest-path tools/linux-no-python-probe/Cargo.toml -- \
  --self-test --output "$RUNNER_TEMP/rc0-linux-no-python"
```

The self-test runs direct, descendant, shebang, and dynamic-embedding Python
positive controls first. It then creates a Landlock policy inherited by child
processes, allows only exact executable paths and the recorded ELF read
closure, and denies the runner's Python executable and `libpython`. The C
fixture remains executable under policy and attempts `dlopen` on the recorded
library, so the test measures denial at library loading rather than only
refusing the fixture binary. Seccomp blocks `execveat`, `memfd_create`, and
x32 syscall numbers.

The command exits nonzero unless controls pass, policy setup succeeds, the
native allowlisted binary runs, and the named direct, descendant, shebang,
embedding, loader, `execveat`, and `memfd_create` denial controls produce their
expected markers and raw outcomes. It writes a unique JSON report and fixture
directory under `--output`; reports are never overwritten. Each command has a
20-second deadline, process-group timeout cleanup, and a 64 KiB capture limit
per output stream.

See [`../../docs/rust-cli-migration/linux-no-python-design.md`](../../docs/rust-cli-migration/linux-no-python-design.md)
for the policy boundary, review notes, interpretation, and limitations. A
macOS build or Linux cross-compilation checks compilation only. Only a native
Ubuntu run can produce Linux enforcement evidence.
