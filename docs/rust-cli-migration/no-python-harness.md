# RC0-A4 no-Python harness feasibility probe

Status: **PARTIAL; RC0-A4 remains open.** The bounded macOS run passes a native
positive control and direct, descendant, absolute-shebang, and embedded-runtime
counterprobes. The controls prove that the tested routes are refused under an
inherited deny-by-default process-execution policy. They do not qualify a
complete component closure, an independent audit stream for arbitrary denied
execs, opaque embedded-runtime detection, or Linux behavior.

The executable is a standalone Rust standard-library-only crate at
[`tools/no-python-probe`](../../tools/no-python-probe/). It writes local,
ignored evidence to
[`tools/no-python-probe/artifacts/report.json`](../../tools/no-python-probe/artifacts/report.json).
The initial Homebrew Python 3.15 attempt and the intermediate pinned-runtime
attempt are retained separately under the same ignored artifacts directory.
These reports contain machine-local paths and are not milestone attachments;
copy reviewed evidence to the qualification evidence store before attaching it.

## Host and pinned inputs

The final run used macOS 26.5.1 on Apple Silicon (`Darwin 25.5.0`, `aarch64`),
with `rustc` and Cargo 1.98.1; the compiler commit was
`48a229ceaefd4985c50990b14116b6d856af0985`. The standalone crate has a
committed lockfile and no third-party crates. `/usr/bin/sandbox-exec` is
available on this host; Apple's local manual page marks it deprecated.

The control interpreter was the existing qualification-state CPython 3.12.15
runtime at `$STATE/ami-rust-python-bootstrap/runtime/python/bin/python3.12`.
Its observed SHA-256, `aed8ed802d0387d6831dead5885840e4e2ff3a7984dd7297e9a5f4466e9cda1d`,
matches the pinned macOS runtime hash in `release/ci-python-inputs.json`. The
earlier Python 3.15 run is retained as a first exploratory attempt only; the
pinned 3.12.15 run below is the result to assess.

To reproduce from the repository root after setting `STATE` to the recorded
qualification-state directory:

```sh
rustup run 1.98.1 rustc -Vv
rustup run 1.98.1 cargo test --locked --offline --manifest-path tools/no-python-probe/Cargo.toml
rustup run 1.98.1 cargo build --locked --offline --manifest-path tools/no-python-probe/Cargo.toml
tools/no-python-probe/target/debug/no-python-probe --python "$STATE/ami-rust-python-bootstrap/runtime/python/bin/python3.12"
```

The crate's unit test checks its SHA-256 implementation against the standard
`abc` vector. The harness hashes its declared components before each case and
after the run. Those observed hashes are useful evidence and drift checks, not
committed trust pins or protection from a same-user path replacement race.

## Positive controls and sandboxed refusals

Four explicit, owned positive controls ran outside the sandbox to prove that
each negative fixture reaches the intended interpreter route. They execute
only the pinned interpreter with fixed print-only code, an owned shebang file,
an owned Rust descendant control, or an owned C embedding fixture. The
embedded fixture was built locally with `/usr/bin/clang` against the pinned
runtime and was executed only for this unconfined positive control. These
positive controls do not establish sandbox network or file-write restrictions.

| Case | Result | Evidence |
| --- | --- | --- |
| Direct Python positive control | Pass, exit 0 | Pinned CPython prints the direct marker and `PYTHON_VERSION=3.12.15` with `-I -S`. |
| Descendant Python positive control | Pass, expected control exit 92 | An owned Rust descendant starts the pinned interpreter and captures the direct marker. |
| Absolute Python shebang positive control | Pass, exit 0 | The owned shebang fixture uses the absolute interpreter path and prints its marker. |
| Embedded Python positive control | Pass, exit 0 | The owned C fixture initializes Python and prints its embedding marker. |
| Sandboxed native positive | Pass, exit 0 | `/usr/bin/true` starts under the generated profile. |
| Sandboxed direct absolute Python | Refused, `EPERM` (1), control exit 77 | The direct marker is absent. |
| Sandboxed descendant absolute Python | Refused, `EPERM` (1), control exit 78 | The descendant inherits the refusal; the direct marker is absent. |
| Sandboxed absolute Python shebang | Refused, `EPERM` (1), control exit 77 | The shebang file is allowlisted; its absolute interpreter is denied and its marker is absent. |
| Sandboxed unlisted embedded fixture | Refused, `EPERM` (1), control exit 77 | The C fixture's executable path is outside the allowlist; its embedding marker is absent. |

The report records the exact commands, return codes, stdout, stderr, and marker
checks for all cases. No Python marker appeared in a sandbox refusal output.
The fixture's Python dependency is found through `otool`, and its `@rpath`
reference resolves through its `LC_RPATH` to the pinned `libpython3.12.dylib`,
which is hashed and kept outside the process-exec allowlist. This is a
reviewed test policy choice: dependency inspection does not automatically
construct or enforce the allowlist.

## Limits that keep the status partial

The profile denies by default, imports Apple's `system.sb`, denies network and
file writes, and allows process execution only for the probe, `/usr/bin/true`,
and the owned shebang fixture. It allows process-fork so the descendant test
can verify inherited enforcement. No `PATH` blacklist is used.

The controls observe caller-visible `EPERM`; this run does not qualify an
independent per-exec audit stream that records every path when arbitrary code
catches or suppresses a denial. The sandbox refuses the known dynamic fixture
because its executable path was deliberately excluded. It does not identify
Python semantics inside a binary already allowed to execute. Static, renamed,
or otherwise opaque embedded runtimes cannot be recognized by exec filtering;
no universal language detector is claimed.

The harness recursively inspects Mach-O load references, resolves absolute
`LC_RPATH` and `@loader_path` dependencies, excludes each dylib's own
`LC_ID_DYLIB` install name, and hashes addressable files. The report retains
unresolved Apple dyld shared-cache paths such as `/usr/lib/libSystem.B.dylib`
and CoreFoundation; this prevents a complete hash-verified closure claim. It
also keeps any unresolved loader-relative dependency as an explicit edge.
The production design still needs reviewed source/build provenance and a
complete declared closure, including a defined OS runtime boundary.

This run qualifies macOS only. There was no Linux runner available. A Linux
candidate is an unprivileged Landlock `EXECUTE` ruleset with `no_new_privs`,
plus a parent-child `ptrace` supervisor that follows fork/clone descendants
and records or blocks out-of-allowlist `execve` and `execveat`; a seccomp filter
would close bypass routes. That design must be implemented and tested on the
actual Ubuntu 24.04 runner, including Landlock ABI support, Yama/ptrace policy,
shebangs, `AT_EMPTY_PATH`, and thread/descendant races. This has not been run.

Until a supported macOS enforcement and observation mechanism, complete
reviewed component identities, and Linux positive/counterprobes are qualified,
RC0-A4 remains open.
