# Linux no-Python enforcement proof design

Status: implementation and cross-compilation checks are ready for a native
Ubuntu 24.04 x86-64 run. No Linux runtime result has been observed from this
macOS environment. RC0-A4 accepts only evidence produced by the native Linux
runner.

## Enforcement design

The standalone standard-library-only crate is
[`tools/linux-no-python-probe`](../../tools/linux-no-python-probe/). Each
policy case runs in a fresh, single-threaded probe process. It queries the
Landlock ABI, sets `PR_SET_NO_NEW_PRIVS`, creates a Landlock ruleset handling
only `LANDLOCK_ACCESS_FS_EXECUTE` and `LANDLOCK_ACCESS_FS_READ_FILE`, adds
exact-file rules, and calls `landlock_restrict_self`. Landlock restrictions
are inherited by future children. The child then installs a seccomp-BPF filter
with thread synchronization. The filter checks `AUDIT_ARCH_X86_64`, rejects
x32 syscall numbers, and returns `EACCES` for `execveat` and `memfd_create`.
Unsupported Landlock, failed rule setup, or failed seccomp installation fails
the case before its control action. The implementation follows the Linux
kernel's [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
and [seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html);
the x86-64 syscall numbers match the kernel's
[`syscall_64.tbl`](https://github.com/torvalds/linux/blob/v6.8/arch/x86/entry/syscalls/syscall_64.tbl).

The report makes both allowlists reviewable. The executable list contains the
probe (for a descendant control), `/usr/bin/true` after canonicalization, the
absolute-shebang script, the C embedding fixture, and the ELF dynamic loader.
The readable-file list contains only those ELF files' observed runtime
libraries, the loader cache when present, and an empty `/etc/ld.so.preload`
when present. The runner Python executable and its dynamically loadable
`libpython` are excluded from both rights. Paths are canonicalized and SHA-256
digests are recorded; file identity is checked when a Landlock rule is opened,
and inputs are rehashed between cases. These checks detect ordinary changes
during a run but do not authenticate files against replacement by a same-user
actor.

## Controls and evidence

Python is resolved from `--python` or `python3` on the runner's `PATH`. The
report records its canonical path, observed version, SHA-256, raw version
command, and whether the path was caller-supplied or resolved from the runner's
`PATH`. It labels either selection as test-only and sets
`supported_no_python_path` to `false`; a supplied path/hash is observed, not
authenticated by the probe. The fixture interpreter and its shared library
are detector inputs, not a supported execution path.

Before any policy-denial case, the probe runs direct Python, Python started by
an owned child process, an absolute Python shebang, and a C fixture that loads
the discovered `libpython` by `dlopen` and runs a marker. The fixture is
compiled with `cc` and `-ldl`, without Python headers or a startup link to
`libpython`; `readelf` and `ldd` outputs are retained and checked for that
shape. The runtime library path and hash are recorded. `/etc/ld.so.preload`
must be absent or empty because a nonempty system preload could run before
Landlock is installed.

For the allowed-fixture denial, the policy child captures the C fixture's
stdout and stderr, then reports those streams in base64 fields on its own
stdout. The parent decodes the nested stderr and checks both `EACCES` and the
exact observed `libpython` path. Refusal diagnostics omit the Python marker;
that marker is evidence only when it comes from executed Python output.

The positive detector controls finish before sandbox denials. `/usr/bin/true`
must then execute successfully under the native policy. Negative controls
attempt direct absolute-path Python execution, an absolute-shebang script,
Python execution by an allowed descendant, `dlopen` from the *allowed*
embedding fixture, direct invocation through the allowed ELF loader,
`execveat(AT_EMPTY_PATH)` targeting allowed `/usr/bin/true`, and
`memfd_create`. Cases preserve exact argv, exit code or signal, launch errno,
duration, raw output bytes as base64, decoded text, byte counts, and truncation
state. A distinct marker must remain absent when its Python target is denied.

Each spawned command has a 20-second wall-clock deadline. Timeout handling
kills its process group, waits briefly for output pipes to drain, and retains
at most 64 KiB per output stream while continuing to drain excess bytes. The
report is created with `create_new`, mode `0600`, and a unique name beneath the
requested output directory; an earlier report is never overwritten.

## Limits and interpretation

Landlock enforces only the named filesystem rights in these cases. The
seccomp filter closes the tested `execveat` and anonymous-memfd routes; it is
not a general syscall or network sandbox. The harness preserves the raw
outcomes of its named controls, but it has no independent audit stream for
every failed execution or library-load attempt made by arbitrary code. Code
that catches and hides a denied attempt is outside the observation guarantee.

The dynamic fixture demonstrates that an allowed C executable can reach
`dlopen`, while the closed read/execute mapping prevents that fixture from
loading the identified `libpython`. It does not detect all embedded runtimes,
Python implementations, or alternate library-loading techniques. An allowed
binary could statically contain a runtime or implement Python. Production
acceptance still needs reviewed source, build inputs, complete dependency
closure, exact executable hashes, and producer provenance. This probe's ELF
closure covers only its own controls.

The test needs a working `python3` with a dynamically loadable shared
`libpython`, `cc`, `readelf`, and `ldd`. Missing prerequisites, unsupported
Landlock, changed inputs, unexpected markers or exit codes, or incomplete
observations must fail the run; they are not skips. This scope is native
Ubuntu 24.04 x86-64. It does not cover other Linux distributions, architectures,
container configurations, or macOS. Building or cross-compiling on macOS does
not establish Linux enforcement.

## Native Ubuntu command

From the repository root on an Ubuntu 24.04 x86-64 runner with Rust 1.98.1 and
the listed Python/C/binutils prerequisites:

```sh
rustup run 1.98.1 cargo test --locked --offline \
  --manifest-path tools/linux-no-python-probe/Cargo.toml
rustup run 1.98.1 cargo run --locked --offline \
  --manifest-path tools/linux-no-python-probe/Cargo.toml -- \
  --self-test --output "$RUNNER_TEMP/rc0-linux-no-python"
```

Review `overall`, `policy.allowed_executables`, `policy.readable_files`,
`python_control`, `embedded_control`, and every `cases[]` raw outcome in the
resulting JSON report. A Linux PASS is valid only when this native command
actually runs to completion.
