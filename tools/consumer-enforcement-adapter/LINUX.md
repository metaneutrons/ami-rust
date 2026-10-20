# Linux consumer command enforcement adapter A1

This qualification adapter runs one real consumer command under a
Linux x86-64 Landlock and seccomp policy. It reuses the policy vocabulary and
report schema from the private macOS A1 adapter. It is intended for review and
one native Ubuntu 24.04 x86-64 validation; a macOS cross-check is not runtime
evidence.

## Build and run

The crate has no third-party dependencies. Build it on the selected Ubuntu
runner with the pinned Rust 1.98.1 toolchain, or cross-check its Linux target
from macOS:

    cargo build --locked --offline --release
    cargo check --locked --offline --target x86_64-unknown-linux-gnu

The command mode is:

    target/release/consumer-enforcement-adapter \
      --policy /absolute/path/policy.txt \
      --report-dir /absolute/path/new-report-directory \
      --run -- /absolute/path/consumer-command ARG...

The adapter requires a new report directory, preserves the original child exit
code and signal in report.json, and returns that child status when evidence is
valid. A raw-capture, replay, expected-hash, or report-write failure returns
125 and reports the original child status on stderr. It captures at most 1 MiB
per stream and keeps draining the child output. The existing outer Supervisor
must bound wall time, memory, disk use, and process-group cleanup; this
adapter records that requirement but does not verify that a Supervisor is
present or that it performs cleanup. The report directory must be disjoint
from every declared child write-tree: equality and overlap in either ancestor
direction are rejected before the command starts.

## Policy

consumer-policy-v1 accepts the existing A1 directives: exec, exec-hash,
exec-future, exec-derived, exec-derived-tree, deny-exec, deny-library,
read-file, read-directory, read-library, read-tree, write-tree, env, cwd, and network. Linux
supports two narrow execution-tree directives for paths that do not exist
until the command runs:

    exec-tree installer-stage /owned/work/exec-staging
    exec-tree target-generated-buildscripts /owned/project/target/debug/build
    exec-derived-tree consumer-build-parent /owned/project/target/consumer-build-parent <source-closure-sha256>
    exec-derived-tree consumer-state-parent /owned/work/consumer-state-parent <source-closure-sha256>

Each exec-tree directory must already exist and be a strict descendant of a
declared write-tree. Only the two reviewed roles above are accepted. Landlock
implements these as path-beneath rules: every executable under the named tree
can run, including descendants created during the command. The tree therefore
must be a narrowly prepared, source-reviewed staging or generated-buildscript
area. Do not point it at /bin, /usr/bin, an entire SDK/source tree, the project
root, or a general Cargo target root. Create the staging directory before the
run. The command can create nested directories and files below that managed
root.

exec-derived-tree is limited to consumer-state-parent and
consumer-build-parent. The named parent must be an existing canonical empty
directory, owned by the current effective user with mode 0700, and a strict
descendant of a declared work, state, or target write-tree. The target
directories produced by the command can be absent when policy is loaded; the
adapter grants descendant execution below this one private parent so the real
command can create them. This does not authorize the whole project, source,
SDK, Cargo target, or system tree. Exact known tools remain separate policy
entries and should use exec-hash.

The source-closure digest is recorded as a policy declaration and is not
verified by the adapter. The caller must bind it to the reviewed compiler,
vendor inputs, build scripts, source recipe, and other command inputs. This
trusted recipe evidence does not contain malicious source or guarantee
detection of every runtime.

An exact exec or exec-hash path grants EXECUTE and READ_FILE only for that
file. An exec-future or exec-derived path must be under a declared write-tree.
If the executable is absent at policy load, it must also be under an existing
reviewed exec-tree or exec-derived-tree; the adapter resolves nested missing
components against the nearest existing canonical ancestor. exec-future
checks the declared byte hash before and after the command when the path exists
at policy-load time. If it is absent then, a matching post-run file hash is
only an observation of the output file; it does not prove which bytes were
executed. A self-removing executable cannot pass the post-run hash check. Use
exec-derived PATH SOURCE_CLOSURE_SHA256 for a transient executable whose
identity is bound to separately reviewed source/build evidence. The adapter
records that digest as declared but does not verify it. For absent or
self-removing executables, the source/recipe closure and its binding to the
managed path remain external review evidence.

read-library PATH SHA256 resolves each supplied lookup path to an existing
canonical regular file and verifies every declared hash before admission.
Distinct verified aliases to the same canonical target share one Landlock
READ_FILE rule and one read_library_mappings report row; a repeated identical
lookup directive is refused. The canonical target hash is checked again after
the command. This does not authorize executing the library. A path
overlapping deny-library, an executable allowance, or a writable tree is
rejected. Library mappings are listed separately from the executable allowlist
in report.json.

read-directory PATH accepts an existing canonical directory and grants Landlock
READ_DIR only. It does not grant READ_FILE or EXECUTE, so a directory parent can
be listed without making a denied library's bytes readable. Landlock path-beneath
rules permit directory listing below the named root, so names in descendant
directories may be visible; the report lists this allowance separately. Keep
read-file and read-library for inputs whose contents are intentionally needed.

read-tree ROLE PATH grants read-file and directory-listing access below that
tree. write-tree ROLE PATH grants reads and the supported write, create,
remove, rename, symlink, and truncate rights below it. Neither directive grants
execution. Grant the actual ELF `PT_INTERP` loader exact hashed execution as well
as reads; other ELF dependencies receive individually reviewed read-file entries.
Native subprocesses using null stdin also need exact `read-file /dev/null`
access. Without it, `Command::output` can fail before attempting an exec, so
that error alone cannot establish interpreter refusal. The native descendant
positive and isolated missing-stdin counterprobe distinguish these cases.
deny-library PATH is enforced by absence of a matching
Landlock read allowance; the parser rejects a policy when a read-library
mapping, read tree, write-tree, or executable rule would also grant access to
that path. Thus broad system library trees are unsuitable when a denied library
sits inside them.

network outbound permits ordinary network syscalls. The default and
network-deny profiles block Linux x86-64 socket operations and io_uring_setup
with seccomp, with one cause-specific exception: `socketpair` accepts only
`AF_UNIX`, `SOCK_SEQPACKET`, protocol `0`, and the same type with optional
`SOCK_CLOEXEC`. Rust's Unix process-spawn path uses this unnamed local pair for
its private child handshake when a `pre_exec` hook requires `fork`. The
exception creates no addressable or public-network socket. Other socketpair
domains, types, and protocols still return `EACCES`; `socket`, `connect`,
`bind`, `listen`, send/receive entry points, and `io_uring_setup` remain
denied. The filter compares the low 32 bits of the three integer arguments,
matching the kernel syscall parameters. Network-outbound behavior is
unchanged. In all cases the filter also denies x32 syscall numbers,
`execveat`, and `memfd_create`, following the accepted
tools/linux-no-python-probe mechanism.

The adapter requires Landlock ABI 2 or newer because its write policy handles
REFER. It requests the filesystem rights known through ABI 5, including device
ioctl denial, and records the ABI and handled-rights mask. Later ABI additions
are outside this prototype's mask and scope; they do not disable the reviewed
EXECUTE and READ_FILE rules. Landlock network rights are not used; the network
deny profile is the listed seccomp syscall filter. See the kernel's
[Landlock userspace API documentation](https://docs.kernel.org/userspace-api/landlock.html)
for its handled-rights and ABI compatibility model. This known-rights subset
does not claim to constrain every operation that newer kernels may add.

Example shape for a reviewed project policy (replace every path and digest
with observed inputs; this is not a complete system runtime closure):

    consumer-policy-v1
    exec-hash /owned/toolchain/bin/cargo <64-hex-sha256>
    exec-hash /owned/toolchain/bin/rustc <64-hex-sha256>
    exec-hash /usr/bin/bash <64-hex-sha256>
    exec-derived /owned/project/target/debug/build/some-crate/build-script-build <reviewed-source-closure-sha256>
    exec-derived-tree consumer-build-parent /owned/project/target/consumer-build-parent <reviewed-source-closure-sha256>
    exec-tree target-generated-buildscripts /owned/project/target/debug/build
    deny-exec /usr/bin/python3
    deny-library /usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0
    exec-hash /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 <64-hex-sha256>
    read-file /dev/null
    read-library /owned/sdk/lib/libclosed-sdk.so <64-hex-sha256>
    read-file /usr/lib/x86_64-linux-gnu/libc.so.6
    read-tree source /owned/project
    read-tree sdk /owned/sdk
    read-tree toolchain /owned/toolchain
    write-tree target /owned/project/target
    write-tree cargo-home /owned/cargo-home
    write-tree home /owned/home
    env CARGO_HOME=/owned/cargo-home
    env CARGO_NET_OFFLINE=true
    env HOME=/owned/home
    env RUSTC=/owned/toolchain/bin/rustc
    network deny
    cwd /owned/project

The example intentionally shows no broad executable directory. Its
deny-library example is valid only if none of the read/write roots contains
that file; the parser checks this. Before using a policy, review every
executable, source/buildscript identity, shebang interpreter, ELF interpreter,
runtime library, generated path, and network requirement for the actual
consumer command.

## Native controls

The --control modes can be invoked through --run and the same policy:

    --control positive [--path /owned/work/positive-output]
    --control positive-fork-spawn [--path /owned/work/positive-output]
    --control socketpair-refusal
    --control direct --python /absolute/path/to/python3
    --control transitive --python /absolute/path/to/python3
    --control shebang --script /owned/work/python-shebang
    --control embedded --binary /owned/work/embedded-fixture --library /absolute/path/to/libpython.so
    --control seccomp
    --control future-materialize --source /owned/work/native-fixture --path /owned/work/exec-staging/nested/fixture

For the direct and descendant controls, allow this adapter executable and the
native command's runtime files, but omit EXECUTE permission for the Python
binary. For the shebang control, allow the script itself and its declared
absolute interpreter line, then omit EXECUTE permission for that interpreter.
For the embedding control, allow the fixture's exact executable, list its ELF
runtime closure, and omit READ_FILE for the named libpython. The fixture
source is controls/embedded-libpython.c; on the Linux runner build it with:

    cc -O2 -Wall -Wextra -Werror -o embedded-fixture controls/embedded-libpython.c -ldl

The seccomp control checks execveat(AT_EMPTY_PATH) and memfd_create return
EACCES. The future-materialize control exercises nested directory creation,
execution under the designated subtree, and the report's transient-hash
distinction.

The positive-fork-spawn control installs an empty `pre_exec` hook to force
Rust's fork-based subprocess path and prints
`ADAPTER_NATIVE_FORK_DESCENDANT_POSITIVE` after its child succeeds. Its hook
does no allocation or locking. The socketpair-refusal control verifies that
the two permitted private local pair forms can exchange bytes through
`read`/`write`; it then checks that disallowed socketpair arguments and the
network socket syscalls return `EACCES`. Its denied calls use an invalid file
descriptor or null address and do not contact an external endpoint.

tools/linux-no-python-probe remains the accepted native direct, transitive,
absolute-shebang, and embedded-library control harness. This adapter adds an
actual --run command path and does not replace that detector suite.

## Limits

Landlock path rules bind to opened filesystem objects and inherit into
descendants. Exact file rules support exact paths; exec-tree intentionally
grants a reviewed subtree because Landlock cannot authorize a missing future
file by a future byte hash. Source/build closure evidence is still required for
all such generated or transient executables. The adapter does not claim a
universal interpreter or embedded-runtime detector.

The seccomp network-deny profile blocks socket syscalls created by the child;
it does not revoke a network descriptor inherited from the caller. Run it
inside the existing clean Supervisor process environment. Seccomp is not a
general syscall sandbox. The child shares the Supervisor's process group so
its established timeout and cleanup can stop the full command tree.

Cross-compilation checks Rust types and conditional compilation only. Qualify
Landlock/seccomp behavior, the controls and actual consumer commands on native
Ubuntu 24.04 x86-64 before using their results as acceptance evidence.
