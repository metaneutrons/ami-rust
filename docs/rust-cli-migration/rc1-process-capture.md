# RC1 bounded external-command capture

This partial [RC1 delivery](https://github.com/metaneutrons/ami-rust/issues/71)
adds one noninteractive POSIX process adapter to the shared Rust core. It does
not activate a consumer command, authenticate a publisher, or close RC1.

## Invocation and output

The caller supplies an absolute executable, absolute working directory, exact
OS-string arguments and a complete replacement environment. There is no shell,
inherited environment, PATH fallback or interactive stdin. The caller remains
responsible for selecting and checking the executable's identity, host profile
and permitted environment. Absolute paths alone do not establish trust.
Supported verifier tools keep the caller's credentials. The embedding process
must own this child's reaping and must not change SIGCHLD disposition or install
a competing reaper during capture. Ignored SIGCHLD and `SA_NOCLDWAIT` are refused
before spawn. A detected `ECHILD` loses the PID reservation: cleanup reports the
loss and refrains from signalling that potentially reused numeric group.

The adapter captures stdout and stderr independently through nonblocking pipes.
Each stream has a separate byte bound; reads continue in bounded, alternating
passes so one full pipe cannot indefinitely starve the other. A nonzero exit or
terminating signal is preserved as an actual child status, not interpreted as
a successful verifier result. Failure retains bounded partial diagnostics,
the original cause, the collected child status and any separate cleanup error.

The existing publisher profile can select 60 seconds per invocation, 4 MiB of
stdout, 64 KiB of stderr and a two-second termination grace. The orchestrator
still needs to enforce its 300-second total authentication budget. These are
host-operation profiles, not restrictions on AROS applications.

## Lifecycle

Each invocation starts a new process group. Deadline, cancellation, pipe-limit
and capture failures send TERM, drain bounded diagnostics during the grace
period, then send KILL and reap the direct child. A cancellation-callback panic
also cleans up before resuming unwinding. `waitid` with `WNOWAIT` keeps the
direct child's PID reserved until group signalling has finished. The adapter
does not signal a group after its direct child has been reaped.

After observing child exit, a final bounded read pass collects its buffered
tail before distinguishing EOF from a descendant retaining a writer. Ordinary
completion reaps the direct child. A same-group descendant retaining an output
pipe causes refusal and group cleanup; a descendant that closed both pipes may
outlive ordinary completion.

This is a process-group adapter, not process containment. Escaped sessions or
groups, aggregate descendant RSS, workspace growth and no-Python observation
need the separate host observer before affected public paths are activated.
Successful signal delivery is not proof that every descendant has disappeared.
The polling quantum is 25 ms; scheduling, spawn, callbacks and kernel waits are
not hard real-time bounds. The direct child's wait is required to avoid leaving
a zombie, including after forced termination.

## Verification

Review found two errors in the initial, unaccepted draft: extracting the exit
status cleared the RAII completion flag and could signal a reused group after
reaping; reading before observing exit could misclassify a final buffered write
as a retained pipe. Both have regression controls. Failed development runs are
retained separately from final exact-source results.

The fixtures cover explicit arguments/environment/cwd/null stdin, both streams,
nonzero and signal exits, independent byte caps, timeout and cancellation,
panic cleanup, a pipe-retaining same-group descendant and a closed-pipe
descendant that must survive ordinary completion. The fixture process is the
native Rust test executable; no interpreter is invoked. Both-host CI and the
later observed consumer integration remain separate acceptance evidence.
