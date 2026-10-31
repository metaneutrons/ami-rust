---
title: ami-rust 0.2 initiative plan
---

# Initiative plan: ami-rust 0.2 with everyday AROS APIs on ABI1 and ABI11

Epic: https://github.com/metaneutrons/ami-rust/issues/52
Decision state: accepted by the maintainer on 2026-10-31; proposed in PR #64

## Outcome and boundaries

ami-rust 0.2 shall let a Rust application on PC x86-64 AROS do the everyday
things that 0.1 leaves to raw `aros-sys` calls: walk directories and manage
files, read arguments and environment variables, measure and wait for time,
draw into bitmaps and windows, open file requesters, localise strings and
integrate with Workbench. Each capability is a safe, task-affine crate on top
of a reviewed raw layer, in the pattern of `aros` / `aros-sys` and
`aros-mui` / `aros-mui-sys`.

The measured baseline on 2026-10-31 (`main`, release 0.1.0):

- `bindings/aros-api.json` allows 59 functions: 25 muimaster, 13 DOS, 12 Exec,
  6 Intuition, 3 Utility.
- `aros` offers entry, context, files, optional libraries, signals, private
  ports and messages. Its bridge registries are fixed: 16 files, 4 optional
  libraries, 2 private ports, 4 signal slots and 8 messages of at most 256
  bytes.
- `aros-mui` covers every public standard MUI class on both ABIs.
- Missing: directory iteration, delete and rename, environment variables,
  argument templates, device I/O, time, graphics, windows, requesters, locale
  and Workbench integration.

Planned crates, in addition to the existing four:

| Crate | Library or device | Milestone |
| --- | --- | --- |
| `aros-timer` | `timer.device` | M3 |
| `aros-graphics` | `graphics.library` | M5 |
| `aros-intuition` | `intuition.library` | M6 |
| `aros-asl` | `asl.library` | M7 |
| `aros-locale` | `locale.library` | M8 |
| `aros-icon`, `aros-workbench` | `icon.library`, `workbench.library` | M9 |

Core additions (M1, M2) land in `aros`. Each new crate has a matching `-sys`
crate or, where the raw surface is small, raw declarations in `aros-sys`; the
choice is recorded in the crate's milestone.

Non-goals for 0.2: a `std` port (analysed separately in
[the `std` feasibility analysis](std-port-feasibility.md)), other CPU
architectures, processes and threads, networking, datatypes, CyberGraphX,
AHI, input and console devices, commodities and ARexx, and publication on
crates.io. These are candidates for 0.3.

## Design and decisions

**ABI policy.** ABI1 is the upstream standard. ABI11 is Deadwood's AROS port
and is supported alongside it. Every new item is available on both ABIs by
default. An item may be ABI-specific only when a header or library difference
requires it; it is then declared as such in its documentation and appears on
the generated ABI differences page, which is cross-checked against the
declarations. If dual-ABI support of an item is disproportionately complex,
the item is delivered for the ABI that supports it and the other ABI is
recorded as a limitation. ABI1-only items are never removed to obtain a common
subset.

**Dual-ABI assessment.** Compared at AROS-NX `e0d5e36` and Deadwood `fbc242c`
(the pinned inputs of 0.1):

- Vector tables are identical for dos, utility, intuition, graphics, layers,
  timer, keymap, input, console, asl, locale, icon, workbench, datatypes,
  iffparse, commodities, diskfont, cybergraphics, rexxsyslib and gadtools.
  Deadwood's exec appends 7 vectors and has none missing.
- Public headers are identical for every library above except three
  differences: `devices/timer.h` (`timerequest` uses `struct timeval` on ABI1
  and `struct timeval32` on ABI11), `dos/dos.h` (`FIBB_HOLD` exists only on
  ABI1) and the exec structures `Task`, `SignalSemaphore`, `MemHeader`,
  `MsgPort` and `Library`, which carry SMP spinlock fields only on ABI1.
- ABI11 passes at most six integer arguments in registers. The candidate
  libraries contain these functions with more than six arguments: graphics 14,
  cybergraphics 9, layers 6, intuition 6, datatypes 3, workbench 2, icon 1,
  dos 1; asl, locale, iffparse, commodities, diskfont, exec and timer have
  none.

Consequences: no crate is skipped for ABI reasons. Struct layouts stay behind
the C bridge as opaque handles with layout oracles, so Rust never depends on
a per-ABI field offset where avoidable. Functions with more than six
arguments need a generated stack-argument adapter on ABI11 (M4). The
comparison used throwaway scripts; its method and pins are recorded here
rather than committed.

**Resource model (M1).** The fixed registries of 0.1 are the main obstacle for
new crates: a timer needs a port and a signal, and a window needs a library, a
port and a signal. M1 replaces fixed registry sizes by allocation-bounded
capacities where Exec permits, keeps `ErrorKind::Limit` as the deterministic
failure, and documents the limits that remain. Signals stay capped by the
32-bit task mask.

**Device I/O (M1).** `OpenDevice`, `CloseDevice` and request allocation are
added with typed request ownership and `DoIO`, `SendIO`, `WaitIO`, `AbortIO`
and `CheckIO` semantics. A request that is aborted, dropped or forgotten
leaves no ledger entry and no pending message.

**`aros-async` is a stretch goal, not a 0.2 commitment.** Timer is committed:
it is needed by windows, events and any waiting. An executor needs no bridge
change, because it can be built from public signal, port and timer APIs. Its
API (wakers, `!Send` futures, integration with other signal sources such as
the MUI event loop) is the risky part and is better frozen after M1 to M3
have been used. It is therefore delivered as an experimental, feature-gated
crate (S1) with an explicit cut line: if any committed milestone is late it
moves to 0.3 without affecting the release.

**Intuition is the hub.** Requesters, AppWindows and drawing into windows all
need a window handle. `aros-intuition` is therefore placed before `aros-asl`
and `aros-icon`/`aros-workbench`. Graphics is first tested on offscreen
bitmaps so it does not depend on a window.

**Common acceptance (C).** Every crate milestone must meet these in addition
to its own criteria:

- C1: The raw allowlist entries are reviewed; per-ABI backends are generated
  and committed; the checker reproduces them against both pinned SDKs and
  verifies vectors and layouts.
- C2: Safe handles are task-affine and borrow `Context`; cleanup is explicit
  and also happens on drop; no raw pointer appears in the safe API.
- C3: `#![deny(missing_docs)]`, compiled examples and a generated reference
  page, including the ABI availability notes.
- C4: A qualification application runs to completion on the ABI1 and ABI11
  native baselines with zero registry residue, and binary identities are
  recorded.
- C5: Negative cases (limit, invalid input, wrong task, cancelled operation)
  are tested.
- C6: No new crate depends on `std`; `no_std` with optional `alloc` as in
  `aros`.

## Delivery and acceptance

### M1: Resource model and device I/O

Execution: https://github.com/metaneutrons/ami-rust/issues/53
Dependencies: none

- M1-A1: Replace the fixed registries for files, libraries, ports, signals
  and messages by documented, allocation-bounded capacities; the remaining
  limits are documented in the crate and in `docs/`.
- M1-A2: Opening more than the 0.1 limits succeeds on both ABIs; exhaustion
  returns `ErrorKind::Limit`; forgetting handles still returns every slot.
- M1-A3: Provide device open and close and typed I/O requests with `DoIO`,
  `SendIO`, `WaitIO`, `AbortIO` and `CheckIO`; the per-ABI `IORequest` layout
  stays behind the bridge.
- M1-A4: Aborted, dropped and forgotten requests leave no pending message and
  no ledger entry, verified natively on both ABIs.
- M1-A5: The 0.1 qualification application still passes unchanged (no
  regression of the 0.1 API).

### M2: Directories, environment and arguments

Execution: https://github.com/metaneutrons/ami-rust/issues/54
Dependencies: M1

- M2-A1: Directory iteration (`Lock`, `Examine`, `ExNext`), metadata, create
  directory, delete and rename in `aros`, with the `FIBB_HOLD` difference
  declared as ABI1-only.
- M2-A2: Local and global variables (`GetVar`, `SetVar`, `DeleteVar`) and the
  current directory.
- M2-A3: An argument template parser in the AROS `ReadArgs` language
  (keywords, `/A`, `/K`, `/S`, `/N`, `/M`, `/F`) over `Context::args()`,
  documented and tested against known AROS behaviour.
- M2-A4: A native test creates, lists, renames and deletes entries on a RAM
  disk on both ABIs with zero registry residue.

### M3: `aros-timer`

Execution: https://github.com/metaneutrons/ami-rust/issues/55
Dependencies: M1

- M3-A1: A monotonic clock (`ReadEClock`) with documented resolution, and a
  blocking sleep.
- M3-A2: Asynchronous timer requests with start, abort, signal mask and
  completion check, usable from `wait_signals`; cleanup on drop and abort.
- M3-A3: System time (`GetSysTime`) with a tested conversion from the AROS
  epoch.
- M3-A4: The `timerequest` layout difference (`timeval` and `timeval32`) is
  covered by the layout oracle on both ABIs.
- M3-A5: Sleep accuracy is measured natively on both ABIs and the observed
  overshoot is recorded; no tolerance is assumed in advance.

### M4: Stack-passed arguments on ABI11

Execution: https://github.com/metaneutrons/ami-rust/issues/56
Dependencies: none

- M4-A1: The generator emits a reviewed ABI11 adapter for calls with seven or
  more arguments; larger counts are rejected at generation time.
- M4-A2: A synthetic native probe verifies every argument position and the
  library base for 7 to 12 arguments.
- M4-A3: The hand-written `MUI_RequestA` adapter is replaced by the generated
  one or proven equivalent.
- M4-A4: The ABI1 path is unchanged, since ordinary `extern "C"` calls place
  the extra arguments on the stack.

### M5: `aros-graphics`

Execution: https://github.com/metaneutrons/ami-rust/issues/57
Dependencies: M1, M4 (for functions with more than six arguments)

- M5-A1: Owned `BitMap` and `RastPort` types, pens and drawing modes, `Move`,
  `Draw`, rectangle fill, ellipse, polygon, text drawing and measurement.
- M5-A2: An offscreen test draws the primitives and compares a deterministic
  pixel digest on both ABIs.
- M5-A3: Blits and other functions with more than six arguments are exposed on
  both ABIs once M4 has landed; otherwise they are declared ABI1-only and the
  milestone is not delayed.
- M5-A4: A `RastPort` borrowed from a window is lifetime-bound to it.
- M5-A5: The allowlist is the reviewed function list in the milestone and
  excludes variadic functions.

### M6: `aros-intuition`

Execution: https://github.com/metaneutrons/ami-rust/issues/58
Dependencies: M1, M3, M5

- M6-A1: A tag-based window builder, minimal public screen locking and
  safe window ownership with deterministic close.
- M6-A2: A typed IDCMP loop for close, key, mouse, refresh and resize events,
  usable from `wait_signals` together with timers.
- M6-A3: Drawing from M5 into a window `RastPort`.
- M6-A4: A native test drives the window by injected input and checks the
  drawn result on both ABIs; coexistence with `aros-mui` is documented.

### M7: `aros-asl`

Execution: https://github.com/metaneutrons/ami-rust/issues/59
Dependencies: M6

- M7-A1: A file requester with a tag-based builder that returns owned paths.
- M7-A2: A native test covers the open and cancel paths, a scripted selection
  and `FreeAslRequest` cleanup on both ABIs.

### M8: `aros-locale`

Execution: https://github.com/metaneutrons/ami-rust/issues/60
Dependencies: M1

- M8-A1: Catalog lookup with built-in default strings, translation from a
  fixture catalog, and date formatting verified against fixed timestamps.
- M8-A2: Memory use is bounded and cleanup is verified on both ABIs.

### M9: `aros-icon` and `aros-workbench`

Execution: https://github.com/metaneutrons/ami-rust/issues/61
Dependencies: M6

- M9-A1: Disk objects (`GetDiskObject`, `PutDiskObject`, `FreeDiskObject`),
  tool types and matching.
- M9-A2: `AppIcon`, `AppWindow` and `AppMenuItem` registration and message
  receipt with cleanup of the message port.
- M9-A3: Drop delivery is tested deterministically by sending an app window
  message to the application's own `AppWindow` (a user drag is not simulated).
- M9-A4: `AddAppIconA` and `SendAppWindowMessage` are exposed on both ABIs
  once M4 has landed.

### M10: Qualify and prepare the ami-rust 0.2 release candidate

Execution: https://github.com/metaneutrons/ami-rust/issues/62
Dependencies: M1 through M9

- M10-A1: Build the exact candidate on macOS ARM64, Linux x86-64 and Linux
  ARM64 for both canonical targets.
- M10-A2: Run the qualification applications of every crate on the pinned
  ABI1 and ABI11 baselines and record source, toolchain, SDK, image, binary
  and evidence identities.
- M10-A3: The documentation (guides, generated reference, ABI differences,
  compatibility, changelog) matches the candidate; `cargo xtask check mui`
  and the other generator checks pass.
- M10-A4: Publication stays a separate maintainer decision.

### S1 (stretch): `aros-async`

Execution: https://github.com/metaneutrons/ami-rust/issues/63
Dependencies: M1, M3

- S1-A1: A single-task executor with local `!Send` futures woken through
  signals; timers and ports as futures; a mask API so other signal sources can
  take part.
- S1-A2: Feature-gated and documented as experimental; `no_std` with `alloc`.
- S1-A3: Cut line: S1 is dropped from 0.2 if any of M1 to M10 is late. It does
  not block the epic.

The initiative is complete when M1 to M10 are accepted against the same plan
revision and exact release candidate. S1 is optional.

## Migration, risks and verification cost

The principal risks are the registry redesign (M1), which every later crate
depends on, ABI11 stack-argument calls (M4), and window and event behaviour
that is hard to drive headlessly (M6). Additions are semver-minor for `aros`.
Each milestone is an independently reviewable pull request or short ordered
series. Native dual-ABI checks run where behaviour changes; the three-host
matrix runs only at M10. A native boot is on the order of minutes, so the cost
per qualification run is recorded during M1 rather than estimated here.

## Decision changes

- 2026-10-31: The maintainer accepted the plan, including the milestone order,
  `aros-async` as a stretch goal with a cut line, and the scope of 0.2. Work
  starts with M1, with the STD-M1 spike of the `std` plan in parallel.
