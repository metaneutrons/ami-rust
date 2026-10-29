# API, lifetime and failure inventory

The facade's global allocator uses public Exec allocation for valid Rust layouts,
with checked sizes, accounting, supported alignment and ownership. Native memory
exhaustion and checked size, accounting or ownership refusal remain possible. The
SDK does not impose the historical 1 MiB per-allocation or 16 MiB heap quotas;
reference-program code, file and whole-memory thresholds do not constrain
arbitrary applications. The fixed startup stack and other stated API capacities
remain unchanged.

The qualified source SDK targets the pinned native x86-64 ABI1 and ABI11
images. Target std, foreign-task APIs, asynchronous callbacks, native
AROS-hosted Rust tools, hardware and other CPU/ABI combinations remain outside
scope. The [compatibility profile](compatibility.md) records the host and target
identities. Qualification is limited to the exact artifact bytes and host
profile it identifies; it does not establish acceptance for another artifact
or release.

## Source-level `aros` public API index

`aros` is the `no_std` task-affine application crate. It contains the qualified
runtime, allocator and core SDK implementation instead of exposing those as
separate application dependencies. `aros-sys` is the raw ABI package. Optional
libraries use focused pairs; the initial pair is `aros-mui` and
`aros-mui-sys`. These source APIs are not yet a stability promise.

The raw `aros-sys` library modules expose the first generated base set:
`exec` covers library, signal and message-port primitives; `dos` covers files,
locks, directory iteration, error retrieval and path operations; `utility`
covers tag-list traversal; `intuition` covers basic windows and BOOPSI object
attributes. All calls require an explicit live library base and remain unsafe.
The committed allowlist is verified against both pinned SDKs before generation.
Variadic functions remain excluded. Nonordinary call shapes require an
explicit reviewed adapter; the seven-argument `MUI_RequestA` call has one for
the ABI11 stack argument.

| Surface | Current signature and semantics |
| --- | --- |
| Entry and status | `aros::entry!(application)` installs the entry for `application: fn(&Context) -> AppStatus`; `aros::entry!(application, alloc)` also installs the global allocator when the default `alloc` feature is enabled. `AppStatus` is `Success = 0`, `Error = 10`, or `Fatal = 20`. |
| `Context` | `Context::args(&self) -> Args<'_>` yields borrowed argument byte slices for the active application frame; `Context::diagnostic(&self, label: &[u8], code: u64)` emits a bounded diagnostic; `Context::statistics(&self) -> aros_sys::SdkStats` returns native resource counters from the raw ABI exposed by `aros-sys`. The context is supplied by the entry and is task-affine. |
| Errors | `ErrorKind` is `Native`, `Input`, `Limit`, `Owner`, `State`, `Eof`, or `ZeroProgress`; `Operation` identifies the operation. `Error { kind: ErrorKind, native: i64, operation: Operation }` is allocation-free and has `kind_code(self) -> u8`. There is no `OutOfMemory` error kind. |
| Paths and files | `BytePath::new(path: &[u8]) -> Result<Self, Error>` rejects embedded NUL and payloads over 127 bytes; `len(&self) -> usize` and `is_empty(&self) -> bool` inspect it. `FileMode` is `ReadExisting`, `CreateTruncate`, or `ReadWrite`. `File::open(context: &'ctx Context, path: &BytePath, mode: FileMode) -> Result<File<'ctx>, Error>` creates an owned context-bound handle. `File::read(&mut self, &mut [u8]) -> Result<usize, Error>`, `File::write(&mut self, &[u8]) -> Result<usize, Error>`, `File::read_exact(&mut self, &mut [u8]) -> Result<(), Error>`, `File::write_all(&mut self, &[u8]) -> Result<(), Error>`, and consuming `File::close(self) -> Result<(), Error>` operate on borrowed buffers; one transfer is at most 64 KiB. |
| Standard streams | `Stdout::new(context: &'ctx Context) -> Result<Stdout<'ctx>, Error>` and `Stderr::new(context: &'ctx Context) -> Result<Stderr<'ctx>, Error>` borrow process handles. `Stdout::write(&mut self, &[u8]) -> Result<usize, Error>` and `Stdout::write_all(&mut self, &[u8]) -> Result<(), Error>` write borrowed buffers; `Stderr::write(&mut self, &[u8]) -> Result<usize, Error>` and `Stderr::write_all(&mut self, &[u8]) -> Result<(), Error>` do the same for standard error. Each single transfer is at most 64 KiB. `Stderr` requires a DOS process and selects `pr_CES`, falling back to `pr_COS`; neither wrapper closes its borrowed handle. A DOS handler may allocate while writing. |
| Libraries and signals | `Library::open(context: &'ctx Context, name: &BytePath, minimum_version: u16) -> Result<Library<'ctx>, Error>` and consuming `Library::close(self) -> Result<(), Error>` manage an owned library reference. `Signal::new(context: &'ctx Context) -> Result<Signal<'ctx>, Error>`, `Signal::post(&self) -> Result<(), Error>`, and `Signal::wait(&self) -> Result<(), Error>` manage a signal in the creating task. |
| Local ports and messages | `Port::new(context: &'ctx Context) -> Result<Port<'ctx>, Error>` creates an owner-task port; `Port::send(&self, message: &mut Message<'ctx>, reply: &Port<'ctx>) -> Result<(), Error>` queues an owned message and reply route; `Port::receive(&self, message: &mut Message<'ctx>) -> Result<bool, Error>` reports whether that message is queued there. `Message::new(context: &'ctx Context, payload: &[u8]) -> Result<Message<'ctx>, Error>` owns at most 256 payload bytes; `Message::copy_to(&self, output: &mut [u8]) -> Result<usize, Error>` copies into caller storage, and `Message::reply(&self) -> Result<(), Error>` replies to a received local message. |
| Synchronous callback | `call<F>(context: &Context, callback: &mut F, input: u64) -> Result<u64, Error> where F: FnMut(u64) -> u64` invokes a callback synchronously; callback state is not retained. |

Owned handles borrow their creating context and remain confined to that task;
the context and handles are neither `Send` nor `Sync`. `aros-sys` is the
separate unsafe raw ABI boundary.

## MUI base set

`aros-mui` opens `muimaster.library` at API version 19 and
`intuition.library` at version 36. `Mui::scope` creates a non-escaping,
task-affine arena. Typed `Object<'scope, C>` handles may be copied, but their
native storage remains owned by that scope. The ownership ledger disposes only
roots; `Application`, `Window`, and `Group` recursively dispose children after
typed `adopt` operations. Repeated ownership transfer, ownership cycles,
cross-scope references, and a second root object for one window are rejected
before a native call.

The shared M4 core supplies sealed classes, builders, inheritance and parent
relations, plus typed build/get/set attributes and typed methods. M5 generates
all 72 public standard classes, their transitive inheritance and ownership
relations, 454 classified attributes, 182 classified methods, and 252 public
values from the canonical dual-ABI model. Safe value kinds cover strings,
retained string arrays, booleans, fixed and pointer-sized integers, checked
enums, and reviewed same-scope object references.

Foreign pointers, incomplete native messages, and unproven retained-resource
contracts require an explicit unsafe raw operation; they are listed rather than
silently omitted. Raw tags, native pointers, class IDs, and vector calls remain
confined to aros-mui-sys. The complete generated safe/typed-unsafe/raw and
ABI-availability inventory is in [the MUI API reference](mui-safe-api.md), with
qualification evidence in [the M5 record](m5-qualification.md).

`aros-mui-sys` exposes the complete reviewed non-variadic muimaster vector set
and the generated public raw class, identifier, value, and message surface.
Both x86-64 backends use the negative pointer-vector layout. ABI1 passes the
library base as the final ordinary C argument; ABI11 places it in `r12` and
otherwise follows the SysV argument registers. No variadic MUI interface is
exposed. Additional architectures require their own qualified vector backend.
The exact M3 candidates completed C-layout comparison and native application
execution on ABI1 and ABI11; see [the M3 evidence](m3-qualification.md).

Global allocator refusal is distinct from a fallible API error. A Rust
fallible allocation operation such as `Vec::try_reserve` reports refusal in
its own error type. The `GlobalAlloc` implementation returns null when native
allocation is refused; if an infallible allocation reaches Rust's allocation
error handler, the installed entry hook follows the nonreturning native fatal
path and ends the current application with status 20. This does not unwind
Rust `Drop`; native registry cleanup runs separately. There is no facade
`ErrorKind::OutOfMemory`, and removing fixed quotas does not remove actual
out-of-memory, overflow or ownership failures.

## Internal implementation and qualification inventory

The following `aros-*` table is internal implementation and qualification
inventory, not a consumer API list or a separate compatibility promise.

| Boundary | Preconditions and enforcement | Native qualification |
| --- | --- | --- |
| aros-sys raw externs and ABI structs | Caller owns valid pointers, buffers, C callbacks and native lifecycle. C/Rust independently compare all 81 exposed layout/scalar values. BPTR is the pinned identity pointer; IoErr remains signed 64-bit. | ABI1..10; malformed ELF/layout copied controls |
| `aros` allocator module | Rust Layout; original base and exact requested layout retained in C intrusive records. Allocate/copy/free realloc leaves old block untouched on refusal; zeroed memory and zero-size request follow the same ownership path. No TLSF private API in product. | ALLOC, CHURN, FAULT1, FAULT9, OOM |
| `aros` runtime module | Native C main alone initializes once and calls one Rust entry. A scoped HRTB closure borrows a non-Send/non-Sync Context; argv borrows valid bounded C storage only while active. C boundary, rather than Context Drop, drains forgotten global resources after Rust returns. | ABI1..10, EXPECTED, FALLIBLE, FORGOT; compile lifetime failures |
| File / borrowed Stdout | BytePath owns at most 128 bytes including NUL; modes explicit, transfers at most 64 KiB. Buffers remain borrowed for synchronous C call. File token consumed before Close even on failure. Stdout never closes its borrowed handle. IoErr captured immediately before any other native call. | FILES, PROTECTED, FAULT2..5/10..12 |
| R1 candidate borrowed Stderr | The owner must be a DOS Process before casting its Task header. Each write selects `pr_CES`, falling back to `pr_COS` when null; neither process-owned handle is registered or closed. The wrapper borrows Context, is neither Send nor Sync, and shares bounded Write/short-transfer/zero-progress/native-error handling with file I/O. Stack-only error formatting does not establish allocation-free DOS handlers. | R3 full48 and production31 records cover redirection, fallback, errors, diagnostics and final M1 regression on exact candidate native bytes. |
| Library | Four owned optional references; mandatory DOS separate. `raw_base` is an explicitly unsafe, lifetime-bounded escape hatch used by typed library crates such as `aros-mui`; ordinary safe consumers receive no arbitrary-call capability. | LIBRARIES, FAULT6/9, STARTFAIL |
| Signal, Port, Message | Owner task only, four signal bits including two port-owned bits; eight static stable messages, 256 bytes each. Product C registry is authoritative queue state. Port destruction detaches local queued messages before DeleteMsgPort; owned bits released exactly once. No foreign or published port. | PORTS, FAULT7..9, forgotten and fatal cleanup cases |
| Synchronous callback trampoline | Rust CallbackFrame remains on the live stack, C cannot retain its address. Owner/key and nested-call guard precede user dereference. No unwind: panic follows nonreturning abort path. | CALLBACKS, CBPANIC; callback-escape compile refusal |
| Diagnostics and fatal boundary | Borrowed label, scalar and fixed 256-byte C buffer; truncate label to 230 bytes. No user Display, lazy worker or heap formatting. Every RawPutChar chain is watched for owner allocator entries. C setjmp checkpoint exists only inside live cleanup; longjmp never returns into Rust. Registry progress is global and each record retires before native release. | DIAG_NORMAL/LONG, CALDIAG1..3, PANIC, OOM, SECONDARY, CLEANSECOND |
| Stock startup and entry | Exact 131072-byte stack and Exec/DOS headers checked before stock startup. Linker uses an isolated renamed copy of immutable startup.o. All loader/startup/teardown allocations included by whole-physical inventory. | CAL, every native mode; upstream and compatibility inventories |

The raw extern declaration in aros-sys is unsafe by design. In the `aros` runtime the
only pointer-to-slice conversion uses argv storage bounded by native argument
validation and scoped to the context. The entry macro claims the context once;
its panic/OOM hooks never return. In the `aros` allocator, copy, zeroing and
release operate on the owned blocks and Layout supplied by Rust. In the safe API
each unsafe call passes a live context key, a private token, a bounded borrowed
buffer and stack SdkError; success/failure conversion does not allocate. File,
library, signal, port and message Drop clear the token before release. The
callback trampoline dereferences only the synchronous, live CallbackFrame.
Explicit raw calls can violate these contracts and are outside safe guarantees.

Qualification-only headers and AMI_SDK_TESTING add fault sites, independent
native acquisition/release observers, diagnostic controls and GDB publishing.
Production recipes exclude them. Memory measurement uses private pinned TLSF
layout solely as an independent test instrument; product allocation uses public
Exec contracts. Stack instrumentation paints only proven unused lower stack
space and restores its deliberately damaged canary/excess bytes.

The native accounting control temporarily supplies an overflowing backing-charge
ledger to the actual SDK overflow branch, verifies refusal with unchanged native
acquisitions and restores it. It deliberately does not exhaust global OS memory.
The task-owner control temporarily changes the stored owner for comparison only;
it exercises the actual FindTask mismatch branch without creating a task or
dereferencing a forged task. Expired-context callbacks are refused after cleanup
before invocation. These controls prove guard behavior, not multithread support.

The finite injection inventory is: 1 AllocMem, 2 Open, 3 Read, 4 Write,
5 Close-after-consumption, 6 OpenLibrary, 7 AllocSignal, 8 CreateMsgPort,
9 each SDK allocation/token reservation (including both port tokens), 10 short
Read, 11 short Write, 12 zero Write, 13 mandatory DOS and 14 secondary fatal
diagnostic. Every fault has a valid subsequent operation and reconciled ownership
or a bounded native fatal status with post-cleanup records. The fixed manifest
enumerates whole native invocations; repeated subcases occur inside them.

Safe compile controls reject use after Close, context escape, owned Clone,
Send, Sync and borrowed callback escape. They follow a successful positive-safe
fixture using the same pinned compiler/target/dependency graph. A compiler
failure for missing input or unrelated syntax is not accepted as a lifetime proof.

Allocation checker controls pass misaligned pointer copies to the same alignment
checker before dereferencing, and an isolated backend record through its actual
release checker twice. The second release is detected, with no fake pointer
passed to an OS call; deliberate checker state is restored. Host ledger-copy
controls independently reject leaked records.

GlobalAlloc calls require nonzero Layout sizes, as specified by the pinned Rust
core trait. Zero-size native requests are tested only via the explicitly richer
raw SDK API; safe Rust ZST collections perform no global allocation. The initial
W07 candidate violated that caller condition in its fixture and is superseded,
with results preserved. Product allocation behavior is unchanged.
