# M1 API, lifetime and failure inventory

The next candidate removes the historical 1 MiB per-allocation and 16 MiB
heap quotas. Allocations use available native memory with checked sizes,
accounting, alignment and ownership; OOM remains explicit. Reference-program
code/file/whole-memory thresholds do not constrain arbitrary applications.
The fixed startup stack and other stated API capacities remain unchanged.
Fresh native qualification is pending for this changed allocator; see
[memory policy](memory-policy.md).

The source SDK is limited to the exact pinned native x86-64 ABI-v1 image. It
provides no target std, foreign-task API, asynchronous callback, hardware or
public release. R3 qualifies the pinned macOS and Linux host profiles and exact
native artifact bytes; installation and publisher acceptance are separate gates.
All crates remain unpublished.

| Boundary | Preconditions and enforcement | Native qualification |
| --- | --- | --- |
| aros-sys raw externs and ABI structs | Caller owns valid pointers, buffers, C callbacks and native lifecycle. C/Rust independently compare all 81 exposed layout/scalar values. BPTR is the pinned identity pointer; IoErr remains signed 64-bit. | ABI1..10; malformed ELF/layout copied controls |
| aros-alloc GlobalAlloc | Rust Layout; original base and exact requested layout retained in C intrusive records. Allocate/copy/free realloc leaves old block untouched on refusal; zeroed memory and zero-size request follow the same ownership path. No TLSF private API in product. | ALLOC, CHURN, FAULT1, FAULT9, OOM |
| aros-runtime Context and entry macro | Native C main alone initializes once and calls one Rust entry. A scoped HRTB closure borrows a non-Send/non-Sync Context; argv borrows valid bounded C storage only while active. C boundary, rather than Context Drop, drains forgotten global resources after Rust returns. | ABI1..10, EXPECTED, FALLIBLE, FORGOT; compile lifetime failures |
| File / borrowed Stdout | BytePath owns at most 128 bytes including NUL; modes explicit, transfers at most 64 KiB. Buffers remain borrowed for synchronous C call. File token consumed before Close even on failure. Stdout never closes its borrowed handle. IoErr captured immediately before any other native call. | FILES, PROTECTED, FAULT2..5/10..12 |
| R1 candidate borrowed Stderr | The owner must be a DOS Process before casting its Task header. Each write selects `pr_CES`, falling back to `pr_COS` when null; neither process-owned handle is registered or closed. The wrapper borrows Context, is neither Send nor Sync, and shares bounded Write/short-transfer/zero-progress/native-error handling with file I/O. Stack-only error formatting does not establish allocation-free DOS handlers. | R3 full48 and production31 records cover redirection, fallback, errors, diagnostics and final M1 regression on exact candidate native bytes. |
| Library | Four owned optional references; mandatory DOS separate. Native library pointer is never exposed as a safe arbitrary-call capability. | LIBRARIES, FAULT6/9, STARTFAIL |
| Signal, Port, Message | Owner task only, four signal bits including two port-owned bits; eight static stable messages, 256 bytes each. Product C registry is authoritative queue state. Port destruction detaches local queued messages before DeleteMsgPort; owned bits released exactly once. No foreign or published port. | PORTS, FAULT7..9, forgotten and fatal cleanup cases |
| Synchronous callback trampoline | Rust CallbackFrame remains on the live stack, C cannot retain its address. Owner/key and nested-call guard precede user dereference. No unwind: panic follows nonreturning abort path. | CALLBACKS, CBPANIC; callback-escape compile refusal |
| Diagnostics and fatal boundary | Borrowed label, scalar and fixed 256-byte C buffer; truncate label to 230 bytes. No user Display, lazy worker or heap formatting. Every RawPutChar chain is watched for owner allocator entries. C setjmp checkpoint exists only inside live cleanup; longjmp never returns into Rust. Registry progress is global and each record retires before native release. | DIAG_NORMAL/LONG, CALDIAG1..3, PANIC, OOM, SECONDARY, CLEANSECOND |
| Stock startup and entry | Exact 131072-byte stack and Exec/DOS headers checked before stock startup. Linker uses an isolated renamed copy of immutable startup.o. All loader/startup/teardown allocations included by whole-physical inventory. | CAL, every native mode; upstream and compatibility inventories |

The raw extern declaration in aros-sys is unsafe by design. In aros-runtime the
only pointer-to-slice conversion uses argv storage bounded by native argument
validation and scoped to the context. The entry macro claims the context once;
its panic/OOM hooks never return. In aros-alloc allocation, copy, zeroing and
release operate on the owned blocks and Layout supplied by Rust. In aros-sdk
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
