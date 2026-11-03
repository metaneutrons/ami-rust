---
title: The aros-sys crate
description: Raw declarations of AROS libraries, records and the native bridge for both ABI profiles. The layer under the safe crates.
---

`aros-sys` is the raw layer that every safe crate stands on. It declares the AROS library calls, the native records and the functions of the C bridge, and it adds nothing else: no ownership, no checking, no allocation. It is `no_std`.

Most programs should not use it. [`aros`](/api/aros/) and the crates built on it wrap everything below in handles that release their resources and that cannot leave the task that made them. Use `aros-sys` when you need a library function that no safe crate wraps yet, or when you are writing such a wrapper. Every function here is `unsafe` and its documentation states what you must guarantee.

## What it contains

| Part | What it is |
| --- | --- |
| Library modules | `asl`, `dos`, `exec`, `graphics`, `icon`, `intuition`, `locale`, `timer`, `utility` and `workbench`: 100 raw library calls in all, one function per vector (3, 13, 12, 27, 8, 17, 7, 3, 3 and 7). They are generated from the pinned SDK headers and are the same set on both ABIs. |
| Records | The AROS structures the safe crates read: `Node`, `List`, `Library`, `Message`, `MsgPort`, `FileInfoBlock`, `IoRequest`, the timer types, and the BOOPSI `Hook` and `IClass`. |
| Native bridge | 118 `sdk_*` functions, the Rust declarations of the C bridge that starts the program, owns its resources and calls AROS on behalf of the safe crates. |
| Tags and codes | The window (`wa`), IDCMP (`idcmp`), file requester (`aslfr`) and catalog (`oc`) tags, and the Workbench types (`wb`) that the safe crates use. |
| Layout oracles | `layout_values` and the `*_layout_values` functions: the sizes and offsets that the Rust declarations assume, in the order of the tables that the C bridge reports from the real headers. The qualification compares them value by value. |

Every public item has documentation. The site's generated reference covers the safe crates only; for this crate build the reference locally with the installed toolchain:

```text
RUSTDOCFLAGS="-Zunstable-options" cargo +"$toolchain" doc -p aros-sys \
  --no-deps --target x86_64-unknown-aros-abi11 --open
```

## How library calls reach AROS

A call goes through the vector table of the library base, and the two ABIs pass the base differently. ABI-v1 passes it after the ordinary arguments; ABI-v11 loads it into register `r12`. The crate contains both backends and selects one from the Cargo target, so the declarations that you call are the same:

```text
x86_64-unknown-aros-abi1     base passed last
x86_64-unknown-aros-abi11    base passed in r12
```

On a host target the ABI-v1 backend is selected so that the crate and the crates above it still build and can be unit tested; a call into a library is only meaningful on AROS.

## The native bridge

The `sdk_*` functions follow one set of conventions, described in full at the top of the bridge block in the source:

- **Handles.** A handle is a non-zero 64-bit token that the bridge issues. It is valid only for the running program and only until it is released. A token that is stale, foreign or of the wrong kind is refused, never dereferenced.
- **Context.** Almost every function takes the `context` key from `sdk_context` or `sdk_claim_context` and refuses a call from any task other than the one that started the bridge.
- **Results.** A function that returns a handle returns 0 on failure. A function that returns `c_int` returns 0 on success and -1 on failure, unless its documentation says otherwise.
- **Errors.** The `error` argument may be null. When it is not, the bridge clears it on entry and fills it on failure with a class and the native error code:

| `SdkError::kind` | Meaning |
| --- | --- |
| `ERROR_KIND_NATIVE` (1) | A native AROS call or an allocation failed; `native` holds its code. |
| `ERROR_KIND_INPUT` (2) | An argument was invalid. |
| `ERROR_KIND_LIMIT` (3) | A bound was reached. |
| `ERROR_KIND_OWNER` (4) | The context or the calling task is not the owner. |
| `ERROR_KIND_STATE` (5) | The handle is unknown or released, or the state does not allow the operation. |
| `ERROR_KIND_EOF` (6), `ERROR_KIND_ZERO_PROGRESS` (7) | Reserved: the bridge does not set them; the safe layer maps them if a call reports them. |

## Bounds

The bridge enforces these limits; the safe crates report a refusal as an error of kind `Limit` or `Input`.

| Bound | Value |
| --- | --- |
| Command-line arguments | 32, with at most 4096 bytes in all |
| Path or name argument | 128 bytes including the terminating NUL |
| One file transfer | 64 KiB per call |
| Message payload | 256 bytes |
| Device request data | 64 KiB |
| Allocation alignment | a power of two up to 4096 |
| Callbacks running at one time | 1 |

## ABI differences

The ABI-v1 `struct Library` and `struct MsgPort` end with SMP `spinlock_t` padding (`SpinLockPadding`). On ABI-v11 `Library` ends at `open_count` and `MsgPort` ends in the private field `mp_Private`, and `SpinLockPadding` does not exist. The layout table therefore has 106 values on ABI-v1 and 101 on ABI-v11. File sizes and positions above 2 GiB are available only on ABI-v1, through `dos64.library`; see the [`aros`](/api/aros/) guide.

Everything else in the crate is the same on both ABIs. See [targets and ABIs](/targets-and-abis/).

## Safety

Calling a raw function is `unsafe` because nothing here checks the arguments for you. The documentation of each function lists what must hold: valid pointers and lengths, a live library base, the right task, and the cleanup that pairs with the call. The safe crates meet those conditions for you, which is the reason to prefer them.
