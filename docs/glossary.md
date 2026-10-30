---
title: Glossary
description: Definitions of the AROS, MUI and ami-rust terms used in this documentation.
---

**ABI-v1** — The AROS ABI profile of upstream AROS, qualified through the AROS-NX integration fork. Cargo target `x86_64-unknown-aros-abi1`. The library base is passed as the last ordinary argument. See [targets and ABIs](/targets-and-abis/).

**ABI-v11** — The AROS ABI profile of [Deadwood's AROS](https://github.com/deadwood2/AROS) port, code-named ABIv11. Cargo target `x86_64-unknown-aros-abi11`. The library base is passed in register `r12`.

**`alloc`** — The Rust standard-library layer that provides heap types such as `Vec` and `Box` without the operating-system parts of `std`. Available through `ExecAllocator`.

**AROS** — The AROS Research Operating System, an open-source operating system compatible with the AmigaOS API. ami-rust targets its PC x86-64 builds.

**Attribute (MUI)** — A named property of a MUI class, such as a window title. Attributes can be set at construction, written later, read, or a mix of these. Each attribute is a typed descriptor in `aros_mui::attributes`.

**BOOPSI** — The object system underneath MUI and Intuition gadgets. MUI classes are BOOPSI classes.

**Class (MUI)** — A kind of MUI object, such as `Window`, `Group` or `Text`. Classes form a hierarchy; attributes and methods of a class are valid on its subclasses.

**`Context`** — The borrowed proof, passed to your entry function, that you are on the application task inside its live entry frame. Every safe handle is created from it and cannot outlive it.

**Deadwood's AROS** — A maintained fork of AROS whose `master` branch is code-named ABIv11. The source for [ABI-v11](/targets-and-abis/).

**DOS (`dos.library`)** — The AROS library for files, directories, processes and the shell. Exposed through `File`, `Stdout` and `Stderr`.

**Exec (`exec.library`)** — The AROS kernel library: memory, tasks, signals, message ports and libraries. Exposed through `ExecAllocator`, `Signal`, `Port`, `Message` and `Library`.

**Hook** — A callback retained by a MUI scope and invoked on a notification. A `Hook` is valid only for its scope and is not reentrant.

**Intuition (`intuition.library`)** — The AROS windowing library. MUI is built on it.

**Library base** — The pointer to an open AROS library. Calls to the library are made through a vector table relative to the base, and the two ABIs pass the base differently.

**Library vector** — An entry in a library's jump table. A raw call selects a function by its vector number.

**MUI** — The Magic User Interface, a GUI toolkit. AROS provides it through `muimaster.library`, known as Zune. `aros-mui` is its safe Rust interface.

**Method (MUI)** — A message that a MUI object can receive. Generated descriptors live in `aros_mui::methods`; dispatching one is `unsafe` unless a safe typed form exists.

**Native bridge** — The small C library compiled into every application by [`aros-native-build`](/build-system/). It owns the resource registries and the startup checks.

**Notification** — A rule that connects a change of a readable attribute on one object to an action, such as returning an ID to the application loop, setting another attribute, or calling a hook.

**`no_std`** — A Rust crate that does not link the standard library. All ami-rust crates and applications are `no_std`.

**Qualified** — Built, run and recorded on the pinned inputs listed in the repository's qualification documents. "Qualified" describes what was tested, not a general promise.

**Return ID** — A nonzero value that a notification can hand to the MUI application loop. `ReturnId::QUIT` ends the loop.

**Scope** — The `Mui::scope` closure's `Scope`. It owns every MUI object, string array, hook and custom-class registration created through it, and disposes them when the closure returns.

**Target** — A Cargo `--target` triple. ami-rust provides `x86_64-unknown-aros-abi1` and `x86_64-unknown-aros-abi11`. The target selects the ABI.

**Task** — An AROS unit of execution. Handles in ami-rust belong to the task that created them (they are *task-affine*) and are neither `Send` nor `Sync`.

**Toolchain** — The versioned rustup toolchain, `0.1.0`: compiler, Cargo, target libraries, C SDK, collector and `aros-link`.

**TCG** — QEMU's Tiny Code Generator, its software CPU emulation. The release was qualified with single-threaded TCG.
