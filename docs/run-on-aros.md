---
title: Run on AROS
description: Get an ami-rust executable onto an AROS system, start it, and read its result.
---

`cargo build` produces a native AROS executable at `target/<target>/release/<package-name>`. This page covers what the target system must provide, how to start the program, and how to interpret what happens. A build host (macOS or Linux) and the AROS system you run on are separate machines or a host and an emulator.

## What the target system must provide

The native start-up code checks its environment before it runs any Rust code. If a check fails the program returns immediately, with return code 20 (or 10 for oversized arguments), and prints nothing.

| Requirement | Why |
| --- | --- |
| The AROS ABI that matches the target you built for | `x86_64-unknown-aros-abi1` needs upstream AROS ABI-v1; `x86_64-unknown-aros-abi11` needs [Deadwood's AROS](https://github.com/deadwood2/AROS) ABI-v11. See [targets and ABIs](/targets-and-abis/). |
| `exec.library` version 51 | Checked on both ABIs: the version and the size of the library's vector table. |
| `dos.library` version 50 | The same check, applied to DOS, on both ABIs. |
| A task stack of exactly 131072 bytes (128 KiB) | On ABI-v1 the start-up code refuses to run with any other stack size. The ABI-v11 release was qualified with a 128 KiB shell stack too, so use 131072 on both. |

Check the library versions with the shell's `Version` command (`Version exec.library`, `Version dos.library`).

## Start a program

1. **Copy the executable to AROS.** Any way of placing a file on an AROS volume works: a shared folder, a network share, a disk image, or a re-mastered boot ISO. The release qualification re-mastered a copy of the boot ISO with the executable and an `S:User-Startup` entry, keeping the original El Torito boot record (`xorriso -boot_image any keep`) and leaving the source image unmodified.
2. **Open a Shell** on the AROS system.
3. **Set the stack size**, which the program inherits from the launching shell:

   ```text
   Stack 131072
   ```

4. **Run the program**, passing arguments as you would for any AROS command:

   ```text
   SYS:Work/hello-aros
   ```

5. **Read the return code.** The shell stores it in `RC`.

Arguments reach the program as raw bytes through `Context::args`. The native start-up accepts at most 4096 argument bytes in total; more than that makes the program return code 10 before it runs.

## Return codes

| Code | Meaning |
| --- | --- |
| 0 | The application function returned `AppStatus::Success`. |
| 10 | `AppStatus::Error`, or the arguments exceeded 4096 bytes. |
| 20 | `AppStatus::Fatal`, a panic, or a refused start-up (wrong `exec.library` or `dos.library` version, or on ABI-v1 a stack that is not 128 KiB). |

A panic never unwinds into AROS. The runtime enters its native fatal path and the program ends with `AppStatus::Fatal`. After the application function returns, the runtime releases every tracked resource, including handles whose Rust owners were forgotten.

## Diagnostics

`Context::diagnostic(label, code)` writes a bounded line through the system's low-level debug output. Where that output appears depends on how the system routes it. On the ABI-v1 image used for qualification it reached the serial port. On the ABI-v11 image used for qualification it did not, so those runs were checked from the screen instead. For user-visible output, write to `Stdout` or `Stderr` instead.

## Graphical programs

MUI programs need a running graphical AROS session. A program such as [MUI hello](/mui-hello/) stays in its event loop until MUI reports `QUIT`, which for that example happens when you close its window. The shell prompt returns only then.

## Running in an emulator

The release was qualified in QEMU with the following profile. The table lists the recorded parameters. It is not a command line.

| Setting | Value |
| --- | --- |
| Machine | `pc-i440fx-11.1` |
| CPU | `qemu64-v1`, one vCPU |
| Acceleration | TCG, single-threaded |
| Memory | 512 MiB |
| Boot media | Read-only IDE CD-ROM at index 2 |
| Disk | Empty disposable IDE disk at index 0 |
| Network | None |
| Firmware | Pinned SeaBIOS and standard VGA ROMs |
| Shell stack | 128 KiB |

Real hardware, other CPUs and other emulators are outside the qualified boundary; see [compatibility](/compatibility/). The exact images, hashes and observations are recorded in the repository's qualification documents for the [baseline run](https://github.com/metaneutrons/ami-rust/blob/main/docs/m1-qualification.md), the [mui-hello run](https://github.com/metaneutrons/ami-rust/blob/main/docs/mui-hello-qualification.md) and the [release candidate](https://github.com/metaneutrons/ami-rust/blob/main/docs/m7-qualification.md).

## If nothing happens

The program returns code 20 silently when a start-up check fails. See [Troubleshooting](/troubleshooting/#the-program-returns-code-20-immediately).
