---
title: STD-M3 findings
---

# STD-M3: time, random and file system

Execution: https://github.com/metaneutrons/ami-rust/issues/68
Plan: [ami-rust-std](ami-rust-std.md), milestone STD-M3.
Measured on 2026-11-07 on a macOS ARM64 host with the released toolchain `0.2.0`
(`rust-src` of `nightly-2026-09-18`), the patch in `host/std-aros/` and a local toolchain
with the target specifications of `main`. Everything under "Verified" was run natively on
the pinned ABI-v1 and ABI-v11 images.

## Status

Delivered in slices, each its own pull request.

| Criterion | State |
| --- | --- |
| A1: `Instant`, `SystemTime` (AROS epoch converted and tested), `thread::sleep` without threads | Met, see below. |
| A2: `std::fs` and `std::path` | Not started. |
| A3: `HashMap` seeding with the best available entropy, quality documented | Not started. The decision is recorded in the plan: `getentropy` on ABI-v1, `RDRAND` after a `CPUID` check with the mixer as fallback on ABI-v11 (#115). |
| A4: ABI differences declared | Open until A2 and A3 are done. |

## A1: time and sleep

The test program is `examples/std-time` (listed as in development under #68); its README
has the table of results. All of it was verified on both ABIs.

- **The epoch.** The plan expected that the AROS epoch (1 January 1978) had to be converted.
  For the clock it does not: the C library's `clock_gettime(CLOCK_REALTIME)` already adds the
  offset to 1970 and the time zone of the locale, and the guest clock agreed with the host's
  UTC. The 1978 epoch matters for file times (`DateStamp`), which belong to A2.
- **Beyond 2038.** `time_t` is a signed 32-bit integer in both C libraries, so a `SystemTime`
  built from it would break in January 2038. The clock underneath is unsigned, and AROS cannot
  be before 1978, so a negative `tv_sec` means a later date and `std` reads the value as
  unsigned. With the virtual machine's clock set to 2040 the C library returns -2,085,978,494
  (which would read as 1903) and `SystemTime::now` returns 2,208,988,802, as it should. The
  range ends on **7 February 2106**, where the counter wraps: a clock set to 2107 gives
  41,362,307, as predicted. This is a limit of the C library that `std` cannot remove.
- **`Instant`** uses `CLOCK_MONOTONIC` (the uptime) with a resolution of one microsecond and
  never went backwards in 200,000 reads. It is not affected by the 2106 limit.
- **`thread::sleep`** uses `nanosleep`. Seven durations from 0 to 1.5 seconds were accurate to
  about a millisecond. `nanosleep` is what makes a `std` program usable that only waits.
- **Arithmetic** of `SystemTime` and `Instant` (carry and borrow of nanoseconds, times before
  the epoch, overflow and underflow) is the same as on Unix; 11 checks pass.

## Facts that matter later

- The QEMU runner of the maintainer cannot set the virtual machine's clock. A private copy of
  the runner with one added option was used for the dates beyond 2038; the maintainer's
  runner was not changed. Without such an option the qualification run cannot repeat these
  tests.
- `CLOCK_MONOTONIC` is 0 and `CLOCK_REALTIME` is 2 on AROS, the reverse of Linux.

## Not verified

- Time zones other than UTC, and a system whose real-time clock has never been set.
- Sleeping from several tasks, and `nanosleep` under load.
- Linux hosts and the authenticated pipeline.
