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
| A2: `std::fs` and `std::path` | In progress. Slice 1 (open, read, write, seek, truncate, duplicate, remove) is met, see below. Metadata, directories, `rename` and `std::path` are open. |
| A3: `HashMap` seeding with the best available entropy, quality documented | Met, see below. |
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

## A2, slice 1: files

The test program is `examples/std-fs` (listed as in development under #68); its README has the
workarounds, the table of results and the ABI differences. All 15 modes (104 checks) pass on both
ABIs, every boot on the first attempt.

- **Implemented:** `File::open`, `File::create`, `OpenOptions`, `read`, `write`, `seek`,
  `stream_position`, `set_len`, `sync_all`, `sync_data`, `try_clone`, `fs::remove_file`, and what is
  built on them (`fs::read`, `fs::write`, `BufReader`, `BufWriter`), through the C library's
  descriptors.
- **Still `Unsupported`** (the unsupported fallback, one check each in the `unsupported` mode):
  `metadata`, `File::lock` and `try_lock`, `read_dir`, `create_dir`, `rename`, `canonicalize`,
  `set_permissions`, `set_times`. Slices 2 and 3 replace the first three groups and `rename`;
  locking stays unsupported.
- **Five behaviours of the C library are worked around** (details in the program's README):
  DOS requesters that wait for a person on a missing volume, access modes that are not enforced,
  append that does not follow a seek, a seek past the end that extends the file at once (and by the
  wrong amount on ABI-v11), and `unlink` of an open file reporting "not found" on ABI-v1.
- **Requesters.** `std` switches requesters off only around the calls that resolve a path and
  restores the setting afterwards. It does so through a bridge function, `sdk_proc_window_set`,
  because `std` must not call Exec itself: the Exec link library defines strong `open` and
  `close`, which replace the C library's weak ones on ABI-v1 and are a duplicate-symbol link error
  on ABI-v11. This policy is open for the maintainer's confirmation.
- **Errors.** A DOS error with no C equivalent reaches `std` as `1000 + code`. These now map to
  kinds and texts.
- **Facts about the C library:** `off_t` is 64 bits on both ABIs; the `open` flags are the same in
  both SDKs, except that `O_CLOEXEC`, `O_DIRECTORY` and `O_NOFOLLOW` are only defined on ABI-v1; a
  name component of 108 characters or more is `InvalidInput`; the shell cannot redirect standard error.
- **Reported upstream:** nothing yet. Candidates, each needing the maintainer's go: the strong
  `open`/`close` in `libexec.a`, the seek past the end, and `unlink` of an open file (AROS-NX), and the
  wrong seek amount on ABI-v11 (Deadwood).

## A3: random

The test program is `examples/std-random` (listed as in development under #68); its README has
the sources, the quality statement and the table of results.

- **ABI-v1** uses `getentropy` (`entropy.resource`, a ChaCha20 generator reseeded on every call
  from a software collector and `RDRAND` where present, at most 256 bytes per call).
- **ABI-v11** has nothing to call. It uses the weak generator of the spike and, when the CPU has
  `RDRAND` (checked with `CPUID`), mixes the instruction's output in with XOR, so a faulty
  hardware generator cannot make the result weaker than the weak generator alone. This follows the
  maintainer's decision of 2026-11-05; `getentropy` for the Deadwood tree is tracked in #115.
- **Which path ran** is observable: `std` exports `__ami_rust_random_source`. On `qemu64-v1`
  (no `RDRAND`) ABI-v1 reports `getentropy` and ABI-v11 the weak generator only; on `Haswell` ABI-v1
  still reports `getentropy` and ABI-v11 reports the weak generator mixed with `RDRAND`.
- **Statistics** of 64 KiB through `std::random` pass in all four cases, and a self-test shows that
  the same statistics reject zeros, a counter, a biased stream and a repeating pattern. They do not
  measure unpredictability, and the weak generator passes them; its weakness is that the seed is
  predictable to someone who knows the boot time and memory layout.
- **Across boots** (four each) the seeds and the `RandomState` hashes differ in every configuration.
- The `RDRAND` path needed a CPU model that has the instruction. A private copy of the runner with a
  `-cpu` option was used; the maintainer's runner always uses `qemu64-v1`, so a qualification
  run with the current runner exercises the fallback, not `RDRAND`.

## Facts that matter later

- The QEMU runner of the maintainer cannot set the virtual machine's clock. A private copy of
  the runner with one added option was used for the dates beyond 2038; the maintainer's
  runner was not changed. Without such an option the qualification run cannot repeat these
  tests.
- `CLOCK_MONOTONIC` is 0 and `CLOCK_REALTIME` is 2 on AROS, the reverse of Linux.
- The sporadic ABI-v1 boot fault of AROS-NX#122 showed up three times in about 70 ABI-v1 boots during the random runs, each time before the program started (no output from it, the page fault in the serial log). A rerun passed every time.

## Not verified

- Time zones other than UTC, and a system whose real-time clock has never been set.
- Random: the fallback when `getentropy` fails, the quality of `entropy.resource`'s software collector, a CPU whose `RDRAND` fails, and more than one task.
- Sleeping from several tasks, and `nanosleep` under load.
- Linux hosts and the authenticated pipeline.
