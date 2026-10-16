# Practical memory policy

Owner decision: Fabian, 2026-10-16. Applies prospectively to the next ami-rust
candidate; earlier M0/M1/R3 results and their original limits remain unchanged.

## SDK applications

The SDK does not impose the feasibility experiment's 1 MiB allocation, 16 MiB
heap or 32 MiB whole-application quotas on user programs. A valid supported
allocation is attempted through public Exec AllocMem. Available contiguous AROS
memory and allocation failure determine success. No AvailMem precheck promises
success: another task can consume memory between a check and allocation.

Keep checks for representable object size, arithmetic overflow, supported
alignment (currently up to 4096 bytes), owner task, original allocation layout,
matching release, panic/OOM cleanup and allocation-free diagnostics. The
conservative backing-charge statistic remains an overflow-checked measurement;
it is not an application heap quota or an exact physical-memory measurement.

The ELF auditor continues to reject invalid ABI, sections, startup, symbols and
unsupported relocations. It reports code, data and file sizes. The historical
reference-program size thresholds are observations; exceeding them alone does
not reject an otherwise valid user program.

The existing 128 KiB startup stack is a separately supported runtime contract;
this decision does not silently enlarge it or claim unbounded recursion.
Unrelated API capacities and task-affinity restrictions remain explicit.

## Qualification

Keep the immutable 512 MiB QEMU/ABI-v1 boot profile. Rebuild on macOS Apple
Silicon and Linux x86-64 and rerun the affected native matrix on the actual
candidate. The old native hashes cannot qualify changed allocator code.

Acceptance requires:

- The inherited ABI, alignment, zeroing, realloc, owner/lifetime, failure and
  cleanup matrix passes, including allocation-free fatal diagnostics and full
  loader/startup/teardown memory accounting.
- The new `memory-large` native mode simultaneously owns 32 MiB + 17 bytes and
  17 MiB + 31 bytes at 4096-byte alignment. It writes and verifies every page and
  each final byte, then reconciles the original block and backing ledgers. Run
  it ten times on each host's resulting native executable. This is a concrete
  test workload, not a new 49 MiB product cap.
- Overflowed sizes/accounting fail before native allocation. Injected native
  OOM returns refusal; failed realloc preserves the old allocation. Test OOM
  without deliberately exhausting the guest's memory.
- Record measured physical peaks, stack use and code/file sizes. Earlier
  16/32 MiB workload thresholds are comparison baselines, not universal product
  limits. Unexpected growth requires investigation; a justified change is
  recorded with its cause and supported machine requirement. Leaks, corruption,
  unbalanced ownership, invalid layouts and broken cleanup remain failures.
- A structurally valid ELF larger than the old reference limits passes the
  generic auditor; malformed ABI/section/relocation controls still fail.

Host-only arithmetic and ELF fixtures do not establish native acceptance.
The [R4 qualification record](https://github.com/metaneutrons/ami-rust/blob/main/release/candidate-r4/qualification.json)
records native-profile acceptance for the identified changed runtime and pinned
QEMU baseline. Exact-version SDK production, authentication, final consumer
qualification and independent R1 acceptance remain separate, open release gates.

## Development and CI

Local work uses actual free disk space and the existing 32 GiB operating
headroom, without cumulative archive or per-directory quotas. On the current
64 GiB Mac, a developer-memory budget is not inferred from the small guest's
heap experiment.

The standard hosted CI profile retains its measured 6 GiB host admission,
4 GiB aggregate build RSS and two build jobs. Prior successful Cargo producers
measured about 2.0–2.5 GiB RSS. These are runner operational settings, not AROS
application limits or a general Rust limitation. Record a prospective capacity
change if a real build needs more; do not change the compiler/input identities
or rerun successful builds solely to increase an unused ceiling. Timeouts and
bounded parsing of untrusted distribution inputs remain separate controls.

Protected AROS-NX/aros-tools checkouts, boot image and ABI are unchanged; nxpk
is outside this work.
