# std-random

Native test of randomness in `std` on AROS: which source `std` uses, statistics of its
output, and whether the seeds of a `HashMap` differ from boot to boot. It goes through
`std::random` (feature `random`), which is the same path that `HashMap` seeds from. One
behaviour per run, chosen by the first argument. Like the other `std` programs it is not
a workspace member: it needs a toolchain that ships `std` (see `examples/std-runtime/README.md`). The native matrix (`tools/native-matrix.mjs`) runs every mode on both ABIs; the set-up and expected result of each mode are in `tests/programs.json`.

## Where the randomness comes from

| | Source |
| --- | --- |
| ABI-v1 | `getentropy` of the C library, backed by `entropy.resource`: a ChaCha20 generator that is reseeded on every call from a software collector and, where the CPU has them, `RDRAND` and `RDSEED`. At most 256 bytes per call, so `std` asks in pieces. If it fails, the weak generator is used. |
| ABI-v11 | The Deadwood tree has no `getentropy`, no `getrandom` and no `entropy.resource`. `std` uses a weak generator (the two clocks, a stack address, a heap address and a counter through SplitMix64) and, when the CPU has `RDRAND` (checked with `CPUID`), mixes `RDRAND` output into the result with XOR. A faulty hardware generator therefore cannot make the result weaker than the weak generator alone. |

`getentropy` for the Deadwood tree is tracked in #115; when it exists, ABI-v11 switches to it.

**What the quality is.** On ABI-v1 it is that of `entropy.resource`; its software collector was
not evaluated here, and on the CPU model of the qualification (`qemu64-v1`, which has no
`RDRAND`) only that collector is in play. On ABI-v11 without `RDRAND` it is **weak**: a
statistical test cannot tell, because SplitMix64 is a good mixer, but the seed is predictable
for someone who knows the boot time to within a few seconds and the memory layout. It is
good enough to keep `HashMap` seeds apart between runs and not good enough against an
attacker who crafts keys, and **not suitable for cryptography**. With `RDRAND` on ABI-v11 the
result is as good as the hardware generator, with the weak generator as a floor.

## Modes

| Mode | What it does |
| --- | --- |
| `source` | fills 16 bytes and reports which source was used (read from the symbol `__ami_rust_random_source`, which `std` exports for this purpose) and whether the CPU has `RDRAND` |
| `stats` | 64 KiB from `SystemRng`: fraction of one bits, chi-squared of the byte values, duplicate 8-byte words, longest run of equal bytes |
| `selftest` | the same statistics on zeros, a counter, a biased stream and a repeating pattern, which they must all reject |
| `sizes` | 13 sizes from 0 to 65,536 bytes: not all zero, and the last byte is covered |
| `hashmap` | two `RandomState` values differ, and a `HashMap` of 2,000 entries works |
| `api` | `random(..)` for `u64`, `u8` and `bool` |
| `seed` | prints 16 random bytes and a `RandomState` hash, for comparing boots |

## Results

All modes pass on both ABIs and on both CPU models: `qemu64-v1` without `RDRAND` (the model of
the qualification) and `Haswell` with it.

| Case | Source reported | Statistics (64 KiB) |
| --- | --- | --- |
| ABI-v1, `qemu64-v1` | `getentropy` | ones 0.5004, chi-squared 248.2, no duplicate words |
| ABI-v1, `Haswell` | `getentropy` | ones 0.4994, chi-squared 250.5, no duplicate words |
| ABI-v11, `qemu64-v1` | weak generator only | ones 0.5011, chi-squared 250.0, no duplicate words |
| ABI-v11, `Haswell` | weak generator mixed with `RDRAND` | ones 0.5009, chi-squared 264.6, no duplicate words |

- The bounds are 0.5 plus or minus 0.005 for the ones, 130 to 400 for chi-squared (255 degrees of
  freedom), no duplicate words and no run of more than four equal bytes.
- **The selftest rejects all four bad streams** (zeros, counter, biased, repeating), so the bounds
  are not vacuous.
- **Across boots** the seeds differ in every configuration: four boots each of ABI-v1 on
  `qemu64-v1`, ABI-v11 on `qemu64-v1` and ABI-v11 on `Haswell` gave four different byte strings and
  four different `RandomState` hashes.
- The statistics do not measure unpredictability. That the weak generator passes them is why the
  quality statement above rests on how it is built, not on these numbers.
- The runs on `Haswell` used the runner option `--cpu Haswell`. Without it the runner uses
  `qemu64-v1`, the qualified profile, which has no `RDRAND`, so a qualification run exercises
  the fallback unless it is repeated with a CPU that has the instruction.

## Not verified

- The behaviour when `getentropy` fails (no `entropy.resource`) on ABI-v1: the fallback to the
  weak generator is in the code and was not triggered.
- The quality of the software collector of `entropy.resource`.
- A CPU whose `RDRAND` reports failure, and AMD CPUs with known `RDRAND` faults (the XOR with the
  weak generator is meant to cover them).
- More than one task.
