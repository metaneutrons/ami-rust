# std-time

Native test of time in `std` on AROS: the clock behind `Instant`, `SystemTime`,
`thread::sleep`, and the dates beyond 2038. One behaviour per run, chosen by the
first argument. Like the other `std` programs it is not a workspace member: it needs
a toolchain that ships `std` (see `examples/std-runtime/README.md` for the build). It is listed as
in development under #72 (STD-M7) because the native matrix cannot build it yet.

## How time works

- `Instant` reads `CLOCK_MONOTONIC` of the C library, which is the uptime of
  timer.device with a resolution of one microsecond.
- `SystemTime` reads `CLOCK_REALTIME`. The C library returns the system clock
  (seconds since 1978) plus the offset to 1970 plus the time zone of the locale, so the
  result is Unix time in UTC when the locale's time zone is set correctly. The default of
  the qualified images is UTC. **The AROS epoch (1978) therefore needs no conversion for
  the clock.** The 1978 epoch does matter for file times, which come with the file system.
- `thread::sleep` calls `nanosleep`, which waits on timer.device. A sleep that is
  interrupted continues for the time that is left, and a sleep longer than 2^31 - 1
  seconds is made of several calls.
- **The year range.** The C library's `time_t` is a signed 32-bit integer, but the clock
  underneath is an unsigned 32-bit counter. A value that looks negative means a date after
  2038, because the clock of AROS cannot be before 1978, so `std` reads it as unsigned.
  `SystemTime::now` is correct until **7 February 2106**, where the counter wraps, and
  it then goes back to 1970. `Instant` is not affected.

## Modes

| Mode | What it does |
| --- | --- |
| `clock` | 200,000 `Instant::now` calls: counts steps backwards, distinct values and the smallest step |
| `sleep` | sleeps of 0, 1 ns, 1 ms, 10 ms, 100 ms, 1 s and 1.5 s, and checks that each took at least that long and less than 100 ms more |
| `arith` | 11 checks of `SystemTime` and `Instant` arithmetic: carry and borrow of nanoseconds, times before the epoch, overflow and underflow |
| `system HOSTSECS` | prints `SystemTime::now` and its difference from the host's Unix time that is passed as the argument |
| `future` | prints `SystemTime::now` as seconds since the epoch |
| `raw` | prints the signed value that the C library itself returns for `tv_sec` |

## Results

Observed on the pinned ABI-v1 and ABI-v11 images, identical on both unless stated.

| Mode | Result |
| --- | --- |
| `clock` | no step backwards; the smallest step is 1 microsecond |
| `sleep` | all seven pass; for example 10 ms took 10.2 to 10.3 ms, and 1 s took 1000.6 to 1000.9 ms. A 1 ms sleep took 1.1 ms on ABI-v11 and 2.3 ms on ABI-v1 |
| `arith` | all 11 pass |
| `system` | the clock agrees with the host's UTC; the difference of 3 to 4 seconds is the boot time between taking the host time and starting the program |
| `future`, clock set to 2040-01-01 | 2,208,988,802 (ABI-v1) and 2,208,988,804 (ABI-v11), as expected for 2040-01-01 |
| `future`, clock set to 2105-06-01 | 4,273,257,603 and 4,273,257,604, as expected |
| `future`, clock set to 2107-06-01 | 41,362,307 and 41,362,313: the value wrapped, as the range above says (4,336,329,600 - 2^32 = 41,362,304) |
| `raw`, clock set to 2040-01-01 | the C library returns -2,085,978,494 and -2,085,978,492, which is why `std` has to read the value as unsigned |

The runs with another date used the runner option `--rtc base=2040-01-01T00:00:00,clock=vm`,
which sets the clock of the virtual machine (QEMU's `-rtc`). Without it the guest uses the host
clock in UTC.

## Not verified

- Time zones other than UTC (the locale's offset is applied by the C library, and was not
  changed).
- A system whose real-time clock has never been set (AROS then starts at 1978).
- Sleeping from more than one task, and the resolution of `nanosleep` under load.
