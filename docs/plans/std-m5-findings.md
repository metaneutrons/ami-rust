# STD-M5: networking, findings

Written 2026-11-10. `std::net` on AROS, measured on the two pinned boot images with `examples/std-net`. The earlier
look at the stack and the reason it did not start on ABI-v1 are in `docs/plans/std-m5-m6-findings.md`.

## What was built

- **Bridge.** `sdk_net_*` in `tooling/crates/aros-native-build/native/sdk.c`: `socket`, `close`, `bind`, `listen`,
  `accept`, `connect`, `send`, `recv`, `sendto`, `recvfrom`, `getsockname`/`getpeername`, `shutdown`, socket options,
  non-blocking mode and `gethostbyname`, plus `sdk_net_probe`.
- **`std`.** `sys/net/connection/aros.rs` in the patch: `TcpStream`, `TcpListener`, `UdpSocket` and `lookup_host`. The
  patch has 43 files.
- **Test.** `examples/std-net`, six modes, 46 checks; the stack for the loopback is two files in `examples/std-net/stack/`.

## Decisions and what they rest on

1. **The calls are declared in the bridge.** The ABI-v11 C SDK has no header for `bsdsocket.library` (no
   `proto/bsdsocket.h`, `clib/bsdsocket_protos.h` or `sys/socket.h` below `c-sdk-abi11/include`); the ABI-v1 SDK has them.
   The bridge declares the calls with `AROS_LC*` and the register assignments of the ABI-v1 header, and uses the BSD
   values of the library (families, option numbers, the `sockaddr` with its length byte). Both ABIs run the same code.
2. **One library base for each task, opened on first use, closed when the task ends.** A base belongs to the task that
   opened it, and so does each socket made through it (read from the AmiTCP interface and the AROSTCP source; not measured
   what the stack does when another task uses a base). So a socket is used only by the thread that made it: another
   thread gets `ErrorKind::Unsupported` from the bridge. This rules out moving a listener into a thread, which is common
   in Rust code; the test makes the listener in the thread that accepts. Moving a socket to the thread that uses it
   (`ReleaseSocket` and `ObtainSocket`) was not tried, and two threads that use one socket at the same time could not
   work with it.
3. **A socket dropped in another thread is closed by its own thread.** The bridge marks it, and the owner closes it at
   its next socket call (or at the end of the thread, which closes the base and with it the socket). Measured: the
   address of a listener dropped in another thread can be bound again at the next call.
4. **No stack means `Unsupported`, at once.** `OpenLibrary("bsdsocket.library", 3)` fails when the library is not there,
   and the message of the error says so. Measured on both ABIs with no stack started (8.7 ms and 5.7 ms for six calls);
   measured on ABI-v1 with the daemon started from `SYS:` and no `db` (the library cannot be opened then either, and
   nothing waits). On ABI-v11 the daemon started from `SYS:` runs with the configuration of the image, so that case is
   not a missing stack there.
5. **Timeouts are waits.** A read or write timeout is a `WaitSelect` on the descriptor before the call;
   `connect_timeout` is a non-blocking `connect` and a wait. The kind of a timed-out read is `WouldBlock`, as on Unix.
6. **Unsupported:** `try_clone`, `set_linger`, `set_only_v6` and the multicast options. Name lookup is IPv4 only
   (`gethostbyname`) and reads what the stack's `netdb` names.
7. **The value of `FIONBIO`** is `0x8008667e`, which is `_IOW('f', 126, long)` with an 8-byte `long`; the ABI-v1 header
   computes it, the ABI-v11 SDK has no header. Measured: a read on a non-blocking socket returns `WouldBlock` on both ABIs.

## The stack for the test

A stack needs a `db` directory next to the `C` directory of the daemon. The test copies the daemon to `RAM:N/C`, puts its
two files in `RAM:N/db`, starts it with `Run` and waits for its port with `WaitForPort AROSTCP`. Single runs on ABI-v1
(`port rc=0` means the port was made):

| `db` | Port |
| --- | --- |
| the 12 files of the ABI-v11 image | yes |
| the same without `group` or without `passwd` | yes |
| the same without any one other file (the `netdb` of the image names each) | no |
| `general.config` (two lines: `GUI PANEL=NONE`, `OPENGUI=NO`) and a `netdb` with comments only | yes |
| the same and a `HOST 127.0.0.1 localhost` line in `netdb` | yes |
| `netdb` alone | no |
| `general.config` alone | no |

The files in `examples/std-net/stack/` are the fourth and fifth rows: written for this repository, they need no licence
note. The `localhost` line is what makes the name `localhost` resolve in the `lookup` mode. Each row is one run, except
that the fourth and the fifth also ran on ABI-v11.

## Measured

- `std-net`, 6 modes, 46 checks, all passing on ABI-v1 and ABI-v11 (one boot each, builds from the patched tree with the
  native bridge compiled for each ABI): `nostack` 6, `tcp` 16, `udp` 13, `lookup` 4, `threads` 4, `many` 3.
  One ABI-v1 boot of 12 died with the known page fault (`CR2=0x10`) before the script started; the run was repeated and
  passed. The numbers are of the final build (header and bridge as committed).
- **Loopback.** An echo over TCP between two threads, UDP datagrams of 4 and 1200 bytes, a connected UDP pair, a refused
  connection (`ConnectionRefused` from `connect` and `connect_timeout`), 200 sockets opened and closed one after the other,
  20 held at once, 30 connections to one listener.
- **Timeouts.** A 300 ms read timeout ended after 321 ms (ABI-v1) and 316 ms (ABI-v11); the same for `recv` on UDP.

## Problems met, and what they teach

- **A `std` built with `--target <path to the JSON>` is not found by a build with the bare triple.** `rustc` records the
  target as `x86_64-unknown-aros-abi1-<hash of the JSON>` in that case, and the compiler of the program, which names the
  triple, reports `E0461` for `std`. The libraries must be built with the bare triple.
- **The build script checks the libraries of the toolchain against the pins.** A development loop that changes `std`
  needs a toolchain whose libraries are the ones just built, pins written from them (`writepins.mjs`) in a copy of
  `aros-native-build`, and an `aros-link` built from that copy, in `bin` and in `lib/rustlib/<host>/bin`.
- **A moved listener is a panic in Rust code, not an error.** The first version of the thread test moved a listener into
  a server thread and failed with four `ami-rust fatal in a thread`: every `unwrap()` on the `Unsupported` error.

## Open

- **A late byte on ABI-v11 with two connections at once.** With two or more pairs of threads at once, one transfer
  takes about 5.1 s on ABI-v11 (every run); a pair alone takes 10 ms, and ABI-v1 takes 13 to 17 ms for four pairs. Timed
  step by step in the server thread of the slow pair: `accept` returned after 1.9 ms, and the one byte that the client had
  sent right after `connect` was read after 5.09 s (the reply went out at once). The bridge does nothing between
  `send` and `recv` but the call, so the byte was late inside the stack; a segment that is lost and sent again after
  about 5 s would look like this, but that was not seen. It was not reduced to a program without `std` (a plain C
  program could not be linked here without the steps of `aros-link`), and nothing was filed.
- **A line printed after a long one is garbled or lost.** `println!` of a line of about 100 characters, followed by
  another line, gave a second line with the end of the first mixed into it, or no second line, in the serial output of
  `NRDBG:`. It happened with one thread printing, so it is not about threads (an earlier reading of this note was
  wrong); lines of up to about 60 characters came through. The cause is below `std` (the handler or the serial
  stream) and was not looked at; `examples/std-net` keeps its `INFO` lines short because of it.
- **The matrix.** `tools/native-matrix.mjs` ran `std-net` and `std-process` with a toolchain installed from the
  direct archive of a producer run on the final commit (macOS; the first archive carried the old pins in its linker and
  could not link, which is the usual order: pins first, then a producer run that bakes them in). 33 of 34 boots passed,
  all 12 of `std-net`. The one that did not: `std-process concurrent` on ABI-v1, whose check "three children at once
  in under 5 s" took 10.05 s. Repeats of that mode on ABI-v1: 4.56, 4.59 and 5.10 s (fail), then ten runs of 4.55 to 4.85 s
  (pass); the binary of the STD-M6 state gave 3.5 to 4.5 s in six runs. On ABI-v11 it takes 2.4 to 2.8 s. So the margin of
  the check on ABI-v1 is thin and two of about twenty runs were over it, against none of six at the earlier state; that
  is too few to say whether this change made it worse. Nothing was changed.
- **Not verified:** traffic beyond the loopback, IPv6 traffic, a name server, a network card, and a stack that is stopped
  after a program has used it.
- **The set-up of a stack** is the test's own (a copy of the daemon with a `db`). Whether the images should carry a `db`
  is a question for the images; this repository changed none.
