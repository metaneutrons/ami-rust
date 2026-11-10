# std-net

Native test of the sockets of `std` on AROS: `TcpStream`, `TcpListener`, `UdpSocket` and name lookup over
`bsdsocket.library`, on the loopback interface. One behaviour per run, chosen by the first argument. Like the other
`std` programs it is not a workspace member: it needs a toolchain that ships `std` (see `examples/std-runtime/README.md`
for the build). The native matrix (`tools/native-matrix.mjs`) runs every mode on both ABIs; the set-up and the expected
result of each mode are in `tests/programs.json`.

The run must create `RAM:ami-rust-m1` (`MakeDir`), start in it (`CD RAM:ami-rust-m1`) and use `Stack 131072`, as the
other `std` programs do.

## The network stack

`std` does not start a stack. AROSTCP has to be running before the program asks for a socket, and it has to find its
configuration: AROSTCP reads it from the directory `db` next to the directory that holds the program, so
`SYS:System/Network/AROSTCP/C/AROSTCP` finds nothing on the ABI-v1 image, which has no `db` at all (the ABI-v11 image
has one). Without one the daemon runs and never creates its port. The test starts the stack the same way on both ABIs,
from a copy of the daemon and these files, which are enough for a stack with the loopback interface only:

- `general.config` (two lines) keeps the stack from opening its window;
- `netdb` (one comment line and one `HOST` line) is the file the stack reads first; it may name no other file.

The modes that need a stack start it first (their `before` lines in `tests/programs.json`): the files go to `RAM:N/db`,
the daemon is copied to `RAM:N/C`, started with `Run`, and `WaitForPort AROSTCP` waits until it has made its port.

## Modes and results

| Mode | Checks | What it covers |
| --- | --- | --- |
| `nostack` | 6 | no stack is running: `connect`, `bind`, `UdpSocket::bind` and a name lookup return `ErrorKind::Unsupported` at once, with a message that says why; an address of digits needs no stack |
| `tcp` | 16 | a server thread makes a listener, the client connects; both addresses; an echo; read timeout (the kind and the time); non-blocking mode; `TCP_NODELAY`; the time to live; `take_error`; `try_clone` is `Unsupported`; the server sees the data and the end of the stream; `ConnectionRefused` from `connect` and from `connect_timeout` |
| `udp` | 13 | two sockets, `send_to`, `peek_from`, `recv_from`; a connected pair; `recv` timeout; `set_broadcast`; multicast and `try_clone` are `Unsupported`; a datagram of 1200 bytes |
| `lookup` | 4 | an address of digits, `localhost` through the `HOST` line, an unknown name (`NotFound`), a name with a nul byte |
| `threads` | 4 | a socket used by a thread other than the one that made it is refused; four pairs run at once, each server making its own listener; the address of a listener dropped in another thread is free again |
| `many` | 3 | 200 sockets opened and closed one after the other, 20 held at once, 30 connections to one listener |

`threads` takes the number of pairs as a second argument (4 if it is missing). It prints `INFO` lines with the time of
each pair.

## Differences between the ABIs

Every check gives the same result on ABI-v1 and ABI-v11. One difference of time: with two or more pairs at once on
ABI-v11, one transfer takes about 5.1 s (a pair alone takes 10 ms); ABI-v1 takes 13 ms for four. The time is in the
answer of the server to the first byte, not in `connect`. The cause is not known (see Not verified).

## Not verified

- Traffic beyond the loopback interface, IPv6 traffic, a name server, and the behaviour of a stack that has a network
  card.
- The 5.1 s above: whether it is in the stack of ABI-v11 or in how the bridge waits is not known; it was not reduced to
  a program that does not use `std`.
- A socket used by two threads in turn: refused by design, not worked around.
- `std::net` while the stack is stopped after the program has used it.
