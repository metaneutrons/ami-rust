# STD-M5 and STD-M6: first findings

Written 2026-11-09, before any code. What was measured on the two pinned boot images (ABI-v1 and ABI-v11, run with
`run-on-aros`, CPU model `qemu64-v1`, no `--net` option) and what that means for the two milestones. Nothing here is
implemented yet.

## STD-M5: networking

Measured with scripts that list and start the stack; the outputs are in the session, not in the repository.

| | ABI-v1 image | ABI-v11 image |
| --- | --- | --- |
| `bsdsocket.library` in `LIBS:` | no | no |
| `C:ifconfig`, `C:netstat`, `C:resolve` | yes | yes |
| `SYS:System/Network/AROSTCP/C/AROSTCP` and `dhclient` | yes | yes |
| `SYS:System/Network/AROSTCP/db` (configuration), `S/startnet` | **missing** | present (14 files) |
| Network drivers in `DEVS:Networks` | 15 | not listed here |
| After `Run SYS:System/Network/AROSTCP/C/AROSTCP` and 5 s | `Version bsdsocket.library`: object not found; `ifconfig -a` does not return (ran into the 150 s timeout) | `bsdsocket.library 4.59`; `lo0 127.0.0.1` up; `ifconfig -a` and `netstat -i` return |
| The same with a loopback-only `db` made in `RAM:` and `Assign AROSTCP: RAM:AROSTCP` | still no library, `ifconfig` hangs (one attempt, 100 s) | not tried |

What follows:

- On ABI-v11 the pinned image runs the stack by starting `AROSTCP` by hand, and the loopback interface is there without a network card. A loopback
  test (A3) is possible there as the images are.
- On ABI-v1 the pinned image does not give a working stack by the same route, and one attempt with a hand-made
  configuration did not change that. Why is not known: the stack may not start, may stop at once, or may wait for something.
  This was not investigated further (no log of the stack was found, and no break-in was tried). A3 asks for a loopback test on
  both ABIs; as things stand it can be met on ABI-v11 only.
- A1 asks for a documented behaviour when no stack is installed. The ABI-v1 image is a real case of it: the program must get an
  error from `std::net`, not a crash or a wait.
- `bsdsocket.library` is opened per program (the plan says so) and has to be opened by the task that uses it: a socket
  library base belongs to the opening task in AmiTCP-style stacks. With threads (STD-M4) each thread that uses sockets needs
  its own base. This is read from the AmiTCP/AROSTCP interface, not measured here.

## STD-M6: processes

Not yet looked at beyond the tools of the images: `C:Run`, `C:Execute` and `C:Echo` exist on both. A child that is a DOS
program can be started by `SystemTagList` or `CreateNewProc` (the plan's choice); the bridge already makes DOS processes
for threads (`tooling/crates/aros-native-build/native/sdk.c`). To do: the interface of `process::Command` that `std` asks
of a platform (the new nightly asks for more than the pinned one, see the A4 findings), exit status, captured output through
`PIPE:` or files, and the error behaviour. The shared C-library `errno` (STD-M4) applies to every call.

## Order of work

1. STD-M6 first: it does not depend on a stack, and it can be tested on both images as they are.
2. STD-M5 second, with the ABI-v1 stack as the open problem. The decision that is not mine: if a stack cannot be made to run on the
   pinned ABI-v1 image, whether A3 is met on ABI-v11 only, with the reason recorded, or whether the ABI-v1 image is changed.
3. One change of `host/std-aros/std-aros.patch` for both, so the six library pins and the digest constants are regenerated once.
