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

## STD-M5: the ABI-v1 stack runs once its configuration is there (2026-11-10)

The maintainer decided on 2026-11-10 to change what the ABI-v1 image offers so that a stack can run there. The cause turned out
to be missing configuration, not a fault of the stack, and the qualified image (`aros-nx-abiv1-qualified.iso`) does not have to
change.

- **What was wrong.** `AROSTCP` reads its configuration from `<directory of the program>/../db`, not from an assign (read in
  `workbench/network/stacks/AROSTCP/bsdsocket/kern/amiga_main.c` of the AROS-NX tree; that tree is not touched). The ABI-v1
  image has `System/Network/AROSTCP/C/AROSTCP` and `dhclient` only: no `db/` and no `S/`. Without `db/` the daemon is alive
  (it shows in `Status FULL`) but never opens its port `AROSTCP`, and `ifconfig` does not return. The earlier attempt with a
  hand-made `db` in `RAM:` and `Assign AROSTCP:` failed for that reason: the assign is not used, and the check
  `Version bsdsocket.library` ran a `Version` command that is not on the image, so its "object not found" said nothing about the library.
- **What works.** The daemon copied to `RAM:N/C/AROSTCP` with the configuration of the ABI-v11 image in `RAM:N/db`
  (`Run RAM:N/C/AROSTCP`, wait, `WaitForPort AROSTCP` returns 0, `ifconfig -a` shows `lo0` with `127.0.0.1` and `::1`).
  Without a network card, as the runner starts the guest.
- **Smallest set found.** Eleven files of `db/`: `general.config`, `interfaces`, `netdb`, `netdb-myhost`, `protocols`,
  `services`, `hosts`, `networks`, `inet.access`, `passwd`, `group`, `static-routes`. Without `netdb-myhost` the port does not
  appear (the same set without it, and a set of five files, both failed); a set of six with it failed too, so the
  remaining files are needed as a group, not checked one by one. With `OPENGUI=NO` and `GUI PANEL=NONE` in `general.config`.
  The same files make the stack start on ABI-v11 from a copy in `RAM:`. The files were taken from the ABI-v11 image (AROS
  Public License); a delivery of them as test fixtures needs their licence recorded.
- **Not yet done.** The stack is not started by a program yet, and no socket call was made; A3 (loopback test on both ABIs)
  is open. Which side delivers the files (the matrix, as files of the delivery medium with `before` lines, or the runner's
  cached boot image) is not decided. Boots of the ABI-v1 image fault now and then before the script starts (1 in about 15
  runs here, a page fault in user mode at `CR2=0x10`, before any script line); a run that shows it is repeated.
