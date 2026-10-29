# M4 safe MUI object-model qualification

Status: PASS on 2026-10-29. This record applies M4-A1 through M4-A4 in
`docs/plans/ami-rust-0.1.md` to the repository revision containing this file.
GitHub issue #10 owns the execution state. This is not a release qualification
or publication.

## Pinned inputs

| Input | Exact identity |
| --- | --- |
| ABI1 source | AROS-NX commit `e0d5e367d15cc7da4ebac8f9db17868756c79569` |
| ABI11 source | Deadwood AROS commit `fbc242c1046cffb5e5827a4626ee62bdd45664e9` (`ABIv11_2026.09`) |
| ABI1 boot image | SHA-256 `9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1` |
| ABI11 boot image | SHA-256 `2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7` |
| ABI1 C SDK | Qualified Developer tree from the ABI1 source pin; archive SHA-256 `70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87` |
| ABI11 C SDK | `SDK-202609-any-x86_64.zip`, SHA-256 `8a4e5f09f027844501c1421bd3948c4e55ceb005a16b0bd3575276f40c8977e6` |
| Rust | `nightly-2026-09-18`, rustc commit `330d317121e16b5db8e5adc63595910528ff2ee7`, LLVM 23.1.1 |
| Cargo | 1.99.0 commit `3efb1f477`; binary SHA-256 `671bc15372da8d9abfe15dadbcc4ac00c61fe2f16c1fad86361dc8bcc99396e3` |
| rustc | Binary SHA-256 `5bb7cf7ca89e240c2f97c00c94b5aa3576a84798def7d329b72cb12a20e6e6d0` |
| ABI1 linker | `aros-link` SHA-256 `bdff517d08d9d70fd27f4b7a6c3fd9746ddeb7ee32f7345cc38550536f361a42` |
| ABI11 linker | Accepted link adapter SHA-256 `83dc4003a83274d8f666a9587350060d45087b052ee181f0dc9167e32a54b55c` |
| ABI1 target | `targets/x86_64-unknown-aros-abi1.json`, SHA-256 `0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807` |
| ABI11 target | `targets/x86_64-unknown-aros-abi11.json`, SHA-256 `5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9` |
| Native objects | ABI1 manifest SHA-256 `7c12fea03cbe8ceddc350db7ad0002ddde048406d2dcf5f57c440324b81b6191`; ABI11 manifest SHA-256 `79f3d389dd72e3f7a429550d1355cd26acf88c56272ad5a6ccaf4d055812db64` |
| QEMU | 11.1.2, binary SHA-256 `a1b97665fb9f341a65acf9b0e7dc4c7235972aae61182545ed1aacf5ffca87fa` |
| Firmware | `bios-256k.bin` SHA-256 `ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650`; `vgabios-stdvga.bin` SHA-256 `e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472` |

The AROS-NX checkout retained only its pre-existing untracked `build/`
directory. The ABI11 source checkout remained clean. Neither AROS-NX nor
aros-tools was modified.

## Safe model and ownership contract

`Mui` owns the task-affine `muimaster.library` and `intuition.library`
references. `Mui::scope` creates a non-escaping native-object arena; the
higher-ranked closure prevents an `Object` from outliving that arena. Class,
superclass, parent/child, attribute, method, and builder traits are sealed, so
safe downstream code cannot invent native identifiers or unsupported
relations.

The scope reserves ledger capacity before native construction. A new object is
therefore recorded as a root without a fallible allocation after the native
constructor succeeds. Parent attachment validates both scope identity and the
sealed parent/child relation, rejects repeated ownership, cycles, and a second
window root, and changes the ledger only around the synchronous native
operation. Scope destruction disposes roots in reverse order; MUI recursively
disposes transferred descendants. Constructor failure and unattached objects
remain roots and are cleaned up by the same path.

Typed values cover strings, booleans, signed and unsigned numbers,
pointer-sized numbers, closed enums, and same-scope object references.
Pointer-valued expert contracts require `ForeignPtr::from_raw`, an explicit
unsafe constructor with a scope lifetime. Raw MUI vectors, tags, native object
pointers, and ownership state remain private.

## Verification

The focused host checks passed with Rust 1.98.1:

- `cargo check -p aros-mui --all-targets --locked --offline`;
- `cargo test -p aros-mui --locked --offline`;
- `cargo clippy -p aros-mui --all-targets --no-deps --locked --offline -- -D warnings`;
- `cargo doc -p aros-mui --no-deps --locked --offline`.

The existing M1 runtime consumer also built successfully for both targets with
the new safe API. Its host-side build dependencies came from the existing
offline Cargo cache because its current lock file is newer than the Rust source
vendor snapshot; this compatibility build is not used as M4 runtime evidence.

The M4 application source contains no `unsafe`, raw tag list, raw vector call,
or native object pointer. It constructs
`Application -> Window -> Group -> Text`, exercises typed strings, booleans,
numbers, enums, object references, an inherited attribute, a typed method, and
a rejected second window root. A successful exit also requires every runtime
allocation, backing charge, file, library, port, signal, and message counter to
be zero after scope and library cleanup.

Both cold boots used `pc-i440fx-11.1`, `qemu64-v1`, single-threaded TCG, one
vCPU, 512 MiB RAM, the pinned BIOS and VGA ROM, no network, and a read-only IDE
CD at index 2. The shell fixture used a 128 KiB stack.

| Target | Application SHA-256 | Qualification ISO SHA-256 | Durable observation | Result |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-aros-abi1` | `6cd1c1df9a2b5a8bd16f46fd27ab90eb3ef04c8403229fe9ae0ff929af01c5f9` | `95940d7c1e1c75487373d3c0fcb1d2e9447098f8b68787440225467e69c083d0` | serial log SHA-256 `562d6a37cc25dd86289396a47c34177ed9dc17f28c964adf374f87f75fc795d2` | PASS |
| `x86_64-unknown-aros-abi11` | `a7c98eadfc1cb397e7548899132a4bafef609fe5491bea1ce17878236ad9257b` | `7301d4ae5dff11ab386a7d8fb4a7fdc2b550f43ba5e79a50dbd35271da77c65d` | screenshot SHA-256 `a6d071617df168a427f0a480201695ea9d9918b364b7a2b82791b7c5d1164468` | PASS, return code 0 |

The ABI1 serial record contains `safe tree pass`, `cleanup pass`, and final
`pass`. The ABI11 guest console reports `ami-rust M4 process returned 0`.

## Acceptance mapping

- M4-A1: PASS. The shared task-affine scope, typed handles, sealed class and
  relationship traits, typed attributes and methods, and generic builder are
  implemented.
- M4-A2: PASS. The ownership ledger covers roots, transfer, cycle and duplicate
  rejection, partial construction, and reverse root disposal; both native runs
  ended with every tracked resource counter at zero.
- M4-A3: PASS. Supported scalar, string, enum, and typed-object conversions are
  safe; foreign pointers are isolated behind an explicit unsafe type.
- M4-A4: PASS. The committed safe application built and ran on both pinned ABI
  baselines without application unsafe code or raw MUI operations.
