---
title: M5 generated MUI API qualification
---

# M5 generated MUI API qualification

Status: PASS on 2026-10-29. This record applies M5-A1 through M5-A4 in
docs/plans/ami-rust-0.1.md to the repository revision containing this file.
GitHub issue #11 owns the execution state. This is not a release qualification
or publication.

## Pinned inputs

| Input | Exact identity |
| --- | --- |
| M4 dependency | Accepted commit b8ab0a6a0b799042d0e038890da513d3fb18ef2e |
| ABI1 source | AROS-NX commit e0d5e367d15cc7da4ebac8f9db17868756c79569 |
| ABI11 source | Deadwood AROS commit fbc242c1046cffb5e5827a4626ee62bdd45664e9 (ABIv11_2026.09) |
| Canonical MUI model | bindings/mui/api.json, SHA-256 4c1aed0484cdd070a729e1ea2d99677257158cf393eab6d9e0555558fe2614f4 |
| Reviewed safe overrides | bindings/mui/safe-overrides.json, SHA-256 71c5d61d8570ddce38e05a72492df1c68f629471003609856c95e9a822fb2c3f |
| ABI1 boot image | SHA-256 9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1 |
| ABI11 boot image | SHA-256 2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7 |
| ABI1 target | targets/x86_64-unknown-aros-abi1.json, SHA-256 0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807 |
| ABI11 target | targets/x86_64-unknown-aros-abi11.json, SHA-256 5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9 |
| Rust/Cargo/native objects | Unchanged accepted M4 inputs recorded in docs/m4-qualification.md |
| QEMU | 11.1.2, SHA-256 a1b97665fb9f341a65acf9b0e7dc4c7235972aae61182545ed1aacf5ffca87fa |
| Firmware | bios-256k.bin SHA-256 ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650; vgabios-stdvga.bin SHA-256 e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472 |

The AROS-NX checkout retained only its pre-existing untracked build directory.
The ABI11 source checkout remained clean. Neither AROS-NX nor aros-tools was
modified.

## Generated surface

The existing cargo xtask generate mui command now derives both raw and safe
outputs from the same canonical dual-ABI model. cargo xtask check mui
reconstructs and byte-compares the complete output set. Generated Rust source is
not edited by hand.

The classified manifest at bindings/mui/safe-api.json has SHA-256
b71fad153f5c54d608066ad554d16692c62a3fce25e67e65d5b0582a12c87c95
and records:

- 72 public standard classes with safe fallible builders;
- 454 public attributes and all 1,362 possible init/set/get positions: 652 safe,
  172 typed-unsafe, and 538 unavailable under the native access markers;
- 182 public methods: one existing safe equivalent, 175 generated typed-unsafe
  message descriptors, and six raw-only methods whose headers expose no complete
  public message structure;
- 252 public values: 113 members of 29 generated checked enums and 139 raw
  constants or parameterized values.

The generated class layer expresses all transitive superclass relations.
Attribute and method implementations are written once against their defining
class and become available to every generated subclass through the sealed IsA
relation. Parent capabilities similarly use generated role relations rather
than handwritten forwarding implementations.

Every class uses the shared M4 builder. Native object pointers, hooks, incomplete
messages, and other contracts that cannot be proven safe remain behind
RawBuildAttribute, RawSetAttribute, RawGetAttribute, or RawMethod and an
explicit unsafe call. Reviewed string-array contracts use scope-owned
NULL-terminated pointer arrays. The one reviewed typed-object override preserves
same-scope identity without transferring ownership. Generated documentation in
docs/mui-safe-api.md lists every class and operation with ABI availability and
its safe, typed-unsafe, raw, or unavailable classification.

## Verification

The following focused checks passed:

- byte-clean cargo xtask check mui against both pinned source trees;
- cargo check -p aros-mui --all-targets --locked --offline;
- cargo test -p aros-mui --locked --offline;
- cargo clippy -p aros-mui --all-targets --no-deps --locked --offline -- -D warnings;
- RUSTDOCFLAGS="-D warnings" cargo doc -p aros-mui --no-deps --locked --offline;
- release builds of the M4 compatibility application for ABI1 and ABI11;
- release builds of the M5 gallery for ABI1 and ABI11.

The repository-wide xtask Clippy command was also inspected. It still reports
six pre-existing findings in unrelated acquisition, archive-comparison,
publisher, and parser code. The MUI generator compiles and its byte-reproduction
gate passes; no unrelated source was changed for M5.

The gallery source contains no unsafe block, native object pointer, raw tag
list, raw vector call, or class-specific binding implementation. It constructs
an Application with a Menustrip/Menu/Menuitem hierarchy and a Window containing
a vertical Group, text, a button, a String gadget, a List backed by a retained
string array, and a Register with two pages.

Both cold boots used pc-i440fx-11.1, qemu64-v1, single-threaded TCG, one vCPU,
512 MiB RAM, the pinned BIOS and VGA ROM, no network, and a read-only IDE CD at
index 2. The shell fixture used a 128 KiB stack. A successful process exit
requires all tracked allocation, backing-charge, file, library, port, signal,
and message counters to be zero after object-scope and library cleanup.

| Target | Application SHA-256 | Qualification ISO SHA-256 | Durable observation | Result |
| --- | --- | --- | --- | --- |
| x86_64-unknown-aros-abi1 | f499e451a44e4aa9cb1cb6cac9d2f0446426a2e5480b1c55118b39fb2e0756f8 | ef5b89d74a705748c449979dacec020c09072d15676abf66b19a2224e6758977 | serial log SHA-256 1f77da39b2d8f337e031412253fdc4c6d996063344d933478332db53655353c6 | PASS |
| x86_64-unknown-aros-abi11 | 3cb29771a577ea0c8cdd0fcf50c11667be868b7843f171d19492153de8166556 | 1afc91ad184598792b6f86e6d9f1511149e4f7e0222ad8b61f428871558f19f2 | screenshot SHA-256 1765df0f4e93e26b30ab67cf649c3c85cb75bd85b42e8e5cbb58286fb62ae0b1 | PASS, return code 0 |

The ABI1 serial record contains gallery pass, cleanup pass, and final pass. The
ABI11 guest console reports "ami-rust M5 process returned 0".

## Acceptance mapping

- M5-A1: PASS. All 72 public classes and the complete classified attribute,
  method, value, builder, inheritance, ABI-availability, and documentation
  surface are generated from the canonical model.
- M5-A2: PASS. Generated transitive IsA and parent-role relations expose
  inherited operations without per-subclass forwarding code.
- M5-A3: PASS. Every class has the shared safe fallible builder; all valid
  operations have an explicit safe, typed-unsafe, raw, or unavailable
  classification and the corresponding API boundary.
- M5-A4: PASS. The representative safe gallery builds and runs on both pinned
  ABIs without application unsafe code or handwritten class bindings.
