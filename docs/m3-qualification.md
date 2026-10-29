# M3 raw MUI and BOOPSI qualification

Status: PASS on 2026-10-29. This record applies M3-A1 through M3-A4 in
`docs/plans/ami-rust-0.1.md` to the repository revision containing this file.
GitHub issue #9 owns the execution state; the plan remains the acceptance
authority. This is not a release qualification or publication.

## Pinned inputs

| Input | Exact identity |
| --- | --- |
| ABI1 source | AROS-NX commit `e0d5e367d15cc7da4ebac8f9db17868756c79569` |
| ABI11 source | Deadwood AROS commit `fbc242c1046cffb5e5827a4626ee62bdd45664e9` (`ABIv11_2026.09`) |
| ABI1 boot image | SHA-256 `9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1` |
| ABI11 boot image | SHA-256 `2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7` |
| ABI1 C SDK | Qualified Developer tree from the ABI1 source pin; archive SHA-256 `70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87` |
| ABI11 C SDK | `SDK-202609-any-x86_64.zip`, SHA-256 `8a4e5f09f027844501c1421bd3948c4e55ceb005a16b0bd3575276f40c8977e6` |
| C compiler | Clang 11.0.0, binary SHA-256 `8f46414db967c5d407757f3c55ea8ee0f923c1739cc69b004d80e451ea4ea514` |
| Rust | `nightly-2026-09-18`, rustc commit `330d317121e16b5db8e5adc63595910528ff2ee7`, LLVM 23.1.1 |
| ABI1 target | `targets/x86_64-aros.json`, SHA-256 `de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71` |
| ABI11 target | `targets/x86_64-unknown-aros-abi11.json`, SHA-256 `5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9` |
| QEMU | 11.1.2, binary SHA-256 `a1b97665fb9f341a65acf9b0e7dc4c7235972aae61182545ed1aacf5ffca87fa` |
| Firmware | `bios-256k.bin` SHA-256 `ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650`; `vgabios-stdvga.bin` SHA-256 `e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472` |

The AROS-NX checkout retained its pre-existing untracked `build/` directory and
no tracked change. The ABI11 source checkout remained clean. Neither AROS-NX
nor aros-tools was modified.

## Generated surface

The model produces these public occurrences and union names:

| Category | ABI1 | ABI11 | Union |
| --- | ---: | ---: | ---: |
| Classes | 72 | 68 | 72 |
| Attributes | 454 | 427 | 454 |
| Methods | 182 | 176 | 182 |
| Values | 95 | 82 | 95 |
| Identifier bases | 65 | 64 | 65 |
| Enum values | 157 | 157 | 157 |
| `MUIP_*` messages | 184 | 179 | 184 |

`cargo xtask check mui` reproduced `api.json`, provenance, both generated Rust
modules, and both C oracles byte for byte from the pinned Git objects. Every
public message uses `repr(C)` plus `Stacked<T>` for the x86-64 AROS per-field
alignment. This fixed the independently observed single-`ULONG` message size
case rather than special-casing one structure.

The reviewed vector allowlist contains all 25 non-variadic muimaster calls and
the six required Intuition calls. `aros-sys` also supplies non-variadic
`DoMethodA`, `DoSuperMethodA`, and `CoerceMethodA` adapters. ABI1 uses the
base-last call contract. ABI11 loads the library base into `r12`; its explicit
`MUI_RequestA` adapter places arguments one through six in SysV registers and
the seventh argument on the stack. The native synthetic vector probe verifies
both forms and the exact base value.

## Independent C comparison

The two generated C files were compiled with the pinned Clang using
`-target x86_64-unknown-aros -std=c11 -Wall -Wextra -Werror`, the corresponding
muimaster source directory, and the corresponding complete SDK include tree.

| ABI | C oracle source SHA-256 | C oracle object SHA-256 |
| --- | --- | --- |
| ABI1 | `60aa05fe0efafc20dbd228221def2fed58ecc7c913e4c9b39f2846c320c41202` | `0962c6eb5d892ebac339233408d6f3869e1458beec2a7561aff1dde2401bf6a1` |
| ABI11 | `2b54bd4e91ca1b37c08bd600fc2da5dc95af8479dc2444a3f0777e6c0542af36` | `527bf5f90a45a772ff652c462042e0c24f3b993e9b38b36a3fdc9281f3be723b` |

At runtime the application compares C and Rust sizes, alignments, and offsets
for `MinNode`, `Hook`, `IClass`, `MUI_CustomClass`, and every public message. It
also compares selected constants and the `MUIC_Window` class identifier.

## Native execution

Both cold boots used `pc-i440fx-11.1`, `qemu64-v1`, single-threaded TCG, one
vCPU, 512 MiB RAM, the pinned BIOS and VGA ROM, no network, and a read-only IDE
CD at index 2. The shell fixture used a 128 KiB stack.

| Target | Application SHA-256 | Qualification ISO SHA-256 | Durable observation | Result |
| --- | --- | --- | --- | --- |
| `x86_64-unknown-aros-abi1` | `d0901de9446aa9db77b154361a2a5895c8e5213bd55e22907d536e1cf3485bc3` | `9bb97733677d24eb6b9850e41341c1f466eeee679d9746200ebace734877d538` | serial log SHA-256 `5ccb95da202bba52edf12e74d90df17eb6a699643e20573bda5917df8b5144aa` | PASS |
| `x86_64-unknown-aros-abi11` | `77c2e6fce20eb8a5857bb1dc43209d6ef9f080a57fc15afea62cfec94cacf35a` | `6802c4cff124a9ef3a9082b0ca6fa968469568b972110cffa3baa66d14f86003` | screenshot SHA-256 `6fc68096c4273b9b9abe9e7f91137e29e6f52483a9736d8d5ad6b0ae1c79a362` | PASS, return code 0 |

The ABI1 serial record contains `layout pass`, `call adapter pass`, `raw MUI
pass`, and final `pass`. The ABI11 guest console reports `ami-rust M3 process
returned 0`. In both executions the application created a raw `Window.mui`
object, exercised all three BOOPSI adapters, released the class and object, and
finished with zero live allocation, backing-charge, file, library, port,
signal, and message counters.

## Acceptance mapping

- M3-A1: PASS. The complete public raw generated surface and provenance are
  committed and reproducible.
- M3-A2: PASS. The reviewed muimaster, Intuition, and BOOPSI non-variadic calls
  are present; no Rust variadic ABI is exposed.
- M3-A3: PASS. Both backends were source-reviewed and the ordinary plus
  seventh-stack-argument call shapes executed natively.
- M3-A4: PASS. Independent C comparison and one raw MUI application completed
  on each pinned ABI baseline using the exact binaries above.
