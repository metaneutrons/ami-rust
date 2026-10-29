# M1 x86-64 dual-ABI qualification

Status: PASS on 2026-10-29. This record qualifies the runtime baseline used by
the 0.1 work; it is not a release or a release-candidate qualification.

## Pinned inputs

| Input | Exact identity |
| --- | --- |
| ABI1 source | AROS-NX commit `e0d5e367d15cc7da4ebac8f9db17868756c79569` |
| ABI1 boot image | `aros-nx-abiv1-qualified.iso`, SHA-256 `9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1` |
| ABI1 C SDK | `aros-nx-abiv1-qualified-sdk-20261013.tar.xz`, SHA-256 `70cc3e45969c6e1eca7e4c5c2183429b88424f6c22c8ec6bb90e6cc70452ab87` |
| ABI11 source | Deadwood AROS tag `ABIv11_2026.09`, commit `fbc242c1046cffb5e5827a4626ee62bdd45664e9` |
| ABI11 boot archive | `AROS-202609-pc-x86_64-boot-iso.zip`, SHA-256 `4d405e07b597d8d43964548b54b7c38dc4becaac6c6d681ad341567770fa007f` |
| ABI11 boot image | `aros-pc-x86_64.iso`, SHA-256 `2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7` |
| ABI11 SDK | `SDK-202609-any-x86_64.zip`, 14,716 archive entries, SHA-256 `8a4e5f09f027844501c1421bd3948c4e55ceb005a16b0bd3575276f40c8977e6` |
| Native LLVM tools | `aros-toolchain-v1-llvm11.0.0-macos-aarch64-pc-x86_64.tar.xz`, SHA-256 `969d150761a2a999a43992660ab6c84d8ab07c1396ce49b17024bb5b08993342` |
| Native collector | `aros-tools-v0.3.19-aarch64-apple-darwin.tar.gz`, SHA-256 `8eb7c8e1ea40dae35943295c01b208a07b4264cf6c41e9b498f3fb0493e44625` |
| Rust | `nightly-2026-09-18`, rustc commit `330d317121e16b5db8e5adc63595910528ff2ee7`, LLVM 23.1.1 |
| QEMU | 11.1.2, binary SHA-256 `a1b97665fb9f341a65acf9b0e7dc4c7235972aae61182545ed1aacf5ffca87fa` |
| Firmware | `bios-256k.bin` SHA-256 `ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650`; `vgabios-stdvga.bin` SHA-256 `e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472` |

The target contracts used for the final binaries are
`x86_64-aros.json` at SHA-256
`de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71`
for ABI1 and `x86_64-unknown-aros-abi11.json` at SHA-256
`5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9`
for ABI11. The canonical ABI1 alias has SHA-256
`0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807`.

## Execution profile

Both cold boots used the unchanged M0 profile: `pc-i440fx-11.1`,
`qemu64-v1`, single-threaded TCG, one vCPU, 512 MiB RAM, explicit BIOS and
standard-VGA ROMs, no network, and a read-only IDE CD at index 2. The launch
fixture supplied a 128 KiB shell stack.

The same `no_std` Rust application body was compiled for both targets. It
verified:

- a 4 KiB allocation, byte fill, byte check, and deallocation;
- DOS create, write, close, reopen, read, compare, and close;
- `utility.library` open and close;
- `muimaster.library` open, `Window.mui` construction, disposal, and close;
- zero live allocation, file, library, port, signal, and message ledgers;
- clean process exit.

The final shell result was `ami-rust M1 process returned 0` for both ABIs.

| Target | Final application SHA-256 | Qualification ISO SHA-256 | Result |
| --- | --- | --- | --- |
| `x86_64-unknown-aros-abi1` | `6665cf8cba9de28b34b040fe7e6dc8219ddc1ac5bfca5df9b478bcb7ad3d941c` | `fc310dd6cf9fa51e2e8476e6f47adbf7a45cf2e03f6b79c7227dd76b110d7c8b` | PASS, return code 0 |
| `x86_64-unknown-aros-abi11` | `17b42eadd7635a434ce4d8d10c8694ced1a233fbe9a3e50a5d6a391fc623656d` | `e88448c01370042d57b40c1be1d9d9605f024f28ffbe53696b21f9eabd903c3f` | PASS, return code 0 |

## ABI evidence and required bridge changes

Disassembly of the exact ABI1 binary shows the MUI wrappers placing the
library base last: `mui_new_object_a` moves the base from `rdi` to `rdx` before
jumping through vector `-40`, while `mui_dispose_object` moves it to `rsi`
before vector `-48`.

Disassembly of the exact ABI11 binary shows the application loading the MUI
base into `r12`, then calling vectors `-40` and `-48` through that register.
The ABI11 bridge also isolates `FindTask(NULL)` in a non-inlined C function.
The pinned Clang 11 otherwise reused `r12` for a live ordinary value around
the inline library call, overwrote the ABI11 base register, and faulted. This
source-level boundary preserves the pinned compiler and the ABI contract.

ABI11 header differences required conditional layout descriptions for
`Library`, `MsgPort`, and the ABI1-only `spinlock_t`, plus a conservative
`PTRDIFF_MAX` fallback for the older SDK headers. These changes are confined to
ami-rust. This work did not modify AROS-NX or aros-tools, and the qualified ABI1
boot and SDK inputs remain unchanged.

## Acceptance

M1-A1 through M1-A4 pass. The application and fixtures live in
`tests/m1-runtime`; the native bridge changes are mirrored in the packaged
`aros-native-build` sources. The implementation PR and merge revision form the
source identity and are recorded in the M1 issue acceptance record.
