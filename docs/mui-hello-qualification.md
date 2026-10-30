# `mui-hello` native qualification

This is a focused documentation-example check, not a new SDK release gate. It
records that the committed `mui-hello` source opens and renders a safe
`aros-mui` window on both currently supported x86-64 AROS ABIs.

## Inputs

| Input | Identity |
| --- | --- |
| Source | commit `6c54167c1b5bb6f9f549a8c8988383dffbc6fbe9` |
| Toolchain | `0.1.0-aarch64-apple-darwin`; rustc `1.100.0-nightly` (`330d317121e16b5db8e5adc63595910528ff2ee7`), Cargo `1.100.0-nightly` (`495c385d0`) |
| ABI1 target | `targets/x86_64-unknown-aros-abi1.json`, SHA-256 `0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807` |
| ABI11 target | `targets/x86_64-unknown-aros-abi11.json`, SHA-256 `5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9` |
| ABI1 boot image | SHA-256 `9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1` |
| ABI11 boot image | SHA-256 `2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7` |
| QEMU | 11.1.3, SHA-256 `0dba441e49c3cda068f3b33916ad9d2146d173d9bb65a6a62ce2e61d3211baaf` |
| Firmware | SeaBIOS `ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650`; standard VGA ROM `e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472` |

## Method

Both artifacts were built from the committed workspace with ordinary Cargo:

```sh
CARGO_HOME=/tmp/ami-rust-native-cargo CARGO_BUILD_RUSTC_WRAPPER='' \
  cargo +0.1.0 build -p mui-hello --target <target> --release --locked
```

Each immutable boot image was copied to an ephemeral ISO. The copy received
only the matching executable and the `S:User-Startup` entry that opens a shell
and runs it. `xorriso -boot_image any keep` retained the original El Torito
record. The source boot images were never modified.

Each cold guest used `pc-i440fx-11.1`, `qemu64-v1`, one vCPU, 512 MiB RAM,
single-threaded TCG, the pinned BIOS and standard VGA ROM, an empty disposable
IDE disk at index 0, a read-only CD-ROM at index 2, and no network. After the
window was visible, QMP captured the framebuffer; QMP then stopped the guest.
The application deliberately remains in its event loop, so this check asserts
visible native startup and rendering, not an automatic process exit.

The repository image is a direct 320×130 crop at `(x=360, y=320)` from the
ABI11 framebuffer. It removes unused desktop area; no generated or substituted
content is present.

## Results

| Target | Executable SHA-256 | Derived ISO SHA-256 | Visible native result |
| --- | --- | --- | --- |
| `x86_64-unknown-aros-abi1` | `2996766e3017b2fa4f55be621547235085b20128525752ea2bc815ce76738f6f` | `d031e6633dd5948caafee9cd25f6dd15706bc5c6a848268811c8bca9346b54e7` | PASS: title, framed heading, detail text and close gadget rendered |
| `x86_64-unknown-aros-abi11` | `d6fa81cec6db7a2108b14a9efc7e3e4ca05489c4480e4d54ea3f79a16916cfb1` | `55233ef4c1d69c604bfaa5815c355cfe2b8367460f097dbe3934f33e68e0e65c` | PASS: title, framed heading, detail text and close gadget rendered |

The ABI11 raw framebuffer capture has SHA-256
`977469df527ece23f6bc86c7f8c88cbc51a910836128907a34ad920b186dcecf`.
The repository version is the 320×130 WebP crop
[`assets/mui-hello-abi11.webp`](../assets/mui-hello-abi11.webp), SHA-256
`4a38df85ab7fe9593920d16082c00355257ae69ea6d0d4c9c03bbf4f8667d885`.

This evidence qualifies the example's documented MUI path on the two named
targets. It does not extend the SDK compatibility boundary beyond the existing
0.1.0 release scope.
