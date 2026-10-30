# mui-hello

`mui-hello` is the smallest graphical AROS application in this repository. It
opens `muimaster.library` and `intuition.library` through `aros-mui`, creates an
application, window, group, and text objects, and remains in the standard MUI
event loop until the user closes the window.

The example uses no raw tags, pointers, vector calls, or application-specific
wrapper. Its target selects ABI-v1 or ABI-v11; the Rust source is the same for
both.

Build it from this checkout after installing the matching ami-rust toolchain:

```sh
cargo +0.1.0 build -p mui-hello \
  --target x86_64-unknown-aros-abi1 --release
cargo +0.1.0 build -p mui-hello \
  --target x86_64-unknown-aros-abi11 --release
```

For a standalone consumer project, see the complete manifest and target setup
in [the crates and consumer guide](../../docs/consumer-guide.md). Native ABI-v1
and ABI-v11 runs, plus the ABI-v11 WebP capture, are recorded in the
[qualification record](../../docs/mui-hello-qualification.md).
