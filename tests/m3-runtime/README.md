# M3 raw MUI dual-ABI qualification

This private application compares every generated public `MUIP_*` message
layout with an independently compiled C oracle, compares selected constants
and a class identifier, then creates and disposes a raw `Window.mui` object.
It also exercises the non-variadic `DoMethodA`, `CoerceMethodA`, and
`DoSuperMethodA` adapters and a synthetic `MUI_RequestA` vector that verifies
the ABI1 base-last argument and the ABI11 `r12` plus seventh-stack-argument
contract without opening a requester.

The ABI-specific C oracle files are generated from the pinned MUI input model.
They are compiled with the pinned AROS Clang and source-header closure before
the application is linked and run on the corresponding qualified image.
The exact inputs, commands, artifact identities, and results are recorded in
[`docs/m3-qualification.md`](../../docs/m3-qualification.md).
