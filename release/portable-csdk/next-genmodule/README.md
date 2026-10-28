# Prospective genmodule portability patches

`0001-genmodule-void-short-circuit.patch` prevents the regular-argument parser
from reading before its allocation for `void`, `...`, and other unnamed
arguments. It checks the existing empty-range branch before dereferencing
`end - 1`.

`0002-genmodule-suffix-vla-inline.patch` and
`0003-genmodule-suffix-vla-defines.patch` apply the same two writer fixes to the
inline and defines generators. The suffix checks now require a function name of
length greater than zero before checking a trailing `A`, at least seven before
checking `TagList`, and at least four before checking `Args`. Both writers also
allocate one `argtypes` slot when `argcount` is zero. The zero-argument path
emits `AROS_LC0` and skips the loop that reads `argtypes`, so this avoids a
zero-length VLA without changing generated output for that path.

All three patches are based on
`AROS-NX@e0d5e367d15cc7da4ebac8f9db17868756c79569`. Their source and patch
SHA-256 values are recorded in `series.json`. The original source notices and
applicable APL terms remain unchanged.

The combined void, suffix, and VLA postimages received an actual private
AddressSanitizer/UndefinedBehaviorSanitizer run. The instrumented genmodule
completed all 106 recipes, and all 530 generated headers matched both the
native and historical header maps; those two maps were identical. This is
specific evidence for that generator run and header comparison. It does not
qualify the full producer contract, native Linux behavior, or RC4 acceptance.
The result is recorded in
`../../../evidence/rc1-native-qualification-flow-20261019/rc4-genmodule-vla-patch-a1/result.json`
(SHA-256 `cb647dde773e52f20ec8499632f9eb99861f0b14aac784e7fd1a8954d3721776). The
patch-application replay report is at
`../../../evidence/rc1-native-qualification-flow-20261019/rc4-genmodule-writer-integration-a1/report.json`.

This remains an isolated prospective input. It is not wired into the sealed
C-SDK specification or published SDK. Original source archives, references,
compiler metadata, and the AROS boot/ABI baseline remain unchanged. The native
header recipe uses short, owned relative output paths to avoid the generator's
separate fixed-size output filename buffer.
