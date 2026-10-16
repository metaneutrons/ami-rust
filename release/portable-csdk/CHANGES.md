# Portable C-SDK modifications

## 2026-10-16 — ami-rust portability patch set, revision 2

The AROS-covered modifications are derived from Original Code provided by the
AROS Development Team (Initial Developer), preserved at AROS source revision
`e0d5e367d15cc7da4ebac8f9db17868756c79569`. Original notices and licence terms
remain in force. The AROS Public License 1.1 applies to the covered modifications;
see [the complete licence](APL-1.1.txt).

The [versioned patch series](../patches/portable-csdk/series.json) records exact
original and resulting source digests, source revisions and patch digests:

- `0001-relative-genmodule-provenance.patch` changes the copied aros-tools
  `GenmoduleHeaders.cmake` generator to emit relative source provenance for five
  public headers. The aros-tools source revision is
  `b399c714560e6629b4084290ce5575513521c8e3`.
- `0002-relative-nouveau-diagnostics.patch` changes the AROS
  `workbench/hidds/nouveau/mmakefile.src` build recipe to map the original absolute
  source prefix to a relative prefix using compiler file-prefix mapping. All
  825 objects are rebuilt from source: 616 retain their original bytes and 209
  change only the source-prefix strings. No finished object or archive is
  rewritten to remove paths.
- `0003-relocatable-aom-pkgconfig.patch` changes libaom 3.12.1's
  `build/cmake/pkg_config.cmake`: derive the install prefix from the location of
  `aom.pc` and select the AROS target's math-link configuration. The pinned AROS
  C-SDK provides its math routines in `libstdc.a` and has no separate `libm.a`.
  The original upstream archive and pre-existing AROS patch remain preserved.
- `0004-relative-public-module-provenance.patch` changes the copied aros-tools
  `AROS.cmake` generator to emit relative source provenance for the remaining
  525 public headers, from the same aros-tools revision as patch 0001.

The derived C-SDK preserves all 2,835 original file names. Its 532 changed files
are the 530 generated headers, `lib/libdrm_nouveau.a` and `lib/pkgconfig/aom.pc`.
The [original and derived identities](spec.json) are separate. This record does
not change the qualified boot/ABI-v1 baseline or the protected source checkouts.
Complete Linux qualification and the independent ami-rust release gates remain
required before an SDK release.
