# One-time 0.1.0 release-version exception — 2026-10-18

Fabian explicitly authorised releasing the corrected SDK as `0.1.0` despite
an existing failed public prerelease using that version. The proposed `0.1.1`
migration is withdrawn. This decision changes version disposition only.

## Reason and consequence

There is no SDK implementation requirement to increment the version. Reusing
it creates an identification hazard: a cached archive or checkout named
`0.1.0` may contain the earlier candidate. A version string alone therefore
cannot identify the corrected SDK. Use the exact source commit, authenticated
producer run/attempt and archive SHA-256 to distinguish the candidates.

The earlier candidate is publisher commit
`e3d0adbd25aee4ad61a0506f7a451e69955cecba`, tree
`29957f13f2618accc31b4483e13914b5ed38867e`, originally associated with tag
`v0.1.0` and GitHub release ID `416229826`. It failed public replay; its
prepublication passes do not establish R1 completion.

## Required sequence

1. Merge the release-consumer fixes through protected source CI and freeze the
   corrected source. Keep package version `0.1.0`; omit the version migration.
2. Qualify the corrected source and inputs afresh. Both supported hosts must
   consume the same authenticated distribution bundle. Retain all installation,
   native runtime, memory, licensing, negative and authentication criteria.
3. Before replacing a public tag association or asset, preserve and verify the
   earlier source/tag mapping, release metadata, all six original assets and
   checksums under an unambiguous historical archive identity. Retain original
   provenance as historical evidence; do not relabel it as the corrected build.
4. Stage the newly generated `0.1.0` candidate with fresh signatures and
   provenance bound to its actual source/run/attempt. Verify downloaded bytes.
   Record the old/new identity mapping in release notes and qualification data.
5. Complete the public two-host consumer replay and the required native replay
   before stable/latest promotion. Verify the final anonymous public downloads.

The final corrected commit and checksums are pending; this record does not
claim that the archive transition, corrected qualification or publication has
already happened. This exception does not establish a general permission to
replace future released versions, relax any acceptance test, reuse acceptance
for changed inputs or waive campaign budgets.

The AROS x86-64 ABI-v1 boot baseline remains unchanged. Protected AROS-NX and
aros-tools checkouts and nxpk remain outside this work.
