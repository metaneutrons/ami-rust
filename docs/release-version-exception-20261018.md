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
3. Fabian subsequently explicitly requested deleting the old candidate instead
   of creating a public historical archive. On 2026-10-18, release ID
   `416229826`, its six assets and the old `v0.1.0` tag were deleted. API
   readback confirmed both release and tag absent. The immutable-tag rule was
   restored to its original state after excluding only this exact tag for its
   deletion. Existing local evidence and original source/checksum records remain
   historical; no additional public archive release is required.
4. Stage the newly generated `0.1.0` candidate with fresh signatures and
   provenance bound to its actual source/run/attempt. Verify downloaded bytes.
   Record the old/new identity mapping in release notes and qualification data.
5. Complete the public two-host consumer replay and the required native replay
   before stable/latest promotion. Verify the final anonymous public downloads.

The corrected release is publisher commit
`b4ebb9cce5decd01616b75acf451d0eba9995ee3`, tree
`c5d9eed6b057ddadd17356801f8b3897e3e430dc`, from protected SDK run
`39121017959/1`. Its public two-host consumer run `39143613042/1` and fresh
155-case plus two-check native replay passed independent acceptance. Release
ID `416548451` is now stable/latest. The payload
`ami-rust-0.1.0-release.tar.xz` has SHA-256
`f4a8cbc562d3c43c573a5a34ddfa99d74928ded94c47df45f4182fde71567d5c`;
final anonymous downloads matched all six accepted files. See the
[public evidence summary](evidence/r1-0.1.0.json).

Removal of the old public candidate and qualification/publication of the
corrected release are complete. This exception does not establish a general permission to
replace future released versions, relax any acceptance test, reuse acceptance
for changed inputs or waive campaign budgets.

The AROS x86-64 ABI-v1 boot baseline remains unchanged. Protected AROS-NX and
aros-tools checkouts and nxpk remain outside this work.
