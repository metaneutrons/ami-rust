# RC1 receipt records

This partial [RC1 delivery](https://github.com/metaneutrons/ami-rust/issues/71)
implements structural parsing in `tooling/crates/core/src/receipts.rs` under
the frozen migration contracts. It does not activate a consumer command.

The parser distinguishes qualification v1, historical production v2 and native
v3. V1/v2 never identify a native Rust driver. V3 requires the frozen host,
CLI/core identity and authentication fields; the current statically linked
launcher uses equal CLI/core digests. Parsing does not establish that any
claimed executable exists or that the current host matches it.

Every family has exact outer fields. Authentication/report/workflow and
inventory rows also have closed typed fields. The shared JSON boundary retains
UTF-8, duplicate-key, container-depth and 4 MiB input checks. Inventory paths,
required metadata, exact/case/ancestor conflicts, SHA strings, positive workflow
counters and the historical file/byte profiles are checked before any caller
may use the record.

The authentication object is still an untrusted report. Its schema, publisher,
workflow, subjects and manifest binding must be internally consistent; no
cryptographic publisher verification occurs here. External receipt-pin,
policy, full release/SDK manifest and actual filesystem binding remain separate
required checks before installation, inspection, migration or removal.

## Historical integer compatibility

The pinned Python 3.12.15 validator accepts exact positive workflow counters
above u64. A u64-only Rust representation was found during independent review
and replaced. A bounded typed `raw_value` prepass borrows just the two counter
tokens. A lexical depth guard runs before ignored children. Large integer
tokens use finite placeholders only in a temporary validation copy; the full
duplicate/depth/schema/type checks follow and the exact original tokens are
restored in the returned report. The input record is never rewritten and its
external digest must always use the original bytes.

The 4,300-digit boundary is measured from that pinned runtime, not an invented
application quota. The old Python parser raises an uncaught `ValueError` at
4,301 digits; the Rust core reports a refusal. Exponent-form JSON numbers remain
invalid as integer workflow counters. Serialization preserves accepted decimal
tokens exactly. `arbitrary_precision` remains disabled; the raw-value feature
adds no registry packages or licence identities. See the
[feature review](rc1-receipt-inputs.json).

Typed refusal wording and the first reported problem can differ for records
containing several errors. The compatibility evidence compares decisions,
typed accepted fields and inventory identities; it does not claim identical
internal exception text or public CLI diagnostics before command integration.

## Evidence scope

The Rust tests consume inert fixture JSON and recorded oracle results. They
execute no Python. Fourteen historical v1/v2 cases cover two accepts and twelve
refusals; six additional counter cases cover u64, larger exact integers, the
digit limit and exponent form. Native v3 has separate positive/negative contract
tests because the historical validator does not support that schema. Tests also
check unknown nested fields, duplicate keys after counter normalization,
private-number object decoys, exact depth, and normalized counter serialization.

The copied oracle records identify their source and pinned interpreter; their
Python exception for the over-limit integer remains recorded. Receipt parsing
has independent review and focused tests. Full both-host CI, filesystem/release
binding and all remaining RC1 acceptance criteria are separate gates.
