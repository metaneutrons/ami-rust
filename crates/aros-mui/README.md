# aros-mui

Task-affine, typed MUI access for the selected AROS ABI profile. `Mui::open`
owns explicit `muimaster.library` and `intuition.library` references.
`Mui::scope` owns all native objects created inside its closure and disposes
only native roots; MUI parents recursively dispose children after ownership
transfer.

The M4 core provides sealed class and attribute traits, typed builders,
safe strings, retained string arrays, booleans, numbers, enums and reviewed
object references, plus typed get, set, adopt, upcast and method operations. M5
generates the complete public standard class surface, inherited relations,
valid attributes, method descriptors and values from the canonical ABI1/ABI11
model. Foreign pointers and incomplete or unproven native contracts remain
behind explicit unsafe raw operations. Raw tags, native pointers and vector
calls remain in aros-mui-sys.

The generated docs/mui-safe-api.md file at the repository root records every
operation's ABI availability and safe, typed-unsafe, raw, or unavailable
classification.

```rust
let result = mui.scope(|scope| {
    let text = scope
        .builder::<Text>()
        .with::<TextContents>(c"Hello from AROS")?
        .build()?;
    let group = scope.builder::<Group>().build()?;
    group.adopt(text)?;
    Ok::<_, aros_mui::Error>(())
});
```
