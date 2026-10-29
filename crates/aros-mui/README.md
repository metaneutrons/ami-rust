# aros-mui

Task-affine, typed MUI access for the selected AROS ABI profile. `Mui::open`
owns explicit `muimaster.library` and `intuition.library` references.
`Mui::scope` owns all native objects created inside its closure and disposes
only native roots; MUI parents recursively dispose children after ownership
transfer.

The M4 core provides sealed class and attribute traits, typed builders,
safe strings, booleans, numbers, enums and object references, plus typed
`get`, `set`, `adopt`, upcast and method operations. The initial shared class
set is `Application`, `Window`, `Group`, `Text`, `Area` and `Notify`.
Foreign pointers require the explicit unsafe `ForeignPtr` boundary. Raw tags,
native pointers and vector calls remain in `aros-mui-sys`.

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
