---
title: aros-mui API
description: Typed, scope-owned MUI objects for AROS applications.
---

# `aros-mui` API

`aros-mui` is the safe-facing MUI layer. It opens `muimaster.library` and
`intuition.library` for an active `aros::Context`, then confines all native
objects to a non-escaping `Mui::scope` closure. It supports the x86-64 AROS
ABI-v1 and ABI-v11 targets.

```rust
let mui = aros_mui::Mui::open(context)?;
mui.scope(|scope| {
    let text = scope.builder::<aros_mui::classes::Text>().build()?;
    let _ = text;
    Ok::<(), aros_mui::Error>(())
})?;
```

## Ownership model

| Item | Contract |
| --- | --- |
| `Mui::open(context)` | Opens MUI and Intuition for the active task. Keep it alive for all scopes. |
| `Mui::scope` | Runs a higher-ranked closure with a fresh `Scope`; scope-bound values cannot escape it. |
| `Scope` | Owns native roots, string arrays, hooks, and custom-class registrations. |
| `Object<'scope, C>` | A copyable typed view of native storage owned by its `Scope`; copying never clones or disposes native state. |
| `Object::adopt` | Transfers native child ownership only between compatible classes in the same scope. |
| `Object::upcast` | Changes the compile-time class view without changing lifetime or ownership. |

Every handle is task-affine. Objects, hooks, retained strings, and custom
classes from one scope cannot be used in another scope. Ownership cycles,
duplicate attachment, and a second window root are rejected before a native
call.

## Construction and attributes

`Scope::builder::<C>()` creates a `Builder<C>`. Add construction attributes
with `Builder::with::<A>(value)`, then call `build`. `Object::set::<A>(value)`
and `Object::get::<A>()` accept only generated descriptors that are valid for
the object's class and access direction.

| Module | Contents |
| --- | --- |
| `classes` | Supported standard MUI class hierarchy. |
| `attributes` | Class-checked construction, get, and set descriptors. |
| `methods` | Generated method descriptors. |
| `values` | Checked MUI enum and value types. |

The full generated class, attribute, method, and value inventory is available
in the [MUI API inventory](https://ami-rust.metaneutrons.cc/mui-safe-api/).

## Notifications and event loop

`Object::notify` starts a typed notification from a readable attribute.
`Notification` can send an application `ReturnId`, make a typed no-notify
write, or invoke a scope-retained `Hook`. `Trigger::EveryTime` listens to every
change; `Trigger::Value(value)` listens for a typed match.

Hooks are non-reentrant and valid only for their scope. A hook receives the
native `HookCall` supplied by MUI; callers must not assume that a value trigger
provides the current source-attribute value in every native case.

`Object<Application>::run` processes MUI return IDs and waits for the signal
mask supplied by the preceding native input step. It returns `LoopExit::Quit`
for MUI's reserved quit ID or `LoopExit::Handler(id)` when the handler asks to
exit.

## Custom classes and raw boundary

`Scope::custom_class::<S>()` registers a safe custom class described by
`CustomClassSpec`; `CustomBuilder` constructs a `CustomObject`. Safe custom
methods are argument-free Rust enum values. Foreign-layout native messages are
forwarded to the native superclass or require the explicit raw boundary.

`ForeignPtr`, `RawAttribute`, `RawMethod`, and `Object::call_raw` are expert
interfaces. Their callers must uphold message layout, pointer lifetime,
ownership, and native retention rules. Ordinary applications should use
builders, generated attributes, notifications, hooks, and custom classes.

For a full application, start with
[MUI hello](https://ami-rust.metaneutrons.cc/mui-hello/).
