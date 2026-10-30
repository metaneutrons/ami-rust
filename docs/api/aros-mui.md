---
title: The aros-mui crate
description: "Typed, scope-owned MUI objects: builders, attributes, notifications, hooks, custom classes and the application loop."
---

`aros-mui` is the safe-facing MUI layer. It opens `muimaster.library` and
`intuition.library` for an active `aros::Context`, then confines all native
objects to a non-escaping `Mui::scope` closure. It supports the x86-64 AROS
ABI-v1 and ABI-v11 targets; a [few classes](/reference/abi-differences/) exist on only one. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_mui/).

```rust
use aros::Context;
use aros_mui::{Error, Mui, attributes::TextContents, classes::Text};

fn show_label(context: &Context) -> Result<(), Error> {
    let mui = Mui::open(context)?;
    let result = mui.scope(|scope| {
        let label = scope
            .builder::<Text>()
            .with::<TextContents>(c"Hello")?
            .build()?;
        let _ = label; // every object is disposed when the scope returns
        Ok::<(), Error>(())
    });
    mui.close()?;
    result
}
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

The generated class, attribute, method, and value types are part of the crate's
public API. The reference derives their relations from the type system:
the [class hierarchy](/reference/aros_mui/classes/) with each class's own and
inherited attributes, the [attribute index](/reference/aros_mui/attributes/) with
value type and access mode (construct, set, get), the
[method index](/reference/aros_mui/methods/) and the
[value types](/reference/aros_mui/values/).

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
[MUI hello](/mui-hello/).

## Worked examples

Each of these is a complete, compile-checked example on the item's reference page:

| To do this | See |
| --- | --- |
| Open MUI and create a scope | [`Mui`](/reference/aros_mui/mui/) |
| Build a window from a group and a label | [`Object::adopt`](/reference/aros_mui/object/#adopt) |
| Write and read attributes | [`Object::set`](/reference/aros_mui/object/#set) |
| Close the application when the window closes | [`Object::notify`](/reference/aros_mui/object/#notify) |
| Run the event loop and handle return IDs | [`Object::run`](/reference/aros_mui/object/#run) |
| Call back into Rust on a change | [`Hook`](/reference/aros_mui/hook/) |
| Define a custom class | [`CustomClassSpec`](/reference/aros_mui/customclassspec/) |
| Handle a failure by kind | [`Error`](/reference/aros_mui/error/) |

For a whole application, see [MUI hello](/mui-hello/).
