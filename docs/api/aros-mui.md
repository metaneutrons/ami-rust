---
title: "aros-mui: safe MUI objects and events"
description: "Typed, scope-owned MUI objects: builders, attributes, notifications, hooks, custom classes and the application loop."
---

`aros-mui` is the safe MUI layer. It opens `muimaster.library` and
`intuition.library` for an active `aros::Context`, then confines all native
objects to a `Mui::scope` closure that they cannot escape. It supports the
x86-64 AROS ABI-v1 and ABI-v11 targets, although a
[few classes](/reference/abi-differences/) exist on only one of them.

The rules shared by every handle are in the [programming model](/api/). Every
item is listed in the [reference](/reference/aros_mui/).

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
| `Object<'scope, C>` | A copyable, typed view of native storage that its `Scope` owns. Copying never clones or disposes native state. |
| `Object::adopt` | Transfers native child ownership only between compatible classes in the same scope. |
| `Object::upcast` | Changes the compile-time class view without changing lifetime or ownership. |

Every handle stays on the task that created it. Objects, hooks, retained strings
and custom classes from one scope cannot be used in another scope. The crate
rejects ownership cycles, duplicate attachment and a second window root before
it makes a native call.

## Construction and attributes

`Scope::builder::<C>()` creates a `Builder<C>`. Add construction attributes
with `Builder::with::<A>(value)`, then call `build`. `Object::set::<A>(value)`
and `Object::get::<A>()` accept only generated descriptors that are valid for the
object's class and for that direction of access.

| Module | Contents |
| --- | --- |
| `classes` | Supported standard MUI class hierarchy. |
| `attributes` | Class-checked construction, get, and set descriptors. |
| `methods` | Generated method descriptors. |
| `values` | Checked MUI enum and value types. |

The generated class, attribute, method and value types are part of the crate's
public API. The reference derives how they relate from the type system. It has
the [class hierarchy](/reference/aros_mui/classes/) with each class's own and
inherited attributes, the [attribute index](/reference/aros_mui/attributes/) with
value type and access mode (construct, set, get), the
[method index](/reference/aros_mui/methods/) and the
[value types](/reference/aros_mui/values/).

## Notifications and event loop

`Object::notify` starts a typed notification from a readable attribute. A
`Notification` can send an application `ReturnId`, make a typed write that does
not notify, or invoke a `Hook` that the scope retains. `Trigger::EveryTime` fires
on every change of the attribute, and `Trigger::Value(value)` fires only when the
attribute equals `value`.

A hook is valid only for its scope, and it is not reentrant. It receives the
native `HookCall` that MUI supplies. With `Trigger::Value`, do not assume that
the `HookCall` carries the current value of the source attribute, because that is
not so in every case.

`Object<Application>::run` is the event loop. It passes every return ID except
`QUIT` to your handler, which returns `LoopControl::Continue` or
`LoopControl::Exit`. Between steps it waits, through `aros::wait_signals`, for the
signals that MUI asked for. The loop returns `LoopExit::Quit` when MUI reports
`QUIT`, or `LoopExit::Handler(id)` when your handler chose to exit on return ID
`id`.

## Custom classes and the raw boundary

`Scope::custom_class::<S>()` registers a safe custom class that a
`CustomClassSpec` describes, and a `CustomBuilder` constructs a `CustomObject`.
The methods of a safe custom class are argument-free Rust enum values. A native
message whose layout the class does not describe is forwarded to the native
superclass. To handle such a message yourself, you need the explicit raw
boundary.

`ForeignPtr`, `RawAttribute`, `RawMethod` and `Object::call_raw` are expert
interfaces. When you use them, you must uphold the rules for message layout,
pointer lifetime, ownership and native retention. Ordinary applications should
use builders, generated attributes, notifications, hooks and custom classes.

## Examples

Each of these has a complete example, which the repository compiles, on the reference page of the item:

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
