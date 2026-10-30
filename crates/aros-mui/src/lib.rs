#![no_std]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Task-affine, typed MUI objects for AROS.
//!
//! This crate wraps MUI object creation, attributes, methods, notifications,
//! and custom classes with class- and value-typed Rust APIs. It builds on
//! `aros-mui-sys` for generated native identifiers and ABI declarations, and
//! keeps direct native vector access outside its public safe interface.
//!
//! # Task and scope ownership
//!
//! Open [`Mui`] on an AROS [`Context`](aros::Context), then create objects in
//! [`Mui::scope`]. A scope owns every native object, string array, callback,
//! and custom-class registration created through it. Its higher-ranked
//! closure prevents scope-bound handles from escaping. These values are task
//! affine and cannot be sent to another task.
//!
//! [`Scope::builder`] constructs a typed [`Object`]. Objects begin as native
//! roots; [`Object::adopt`] can transfer a child to a class-checked parent.
//! Both root objects and attached children remain usable through typed handles
//! until the scope ends. At scope teardown, the scope disposes remaining roots
//! and native parents dispose their adopted descendants.
//!
//! # Typed interfaces and raw boundaries
//!
//! The [`attributes`] module describes each generated attribute, the classes
//! on which it is valid, and whether it can be used during construction,
//! queried, or set. [`Object::set`], [`Object::get`], and typed methods accept
//! only descriptors with the corresponding capability. [`methods`] contains
//! generated message descriptors for calls whose message layout still needs
//! caller validation; dispatching those messages uses the explicit unsafe
//! [`Object::call_raw`] boundary. Raw attribute access follows the same rule.
//! [`ForeignPtr`] is another explicit unsafe boundary for pointers retained by
//! native code. Ordinary native vectors are not exposed by this crate.
//!
//! Notifications are registered between objects in the same scope. Hooks are
//! retained by that scope and are non-reentrant. Safe custom classes declare
//! argument-free methods and forward other native messages to their
//! superclass; messages with foreign layouts require the raw interface.
//!
//! The generated [`classes`] and [`values`] modules contain the supported
//! standard class hierarchy and typed enum/value vocabulary.

extern crate alloc;

mod allocation;
mod application;
mod attribute;
mod callback;
mod class;
mod custom;
mod method;
mod notification;
mod object;
mod requester;
#[path = "value.rs"]
mod value_kind;

pub mod attributes;
pub mod classes;
pub mod methods;
pub mod values;

pub use application::{LoopControl, LoopExit};
pub use attribute::{
    Attribute, BuildAttribute, GetAttribute, RawAttribute, RawBuildAttribute, RawGetAttribute,
    RawSetAttribute, SetAttribute,
};
pub use callback::{Hook, HookCall};
pub use class::{Class, IsA, ParentOf};
pub use custom::{CustomBuilder, CustomClass, CustomClassSpec, CustomObject};
pub use method::RawMethod;
pub use notification::{Notification, ReturnId, Trigger};
pub use object::{Builder, Error, Mui, Object, Scope};
#[doc(hidden)]
pub use value_kind::DecodeValueKind;
pub use value_kind::{ForeignPtr, MuiEnum, StringArray, ValueKind, value};
