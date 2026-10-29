#![no_std]
//! Task-affine, typed MUI objects for AROS.
//!
//! `Mui::scope` owns every native object created inside its closure. Typed
//! handles remain valid until that closure returns, including after native
//! parent/child ownership transfer. Raw vector calls stay in `aros-mui-sys`.

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
