#![no_std]
//! Task-affine, typed MUI objects for AROS.
//!
//! `Mui::scope` owns every native object created inside its closure. Typed
//! handles remain valid until that closure returns, including after native
//! parent/child ownership transfer. Raw vector calls stay in `aros-mui-sys`.

extern crate alloc;

mod attribute;
mod class;
mod method;
mod object;
#[path = "value.rs"]
mod value_kind;

pub mod attributes;
pub mod classes;
pub mod methods;
pub mod values;

pub use attribute::{
    Attribute, BuildAttribute, GetAttribute, RawAttribute, RawBuildAttribute, RawGetAttribute,
    RawSetAttribute, SetAttribute,
};
pub use class::{Class, IsA, ParentOf};
pub use method::RawMethod;
pub use object::{Builder, Error, Mui, Object, Scope};
#[doc(hidden)]
pub use value_kind::DecodeValueKind;
pub use value_kind::{ForeignPtr, MuiEnum, StringArray, ValueKind, value};
