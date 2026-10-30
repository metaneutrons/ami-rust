use crate::{Class, ValueKind};

pub(crate) mod sealed {
    pub trait Attribute<C> {}
    pub trait Build<C> {}
    pub trait Get<C> {}
    pub trait Set<C> {}
    pub trait RawAttribute<C> {}
    pub trait RawBuild<C> {}
    pub trait RawGet<C> {}
    pub trait RawSet<C> {}
}

/// Generated descriptor for a public native attribute whose complete value
/// contract has not necessarily been proven safe.
///
/// Raw descriptors expose the native identifier and C type string. Their
/// values are machine words, so callers must use the corresponding unsafe
/// `Object` or builder operation and uphold the complete native retention
/// contract.
pub trait RawAttribute<C: Class>: sealed::RawAttribute<C> + 'static {
    /// Native MUI attribute identifier.
    const ID: u32;
    /// C-level value type recorded for the generated attribute.
    const C_TYPE: &'static str;
}

/// Attribute accepted during construction through the explicit unsafe API.
///
/// Implementations are generated and sealed. The raw tag value must satisfy
/// [`RawAttribute::C_TYPE`] for the full scope lifetime.
pub trait RawBuildAttribute<C: Class>: RawAttribute<C> + sealed::RawBuild<C> {}

/// Attribute readable through the explicit unsafe API.
///
/// The returned machine word needs interpretation according to
/// [`RawAttribute::C_TYPE`].
pub trait RawGetAttribute<C: Class>: RawAttribute<C> + sealed::RawGet<C> {}

/// Attribute writable through the explicit unsafe API.
///
/// The supplied machine word must satisfy [`RawAttribute::C_TYPE`] and its
/// native lifetime requirements.
pub trait RawSetAttribute<C: Class>: RawAttribute<C> + sealed::RawSet<C> {}

/// A typed MUI attribute applicable to class `C`.
///
/// Generated descriptors implement this trait only for supported classes.
/// The value type fixes how Rust inputs and outputs map to the native tag
/// word; capability traits below further restrict construction, reading, and
/// writing.
pub trait Attribute<C: Class>: sealed::Attribute<C> + 'static {
    /// Typed value representation used by this attribute.
    type Value: ValueKind;
    /// Native MUI attribute identifier.
    const ID: u32;
}

/// Typed attribute accepted by [`Builder::with`](crate::Builder::with).
///
/// This capability is generated only when the native class accepts the tag
/// during construction.
pub trait BuildAttribute<C: Class>: Attribute<C> + sealed::Build<C> {}

/// Typed attribute readable through [`Object::get`](crate::Object::get).
pub trait GetAttribute<C: Class>: Attribute<C> + sealed::Get<C> {}

/// Typed attribute writable through [`Object::set`](crate::Object::set) and
/// methods that update attributes.
pub trait SetAttribute<C: Class>: Attribute<C> + sealed::Set<C> {}
