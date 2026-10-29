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
pub trait RawAttribute<C: Class>: sealed::RawAttribute<C> + 'static {
    const ID: u32;
    const C_TYPE: &'static str;
}

/// Attribute accepted during construction through the explicit unsafe API.
pub trait RawBuildAttribute<C: Class>: RawAttribute<C> + sealed::RawBuild<C> {}

/// Attribute readable through the explicit unsafe API.
pub trait RawGetAttribute<C: Class>: RawAttribute<C> + sealed::RawGet<C> {}

/// Attribute writable through the explicit unsafe API.
pub trait RawSetAttribute<C: Class>: RawAttribute<C> + sealed::RawSet<C> {}

/// A typed MUI attribute applicable to class `C`.
pub trait Attribute<C: Class>: sealed::Attribute<C> + 'static {
    type Value: ValueKind;
    const ID: u32;
}

/// Attribute accepted during object construction.
pub trait BuildAttribute<C: Class>: Attribute<C> + sealed::Build<C> {}

/// Attribute readable through `Object::get`.
pub trait GetAttribute<C: Class>: Attribute<C> + sealed::Get<C> {}

/// Attribute writable through `Object::set` and typed methods.
pub trait SetAttribute<C: Class>: Attribute<C> + sealed::Set<C> {}
