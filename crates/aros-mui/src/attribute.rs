use crate::{Class, ValueKind};

pub(crate) mod sealed {
    pub trait Attribute<C> {}
    pub trait Build<C> {}
    pub trait Get<C> {}
    pub trait Set<C> {}
}

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
