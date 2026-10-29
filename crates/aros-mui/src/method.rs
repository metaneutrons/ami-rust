//! Safe and explicitly unsafe typed MUI method dispatch.

use crate::{Attribute, Class, Error, Object, Scope, SetAttribute, ValueKind};
use aros_mui_sys::{MUIM_NoNotifySet, MUIP_NoNotifySet, Stacked};
use core::marker::PhantomData;

pub(crate) mod sealed {
    pub trait Method<C> {}
    pub trait RawMethod<C> {}
}

/// A sealed safe MUI method applicable to class `C`.
pub trait Method<C: Class>: sealed::Method<C> + 'static {
    type Arguments<'scope>;
    type Output;

    #[doc(hidden)]
    unsafe fn invoke<'scope>(
        scope: &'scope Scope,
        object: Object<'scope, C>,
        arguments: Self::Arguments<'scope>,
    ) -> Self::Output;
}

/// Generated native message descriptor. Calling it is unsafe because the
/// message fields may contain unvalidated pointers and retained resources.
pub trait RawMethod<C: Class>: sealed::RawMethod<C> + 'static {
    type Message;
    const ID: u32;
}

/// Typed `MUIM_NoNotifySet` for any safely writable attribute.
#[derive(Clone, Copy, Debug)]
pub struct NoNotifySet<A>(PhantomData<A>);

impl<C, A> sealed::Method<C> for NoNotifySet<A>
where
    C: Class,
    A: SetAttribute<C>,
{
}

impl<C, A> Method<C> for NoNotifySet<A>
where
    C: Class,
    A: SetAttribute<C>,
{
    type Arguments<'scope> = <<A as Attribute<C>>::Value as ValueKind>::Input<'scope>;
    type Output = Result<(), Error>;

    unsafe fn invoke<'scope>(
        scope: &'scope Scope,
        object: Object<'scope, C>,
        arguments: Self::Arguments<'scope>,
    ) -> Self::Output {
        let value = <A::Value as ValueKind>::encode(scope, arguments)?;
        let mut message = MUIP_NoNotifySet {
            MethodID: Stacked::new(MUIM_NoNotifySet),
            attr: Stacked::new(A::ID),
            val: Stacked::new(value as isize),
        };
        // SAFETY: the typed object and generated layout belong to the live
        // scope; the attribute encoder validated every retained input.
        unsafe {
            aros_sys::do_method_a(
                object.raw().as_ptr().cast(),
                core::ptr::addr_of_mut!(message).cast(),
            )
        };
        Ok(())
    }
}
