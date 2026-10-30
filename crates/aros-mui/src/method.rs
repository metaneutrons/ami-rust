//! Safe and explicitly unsafe typed MUI method dispatch.
//!
//! [`Method`] implementations encode their own argument and return-value
//! contract. Generated [`RawMethod`] descriptors identify native messages
//! whose layouts are exposed to callers; dispatch through them is available
//! only as [`Object::call_raw`](crate::Object::call_raw).

use crate::{Attribute, Class, Error, Object, Scope, SetAttribute, ValueKind};
use aros_mui_sys::{MUIM_NoNotifySet, MUIP_NoNotifySet, Stacked};
use core::marker::PhantomData;

pub(crate) mod sealed {
    pub trait Method<C> {}
    pub trait RawMethod<C> {}
}

/// A sealed safe MUI method applicable to class `C`.
///
/// Implementations validate and encode their arguments before dispatch. The
/// associated lifetime ties borrowed arguments to the same object scope.
pub trait Method<C: Class>: sealed::Method<C> + 'static {
    /// Rust arguments accepted by this method for a live object scope.
    type Arguments<'scope>;
    /// Result returned after the native method dispatch.
    type Output;

    #[doc(hidden)]
    /// Dispatches this method for a live, validated object in `scope`.
    ///
    /// # Safety
    ///
    /// `object` and `arguments` must belong to `scope` and satisfy this
    /// descriptor's class and value contracts. Safe callers should use
    /// [`Object::call`](crate::Object::call).
    unsafe fn invoke<'scope>(
        scope: &'scope Scope,
        object: Object<'scope, C>,
        arguments: Self::Arguments<'scope>,
    ) -> Self::Output;
}

/// Generated native message descriptor. Calling it is unsafe because the
/// message fields may contain unvalidated pointers and retained resources.
pub trait RawMethod<C: Class>: sealed::RawMethod<C> + 'static {
    /// ABI message structure passed to the native method.
    type Message;
    /// Native MUI method identifier.
    const ID: u32;
}

/// Typed `MUIM_NoNotifySet` for any safely writable attribute.
///
/// This method updates the selected attribute while suppressing the
/// notification that a normal set would generate for that attribute.
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
