use crate::{
    Attribute, Class, Error, GetAttribute, Hook, IsA, Object, SetAttribute, ValueKind,
    classes::Notify,
};
use aros_mui_sys::{
    MUIM_Application_ReturnID, MUIM_CallHook, MUIM_NoNotifySet, MUIM_Notify,
    MUIV_Application_ReturnID_Quit, MUIV_EveryTime, MUIV_TriggerValue, Stacked,
};
use core::{ffi::c_void, marker::PhantomData};

/// Typed condition for one attribute notification.
pub enum Trigger<'scope, V: ValueKind> {
    /// Run the action whenever the source attribute changes.
    EveryTime,
    /// Run the action only when the attribute equals this typed value.
    Value(V::Input<'scope>),
}

/// Nonzero value returned by an Application event loop.
///
/// The reserved MUI quit identifier is available as [`ReturnId::QUIT`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnId(u32);

impl ReturnId {
    /// MUI's reserved Application quit return ID.
    pub const QUIT: Self = Self(MUIV_Application_ReturnID_Quit);

    /// Creates a return ID, rejecting zero because it means no return ID.
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Returns the native integer value of this ID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A typed source attribute and trigger ready to be connected to one action.
///
/// Notifications are registered with MUI when an action method is called.
/// The source and destination must belong to the same scope, which retains
/// their native objects and any callback hook for the notification lifetime.
pub struct Notification<'scope, C: Class> {
    source: Object<'scope, C>,
    attribute: u32,
    value: isize,
    _lifetime: PhantomData<&'scope ()>,
}

#[repr(C)]
struct NotifyTwo {
    method_id: Stacked<u32>,
    trigger_attribute: Stacked<u32>,
    trigger_value: Stacked<isize>,
    destination: Stacked<*mut c_void>,
    follow_parameters: Stacked<u32>,
    follow_method: Stacked<u32>,
    argument: Stacked<isize>,
}

#[repr(C)]
struct NotifyThree {
    method_id: Stacked<u32>,
    trigger_attribute: Stacked<u32>,
    trigger_value: Stacked<isize>,
    destination: Stacked<*mut c_void>,
    follow_parameters: Stacked<u32>,
    follow_method: Stacked<u32>,
    argument_1: Stacked<isize>,
    argument_2: Stacked<isize>,
}

impl<'scope, C: Class> Object<'scope, C> {
    /// Starts a typed notification for an attribute valid on this object.
    ///
    /// The attribute must be readable on this source class. A value trigger
    /// is encoded with the attribute's generated value type and any borrowed
    /// input must remain valid for the scope.
    pub fn notify<A>(
        self,
        trigger: Trigger<'scope, A::Value>,
    ) -> Result<Notification<'scope, C>, Error>
    where
        A: Attribute<C> + GetAttribute<C>,
    {
        let value = match trigger {
            Trigger::EveryTime => MUIV_EveryTime as isize,
            Trigger::Value(value) => <A::Value as ValueKind>::encode(self.scope(), value)? as isize,
        };
        Ok(Notification {
            source: self,
            attribute: A::ID,
            value,
            _lifetime: PhantomData,
        })
    }
}

impl<'scope, C: Class> Notification<'scope, C> {
    /// Queues a typed return ID on the destination Application.
    ///
    /// When the trigger matches, MUI sends the return ID to the Application's
    /// input loop. The Application must belong to the source object's scope.
    pub fn return_id(
        self,
        application: Object<'scope, crate::classes::Application>,
        return_id: ReturnId,
    ) -> Result<(), Error> {
        self.require_same_scope(application)?;
        let mut message = NotifyTwo {
            method_id: Stacked::new(MUIM_Notify),
            trigger_attribute: Stacked::new(self.attribute),
            trigger_value: Stacked::new(self.value),
            destination: Stacked::new(application.raw().as_ptr().cast()),
            follow_parameters: Stacked::new(2),
            follow_method: Stacked::new(MUIM_Application_ReturnID),
            argument: Stacked::new(return_id.get() as isize),
        };
        self.register(core::ptr::addr_of_mut!(message).cast())
    }

    /// Sets another typed attribute without recursively notifying its target.
    ///
    /// The destination must be a `Notify`-derived object in the same scope.
    /// The target attribute is checked against the destination class and its
    /// value is encoded before registration.
    pub fn set<D, A>(
        self,
        destination: Object<'scope, D>,
        value: <A::Value as ValueKind>::Input<'scope>,
    ) -> Result<(), Error>
    where
        D: Class + IsA<Notify>,
        A: SetAttribute<D>,
    {
        self.require_same_scope(destination)?;
        let value = <A::Value as ValueKind>::encode(self.source.scope(), value)?;
        let mut message = NotifyThree {
            method_id: Stacked::new(MUIM_Notify),
            trigger_attribute: Stacked::new(self.attribute),
            trigger_value: Stacked::new(self.value),
            destination: Stacked::new(destination.raw().as_ptr().cast()),
            follow_parameters: Stacked::new(3),
            follow_method: Stacked::new(MUIM_NoNotifySet),
            argument_1: Stacked::new(A::ID as isize),
            argument_2: Stacked::new(value as isize),
        };
        self.register(core::ptr::addr_of_mut!(message).cast())
    }

    /// Invokes a scope-retained callback when the notification fires.
    ///
    /// The destination must be a `Notify`-derived object in the same scope.
    /// The callback receives the native [`HookCall`](crate::HookCall) supplied
    /// by MUI. In particular, callers must not assume that it contains the
    /// source attribute's current value for a [`Trigger::Value`] notification.
    pub fn call<D>(self, destination: Object<'scope, D>, hook: &Hook<'scope>) -> Result<(), Error>
    where
        D: Class + IsA<Notify>,
    {
        self.require_same_scope(destination)?;
        let hook = hook.raw(self.source.scope())?;
        let mut message = NotifyThree {
            method_id: Stacked::new(MUIM_Notify),
            trigger_attribute: Stacked::new(self.attribute),
            trigger_value: Stacked::new(self.value),
            destination: Stacked::new(destination.raw().as_ptr().cast()),
            follow_parameters: Stacked::new(3),
            follow_method: Stacked::new(MUIM_CallHook),
            argument_1: Stacked::new(hook.as_ptr().addr() as isize),
            argument_2: Stacked::new(MUIV_TriggerValue as isize),
        };
        self.register(core::ptr::addr_of_mut!(message).cast())
    }

    fn require_same_scope<D: Class>(&self, object: Object<'scope, D>) -> Result<(), Error> {
        if core::ptr::eq(self.source.scope(), object.scope()) {
            Ok(())
        } else {
            Err(Error::WrongScope)
        }
    }

    fn register(self, message: *mut c_void) -> Result<(), Error> {
        // SAFETY: every fixed trailing word has been constructed from typed,
        // same-scope values and the native call copies the notification record.
        let registered =
            unsafe { aros_sys::do_method_a(self.source.raw().as_ptr().cast(), message) };
        if registered == 0 {
            Err(Error::NativeOperation)
        } else {
            Ok(())
        }
    }
}
