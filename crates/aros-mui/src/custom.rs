use crate::{
    BuildAttribute, Class, Error, Object, RawBuildAttribute, Scope, ValueKind, allocation::try_box,
};
use alloc::{boxed::Box, vec::Vec};
use aros_mui_sys::{MuiCustomClass, Stacked, TagItem};
use core::{
    cell::{Cell, UnsafeCell},
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
};

const OM_NEW: u32 = 0x0101;
const OM_DISPOSE: u32 = 0x0102;

/// Safe definition of a regular MUI custom class.
///
/// The custom methods described here have no native trailing arguments. Every
/// other message is forwarded unchanged to the standard superclass. Foreign
/// messages with custom layouts remain available only through the raw API.
pub trait CustomClassSpec: 'static {
    /// Standard MUI superclass for this custom class.
    type Super: Class;
    /// Per-instance state, initialized with [`Default::default`].
    type Data: Default + 'static;
    /// Copyable identifier for a supported custom method.
    type Method: Copy + 'static;

    /// Decodes a native method ID owned by this specification.
    ///
    /// Return `Some` only for custom methods handled by [`Self::dispatch`].
    fn decode_method(method_id: u32) -> Option<Self::Method>;

    /// Returns the native user-method ID for a typed custom method.
    ///
    /// IDs below `aros_sys::TAG_USER` are rejected by [`CustomObject::call`].
    fn method_id(method: Self::Method) -> u32;

    /// Handles one custom method without trailing native arguments.
    ///
    /// The state is unique to one native object and is mutably borrowed only
    /// for this call. Reentrant dispatch to the same object returns zero.
    fn dispatch(data: &mut Self::Data, method: Self::Method) -> usize;
}

/// Scope-owned registration of one native MUI custom class.
pub struct CustomClass<'scope, S: CustomClassSpec> {
    raw: NonNull<MuiCustomClass>,
    scope: &'scope Scope,
    _spec: PhantomData<fn() -> S>,
    _task_affine: PhantomData<*mut ()>,
}

impl<S: CustomClassSpec> Copy for CustomClass<'_, S> {}

impl<S: CustomClassSpec> Clone for CustomClass<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'scope, S: CustomClassSpec> CustomClass<'scope, S> {
    /// Starts building an instance using typed superclass construction tags.
    pub fn builder(self) -> CustomBuilder<'scope, S> {
        CustomBuilder {
            class: self,
            tags: Vec::new(),
        }
    }
}

/// Typed tag builder for an instance of a registered custom class.
pub struct CustomBuilder<'scope, S: CustomClassSpec> {
    class: CustomClass<'scope, S>,
    tags: Vec<TagItem>,
}

impl<'scope, S: CustomClassSpec> CustomBuilder<'scope, S> {
    /// Adds a typed construction attribute supported by the superclass.
    ///
    /// Scope-bound values must come from the class registration's scope.
    pub fn with<A>(mut self, value: <A::Value as ValueKind>::Input<'scope>) -> Result<Self, Error>
    where
        A: BuildAttribute<S::Super>,
    {
        let encoded = <A::Value as ValueKind>::encode(self.class.scope, value)?;
        self.tags.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.tags.push(TagItem::new(A::ID, encoded));
        Ok(self)
    }

    /// Adds a raw superclass construction attribute.
    ///
    /// # Safety
    ///
    /// `value` must satisfy the native type and retention contract reported by
    /// `A::C_TYPE` for the complete scope lifetime.
    pub unsafe fn with_raw<A>(mut self, value: usize) -> Result<Self, Error>
    where
        A: RawBuildAttribute<S::Super>,
    {
        self.tags.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.tags.push(TagItem::new(A::ID, value));
        Ok(self)
    }

    /// Creates a native instance and returns its typed custom-class handle.
    ///
    /// The scope retains the instance and registration until teardown. The
    /// returned handle is a copyable view and does not own native storage.
    pub fn build(self) -> Result<CustomObject<'scope, S>, Error> {
        let class = unsafe { self.class.raw.as_ref().class };
        let class = NonNull::new(class).ok_or(Error::CustomClassCreation)?;
        let object = self
            .class
            .scope
            .create_from_class::<S::Super>(class, self.tags)?;
        Ok(CustomObject {
            object,
            class,
            _spec: PhantomData,
        })
    }
}

/// Live instance of one registered custom class.
///
/// Its native storage and class registration are owned by the same scope.
/// This copyable handle provides custom method dispatch plus access to the
/// ordinary typed superclass interface.
pub struct CustomObject<'scope, S: CustomClassSpec> {
    object: Object<'scope, S::Super>,
    class: NonNull<aros_sys::IClass>,
    _spec: PhantomData<fn() -> S>,
}

impl<S: CustomClassSpec> Copy for CustomObject<'_, S> {}

impl<S: CustomClassSpec> Clone for CustomObject<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'scope, S: CustomClassSpec> CustomObject<'scope, S> {
    /// Returns the ordinary typed superclass view used for attributes,
    /// notifications, ownership transfer, and standard methods.
    ///
    /// This is only a type view of the same native object.
    pub fn object(self) -> Object<'scope, S::Super> {
        self.object
    }

    /// Dispatches one declared argument-free custom method.
    ///
    /// Its return value is the native pointer-sized method result. Use the
    /// superclass object view for generated standard methods and attributes.
    pub fn call(self, method: S::Method) -> Result<usize, Error> {
        let method_id = S::method_id(method);
        if method_id < aros_sys::TAG_USER {
            return Err(Error::InvalidCustomMethod);
        }
        let mut message = Stacked::new(method_id);
        // SAFETY: this API admits only one method word and the dispatcher calls
        // `S` only for IDs decoded by the same safe specification. The class
        // registration and object are retained by the same owning scope.
        Ok(unsafe {
            aros_sys::coerce_method_a(
                self.class.as_ptr(),
                self.object.raw().as_ptr().cast(),
                core::ptr::addr_of_mut!(message).cast(),
            )
        })
    }
}

pub(crate) struct RetainedCustomClass {
    mui_base: NonNull<aros_sys::Library>,
    raw: NonNull<MuiCustomClass>,
}

impl Drop for RetainedCustomClass {
    fn drop(&mut self) {
        // SAFETY: Scope drops every object before its retained class records.
        unsafe { aros_mui_sys::mui_delete_custom_class(self.mui_base.as_ptr(), self.raw.as_ptr()) };
    }
}

struct Instance<S: CustomClassSpec> {
    busy: Cell<bool>,
    data: UnsafeCell<S::Data>,
}

impl Scope {
    /// Registers one custom class whose native lifetime is bounded by this
    /// complete object scope.
    ///
    /// The generated dispatcher stores a fresh `S::Data` value in each native
    /// instance. The registration remains live until all objects from this
    /// scope have been disposed.
    pub fn custom_class<'scope, S>(&'scope self) -> Result<CustomClass<'scope, S>, Error>
    where
        S: CustomClassSpec,
    {
        let mut classes = self
            .custom_classes
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?;
        classes.try_reserve(1).map_err(|_| Error::Allocation)?;
        // SAFETY: the standard superclass identifier is generated and live;
        // the monomorphized dispatcher uses one pointer-sized native instance
        // slot and the registration remains retained by this scope.
        let raw = unsafe {
            aros_mui_sys::mui_create_custom_class(
                self.mui_base().as_ptr(),
                core::ptr::null_mut(),
                S::Super::ID.as_ptr(),
                core::ptr::null_mut(),
                core::mem::size_of::<*mut Instance<S>>() as u32,
                custom_dispatch::<S> as *mut c_void,
            )
        };
        let raw = NonNull::new(raw).ok_or(Error::CustomClassCreation)?;
        classes.push(RetainedCustomClass {
            mui_base: self.mui_base(),
            raw,
        });
        Ok(CustomClass {
            raw,
            scope: self,
            _spec: PhantomData,
            _task_affine: PhantomData,
        })
    }
}

unsafe extern "C" fn custom_dispatch<S: CustomClassSpec>(
    class: *mut aros_sys::IClass,
    object: *mut aros_sys::Object,
    message: aros_sys::Msg,
) -> usize {
    let (Some(class), Some(message)) = (NonNull::new(class), NonNull::new(message)) else {
        return 0;
    };
    // Every BOOPSI message begins with one STACKED ULONG method ID.
    let method_id = unsafe { message.cast::<u32>().read() };
    if method_id == OM_NEW {
        let created =
            unsafe { aros_sys::do_super_method_a(class.as_ptr(), object, message.as_ptr()) };
        let Some(created) = NonNull::new(created as *mut aros_sys::Object) else {
            return 0;
        };
        let instance = match try_box(Instance::<S> {
            busy: Cell::new(false),
            data: UnsafeCell::new(S::Data::default()),
        }) {
            Ok(instance) => Box::into_raw(instance),
            Err(_) => {
                let mut dispose = Stacked::new(OM_DISPOSE);
                unsafe {
                    aros_sys::do_super_method_a(
                        class.as_ptr(),
                        created.as_ptr(),
                        core::ptr::addr_of_mut!(dispose).cast(),
                    )
                };
                return 0;
            }
        };
        unsafe { instance_slot::<S>(class, created).write(instance) };
        return created.as_ptr().addr();
    }
    let Some(object) = NonNull::new(object) else {
        return 0;
    };
    if method_id == OM_DISPOSE {
        let slot = unsafe { instance_slot::<S>(class, object) };
        let instance = unsafe { slot.read() };
        unsafe { slot.write(core::ptr::null_mut()) };
        if !instance.is_null() {
            // The application panic handler is nonreturning, so `Drop` cannot
            // unwind through the native dispatcher.
            unsafe { drop(Box::from_raw(instance)) };
        }
        return unsafe {
            aros_sys::do_super_method_a(class.as_ptr(), object.as_ptr(), message.as_ptr())
        };
    }
    if method_id >= aros_sys::TAG_USER
        && let Some(method) = S::decode_method(method_id)
    {
        let instance = unsafe { instance_slot::<S>(class, object).read() };
        if let Some(instance) = NonNull::new(instance) {
            let instance = unsafe { instance.as_ref() };
            if !instance.busy.replace(true) {
                // SAFETY: the busy flag prevents reentrant mutable access.
                let result = unsafe { S::dispatch(&mut *instance.data.get(), method) };
                instance.busy.set(false);
                return result;
            }
            return 0;
        }
    }
    unsafe { aros_sys::do_super_method_a(class.as_ptr(), object.as_ptr(), message.as_ptr()) }
}

unsafe fn instance_slot<S: CustomClassSpec>(
    class: NonNull<aros_sys::IClass>,
    object: NonNull<aros_sys::Object>,
) -> *mut *mut Instance<S> {
    let offset = unsafe { class.as_ref().instance_offset as usize };
    unsafe { object.as_ptr().cast::<u8>().add(offset).cast() }
}
