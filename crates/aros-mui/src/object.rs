use crate::{
    BuildAttribute, Class, DecodeValueKind, GetAttribute, ParentOf, RawBuildAttribute,
    RawGetAttribute, RawMethod, RawSetAttribute, SetAttribute, StringArray, ValueKind,
    callback::RetainedHook, class::Attachment, custom::RetainedCustomClass, method::Method,
};
use alloc::{boxed::Box, vec::Vec};
use aros::{BytePath, Context, Library};
use aros_mui_sys::{Stacked, TagItem, mui_dispose_object, mui_new_object_a};
use core::{
    cell::RefCell,
    marker::PhantomData,
    mem,
    ptr::{self, NonNull},
};

const MUI_LIBRARY_NAME: &[u8] = b"muimaster.library";
const INTUITION_LIBRARY_NAME: &[u8] = b"intuition.library";
const INTUITION_MINIMUM_VERSION: u16 = 36;
const OM_ADDMEMBER: u32 = 0x0109;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Aros(aros::Error),
    Allocation,
    AttributeUnavailable,
    Busy,
    LibraryBaseUnavailable,
    NativeOperation,
    ObjectCreation,
    NullValue,
    InvalidFormat,
    InvalidCustomMethod,
    CustomClassCreation,
    AlreadyOwned,
    OwnershipCycle,
    ParentOccupied,
    UnknownEnumValue,
    ValueOutOfRange,
    WrongScope,
}

impl From<aros::Error> for Error {
    fn from(value: aros::Error) -> Self {
        Self::Aros(value)
    }
}

/// Open MUI and Intuition libraries bound to one AROS application task.
pub struct Mui<'ctx> {
    context: &'ctx Context,
    mui_library: Library<'ctx>,
    intuition_library: Library<'ctx>,
    mui_base: NonNull<aros_sys::Library>,
    intuition_base: NonNull<aros_sys::Library>,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Mui<'ctx> {
    pub fn open(context: &'ctx Context) -> Result<Self, Error> {
        let mui_name = BytePath::new(MUI_LIBRARY_NAME)?;
        let mui_library = Library::open(context, &mui_name, aros_mui_sys::MUI_API_VERSION)?;
        let intuition_name = BytePath::new(INTUITION_LIBRARY_NAME)?;
        let intuition_library = Library::open(context, &intuition_name, INTUITION_MINIMUM_VERSION)?;

        // SAFETY: each pointer is retained only while its matching owned
        // library handle remains in this task-affine value.
        let mui_base = unsafe { mui_library.raw_base() }
            .and_then(|base| NonNull::new(base.cast()))
            .ok_or(Error::LibraryBaseUnavailable)?;
        // SAFETY: same owned-library contract as above.
        let intuition_base = unsafe { intuition_library.raw_base() }
            .and_then(|base| NonNull::new(base.cast()))
            .ok_or(Error::LibraryBaseUnavailable)?;

        Ok(Self {
            context,
            mui_library,
            intuition_library,
            mui_base,
            intuition_base,
            _task_affine: PhantomData,
        })
    }

    /// Runs one non-escaping object scope and disposes every native root when
    /// the closure returns, including on an ordinary `Result::Err` path.
    pub fn scope<R>(&self, run: impl for<'scope> FnOnce(&'scope Scope) -> R) -> R {
        let scope = Scope {
            context: NonNull::from(self.context),
            mui_base: self.mui_base,
            intuition_base: self.intuition_base,
            entries: RefCell::new(Vec::new()),
            string_arrays: RefCell::new(Vec::new()),
            hooks: RefCell::new(Vec::new()),
            custom_classes: RefCell::new(Vec::new()),
            _task_affine: PhantomData,
        };
        run(&scope)
    }

    pub fn last_error(&self) -> i32 {
        // SAFETY: this value owns the live muimaster library reference.
        unsafe { aros_mui_sys::mui_error(self.mui_base.as_ptr()) }
    }

    pub fn set_error(&self, error: i32) -> i32 {
        // SAFETY: this value owns the live muimaster library reference.
        unsafe { aros_mui_sys::mui_set_error(self.mui_base.as_ptr(), error) }
    }

    pub fn close(self) -> Result<(), Error> {
        let Self {
            mui_library,
            intuition_library,
            ..
        } = self;
        let intuition = intuition_library.close().map_err(Error::Aros);
        let mui = mui_library.close().map_err(Error::Aros);
        intuition.and(mui)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ownership {
    Root,
    Attaching { parent: usize },
    Parent { parent: usize },
}

impl Ownership {
    fn parent(self) -> Option<usize> {
        match self {
            Self::Root => None,
            Self::Attaching { parent } | Self::Parent { parent } => Some(parent),
        }
    }
}

#[derive(Debug)]
struct Entry {
    raw: NonNull<aros_mui_sys::Object>,
    ownership: Ownership,
}

/// Native object arena owned by one `Mui::scope` invocation.
pub struct Scope {
    context: NonNull<Context>,
    mui_base: NonNull<aros_sys::Library>,
    intuition_base: NonNull<aros_sys::Library>,
    entries: RefCell<Vec<Entry>>,
    string_arrays: RefCell<Vec<Box<[*const core::ffi::c_char]>>>,
    pub(crate) hooks: RefCell<Vec<RetainedHook>>,
    pub(crate) custom_classes: RefCell<Vec<RetainedCustomClass>>,
    _task_affine: PhantomData<*mut ()>,
}

impl Scope {
    pub(crate) fn context(&self) -> &Context {
        // SAFETY: Mui owns this Context borrow for longer than every scope it
        // creates, and neither type is Send or Sync.
        unsafe { self.context.as_ref() }
    }

    pub(crate) fn mui_base(&self) -> NonNull<aros_sys::Library> {
        self.mui_base
    }

    pub fn builder<C: Class>(&self) -> Builder<'_, C> {
        Builder {
            scope: self,
            tags: Vec::new(),
            _class: PhantomData,
        }
    }

    /// Retains a NULL-terminated native string array for this complete scope.
    pub fn string_array<'scope>(
        &'scope self,
        strings: &[&'scope core::ffi::CStr],
    ) -> Result<StringArray<'scope>, Error> {
        let length = strings.len().checked_add(1).ok_or(Error::Allocation)?;
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        pointers.extend(strings.iter().map(|string| string.as_ptr()));
        pointers.push(core::ptr::null());
        let mut pointers = pointers.into_boxed_slice();
        let pointer = NonNull::new(pointers.as_mut_ptr()).ok_or(Error::Allocation)?;
        let mut retained = self
            .string_arrays
            .try_borrow_mut()
            .map_err(|_| Error::Busy)?;
        retained.try_reserve(1).map_err(|_| Error::Allocation)?;
        retained.push(pointers);
        Ok(StringArray {
            pointer,
            scope: self,
            _lifetime: PhantomData,
        })
    }

    fn create<C: Class>(&self, mut tags: Vec<TagItem>) -> Result<Object<'_, C>, Error> {
        tags.try_reserve(1).map_err(|_| Error::Allocation)?;
        tags.push(TagItem::done());

        {
            let mut entries = self.entries.try_borrow_mut().map_err(|_| Error::Busy)?;
            entries.try_reserve(1).map_err(|_| Error::Allocation)?;
        }

        // SAFETY: the class marker is sealed and NUL terminated. Every tag was
        // produced by a typed attribute and the final TAG_DONE is live for the
        // complete synchronous call.
        let raw =
            unsafe { mui_new_object_a(self.mui_base.as_ptr(), C::ID.as_ptr(), tags.as_mut_ptr()) };
        let raw = NonNull::new(raw).ok_or(Error::ObjectCreation)?;

        let mut entries = self.entries.try_borrow_mut().map_err(|_| Error::Busy)?;
        let index = entries.len();
        entries.push(Entry {
            raw,
            ownership: Ownership::Root,
        });
        Ok(Object {
            scope: self,
            index,
            raw,
            _class: PhantomData,
        })
    }

    pub(crate) fn create_from_class<C: Class>(
        &self,
        class: NonNull<aros_sys::IClass>,
        mut tags: Vec<TagItem>,
    ) -> Result<Object<'_, C>, Error> {
        tags.try_reserve(1).map_err(|_| Error::Allocation)?;
        tags.push(TagItem::done());
        {
            let mut entries = self.entries.try_borrow_mut().map_err(|_| Error::Busy)?;
            entries.try_reserve(1).map_err(|_| Error::Allocation)?;
        }
        // SAFETY: the retained custom class and terminated typed tag list are
        // live for the complete synchronous construction call.
        let raw = unsafe {
            aros_sys::intuition::new_object_a(
                self.intuition_base.as_ptr(),
                class.as_ptr(),
                core::ptr::null_mut(),
                tags.as_mut_ptr(),
            )
        };
        let raw = NonNull::new(raw.cast::<aros_mui_sys::Object>()).ok_or(Error::ObjectCreation)?;
        let mut entries = self.entries.try_borrow_mut().map_err(|_| Error::Busy)?;
        let index = entries.len();
        entries.push(Entry {
            raw,
            ownership: Ownership::Root,
        });
        Ok(Object {
            scope: self,
            index,
            raw,
            _class: PhantomData,
        })
    }

    fn set<'scope, C, A>(
        &'scope self,
        object: Object<'_, C>,
        value: <A::Value as ValueKind>::Input<'scope>,
    ) -> Result<(), Error>
    where
        C: Class,
        A: SetAttribute<C>,
    {
        self.validate(object)?;
        let encoded = <A::Value as ValueKind>::encode(self, value)?;
        let mut tags = [TagItem::new(A::ID, encoded), TagItem::done()];
        // SAFETY: both bases and the typed object are live in this scope; the
        // stack tag list is terminated and retained only for this call.
        unsafe {
            aros_sys::intuition::set_attrs_a(
                self.intuition_base.as_ptr(),
                object.raw.as_ptr(),
                tags.as_mut_ptr(),
            )
        };
        Ok(())
    }

    fn get<'scope, C, A>(
        &'scope self,
        object: Object<'scope, C>,
    ) -> Result<<A::Value as ValueKind>::Output<'scope>, Error>
    where
        C: Class,
        A: GetAttribute<C>,
        A::Value: DecodeValueKind,
    {
        self.validate(object)?;
        let mut raw = 0usize;
        // SAFETY: the object and storage are live for this synchronous typed
        // query and the generated attribute is readable for this class.
        let found = unsafe {
            aros_sys::intuition::get_attr(
                self.intuition_base.as_ptr(),
                A::ID,
                object.raw.as_ptr(),
                &mut raw,
            )
        };
        if found == 0 {
            return Err(Error::AttributeUnavailable);
        }
        <A::Value as DecodeValueKind>::decode(self, raw)
    }

    unsafe fn set_raw<C, A>(&self, object: Object<'_, C>, value: usize) -> Result<(), Error>
    where
        C: Class,
        A: RawSetAttribute<C>,
    {
        self.validate(object)?;
        let mut tags = [TagItem::new(A::ID, value), TagItem::done()];
        // SAFETY: the caller owns the complete native value contract.
        unsafe {
            aros_sys::intuition::set_attrs_a(
                self.intuition_base.as_ptr(),
                object.raw.as_ptr(),
                tags.as_mut_ptr(),
            )
        };
        Ok(())
    }

    unsafe fn get_raw<C, A>(&self, object: Object<'_, C>) -> Result<usize, Error>
    where
        C: Class,
        A: RawGetAttribute<C>,
    {
        self.validate(object)?;
        let mut value = 0usize;
        // SAFETY: the caller interprets the returned native value.
        let found = unsafe {
            aros_sys::intuition::get_attr(
                self.intuition_base.as_ptr(),
                A::ID,
                object.raw.as_ptr(),
                &mut value,
            )
        };
        if found == 0 {
            Err(Error::AttributeUnavailable)
        } else {
            Ok(value)
        }
    }

    fn validate<C: Class>(&self, object: Object<'_, C>) -> Result<(), Error> {
        if !ptr::eq(self, object.scope) {
            return Err(Error::WrongScope);
        }
        let entries = self.entries.try_borrow().map_err(|_| Error::Busy)?;
        if entries
            .get(object.index)
            .is_some_and(|entry| entry.raw == object.raw)
        {
            Ok(())
        } else {
            Err(Error::WrongScope)
        }
    }

    fn attach<P, C>(
        &self,
        parent: Object<'_, P>,
        child: Object<'_, C>,
        attachment: Attachment,
    ) -> Result<(), Error>
    where
        P: Class,
        C: Class,
    {
        self.validate(parent)?;
        self.validate(child)?;
        if parent.index == child.index {
            return Err(Error::OwnershipCycle);
        }

        {
            let mut entries = self.entries.try_borrow_mut().map_err(|_| Error::Busy)?;
            if entries[child.index].ownership != Ownership::Root {
                return Err(Error::AlreadyOwned);
            }
            let mut ancestor = Some(parent.index);
            while let Some(index) = ancestor {
                if index == child.index {
                    return Err(Error::OwnershipCycle);
                }
                ancestor = entries[index].ownership.parent();
            }
            if attachment == Attachment::WindowRoot
                && entries
                    .iter()
                    .any(|entry| entry.ownership.parent() == Some(parent.index))
            {
                return Err(Error::ParentOccupied);
            }
            entries[child.index].ownership = Ownership::Attaching {
                parent: parent.index,
            };
        }

        let attached = match attachment {
            Attachment::ApplicationWindow | Attachment::FamilyChild | Attachment::GroupChild => {
                self.add_member(parent.raw, child.raw)
            }
            Attachment::ApplicationMenustrip => {
                self.set_application_menustrip(parent.raw, child.raw);
                true
            }
            Attachment::WindowRoot => {
                self.set_window_root(parent.raw, child.raw);
                true
            }
        };

        let mut entries = self.entries.try_borrow_mut().map_err(|_| Error::Busy)?;
        entries[child.index].ownership = if attached {
            Ownership::Parent {
                parent: parent.index,
            }
        } else {
            Ownership::Root
        };
        if attached {
            Ok(())
        } else {
            Err(Error::NativeOperation)
        }
    }

    fn add_member(
        &self,
        parent: NonNull<aros_mui_sys::Object>,
        child: NonNull<aros_mui_sys::Object>,
    ) -> bool {
        #[repr(C)]
        struct OpMember {
            method_id: Stacked<u32>,
            object: Stacked<*mut aros_mui_sys::Object>,
        }
        let mut message = OpMember {
            method_id: Stacked::new(OM_ADDMEMBER),
            object: Stacked::new(child.as_ptr()),
        };
        // SAFETY: both typed objects are live and the message exactly follows
        // `struct opMember`; the generated parent relation limits this call to
        // native classes whose ownership contract is OM_ADDMEMBER.
        unsafe {
            aros_sys::do_method_a(parent.as_ptr().cast(), ptr::addr_of_mut!(message).cast());
        }
        // The supported implementations have no native refusal path
        // after receiving two live objects. Its return value is not part of
        // the ownership contract.
        true
    }

    fn set_application_menustrip(
        &self,
        parent: NonNull<aros_mui_sys::Object>,
        child: NonNull<aros_mui_sys::Object>,
    ) {
        let mut tags = [
            TagItem::new(
                aros_mui_sys::MUIA_Application_Menustrip,
                child.as_ptr().addr(),
            ),
            TagItem::done(),
        ];
        // SAFETY: the generated relation permits only Menustrip here and both
        // native objects remain owned by this scope.
        unsafe {
            aros_sys::intuition::set_attrs_a(
                self.intuition_base.as_ptr(),
                parent.as_ptr(),
                tags.as_mut_ptr(),
            )
        };
    }

    fn set_window_root(
        &self,
        parent: NonNull<aros_mui_sys::Object>,
        child: NonNull<aros_mui_sys::Object>,
    ) {
        let mut tags = [
            TagItem::new(aros_mui_sys::MUIA_Window_RootObject, child.as_ptr().addr()),
            TagItem::done(),
        ];
        // SAFETY: a typed Window owns at most one typed Area root in the
        // ledger; the synchronous tag list is complete and terminated.
        unsafe {
            aros_sys::intuition::set_attrs_a(
                self.intuition_base.as_ptr(),
                parent.as_ptr(),
                tags.as_mut_ptr(),
            )
        };
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let entries = mem::take(self.entries.get_mut());
        for entry in entries.into_iter().rev() {
            if entry.ownership == Ownership::Root {
                // SAFETY: roots are uniquely owned by this scope. Native
                // parents recursively dispose their transferred descendants.
                unsafe { mui_dispose_object(self.mui_base.as_ptr(), entry.raw.as_ptr()) };
            }
        }
    }
}

/// Copyable typed handle whose native storage is owned by its `Scope`.
pub struct Object<'scope, C: Class> {
    scope: &'scope Scope,
    index: usize,
    raw: NonNull<aros_mui_sys::Object>,
    _class: PhantomData<C>,
}

impl<C: Class> Copy for Object<'_, C> {}

impl<C: Class> Clone for Object<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'scope, C: Class> Object<'scope, C> {
    pub fn upcast<Target: Class>(self) -> Object<'scope, Target>
    where
        C: crate::IsA<Target>,
    {
        Object {
            scope: self.scope,
            index: self.index,
            raw: self.raw,
            _class: PhantomData,
        }
    }

    pub fn adopt<Child: Class>(self, child: Object<'scope, Child>) -> Result<(), Error>
    where
        C: ParentOf<Child>,
    {
        self.scope.attach(self, child, C::ATTACHMENT)
    }

    pub fn set<A>(self, value: <A::Value as ValueKind>::Input<'scope>) -> Result<(), Error>
    where
        A: SetAttribute<C>,
    {
        self.scope.set::<C, A>(self, value)
    }

    pub fn get<A>(self) -> Result<<A::Value as ValueKind>::Output<'scope>, Error>
    where
        A: GetAttribute<C>,
        A::Value: DecodeValueKind,
    {
        self.scope.get::<C, A>(self)
    }

    pub fn call<M: Method<C>>(self, arguments: M::Arguments<'scope>) -> M::Output {
        // SAFETY: Method is sealed; its implementation receives the same live
        // typed object and scope used to validate all arguments.
        unsafe { M::invoke(self.scope, self, arguments) }
    }

    /// Dispatches a generated native message whose field contracts remain an
    /// explicit expert boundary.
    ///
    /// # Safety
    ///
    /// Every pointer, lifetime, message ID, and retained resource in
    /// `message` must satisfy the native MUI method contract.
    pub unsafe fn call_raw<M: RawMethod<C>>(self, message: &mut M::Message) -> usize {
        // SAFETY: delegated to the caller as documented above.
        unsafe {
            aros_sys::do_method_a(
                self.raw.as_ptr().cast(),
                core::ptr::from_mut(message).cast(),
            )
        }
    }

    /// Writes an attribute through its generated raw descriptor.
    ///
    /// # Safety
    ///
    /// `value` must satisfy the native type and retention contract reported by
    /// `A::C_TYPE`.
    pub unsafe fn set_raw<A: RawSetAttribute<C>>(self, value: usize) -> Result<(), Error> {
        // SAFETY: delegated to the caller as documented above.
        unsafe { self.scope.set_raw::<C, A>(self, value) }
    }

    /// Reads a native attribute without interpreting its value.
    ///
    /// # Safety
    ///
    /// The caller must interpret and retain the returned word according to
    /// `A::C_TYPE`.
    pub unsafe fn get_raw<A: RawGetAttribute<C>>(self) -> Result<usize, Error> {
        // SAFETY: delegated to the caller as documented above.
        unsafe { self.scope.get_raw::<C, A>(self) }
    }

    pub(crate) fn scope(self) -> &'scope Scope {
        self.scope
    }

    pub(crate) fn raw(self) -> NonNull<aros_mui_sys::Object> {
        self.raw
    }
}

/// Allocation-aware typed tag builder shared by every generated class.
pub struct Builder<'scope, C: Class> {
    scope: &'scope Scope,
    tags: Vec<TagItem>,
    _class: PhantomData<C>,
}

impl<'scope, C: Class> Builder<'scope, C> {
    pub fn with<A>(mut self, value: <A::Value as ValueKind>::Input<'scope>) -> Result<Self, Error>
    where
        A: BuildAttribute<C>,
    {
        let encoded = <A::Value as ValueKind>::encode(self.scope, value)?;
        self.tags.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.tags.push(TagItem::new(A::ID, encoded));
        Ok(self)
    }

    pub fn build(self) -> Result<Object<'scope, C>, Error> {
        self.scope.create::<C>(self.tags)
    }

    /// Adds a generated raw construction attribute.
    ///
    /// # Safety
    ///
    /// `value` must satisfy the native type and retention contract reported by
    /// `A::C_TYPE` for the complete scope lifetime.
    pub unsafe fn with_raw<A: RawBuildAttribute<C>>(mut self, value: usize) -> Result<Self, Error> {
        self.tags.try_reserve(1).map_err(|_| Error::Allocation)?;
        self.tags.push(TagItem::new(A::ID, value));
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::Ownership;

    #[test]
    fn ownership_state_exposes_only_native_roots_for_disposal() {
        assert_eq!(Ownership::Root.parent(), None);
        assert_eq!(Ownership::Attaching { parent: 2 }.parent(), Some(2));
        assert_eq!(Ownership::Parent { parent: 3 }.parent(), Some(3));
    }
}
