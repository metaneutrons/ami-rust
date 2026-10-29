use core::ffi::CStr;

pub(crate) mod sealed {
    pub trait Class {}
    pub trait ParentOf<Child> {}
    pub trait ParentRole {}
}

/// A sealed marker for one native MUI class.
pub trait Class: sealed::Class + 'static {
    /// NUL-terminated native class identifier.
    const ID: &'static CStr;
    #[doc(hidden)]
    type ParentRole: sealed::ParentRole;
}

/// Compile-time MUI superclass relation.
pub trait IsA<Target: Class>: Class {}

impl<C: Class> IsA<C> for C {}

/// Native ownership operation used when a child is attached.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attachment {
    ApplicationWindow,
    ApplicationMenustrip,
    FamilyChild,
    GroupChild,
    WindowRoot,
}

/// Generated parent capability markers. They keep the ownership relation
/// closed while allowing inheritance to be expressed without handwritten
/// forwarding implementations for every class.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct NoParent;
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ApplicationParent;
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct WindowParent;
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct GroupParent;
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct FamilyParent;

impl sealed::ParentRole for NoParent {}
impl sealed::ParentRole for ApplicationParent {}
impl sealed::ParentRole for WindowParent {}
impl sealed::ParentRole for GroupParent {}
impl sealed::ParentRole for FamilyParent {}

#[doc(hidden)]
pub trait ParentSupport<Child: Class>: sealed::ParentRole {
    const ATTACHMENT: Attachment;
}

/// A sealed, type-checked native parent/child ownership relation.
pub trait ParentOf<Child: Class>: Class + sealed::ParentOf<Child> {
    #[doc(hidden)]
    const ATTACHMENT: Attachment;
}

impl<P, Child> sealed::ParentOf<Child> for P
where
    P: Class,
    Child: Class,
    P::ParentRole: ParentSupport<Child>,
{
}

impl<P, Child> ParentOf<Child> for P
where
    P: Class,
    Child: Class,
    P::ParentRole: ParentSupport<Child>,
{
    const ATTACHMENT: Attachment = <P::ParentRole as ParentSupport<Child>>::ATTACHMENT;
}
