use core::ffi::CStr;

pub(crate) mod sealed {
    pub trait Class {}
    pub trait ParentOf<Child> {}
}

/// A sealed marker for one native MUI class.
pub trait Class: sealed::Class + 'static {
    /// NUL-terminated native class identifier.
    const ID: &'static CStr;
}

/// Compile-time MUI superclass relation.
pub trait IsA<Target: Class>: Class {}

impl<C: Class> IsA<C> for C {}

/// Native ownership operation used when a child is attached.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attachment {
    ApplicationWindow,
    GroupChild,
    WindowRoot,
}

/// A sealed, type-checked native parent/child ownership relation.
pub trait ParentOf<Child: Class>: Class + sealed::ParentOf<Child> {
    #[doc(hidden)]
    const ATTACHMENT: Attachment;
}
