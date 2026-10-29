//! Core MUI class markers used by the generic object model.

use crate::class::{self, Attachment, Class, IsA, ParentOf};

macro_rules! class {
    ($name:ident, $id:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name;

        impl class::sealed::Class for $name {}

        impl Class for $name {
            const ID: &'static core::ffi::CStr = $id;
        }
    };
}

class!(Notify, c"Notify.mui");
class!(Area, c"Area.mui");
class!(Application, c"Application.mui");
class!(Group, c"Group.mui");
class!(Text, c"Text.mui");
class!(Window, c"Window.mui");

impl IsA<Notify> for Area {}
impl IsA<Notify> for Application {}
impl IsA<Notify> for Group {}
impl IsA<Notify> for Text {}
impl IsA<Notify> for Window {}
impl IsA<Area> for Group {}
impl IsA<Area> for Text {}

impl<C> class::sealed::ParentOf<C> for Application where C: Class + IsA<Window> {}
impl<C> ParentOf<C> for Application
where
    C: Class + IsA<Window>,
{
    const ATTACHMENT: Attachment = Attachment::ApplicationWindow;
}

impl<C> class::sealed::ParentOf<C> for Group where C: Class + IsA<Area> {}
impl<C> ParentOf<C> for Group
where
    C: Class + IsA<Area>,
{
    const ATTACHMENT: Attachment = Attachment::GroupChild;
}

impl<C> class::sealed::ParentOf<C> for Window where C: Class + IsA<Area> {}
impl<C> ParentOf<C> for Window
where
    C: Class + IsA<Area>,
{
    const ATTACHMENT: Attachment = Attachment::WindowRoot;
}
