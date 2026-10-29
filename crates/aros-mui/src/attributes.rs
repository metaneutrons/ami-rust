//! Typed attributes needed by the generic M4 core and reference tree.

use crate::{
    Attribute, BuildAttribute, Class, GetAttribute, IsA, MuiEnum, SetAttribute, attribute, classes,
    value,
};

macro_rules! attribute {
    ($name:ident, $kind:ty, $id:path, for $class:ty) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl attribute::sealed::Attribute<$class> for $name {}
        impl Attribute<$class> for $name {
            type Value = $kind;
            const ID: u32 = $id;
        }
    };
}

macro_rules! inherited_attribute {
    ($name:ident, $kind:ty, $id:path, for $base:ty) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl<C> attribute::sealed::Attribute<C> for $name where C: Class + IsA<$base> {}
        impl<C> Attribute<C> for $name
        where
            C: Class + IsA<$base>,
        {
            type Value = $kind;
            const ID: u32 = $id;
        }
    };
}

macro_rules! build {
    ($name:ident for $class:ty) => {
        impl attribute::sealed::Build<$class> for $name {}
        impl BuildAttribute<$class> for $name {}
    };
}

macro_rules! inherited_build {
    ($name:ident for $base:ty) => {
        impl<C> attribute::sealed::Build<C> for $name where C: Class + IsA<$base> {}
        impl<C> BuildAttribute<C> for $name where C: Class + IsA<$base> {}
    };
}

macro_rules! get {
    ($name:ident for $class:ty) => {
        impl attribute::sealed::Get<$class> for $name {}
        impl GetAttribute<$class> for $name {}
    };
}

macro_rules! inherited_get {
    ($name:ident for $base:ty) => {
        impl<C> attribute::sealed::Get<C> for $name where C: Class + IsA<$base> {}
        impl<C> GetAttribute<C> for $name where C: Class + IsA<$base> {}
    };
}

macro_rules! set {
    ($name:ident for $class:ty) => {
        impl attribute::sealed::Set<$class> for $name {}
        impl SetAttribute<$class> for $name {}
    };
}

macro_rules! inherited_set {
    ($name:ident for $base:ty) => {
        impl<C> attribute::sealed::Set<C> for $name where C: Class + IsA<$base> {}
        impl<C> SetAttribute<C> for $name where C: Class + IsA<$base> {}
    };
}

attribute!(ApplicationBase, value::String, aros_mui_sys::MUIA_Application_Base, for classes::Application);
build!(ApplicationBase for classes::Application);

attribute!(ApplicationTitle, value::String, aros_mui_sys::MUIA_Application_Title, for classes::Application);
build!(ApplicationTitle for classes::Application);

attribute!(WindowTitle, value::String, aros_mui_sys::MUIA_Window_Title, for classes::Window);
build!(WindowTitle for classes::Window);
set!(WindowTitle for classes::Window);

attribute!(WindowOpen, value::Boolean, aros_mui_sys::MUIA_Window_Open, for classes::Window);
get!(WindowOpen for classes::Window);
set!(WindowOpen for classes::Window);

attribute!(WindowDefaultObject, value::Object<classes::Area>, aros_mui_sys::MUIA_Window_DefaultObject, for classes::Window);
build!(WindowDefaultObject for classes::Window);
set!(WindowDefaultObject for classes::Window);

attribute!(GroupHorizontal, value::Boolean, aros_mui_sys::MUIA_Group_Horiz, for classes::Group);
build!(GroupHorizontal for classes::Group);

attribute!(GroupColumns, value::Unsigned, aros_mui_sys::MUIA_Group_Columns, for classes::Group);
build!(GroupColumns for classes::Group);

attribute!(GroupActivePage, value::Enumeration<ActivePage>, aros_mui_sys::MUIA_Group_ActivePage, for classes::Group);
build!(GroupActivePage for classes::Group);
get!(GroupActivePage for classes::Group);
set!(GroupActivePage for classes::Group);

attribute!(TextContents, value::String, aros_mui_sys::MUIA_Text_Contents, for classes::Text);
build!(TextContents for classes::Text);
set!(TextContents for classes::Text);

inherited_attribute!(Frame, value::Enumeration<FrameStyle>, aros_mui_sys::MUIA_Frame, for classes::Area);
inherited_build!(Frame for classes::Area);
inherited_get!(Frame for classes::Area);
inherited_set!(Frame for classes::Area);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivePage {
    First,
    Last,
    Previous,
    Next,
    Advance,
}

impl MuiEnum for ActivePage {
    fn into_raw(self) -> isize {
        match self {
            Self::First => aros_mui_sys::MUIV_Group_ActivePage_First as isize,
            Self::Last => aros_mui_sys::MUIV_Group_ActivePage_Last as isize,
            Self::Previous => aros_mui_sys::MUIV_Group_ActivePage_Prev as isize,
            Self::Next => aros_mui_sys::MUIV_Group_ActivePage_Next as isize,
            Self::Advance => aros_mui_sys::MUIV_Group_ActivePage_Advance as isize,
        }
    }

    fn from_raw(raw: isize) -> Option<Self> {
        match raw {
            value if value == aros_mui_sys::MUIV_Group_ActivePage_First as isize => {
                Some(Self::First)
            }
            value if value == aros_mui_sys::MUIV_Group_ActivePage_Last as isize => Some(Self::Last),
            value if value == aros_mui_sys::MUIV_Group_ActivePage_Prev as isize => {
                Some(Self::Previous)
            }
            value if value == aros_mui_sys::MUIV_Group_ActivePage_Next as isize => Some(Self::Next),
            value if value == aros_mui_sys::MUIV_Group_ActivePage_Advance as isize => {
                Some(Self::Advance)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameStyle {
    None,
    Button,
    Text,
    String,
    Group,
    Register,
}

impl MuiEnum for FrameStyle {
    fn into_raw(self) -> isize {
        match self {
            Self::None => aros_mui_sys::MUIV_Frame_None as isize,
            Self::Button => aros_mui_sys::MUIV_Frame_Button as isize,
            Self::Text => aros_mui_sys::MUIV_Frame_Text as isize,
            Self::String => aros_mui_sys::MUIV_Frame_String as isize,
            Self::Group => aros_mui_sys::MUIV_Frame_Group as isize,
            Self::Register => aros_mui_sys::MUIV_Frame_Register as isize,
        }
    }

    fn from_raw(raw: isize) -> Option<Self> {
        match raw {
            value if value == aros_mui_sys::MUIV_Frame_None as isize => Some(Self::None),
            value if value == aros_mui_sys::MUIV_Frame_Button as isize => Some(Self::Button),
            value if value == aros_mui_sys::MUIV_Frame_Text as isize => Some(Self::Text),
            value if value == aros_mui_sys::MUIV_Frame_String as isize => Some(Self::String),
            value if value == aros_mui_sys::MUIV_Frame_Group as isize => Some(Self::Group),
            value if value == aros_mui_sys::MUIV_Frame_Register as isize => Some(Self::Register),
            _ => None,
        }
    }
}
