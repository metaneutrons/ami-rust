#![no_main]
#![no_std]

use aros::{AppStatus, Context};
use aros_mui::{
    Error, Mui,
    attributes::{
        ActivePage, ApplicationBase, ApplicationTitle, Frame, FrameStyle, GroupActivePage,
        GroupColumns, GroupHorizontal, TextContents, WindowDefaultObject, WindowOpen, WindowTitle,
    },
    classes::{Application, Area, Group, Text, Window},
    methods::NoNotifySet,
};

fn safe_tree(mui: &Mui<'_>) -> Result<(), Error> {
    mui.scope(|scope| {
        let text = scope
            .builder::<Text>()
            .with::<TextContents>(c"ami-rust M4 safe tree")?
            .with::<Frame>(FrameStyle::Text)?
            .build()?;

        let group = scope
            .builder::<Group>()
            .with::<GroupHorizontal>(false)?
            .with::<GroupColumns>(1)?
            .with::<GroupActivePage>(ActivePage::First)?
            .with::<Frame>(FrameStyle::Group)?
            .build()?;
        group.adopt(text)?;

        let window = scope
            .builder::<Window>()
            .with::<WindowTitle>(c"ami-rust M4")?
            .with::<WindowDefaultObject>(group.upcast::<Area>())?
            .build()?;
        window.adopt(group)?;

        let unattached = scope.builder::<Group>().build()?;
        if window.adopt(unattached) != Err(Error::ParentOccupied) {
            return Err(Error::NativeOperation);
        }

        let application = scope
            .builder::<Application>()
            .with::<ApplicationBase>(c"AMIRUSTM4")?
            .with::<ApplicationTitle>(c"ami-rust M4 safe object model")?
            .build()?;
        application.adopt(window)?;

        window.call::<NoNotifySet<WindowOpen>>(false)?;
        if window.get::<WindowOpen>()? {
            return Err(Error::NativeOperation);
        }
        if group.get::<Frame>()? != FrameStyle::Group {
            return Err(Error::NativeOperation);
        }
        Ok(())
    })
}

fn application(context: &Context) -> AppStatus {
    context.diagnostic(b"ami-rust M4 begin", 1);
    let Ok(mui) = Mui::open(context) else {
        return AppStatus::Error;
    };
    if safe_tree(&mui).is_err() {
        return AppStatus::Fatal;
    }
    context.diagnostic(b"ami-rust M4 safe tree pass", 0);
    if mui.close().is_err() {
        return AppStatus::Error;
    }

    let stats = context.statistics();
    if stats.blocks != 0
        || stats.backing_charge != 0
        || stats.files != 0
        || stats.libraries != 0
        || stats.ports != 0
        || stats.signals != 0
        || stats.messages != 0
    {
        return AppStatus::Fatal;
    }
    context.diagnostic(b"ami-rust M4 cleanup pass", 0);
    context.diagnostic(b"ami-rust M4 pass", 0);
    AppStatus::Success
}

aros::entry!(application, alloc);
