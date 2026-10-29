#![no_main]
#![no_std]

use aros::{AppStatus, Context};
use aros_mui::{
    Error, Mui,
    attributes::{
        ApplicationBase, ApplicationTitle, Frame, GroupColumns, GroupHoriz, InputMode,
        ListSourceArray, ListTitle, MenuTitle, MenuitemShortcut, MenuitemTitle, RegisterTitles,
        StringContents, TextContents, WindowTitle,
    },
    classes::{
        Application, Group, List, Menu, Menuitem, Menustrip, Register, String as MuiString, Text,
        Window,
    },
    values::{FrameValue, InputModeValue},
};

fn safe_gallery(mui: &Mui<'_>) -> Result<(), Error> {
    mui.scope(|scope| {
        let heading = scope
            .builder::<Text>()
            .with::<TextContents>(c"ami-rust generated MUI gallery")?
            .with::<Frame>(FrameValue::Text)?
            .build()?;

        let button = scope
            .builder::<Text>()
            .with::<TextContents>(c"Generated button")?
            .with::<Frame>(FrameValue::Button)?
            .with::<InputMode>(InputModeValue::RelVerify)?
            .build()?;

        let string = scope
            .builder::<MuiString>()
            .with::<StringContents>(c"Safe generated string")?
            .with::<Frame>(FrameValue::String)?
            .build()?;

        let list_entries = scope.string_array(&[c"Application", c"Window", c"Group", c"List"])?;
        let list = scope
            .builder::<List>()
            .with::<ListTitle>(c"Generated classes")?
            .with::<ListSourceArray>(list_entries)?
            .with::<Frame>(FrameValue::ReadList)?
            .build()?;

        let register_titles = scope.string_array(&[c"Overview", c"Details"])?;
        let register = scope
            .builder::<Register>()
            .with::<RegisterTitles>(register_titles)?
            .build()?;
        let overview = scope
            .builder::<Text>()
            .with::<TextContents>(c"ABI1 and ABI11")?
            .build()?;
        let details = scope
            .builder::<Text>()
            .with::<TextContents>(c"Generated from the canonical model")?
            .build()?;
        register.adopt(overview)?;
        register.adopt(details)?;

        let root = scope
            .builder::<Group>()
            .with::<GroupHoriz>(false)?
            .with::<GroupColumns>(1)?
            .with::<Frame>(FrameValue::Group)?
            .build()?;
        root.adopt(heading)?;
        root.adopt(button)?;
        root.adopt(string)?;
        root.adopt(list)?;
        root.adopt(register)?;

        let menu_item = scope
            .builder::<Menuitem>()
            .with::<MenuitemTitle>(c"Quit")?
            .with::<MenuitemShortcut>(c"Q")?
            .build()?;
        let menu = scope
            .builder::<Menu>()
            .with::<MenuTitle>(c"Project")?
            .build()?;
        menu.adopt(menu_item)?;
        let menu_strip = scope.builder::<Menustrip>().build()?;
        menu_strip.adopt(menu)?;

        let window = scope
            .builder::<Window>()
            .with::<WindowTitle>(c"ami-rust M5 generated gallery")?
            .build()?;
        window.adopt(root)?;

        let application = scope
            .builder::<Application>()
            .with::<ApplicationBase>(c"AMIRUSTM5")?
            .with::<ApplicationTitle>(c"ami-rust generated MUI gallery")?
            .build()?;
        application.adopt(menu_strip)?;
        application.adopt(window)?;
        Ok(())
    })
}

fn application(context: &Context) -> AppStatus {
    context.diagnostic(b"ami-rust M5 begin", 1);
    let Ok(mui) = Mui::open(context) else {
        return AppStatus::Error;
    };
    if safe_gallery(&mui).is_err() {
        return AppStatus::Fatal;
    }
    context.diagnostic(b"ami-rust M5 gallery pass", 0);
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
    context.diagnostic(b"ami-rust M5 cleanup pass", 0);
    context.diagnostic(b"ami-rust M5 pass", 0);
    AppStatus::Success
}

aros::entry!(application, alloc);
