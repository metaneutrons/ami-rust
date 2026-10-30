#![no_main]
#![no_std]

use aros::{AppStatus, Context};
use aros_mui::{
    Error, LoopControl, Mui, ReturnId, Trigger,
    attributes::{
        ApplicationBase, ApplicationTitle, Frame, GroupHoriz, TextContents, WindowCloseGadget,
        WindowCloseRequest, WindowOpen, WindowTitle,
    },
    classes::{Application, Group, Text, Window},
    values::FrameValue,
};

fn build_and_run(context: &Context) -> Result<(), Error> {
    let mui = Mui::open(context)?;
    let result = mui.scope(|scope| {
        let heading = scope
            .builder::<Text>()
            .with::<TextContents>(c"Hello from Rust on AROS")?
            .with::<Frame>(FrameValue::Text)?
            .build()?;
        let detail = scope
            .builder::<Text>()
            .with::<TextContents>(c"This window uses the safe aros-mui API.")?
            .build()?;
        let root = scope
            .builder::<Group>()
            .with::<GroupHoriz>(false)?
            .build()?;
        root.adopt(heading)?;
        root.adopt(detail)?;

        let window = scope
            .builder::<Window>()
            .with::<WindowTitle>(c"mui-hello")?
            .with::<WindowCloseGadget>(true)?
            .build()?;
        window.adopt(root)?;

        let application = scope
            .builder::<Application>()
            .with::<ApplicationBase>(c"MUIHELLO")?
            .with::<ApplicationTitle>(c"ami-rust mui-hello")?
            .build()?;
        application.adopt(window)?;
        window
            .notify::<WindowCloseRequest>(Trigger::Value(true))?
            .return_id(application, ReturnId::QUIT)?;
        window.set::<WindowOpen>(true)?;
        application.run(|_| LoopControl::Continue).map(|_| ())
    });
    mui.close()?;
    result
}

fn application(context: &Context) -> AppStatus {
    match build_and_run(context) {
        Ok(()) => AppStatus::Success,
        Err(_) => AppStatus::Error,
    }
}

aros::entry!(application, alloc);
