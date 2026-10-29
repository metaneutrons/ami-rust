#![no_main]
#![no_std]

use aros::{AppStatus, Context};
use aros_mui::{
    CustomClassSpec, Error, LoopControl, LoopExit, Mui, ReturnId, Trigger,
    attributes::{
        ApplicationBase, ApplicationTitle, GroupHoriz, MenuTitle, MenuitemShortcut, MenuitemTitle,
        TextContents, UserData, WindowTitle,
    },
    classes::{Application, Group, Menu, Menuitem, Menustrip, Notify, Text, Window},
};
use core::cell::Cell;

const METHOD_TOUCH: u32 = 0x8000_4d36;

struct ProofClass;

#[derive(Clone, Copy)]
enum ProofMethod {
    Touch,
}

#[derive(Default)]
struct ProofData {
    calls: usize,
}

impl CustomClassSpec for ProofClass {
    type Super = Text;
    type Data = ProofData;
    type Method = ProofMethod;

    fn decode_method(method_id: u32) -> Option<Self::Method> {
        (method_id == METHOD_TOUCH).then_some(ProofMethod::Touch)
    }

    fn method_id(method: Self::Method) -> u32 {
        match method {
            ProofMethod::Touch => METHOD_TOUCH,
        }
    }

    fn dispatch(data: &mut Self::Data, method: Self::Method) -> usize {
        match method {
            ProofMethod::Touch => {
                data.calls += 1;
                data.calls
            }
        }
    }
}

fn safe_interactions(context: &Context, mui: &Mui<'_>) -> Result<(), Error> {
    let callback_calls = Cell::new(0u32);
    let callback_value = Cell::new(0isize);

    mui.scope(|scope| {
        let hook = scope.hook(|call| {
            callback_calls.set(callback_calls.get() + 1);
            callback_value.set(call.value);
            1
        })?;

        let custom_class = scope.custom_class::<ProofClass>()?;
        let custom_text = custom_class
            .builder()
            .with::<TextContents>(c"Safe Rust custom class")?
            .build()?;
        let custom_result = custom_text.call(ProofMethod::Touch)?;
        if custom_result != 1 {
            return Err(Error::NativeOperation);
        }
        context.diagnostic(b"ami-rust M6 custom dispatch pass", custom_result as u64);
        let source = scope.builder::<Notify>().build()?;

        let root = scope
            .builder::<Group>()
            .with::<GroupHoriz>(false)?
            .build()?;
        root.adopt(custom_text.object())?;
        let window = scope
            .builder::<Window>()
            .with::<WindowTitle>(c"ami-rust M6 interactions")?
            .build()?;
        window.adopt(root)?;

        let quit_item = scope
            .builder::<Menuitem>()
            .with::<MenuitemTitle>(c"Quit")?
            .with::<MenuitemShortcut>(c"Q")?
            .build()?;
        let menu = scope
            .builder::<Menu>()
            .with::<MenuTitle>(c"Project")?
            .build()?;
        menu.adopt(quit_item)?;
        let menu_strip = scope.builder::<Menustrip>().build()?;
        menu_strip.adopt(menu)?;

        let application = scope
            .builder::<Application>()
            .with::<ApplicationBase>(c"AMIRUSTM6")?
            .with::<ApplicationTitle>(c"ami-rust M6 interactions")?
            .build()?;
        application.adopt(menu_strip)?;
        application.adopt(window)?;

        source
            .notify::<UserData>(Trigger::EveryTime)?
            .call(application, &hook)?;
        source
            .notify::<UserData>(Trigger::EveryTime)?
            .return_id(application, ReturnId::QUIT)?;
        source.set::<UserData>(42)?;

        if callback_calls.get() != 1 || callback_value.get() != 42 {
            return Err(Error::NativeOperation);
        }
        context.diagnostic(b"ami-rust M6 callback pass", callback_value.get() as u64);
        if application.run(|_| LoopControl::Continue)? != LoopExit::Quit {
            return Err(Error::NativeOperation);
        }
        context.diagnostic(b"ami-rust M6 event loop pass", 0);
        Ok(())
    })
}

fn application(context: &Context) -> AppStatus {
    context.diagnostic(b"ami-rust M6 begin", 1);
    let Ok(mui) = Mui::open(context) else {
        return AppStatus::Error;
    };
    if safe_interactions(context, &mui).is_err() {
        return AppStatus::Fatal;
    }
    context.diagnostic(b"ami-rust M6 interactions pass", 0);
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
    context.diagnostic(b"ami-rust M6 cleanup pass", 0);
    context.diagnostic(b"ami-rust M6 pass", 0);
    AppStatus::Success
}

aros::entry!(application, alloc);
