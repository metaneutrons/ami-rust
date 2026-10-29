#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec;
use aros::{AppStatus, BytePath, Context, File, FileMode, Library};
use aros_mui::{Mui, TagItem};

fn application(context: &Context) -> AppStatus {
    context.diagnostic(b"ami-rust M1 begin", 1);

    let mut allocation = vec![0u8; 4096];
    for (index, byte) in allocation.iter_mut().enumerate() {
        *byte = (index & 0xff) as u8;
    }
    if allocation
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte != (index & 0xff) as u8)
    {
        return AppStatus::Fatal;
    }
    drop(allocation);
    context.diagnostic(b"ami-rust M1 allocation pass", 0);

    let Ok(path) = BytePath::new(b"RAM:ami-rust-m1.txt") else {
        return AppStatus::Fatal;
    };
    let Ok(mut file) = File::open(context, &path, FileMode::CreateTruncate) else {
        return AppStatus::Error;
    };
    if file.write_all(b"ami-rust M1 dual ABI\n").is_err() || file.close().is_err() {
        return AppStatus::Error;
    }
    let Ok(mut file) = File::open(context, &path, FileMode::ReadExisting) else {
        return AppStatus::Error;
    };
    let mut readback = [0u8; 21];
    if file.read_exact(&mut readback).is_err()
        || readback != *b"ami-rust M1 dual ABI\n"
        || file.close().is_err()
    {
        return AppStatus::Error;
    }
    context.diagnostic(b"ami-rust M1 file I/O pass", 0);

    let Ok(utility_name) = BytePath::new(b"utility.library") else {
        return AppStatus::Fatal;
    };
    let Ok(utility) = Library::open(context, &utility_name, 0) else {
        return AppStatus::Error;
    };
    if utility.close().is_err() {
        return AppStatus::Error;
    }
    context.diagnostic(b"ami-rust M1 library pass", 0);

    let Ok(mui) = Mui::open(context) else {
        return AppStatus::Error;
    };
    let class = c"Window.mui";
    let mut tags = [TagItem::done()];
    // SAFETY: the class identifier is static and this deliberately minimal
    // lifecycle supplies a terminated tag list for synchronous construction.
    let Ok(window) = (unsafe { mui.new_object_raw(class, &mut tags) }) else {
        return AppStatus::Error;
    };
    drop(window);
    if mui.close().is_err() {
        return AppStatus::Error;
    }
    context.diagnostic(b"ami-rust M1 MUI pass", 0);

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

    context.diagnostic(b"ami-rust M1 pass", 0);
    AppStatus::Success
}

aros::entry!(application, alloc);
