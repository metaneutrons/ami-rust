#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros_sdk::{BytePath, Context, File, FileMode};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

pub fn return_file_after_context(context: &Context) -> File<'static> {
    let path = BytePath::new(b"RAM:m1-context-exit").unwrap();
    File::open(context, &path, FileMode::ReadExisting).unwrap()
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
