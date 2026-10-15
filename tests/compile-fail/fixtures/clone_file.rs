#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros_sdk::{BytePath, Context, File, FileMode};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

pub fn clone_owned_file(context: &Context) {
    let path = BytePath::new(b"RAM:m1-clone-file").unwrap();
    let file = File::open(context, &path, FileMode::ReadExisting).unwrap();
    let _: File<'_> = Clone::clone(&file);
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
