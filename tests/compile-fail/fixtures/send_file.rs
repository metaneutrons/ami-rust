#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros_sdk::{BytePath, Context, File, FileMode};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

fn require_send<T: Send>(_: T) {}

pub fn transfer_file(context: &Context) {
    let path = BytePath::new(b"RAM:m1-send-file").unwrap();
    let file = File::open(context, &path, FileMode::ReadExisting).unwrap();
    require_send(file);
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
