#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros_sdk::{BytePath, Context, File, FileMode};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

fn require_sync<T: Sync>(_: &T) {}

pub fn share_file(context: &Context) {
    let path = BytePath::new(b"RAM:m1-sync-file").unwrap();
    let file = File::open(context, &path, FileMode::ReadExisting).unwrap();
    require_sync(&file);
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
