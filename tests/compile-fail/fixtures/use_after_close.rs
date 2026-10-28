#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros::{BytePath, Context, File, FileMode};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

pub fn use_closed_file(context: &Context) {
    let path = BytePath::new(b"RAM:m1-use-after-close").unwrap();
    let mut file = File::open(context, &path, FileMode::ReadExisting).unwrap();
    let _ = file.close();
    let _ = file.read(&mut [0; 1]);
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
