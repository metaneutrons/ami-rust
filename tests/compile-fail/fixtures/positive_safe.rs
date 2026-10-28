#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros::{BytePath, Context, Error, File, FileMode};

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

pub fn safe_file_use(context: &Context) -> Result<(), Error> {
    let path = BytePath::new(b"RAM:m1-safe-fixture")?;
    let mut file = File::open(context, &path, FileMode::CreateTruncate)?;
    file.write_all(b"safe")?;
    file.close()
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
