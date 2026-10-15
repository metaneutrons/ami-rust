#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aros_sdk::Context;

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

pub fn escape_borrowed_callback(
    context: &Context,
) -> impl FnMut(u64) -> u64 + 'static {
    let mut callback = |value: u64| context.key().wrapping_add(value);
    let _ = aros_sdk::call(context, &mut callback, 0);
    callback
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_sdk_main() -> i32 {
    0
}
