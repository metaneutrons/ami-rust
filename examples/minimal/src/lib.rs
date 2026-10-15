#![no_std]
use aros_runtime::{AppStatus,Context};
#[cfg(feature="alloc")]
extern crate alloc;
fn application(ctx: &Context) -> AppStatus {
    let expected = aros_sys::layout_values();
    let mut actual = [0u64; aros_sys::ABI_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity, C only writes these scalar oracle values.
    let count = unsafe { aros_sys::sdk_layout(actual.as_mut_ptr(), actual.len()) };
    if count != actual.len() || actual != expected { return AppStatus::Fatal; }
    let scalar = unsafe { aros_sys::sdk_scalar(-7,0xfedcba98,0x123456789abcdef0,0x876543210,0x102030405) };
    let want = ((-7i32 as u32 as u64)<<32)^0xfedcba98^0x123456789abcdef0^0x876543210^0x102030405;
    if scalar != want { return AppStatus::Fatal; }
    let mut callback = |n| n ^ 0x41524f5352555354;
    if aros_sdk::call(ctx,&mut callback,0x123456789abcdef0) != Ok(0x123456789abcdef0 ^ 0x41524f5352555354) { return AppStatus::Fatal; }
    let stats = ctx.statistics();
    if stats.blocks != 0 || stats.files != 0 || stats.ports != 0 || stats.messages != 0 { return AppStatus::Fatal; }
    #[cfg(feature="alloc")]
    {
        let mut bytes = alloc::vec::Vec::<u8>::new();
        if bytes.try_reserve_exact(4096).is_err() { return AppStatus::Error; }
        for i in 0..4096 { bytes.push((i&255) as u8); }
        if bytes.iter().enumerate().any(|(i,b)| *b != (i&255) as u8) { return AppStatus::Fatal; }
        drop(bytes);
        let after = ctx.statistics();
        if after.blocks != 0 || after.backing_charge != 0 || after.peak_charge == 0 { return AppStatus::Fatal; }
    }
    ctx.diagnostic(b"ami-rust ABI/startup",count as u64);
    AppStatus::Success
}
#[cfg(not(feature="alloc"))]
aros_runtime::entry!(application);
#[cfg(feature="alloc")]
aros_runtime::entry!(application, alloc);
