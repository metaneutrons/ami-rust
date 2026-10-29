#![no_main]
#![no_std]

use aros::{AppStatus, BytePath, Context, Library};
use aros_mui_sys::{
    MUI_CONSTANT_VALUES, MUI_CUSTOM_CLASS_LAYOUT_VALUES, MUI_LAYOUT_VALUES, MUIA_Window_Open,
    MUIC_Window, MUIM_NoNotifySet, MUIP_NoNotifySet, Stacked, TagItem, mui_dispose_object,
    mui_free_class, mui_get_class, mui_new_object_a, mui_request_a,
};
use aros_sys::{
    BOOPSI_LAYOUT_VALUES, Library as RawLibrary, coerce_method_a, do_method_a, do_super_method_a,
};
use core::{
    ffi::{c_char, c_void},
    slice,
};

const REQUEST_PROBE_RESULT: i32 = 0x3141_5926;
static mut EXPECTED_BASE: usize = 0;

fn request_arguments_match(
    application: *mut c_void,
    window: *mut c_void,
    flags: u32,
    title: *const c_char,
    gadgets: *const c_char,
    format: *const c_char,
    parameters: *mut c_void,
) -> bool {
    application.addr() == 0x1111
        && window.addr() == 0x2222
        && flags == 0x3333
        && title.addr() == 0x4444
        && gadgets.addr() == 0x5555
        && format.addr() == 0x6666
        && parameters.addr() == 0x7777
}

#[cfg(any(target_abi = "", target_abi = "abi1"))]
unsafe extern "C" fn request_probe(
    application: *mut c_void,
    window: *mut c_void,
    flags: u32,
    title: *const c_char,
    gadgets: *const c_char,
    format: *const c_char,
    parameters: *mut c_void,
    base: *mut RawLibrary,
) -> i32 {
    let expected_base = unsafe { EXPECTED_BASE };
    if request_arguments_match(
        application,
        window,
        flags,
        title,
        gadgets,
        format,
        parameters,
    ) && base.addr() == expected_base
    {
        REQUEST_PROBE_RESULT
    } else {
        -1
    }
}

#[cfg(target_abi = "abi11")]
unsafe extern "C" fn request_probe(
    application: *mut c_void,
    window: *mut c_void,
    flags: u32,
    title: *const c_char,
    gadgets: *const c_char,
    format: *const c_char,
    parameters: *mut c_void,
) -> i32 {
    let observed_base: usize;
    // SAFETY: this reads the ABI-v11 library-base register without changing
    // machine state.
    unsafe {
        core::arch::asm!(
            "mov {}, r12",
            out(reg) observed_base,
            options(nomem, nostack, preserves_flags),
        );
    }
    let expected_base = unsafe { EXPECTED_BASE };
    if request_arguments_match(
        application,
        window,
        flags,
        title,
        gadgets,
        format,
        parameters,
    ) && observed_base == expected_base
    {
        REQUEST_PROBE_RESULT
    } else {
        -1
    }
}

fn explicit_call_adapter_matches() -> bool {
    let mut vectors = [0, request_probe as *const () as usize, 0, 0, 0, 0, 0, 0];
    // The raw vector reader addresses vector 7 as seven pointer slots before
    // the public library base.
    let base = unsafe { vectors.as_mut_ptr().add(vectors.len()).cast::<RawLibrary>() };
    unsafe { EXPECTED_BASE = base.addr() };
    // SAFETY: the synthetic vector table and probe function implement the
    // complete ABI-specific `MUI_RequestA` contract for this call.
    unsafe {
        mui_request_a(
            base,
            0x1111usize as *mut c_void,
            0x2222usize as *mut c_void,
            0x3333,
            0x4444usize as *const c_char,
            0x5555usize as *const c_char,
            0x6666usize as *const c_char,
            0x7777usize as *mut c_void,
        ) == REQUEST_PROBE_RESULT
    }
}

unsafe extern "C" {
    static ami_rust_boopsi_layout_values: u64;
    static ami_rust_boopsi_layout_value_count: usize;
    static ami_rust_custom_class_layout_values: u64;
    static ami_rust_custom_class_layout_value_count: usize;
    static ami_rust_mui_layout_values: u64;
    static ami_rust_mui_layout_value_count: usize;
    static ami_rust_mui_constant_values: u64;
    static ami_rust_mui_constant_value_count: usize;
    fn ami_rust_mui_window_class_id() -> *const c_char;
}

fn c_string_equal(left: *const c_char, right: *const c_char) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    for index in 0..128 {
        // SAFETY: both class IDs are native NUL-terminated strings and the
        // comparison is bounded independently of their content.
        let left_byte = unsafe { left.add(index).read() };
        // SAFETY: same bounded class-ID contract as above.
        let right_byte = unsafe { right.add(index).read() };
        if left_byte != right_byte {
            return false;
        }
        if left_byte == 0 {
            return true;
        }
    }
    false
}

fn first_mismatch(c_values: &[u64], rust_values: &[usize]) -> Option<usize> {
    if c_values.len() != rust_values.len() {
        return Some(c_values.len().min(rust_values.len()));
    }
    c_values
        .iter()
        .zip(rust_values)
        .position(|(c, rust)| *c != *rust as u64)
}

fn generated_surface_mismatch() -> Option<usize> {
    let mut offset = 0;
    // SAFETY: the generated C oracle exports exactly the recorded count and
    // layout array for the BOOPSI records read by the dispatch adapters.
    let c_boopsi = unsafe {
        slice::from_raw_parts(
            core::ptr::addr_of!(ami_rust_boopsi_layout_values),
            ami_rust_boopsi_layout_value_count,
        )
    };
    if let Some(index) = first_mismatch(c_boopsi, &BOOPSI_LAYOUT_VALUES) {
        return Some(offset + index);
    }
    offset += BOOPSI_LAYOUT_VALUES.len();
    // SAFETY: same generated-oracle contract for `MUI_CustomClass`.
    let c_custom_class = unsafe {
        slice::from_raw_parts(
            core::ptr::addr_of!(ami_rust_custom_class_layout_values),
            ami_rust_custom_class_layout_value_count,
        )
    };
    if let Some(index) = first_mismatch(c_custom_class, &MUI_CUSTOM_CLASS_LAYOUT_VALUES) {
        return Some(offset + index);
    }
    offset += MUI_CUSTOM_CLASS_LAYOUT_VALUES.len();
    // SAFETY: the generated C oracle exports exactly the recorded counts and
    // arrays and is linked into this qualification executable.
    let c_layouts = unsafe {
        slice::from_raw_parts(
            core::ptr::addr_of!(ami_rust_mui_layout_values),
            ami_rust_mui_layout_value_count,
        )
    };
    if let Some(index) = first_mismatch(c_layouts, &MUI_LAYOUT_VALUES) {
        return Some(offset + index);
    }
    offset += MUI_LAYOUT_VALUES.len();
    // SAFETY: same generated-oracle contract as the layout array.
    let c_constants = unsafe {
        slice::from_raw_parts(
            core::ptr::addr_of!(ami_rust_mui_constant_values),
            ami_rust_mui_constant_value_count,
        )
    };
    if let Some(index) = c_constants
        .iter()
        .zip(MUI_CONSTANT_VALUES)
        .position(|(c, rust)| *c != rust)
    {
        return Some(offset + index);
    }
    if c_constants.len() != MUI_CONSTANT_VALUES.len() {
        return Some(offset + c_constants.len().min(MUI_CONSTANT_VALUES.len()));
    }
    offset += MUI_CONSTANT_VALUES.len();
    // SAFETY: the generated C function returns the static `MUIC_Window`.
    if !c_string_equal(unsafe { ami_rust_mui_window_class_id() }, MUIC_Window) {
        return Some(offset);
    }
    None
}

fn application(context: &Context) -> AppStatus {
    context.diagnostic(b"ami-rust M3 begin", 1);
    if let Some(index) = generated_surface_mismatch() {
        context.diagnostic(b"ami-rust M3 C/Rust mismatch index", index as u64);
        return AppStatus::Fatal;
    }
    context.diagnostic(b"ami-rust M3 layout pass", 0);
    if !explicit_call_adapter_matches() {
        context.diagnostic(b"ami-rust M3 call adapter mismatch", 20);
        return AppStatus::Fatal;
    }
    context.diagnostic(b"ami-rust M3 call adapter pass", 0);

    let Ok(name) = BytePath::new(b"muimaster.library") else {
        return AppStatus::Fatal;
    };
    let Ok(library) = Library::open(context, &name, 19) else {
        return AppStatus::Error;
    };
    // SAFETY: the live handle is retained through every raw call and closed
    // only after the object and class references are released.
    let Some(base) = (unsafe { library.raw_base() }) else {
        return AppStatus::Fatal;
    };
    let mut tags = [TagItem::done()];
    // SAFETY: generated static class ID plus a terminated synchronous tag list.
    let object = unsafe { mui_new_object_a(base.cast(), MUIC_Window, tags.as_mut_ptr()) };
    if object.is_null() {
        return AppStatus::Error;
    }
    // SAFETY: the class ID and live muimaster base satisfy vector 13.
    let class = unsafe { mui_get_class(base.cast(), MUIC_Window) };
    if class.is_null() {
        // SAFETY: `object` was created by this live base.
        unsafe { mui_dispose_object(base.cast(), object) };
        return AppStatus::Error;
    }
    let mut message = MUIP_NoNotifySet {
        MethodID: Stacked::new(MUIM_NoNotifySet),
        attr: Stacked::new(MUIA_Window_Open),
        val: Stacked::new(0),
    };
    let message = core::ptr::addr_of_mut!(message).cast();
    // SAFETY: this is a live Window.mui object and a generated, layout-checked
    // `MUIM_NoNotifySet` message. Each adapter uses the native BOOPSI contract.
    unsafe {
        do_method_a(object.cast(), message);
        coerce_method_a(class, object.cast(), message);
        do_super_method_a(class, object.cast(), message);
        mui_free_class(base.cast(), class);
        mui_dispose_object(base.cast(), object);
    }
    if library.close().is_err() {
        return AppStatus::Error;
    }
    context.diagnostic(b"ami-rust M3 raw MUI pass", 0);

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
    context.diagnostic(b"ami-rust M3 pass", 0);
    AppStatus::Success
}

aros::entry!(application);
