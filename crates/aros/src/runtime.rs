//! One scoped Rust application frame inside the initialized native C runtime.
use core::marker::PhantomData;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStatus {
    Success = 0,
    Error = 10,
    Fatal = 20,
}

/// Borrowed owner-task witness. It owns no allocations and cannot escape dispatch.
/// Global resource reclamation is performed by C only after the user frame returns.
pub struct Context {
    key: u64,
    task_affinity: PhantomData<*mut ()>,
}
impl Context {
    #[doc(hidden)]
    pub fn key(&self) -> u64 {
        self.key
    }
    pub fn args(&self) -> Args<'_> {
        Args {
            context: self,
            index: 0,
        }
    }
    pub fn diagnostic(&self, label: &[u8], code: u64) {
        // SAFETY: borrowed bytes remain alive for this bounded synchronous call.
        unsafe { aros_sys::sdk_diagnostic(label.as_ptr(), label.len(), code) };
    }
    pub fn statistics(&self) -> aros_sys::SdkStats {
        // SAFETY: Context is not Send/Sync and native application remains active.
        unsafe { aros_sys::sdk_stats() }
    }
}
pub struct Args<'a> {
    context: &'a Context,
    index: usize,
}
impl<'a> Iterator for Args<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: stdc argv is validated by C and remains borrowed until dispatch returns.
        let count = unsafe { aros_sys::sdk_arg_count(self.context.key) };
        if self.index >= count {
            return None;
        }
        let mut length = 0;
        let pointer = unsafe { aros_sys::sdk_arg(self.context.key, self.index, &mut length) };
        self.index += 1;
        if pointer.is_null() {
            return None;
        }
        Some(unsafe { core::slice::from_raw_parts(pointer, length) })
    }
}
#[doc(hidden)]
pub fn dispatch(application: fn(&Context) -> AppStatus) -> i32 {
    // SAFETY: native C initializes stdc/owner state before invoking Rust. A failed
    // claim refuses before constructing a Context, including nested dispatch.
    let key = unsafe { aros_sys::sdk_claim_context() };
    if key == 0 {
        return AppStatus::Fatal as i32;
    }
    let context = Context {
        key,
        task_affinity: PhantomData,
    };
    application(&context) as i32
}
/// Install exactly one application entry and heap-free fatal panic handler.
#[macro_export]
macro_rules! entry {
    ($application:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn rust_sdk_main() -> i32 {
            $crate::dispatch($application)
        }
        #[panic_handler]
        fn ami_rust_panic(_: &core::panic::PanicInfo<'_>) -> ! {
            // SAFETY: this handler is installed only in the native application.
            unsafe { $crate::__fatal(1) }
        }
    };
    ($application:path, alloc) => {
        #[global_allocator]
        static AMI_RUST_ALLOCATOR: $crate::ExecAllocator = $crate::ExecAllocator;
        $crate::entry!($application);
    };
}
#[doc(hidden)]
pub unsafe fn __fatal(reason: u64) -> ! {
    // SAFETY: caller is the registered native application panic/OOM path.
    unsafe { aros_sys::sdk_fatal(reason) }
}
