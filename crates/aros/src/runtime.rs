//! The task-affine application frame established by the native C runtime.
use core::marker::PhantomData;

/// Application result returned to the native runtime.
///
/// The discriminants are the native process status values: success (`0`),
/// ordinary application error (`10`), and fatal failure (`20`). Returning a
/// status does not skip native cleanup; the C runtime drains its resource
/// registry after the Rust application function returns.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStatus {
    /// The application completed successfully.
    Success = 0,
    /// The application completed with an ordinary error.
    Error = 10,
    /// The application or runtime encountered a fatal failure.
    Fatal = 20,
}

/// Borrowed witness for the active native application task.
///
/// The native runtime creates this value after it has initialized the SDK and
/// successfully claimed the owner task. It owns no native resource. Its
/// private lifetime is the call to the application function, so references to
/// it and handles that borrow it cannot outlive that frame. The type is neither
/// [`Send`](core::marker::Send) nor [`Sync`](core::marker::Sync): SDK operations
/// must run on the creating task. Native C cleanup runs after the application
/// function returns, including when safe handles were forgotten.
pub struct Context {
    key: u64,
    task_affinity: PhantomData<*mut ()>,
}
impl Context {
    /// Returns the opaque key used internally to validate SDK operations.
    ///
    /// This is not an operating-system task pointer and must not be treated as
    /// a native handle. The method is hidden from generated documentation and
    /// exists for the crate's internal safe wrappers and ABI adapters.
    #[doc(hidden)]
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Iterates over the native `argv` entries as byte slices.
    ///
    /// The slices borrow native argument storage and are valid only while this
    /// context is live. They are not required to be UTF-8. The runtime accepts
    /// at most 32 arguments and at most 4096 encoded argument bytes in total,
    /// including each argument's terminating NUL.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use aros::Stdout;
    /// let mut out = Stdout::new(context)?;
    /// for argument in context.args() {
    ///     out.write_all(argument)?; // bytes, not necessarily UTF-8
    ///     out.write_all(b"\n")?;
    /// }
    /// ```
    pub fn args(&self) -> Args<'_> {
        Args {
            context: self,
            index: 0,
        }
    }

    /// Emits a bounded diagnostic label and decimal code through the native
    /// diagnostic sink.
    ///
    /// The label is interpreted as bytes, not UTF-8, and is truncated to 230
    /// bytes. The native side uses a fixed 256-byte buffer and appends the
    /// decimal representation of `code` and a newline. This call does not
    /// format through Rust or allocate.
    pub fn diagnostic(&self, label: &[u8], code: u64) {
        // SAFETY: borrowed bytes remain alive for this bounded synchronous call.
        unsafe { aros_sys::sdk_diagnostic(label.as_ptr(), label.len(), code) };
    }

    /// Returns a point-in-time snapshot of native SDK resource counters.
    ///
    /// The counters cover allocations, backing charge, peak charge, files,
    /// libraries, ports, signals, messages, and native refusals. The returned
    /// [`aros_sys::SdkStats`] is a raw ABI record from `aros-sys`; obtaining it
    /// does not allocate.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use aros::Signal;
    /// let before = context.statistics();
    /// {
    ///     let _signal = Signal::new(context)?;
    ///     assert_eq!(context.statistics().signals, before.signals + 1);
    /// }
    /// // Dropping the handle returned its slot.
    /// assert_eq!(context.statistics().signals, before.signals);
    /// ```
    pub fn statistics(&self) -> aros_sys::SdkStats {
        // SAFETY: Context is not Send/Sync and native application remains active.
        unsafe { aros_sys::sdk_stats() }
    }
}

/// Iterator over borrowed native `argv` bytes.
///
/// Each item borrows the argument storage owned by the native runtime and is
/// valid only while the [`Context`] used to create this iterator remains live.
/// No argument bytes are copied or converted to UTF-8. The validated runtime
/// bounds the collection to 32 arguments and 4096 encoded bytes in total.
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

/// Claims the initialized native runtime and calls the application function.
///
/// This function is hidden from generated documentation because applications
/// should use [`crate::entry!`], which exports the required C entry symbol and
/// panic handler. It returns the application's [`AppStatus`] as its native
/// integer status. If the runtime is unavailable, the owner task is wrong, or
/// another dispatch already claimed it, the application is not called and
/// [`AppStatus::Fatal`] is returned.
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

/// Defines the native application entry and a heap-free fatal panic handler.
///
/// Pass a function with signature `fn(&Context) -> AppStatus`. Invoke this
/// macro exactly once in the final application crate: it defines the exported
/// `rust_sdk_main` symbol and the crate's `#[panic_handler]`.
///
/// `entry!(application)` installs no global allocator, so the application must
/// not rely on allocation. `entry!(application, alloc)` additionally installs
/// [`ExecAllocator`](crate::ExecAllocator) and requires this crate's `alloc`
/// feature. That allocator only supports allocations made by the registered
/// owner task while the native SDK runtime is active. Native allocation can
/// still fail; an infallible allocation failure or panic enters the native
/// non-returning fatal path rather than unwinding through C.
///
/// ```ignore
/// fn application(_context: &aros::Context) -> aros::AppStatus {
///     aros::AppStatus::Success
/// }
///
/// aros::entry!(application, alloc);
/// ```
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

/// Enters the native non-returning fatal path.
///
/// This is hidden from generated documentation and is used by [`entry!`]'s
/// panic handler.
///
/// # Safety
///
/// Call only from the registered application's fatal or panic path while the
/// native runtime owns the current task. The function never returns.
#[doc(hidden)]
pub unsafe fn __fatal(reason: u64) -> ! {
    // SAFETY: caller is the registered native application panic/OOM path.
    unsafe { aros_sys::sdk_fatal(reason) }
}
