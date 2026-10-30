//! Exec-backed global allocator used by the application's registered task.
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

/// Global allocator backed by the native SDK's public Exec allocation API.
///
/// Install this allocator with `crate::entry!(application, alloc)`; the
/// `alloc` feature must be enabled. Allocations are supported only while the
/// native SDK runtime is active and on its registered owner task. The native
/// bridge checks size arithmetic, requested alignment, ownership, and its
/// current accounting before accepting a block. It supports alignments up to
/// 4096 bytes; native memory exhaustion and checked refusal remain possible.
///
/// Allocation refusal returns null through [`GlobalAlloc::alloc`]. Fallible
/// collection APIs can report that refusal themselves; an infallible Rust
/// allocation that cannot proceed reaches Rust's allocation-error path, which
/// the `entry!` panic handler routes to the native fatal path. The allocator
/// does not impose an application-wide heap quota.
///
/// Reallocation allocates a replacement, copies the valid prefix, and releases
/// the old block only after the replacement succeeds. If allocation fails,
/// the old block remains valid and unchanged. Zeroed allocation clears the
/// requested bytes before returning them.
pub struct ExecAllocator;
// SAFETY: the native owner-task registry preserves original backing pointers,
// checks size/alignment/overflow, and never returns an accepted misaligned block.
// Global allocations are supported only in the declared single application task.
unsafe impl GlobalAlloc for ExecAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Layout is valid; native refusal is returned as null.
        unsafe { aros_sys::sdk_alloc(layout.size(), layout.align()).cast() }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc caller supplies the original allocation and Layout.
        unsafe { aros_sys::sdk_dealloc(pointer.cast(), layout.size(), layout.align()) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { self.alloc(layout) };
        if !pointer.is_null() {
            // SAFETY: accepted allocation has at least layout.size() writable bytes.
            unsafe { ptr::write_bytes(pointer, 0, layout.size()) };
        }
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let Ok(new) = Layout::from_size_align(new_size, old.align()) else {
            return ptr::null_mut();
        };
        let fresh = unsafe { self.alloc(new) };
        if fresh.is_null() {
            return fresh;
        }
        // SAFETY: allocations are disjoint; preserve the entire valid prefix.
        unsafe {
            ptr::copy_nonoverlapping(pointer, fresh, core::cmp::min(old.size(), new_size));
            self.dealloc(pointer, old);
        }
        fresh
    }
}
