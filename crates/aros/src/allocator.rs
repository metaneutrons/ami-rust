//! Exec-backed global allocator; installed explicitly by the application.
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

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
