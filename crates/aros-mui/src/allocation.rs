use crate::Error;
use alloc::{alloc::alloc, boxed::Box};
use core::{alloc::Layout, mem, ptr::NonNull};

pub(crate) fn try_box<T>(value: T) -> Result<Box<T>, Error> {
    if mem::size_of::<T>() == 0 {
        return Ok(Box::new(value));
    }
    let layout = Layout::new::<T>();
    // SAFETY: the returned allocation is checked before `value` is written,
    // and ownership is transferred immediately to `Box` with the same layout.
    let pointer = NonNull::new(unsafe { alloc(layout).cast::<T>() }).ok_or(Error::Allocation)?;
    unsafe {
        pointer.as_ptr().write(value);
        Ok(Box::from_raw(pointer.as_ptr()))
    }
}
