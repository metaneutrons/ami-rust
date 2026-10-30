use crate::{Error, Scope, allocation::try_box};
use alloc::boxed::Box;
use aros_sys::{Hook as RawHook, MinNode};
use core::{
    cell::{Cell, UnsafeCell},
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
};

/// Value delivered by a typed MUI notification callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HookCall {
    /// Native trigger value, widened to a signed pointer-sized integer.
    pub value: isize,
}

/// A callback retained by one live [`Scope`].
///
/// Handles cannot outlive their scope. The callback is non-reentrant: a nested
/// native invocation is refused with a zero result rather than creating a
/// second mutable reference to the closure. MUI invokes it on the owning
/// application task; its storage is released after that scope's native roots
/// have been disposed.
///
/// # Examples
///
/// ```ignore
/// # use aros_mui::{
/// #     Mui, Trigger,
/// #     attributes::{TextContents, WindowOpen},
/// #     classes::{Application, Text, Window},
/// # };
/// # use core::cell::Cell;
/// let clicks = Cell::new(0u32);
/// let mui = Mui::open(context)?;
/// mui.scope(|scope| {
///     // The closure may borrow local state: the hook cannot outlive this scope.
///     let hook = scope.hook(|_call| {
///         clicks.set(clicks.get() + 1);
///         0
///     })?;
///     let app = scope.builder::<Application>().build()?;
///     let window = scope.builder::<Window>().build()?;
///     app.adopt(window)?;
///     window.notify::<WindowOpen>(Trigger::EveryTime)?.call(app, &hook)?;
///     Ok::<(), aros_mui::Error>(())
/// })?;
/// mui.close()?;
/// ```
pub struct Hook<'scope> {
    raw: NonNull<RawHook>,
    scope: *const Scope,
    _lifetime: PhantomData<&'scope Scope>,
    _task_affine: PhantomData<*mut ()>,
}

impl Hook<'_> {
    pub(crate) fn raw(&self, scope: &Scope) -> Result<NonNull<RawHook>, Error> {
        if core::ptr::eq(scope, self.scope) {
            Ok(self.raw)
        } else {
            Err(Error::WrongScope)
        }
    }
}

struct HookState<F> {
    active: Cell<bool>,
    busy: Cell<bool>,
    callback: UnsafeCell<F>,
}

pub(crate) struct RetainedHook {
    hook: Box<RawHook>,
    state: NonNull<c_void>,
    deactivate: unsafe fn(NonNull<c_void>),
    drop_state: unsafe fn(NonNull<c_void>),
}

impl RetainedHook {
    fn new<F>(callback: F) -> Result<Self, Error>
    where
        F: FnMut(HookCall) -> isize,
    {
        let state = try_box(HookState {
            active: Cell::new(true),
            busy: Cell::new(false),
            callback: UnsafeCell::new(callback),
        })?;
        let state = NonNull::new(Box::into_raw(state).cast::<c_void>()).ok_or(Error::Allocation)?;
        let hook = match try_box(RawHook {
            min_node: MinNode {
                successor: core::ptr::null_mut(),
                predecessor: core::ptr::null_mut(),
            },
            entry: hook_trampoline::<F> as *mut c_void,
            sub_entry: core::ptr::null_mut(),
            data: state.as_ptr(),
        }) {
            Ok(hook) => hook,
            Err(error) => {
                unsafe { drop_state::<F>(state) };
                return Err(error);
            }
        };
        Ok(Self {
            hook,
            state,
            deactivate: deactivate::<F>,
            drop_state: drop_state::<F>,
        })
    }

    fn handle<'scope>(&self, scope: &'scope Scope) -> Hook<'scope> {
        Hook {
            raw: NonNull::from(self.hook.as_ref()),
            scope,
            _lifetime: PhantomData,
            _task_affine: PhantomData,
        }
    }
}

impl Drop for RetainedHook {
    fn drop(&mut self) {
        // SAFETY: this record uniquely owns the erased state and runs only
        // after every native object in the scope has been disposed.
        unsafe {
            (self.deactivate)(self.state);
            (self.drop_state)(self.state);
        }
    }
}

unsafe fn deactivate<F>(state: NonNull<c_void>) {
    let state = unsafe { state.cast::<HookState<F>>().as_ref() };
    state.active.set(false);
}

unsafe fn drop_state<F>(state: NonNull<c_void>) {
    unsafe { drop(Box::from_raw(state.cast::<HookState<F>>().as_ptr())) };
}

unsafe extern "C" fn hook_trampoline<F>(
    hook: *mut RawHook,
    _object: *mut c_void,
    message: *mut c_void,
) -> usize
where
    F: FnMut(HookCall) -> isize,
{
    let Some(hook) = NonNull::new(hook) else {
        return 0;
    };
    // SAFETY: retained hook storage stays live until all scope objects have
    // been disposed, and its data pointer was created for this monomorphized
    // trampoline.
    let state_pointer = unsafe { hook.as_ref().data.cast::<HookState<F>>() };
    let Some(state_pointer) = NonNull::new(state_pointer) else {
        return 0;
    };
    let state = unsafe { state_pointer.as_ref() };
    if !state.active.get() || state.busy.replace(true) {
        return 0;
    }
    let value = if message.is_null() {
        0
    } else {
        // MUIM_CallHook passes a pointer to its first STACKED IPTR parameter.
        unsafe { message.cast::<isize>().read() }
    };
    // SAFETY: `busy` guarantees one mutable callback invocation at a time.
    // The application panic handler is nonreturning, so a panic cannot unwind
    // across this native ABI boundary.
    let result = unsafe { (&mut *state.callback.get())(HookCall { value }) };
    state.busy.set(false);
    result as usize
}

impl Scope {
    /// Retains a non-reentrant callback until the complete object scope ends.
    ///
    /// Use the returned handle with [`Notification::call`](crate::Notification::call).
    /// The callback receives the notification's native trigger value and
    /// returns the pointer-sized result expected by `MUIM_CallHook`. A nested
    /// invocation of this same hook returns zero without calling the closure.
    /// The hook must be used only with objects from this scope.
    pub fn hook<'scope, F>(&'scope self, callback: F) -> Result<Hook<'scope>, Error>
    where
        F: FnMut(HookCall) -> isize + 'scope,
    {
        let retained = RetainedHook::new(callback)?;
        let mut hooks = self.hooks.try_borrow_mut().map_err(|_| Error::Busy)?;
        hooks.try_reserve(1).map_err(|_| Error::Allocation)?;
        hooks.push(retained);
        Ok(hooks
            .last()
            .expect("retained hook was just inserted")
            .handle(self))
    }
}
