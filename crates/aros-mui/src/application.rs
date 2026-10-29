use crate::{Error, Object, classes::Application};
use aros_mui_sys::{
    MUIM_Application_NewInput, MUIP_Application_NewInput, MUIV_Application_ReturnID_Quit, Stacked,
};

/// Decision returned by an Application event handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopControl {
    Continue,
    Exit,
}

/// Reason a safe Application event loop returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopExit {
    Quit,
    Handler(u32),
}

impl Object<'_, Application> {
    /// Runs the standard MUI Application input loop.
    ///
    /// MUI-owned signals are waited through the same task-affine AROS runtime
    /// context that owns this object scope. Return IDs other than `QUIT` are
    /// delivered to `handler`.
    pub fn run(self, mut handler: impl FnMut(u32) -> LoopControl) -> Result<LoopExit, Error> {
        loop {
            let mut signals = 0u32;
            let mut message = MUIP_Application_NewInput {
                MethodID: Stacked::new(MUIM_Application_NewInput),
                signal: Stacked::new(&mut signals),
            };
            // SAFETY: the typed Application and output word belong to this
            // live scope and the generated message has the pinned ABI layout.
            let raw = unsafe {
                aros_sys::do_method_a(
                    self.raw().as_ptr().cast(),
                    core::ptr::addr_of_mut!(message).cast(),
                )
            };
            let return_id = raw as u32;
            if return_id == MUIV_Application_ReturnID_Quit {
                return Ok(LoopExit::Quit);
            }
            if return_id != 0 && handler(return_id) == LoopControl::Exit {
                return Ok(LoopExit::Handler(return_id));
            }
            if signals == 0 {
                if return_id == 0 {
                    return Err(Error::NativeOperation);
                }
                continue;
            }
            aros::wait_signals(self.scope().context(), signals)?;
        }
    }
}
