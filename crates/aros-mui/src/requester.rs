use crate::{
    Error, Object,
    classes::{Application, Window},
};
use core::ffi::CStr;

impl Object<'_, Application> {
    /// Opens a synchronous MUI requester without variadic formatting data.
    ///
    /// `message` must contain no `%` conversion. Format-driven requester
    /// argument arrays remain an explicit raw boundary because their native
    /// element widths depend on the conversion sequence. The optional Window
    /// must belong to the Application's scope. All strings are borrowed only
    /// for this call; MUI retains none of them after it returns.
    pub fn request(
        self,
        window: Option<Object<'_, Window>>,
        title: Option<&CStr>,
        gadgets: &CStr,
        message: &CStr,
    ) -> Result<i32, Error> {
        if message.to_bytes().contains(&b'%') {
            return Err(Error::InvalidFormat);
        }
        if let Some(window) = window
            && !core::ptr::eq(self.scope(), window.scope())
        {
            return Err(Error::WrongScope);
        }
        let window = window.map_or(core::ptr::null_mut(), |window| window.raw().as_ptr().cast());
        let title = title.map_or(core::ptr::null(), CStr::as_ptr);
        // SAFETY: all object handles belong to the live scope, every string is
        // NUL terminated, and the validated message requires no parameter
        // array. MUI_RequestA is synchronous and retains none of these borrows.
        let result = unsafe {
            aros_mui_sys::mui_request_a(
                self.scope().mui_base().as_ptr(),
                self.raw().as_ptr().cast(),
                window,
                0,
                title,
                gadgets.as_ptr(),
                message.as_ptr(),
                core::ptr::null_mut(),
            )
        };
        if result < 0 {
            Err(Error::NativeOperation)
        } else {
            Ok(result)
        }
    }
}
