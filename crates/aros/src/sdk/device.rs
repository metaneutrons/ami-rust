//! Exec devices and their I/O requests.
//!
//! A [`Device`] owns an opened Exec device together with the reply port that
//! all of its requests use. A [`Request`] owns its `IORequest` and a bounded
//! copy of its data, so the device never sees a Rust pointer and the
//! per-ABI layout of timer requests stays inside the native bridge.

use core::{marker::PhantomData, mem};

#[cfg(doc)]
use super::ErrorKind;
use super::{BytePath, Error, Operation, fresh_sys_error};
use crate::Context;
use aros_sys::{self as sys, SdkError};

/// Largest data area a [`Request`] can own, in bytes.
pub const MAX_REQUEST_DATA_BYTES: usize = sys::MAX_REQUEST_DATA_BYTES;

/// Shape of the `IORequest` a [`Request`] owns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum RequestKind {
    /// A standard request (`IOStdReq`) with a data area, length and offset.
    Standard = sys::IO_KIND_STANDARD,
    /// A timer request (`timerequest`) carrying a time value and no data.
    Timer = sys::IO_KIND_TIMER,
}

/// Result of a finished device request.
///
/// `device_error` is the device's `io_Error` (zero on success, negative
/// values are device-specific failures; `-2` is `IOERR_ABORTED`). It is not
/// an SDK failure: the request itself completed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoOutcome {
    /// The device's `io_Error` value.
    pub device_error: i8,
    /// The device's `io_Actual` value, or zero for a timer request.
    pub actual: u32,
}

impl IoOutcome {
    /// Returns `true` when the device reported no error.
    pub const fn is_ok(self) -> bool {
        self.device_error == 0
    }
}

/// An opened Exec device.
///
/// The handle is task-affine and borrows its creating [`Context`]. It owns the
/// device's reply port, so it uses one signal bit; see
/// [`signal_mask`](Self::signal_mask). Every [`Request`] borrows its device, so
/// the device cannot be closed while a request exists.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, Device};
/// let name = BytePath::new(b"timer.device")?;
/// // Unit 1 is UNIT_VBLANK.
/// let device = Device::open(context, &name, 1, 0)?;
/// device.close()?;
/// ```
pub struct Device<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Device<'ctx> {
    /// Opens the named device and unit.
    ///
    /// The bridge uses `name` synchronously. `unit` and `flags` are passed to
    /// `OpenDevice` unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`] if Exec cannot open the device, create its
    /// reply port or allocate memory (the `native` field carries the
    /// `OpenDevice` error), [`ErrorKind::Limit`] if the registry's token space
    /// is exhausted, or another class if the bridge rejects the context.
    pub fn open(
        context: &'ctx Context,
        name: &BytePath,
        unit: u32,
        flags: u32,
    ) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe {
            sys::sdk_device_open(context.key(), name.as_ptr(), unit, flags, &mut native_error)
        };
        if token == 0 {
            return Err(Error::native(Operation::DeviceOpen, native_error));
        }
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Returns the signal mask of this device's reply port.
    ///
    /// Pass it, or a combination with other masks, to a signal wait. A bit is
    /// set when a request has completed; use [`Request::check`] or
    /// [`Request::wait`] to identify and reclaim it.
    pub fn signal_mask(&self) -> u32 {
        unsafe { sys::sdk_device_signal_mask(self.context.key(), self.token) }
    }

    /// Closes the device and releases its reply port.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the native registry rejects the handle
    /// or requests of this device still exist.
    pub fn close(mut self) -> Result<(), Error> {
        let token = mem::replace(&mut self.token, 0);
        let mut native_error = fresh_sys_error();
        let result = unsafe { sys::sdk_device_close(self.context.key(), token, &mut native_error) };
        if result == 0 {
            Ok(())
        } else {
            Err(Error::native(Operation::DeviceClose, native_error))
        }
    }
}

impl Drop for Device<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_device_close(self.context.key(), token, &mut native_error) };
    }
}

/// An owned device I/O request.
///
/// A request is either idle or pending. Setup ([`prepare`](Self::prepare),
/// [`write_data`](Self::write_data), [`set_time`](Self::set_time)) and result
/// access ([`read_data`](Self::read_data), [`outcome`](Self::outcome),
/// [`time`](Self::time)) need an idle request. [`do_io`](Self::do_io) runs it
/// synchronously. [`send`](Self::send) makes it pending until
/// [`wait`](Self::wait) reclaims it; [`abort`](Self::abort) asks the device to
/// finish it early but the request stays pending until `wait`. Dropping a
/// pending request aborts it and waits for the device to return it, so a
/// dropped or forgotten request never leaves a message queued.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, Device, Request, RequestKind, wait_signals};
/// // Wait 50 ms on timer.device (UNIT_VBLANK) and use the reply port's signal.
/// const TR_ADDREQUEST: u16 = 9;
/// let name = BytePath::new(b"timer.device")?;
/// let device = Device::open(context, &name, 1, 0)?;
/// let mut request = Request::new(&device, RequestKind::Timer, 0)?;
/// request.prepare(TR_ADDREQUEST, 0, 0, 0)?;
/// request.set_time(0, 50_000)?;
/// request.send()?;
/// wait_signals(context, device.signal_mask())?;
/// assert!(request.wait()?.is_ok());
/// ```
pub struct Request<'dev, 'ctx> {
    device: &'dev Device<'ctx>,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'dev, 'ctx> Request<'dev, 'ctx> {
    /// Creates an idle request for `device`.
    ///
    /// `data_capacity` is the size of the data area in bytes and must be zero
    /// for [`RequestKind::Timer`].
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Input`] for a data area that is too large or given
    /// to a timer request, [`ErrorKind::Native`] if memory is exhausted, or
    /// another class if the bridge rejects the context or device.
    pub fn new(
        device: &'dev Device<'ctx>,
        kind: RequestKind,
        data_capacity: usize,
    ) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe {
            sys::sdk_io_new(
                device.context.key(),
                device.token,
                kind as i32,
                data_capacity,
                &mut native_error,
            )
        };
        if token == 0 {
            return Err(Error::native(Operation::RequestNew, native_error));
        }
        Ok(Self {
            device,
            token,
            _task_affine: PhantomData,
        })
    }

    fn context(&self) -> &'ctx Context {
        self.device.context
    }

    fn checked(&self, operation: Operation, result: i32, error: SdkError) -> Result<(), Error> {
        if result == 0 {
            Ok(())
        } else {
            Err(Error::native(operation, error))
        }
    }

    /// Sets the command, flags, data length and offset of an idle request.
    ///
    /// `length` must not exceed the data capacity, and for a timer request
    /// `length` and `offset` must be zero.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is pending,
    /// [`ErrorKind::Input`] for an out-of-range value, or an ownership error.
    pub fn prepare(
        &mut self,
        command: u16,
        flags: u8,
        length: usize,
        offset: u32,
    ) -> Result<(), Error> {
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_prepare(
                self.context().key(),
                self.token,
                u32::from(command),
                u32::from(flags),
                length,
                offset,
                &mut native_error,
            )
        };
        self.checked(Operation::RequestPrepare, result, native_error)
    }

    /// Copies `data` into the start of the data area of an idle standard
    /// request.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Input`] if `data` exceeds the capacity,
    /// [`ErrorKind::State`] for a pending or timer request, or an ownership
    /// error.
    pub fn write_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_write(
                self.context().key(),
                self.token,
                data.as_ptr(),
                data.len(),
                &mut native_error,
            )
        };
        self.checked(Operation::RequestWrite, result, native_error)
    }

    /// Copies the bytes the device transferred (`io_Actual`) from an idle
    /// standard request into `out` and returns their count.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Input`] if `out` is shorter than the transferred
    /// bytes, [`ErrorKind::State`] for a pending or timer request, or an
    /// ownership error.
    pub fn read_data(&self, out: &mut [u8]) -> Result<usize, Error> {
        let mut native_error = fresh_sys_error();
        let count = unsafe {
            sys::sdk_io_read(
                self.context().key(),
                self.token,
                out.as_mut_ptr(),
                out.len(),
                &mut native_error,
            )
        };
        if count < 0 {
            Err(Error::native(Operation::RequestRead, native_error))
        } else {
            Ok(count as usize)
        }
    }

    /// Sets the time value of an idle timer request.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Input`] if `micros` is a million or more,
    /// [`ErrorKind::State`] for a pending or non-timer request, or an
    /// ownership error.
    pub fn set_time(&mut self, seconds: u32, micros: u32) -> Result<(), Error> {
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_set_time(
                self.context().key(),
                self.token,
                seconds,
                micros,
                &mut native_error,
            )
        };
        self.checked(Operation::RequestTime, result, native_error)
    }

    /// Returns the time value of an idle timer request as seconds and
    /// microseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] for a pending or non-timer request, or an
    /// ownership error.
    pub fn time(&self) -> Result<(u32, u32), Error> {
        let (mut seconds, mut micros) = (0u32, 0u32);
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_time(
                self.context().key(),
                self.token,
                &mut seconds,
                &mut micros,
                &mut native_error,
            )
        };
        self.checked(Operation::RequestTime, result, native_error)
            .map(|()| (seconds, micros))
    }

    /// Returns the result of the last finished run of an idle request.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is pending, or an
    /// ownership error.
    pub fn outcome(&self) -> Result<IoOutcome, Error> {
        let (mut device_error, mut actual) = (0i32, 0u32);
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_result(
                self.context().key(),
                self.token,
                &mut device_error,
                &mut actual,
                &mut native_error,
            )
        };
        self.checked(Operation::RequestResult, result, native_error)
            .map(|()| IoOutcome {
                device_error: device_error as i8,
                actual,
            })
    }

    /// Runs the request synchronously with `DoIO` and returns its result.
    ///
    /// The call blocks the task until the device finishes.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is pending, or an
    /// ownership error. A device error is reported in the [`IoOutcome`], not
    /// as an `Err`.
    pub fn do_io(&mut self) -> Result<IoOutcome, Error> {
        let mut device_error = 0i32;
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_do(
                self.context().key(),
                self.token,
                &mut device_error,
                &mut native_error,
            )
        };
        self.checked(Operation::RequestDo, result, native_error)?;
        self.outcome().map(|outcome| IoOutcome {
            device_error: device_error as i8,
            ..outcome
        })
    }

    /// Sends the request with `SendIO`; it stays pending until
    /// [`wait`](Self::wait).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is already pending, or an
    /// ownership error.
    pub fn send(&mut self) -> Result<(), Error> {
        let mut native_error = fresh_sys_error();
        let result =
            unsafe { sys::sdk_io_send(self.context().key(), self.token, &mut native_error) };
        self.checked(Operation::RequestSend, result, native_error)
    }

    /// Returns `true` once a pending request has been finished by the device.
    ///
    /// The request stays pending until [`wait`](Self::wait) reclaims it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is not pending, or an
    /// ownership error.
    pub fn check(&self) -> Result<bool, Error> {
        let mut native_error = fresh_sys_error();
        let result =
            unsafe { sys::sdk_io_check(self.context().key(), self.token, &mut native_error) };
        match result {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::native(Operation::RequestCheck, native_error)),
        }
    }

    /// Waits for a pending request, makes it idle again and returns its
    /// result.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is not pending, or an
    /// ownership error.
    pub fn wait(&mut self) -> Result<IoOutcome, Error> {
        let mut device_error = 0i32;
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_io_wait(
                self.context().key(),
                self.token,
                &mut device_error,
                &mut native_error,
            )
        };
        self.checked(Operation::RequestWait, result, native_error)?;
        self.outcome().map(|outcome| IoOutcome {
            device_error: device_error as i8,
            ..outcome
        })
    }

    /// Asks the device to finish a pending request early with `AbortIO`.
    ///
    /// The request stays pending; call [`wait`](Self::wait) to reclaim it. An
    /// aborted request normally reports `IOERR_ABORTED` (`-2`).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the request is not pending, or an
    /// ownership error.
    pub fn abort(&mut self) -> Result<(), Error> {
        let mut native_error = fresh_sys_error();
        let result =
            unsafe { sys::sdk_io_abort(self.context().key(), self.token, &mut native_error) };
        self.checked(Operation::RequestAbort, result, native_error)
    }

    /// Releases the request, aborting and reclaiming it first if it is
    /// pending.
    ///
    /// # Errors
    ///
    /// Returns an error if the native registry rejects the handle.
    pub fn close(mut self) -> Result<(), Error> {
        let token = mem::replace(&mut self.token, 0);
        let mut native_error = fresh_sys_error();
        let result = unsafe { sys::sdk_io_drop(self.context().key(), token, &mut native_error) };
        self.checked(Operation::RequestDrop, result, native_error)
    }
}

impl Drop for Request<'_, '_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_io_drop(self.device.context.key(), token, &mut native_error) };
    }
}
