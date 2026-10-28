//! Small, task-affine safe wrappers for the bounded AROS M1 SDK surface.
//!
//! This crate is intentionally no_std and allocation-free. Handles are opaque
//! registry tokens owned by the native bridge, never native pointers or freely
//! cloneable integers. Every resource borrows the runtime context that created
//! it and is confined to that application-task scope.
//! Message queue state is authoritative in the native registry; Rust handles
//! do not mirror it, so native port-drop cleanup cannot leave stale state.
//!
//! The source surface is specified by docs/m1-specification.md. These wrappers
//! are an implementation candidate; this crate does not claim native
//! qualification or compatibility beyond the pinned M1 inputs.

#![no_std]

use core::{ffi::c_void, marker::PhantomData, mem};

pub use aros_runtime::{AppStatus, Context};
use aros_sys::{self as sys, SdkError};

const MAX_PATH_BYTES: usize = sys::MAX_PATH_BYTES - 1;
const MAX_TRANSFER: usize = sys::MAX_FILE_TRANSFER_BYTES;
const MAX_MESSAGE_BYTES: usize = sys::MAX_MESSAGE_PAYLOAD_BYTES;

/// Stable error classes returned by safe SDK operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorKind {
    Native = 1,
    Input = 2,
    Limit = 3,
    Owner = 4,
    State = 5,
    Eof = 6,
    ZeroProgress = 7,
}

impl ErrorKind {
    fn from_native(value: i32) -> Self {
        match value {
            sys::ERROR_KIND_INPUT => Self::Input,
            sys::ERROR_KIND_LIMIT => Self::Limit,
            sys::ERROR_KIND_OWNER => Self::Owner,
            sys::ERROR_KIND_STATE => Self::State,
            sys::ERROR_KIND_EOF => Self::Eof,
            sys::ERROR_KIND_ZERO_PROGRESS => Self::ZeroProgress,
            _ => Self::Native,
        }
    }
}

/// Operation associated with an error, suitable for static diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    Path = 1,
    Stdout = 2,
    FileOpen = 3,
    FileClose = 4,
    FileRead = 5,
    FileWrite = 6,
    LibraryOpen = 7,
    LibraryClose = 8,
    SignalNew = 9,
    SignalDrop = 10,
    SignalPost = 11,
    SignalWait = 12,
    PortNew = 13,
    PortDrop = 14,
    PortSend = 15,
    PortReceive = 16,
    MessageNew = 17,
    MessageDrop = 18,
    MessageCopy = 19,
    MessageReply = 20,
    Callback = 21,
    Stderr = 22,
}

/// Allocation-free error record.
///
/// The native field preserves the numeric error supplied by the bridge.
/// Errors detected before entering the bridge use zero there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub native: i64,
    pub operation: Operation,
}

impl Error {
    const fn local(kind: ErrorKind, operation: Operation) -> Self {
        Self {
            kind,
            native: 0,
            operation,
        }
    }

    fn from_sys(operation: Operation, error: SdkError) -> Self {
        Self {
            kind: ErrorKind::from_native(error.kind),
            native: error.native,
            operation,
        }
    }

    fn native(operation: Operation, error: SdkError) -> Self {
        Self::from_sys(operation, error)
    }

    fn owner(operation: Operation) -> Self {
        Self::local(ErrorKind::Owner, operation)
    }

    fn state(operation: Operation) -> Self {
        Self::local(ErrorKind::State, operation)
    }

    fn limit(operation: Operation) -> Self {
        Self::local(ErrorKind::Limit, operation)
    }

    fn input(operation: Operation) -> Self {
        Self::local(ErrorKind::Input, operation)
    }

    /// Numeric representation of the stable error class.
    pub const fn kind_code(self) -> u8 {
        self.kind as u8
    }
}

fn fresh_sys_error() -> SdkError {
    SdkError { kind: 0, native: 0 }
}

fn require_context(owner: &Context, other: &Context, operation: Operation) -> Result<(), Error> {
    if owner.key() == other.key() {
        Ok(())
    } else {
        Err(Error::owner(operation))
    }
}

fn require_token(token: u64, operation: Operation) -> Result<(), Error> {
    if token == 0 {
        Err(Error::state(operation))
    } else {
        Ok(())
    }
}

/// A bounded native byte path, stored with its trailing NUL.
///
/// Paths are byte strings; UTF-8 is not required. The maximum payload is 127
/// bytes so the terminating NUL fits in the fixed 128-byte storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BytePath {
    bytes: [u8; 128],
    len: usize,
}

impl BytePath {
    /// Converts a byte path, rejecting embedded NUL and paths longer than 127
    /// bytes without allocating.
    pub fn new(path: &[u8]) -> Result<Self, Error> {
        if path.len() > MAX_PATH_BYTES {
            return Err(Error::limit(Operation::Path));
        }
        if path.iter().any(|byte| *byte == 0) {
            return Err(Error::input(Operation::Path));
        }

        let mut bytes = [0; 128];
        bytes[..path.len()].copy_from_slice(path);
        Ok(Self {
            bytes,
            len: path.len(),
        })
    }

    /// Number of path bytes, excluding the terminating NUL.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the path has no payload bytes.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
}

/// Open mode for an owned DOS file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum FileMode {
    ReadExisting = 0,
    CreateTruncate = 1,
    ReadWrite = 2,
}

/// Owned file handle tied to its creating application context.
pub struct File<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> File<'ctx> {
    /// Opens a file using an explicit bounded byte path and mode.
    pub fn open(context: &'ctx Context, path: &BytePath, mode: FileMode) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe {
            sys::sdk_file_open(context.key(), path.as_ptr(), mode as i32, &mut native_error)
        };
        if token == 0 {
            return Err(Error::native(Operation::FileOpen, native_error));
        }

        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Performs one bounded read. A single native transfer is at most 64 KiB.
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        self.transfer_read(buffer)
    }

    /// Performs one bounded write. A single native transfer is at most 64 KiB.
    pub fn write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        self.transfer_write(buffer)
    }

    /// Fills the buffer, handling short reads and reporting EOF before it is full.
    pub fn read_exact(&mut self, mut buffer: &mut [u8]) -> Result<(), Error> {
        while !buffer.is_empty() {
            let chunk_len = core::cmp::min(buffer.len(), MAX_TRANSFER);
            let read = self.transfer_read(&mut buffer[..chunk_len])?;
            if read == 0 {
                return Err(Error::local(ErrorKind::Eof, Operation::FileRead));
            }
            buffer = &mut buffer[read..];
        }
        Ok(())
    }

    /// Writes all bytes, handling short writes and refusing zero progress.
    pub fn write_all(&mut self, mut buffer: &[u8]) -> Result<(), Error> {
        while !buffer.is_empty() {
            let chunk_len = core::cmp::min(buffer.len(), MAX_TRANSFER);
            let written = self.transfer_write(&buffer[..chunk_len])?;
            if written == 0 {
                return Err(Error::local(ErrorKind::ZeroProgress, Operation::FileWrite));
            }
            buffer = &buffer[written..];
        }
        Ok(())
    }

    /// Closes the native file and consumes this safe handle even if close fails.
    pub fn close(mut self) -> Result<(), Error> {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return Err(Error::state(Operation::FileClose));
        }
        let mut native_error = fresh_sys_error();
        let result = unsafe { sys::sdk_file_close(self.context.key(), token, &mut native_error) };
        if result == 0 {
            Ok(())
        } else if result == -1 {
            Err(Error::native(Operation::FileClose, native_error))
        } else {
            Err(Error::state(Operation::FileClose))
        }
    }

    fn transfer_read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.len() > MAX_TRANSFER {
            return Err(Error::limit(Operation::FileRead));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        require_token(self.token, Operation::FileRead)?;

        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_file_io(
                self.context.key(),
                self.token,
                buffer.as_mut_ptr(),
                buffer.len(),
                0,
                &mut native_error,
            )
        };
        if result < 0 {
            return Err(Error::native(Operation::FileRead, native_error));
        }
        let count = result as usize;
        if count > buffer.len() {
            return Err(Error::state(Operation::FileRead));
        }
        Ok(count)
    }

    fn transfer_write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.len() > MAX_TRANSFER {
            return Err(Error::limit(Operation::FileWrite));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        require_token(self.token, Operation::FileWrite)?;

        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_file_io(
                self.context.key(),
                self.token,
                buffer.as_ptr() as *mut u8,
                buffer.len(),
                1,
                &mut native_error,
            )
        };
        if result < 0 {
            return Err(Error::native(Operation::FileWrite, native_error));
        }
        let count = result as usize;
        if count > buffer.len() {
            return Err(Error::state(Operation::FileWrite));
        }
        Ok(count)
    }
}

impl Drop for File<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_file_close(self.context.key(), token, &mut native_error) };
    }
}

/// Borrowed standard output. Dropping it never closes the native output handle.
pub struct Stdout<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Stdout<'ctx> {
    /// Borrows the context's standard output handle.
    pub fn new(context: &'ctx Context) -> Result<Self, Error> {
        let token = unsafe { sys::sdk_stdout(context.key()) };
        require_token(token, Operation::Stdout)?;
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Writes one bounded transfer to borrowed standard output.
    pub fn write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.len() > MAX_TRANSFER {
            return Err(Error::limit(Operation::Stdout));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_file_io(
                self.context.key(),
                self.token,
                buffer.as_ptr() as *mut u8,
                buffer.len(),
                1,
                &mut native_error,
            )
        };
        if result < 0 {
            return Err(Error::native(Operation::Stdout, native_error));
        }
        let count = result as usize;
        if count > buffer.len() {
            return Err(Error::state(Operation::Stdout));
        }
        Ok(count)
    }

    /// Writes the complete slice, handling short writes and zero progress.
    pub fn write_all(&mut self, mut buffer: &[u8]) -> Result<(), Error> {
        while !buffer.is_empty() {
            let len = core::cmp::min(buffer.len(), MAX_TRANSFER);
            let written = self.write(&buffer[..len])?;
            if written == 0 {
                return Err(Error::local(ErrorKind::ZeroProgress, Operation::Stdout));
            }
            buffer = &buffer[written..];
        }
        Ok(())
    }
}

/// Borrowed standard error for the application's DOS process.
///
/// Each transfer uses the process's currently selected error handle, falling
/// back to its output handle when the error handle is null. Dropping this
/// wrapper never closes either process-owned handle. Rust formatting may be
/// allocation-free; the selected DOS handler can allocate while writing.
pub struct Stderr<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Stderr<'ctx> {
    /// Borrows standard error; refuses an owner task that is not a DOS process.
    pub fn new(context: &'ctx Context) -> Result<Self, Error> {
        // The key is a live borrowed owner-task witness, not an OS pointer.
        let token = unsafe { sys::sdk_stderr(context.key()) };
        require_token(token, Operation::Stderr)?;
        Ok(Self { context, token, _task_affine: PhantomData })
    }

    /// Writes at most 64 KiB, preserving native errors and short transfers.
    pub fn write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.len() > MAX_TRANSFER {
            return Err(Error::limit(Operation::Stderr));
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut native_error = fresh_sys_error();
        // The bridge reads this slice synchronously for writing == 1 and
        // does not retain its pointer or close the borrowed native handle.
        let result = unsafe {
            sys::sdk_file_io(self.context.key(), self.token,
                buffer.as_ptr() as *mut u8, buffer.len(), 1, &mut native_error)
        };
        if result < 0 {
            return Err(Error::native(Operation::Stderr, native_error));
        }
        let count = result as usize;
        if count > buffer.len() {
            return Err(Error::state(Operation::Stderr));
        }
        Ok(count)
    }

    /// Completes bounded short writes and rejects zero progress.
    pub fn write_all(&mut self, mut buffer: &[u8]) -> Result<(), Error> {
        while !buffer.is_empty() {
            let len = core::cmp::min(buffer.len(), MAX_TRANSFER);
            let written = self.write(&buffer[..len])?;
            if written == 0 {
                return Err(Error::local(ErrorKind::ZeroProgress, Operation::Stderr));
            }
            buffer = &buffer[written..];
        }
        Ok(())
    }
}

/// Opens a native library with an explicit minimum version.
pub struct Library<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Library<'ctx> {
    pub fn open(
        context: &'ctx Context,
        name: &BytePath,
        minimum_version: u16,
    ) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe {
            sys::sdk_library_open(
                context.key(),
                name.as_ptr(),
                minimum_version,
                &mut native_error,
            )
        };
        if token == 0 {
            return Err(Error::native(Operation::LibraryOpen, native_error));
        }
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Closes the library and consumes this handle even when native close fails.
    pub fn close(mut self) -> Result<(), Error> {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return Err(Error::state(Operation::LibraryClose));
        }
        let mut native_error = fresh_sys_error();
        let result =
            unsafe { sys::sdk_library_close(self.context.key(), token, &mut native_error) };
        if result == 0 {
            Ok(())
        } else if result == -1 {
            Err(Error::native(Operation::LibraryClose, native_error))
        } else {
            Err(Error::state(Operation::LibraryClose))
        }
    }
}

impl Drop for Library<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_library_close(self.context.key(), token, &mut native_error) };
    }
}

/// An owned signal bit in the creating application's task.
pub struct Signal<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Signal<'ctx> {
    pub fn new(context: &'ctx Context) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe { sys::sdk_signal_new(context.key(), &mut native_error) };
        if token == 0 {
            return Err(Error::native(Operation::SignalNew, native_error));
        }
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    pub fn post(&self) -> Result<(), Error> {
        self.call(Operation::SignalPost, sys::sdk_signal_post)
    }

    pub fn wait(&self) -> Result<(), Error> {
        self.call(Operation::SignalWait, sys::sdk_signal_wait)
    }

    fn call(
        &self,
        operation: Operation,
        invoke: unsafe extern "C" fn(u64, u64, *mut SdkError) -> i32,
    ) -> Result<(), Error> {
        require_token(self.token, operation)?;
        let mut native_error = fresh_sys_error();
        // The wrapper passes a live key, its opaque token, and a writable
        // error record to the raw ABI call.
        let result = unsafe { invoke(self.context.key(), self.token, &mut native_error) };
        if result == 0 {
            Ok(())
        } else if result == -1 {
            Err(Error::native(operation, native_error))
        } else {
            Err(Error::state(operation))
        }
    }
}

impl Drop for Signal<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_signal_drop(self.context.key(), token, &mut native_error) };
    }
}

/// A private message port owned by the creating application task.
pub struct Port<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Port<'ctx> {
    pub fn new(context: &'ctx Context) -> Result<Self, Error> {
        let mut native_error = fresh_sys_error();
        let token = unsafe { sys::sdk_port_new(context.key(), &mut native_error) };
        if token == 0 {
            return Err(Error::native(Operation::PortNew, native_error));
        }
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Queues a locally owned message and records its reply route.
    pub fn send(&self, message: &mut Message<'ctx>, reply: &Port<'ctx>) -> Result<(), Error> {
        require_context(self.context, message.context, Operation::PortSend)?;
        require_context(self.context, reply.context, Operation::PortSend)?;
        require_token(self.token, Operation::PortSend)?;
        require_token(reply.token, Operation::PortSend)?;
        require_token(message.token, Operation::PortSend)?;

        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_port_put(
                self.context.key(),
                self.token,
                message.token,
                reply.token,
                &mut native_error,
            )
        };
        if result == 0 {
            Ok(())
        } else if result == -1 {
            Err(Error::native(Operation::PortSend, native_error))
        } else {
            Err(Error::state(Operation::PortSend))
        }
    }

    /// Checks whether this port has received the supplied owned message.
    ///
    /// The native registry validates the queue state and selected port.
    /// Returns Ok(false) when the message is not queued here.
    pub fn receive(&self, message: &mut Message<'ctx>) -> Result<bool, Error> {
        require_context(self.context, message.context, Operation::PortReceive)?;
        require_token(self.token, Operation::PortReceive)?;
        require_token(message.token, Operation::PortReceive)?;

        let mut native_error = fresh_sys_error();
        let result = unsafe {
            sys::sdk_port_receive(
                self.context.key(),
                self.token,
                message.token,
                &mut native_error,
            )
        };
        match result {
            1 => Ok(true),
            0 => Ok(false),
            -1 => Err(Error::native(Operation::PortReceive, native_error)),
            _ => Err(Error::state(Operation::PortReceive)),
        }
    }
}

impl Drop for Port<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_port_drop(self.context.key(), token, &mut native_error) };
    }
}

/// Stable, native-owned message storage with an at-most-256-byte payload.
pub struct Message<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Message<'ctx> {
    pub fn new(context: &'ctx Context, payload: &[u8]) -> Result<Self, Error> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(Error::limit(Operation::MessageNew));
        }
        let mut native_error = fresh_sys_error();
        let token = unsafe {
            sys::sdk_message_new(
                context.key(),
                payload.as_ptr(),
                payload.len(),
                &mut native_error,
            )
        };
        if token == 0 {
            return Err(Error::native(Operation::MessageNew, native_error));
        }
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Copies payload bytes into caller-provided storage; no payload reference escapes.
    pub fn copy_to(&self, output: &mut [u8]) -> Result<usize, Error> {
        require_token(self.token, Operation::MessageCopy)?;
        let mut native_error = fresh_sys_error();
        let copied = unsafe {
            sys::sdk_message_copy(
                self.context.key(),
                self.token,
                output.as_mut_ptr(),
                output.len(),
                &mut native_error,
            )
        };
        if copied < 0 {
            return Err(Error::native(Operation::MessageCopy, native_error));
        }
        let count = copied as usize;
        if count > output.len() {
            return Err(Error::state(Operation::MessageCopy));
        }
        Ok(count)
    }

    /// Replies to a message received from a local port.
    pub fn reply(&self) -> Result<(), Error> {
        require_token(self.token, Operation::MessageReply)?;
        let mut native_error = fresh_sys_error();
        let result =
            unsafe { sys::sdk_message_reply(self.context.key(), self.token, &mut native_error) };
        if result == 0 {
            Ok(())
        } else if result == -1 {
            Err(Error::native(Operation::MessageReply, native_error))
        } else {
            Err(Error::state(Operation::MessageReply))
        }
    }
}

impl Drop for Message<'_> {
    fn drop(&mut self) {
        let token = mem::replace(&mut self.token, 0);
        if token == 0 {
            return;
        }
        let mut native_error = fresh_sys_error();
        let _ = unsafe { sys::sdk_message_drop(self.context.key(), token, &mut native_error) };
    }
}

/// Performs one synchronous C-to-Rust callback using stack-borrowed state.
///
/// The native adapter must invoke the callback synchronously and must not retain
/// either the callback pointer or user-data pointer after returning.
pub fn call<F>(context: &Context, callback: &mut F, input: u64) -> Result<u64, Error>
where
    F: FnMut(u64) -> u64,
{
    let mut frame = CallbackFrame { callback };
    let mut output = 0u64;
    let mut native_error = fresh_sys_error();
    let result = unsafe {
        sys::sdk_callback(
            context.key(),
            callback_trampoline,
            (&mut frame as *mut CallbackFrame<'_>).cast(),
            input,
            &mut output,
            &mut native_error,
        )
    };
    if result == 0 {
        Ok(output)
    } else if result == -1 {
        Err(Error::native(Operation::Callback, native_error))
    } else {
        Err(Error::state(Operation::Callback))
    }
}

struct CallbackFrame<'a> {
    callback: &'a mut dyn FnMut(u64) -> u64,
}

unsafe extern "C" fn callback_trampoline(user_data: *mut c_void, input: u64) -> u64 {
    // sdk_callback is synchronous; user_data points to the live stack frame.
    let frame = unsafe { &mut *user_data.cast::<CallbackFrame<'_>>() };
    (frame.callback)(input)
}
