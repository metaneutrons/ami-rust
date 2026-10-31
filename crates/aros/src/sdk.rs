//! Bounded safe wrappers for the task-affine AROS application SDK.
//!
//! Every owned handle borrows its creating [`Context`] and is confined to that
//! application's owner task. Handles contain private registry tokens rather
//! than native pointers; the native registry remains authoritative for
//! ownership and message-queue state. Dropping a handle attempts to release its
//! resource, while native runtime cleanup also reclaims tracked resources
//! after the application frame returns.
//!
//! This module's operations do not allocate Rust memory. They return
//! allocation-free [`Error`] values for native failures, invalid input or
//! state, task-ownership failures, and resource-limit exhaustion. The global
//! allocator, when installed, is a separate runtime facility.

use core::{ffi::c_void, marker::PhantomData, mem};

use crate::Context;
use aros_sys::{self as sys, SdkError};

const MAX_PATH_BYTES: usize = sys::MAX_PATH_BYTES - 1;
const MAX_TRANSFER: usize = sys::MAX_FILE_TRANSFER_BYTES;
const MAX_MESSAGE_BYTES: usize = sys::MAX_MESSAGE_PAYLOAD_BYTES;

/// Stable error classes returned by safe SDK operations.
///
/// These variants classify local validation failures and native bridge
/// refusals. A native error's numeric detail is kept separately in the public
/// `native` field of [`Error`]; errors detected before entering the bridge use
/// zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorKind {
    /// The native operation failed; see the `native` field of [`Error`] for
    /// its numeric error value when the bridge supplied one.
    Native = 1,
    /// A caller-supplied value was invalid, such as a path containing NUL or
    /// a zero signal mask.
    Input = 2,
    /// A bounded transfer, handle registry, or other fixed resource limit was
    /// exceeded.
    Limit = 3,
    /// The operation used a context or handle that does not belong to the
    /// current owner task or context.
    Owner = 4,
    /// A handle or native object was in a state that does not allow the
    /// requested operation.
    State = 5,
    /// A read requiring a full buffer reached end-of-file first.
    Eof = 6,
    /// A write-all operation made no progress before completing its input.
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

/// Safe SDK operation associated with an [`Error`].
///
/// The numeric discriminants are stable identifiers for diagnostics and
/// qualification records; they are not native error codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Operation {
    /// Byte-path validation.
    Path = 1,
    /// Borrowing or writing standard output.
    Stdout = 2,
    /// Opening a DOS file.
    FileOpen = 3,
    /// Closing a DOS file.
    FileClose = 4,
    /// Reading a DOS file.
    FileRead = 5,
    /// Writing a DOS file.
    FileWrite = 6,
    /// Opening an optional native library.
    LibraryOpen = 7,
    /// Closing an optional native library.
    LibraryClose = 8,
    /// Allocating an owned signal bit.
    SignalNew = 9,
    /// Releasing an owned signal bit.
    SignalDrop = 10,
    /// Posting an owned signal.
    SignalPost = 11,
    /// Waiting for an owned signal.
    SignalWait = 12,
    /// Creating a private message port.
    PortNew = 13,
    /// Releasing a private message port.
    PortDrop = 14,
    /// Queueing an owned message on a private port.
    PortSend = 15,
    /// Receiving an owned message from a private port.
    PortReceive = 16,
    /// Creating native-owned message storage.
    MessageNew = 17,
    /// Releasing native-owned message storage.
    MessageDrop = 18,
    /// Copying message payload bytes to caller storage.
    MessageCopy = 19,
    /// Replying to a received message.
    MessageReply = 20,
    /// Calling a synchronous Rust callback through the native bridge.
    Callback = 21,
    /// Borrowing or writing standard error.
    Stderr = 22,
    /// Waiting on an externally supplied signal mask.
    SignalWaitMask = 23,
    /// Opening an Exec device.
    DeviceOpen = 24,
    /// Closing an Exec device.
    DeviceClose = 25,
    /// Creating a device I/O request.
    RequestNew = 26,
    /// Releasing a device I/O request.
    RequestDrop = 27,
    /// Setting up a device I/O request's command fields.
    RequestPrepare = 28,
    /// Copying bytes into a device I/O request's data.
    RequestWrite = 29,
    /// Copying bytes out of a device I/O request's data.
    RequestRead = 30,
    /// Reading or setting a timer request's time value.
    RequestTime = 31,
    /// Reading the result of a completed device I/O request.
    RequestResult = 32,
    /// Performing a synchronous device I/O request.
    RequestDo = 33,
    /// Sending an asynchronous device I/O request.
    RequestSend = 34,
    /// Checking an asynchronous device I/O request.
    RequestCheck = 35,
    /// Waiting for an asynchronous device I/O request.
    RequestWait = 36,
    /// Aborting an asynchronous device I/O request.
    RequestAbort = 37,
}

/// Allocation-free error returned by a safe SDK operation.
///
/// `kind` classifies the failure and `operation` identifies the affected API
/// operation. `native` preserves the numeric error supplied by the native
/// bridge; errors detected locally before a native call use zero. This record
/// is `Copy` and contains no dynamically allocated message.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, ErrorKind, File, FileMode};
/// let path = BytePath::new(b"RAM:missing.txt")?;
/// match File::open(context, &path, FileMode::ReadExisting) {
///     Ok(file) => file.close()?,
///     Err(error) if error.kind == ErrorKind::Native => {
///         // `native` carries the DOS error code; `operation` names the failing call.
///         context.diagnostic(b"open failed", error.native as u64);
///     }
///     Err(other) => return Err(other),
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    /// Stable class of the failure.
    pub kind: ErrorKind,
    /// Numeric error reported by the native bridge, or zero for local checks.
    pub native: i64,
    /// SDK operation that failed.
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

    /// Returns the numeric representation of [`Self::kind`].
    ///
    /// This is the `repr(u8)` discriminant, not the value in the `native` field.
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

/// A bounded native path stored as bytes with a trailing NUL.
///
/// Paths are byte strings and need not be UTF-8. A value contains at most 127
/// payload bytes in fixed 128-byte storage. Construction rejects embedded NUL
/// bytes and longer input, but does not check whether a path exists or
/// normalize its spelling. The path is copied into this value, so it does not
/// borrow the input slice.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, ErrorKind};
/// let path = BytePath::new(b"RAM:notes.txt")?;
/// assert_eq!(path.len(), 13);
/// // An embedded NUL byte is rejected before any native call.
/// assert_eq!(BytePath::new(b"bad\0path").unwrap_err().kind, ErrorKind::Input);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BytePath {
    bytes: [u8; 128],
    len: usize,
}

impl BytePath {
    /// Copies a byte path into bounded storage without allocating.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] when `path` exceeds 127 bytes, or
    /// [`ErrorKind::Input`] when it contains an embedded NUL byte.
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

    /// Returns the path length in bytes, excluding its terminating NUL.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the path has no payload bytes.
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
    /// Opens an existing file for reading; fails if it does not exist.
    ReadExisting = 0,
    /// Creates a file for writing, replacing the contents of an existing file.
    CreateTruncate = 1,
    /// Opens a file for reading and writing using DOS `MODE_READWRITE` mode.
    ReadWrite = 2,
}

/// Owned DOS file handle tied to its creating application context.
///
/// The handle is task-affine and cannot outlive the borrowed [`Context`].
/// Explicit [`close`](Self::close) reports native close errors; `Drop` closes
/// the handle on a best-effort basis. The number of open files is bounded by
/// available memory, not by a small fixed table. Every individual transfer is
/// bounded to 64 KiB.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, File, FileMode};
/// let path = BytePath::new(b"RAM:greeting.txt")?;
///
/// let mut file = File::open(context, &path, FileMode::CreateTruncate)?;
/// file.write_all(b"hello\n")?;
/// file.close()?; // close reports native errors; Drop closes silently
///
/// let mut file = File::open(context, &path, FileMode::ReadExisting)?;
/// let mut buffer = [0u8; 6];
/// file.read_exact(&mut buffer)?;
/// file.close()?;
/// assert_eq!(&buffer, b"hello\n");
/// ```
pub struct File<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> File<'ctx> {
    /// Opens a file using an explicit bounded byte path and mode.
    ///
    /// The native bridge uses the path synchronously and does not retain the
    /// `BytePath` reference.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`] if DOS cannot open the file,
    /// [`ErrorKind::Limit`] if the registry's token space is exhausted, or
    /// another class (including [`ErrorKind::Native`] for lack of memory) if
    /// the native bridge rejects the context or request.
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

    /// Performs at most one read of up to 64 KiB.
    ///
    /// Returns the number of bytes read, which may be less than the buffer
    /// length. A return value of zero indicates end-of-file; an empty buffer
    /// returns zero without a native call. A larger buffer is rejected rather
    /// than split into multiple transfers.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] for a buffer larger than 64 KiB, or
    /// [`ErrorKind::Native`] when DOS reports a read failure.
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        self.transfer_read(buffer)
    }

    /// Performs at most one write of up to 64 KiB.
    ///
    /// Returns the number of bytes written, which may be less than the input
    /// length. An empty input returns zero without a native call. A larger
    /// input is rejected rather than split into multiple transfers.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] for an input larger than 64 KiB, or
    /// [`ErrorKind::Native`] when DOS reports a write failure.
    pub fn write(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        self.transfer_write(buffer)
    }

    /// Fills the buffer, retrying short reads in transfers of at most 64 KiB.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Eof`] if the file ends before the buffer is full,
    /// or propagates a native read error. Bytes read before an error remain in
    /// the corresponding prefix of `buffer`, and the file position has
    /// advanced by those bytes.
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

    /// Writes all bytes, retrying short writes in transfers of at most 64 KiB.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::ZeroProgress`] if a write returns zero before all
    /// input is written, or propagates a native write error. Bytes written
    /// before an error are not rolled back.
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

    /// Closes the native file and consumes this handle, including on failure.
    ///
    /// The handle is no longer available to retry a failed close.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`] when DOS reports a close error, or
    /// [`ErrorKind::State`] if the native registry rejects the handle.
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

/// Borrowed standard output for the application task.
///
/// This wrapper borrows the context's process output; it does not own or close
/// that handle. It is task-affine, and each native transfer is limited to 64
/// KiB. Use [`write_all`](Self::write_all) when short writes must be retried.
///
/// # Examples
///
/// ```ignore
/// # use aros::Stdout;
/// let mut out = Stdout::new(context)?;
/// out.write_all(b"hello from AROS\n")?;
/// ```
pub struct Stdout<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Stdout<'ctx> {
    /// Borrows the context's standard output stream.
    ///
    /// The wrapper does not take ownership of the native output handle.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the native runtime does not accept the
    /// supplied context.
    pub fn new(context: &'ctx Context) -> Result<Self, Error> {
        let token = unsafe { sys::sdk_stdout(context.key()) };
        require_token(token, Operation::Stdout)?;
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Performs at most one write of up to 64 KiB to standard output.
    ///
    /// Returns the number of bytes written, which may be less than the input
    /// length. An empty input returns zero without a native call. The native
    /// output handle remains owned by the application process.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] for input larger than 64 KiB,
    /// [`ErrorKind::Native`] when DOS reports a write failure, or
    /// [`ErrorKind::State`] if the stream cannot be used.
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

    /// Writes the complete slice, retrying short writes in 64 KiB chunks.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::ZeroProgress`] if a write returns zero before all
    /// input is written, or propagates a native error. Bytes already written
    /// are not rolled back.
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
/// The native bridge requires the owner task to be a DOS process. For each
/// write it uses the process's current error handle, falling back to its
/// output handle when the error handle is null. Dropping this wrapper never
/// closes either process-owned handle. Each transfer is limited to 64 KiB.
/// The DOS handler may allocate while writing, even when the Rust caller uses
/// allocation-free formatting.
///
/// # Examples
///
/// ```ignore
/// # use aros::Stderr;
/// let mut err = Stderr::new(context)?;
/// err.write_all(b"warning: input file is empty\n")?;
/// ```
pub struct Stderr<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Stderr<'ctx> {
    /// Borrows standard error from a DOS process.
    ///
    /// The native handles remain owned by the process and are resolved again
    /// for each write.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the context is invalid or its owner task
    /// is not a DOS process.
    pub fn new(context: &'ctx Context) -> Result<Self, Error> {
        // The key is a live borrowed owner-task witness, not an OS pointer.
        let token = unsafe { sys::sdk_stderr(context.key()) };
        require_token(token, Operation::Stderr)?;
        Ok(Self {
            context,
            token,
            _task_affine: PhantomData,
        })
    }

    /// Performs at most one write of up to 64 KiB to standard error.
    ///
    /// Returns the number of bytes written, which may be less than the input
    /// length. An empty input returns zero without a native call. The native
    /// process selects its current error handle for this call, falling back to
    /// its output handle when needed.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] for input larger than 64 KiB,
    /// [`ErrorKind::Native`] when DOS reports a write failure or no error/
    /// output handle is available, or [`ErrorKind::State`] for an invalid
    /// stream token.
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
            return Err(Error::native(Operation::Stderr, native_error));
        }
        let count = result as usize;
        if count > buffer.len() {
            return Err(Error::state(Operation::Stderr));
        }
        Ok(count)
    }

    /// Writes the complete slice, retrying short writes in 64 KiB chunks.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::ZeroProgress`] if a write returns zero before all
    /// input is written, or propagates a native error. Bytes already written
    /// are not rolled back.
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

/// Owned reference to an optional native library.
///
/// The handle borrows its creating [`Context`] and is confined to that
/// application task. Opening requires an explicit minimum library version;
/// the number of open library handles is bounded by available memory. `Drop`
/// closes the library on a best-effort basis; use [`close`](Self::close) to
/// observe a bridge refusal while explicitly releasing it.
///
/// # Examples
///
/// ```ignore
/// # use aros::{BytePath, Library};
/// let name = BytePath::new(b"utility.library")?;
/// let library = Library::open(context, &name, 36)?;
/// // Dropping would release the library too; close() lets you observe a failure.
/// library.close()?;
/// ```
pub struct Library<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Library<'ctx> {
    /// Opens `name` if the native library meets `minimum_version`.
    ///
    /// The name is a bounded byte path and is read synchronously; the bridge
    /// does not retain the `BytePath` reference.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`] if the library is unavailable or too old,
    /// [`ErrorKind::Limit`] when the registry's token space is exhausted, or
    /// another class if the bridge rejects the context or request.
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

    /// Returns the native library base for a library-specific raw ABI wrapper.
    ///
    /// The pointer is borrowed from this handle and is valid only while `self`
    /// remains open. Safe consumers should prefer a focused wrapper crate.
    ///
    /// # Safety
    ///
    /// The caller must use the pointer only with the matching library's ABI,
    /// on the owner task, and before this `Library` is dropped or closed. Do
    /// not retain it beyond `self`, close the library directly, or pass the
    /// pointer to an API for a different library.
    ///
    /// # Returns
    ///
    /// `Some(base)` if the native registry still recognizes this live library
    /// handle; otherwise `None`.
    pub unsafe fn raw_base(&self) -> Option<*mut c_void> {
        // SAFETY: this handle remains owned and the native registry validates
        // its context, task, token kind, slot and live library pointer.
        let base = unsafe { sys::sdk_library_base(self.context.key(), self.token) };
        (!base.is_null()).then_some(base)
    }

    /// Closes the library and consumes this handle, including on failure.
    ///
    /// The handle cannot be retried after a failed close.
    ///
    /// # Errors
    ///
    /// Returns an ownership or state error if the native registry rejects the
    /// handle or context.
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

/// An owned Exec signal bit in the creating application's task.
///
/// The handle is task-affine and borrows its creating [`Context`]. Exec
/// allocates signals from one 32-bit task mask, so only the bits Exec leaves
/// free are available, including the bits used by private message ports.
/// Dropping the handle clears and releases its bit.
///
/// # Examples
///
/// ```ignore
/// # use aros::Signal;
/// let signal = Signal::new(context)?;
/// signal.post()?;
/// // The bit was posted first, so this wait finds it already set.
/// signal.wait()?;
/// ```
pub struct Signal<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Signal<'ctx> {
    /// Allocates a signal bit for the application task.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`] when Exec has no free signal bit,
    /// [`ErrorKind::Limit`] if the SDK's 32-slot table is full, or another
    /// class if the native bridge rejects the context.
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

    /// Posts this signal to the application's owner task.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] for an invalid signal state or an
    /// ownership/native error if the bridge rejects the operation.
    pub fn post(&self) -> Result<(), Error> {
        self.call(Operation::SignalPost, sys::sdk_signal_post)
    }

    /// Blocks the owner task until this signal bit is set.
    ///
    /// The call can block indefinitely if no task posts the bit. Waiting does
    /// not release the signal bit; it remains owned by this handle.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] for an invalid signal state or an
    /// ownership/native error if the bridge rejects the operation.
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

/// Private message port owned by the creating application task.
///
/// The handle is task-affine and borrows its creating [`Context`]. Private
/// ports are local application resources, not handles to arbitrary or foreign
/// ports; each one uses a signal bit. Dropping a port asks the native
/// registry to detach queued messages and retire their local queue state.
///
/// # Examples
///
/// ```ignore
/// # use aros::{Message, Port};
/// let port = Port::new(context)?;
/// let reply = Port::new(context)?;
/// let mut message = Message::new(context, b"ping")?;
///
/// port.send(&mut message, &reply)?;
/// assert!(port.receive(&mut message)?);
///
/// let mut payload = [0u8; 4];
/// let length = message.copy_to(&mut payload)?;
/// assert_eq!(&payload[..length], b"ping");
/// message.reply()?;
/// ```
pub struct Port<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Port<'ctx> {
    /// Creates a private message port for the owner task.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Native`] if Exec cannot create the port or has no
    /// free signal bit, [`ErrorKind::Limit`] if the registry's token space or
    /// the 32-slot signal table is exhausted, or another class if the native
    /// bridge rejects the context.
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

    /// Queues `message` on this port and records `reply` as its reply route.
    ///
    /// The message and both ports must belong to the same live context. A
    /// message can be queued only while it is in its idle state; queue state is
    /// tracked by the native registry.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Owner`] for a context mismatch,
    /// [`ErrorKind::State`] if a handle is invalid or the message is already
    /// queued/awaiting a reply, or a native error if the bridge refuses the
    /// operation.
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

    /// Receives the supplied message if it is at the head of this port's queue.
    ///
    /// A successful receive removes that message from the queue and makes its
    /// payload available to [`Message::copy_to`]. The method does not search
    /// past another message at the queue head.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Owner`] for a context mismatch or
    /// [`ErrorKind::State`] if the supplied message is not the queue head or
    /// is otherwise not receivable.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if this call dequeued `message`; `Ok(false)` if the port's
    /// queue is empty.
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

/// Native-owned message storage with a payload of at most 256 bytes.
///
/// The handle is task-affine and borrows its creating [`Context`]. The native
/// registry owns a stable message record and payload copy, so the input slice
/// passed to [`Message::new`] need not remain alive. The number of owned
/// messages is bounded by available memory. Dropping this handle releases the record and detaches
/// it if it is queued.
pub struct Message<'ctx> {
    context: &'ctx Context,
    token: u64,
    _task_affine: PhantomData<*mut ()>,
}

impl<'ctx> Message<'ctx> {
    /// Copies `payload` into a native-owned message record.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Limit`] if the payload exceeds 256 bytes or the
    /// registry's token space is exhausted, or another class if the bridge
    /// rejects the context or request.
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

    /// Copies the complete payload into caller-provided storage.
    ///
    /// Returns the payload length. The native message remains owned by this
    /// handle, and no borrowed payload reference escapes the call. The output
    /// must be large enough for the entire payload; this method does not
    /// truncate it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Input`] if `output` is too small and
    /// [`ErrorKind::State`] if the message is still queued or its handle is
    /// invalid. Native and ownership failures are also reported.
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

    /// Replies to this message after it has been received from a local port.
    ///
    /// The native registry queues it on the reply port recorded by
    /// [`Port::send`]. The message must have been received and the reply port
    /// must still be live.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::State`] if the message is not in a receivable
    /// reply state or its reply port is no longer valid, or an ownership/native
    /// error if the bridge refuses the operation.
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

/// Invokes a Rust callback synchronously through the native bridge.
///
/// The bridge calls `callback` before this function returns and does not retain
/// its pointer or the stack-borrowed callback frame. The callback may mutate
/// its captured state through `&mut F`; that state remains borrowed only for
/// this call. At most one callback may be active, so reentrant callback calls
/// are refused. A panic cannot unwind through C: when installed with
/// [`crate::entry!`], the application's panic handler terminates through the
/// native fatal path.
///
/// # Errors
///
/// Returns [`ErrorKind::State`] when the bridge rejects a nested or invalid
/// callback state, or an ownership/native error if the context is not accepted.
///
/// # Examples
///
/// ```ignore
/// # use aros::call;
/// let mut seen = 0u64;
/// let doubled = call(
///     context,
///     &mut |input| {
///         seen = input;
///         input * 2
///     },
///     21,
/// )?;
/// assert_eq!((seen, doubled), (21, 42));
/// ```
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

/// Waits for one or more signals from an externally owned native subsystem.
///
/// This is the bounded counterpart to Exec `Wait` for event loops whose signal
/// mask comes from a live library object rather than an SDK-owned [`Signal`].
/// The call blocks the owner task until a requested bit is set and returns the
/// mask reported by Exec. It does not allocate or transfer ownership of the
/// supplied bits.
///
/// # Errors
///
/// Returns [`ErrorKind::Input`] for a zero mask, or an ownership/native error
/// if the native bridge rejects the context or wait.
pub fn wait_signals(context: &Context, mask: u32) -> Result<u32, Error> {
    if mask == 0 {
        return Err(Error::input(Operation::SignalWaitMask));
    }
    let mut received = 0u32;
    let mut native_error = fresh_sys_error();
    let result =
        unsafe { sys::sdk_signal_wait_mask(context.key(), mask, &mut received, &mut native_error) };
    if result == 0 {
        Ok(received)
    } else if result == -1 {
        Err(Error::native(Operation::SignalWaitMask, native_error))
    } else {
        Err(Error::state(Operation::SignalWaitMask))
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

mod device;
pub use device::*;
