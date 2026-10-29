#![no_std]
#![allow(non_camel_case_types)]

//! Raw bindings for the native bridge and selected x86-64 AROS library APIs.
//!
//! The selected SDK headers are the source of the ABI contracts translated
//! here. Generated library calls support ABI-v1 and ABI-v11 through separate
//! backends. Their copyrights and licences remain with the AROS Development
//! Team; these declarations do not relicense the SDK.

use core::ffi::{c_char, c_int, c_void};
use core::mem::{align_of, offset_of, size_of};

pub type APTR = *mut c_void;
/// `AROS_FAST_BPTR` selects `APTR` for BPTR in the pinned x86-64 SDK.
pub type BPTR = APTR;
pub type BOOL = i16;
pub type BYTE = i8;
pub type IPTR = usize;
pub type LONG = i32;
pub type SIPTR = isize;
pub type Tag = u32;
pub type UBYTE = u8;
pub type ULONG = u32;

pub const TAG_DONE: u32 = 0;
pub const TAG_IGNORE: u32 = 1;
pub const TAG_MORE: u32 = 2;
pub const TAG_SKIP: u32 = 3;
pub const TAG_USER: u32 = 1 << 31;

/// AROS `struct TagItem` for the selected 64-bit ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagItem {
    pub tag: u32,
    pub data: usize,
}

impl TagItem {
    pub const fn new(tag: u32, data: usize) -> Self {
        Self { tag, data }
    }

    pub const fn done() -> Self {
        Self::new(TAG_DONE, 0)
    }
}

/// Opaque Intuition window handle.
pub type Window = c_void;
/// Opaque Intuition window descriptor.
pub type NewWindow = c_void;
/// Opaque BOOPSI object storage addressed after its private prefix.
pub type Object = c_void;
/// Raw BOOPSI message pointer.
pub type Msg = *mut c_void;

/// Prefix shared by AROS `MinNode` and the BOOPSI object header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MinNode {
    pub successor: *mut MinNode,
    pub predecessor: *mut MinNode,
}

/// AROS callback hook layout used by BOOPSI class dispatchers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Hook {
    pub min_node: MinNode,
    pub entry: *mut c_void,
    pub sub_entry: *mut c_void,
    pub data: *mut c_void,
}

/// Read-only AROS BOOPSI class layout required by the three `*MethodA`
/// dispatch adapters.
#[repr(C)]
#[derive(Debug)]
pub struct IClass {
    pub dispatcher: Hook,
    pub reserved: u32,
    pub super_class: *mut IClass,
    pub id: *const c_char,
    pub instance_offset: u16,
    pub instance_size: u16,
    pub user_data: usize,
    pub subclass_count: u32,
    pub object_count: u32,
    pub flags: u32,
    pub object_size: u32,
    pub memory_pool: *mut c_void,
}

type Dispatcher = unsafe extern "C" fn(*mut IClass, *mut Object, Msg) -> usize;

/// Layout values for the BOOPSI records read by the raw dispatch adapters.
#[doc(hidden)]
pub const BOOPSI_LAYOUT_VALUES: [usize; 24] = [
    core::mem::size_of::<MinNode>(),
    core::mem::align_of::<MinNode>(),
    core::mem::offset_of!(MinNode, successor),
    core::mem::offset_of!(MinNode, predecessor),
    core::mem::size_of::<Hook>(),
    core::mem::align_of::<Hook>(),
    core::mem::offset_of!(Hook, min_node),
    core::mem::offset_of!(Hook, entry),
    core::mem::offset_of!(Hook, sub_entry),
    core::mem::offset_of!(Hook, data),
    core::mem::size_of::<IClass>(),
    core::mem::align_of::<IClass>(),
    core::mem::offset_of!(IClass, dispatcher),
    core::mem::offset_of!(IClass, reserved),
    core::mem::offset_of!(IClass, super_class),
    core::mem::offset_of!(IClass, id),
    core::mem::offset_of!(IClass, instance_offset),
    core::mem::offset_of!(IClass, instance_size),
    core::mem::offset_of!(IClass, user_data),
    core::mem::offset_of!(IClass, subclass_count),
    core::mem::offset_of!(IClass, object_count),
    core::mem::offset_of!(IClass, flags),
    core::mem::offset_of!(IClass, object_size),
    core::mem::offset_of!(IClass, memory_pool),
];

unsafe fn dispatch(class: *mut IClass, object: *mut Object, message: Msg) -> usize {
    if class.is_null() || object.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees a live class; `Hook` is the first member
    // of `IClass`, exactly as required by AROS `CALLHOOKPKT`.
    let entry = unsafe { (*class).dispatcher.entry };
    if entry.is_null() {
        return 0;
    }
    // SAFETY: the AROS x86-64 BOOPSI dispatcher contract is an ordinary C
    // call with class, object and message arguments and an IPTR result.
    let dispatcher: Dispatcher = unsafe { core::mem::transmute(entry) };
    // SAFETY: validity of the native class, object and message is the caller's
    // responsibility.
    unsafe { dispatcher(class, object, message) }
}

/// Raw AROS `DoMethodA` adapter without a Rust variadic ABI.
///
/// # Safety
///
/// `object` must point to a live BOOPSI object whose native private prefix is
/// present immediately before it, and `message` must match its method ID.
pub unsafe fn do_method_a(object: *mut Object, message: Msg) -> usize {
    if object.is_null() {
        return 0;
    }
    // AROS guarantees that `o_Class` stays immediately before the public
    // object pointer even if the private prefix grows or gains stricter
    // alignment. Reading that final pointer avoids depending on the private
    // prefix size.
    let class = unsafe { object.cast::<*mut IClass>().sub(1).read() };
    // SAFETY: forwarded from the public raw adapter contract.
    unsafe { dispatch(class, object, message) }
}

/// Raw AROS `DoSuperMethodA` adapter without a Rust variadic ABI.
///
/// # Safety
///
/// `class`, `object` and `message` must form a valid BOOPSI dispatcher call.
pub unsafe fn do_super_method_a(class: *mut IClass, object: *mut Object, message: Msg) -> usize {
    if class.is_null() || object.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees a live class layout.
    let super_class = unsafe { (*class).super_class };
    // SAFETY: forwarded from the public raw adapter contract.
    unsafe { dispatch(super_class, object, message) }
}

/// Raw AROS `CoerceMethodA` adapter without a Rust variadic ABI.
///
/// # Safety
///
/// `class`, `object` and `message` must form a valid BOOPSI dispatcher call.
pub unsafe fn coerce_method_a(class: *mut IClass, object: *mut Object, message: Msg) -> usize {
    // SAFETY: forwarded from the public raw adapter contract.
    unsafe { dispatch(class, object, message) }
}

#[cfg(all(target_os = "aros", not(target_arch = "x86_64")))]
compile_error!("aros-sys currently implements only the x86-64 AROS vector ABI");
#[cfg(all(
    target_os = "aros",
    not(any(target_abi = "", target_abi = "abi1", target_abi = "abi11"))
))]
compile_error!("aros-sys requires AROS ABI-v1 or ABI-v11");

mod generated;
pub use generated::{dos, exec, intuition, utility};

/// The C bridge's error record (`native` holds the immediately captured
/// native error, such as DOS `IoErr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SdkError {
    pub kind: i32,
    pub native: i64,
}

/// Resource counters returned by the native bridge. Every member is C
/// `size_t`, which is 64-bit for this target.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SdkStats {
    pub blocks: usize,
    pub backing_charge: usize,
    pub peak_charge: usize,
    pub files: usize,
    pub libraries: usize,
    pub ports: usize,
    pub signals: usize,
    pub messages: usize,
    pub refusals: usize,
}

// These layouts follow AROS `exec/nodes.h`, `exec/lists.h`,
// `exec/libraries.h`, `exec/ports.h`, `dos/dos.h`, and
// `aros/types/spinlock_s.h`. The selected public `__AROSPLATFORM_SMP__`
// definition embeds spinlock_t as padding because `__AROSEXEC_SMP__` is not
// enabled; it does not describe an active Exec SMP lock.

#[repr(C)]
pub struct Node {
    pub succ: *mut Node,
    pub pred: *mut Node,
    pub kind: u8,
    pub priority: i8,
    pub name: *mut u8,
}

#[repr(C)]
pub struct List {
    pub head: *mut Node,
    pub tail: *mut Node,
    pub tail_pred: *mut Node,
    pub kind: u8,
    pub _pad: u8,
}

/// The public spinlock_t storage included by the selected SMP-layout define.
/// It is padding in the selected non-Exec-SMP ABI profile.
#[repr(C)]
pub struct SpinLockPadding {
    pub lock_word: u32,
    pub owner: *mut c_void,
    pub isolation: [u8; 112],
}

#[repr(C)]
pub struct Library {
    pub node: Node,
    pub flags: u8,
    pub _pad: u8,
    pub negative_size: u16,
    pub positive_size: u16,
    pub version: u16,
    pub revision: u16,
    pub id_string: *mut u8,
    pub checksum: ULONG,
    pub open_count: u16,
    pub spinlock_padding: SpinLockPadding,
}

#[repr(C)]
pub struct Message {
    pub node: Node,
    pub reply_port: *mut MsgPort,
    pub length: u16,
}

#[repr(C)]
pub struct MsgPort {
    pub node: Node,
    pub flags: u8,
    pub signal_bit: u8,
    pub signal_task: APTR,
    pub message_list: List,
    pub spinlock_padding: SpinLockPadding,
}

#[repr(C)]
pub struct DateStamp {
    pub days: LONG,
    pub minutes: LONG,
    pub ticks: LONG,
}

/// The pinned M0 C profile leaves `__DOS64` undefined, so `dos/dos.h`
/// selects `FileInfoBlock32` and its LONG-sized file and block counts.
#[repr(C)]
pub struct FileInfoBlock {
    pub disk_key: IPTR,
    pub directory_entry_type: LONG,
    pub file_name: [u8; 108],
    pub protection: LONG,
    pub entry_type: LONG,
    pub size: LONG,
    pub num_blocks: LONG,
    pub date: DateStamp,
    pub comment: [u8; 80],
    pub owner_uid: u16,
    pub owner_gid: u16,
    pub reserved: [u8; 32],
}

// Bounds implemented by the safe SDK layer. Paths include the trailing NUL;
// argument bytes are the combined encoded size, including any terminators.
pub const MAX_ARGUMENTS: usize = 32;
pub const MAX_ARGUMENT_BYTES: usize = 4096;
pub const MAX_PATH_BYTES: usize = 128;
pub const MIN_ALLOCATION_ALIGNMENT: usize = 1;
pub const MAX_ALLOCATION_ALIGNMENT: usize = 4096;
pub const MAX_FILE_TRANSFER_BYTES: usize = 64 * 1024;
pub const MAX_OWNED_FILES: usize = 16;
pub const MAX_OPTIONAL_LIBRARIES: usize = 4;
pub const MAX_PRIVATE_PORTS: usize = 2;
pub const MAX_OWNED_SIGNALS: usize = 4;
pub const MAX_OWNED_MESSAGES: usize = 8;
pub const MAX_MESSAGE_PAYLOAD_BYTES: usize = 256;
pub const MAX_ACTIVE_CALLBACKS: usize = 1;
pub const MAX_DIAGNOSTIC_BYTES: usize = 256;

pub const SDK_FILE_READ_EXISTING: i32 = 0;
pub const SDK_FILE_CREATE_TRUNCATE: i32 = 1;
pub const SDK_FILE_READ_WRITE: i32 = 2;

pub const ERROR_KIND_NATIVE: i32 = 1;
pub const ERROR_KIND_INPUT: i32 = 2;
pub const ERROR_KIND_LIMIT: i32 = 3;
pub const ERROR_KIND_OWNER: i32 = 4;
pub const ERROR_KIND_STATE: i32 = 5;
pub const ERROR_KIND_EOF: i32 = 6;
pub const ERROR_KIND_ZERO_PROGRESS: i32 = 7;

/// Layout oracle values in the exact order of the M0 C layout table:
/// Node, Library, Message, List, MsgPort, FileInfoBlock, scalar ABI types,
/// then the selected spinlock_t storage. No native call or allocation occurs.
pub const ABI_LAYOUT_VALUE_COUNT: usize = 81;

const fn layout_value(value: usize) -> u64 {
    value as u64
}

pub const fn layout_values() -> [u64; ABI_LAYOUT_VALUE_COUNT] {
    [
        layout_value(size_of::<Node>()),
        layout_value(align_of::<Node>()),
        layout_value(offset_of!(Node, succ)),
        layout_value(offset_of!(Node, pred)),
        layout_value(offset_of!(Node, kind)),
        layout_value(offset_of!(Node, priority)),
        layout_value(offset_of!(Node, name)),
        layout_value(size_of::<Library>()),
        layout_value(align_of::<Library>()),
        layout_value(offset_of!(Library, node)),
        layout_value(offset_of!(Library, flags)),
        layout_value(offset_of!(Library, _pad)),
        layout_value(offset_of!(Library, negative_size)),
        layout_value(offset_of!(Library, positive_size)),
        layout_value(offset_of!(Library, version)),
        layout_value(offset_of!(Library, revision)),
        layout_value(offset_of!(Library, id_string)),
        layout_value(offset_of!(Library, checksum)),
        layout_value(offset_of!(Library, open_count)),
        layout_value(offset_of!(Library, spinlock_padding)),
        layout_value(size_of::<Message>()),
        layout_value(align_of::<Message>()),
        layout_value(offset_of!(Message, node)),
        layout_value(offset_of!(Message, reply_port)),
        layout_value(offset_of!(Message, length)),
        layout_value(size_of::<List>()),
        layout_value(align_of::<List>()),
        layout_value(offset_of!(List, head)),
        layout_value(offset_of!(List, tail)),
        layout_value(offset_of!(List, tail_pred)),
        layout_value(offset_of!(List, kind)),
        layout_value(offset_of!(List, _pad)),
        layout_value(size_of::<MsgPort>()),
        layout_value(align_of::<MsgPort>()),
        layout_value(offset_of!(MsgPort, node)),
        layout_value(offset_of!(MsgPort, flags)),
        layout_value(offset_of!(MsgPort, signal_bit)),
        layout_value(offset_of!(MsgPort, signal_task)),
        layout_value(offset_of!(MsgPort, message_list)),
        layout_value(offset_of!(MsgPort, spinlock_padding)),
        layout_value(size_of::<FileInfoBlock>()),
        layout_value(align_of::<FileInfoBlock>()),
        layout_value(offset_of!(FileInfoBlock, disk_key)),
        layout_value(offset_of!(FileInfoBlock, directory_entry_type)),
        layout_value(offset_of!(FileInfoBlock, file_name)),
        layout_value(offset_of!(FileInfoBlock, protection)),
        layout_value(offset_of!(FileInfoBlock, entry_type)),
        layout_value(offset_of!(FileInfoBlock, size)),
        layout_value(offset_of!(FileInfoBlock, num_blocks)),
        layout_value(offset_of!(FileInfoBlock, date)),
        layout_value(offset_of!(FileInfoBlock, comment)),
        layout_value(offset_of!(FileInfoBlock, owner_uid)),
        layout_value(offset_of!(FileInfoBlock, owner_gid)),
        layout_value(offset_of!(FileInfoBlock, reserved)),
        layout_value(size_of::<IPTR>()),
        layout_value(align_of::<IPTR>()),
        layout_value(size_of::<BPTR>()),
        layout_value(align_of::<BPTR>()),
        layout_value(size_of::<LONG>()),
        layout_value(align_of::<LONG>()),
        layout_value(size_of::<ULONG>()),
        layout_value(align_of::<ULONG>()),
        layout_value(size_of::<SpinLockPadding>()),
        layout_value(align_of::<SpinLockPadding>()),
        layout_value(offset_of!(SpinLockPadding, owner)),
        layout_value(offset_of!(SpinLockPadding, isolation)),
        layout_value(size_of::<SdkError>()),
        layout_value(align_of::<SdkError>()),
        layout_value(offset_of!(SdkError, kind)),
        layout_value(offset_of!(SdkError, native)),
        layout_value(size_of::<SdkStats>()),
        layout_value(align_of::<SdkStats>()),
        layout_value(offset_of!(SdkStats, blocks)),
        layout_value(offset_of!(SdkStats, backing_charge)),
        layout_value(offset_of!(SdkStats, peak_charge)),
        layout_value(offset_of!(SdkStats, files)),
        layout_value(offset_of!(SdkStats, libraries)),
        layout_value(offset_of!(SdkStats, ports)),
        layout_value(offset_of!(SdkStats, signals)),
        layout_value(offset_of!(SdkStats, messages)),
        layout_value(offset_of!(SdkStats, refusals)),
    ]
}

pub type SdkCallback = unsafe extern "C" fn(*mut c_void, u64) -> u64;

unsafe extern "C" {
    pub fn sdk_begin(argc: c_int, argv: *mut *mut c_char) -> c_int;
    pub fn sdk_end() -> c_int;
    pub fn sdk_context() -> u64;
    pub fn sdk_claim_context() -> u64;
    pub fn sdk_arg_count(context: u64) -> usize;
    pub fn sdk_arg(context: u64, index: usize, length: *mut usize) -> *const u8;
    pub fn sdk_alloc(size: usize, alignment: usize) -> *mut c_void;
    pub fn sdk_dealloc(pointer: *mut c_void, size: usize, alignment: usize);
    pub fn sdk_diagnostic(bytes: *const u8, length: usize, context: u64);
    pub fn sdk_fatal(context: u64) -> !;
    pub fn sdk_stats() -> SdkStats;

    pub fn sdk_library_open(
        context: u64,
        name: *const u8,
        minimum_version: u16,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_library_base(context: u64, library: u64) -> *mut c_void;
    pub fn sdk_library_close(context: u64, library: u64, error: *mut SdkError) -> c_int;

    pub fn sdk_file_open(context: u64, path: *const u8, mode: i32, error: *mut SdkError) -> u64;
    pub fn sdk_file_close(context: u64, file: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_file_io(
        context: u64,
        file: u64,
        buffer: *mut u8,
        length: usize,
        write: i32,
        error: *mut SdkError,
    ) -> i64;
    pub fn sdk_stdout(context: u64) -> u64;
    pub fn sdk_stderr(context: u64) -> u64;

    pub fn sdk_signal_new(context: u64, error: *mut SdkError) -> u64;
    pub fn sdk_signal_drop(context: u64, signal: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_signal_post(context: u64, signal: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_signal_wait(context: u64, signal: u64, error: *mut SdkError) -> c_int;

    pub fn sdk_port_new(context: u64, error: *mut SdkError) -> u64;
    pub fn sdk_port_drop(context: u64, port: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_message_new(
        context: u64,
        bytes: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_message_drop(context: u64, message: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_message_copy(
        context: u64,
        message: u64,
        output: *mut u8,
        capacity: usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_port_put(
        context: u64,
        port: u64,
        message: u64,
        reply_port: u64,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_port_receive(context: u64, port: u64, message: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_message_reply(context: u64, message: u64, error: *mut SdkError) -> c_int;

    pub fn sdk_callback(
        context: u64,
        callback: SdkCallback,
        user_data: *mut c_void,
        input: u64,
        output: *mut u64,
        error: *mut SdkError,
    ) -> c_int;

    pub fn sdk_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_scalar(signed: i32, unsigned: u32, pointer: usize, wide: u64, size: usize) -> u64;
}
