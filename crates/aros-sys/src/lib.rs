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

/// Untyped pointer, the C `APTR` (`void *`) of the AROS headers.
pub type APTR = *mut c_void;
/// `AROS_FAST_BPTR` selects `APTR` for BPTR in the pinned x86-64 SDK.
pub type BPTR = APTR;
/// AROS `BOOL`: a 16-bit integer used as a truth value, where zero is false and any other value is
/// true.
pub type BOOL = i16;
/// AROS `BYTE`: an 8-bit signed integer.
pub type BYTE = i8;
/// AROS `IPTR`: an unsigned integer exactly as wide as a pointer, used where a field holds either a
/// number or an address.
pub type IPTR = usize;
/// AROS `LONG`: a 32-bit signed integer.
pub type LONG = i32;
/// AROS `SIPTR`: the signed counterpart of [`IPTR`], as wide as a pointer.
pub type SIPTR = isize;
/// Identifier of a [`TagItem`]. Tags of the system have bit 31 clear; application tags start at
/// [`TAG_USER`].
pub type Tag = u32;
/// AROS `UBYTE`: an 8-bit unsigned integer.
pub type UBYTE = u8;
/// AROS `ULONG`: a 32-bit unsigned integer.
pub type ULONG = u32;

/// Tag that ends a tag list. The `data` of the item is ignored.
pub const TAG_DONE: u32 = 0;
/// Tag of an item that the receiver skips; its `data` is ignored.
pub const TAG_IGNORE: u32 = 1;
/// Tag that continues the list: the `data` of the item is the address of another tag list to read
/// next.
pub const TAG_MORE: u32 = 2;
/// Tag that skips items: the receiver also skips the number of following items given by `data`.
pub const TAG_SKIP: u32 = 3;
/// First tag value reserved for applications and for class- or library-specific tags: bit 31 set.
pub const TAG_USER: u32 = 1 << 31;

/// AROS `struct TagItem` for the selected 64-bit ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TagItem {
    /// The tag identifier: [`TAG_DONE`], [`TAG_IGNORE`], [`TAG_MORE`], [`TAG_SKIP`] or a library
    /// tag.
    pub tag: u32,
    /// The value of the tag: a number, or a pointer stored as an integer, depending on the tag.
    pub data: usize,
}

impl TagItem {
    /// Creates an item with the given tag and value.
    pub const fn new(tag: u32, data: usize) -> Self {
        Self { tag, data }
    }

    /// Creates the terminating item of a tag list: [`TAG_DONE`] with a value of zero.
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
    /// The next node in the list. The last node points at the list's tail marker.
    pub successor: *mut MinNode,
    /// The previous node in the list. The first node points at the list's head marker.
    pub predecessor: *mut MinNode,
}

/// AROS callback hook layout used by BOOPSI class dispatchers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Hook {
    /// The link by which the hook can be put on a list.
    pub min_node: MinNode,
    /// The function the system calls to run the hook (`h_Entry`). On this ABI it is an ordinary C
    /// function taking the hook, an object and a message.
    pub entry: *mut c_void,
    /// A second entry point (`h_SubEntry`) that the hook's own implementation may use from `entry`;
    /// the system does not call it.
    pub sub_entry: *mut c_void,
    /// Free data owned by the hook's implementation (`h_Data`).
    pub data: *mut c_void,
}

/// Read-only AROS BOOPSI class layout used by custom-class instance access and
/// host-only dispatch controls. Native dispatch itself stays in the C bridge.
#[repr(C)]
#[derive(Debug)]
pub struct IClass {
    /// The hook that dispatches methods to this class (`cl_Dispatcher`).
    pub dispatcher: Hook,
    /// Reserved by the system (`cl_Reserved`); never modify it.
    pub reserved: u32,
    /// The class this class inherits from (`cl_Super`).
    pub super_class: *mut IClass,
    /// The public name of the class (`cl_ID`), or null for a private class.
    pub id: *const c_char,
    /// Offset of this class's instance data within an object (`cl_InstOffset`).
    pub instance_offset: u16,
    /// Size of the instance data that this class adds to its superclass (`cl_InstSize`).
    pub instance_size: u16,
    /// Data that the implementor of the class may use freely (`cl_UserData`).
    pub user_data: usize,
    /// Number of direct subclasses (`cl_SubclassCount`).
    pub subclass_count: u32,
    /// Number of live objects made from this class (`cl_ObjectCount`). It must be zero before the
    /// class is removed.
    pub object_count: u32,
    /// Class flags (`cl_Flags`); `CLF_INLIST` (bit 0) is set while the class is in the public class
    /// list.
    pub flags: u32,
    /// Total size of an object of this class: `cl_InstOffset + cl_InstSize + sizeof(struct
    /// _Object)` (`cl_ObjectSize`).
    pub object_size: u32,
    /// The memory pool the class uses for its objects (`cl_MemoryPool`).
    pub memory_pool: *mut c_void,
}

#[cfg(not(target_os = "aros"))]
type Dispatcher = unsafe extern "C" fn(*mut IClass, *mut Object, Msg) -> usize;

#[cfg(target_os = "aros")]
unsafe extern "C" {
    #[link_name = "sdk_do_method_a"]
    fn native_do_method_a(object: *mut Object, message: Msg) -> usize;
    #[link_name = "sdk_do_super_method_a"]
    fn native_do_super_method_a(class: *mut IClass, object: *mut Object, message: Msg) -> usize;
    #[link_name = "sdk_coerce_method_a"]
    fn native_coerce_method_a(class: *mut IClass, object: *mut Object, message: Msg) -> usize;
}

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

#[cfg(not(target_os = "aros"))]
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
/// `object` must point to a live BOOPSI object and `message` must match its
/// method ID. Native AROS builds apply `OCLASS` and `CALLHOOKPKT` in C so Rust
/// does not reproduce compiler-selected object-header alignment.
pub unsafe fn do_method_a(object: *mut Object, message: Msg) -> usize {
    #[cfg(target_os = "aros")]
    {
        // SAFETY: the native bridge applies the canonical AROS OCLASS and
        // CALLHOOKPKT macros to the caller-validated object and message.
        return unsafe { native_do_method_a(object, message) };
    }
    #[cfg(not(target_os = "aros"))]
    {
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
}

/// Raw AROS `DoSuperMethodA` adapter without a Rust variadic ABI.
///
/// # Safety
///
/// `class`, `object` and `message` must form a valid BOOPSI dispatcher call.
pub unsafe fn do_super_method_a(class: *mut IClass, object: *mut Object, message: Msg) -> usize {
    #[cfg(target_os = "aros")]
    {
        // SAFETY: the native bridge uses the AROS class definition and
        // CALLHOOKPKT macro for the caller-validated values.
        return unsafe { native_do_super_method_a(class, object, message) };
    }
    #[cfg(not(target_os = "aros"))]
    {
        if class.is_null() || object.is_null() {
            return 0;
        }
        // SAFETY: the caller guarantees a live class layout.
        let super_class = unsafe { (*class).super_class };
        // SAFETY: forwarded from the public raw adapter contract.
        unsafe { dispatch(super_class, object, message) }
    }
}

/// Raw AROS `CoerceMethodA` adapter without a Rust variadic ABI.
///
/// # Safety
///
/// `class`, `object` and `message` must form a valid BOOPSI dispatcher call.
pub unsafe fn coerce_method_a(class: *mut IClass, object: *mut Object, message: Msg) -> usize {
    #[cfg(target_os = "aros")]
    {
        // SAFETY: the native bridge applies CALLHOOKPKT to the exact class,
        // object and message validated by the caller.
        return unsafe { native_coerce_method_a(class, object, message) };
    }
    #[cfg(not(target_os = "aros"))]
    {
        // SAFETY: forwarded from the public raw adapter contract.
        unsafe { dispatch(class, object, message) }
    }
}

#[cfg(all(target_os = "aros", not(target_arch = "x86_64")))]
compile_error!("aros-sys currently implements only the x86-64 AROS vector ABI");
#[cfg(all(
    target_os = "aros",
    not(any(target_abi = "", target_abi = "abi1", target_abi = "abi11"))
))]
compile_error!("aros-sys requires AROS ABI-v1 or ABI-v11");

mod generated;
pub use generated::{asl, dos, exec, graphics, icon, intuition, locale, timer, utility, workbench};

/// The C bridge's error record (`native` holds the immediately captured
/// native error, such as DOS `IoErr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SdkError {
    /// The class of the error: one of the `ERROR_KIND_*` values, or zero when the call recorded no
    /// error.
    pub kind: i32,
    /// The native error code captured immediately after the failing call, such as the DOS `IoErr`
    /// value; zero when there is none.
    pub native: i64,
}

/// Resource counters returned by the native bridge. Every member is C
/// `size_t`, which is 64-bit for this target.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SdkStats {
    /// Memory blocks that are currently allocated through the bridge.
    pub blocks: usize,
    /// The accounting charge of the blocks that are currently allocated. The bridge charges twice
    /// the block size plus a fixed overhead for each block.
    pub backing_charge: usize,
    /// The highest value `backing_charge` has reached.
    pub peak_charge: usize,
    /// Files that are currently open.
    pub files: usize,
    /// Libraries that are currently open through the bridge.
    pub libraries: usize,
    /// Message ports that currently exist.
    pub ports: usize,
    /// Signal bits that are currently allocated.
    pub signals: usize,
    /// Messages that currently exist.
    pub messages: usize,
    /// Operations the bridge has refused since it started, counted cumulatively: invalid arguments,
    /// exhausted bounds, wrong owner and failed allocations.
    pub refusals: usize,
    /// Devices that are currently open.
    pub devices: usize,
    /// Device I/O requests that currently exist.
    pub requests: usize,
    /// Directory scans that are currently open.
    pub directories: usize,
    /// Rastports that currently exist.
    pub rastports: usize,
    /// Bitmaps that are currently registered.
    pub bitmaps: usize,
    /// Windows that are currently open.
    pub windows: usize,
    /// Public screens that are currently registered.
    pub pubscreens: usize,
    /// ASL requesters that currently exist.
    pub aslrequests: usize,
    /// Locales that are currently open.
    pub locales: usize,
    /// Message catalogs that are currently open.
    pub catalogs: usize,
    /// Icons (disk objects) that are currently loaded.
    pub icons: usize,
    /// Workbench application ports that currently exist.
    pub wbports: usize,
    /// Workbench application windows, icons and menu items that are currently registered.
    pub wbobjects: usize,
}

/// One directory entry as filled in by the native bridge. `name_length` bytes
/// of `name` are valid and the name is also NUL terminated.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdkEntry {
    /// Size of the entry in bytes.
    pub size: u64,
    /// The protection bits of the entry.
    pub protection: u32,
    /// Number of valid bytes in `name`, not counting the terminating NUL.
    pub name_length: u32,
    /// The entry type the file system reports (`fib_EntryType`).
    pub entry_type: i32,
    /// The directory entry type (`fib_DirEntryType`): greater than zero for a directory, less than
    /// zero for a file.
    pub directory_type: i32,
    /// Days since 1 January 1978 of the last change.
    pub days: i32,
    /// Minutes since midnight of the last change.
    pub minutes: i32,
    /// Ticks of 1/50 second since the start of the minute of the last change.
    pub ticks: i32,
    /// One when `size` is exact, zero when it came from a 32-bit field that reached the 2 GiB limit
    /// and may be truncated.
    pub size_exact: u32,
    /// The name of the entry: `name_length` bytes followed by a NUL, at most 107 bytes.
    pub name: [u8; 108],
}

impl Default for SdkEntry {
    fn default() -> Self {
        Self {
            size: 0,
            protection: 0,
            name_length: 0,
            entry_type: 0,
            directory_type: 0,
            days: 0,
            minutes: 0,
            ticks: 0,
            size_exact: 0,
            name: [0; 108],
        }
    }
}

// These layouts follow AROS `exec/nodes.h`, `exec/lists.h`,
// `exec/libraries.h`, `exec/ports.h`, `dos/dos.h`, and
// `aros/types/spinlock_s.h`. On ABI-v1 the selected public
// `__AROSPLATFORM_SMP__` definition embeds spinlock_t as padding because
// `__AROSEXEC_SMP__` is not enabled; it does not describe an active Exec SMP
// lock. ABI-v11 has no such padding: `struct Library` ends at `lib_OpenCnt`
// and `struct MsgPort` ends in the private extension field `mp_Private`.

/// AROS `struct Node` (`exec/nodes.h`): the link, type, priority and name that every item of an
/// Exec list carries.
#[repr(C)]
pub struct Node {
    /// The next node in the list. The last node points at the list's tail marker.
    pub succ: *mut Node,
    /// The previous node in the list. The first node points at the list's head marker.
    pub pred: *mut Node,
    /// The node type (`ln_Type`), an `NT_*` value such as `NT_TASK` or `NT_MSGPORT`.
    pub kind: u8,
    /// The node priority (`ln_Pri`, -128 to 127), used to order nodes in lists that are kept
    /// sorted.
    pub priority: i8,
    /// Pointer to the NUL-terminated name of the node (`ln_Name`), or null.
    pub name: *mut u8,
}

/// AROS `struct List` (`exec/lists.h`): the header of a doubly linked list of [`Node`]s. An empty
/// list has `head` pointing at `tail` and `tail_pred` pointing at `head`.
#[repr(C)]
pub struct List {
    /// The first node, or the address of the `tail` field when the list is empty (`lh_Head`).
    pub head: *mut Node,
    /// The tail marker. It is always null (`lh_Tail`); the last node's `succ` points at this field.
    pub tail: *mut Node,
    /// The last node, or the address of the `head` field when the list is empty (`lh_TailPred`).
    pub tail_pred: *mut Node,
    /// The type of the nodes in the list (`lh_Type`), an `NT_*` value.
    pub kind: u8,
    /// Padding that keeps the structure aligned (`l_pad`).
    pub _pad: u8,
}

/// The public spinlock_t storage included by the selected SMP-layout define.
/// It is padding in the selected non-Exec-SMP ABI profile. It exists on ABI-v1
/// only; ABI-v11 has no `spinlock_t`.
#[cfg(not(target_abi = "abi11"))]
#[repr(C)]
pub struct SpinLockPadding {
    /// The lock word of the `spinlock_t` storage.
    pub lock_word: u32,
    /// The owner field of the `spinlock_t` storage.
    pub owner: *mut c_void,
    /// Padding bytes that complete the `spinlock_t` storage.
    pub isolation: [u8; 112],
}

/// AROS `struct Library` (`exec/libraries.h`): the common header at the base of every library; the
/// vector table lies before it. On ABI-v1 the structure ends with SMP padding, see
/// [`SpinLockPadding`]; on ABI-v11 it ends at `open_count`.
#[repr(C)]
pub struct Library {
    /// The node by which the library is linked into Exec's library list; its name is the library
    /// name.
    pub node: Node,
    /// Library flags (`lib_Flags`): the `LIBF_*` bits such as changed, sum used and delayed
    /// expunge.
    pub flags: u8,
    /// Padding (`lib_pad`) after the flags.
    pub _pad: u8,
    /// Size in bytes of the vector table that lies before the library base (`lib_NegSize`).
    pub negative_size: u16,
    /// Size in bytes of the library structure and its private data from the base on
    /// (`lib_PosSize`).
    pub positive_size: u16,
    /// Major version number (`lib_Version`).
    pub version: u16,
    /// Minor version number (`lib_Revision`).
    pub revision: u16,
    /// Pointer to a NUL-terminated identification string (`lib_IdString`), or null.
    pub id_string: *mut u8,
    /// The library checksum (`lib_Sum`).
    pub checksum: ULONG,
    /// Number of current openers (`lib_OpenCnt`).
    pub open_count: u16,
    /// The SMP spinlock storage after the public fields (ABI-v1 only).
    #[cfg(not(target_abi = "abi11"))]
    pub spinlock_padding: SpinLockPadding,
}

/// AROS `struct Message` (`exec/ports.h`): the header of a message that is sent to a [`MsgPort`].
/// Messages that carry data embed this header at the start of their own structure.
#[repr(C)]
pub struct Message {
    /// The node by which the message is queued on a port; its type is `NT_MESSAGE` or, once replied
    /// to, `NT_REPLYMSG` (`mn_Node`).
    pub node: Node,
    /// The port that receives the message when the receiver replies, or null (`mn_ReplyPort`).
    pub reply_port: *mut MsgPort,
    /// Total length of the message in bytes, including this header (`mn_Length`).
    pub length: u16,
}

/// Exec `struct IORequest`.
#[repr(C)]
pub struct IoRequest {
    /// The message header; a request is sent to a device as a message (`io_Message`).
    pub message: Message,
    /// The device the request is for (`io_Device`), filled in when the device is opened.
    pub device: *mut c_void,
    /// The unit of the device (`io_Unit`), filled in when the device is opened.
    pub unit: *mut c_void,
    /// The command to perform (`io_Command`), a device command number.
    pub command: u16,
    /// Request flags (`io_Flags`), the `IOF_*` bits.
    pub flags: u8,
    /// The error code the device sets (`io_Error`): zero for success, negative values for the
    /// standard device errors.
    pub error: i8,
}

/// `struct EClockVal` of `devices/timer.h`: the 64-bit E-clock count in two
/// halves.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EClockVal {
    /// The upper 32 bits of the E-clock count (`ev_hi`).
    pub hi: u32,
    /// The lower 32 bits of the E-clock count (`ev_lo`).
    pub lo: u32,
}

/// A time of `devices/timer.h` as seconds and microseconds, 32 bits each. On
/// ABI-v1 this is `struct timeval`; on ABI-v11 `timerequest` carries
/// `struct timeval32`, which has the same layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimeVal {
    /// Seconds.
    pub secs: u32,
    /// Microseconds, from 0 to 999999.
    pub micros: u32,
}

/// `struct timerequest`: an `IORequest` followed by a time value.
#[repr(C)]
pub struct TimeRequest {
    /// The standard request header (`tr_node`).
    pub request: IoRequest,
    /// The time value of the request (`tr_time`): a delay for a delay request, or the time that a
    /// time query fills in.
    pub time: TimeVal,
}

/// AROS `struct MsgPort` (`exec/ports.h`): a queue of messages with a rule for what happens when
/// one arrives. On ABI-v1 the structure ends with SMP padding, see [`SpinLockPadding`]; on ABI-v11
/// it ends in a private extension field.
#[repr(C)]
pub struct MsgPort {
    /// The node by which the port is linked into Exec's port list when it is public; its name is
    /// the port name (`mp_Node`).
    pub node: Node,
    /// What happens when a message arrives (`mp_Flags`): signal a task, cause a software interrupt,
    /// or nothing (`PA_SIGNAL`, `PA_SOFTINT`, `PA_IGNORE`).
    pub flags: u8,
    /// Number of the signal bit allocated for the port (`mp_SigBit`).
    pub signal_bit: u8,
    /// The task that is signalled when a message arrives (`mp_SigTask`).
    pub signal_task: APTR,
    /// The queue of messages that have arrived and not yet been taken (`mp_MsgList`).
    pub message_list: List,
    /// The SMP spinlock storage after the public fields (ABI-v1).
    #[cfg(not(target_abi = "abi11"))]
    pub spinlock_padding: SpinLockPadding,
    /// The private extension field `mp_Private` (ABI-v11).
    #[cfg(target_abi = "abi11")]
    pub private: [IPTR; 2],
}

/// AROS `struct DateStamp` (`dos/dosextens.h`): a date and time as days, minutes and ticks since 1
/// January 1978.
#[repr(C)]
pub struct DateStamp {
    /// Days since 1 January 1978 (`ds_Days`).
    pub days: LONG,
    /// Minutes since midnight (`ds_Minute`).
    pub minutes: LONG,
    /// Ticks of 1/50 second since the start of the minute (`ds_Tick`).
    pub ticks: LONG,
}

/// The pinned M0 C profile leaves `__DOS64` undefined, so `dos/dos.h`
/// selects `FileInfoBlock32` and its LONG-sized file and block counts.
#[repr(C)]
pub struct FileInfoBlock {
    /// A key that the file system uses to identify the entry (`fib_DiskKey`).
    pub disk_key: IPTR,
    /// Type of the entry (`fib_DirEntryType`): greater than zero for a directory, less than zero
    /// for a file.
    pub directory_entry_type: LONG,
    /// The NUL-terminated name of the entry (`fib_FileName`), at most 107 bytes.
    pub file_name: [u8; 108],
    /// The protection bits of the entry (`fib_Protection`).
    pub protection: LONG,
    /// The entry type the file system reports (`fib_EntryType`); it has the same sign convention as
    /// `directory_entry_type`.
    pub entry_type: LONG,
    /// Size of the file in bytes (`fib_Size`). In this 32-bit profile a size of 2 GiB or more
    /// cannot be represented.
    pub size: LONG,
    /// Number of blocks the file occupies (`fib_NumBlocks`).
    pub num_blocks: LONG,
    /// Date of the last change (`fib_Date`).
    pub date: DateStamp,
    /// The NUL-terminated file comment (`fib_Comment`), at most 79 bytes.
    pub comment: [u8; 80],
    /// Owner user ID (`fib_OwnerUID`), for file systems that record owners.
    pub owner_uid: u16,
    /// Owner group ID (`fib_OwnerGID`), for file systems that record owners.
    pub owner_gid: u16,
    /// Reserved bytes (`fib_Reserved`); do not use.
    pub reserved: [u8; 32],
}

// Bounds implemented by the safe SDK layer. Paths include the trailing NUL;
// argument bytes are the combined encoded size, including any terminators.
/// Most command-line arguments the bridge accepts; with more, start-up fails with return code 10.
pub const MAX_ARGUMENTS: usize = 32;
/// Most bytes in all command-line arguments together, counting a terminating NUL for each argument;
/// with more, start-up fails with return code 10.
pub const MAX_ARGUMENT_BYTES: usize = 4096;
/// Longest path accepted by the file functions, including the terminating NUL. The safe API
/// therefore accepts paths of at most one byte less.
pub const MAX_PATH_BYTES: usize = 128;
/// Smallest alignment the safe allocator API accepts. The bridge raises any alignment below 8 to 8.
pub const MIN_ALLOCATION_ALIGNMENT: usize = 1;
/// Largest alignment the bridge accepts for an allocation. It must also be a power of two.
pub const MAX_ALLOCATION_ALIGNMENT: usize = 4096;
/// Most bytes one `sdk_file_io` call moves; a longer request is refused as invalid input. The safe
/// file read and write loops split longer buffers into several calls.
pub const MAX_FILE_TRANSFER_BYTES: usize = 64 * 1024;
/// Largest number of simultaneously open files, optional libraries, private
/// ports or owned messages. Each registry grows on demand, so memory is the
/// practical bound; this is the size of its token space.
pub const MAX_HANDLES_PER_KIND: usize = (1 << 20) - 1;
/// Exec allocates signals from one 32-bit task mask, which caps this count.
pub const MAX_OWNED_SIGNALS: usize = 32;
/// Most payload bytes of one owned message.
pub const MAX_MESSAGE_PAYLOAD_BYTES: usize = 256;
/// Number of callbacks that may run through `sdk_callback` at one time. A second, nested call is
/// refused with `ERROR_KIND_STATE`.
pub const MAX_ACTIVE_CALLBACKS: usize = 1;
/// Most data bytes that a device I/O request can carry.
pub const MAX_REQUEST_DATA_BYTES: usize = 64 * 1024;
/// Request kind for `sdk_io_new`: a standard `IOStdReq`, which carries a data buffer.
pub const IO_KIND_STANDARD: i32 = 0;
/// Request kind for `sdk_io_new`: a `timerequest`, which carries a time value and no data buffer.
pub const IO_KIND_TIMER: i32 = 1;
/// Size of the buffer in which the bridge formats one diagnostic line: the label (cut to 230
/// bytes), a space, the code in decimal and a newline.
pub const MAX_DIAGNOSTIC_BYTES: usize = 256;

/// Number of values [`timer_layout_values`] and `sdk_timer_layout` produce.
pub const TIMER_LAYOUT_VALUE_COUNT: usize = 8;

/// The sizes and offsets of the timer types as the Rust declarations here
/// lay them out; the native bridge reports the same values from the selected
/// SDK headers (`sdk_timer_layout`), so the ABI-specific `timerequest`
/// (`struct timeval` on ABI-v1, `struct timeval32` on ABI-v11) is checked on
/// each ABI.
pub const fn timer_layout_values() -> [u64; TIMER_LAYOUT_VALUE_COUNT] {
    [
        size_of::<TimeRequest>() as u64,
        align_of::<TimeRequest>() as u64,
        offset_of!(TimeRequest, time) as u64,
        size_of::<EClockVal>() as u64,
        offset_of!(EClockVal, lo) as u64,
        size_of::<TimeVal>() as u64,
        offset_of!(TimeVal, micros) as u64,
        size_of::<IoRequest>() as u64,
    ]
}

/// One window's geometry as the native bridge reads it from `struct Window`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SdkWindowInfo {
    /// Left edge of the window on its screen, in pixels.
    pub left: i32,
    /// Top edge of the window on its screen, in pixels.
    pub top: i32,
    /// Width of the window including its borders, in pixels.
    pub width: i32,
    /// Height of the window including its borders, in pixels.
    pub height: i32,
    /// Width of the left border in pixels.
    pub border_left: i32,
    /// Height of the top border in pixels.
    pub border_top: i32,
    /// Width of the right border in pixels.
    pub border_right: i32,
    /// Height of the bottom border in pixels.
    pub border_bottom: i32,
    /// Horizontal mouse position relative to the window (`MouseX`).
    pub mouse_x: i32,
    /// Vertical mouse position relative to the window (`MouseY`).
    pub mouse_y: i32,
    /// Width of the screen the window is on, in pixels.
    pub screen_width: i32,
    /// Height of the screen the window is on, in pixels.
    pub screen_height: i32,
    /// The signal mask of the window's IDCMP port: wait on it to be woken when an event arrives.
    pub signal_mask: u32,
    /// The window's `RastPort`, for drawing into the window.
    pub rastport: *mut c_void,
}

/// One decoded IDCMP message.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SdkIntuiEvent {
    /// The IDCMP class of the event: one `IDCMP_*` bit, see [`idcmp`].
    pub class: u32,
    /// The message code (`Code`); for mouse buttons one of the `idcmp::SELECT_*`, `MENU_*` or
    /// `MIDDLE_*` values, for a raw key the key code.
    pub code: u16,
    /// The qualifier bits that were set when the event happened (`Qualifier`).
    pub qualifier: u16,
    /// Horizontal mouse position of the event, relative to the window (`MouseX`).
    pub x: i16,
    /// Vertical mouse position of the event, relative to the window (`MouseY`).
    pub y: i16,
    /// Seconds of the event's time stamp (`Seconds`).
    pub seconds: u32,
    /// Microseconds of the event's time stamp (`Micros`).
    pub micros: u32,
}

/// Window tags (`WA_*`) the safe window builder uses.
pub mod wa {
    use super::TAG_USER;
    /// `WA_Left`: left edge of the window on its screen.
    pub const LEFT: u32 = TAG_USER + 100;
    /// `WA_Top`: top edge of the window on its screen.
    pub const TOP: u32 = TAG_USER + 101;
    /// `WA_Width`: outer width of the window.
    pub const WIDTH: u32 = TAG_USER + 102;
    /// `WA_Height`: outer height of the window.
    pub const HEIGHT: u32 = TAG_USER + 103;
    /// `WA_IDCMP`: the IDCMP classes the window wants to receive.
    pub const IDCMP: u32 = TAG_USER + 106;
    /// `WA_Title`: the window title, a NUL-terminated string.
    pub const TITLE: u32 = TAG_USER + 110;
    /// `WA_MinWidth`: smallest width the user may size the window to.
    pub const MIN_WIDTH: u32 = TAG_USER + 114;
    /// `WA_MinHeight`: smallest height the user may size the window to.
    pub const MIN_HEIGHT: u32 = TAG_USER + 115;
    /// `WA_MaxWidth`: largest width the user may size the window to.
    pub const MAX_WIDTH: u32 = TAG_USER + 116;
    /// `WA_MaxHeight`: largest height the user may size the window to.
    pub const MAX_HEIGHT: u32 = TAG_USER + 117;
    /// `WA_InnerWidth`: width of the usable area inside the borders.
    pub const INNER_WIDTH: u32 = TAG_USER + 118;
    /// `WA_InnerHeight`: height of the usable area inside the borders.
    pub const INNER_HEIGHT: u32 = TAG_USER + 119;
    /// `WA_PubScreen`: the public screen to open the window on.
    pub const PUB_SCREEN: u32 = TAG_USER + 121;
    /// `WA_SizeGadget`: give the window a sizing gadget.
    pub const SIZE_GADGET: u32 = TAG_USER + 129;
    /// `WA_DragBar`: give the window a drag bar.
    pub const DRAG_BAR: u32 = TAG_USER + 130;
    /// `WA_DepthGadget`: give the window a depth-arrangement gadget.
    pub const DEPTH_GADGET: u32 = TAG_USER + 131;
    /// `WA_CloseGadget`: give the window a close gadget.
    pub const CLOSE_GADGET: u32 = TAG_USER + 132;
    /// `WA_ReportMouse`: report mouse movement while the window is active.
    pub const REPORT_MOUSE: u32 = TAG_USER + 134;
    /// `WA_Borderless`: open the window without borders.
    pub const BORDERLESS: u32 = TAG_USER + 136;
    /// `WA_Activate`: activate the window when it opens.
    pub const ACTIVATE: u32 = TAG_USER + 137;
    /// `WA_SimpleRefresh`: the application redraws damaged parts itself.
    pub const SIMPLE_REFRESH: u32 = TAG_USER + 140;
    /// `WA_SmartRefresh`: the system saves and restores the hidden parts of the window.
    pub const SMART_REFRESH: u32 = TAG_USER + 141;
    /// `WA_GimmeZeroZero`: give the window a separate border layer so that drawing starts at the
    /// inner origin.
    pub const GIMME_ZERO_ZERO: u32 = TAG_USER + 145;
}

/// IDCMP class bits and message codes the safe window API decodes.
pub mod idcmp {
    /// `IDCMP_NEWSIZE`: the window was resized.
    pub const NEW_SIZE: u32 = 1 << 1;
    /// `IDCMP_REFRESHWINDOW`: part of the window needs to be redrawn.
    pub const REFRESH_WINDOW: u32 = 1 << 2;
    /// `IDCMP_MOUSEBUTTONS`: a mouse button changed state; the message code tells which.
    pub const MOUSE_BUTTONS: u32 = 1 << 3;
    /// `IDCMP_MOUSEMOVE`: the mouse moved.
    pub const MOUSE_MOVE: u32 = 1 << 4;
    /// `IDCMP_CLOSEWINDOW`: the user activated the close gadget.
    pub const CLOSE_WINDOW: u32 = 1 << 9;
    /// `IDCMP_RAWKEY`: a key changed state; the message code is the raw key code.
    pub const RAW_KEY: u32 = 1 << 10;
    /// `IDCMP_ACTIVEWINDOW`: the window became active.
    pub const ACTIVE_WINDOW: u32 = 1 << 18;
    /// `IDCMP_INACTIVEWINDOW`: the window stopped being active.
    pub const INACTIVE_WINDOW: u32 = 1 << 19;
    /// `IDCMP_VANILLAKEY`: a key press that maps to a character; the message code is the character.
    pub const VANILLA_KEY: u32 = 1 << 21;
    /// `SELECTDOWN`: message code of a mouse-button message for the left (select) button pressed.
    pub const SELECT_DOWN: u16 = 0x68;
    /// `SELECTUP`: message code of a mouse-button message for the left (select) button released.
    pub const SELECT_UP: u16 = 0xe8;
    /// `MENUDOWN`: message code of a mouse-button message for the right (menu) button pressed.
    pub const MENU_DOWN: u16 = 0x69;
    /// `MENUUP`: message code of a mouse-button message for the right (menu) button released.
    pub const MENU_UP: u16 = 0xe9;
    /// `MIDDLEDOWN`: message code of a mouse-button message for the middle button pressed.
    pub const MIDDLE_DOWN: u16 = 0x6a;
    /// `MIDDLEUP`: message code of a mouse-button message for the middle button released.
    pub const MIDDLE_UP: u16 = 0xea;
}

/// Number of values [`intuition_layout_values`] and `sdk_intui_layout` produce.
pub const INTUITION_LAYOUT_VALUE_COUNT: usize = 45;

/// The bridge's window records and the window tag, IDCMP and message code
/// values as declared here; the native bridge reports the same values from the
/// selected SDK headers (`sdk_intui_layout`).
pub const fn intuition_layout_values() -> [u64; INTUITION_LAYOUT_VALUE_COUNT] {
    [
        size_of::<SdkWindowInfo>() as u64,
        align_of::<SdkWindowInfo>() as u64,
        offset_of!(SdkWindowInfo, signal_mask) as u64,
        offset_of!(SdkWindowInfo, rastport) as u64,
        size_of::<SdkIntuiEvent>() as u64,
        offset_of!(SdkIntuiEvent, x) as u64,
        offset_of!(SdkIntuiEvent, micros) as u64,
        wa::LEFT as u64,
        wa::TOP as u64,
        wa::WIDTH as u64,
        wa::HEIGHT as u64,
        wa::IDCMP as u64,
        wa::TITLE as u64,
        wa::MIN_WIDTH as u64,
        wa::MIN_HEIGHT as u64,
        wa::MAX_WIDTH as u64,
        wa::MAX_HEIGHT as u64,
        wa::INNER_WIDTH as u64,
        wa::INNER_HEIGHT as u64,
        wa::PUB_SCREEN as u64,
        wa::SIZE_GADGET as u64,
        wa::DRAG_BAR as u64,
        wa::DEPTH_GADGET as u64,
        wa::CLOSE_GADGET as u64,
        wa::REPORT_MOUSE as u64,
        wa::BORDERLESS as u64,
        wa::ACTIVATE as u64,
        wa::SIMPLE_REFRESH as u64,
        wa::SMART_REFRESH as u64,
        wa::GIMME_ZERO_ZERO as u64,
        idcmp::NEW_SIZE as u64,
        idcmp::REFRESH_WINDOW as u64,
        idcmp::MOUSE_BUTTONS as u64,
        idcmp::MOUSE_MOVE as u64,
        idcmp::CLOSE_WINDOW as u64,
        idcmp::RAW_KEY as u64,
        idcmp::VANILLA_KEY as u64,
        idcmp::ACTIVE_WINDOW as u64,
        idcmp::INACTIVE_WINDOW as u64,
        idcmp::SELECT_DOWN as u64,
        idcmp::SELECT_UP as u64,
        idcmp::MENU_DOWN as u64,
        idcmp::MENU_UP as u64,
        idcmp::MIDDLE_DOWN as u64,
        idcmp::MIDDLE_UP as u64,
    ]
}

/// File requester tags (`ASLFR_*`) and the requester type the safe requester
/// builder uses.
pub mod aslfr {
    use super::TAG_USER;
    const BASE: u32 = TAG_USER + 0x80000;
    /// `ASL_FileRequest`: the requester type that asks for a file.
    pub const FILE_REQUEST: u32 = 0;
    /// `ASLFR_TitleText`: the requester title.
    pub const TITLE_TEXT: u32 = BASE + 1;
    /// `ASLFR_Window`: the window the requester belongs to.
    pub const WINDOW: u32 = BASE + 2;
    /// `ASLFR_InitialLeftEdge`: left edge of the requester.
    pub const INITIAL_LEFT_EDGE: u32 = BASE + 3;
    /// `ASLFR_InitialTopEdge`: top edge of the requester.
    pub const INITIAL_TOP_EDGE: u32 = BASE + 4;
    /// `ASLFR_InitialWidth`: width of the requester.
    pub const INITIAL_WIDTH: u32 = BASE + 5;
    /// `ASLFR_InitialHeight`: height of the requester.
    pub const INITIAL_HEIGHT: u32 = BASE + 6;
    /// `ASLFR_InitialFile`: the file name shown first.
    pub const INITIAL_FILE: u32 = BASE + 8;
    /// `ASLFR_InitialDrawer`: the drawer shown first.
    pub const INITIAL_DRAWER: u32 = BASE + 9;
    /// `ASLFR_InitialPattern`: the file name pattern shown first.
    pub const INITIAL_PATTERN: u32 = BASE + 10;
    /// `ASLFR_PositiveText`: the label of the confirming button.
    pub const POSITIVE_TEXT: u32 = BASE + 18;
    /// `ASLFR_NegativeText`: the label of the cancelling button.
    pub const NEGATIVE_TEXT: u32 = BASE + 19;
    /// `ASLFR_SleepWindow`: block input to the window that owns the requester while it is open.
    pub const SLEEP_WINDOW: u32 = BASE + 43;
    /// `ASLFR_DoSaveMode`: use the requester to choose a file to save.
    pub const DO_SAVE_MODE: u32 = BASE + 44;
    /// `ASLFR_DoMultiSelect`: allow selecting more than one file.
    pub const DO_MULTI_SELECT: u32 = BASE + 45;
    /// `ASLFR_DoPatterns`: show a pattern gadget.
    pub const DO_PATTERNS: u32 = BASE + 46;
    /// `ASLFR_DrawersOnly`: let the user choose a drawer, not a file.
    pub const DRAWERS_ONLY: u32 = BASE + 47;
    /// `ASLFR_RejectIcons`: hide `.info` icon files.
    pub const REJECT_ICONS: u32 = BASE + 60;
    /// `ASLFR_PopToFront`: bring the requester screen to the front.
    pub const POP_TO_FRONT: u32 = BASE + 131;
    /// `ASLFR_Activate`: activate the requester window when it opens.
    pub const ACTIVATE: u32 = BASE + 132;
}

/// Number of values [`asl_layout_values`] and `sdk_asl_layout` produce.
pub const ASL_LAYOUT_VALUE_COUNT: usize = 20;

/// The requester type and tag values as declared here; the native bridge
/// reports the same values for the selected ABI (`sdk_asl_layout`).
pub const fn asl_layout_values() -> [u64; ASL_LAYOUT_VALUE_COUNT] {
    [
        aslfr::FILE_REQUEST as u64,
        aslfr::TITLE_TEXT as u64,
        aslfr::WINDOW as u64,
        aslfr::INITIAL_LEFT_EDGE as u64,
        aslfr::INITIAL_TOP_EDGE as u64,
        aslfr::INITIAL_WIDTH as u64,
        aslfr::INITIAL_HEIGHT as u64,
        aslfr::INITIAL_FILE as u64,
        aslfr::INITIAL_DRAWER as u64,
        aslfr::INITIAL_PATTERN as u64,
        aslfr::POSITIVE_TEXT as u64,
        aslfr::NEGATIVE_TEXT as u64,
        aslfr::SLEEP_WINDOW as u64,
        aslfr::DO_SAVE_MODE as u64,
        aslfr::DO_MULTI_SELECT as u64,
        aslfr::DO_PATTERNS as u64,
        aslfr::DRAWERS_ONLY as u64,
        aslfr::REJECT_ICONS as u64,
        aslfr::POP_TO_FRONT as u64,
        aslfr::ACTIVATE as u64,
    ]
}

/// Catalog tags (`OC_*`) and locale string numbers the safe locale API uses.
pub mod oc {
    use super::TAG_USER;
    const BASE: u32 = TAG_USER + 0x90000;
    /// `OC_BuiltInLanguage`: the language of the built-in strings of the application, used when no
    /// catalog is found.
    pub const BUILT_IN_LANGUAGE: u32 = BASE + 1;
    /// `OC_Version`: the catalog version that is required.
    pub const VERSION: u32 = BASE + 3;
    /// `OC_Language`: the language to open the catalog for, instead of the user's preferred
    /// languages.
    pub const LANGUAGE: u32 = BASE + 4;
    /// `DAY_1`: string number of the name of the first day of the week (Sunday); the other days
    /// follow.
    pub const DAY_1: u32 = 1;
    /// `ABDAY_1`: string number of the abbreviated name of the first day of the week; the other
    /// days follow.
    pub const ABDAY_1: u32 = 8;
    /// `MON_1`: string number of the name of the first month (January); the other months follow.
    pub const MON_1: u32 = 15;
    /// `ABMON_1`: string number of the abbreviated name of the first month; the other months
    /// follow.
    pub const ABMON_1: u32 = 27;
    /// `YESSTR`: string number of the word for "yes".
    pub const YES_STR: u32 = 39;
    /// `NOSTR`: string number of the word for "no".
    pub const NO_STR: u32 = 40;
    /// `AMSTR`: string number of the morning marker.
    pub const AM_STR: u32 = 41;
    /// `PMSTR`: string number of the afternoon marker.
    pub const PM_STR: u32 = 42;
}

/// The fields of a locale the bridge reads from `struct Locale`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SdkLocaleInfo {
    /// The NUL-terminated name of the locale (`loc_LocaleName`). The string belongs to the locale.
    pub locale_name: *const c_char,
    /// The NUL-terminated name of the language of the locale (`loc_LanguageName`). The string
    /// belongs to the locale.
    pub language_name: *const c_char,
    /// The preferred languages in order (`loc_PrefLanguages`). Unused entries are null.
    pub preferred: [*const c_char; 10],
    /// The offset from GMT as locale.library reports it (`loc_GMTOffset`), in minutes.
    pub gmt_offset: i32,
}

/// Number of values [`locale_layout_values`] and `sdk_locale_layout` produce.
pub const LOCALE_LAYOUT_VALUE_COUNT: usize = 15;

/// The catalog tag and string number values as declared here; the native
/// bridge reports the same values for the selected ABI (`sdk_locale_layout`).
pub const fn locale_layout_values() -> [u64; LOCALE_LAYOUT_VALUE_COUNT] {
    [
        oc::BUILT_IN_LANGUAGE as u64,
        oc::VERSION as u64,
        oc::LANGUAGE as u64,
        oc::DAY_1 as u64,
        oc::ABDAY_1 as u64,
        oc::MON_1 as u64,
        oc::ABMON_1 as u64,
        oc::YES_STR as u64,
        oc::NO_STR as u64,
        oc::AM_STR as u64,
        oc::PM_STR as u64,
        size_of::<SdkLocaleInfo>() as u64,
        offset_of!(SdkLocaleInfo, language_name) as u64,
        offset_of!(SdkLocaleInfo, preferred) as u64,
        offset_of!(SdkLocaleInfo, gmt_offset) as u64,
    ]
}

/// A disk object as the native bridge reads it from `struct DiskObject`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SdkIconInfo {
    /// The type of the disk object (`do_Type`): one of the `wb::DISK` to `wb::APP_ICON` values.
    pub kind: i32,
    /// The stack size in bytes that is recorded for starting the object (`do_StackSize`).
    pub stack_size: i32,
    /// Horizontal position of the icon in its drawer window (`do_CurrentX`).
    pub x: i32,
    /// Vertical position of the icon in its drawer window (`do_CurrentY`).
    pub y: i32,
    /// The NUL-terminated default tool (`do_DefaultTool`), or null. The string belongs to the disk
    /// object.
    pub default_tool: *const c_char,
    /// The null-terminated array of tool type strings (`do_ToolTypes`), or null. The array belongs
    /// to the disk object.
    pub tool_types: *const *const c_char,
}

/// One decoded Workbench application message.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SdkAppMessage {
    /// The message type (`am_Type`): one of the `wb::AMTYPE_*` values.
    pub kind: u32,
    /// The message class (`am_Class`).
    pub class: u32,
    /// Number of paths of this message that the bridge decoded and kept: at most 8, and at most
    /// `total_args`.
    pub num_args: u32,
    /// Number of arguments the message carried (`am_NumArgs`).
    pub total_args: i32,
    /// Horizontal mouse position of a drop (`am_MouseX`).
    pub mouse_x: i16,
    /// Vertical mouse position of a drop (`am_MouseY`).
    pub mouse_y: i16,
    /// Seconds of the message's time stamp (`am_Seconds`).
    pub seconds: u32,
    /// Microseconds of the message's time stamp (`am_Micros`).
    pub micros: u32,
    /// The identifier that was given when the window, icon or menu item was added (`am_ID`).
    pub id: u64,
    /// The user data that was given when the window, icon or menu item was added (`am_UserData`).
    pub user_data: u64,
}

/// Disk object types (`WB*`) and application message types (`AMTYPE_*`).
pub mod wb {
    /// `WBDISK`: a disk icon.
    pub const DISK: u32 = 1;
    /// `WBDRAWER`: a drawer icon.
    pub const DRAWER: u32 = 2;
    /// `WBTOOL`: a program icon.
    pub const TOOL: u32 = 3;
    /// `WBPROJECT`: a document icon with a default tool.
    pub const PROJECT: u32 = 4;
    /// `WBGARBAGE`: the trashcan icon.
    pub const GARBAGE: u32 = 5;
    /// `WBDEVICE`: a device icon.
    pub const DEVICE: u32 = 6;
    /// `WBKICK`: a Kickstart disk icon.
    pub const KICK: u32 = 7;
    /// `WBAPPICON`: an icon that an application put on the Workbench.
    pub const APP_ICON: u32 = 8;
    /// `AMTYPE_APPWINDOW`: message type of an icon dropped on an application window.
    pub const AMTYPE_APP_WINDOW: u32 = 7;
    /// `AMTYPE_APPICON`: message type of an icon dropped on, or a double click on, an application
    /// icon.
    pub const AMTYPE_APP_ICON: u32 = 8;
    /// `AMTYPE_APPMENUITEM`: message type of an application menu item that was chosen.
    pub const AMTYPE_APP_MENU_ITEM: u32 = 9;
}

/// Number of values [`wb_layout_values`] and `sdk_wb_layout` produce.
pub const WB_LAYOUT_VALUE_COUNT: usize = 18;

/// The disk object and message type values and the bridge's icon and message
/// records as declared here; the native bridge reports the same values for the
/// selected ABI (`sdk_wb_layout`).
pub const fn wb_layout_values() -> [u64; WB_LAYOUT_VALUE_COUNT] {
    [
        wb::DISK as u64,
        wb::DRAWER as u64,
        wb::TOOL as u64,
        wb::PROJECT as u64,
        wb::GARBAGE as u64,
        wb::DEVICE as u64,
        wb::KICK as u64,
        wb::APP_ICON as u64,
        wb::AMTYPE_APP_WINDOW as u64,
        wb::AMTYPE_APP_ICON as u64,
        wb::AMTYPE_APP_MENU_ITEM as u64,
        size_of::<SdkIconInfo>() as u64,
        offset_of!(SdkIconInfo, default_tool) as u64,
        offset_of!(SdkIconInfo, tool_types) as u64,
        size_of::<SdkAppMessage>() as u64,
        offset_of!(SdkAppMessage, mouse_x) as u64,
        offset_of!(SdkAppMessage, seconds) as u64,
        offset_of!(SdkAppMessage, id) as u64,
    ]
}

/// File mode for `sdk_file_open`: open an existing file for reading.
pub const SDK_FILE_READ_EXISTING: i32 = 0;
/// File mode for `sdk_file_open`: create the file, or empty it if it exists, and open it for
/// writing.
pub const SDK_FILE_CREATE_TRUNCATE: i32 = 1;
/// File mode for `sdk_file_open`: open an existing file for reading and writing.
pub const SDK_FILE_READ_WRITE: i32 = 2;

/// Error class: a native AROS call or an allocation failed. `SdkError::native` holds its error code
/// (for example the DOS `IoErr` value or `ERROR_NO_FREE_STORE`), or zero when none was available.
pub const ERROR_KIND_NATIVE: i32 = 1;
/// Error class: an argument was invalid, such as a null pointer, a length over a bound, or a name
/// that is not NUL terminated within the allowed length.
pub const ERROR_KIND_INPUT: i32 = 2;
/// Error class: a bound was reached, for example a file size that does not fit the 32-bit file
/// information of the profile.
pub const ERROR_KIND_LIMIT: i32 = 3;
/// Error class: the call was refused because the bridge is not active, the context token is not the
/// current one, or the calling task is not the task that started the bridge.
pub const ERROR_KIND_OWNER: i32 = 4;
/// Error class: the handle is unknown or already released, or the operation is not allowed in the
/// state of the object, for example a nested callback.
pub const ERROR_KIND_STATE: i32 = 5;
/// Error class: the end of the data was reached. The bridge does not set this class itself; if a
/// call ever reports it, the safe layer maps it to the `Eof` error kind.
pub const ERROR_KIND_EOF: i32 = 6;
/// Error class: a transfer made no progress. The bridge does not set this class itself; if a call
/// ever reports it, the safe layer maps it to the `ZeroProgress` error kind.
pub const ERROR_KIND_ZERO_PROGRESS: i32 = 7;

/// Layout oracle values in the exact order of the M0 C layout table:
/// Node, Library, Message, List, MsgPort, FileInfoBlock, scalar ABI types,
/// then the selected spinlock_t storage. No native call or allocation occurs.
#[cfg(not(target_abi = "abi11"))]
pub const ABI_LAYOUT_VALUE_COUNT: usize = 106;

/// ABI-v11 has no `spinlock_t`: the Library and MsgPort tails and the four
/// spinlock values are not part of its table.
#[cfg(target_abi = "abi11")]
pub const ABI_LAYOUT_VALUE_COUNT: usize = 101;

const fn layout_value(value: usize) -> u64 {
    value as u64
}

/// The layout of the exec, DOS and bridge records as the Rust declarations here lay them out, in
/// the order of the native `sdk_layout` table, so that the two can be compared value by value. The
/// table has [`ABI_LAYOUT_VALUE_COUNT`] entries: 106 on ABI-v1 and 101 on ABI-v11, which has no
/// `spinlock_t`.
pub const fn layout_values() -> [u64; ABI_LAYOUT_VALUE_COUNT] {
    let mut values = [0u64; ABI_LAYOUT_VALUE_COUNT];
    let mut next = 0;
    macro_rules! value {
        ($value:expr) => {
            values[next] = layout_value($value);
            next += 1;
        };
    }
    value!(size_of::<Node>());
    value!(align_of::<Node>());
    value!(offset_of!(Node, succ));
    value!(offset_of!(Node, pred));
    value!(offset_of!(Node, kind));
    value!(offset_of!(Node, priority));
    value!(offset_of!(Node, name));
    value!(size_of::<Library>());
    value!(align_of::<Library>());
    value!(offset_of!(Library, node));
    value!(offset_of!(Library, flags));
    value!(offset_of!(Library, _pad));
    value!(offset_of!(Library, negative_size));
    value!(offset_of!(Library, positive_size));
    value!(offset_of!(Library, version));
    value!(offset_of!(Library, revision));
    value!(offset_of!(Library, id_string));
    value!(offset_of!(Library, checksum));
    value!(offset_of!(Library, open_count));
    #[cfg(not(target_abi = "abi11"))]
    value!(offset_of!(Library, spinlock_padding));
    value!(size_of::<Message>());
    value!(align_of::<Message>());
    value!(offset_of!(Message, node));
    value!(offset_of!(Message, reply_port));
    value!(offset_of!(Message, length));
    value!(size_of::<List>());
    value!(align_of::<List>());
    value!(offset_of!(List, head));
    value!(offset_of!(List, tail));
    value!(offset_of!(List, tail_pred));
    value!(offset_of!(List, kind));
    value!(offset_of!(List, _pad));
    value!(size_of::<MsgPort>());
    value!(align_of::<MsgPort>());
    value!(offset_of!(MsgPort, node));
    value!(offset_of!(MsgPort, flags));
    value!(offset_of!(MsgPort, signal_bit));
    value!(offset_of!(MsgPort, signal_task));
    value!(offset_of!(MsgPort, message_list));
    #[cfg(not(target_abi = "abi11"))]
    value!(offset_of!(MsgPort, spinlock_padding));
    #[cfg(target_abi = "abi11")]
    value!(offset_of!(MsgPort, private));
    value!(size_of::<FileInfoBlock>());
    value!(align_of::<FileInfoBlock>());
    value!(offset_of!(FileInfoBlock, disk_key));
    value!(offset_of!(FileInfoBlock, directory_entry_type));
    value!(offset_of!(FileInfoBlock, file_name));
    value!(offset_of!(FileInfoBlock, protection));
    value!(offset_of!(FileInfoBlock, entry_type));
    value!(offset_of!(FileInfoBlock, size));
    value!(offset_of!(FileInfoBlock, num_blocks));
    value!(offset_of!(FileInfoBlock, date));
    value!(offset_of!(FileInfoBlock, comment));
    value!(offset_of!(FileInfoBlock, owner_uid));
    value!(offset_of!(FileInfoBlock, owner_gid));
    value!(offset_of!(FileInfoBlock, reserved));
    value!(size_of::<IPTR>());
    value!(align_of::<IPTR>());
    value!(size_of::<BPTR>());
    value!(align_of::<BPTR>());
    value!(size_of::<LONG>());
    value!(align_of::<LONG>());
    value!(size_of::<ULONG>());
    value!(align_of::<ULONG>());
    #[cfg(not(target_abi = "abi11"))]
    value!(size_of::<SpinLockPadding>());
    #[cfg(not(target_abi = "abi11"))]
    value!(align_of::<SpinLockPadding>());
    #[cfg(not(target_abi = "abi11"))]
    value!(offset_of!(SpinLockPadding, owner));
    #[cfg(not(target_abi = "abi11"))]
    value!(offset_of!(SpinLockPadding, isolation));
    value!(size_of::<SdkError>());
    value!(align_of::<SdkError>());
    value!(offset_of!(SdkError, kind));
    value!(offset_of!(SdkError, native));
    value!(size_of::<SdkStats>());
    value!(align_of::<SdkStats>());
    value!(offset_of!(SdkStats, blocks));
    value!(offset_of!(SdkStats, backing_charge));
    value!(offset_of!(SdkStats, peak_charge));
    value!(offset_of!(SdkStats, files));
    value!(offset_of!(SdkStats, libraries));
    value!(offset_of!(SdkStats, ports));
    value!(offset_of!(SdkStats, signals));
    value!(offset_of!(SdkStats, messages));
    value!(offset_of!(SdkStats, refusals));
    value!(offset_of!(SdkStats, devices));
    value!(offset_of!(SdkStats, requests));
    value!(offset_of!(SdkStats, directories));
    value!(offset_of!(SdkStats, rastports));
    value!(offset_of!(SdkStats, bitmaps));
    value!(offset_of!(SdkStats, windows));
    value!(offset_of!(SdkStats, pubscreens));
    value!(offset_of!(SdkStats, aslrequests));
    value!(offset_of!(SdkStats, locales));
    value!(offset_of!(SdkStats, catalogs));
    value!(offset_of!(SdkStats, icons));
    value!(offset_of!(SdkStats, wbports));
    value!(offset_of!(SdkStats, wbobjects));
    value!(size_of::<SdkEntry>());
    value!(align_of::<SdkEntry>());
    value!(offset_of!(SdkEntry, size));
    value!(offset_of!(SdkEntry, protection));
    value!(offset_of!(SdkEntry, name_length));
    value!(offset_of!(SdkEntry, entry_type));
    value!(offset_of!(SdkEntry, directory_type));
    value!(offset_of!(SdkEntry, days));
    value!(offset_of!(SdkEntry, minutes));
    value!(offset_of!(SdkEntry, ticks));
    value!(offset_of!(SdkEntry, size_exact));
    value!(offset_of!(SdkEntry, name));
    assert!(next == ABI_LAYOUT_VALUE_COUNT);
    values
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
    pub fn sdk_signal_wait_mask(
        context: u64,
        mask: u32,
        received: *mut u32,
        error: *mut SdkError,
    ) -> c_int;

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

    pub fn sdk_device_open(
        context: u64,
        name: *const u8,
        unit: u32,
        flags: u32,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_device_close(context: u64, device: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_device_signal_mask(context: u64, device: u64) -> u32;
    pub fn sdk_io_new(
        context: u64,
        device: u64,
        kind: i32,
        capacity: usize,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_io_drop(context: u64, request: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_io_prepare(
        context: u64,
        request: u64,
        command: u32,
        flags: u32,
        length: usize,
        offset: u32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_write(
        context: u64,
        request: u64,
        data: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_read(
        context: u64,
        request: u64,
        out: *mut u8,
        capacity: usize,
        error: *mut SdkError,
    ) -> i64;
    pub fn sdk_io_set_time(
        context: u64,
        request: u64,
        seconds: u32,
        micros: u32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_time(
        context: u64,
        request: u64,
        seconds: *mut u32,
        micros: *mut u32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_result(
        context: u64,
        request: u64,
        device_error: *mut i32,
        actual: *mut u32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_do(
        context: u64,
        request: u64,
        device_error: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_send(context: u64, request: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_io_check(context: u64, request: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_io_wait(
        context: u64,
        request: u64,
        device_error: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_io_abort(context: u64, request: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_file_seek(
        context: u64,
        file: u64,
        whence: i32,
        offset: i64,
        position: *mut u64,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_file_position(
        context: u64,
        file: u64,
        position: *mut u64,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_file_size(context: u64, file: u64, size: *mut u64, error: *mut SdkError) -> c_int;
    pub fn sdk_gfx_rastport_new(context: u64, error: *mut SdkError) -> u64;
    pub fn sdk_gfx_rastport_ptr(context: u64, rastport: u64) -> *mut c_void;
    pub fn sdk_gfx_rastport_set_bitmap(
        context: u64,
        rastport: u64,
        bitmap: *mut c_void,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_gfx_area_prepare(
        context: u64,
        rastport: u64,
        max_vectors: i32,
        width: i32,
        height: i32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_gfx_area_ptr(context: u64, rastport: u64, which: i32) -> *mut c_void;
    pub fn sdk_gfx_area_size(context: u64, rastport: u64, which: i32) -> usize;
    pub fn sdk_gfx_area_attach(context: u64, rastport: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_gfx_rastport_drop(context: u64, rastport: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_gfx_bitmap_register(
        context: u64,
        base: *mut c_void,
        bitmap: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_gfx_bitmap_release(context: u64, bitmap: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_intui_title_new(
        context: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_intui_title_ptr(context: u64, window: u64) -> *const c_char;
    pub fn sdk_intui_window_set_title(
        context: u64,
        window: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_intui_window_attach(
        context: u64,
        window: u64,
        base: *mut c_void,
        native: *mut c_void,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_intui_window_cancel(context: u64, window: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_intui_window_close(context: u64, window: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_intui_window_info(
        context: u64,
        window: u64,
        info: *mut SdkWindowInfo,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_intui_next_event(
        context: u64,
        window: u64,
        event: *mut SdkIntuiEvent,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_intui_screen_register(
        context: u64,
        base: *mut c_void,
        screen: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_intui_screen_size(
        context: u64,
        screen: u64,
        width: *mut i32,
        height: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_intui_screen_release(context: u64, screen: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_intui_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_asl_register(
        context: u64,
        base: *mut c_void,
        request: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_asl_release(context: u64, request: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_asl_count(
        context: u64,
        request: u64,
        count: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_asl_path(
        context: u64,
        request: u64,
        index: i32,
        buffer: *mut u8,
        capacity: usize,
        length: *mut usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_asl_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_locale_register(
        context: u64,
        kind: i32,
        base: *mut c_void,
        object: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_locale_release(context: u64, object: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_locale_info(
        context: u64,
        locale: u64,
        info: *mut SdkLocaleInfo,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_locale_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_icon_register(
        context: u64,
        base: *mut c_void,
        object: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_icon_info(
        context: u64,
        icon: u64,
        info: *mut SdkIconInfo,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_icon_set_default_tool(
        context: u64,
        icon: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_icon_set_tool_types(
        context: u64,
        icon: u64,
        items: *const *const u8,
        lengths: *const usize,
        count: usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_icon_set_stack(context: u64, icon: u64, stack: i32, error: *mut SdkError) -> c_int;
    pub fn sdk_icon_release(context: u64, icon: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_wb_port_new(context: u64, error: *mut SdkError) -> u64;
    pub fn sdk_wb_port_ptr(context: u64, port: u64) -> *mut c_void;
    pub fn sdk_wb_port_mask(context: u64, port: u64) -> u32;
    pub fn sdk_wb_port_pending(context: u64, port: u64) -> c_int;
    pub fn sdk_wb_port_next(
        context: u64,
        port: u64,
        message: *mut SdkAppMessage,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_wb_path(
        context: u64,
        port: u64,
        index: i32,
        buffer: *mut u8,
        capacity: usize,
        length: *mut usize,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_wb_port_drop(context: u64, port: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_wb_object_new(
        context: u64,
        kind: i32,
        port: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> u64;
    pub fn sdk_wb_object_text(context: u64, object: u64) -> *const c_char;
    pub fn sdk_wb_object_attach(
        context: u64,
        object: u64,
        base: *mut c_void,
        handle: *mut c_void,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_wb_object_cancel(context: u64, object: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_wb_object_remove(context: u64, object: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_wb_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_dir_open(context: u64, path: *const u8, error: *mut SdkError) -> u64;
    pub fn sdk_dir_next(
        context: u64,
        directory: u64,
        entry: *mut SdkEntry,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_dir_close(context: u64, directory: u64, error: *mut SdkError) -> c_int;
    pub fn sdk_entry_info(
        context: u64,
        path: *const u8,
        entry: *mut SdkEntry,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_make_dir(context: u64, path: *const u8, error: *mut SdkError) -> c_int;
    pub fn sdk_delete(context: u64, path: *const u8, error: *mut SdkError) -> c_int;
    pub fn sdk_rename(context: u64, from: *const u8, to: *const u8, error: *mut SdkError) -> c_int;
    pub fn sdk_cwd_get(context: u64, out: *mut u8, capacity: usize, error: *mut SdkError) -> i64;
    pub fn sdk_cwd_set(context: u64, path: *const u8, error: *mut SdkError) -> c_int;
    pub fn sdk_var_get(
        context: u64,
        name: *const u8,
        out: *mut u8,
        capacity: usize,
        scope: i32,
        error: *mut SdkError,
    ) -> i64;
    pub fn sdk_var_set(
        context: u64,
        name: *const u8,
        value: *const u8,
        length: usize,
        scope: i32,
        error: *mut SdkError,
    ) -> c_int;
    pub fn sdk_var_delete(context: u64, name: *const u8, scope: i32, error: *mut SdkError)
    -> c_int;
    pub fn sdk_callback(
        context: u64,
        callback: SdkCallback,
        user_data: *mut c_void,
        input: u64,
        output: *mut u64,
        error: *mut SdkError,
    ) -> c_int;

    pub fn sdk_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_timer_layout(values: *mut u64, capacity: usize) -> usize;
    pub fn sdk_device_base(context: u64, device: u64) -> *mut c_void;
    pub fn sdk_scalar(signed: i32, unsigned: u32, pointer: usize, wide: u64, size: usize) -> u64;
}
