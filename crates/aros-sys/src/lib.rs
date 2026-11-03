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

/// Callback run by [`sdk_callback`] on the owner task.
///
/// It receives the `user_data` pointer given to `sdk_callback` and the `input` value, and returns the
/// output value that `sdk_callback` stores. It runs synchronously inside the `sdk_callback` call.
/// It must return normally; it must not unwind or jump out of the call.
pub type SdkCallback = unsafe extern "C" fn(*mut c_void, u64) -> u64;

unsafe extern "C" {
    // Native bridge runtime. The bridge is implemented in `native/sdk.c` and the other `native/*.c`
    // files; every function below is the Rust declaration of one C function with the same name.
    // Conventions that hold for the whole interface:
    //  - A handle is a nonzero `u64` token issued by the bridge. It is valid only for the runtime that
    //    issued it and only until it is released or `sdk_end` runs. A stale, foreign or wrong-kind token
    //    is refused, it is not dereferenced.
    //  - `context` is the key from `sdk_context` or `sdk_claim_context`.
    //  - Functions that return a handle return 0 on failure. Functions that return `c_int` return 0 on
    //    success and -1 on failure unless their own documentation says otherwise.
    //  - `error` may be null. When it is not null it is cleared on entry and filled on failure.
    //  - Path and name arguments are byte strings and must be NUL terminated within 128 bytes (127
    //    payload bytes). Other byte arguments are given with an explicit length and are not
    //    NUL terminated unless stated.
    /// Starts the native runtime for the current task, which becomes the owner task.
    ///
    /// The native `main` calls this once, before it calls the Rust entry point `rust_sdk_main`; the safe
    /// crates never call it. `argv` is kept and later served by [`sdk_arg_count`] and [`sdk_arg`].
    ///
    /// Returns 0 on success, 10 when the arguments are refused (`argc` outside 1..=32, a null `argv` or
    /// null element, an element of 4096 bytes or more, or more than 4096 bytes in total including the
    /// terminators), and 20 when the runtime cannot start: it already started, is active or is closing
    /// (a second call after `sdk_end` also returns 20), the Exec or DOS library is not the expected
    /// version, `dos.library` cannot be opened, or the token space or the registry pool cannot be created.
    ///
    /// # Safety
    ///
    /// `argv` must point to `argc` pointers, each to a NUL-terminated string, and the strings must stay
    /// valid until `sdk_end` has returned. Call it at most once per process, on the task that is to own
    /// the runtime.
    pub fn sdk_begin(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// Releases every resource the program still holds and stops the runtime.
    ///
    /// The remaining native objects are released in a fixed order: directories, the current directory
    /// changed by `sdk_cwd_set`, Workbench objects and ports, icons, locale catalogs then locales, asl
    /// requesters, windows, public screens, rastports, bitmaps, I/O requests, devices, messages, files,
    /// libraries, message ports, signals, allocator blocks, then `dos64.library` (ABI-v1 only) and
    /// `dos.library`. Afterwards every handle and the context key are invalid, so later calls with the old
    /// key fail the context check (`ERROR_KIND_OWNER`).
    ///
    /// Returns 0 when the teardown was clean and 20 when the runtime is not active, is already closing, the
    /// caller is not the owner task, or a release failed (for example a file that could not be closed).
    /// The native `main` calls it after `rust_sdk_main` returns; the safe crates never call it.
    ///
    /// # Safety
    ///
    /// Call it only on the owner task, once, with no native object still in use. Nothing created from the
    /// runtime (handles, pointers returned by the `*_ptr` functions, blocks from `sdk_alloc`) may be used
    /// after it returns.
    pub fn sdk_end() -> c_int;
    /// Returns the context key, or 0 when there is none for this caller.
    ///
    /// The result is nonzero only while the runtime is active and not closing and the calling task is the
    /// owner task. It does not claim the key, so it can be called repeatedly; use [`sdk_claim_context`] to
    /// take the single claim.
    ///
    /// # Context check
    ///
    /// Every function below that takes `context` first fails with `ERROR_KIND_OWNER` (4) unless `context`
    /// equals this key, the runtime is active and not closing, and the caller is the owner task. This is
    /// how task affinity is enforced: a handle can only be used on the task that ran `sdk_begin`. Each
    /// such refusal is counted in `SdkStats::refusals`.
    ///
    /// Other failure classes used by the bridge: `ERROR_KIND_NATIVE` (1) is a failed operating system
    /// call (`native` is the DOS or Exec error code) or lack of memory; `ERROR_KIND_INPUT` (2) is a
    /// rejected argument; `ERROR_KIND_LIMIT` (3) is a bridge limit or a value the call cannot represent;
    /// `ERROR_KIND_STATE` (5) is an unknown, stale or wrong-state handle.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Call it on the task whose key is wanted; on any other task it returns 0.
    pub fn sdk_context() -> u64;
    /// Returns the context key once and 0 on every later call.
    ///
    /// It succeeds only when [`sdk_context`] would return the key and no earlier call has claimed it. The
    /// Rust `dispatch` function uses it so that the application function is entered once and a nested
    /// dispatch is refused.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Call it on the owner task.
    pub fn sdk_claim_context() -> u64;
    /// Returns the number of program arguments passed to `sdk_begin`, including the program name.
    ///
    /// Returns 0 when the context check fails (see [`sdk_context`]), which cannot be told apart from an
    /// empty list; `sdk_begin` guarantees at least one argument.
    ///
    /// # Safety
    ///
    /// `context` must be the current context key and the call must be on the owner task, otherwise the
    /// result is 0.
    pub fn sdk_arg_count(context: u64) -> usize;
    /// Returns argument `index` and stores its length in `length`.
    ///
    /// The pointer is the argument string given to `sdk_begin` (the C storage keeps its NUL terminator),
    /// and `*length` is its length in bytes without the terminator. The bytes are not converted to UTF-8.
    /// Returns null, leaving `length` unwritten, when the context check fails (see [`sdk_context`]),
    /// `length` is null or `index` is not below [`sdk_arg_count`]. No error record is filled.
    ///
    /// # Safety
    ///
    /// `length` must be valid for a write of one `usize`. The returned pointer is borrowed from the
    /// `argv` of `sdk_begin` and is valid only until `sdk_end`; do not write through it.
    pub fn sdk_arg(context: u64, index: usize, length: *mut usize) -> *const u8;
    /// Allocates `size` bytes with the given alignment from Exec memory and returns a pointer to them.
    ///
    /// The memory is not initialised. `alignment` must be a power of two of at most 4096; an alignment
    /// below 8 is treated as 8. A `size` of 0 returns a valid pointer to a one-byte block. Returns null,
    /// and counts a refusal in `SdkStats::refusals`, when the runtime is not active, is closing or the
    /// caller is not the owner task, when the alignment or size is invalid or overflows, when called while
    /// `sdk_diagnostic` is running, or when memory is exhausted. No context key is taken; the owner task
    /// is checked directly.
    ///
    /// Free the block with [`sdk_dealloc`] using the same `size` and `alignment`. Blocks that are still
    /// allocated at `sdk_end` are freed there. This is the entry point of the Rust `ExecAllocator`.
    ///
    /// # Safety
    ///
    /// Call it only on the owner task while the runtime is active. The returned pointer is valid for
    /// `size` bytes until freed and must not be freed any other way.
    pub fn sdk_alloc(size: usize, alignment: usize) -> *mut c_void;
    /// Frees a block returned by [`sdk_alloc`].
    ///
    /// `pointer`, `size` and `alignment` must be exactly the values of the allocation. A pointer the
    /// bridge does not know, a size or alignment that differs from the allocation, or a call from another
    /// task or outside the active runtime is refused: it is counted in `SdkStats::refusals` and nothing is
    /// freed. It returns nothing and takes no error record.
    ///
    /// # Safety
    ///
    /// Call it only on the owner task. After a successful free the pointer must not be used again, and a
    /// block must not be freed twice.
    pub fn sdk_dealloc(pointer: *mut c_void, size: usize, alignment: usize);
    /// Writes a one-line diagnostic to the Exec debug output (`RawPutChar`).
    ///
    /// The line is the first `length` bytes of the label (at most 230; the rest is dropped), a space, the
    /// decimal value of the code and a newline. A null `bytes` writes only the code. The label is bytes,
    /// not text, and is not NUL terminated. It uses a fixed 256-byte stack buffer and does not allocate,
    /// and the bridge refuses [`sdk_alloc`] while it runs.
    ///
    /// The third parameter is named `context` in this declaration but it is the numeric code printed after
    /// the label (`code` in `native/sdk.h`); it is not checked as a context key. The call performs no
    /// context or task check and fills no error record. The Rust `Context::diagnostic` passes its `code`.
    ///
    /// # Safety
    ///
    /// `bytes` must be null or valid for reads of `length` bytes.
    pub fn sdk_diagnostic(bytes: *const u8, length: usize, context: u64);
    /// Reports a fatal condition, releases everything and ends the program with exit code 20. It never
    /// returns.
    ///
    /// The first call writes `ami-rust fatal <reason>` through the diagnostic output (the parameter is
    /// named `context` in this declaration but it is the reason code, `reason` in the C source). If the
    /// runtime is active and the caller is the owner task, it then performs the same cleanup as
    /// `sdk_end` and leaves through `_Exit(20)`. A second call prints `ami-rust nested fatal` first. A call
    /// made while cleanup is already running writes a fixed message and either resumes the cleanup or
    /// exits with 20. The Rust panic handler of `entry!` and the allocation-failure path call it.
    ///
    /// # Safety
    ///
    /// Call it only to end the program: no destructor or Rust frame runs afterwards.
    pub fn sdk_fatal(context: u64) -> !;
    /// Returns a copy of the bridge's resource counters.
    ///
    /// The record counts live blocks, the backing charge and its peak, and the live number of each handle
    /// kind, plus `refusals`, the number of calls the bridge has refused. The call has no context or task
    /// check, fills no error record and does not allocate.
    ///
    /// # Safety
    ///
    /// No pointer is involved. The values are meaningful only between `sdk_begin` and `sdk_end`.
    pub fn sdk_stats() -> SdkStats;

    // Exec libraries.
    /// Opens the shared library `name` (Exec `OpenLibrary`) and returns a handle for it.
    ///
    /// `name` is a NUL-terminated byte string of at most 127 bytes, such as `intuition.library`.
    /// `minimum_version` is passed to `OpenLibrary`. Returns 0 on failure: `ERROR_KIND_INPUT` for a missing
    /// or unterminated name, `ERROR_KIND_NATIVE` with `native` 0 when the library cannot be opened,
    /// `ERROR_KIND_LIMIT` when the registry is full.
    ///
    /// Release the handle with [`sdk_library_close`]; a handle that is still open at `sdk_end` is closed
    /// there. Use [`sdk_library_base`] to get the library base pointer.
    ///
    /// # Safety
    ///
    /// `name` must be valid for reads up to its NUL (within 128 bytes) and `error` must be null or valid
    /// for a write of an `SdkError`.
    pub fn sdk_library_open(
        context: u64,
        name: *const u8,
        minimum_version: u16,
        error: *mut SdkError,
    ) -> u64;
    /// Returns the library base pointer of an open library handle.
    ///
    /// The pointer is what the generated raw library bindings take. It stays valid until the handle is
    /// closed with [`sdk_library_close`] and must be used only on the owner task. Returns null when the
    /// context check fails or the handle is unknown. No error record is filled, but the refusal is counted.
    ///
    /// # Safety
    ///
    /// Do not use the pointer after the handle is closed, from another task, or for a library other than
    /// the one that was opened.
    pub fn sdk_library_base(context: u64, library: u64) -> *mut c_void;
    /// Closes a library opened with [`sdk_library_open`] (Exec `CloseLibrary`).
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle). The handle is
    /// forgotten before the library is closed, and the base pointer from [`sdk_library_base`] must not be
    /// used afterwards.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Close each handle once.
    pub fn sdk_library_close(context: u64, library: u64, error: *mut SdkError) -> c_int;

    // DOS files and the standard streams. A file is closed with `sdk_file_close`.
    /// Opens the DOS file `path` and returns a handle for it.
    ///
    /// `path` is a NUL-terminated byte string of at most 127 bytes. `mode` is 0 to open an existing file
    /// for reading (`MODE_OLDFILE`), 1 to create a file or truncate an existing one (`MODE_NEWFILE`) or 2
    /// to open for reading and writing (`MODE_READWRITE`); any other value is `ERROR_KIND_INPUT`. Returns 0
    /// on failure; for a DOS failure `error.kind` is `ERROR_KIND_NATIVE` and `native` is the `IoErr` code.
    ///
    /// Release it with [`sdk_file_close`]; a file still open at `sdk_end` is closed there.
    ///
    /// # Safety
    ///
    /// `path` must be valid for reads up to its NUL (within 128 bytes) and `error` must be null or valid
    /// for a write of an `SdkError`.
    pub fn sdk_file_open(context: u64, path: *const u8, mode: i32, error: *mut SdkError) -> u64;
    /// Closes a file opened with [`sdk_file_open`].
    ///
    /// Returns 0 on success and -1 on failure. The handle is forgotten before DOS `Close` runs, so after
    /// an `ERROR_KIND_NATIVE` failure (`native` is the `IoErr` code) the handle is already gone and the
    /// close cannot be retried; an unknown handle is `ERROR_KIND_STATE`. The standard stream handles from
    /// [`sdk_stdout`] and [`sdk_stderr`] are not files and are refused with `ERROR_KIND_STATE`.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_file_close(context: u64, file: u64, error: *mut SdkError) -> c_int;
    /// Reads from or writes to a file or a standard stream with one DOS call, and returns the number of
    /// bytes transferred.
    ///
    /// `file` is a handle from [`sdk_file_open`], [`sdk_stdout`] or [`sdk_stderr`]. `write` is 0 to read
    /// into `buffer` and 1 to write from it; `length` is the number of bytes, at most 65536. `buffer` may
    /// be null only when `length` is 0. The result is the count DOS reported, which may be smaller than
    /// `length`; a read that returns 0 means end of file. It is -1 on failure: `ERROR_KIND_INPUT` for a
    /// length over 65536, a null buffer with a nonzero length or a `write` other than 0 or 1;
    /// `ERROR_KIND_STATE` for an unknown handle, a read on a standard stream, or a write to the error
    /// stream from a task that is not a DOS process; `ERROR_KIND_NATIVE` when DOS or the stream fails
    /// (`native` is the `IoErr` code, or 0 when no output stream exists).
    ///
    /// The output stream is `Output()` of the owner task and the error stream is `pr_CES`, or `pr_COS` if
    /// that is null, resolved on every write and never closed.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for `length` bytes: writable for a read, readable for a write (the pointer
    /// is `*mut` for both, a write does not modify it). `error` must be null or valid for a write.
    pub fn sdk_file_io(
        context: u64,
        file: u64,
        buffer: *mut u8,
        length: usize,
        write: i32,
        error: *mut SdkError,
    ) -> i64;
    /// Returns the handle of the program's standard output, or 0 when the context check fails.
    ///
    /// The handle is a fixed token. It can only be written, through [`sdk_file_io`]; it is not a file and is
    /// never closed.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Use the handle only on the owner task.
    pub fn sdk_stdout(context: u64) -> u64;
    /// Returns the handle of the program's standard error stream, or 0.
    ///
    /// It is 0 when the context check fails or when the owner task is not a DOS process (only a process
    /// has the error and output streams). The handle can only be written, through [`sdk_file_io`], and is
    /// never closed. Each write uses the process error stream (`pr_CES`), or its output stream (`pr_COS`)
    /// when none is set.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Use the handle only on the owner task.
    pub fn sdk_stderr(context: u64) -> u64;

    // Exec signals. The bridge keeps at most 32 signal slots, which message ports and device reply ports
    // also use.
    /// Allocates an Exec signal bit (`AllocSignal(-1)`) on the owner task and returns a handle for it.
    ///
    /// Returns 0 on failure: `ERROR_KIND_LIMIT` when all 32 signal slots are in use (`native` is 32) or the
    /// token space is exhausted, `ERROR_KIND_NATIVE` when Exec has no free signal bit. Release it with
    /// [`sdk_signal_drop`]; a signal left allocated at `sdk_end` is freed there.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_signal_new(context: u64, error: *mut SdkError) -> u64;
    /// Frees a signal allocated with [`sdk_signal_new`].
    ///
    /// The bit is cleared (`SetSignal`) and freed (`FreeSignal`). Returns 0 on success and -1 on failure
    /// (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Do not wait on the signal afterwards.
    pub fn sdk_signal_drop(context: u64, signal: u64, error: *mut SdkError) -> c_int;
    /// Sets the signal bit on the owner task (`Signal`).
    ///
    /// The call signals the calling task itself, so a following [`sdk_signal_wait`] on the same handle
    /// returns at once. Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_signal_post(context: u64, signal: u64, error: *mut SdkError) -> c_int;
    /// Blocks the owner task until the signal bit of the handle is set (Exec `Wait` on that bit).
    ///
    /// Returns 0 once it returned and -1 on failure (`ERROR_KIND_STATE` for an unknown handle). Without a
    /// call to [`sdk_signal_post`] (or an external source of the bit) the call does not return.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. The call blocks the task.
    pub fn sdk_signal_wait(context: u64, signal: u64, error: *mut SdkError) -> c_int;
    /// Blocks the owner task until any bit of `mask` is set (Exec `Wait`) and stores the signals that
    /// caused the return in `received`.
    ///
    /// `mask` must not be 0 and `received` must not be null, otherwise `ERROR_KIND_INPUT`. The bits are
    /// not required to belong to bridge handles; the mask normally comes from [`sdk_device_signal_mask`],
    /// `SdkWindowInfo::signal_mask` or [`sdk_wb_port_mask`], possibly combined. Returns 0 on success and -1 on
    /// failure. If no source can set a bit of `mask` the call does not return.
    ///
    /// # Safety
    ///
    /// `received` must be valid for a write of a `u32` and `error` must be null or valid for a write.
    pub fn sdk_signal_wait_mask(
        context: u64,
        mask: u32,
        received: *mut u32,
        error: *mut SdkError,
    ) -> c_int;

    // Message ports and messages. A message is a bridge-owned record of up to 256 payload bytes; it is
    // queued on a port with `sdk_port_put`, taken with `sdk_port_receive` and answered with
    // `sdk_message_reply`.
    /// Creates an Exec message port (`CreateMsgPort`) and returns a handle for it.
    ///
    /// The port uses one of the 32 signal slots. Returns 0 on failure: `ERROR_KIND_LIMIT` when the slots
    /// or the token space are exhausted, `ERROR_KIND_NATIVE` when the port cannot be created. Release it
    /// with [`sdk_port_drop`]; a port left at `sdk_end` is deleted there.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_port_new(context: u64, error: *mut SdkError) -> u64;
    /// Deletes a port created with [`sdk_port_new`] (`DeleteMsgPort`) and frees its signal slot.
    ///
    /// Messages still queued on the port are taken off it and become idle again; messages that named this
    /// port as their reply port lose that reply port. Returns 0 on success and -1 on failure
    /// (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_port_drop(context: u64, port: u64, error: *mut SdkError) -> c_int;
    /// Creates a message holding a copy of `length` payload bytes and returns a handle for it.
    ///
    /// `length` is at most 256, otherwise `ERROR_KIND_INPUT`; `bytes` may be null only when `length` is 0.
    /// The bytes are not NUL terminated. The new message is idle and belongs to no port. Returns 0 on
    /// failure. Release it with [`sdk_message_drop`]; a message left at `sdk_end` is freed there.
    ///
    /// # Safety
    ///
    /// `bytes` must be valid for reads of `length` bytes when `length` is nonzero, and `error` must be
    /// null or valid for a write of an `SdkError`.
    pub fn sdk_message_new(
        context: u64,
        bytes: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> u64;
    /// Frees a message created with [`sdk_message_new`], first removing it from the port it is queued on.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_message_drop(context: u64, message: u64, error: *mut SdkError) -> c_int;
    /// Copies the payload of a message into `output` and returns its length in bytes.
    ///
    /// The whole payload is copied; the result is the payload length (0 to 256). Returns -1 on failure:
    /// `ERROR_KIND_STATE` for an unknown handle or a message that is currently queued on a port,
    /// `ERROR_KIND_INPUT` when `capacity` is smaller than the payload or `output` is null for a nonempty
    /// payload.
    ///
    /// # Safety
    ///
    /// `output` must be valid for writes of `capacity` bytes (unless the payload is empty) and `error`
    /// must be null or valid for a write of an `SdkError`.
    pub fn sdk_message_copy(
        context: u64,
        message: u64,
        output: *mut u8,
        capacity: usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Queues `message` on `port` (Exec `PutMsg`) with `reply_port` as the reply port.
    ///
    /// `message` must be idle, that is neither queued nor waiting for a reply. `port` and `reply_port` are
    /// both required handles from [`sdk_port_new`]; a 0 or unknown reply port is refused. Returns 0 on success and -1 on failure (`ERROR_KIND_STATE`
    /// for an unknown port, reply port or message, or a message that is not idle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. The message must not be dropped or
    /// copied while it is queued.
    pub fn sdk_port_put(
        context: u64,
        port: u64,
        message: u64,
        reply_port: u64,
        error: *mut SdkError,
    ) -> c_int;
    /// Takes `message` from the head of `port` (Exec `GetMsg`) if it is waiting there.
    ///
    /// Returns 1 when the message was taken and 0 when the port has no message (not an error). The bridge
    /// can take only its own message record, so a head message other than `message`, or a `message`
    /// that is not queued on this `port`, is -1 with `ERROR_KIND_STATE`, as is an unknown handle. A message
    /// taken after [`sdk_port_put`] can be answered with [`sdk_message_reply`]; a message taken from its
    /// reply port after the reply is idle again.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_port_receive(context: u64, port: u64, message: u64, error: *mut SdkError) -> c_int;
    /// Replies to a message that was received from a port (Exec `ReplyMsg`).
    ///
    /// The message is queued on its reply port and is taken there with [`sdk_port_receive`]. Returns 0 on
    /// success and -1 on failure (`ERROR_KIND_STATE` for an unknown message, a message that was not
    /// received after a put, a message already queued, or a reply port that no longer exists).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_message_reply(context: u64, message: u64, error: *mut SdkError) -> c_int;

    // Exec devices and I/O requests. A device handle owns an open device and one reply port; every
    // request of the device completes on that port. A device cannot be closed while it has requests.
    /// Opens an Exec device unit (`OpenDevice`) and returns a handle for it.
    ///
    /// `name` is the NUL-terminated device name (at most 127 bytes, for example `timer.device`); `unit`
    /// and `flags` are passed to `OpenDevice`. The call also creates the device's reply port, which uses
    /// one of the 32 signal slots. Returns 0 on failure: `ERROR_KIND_INPUT` for a bad name,
    /// `ERROR_KIND_NATIVE` with the `OpenDevice` error in `native` (or `ERROR_NO_FREE_STORE`),
    /// `ERROR_KIND_LIMIT` when the slots or the registry are exhausted.
    ///
    /// Release it with [`sdk_device_close`] after all its requests are dropped; a device left open at
    /// `sdk_end` is closed there.
    ///
    /// # Safety
    ///
    /// `name` must be valid for reads up to its NUL (within 128 bytes) and `error` must be null or valid
    /// for a write of an `SdkError`.
    pub fn sdk_device_open(
        context: u64,
        name: *const u8,
        unit: u32,
        flags: u32,
        error: *mut SdkError,
    ) -> u64;
    /// Closes a device opened with [`sdk_device_open`] (`CloseDevice`) and deletes its reply port.
    ///
    /// Returns 0 on success and -1 on failure. `ERROR_KIND_STATE` is returned for an unknown handle and
    /// also when requests created with [`sdk_io_new`] are still alive on the device; drop them first. The
    /// base pointer from [`sdk_device_base`] must not be used afterwards.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_device_close(context: u64, device: u64, error: *mut SdkError) -> c_int;
    /// Returns the signal mask of the device's reply port, `1 << signal bit`, or 0.
    ///
    /// It returns 0 when the context check fails or the handle is unknown. Pass it to
    /// [`sdk_signal_wait_mask`] to wait for a request of the device to complete. No error record is filled.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Use it on the owner task only.
    pub fn sdk_device_signal_mask(context: u64, device: u64) -> u32;
    /// Creates an I/O request for a device and returns a handle for it.
    ///
    /// `kind` is `IO_KIND_STANDARD` (0, an `IOStdReq` with a data area) or `IO_KIND_TIMER` (1, a
    /// `timerequest`); anything else is `ERROR_KIND_INPUT`. `capacity` is the size in bytes of the
    /// bridge-owned data area, at most 65536; it must be 0 for a timer request. The request replies to the
    /// device's reply port. Returns 0 on failure (`ERROR_KIND_STATE` for an unknown device,
    /// `ERROR_KIND_INPUT`, `ERROR_KIND_NATIVE` with `ERROR_NO_FREE_STORE`, or `ERROR_KIND_LIMIT`).
    ///
    /// Release it with [`sdk_io_drop`]. A request still alive at `sdk_end` is released there.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_new(
        context: u64,
        device: u64,
        kind: i32,
        capacity: usize,
        error: *mut SdkError,
    ) -> u64;
    /// Frees a request created with [`sdk_io_new`].
    ///
    /// A request that is still pending is aborted and waited for first (`AbortIO`, `WaitIO`), so the call
    /// can block until the device finishes. Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for
    /// an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_drop(context: u64, request: u64, error: *mut SdkError) -> c_int;
    /// Sets the command fields of an idle request before it is performed.
    ///
    /// `command` (at most 0xffff) becomes `io_Command` and `flags` (at most 0xff) becomes `io_Flags`;
    /// `io_Error` is cleared. For a standard request `length` (at most the request's capacity) becomes
    /// `io_Length`, `offset` becomes `io_Offset`, `io_Data` points to the request's own data area and
    /// `io_Actual` is cleared. For a timer request `length` and `offset` must be 0. Violations are
    /// `ERROR_KIND_INPUT`; an unknown request, or one that is pending, is `ERROR_KIND_STATE`.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_prepare(
        context: u64,
        request: u64,
        command: u32,
        flags: u32,
        length: usize,
        offset: u32,
        error: *mut SdkError,
    ) -> c_int;
    /// Copies `length` bytes into the data area of an idle standard request.
    ///
    /// `length` must not exceed the capacity given to [`sdk_io_new`] and `data` may be null only for
    /// length 0, otherwise `ERROR_KIND_INPUT`. A timer request, a pending request or an unknown handle is
    /// `ERROR_KIND_STATE`. The bytes are not NUL terminated. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `data` must be valid for reads of `length` bytes when `length` is nonzero, and `error` must be
    /// null or valid for a write of an `SdkError`.
    pub fn sdk_io_write(
        context: u64,
        request: u64,
        data: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Copies the bytes a device produced out of an idle standard request and returns their count.
    ///
    /// The count is the request's `io_Actual`, limited to its capacity, and all of those bytes are copied.
    /// Returns -1 on failure: `ERROR_KIND_INPUT` when `capacity` is smaller than the count or `out` is
    /// null for a nonzero count; `ERROR_KIND_STATE` for a timer request, a pending request or an unknown
    /// handle.
    ///
    /// # Safety
    ///
    /// `out` must be valid for writes of `capacity` bytes, and `error` must be null or valid for a write
    /// of an `SdkError`.
    pub fn sdk_io_read(
        context: u64,
        request: u64,
        out: *mut u8,
        capacity: usize,
        error: *mut SdkError,
    ) -> i64;
    /// Sets the time value of an idle timer request (`tr_time`).
    ///
    /// `micros` must be below 1,000,000, otherwise `ERROR_KIND_INPUT`. A standard request, a pending
    /// request or an unknown handle is `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure. The
    /// size of the native time fields is checked by [`sdk_timer_layout`]; both ABIs use two 32-bit fields.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_set_time(
        context: u64,
        request: u64,
        seconds: u32,
        micros: u32,
        error: *mut SdkError,
    ) -> c_int;
    /// Reads the time value of an idle timer request into `seconds` and `micros`.
    ///
    /// Both pointers must be non-null, otherwise `ERROR_KIND_INPUT`. A standard request, a pending request
    /// or an unknown handle is `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `seconds` and `micros` must be valid for writes of a `u32`, and `error` must be null or valid for a
    /// write of an `SdkError`.
    pub fn sdk_io_time(
        context: u64,
        request: u64,
        seconds: *mut u32,
        micros: *mut u32,
        error: *mut SdkError,
    ) -> c_int;
    /// Reads the outcome of an idle request that has been performed.
    ///
    /// `device_error` receives `io_Error` as a signed byte (0 means success) and `actual` receives
    /// `io_Actual` for a standard request or 0 for a timer request. Both pointers must be non-null,
    /// otherwise `ERROR_KIND_INPUT`. A pending request or an unknown handle is `ERROR_KIND_STATE`. Returns
    /// 0 on success and -1 on failure; a nonzero `device_error` is not a bridge failure.
    ///
    /// # Safety
    ///
    /// `device_error` and `actual` must be valid for writes, and `error` must be null or valid for a write
    /// of an `SdkError`.
    pub fn sdk_io_result(
        context: u64,
        request: u64,
        device_error: *mut i32,
        actual: *mut u32,
        error: *mut SdkError,
    ) -> c_int;
    /// Performs an idle request synchronously (`DoIO`) and stores the device's result in `device_error`.
    ///
    /// `device_error` receives the signed byte `DoIO` returned (0 is success). The request stays idle
    /// afterwards, so [`sdk_io_result`] and [`sdk_io_read`] can be used. The call blocks the owner task
    /// until the device finishes. `device_error` null is `ERROR_KIND_INPUT`; a pending request or an
    /// unknown handle is `ERROR_KIND_STATE`. Returns 0 when the request was run and -1 on failure.
    ///
    /// # Safety
    ///
    /// `device_error` must be valid for a write of an `i32`, and `error` must be null or valid for a write
    /// of an `SdkError`. The request must have been set up with [`sdk_io_prepare`] (or [`sdk_io_set_time`]).
    pub fn sdk_io_do(
        context: u64,
        request: u64,
        device_error: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    /// Starts an idle request asynchronously (`SendIO`) and marks it pending.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for a pending request or an unknown
    /// handle). The request completes on the device's reply port, whose signal is
    /// [`sdk_device_signal_mask`]. A pending request must be finished with [`sdk_io_wait`], or dropped
    /// with [`sdk_io_drop`], before it can be used again.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_send(context: u64, request: u64, error: *mut SdkError) -> c_int;
    /// Tests whether a pending request has completed (`CheckIO`).
    ///
    /// Returns 1 when it has completed, 0 when it is still in progress and -1 on failure
    /// (`ERROR_KIND_STATE` for a request that is not pending or an unknown handle). A completed request
    /// stays pending for the bridge until [`sdk_io_wait`] reclaims it.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_check(context: u64, request: u64, error: *mut SdkError) -> c_int;
    /// Waits for a pending request to finish (`WaitIO`), stores its result and makes it idle again.
    ///
    /// `device_error` receives the signed byte `WaitIO` returned (0 is success); it must be non-null,
    /// otherwise `ERROR_KIND_INPUT`. A request that is not pending or an unknown handle is
    /// `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure. The call blocks the owner task until the
    /// request has completed.
    ///
    /// # Safety
    ///
    /// `device_error` must be valid for a write of an `i32`, and `error` must be null or valid for a write
    /// of an `SdkError`.
    pub fn sdk_io_wait(
        context: u64,
        request: u64,
        device_error: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    /// Asks the device to abort a pending request (`AbortIO`).
    ///
    /// The request stays pending: call [`sdk_io_wait`] afterwards to reclaim it. Returns 0 when the abort
    /// was requested and -1 on failure (`ERROR_KIND_STATE` for a request that is not pending or an unknown
    /// handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_io_abort(context: u64, request: u64, error: *mut SdkError) -> c_int;
    /// Moves the position of an open file and stores the new absolute position in `position`.
    ///
    /// `whence` is 0 for the start, 1 for the current position and 2 for the end; `offset` is signed and
    /// must not be negative with whence 0 (`ERROR_KIND_INPUT`, which also covers any other `whence` and a
    /// null `position`). An unknown handle is `ERROR_KIND_STATE`.
    ///
    /// ABI difference: on ABI-v1 with `dos64.library` (opened on first use) the 64-bit calls are used and
    /// the offset and position are full 64-bit. Without it, and always on ABI-v11, the 32-bit `Seek` is
    /// used: an offset outside the `i32` range, or a resulting position of 2 GiB or more, is refused with
    /// `ERROR_KIND_LIMIT` (`native` is `i32::MAX`) instead of wrapping. DOS failures are `ERROR_KIND_NATIVE`
    /// with the `IoErr` code. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `position` must be valid for a write of a `u64`, and `error` must be null or valid for a write of
    /// an `SdkError`.
    pub fn sdk_file_seek(
        context: u64,
        file: u64,
        whence: i32,
        offset: i64,
        position: *mut u64,
        error: *mut SdkError,
    ) -> c_int;
    /// Stores the current absolute position of an open file in `position`.
    ///
    /// A null `position` is `ERROR_KIND_INPUT` and an unknown handle is `ERROR_KIND_STATE`. The ABI
    /// difference is the one of [`sdk_file_seek`]: 64-bit with `dos64.library` on ABI-v1, otherwise the
    /// 32-bit call, which refuses a position of 2 GiB or more with `ERROR_KIND_LIMIT`. Returns 0 on success
    /// and -1 on failure.
    ///
    /// # Safety
    ///
    /// `position` must be valid for a write of a `u64`, and `error` must be null or valid for a write of
    /// an `SdkError`.
    pub fn sdk_file_position(
        context: u64,
        file: u64,
        position: *mut u64,
        error: *mut SdkError,
    ) -> c_int;
    /// Stores the size in bytes of an open file in `size`.
    ///
    /// A null `size` is `ERROR_KIND_INPUT` and an unknown handle is `ERROR_KIND_STATE`. ABI difference: on
    /// ABI-v1 with `dos64.library` the size is 64-bit. Without it, and always on ABI-v11, the size comes
    /// from a 32-bit `ExamineFH`, and a size of `0x7fffffff` bytes or more is refused with
    /// `ERROR_KIND_LIMIT` (`native` is `i32::MAX`) because it cannot be reported exactly. A DOS failure is
    /// `ERROR_KIND_NATIVE`. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `size` must be valid for a write of a `u64`, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_file_size(context: u64, file: u64, size: *mut u64, error: *mut SdkError) -> c_int;
    // graphics.library objects. The bridge owns the RastPort memory and the buffers for area fills,
    // tracks bitmaps, and leaves all drawing to the raw library calls on the pointers it returns.
    /// Allocates a zeroed `RastPort` that the bridge owns and returns a handle for it.
    ///
    /// The memory is not initialised by `InitRastPort`; the caller does that through the library on the
    /// pointer from [`sdk_gfx_rastport_ptr`]. Returns 0 on failure (`ERROR_KIND_NATIVE` with
    /// `ERROR_NO_FREE_STORE`, or `ERROR_KIND_LIMIT`). Release it with [`sdk_gfx_rastport_drop`]; a
    /// rastport left at `sdk_end` is freed there.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_gfx_rastport_new(context: u64, error: *mut SdkError) -> u64;
    /// Returns the pointer to the `RastPort` memory of a rastport handle, or null.
    ///
    /// Null means the context check failed or the handle is unknown. No error record is filled. The
    /// pointer is valid until [`sdk_gfx_rastport_drop`].
    ///
    /// # Safety
    ///
    /// Use the pointer only on the owner task and not after the handle is dropped.
    pub fn sdk_gfx_rastport_ptr(context: u64, rastport: u64) -> *mut c_void;
    /// Stores `bitmap` in the `BitMap` field of the rastport.
    ///
    /// The bitmap pointer is not checked or retained by the bridge; it normally comes from `AllocBitMap`.
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `bitmap` must be a valid `BitMap` that outlives every use of the rastport, and `error` must be null
    /// or valid for a write of an `SdkError`.
    pub fn sdk_gfx_rastport_set_bitmap(
        context: u64,
        rastport: u64,
        bitmap: *mut c_void,
        error: *mut SdkError,
    ) -> c_int;
    /// Allocates the buffers an area fill needs for a rastport.
    ///
    /// It allocates an `AreaInfo`, a vector buffer of `max_vectors * 5` bytes, a `TmpRas` and a raster of
    /// `RASSIZE(width, height)` bytes, all zeroed. `max_vectors` must be 3 to 1024 and `width` and `height`
    /// 1 to 32767, otherwise `ERROR_KIND_INPUT`. It can run once per rastport: an unknown handle or a
    /// rastport that is already prepared is `ERROR_KIND_STATE`. Lack of memory is `ERROR_KIND_NATIVE` with
    /// `ERROR_NO_FREE_STORE`. Returns 0 on success and -1 on failure.
    ///
    /// The buffers are only allocated. The caller then runs `InitArea` and `InitTmpRas` on them (see
    /// [`sdk_gfx_area_ptr`]) and calls [`sdk_gfx_area_attach`].
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_gfx_area_prepare(
        context: u64,
        rastport: u64,
        max_vectors: i32,
        width: i32,
        height: i32,
        error: *mut SdkError,
    ) -> c_int;
    /// Returns a pointer to one of the area-fill buffers of a prepared rastport.
    ///
    /// `which` is 0 for the `AreaInfo`, 1 for the vector buffer, 2 for the `TmpRas` and 3 for the raster.
    /// Returns null for any other value, for a rastport not yet prepared with [`sdk_gfx_area_prepare`],
    /// when the context check fails or the handle is unknown. No error record is filled. The buffers are
    /// valid until [`sdk_gfx_rastport_drop`].
    ///
    /// # Safety
    ///
    /// Use the pointer only on the owner task and not after the rastport is dropped.
    pub fn sdk_gfx_area_ptr(context: u64, rastport: u64, which: i32) -> *mut c_void;
    /// Returns the size in bytes of an area-fill buffer.
    ///
    /// `which` 1 returns the vector buffer size (`max_vectors * 5`) and 3 the raster size
    /// (`RASSIZE(width, height)`). Every other `which` returns 0, as do a rastport that is not prepared, a
    /// failed context check and an unknown handle.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Use it on the owner task only.
    pub fn sdk_gfx_area_size(context: u64, rastport: u64, which: i32) -> usize;
    /// Links the prepared `AreaInfo` and `TmpRas` into the rastport.
    ///
    /// It sets the `AreaInfo` and `TmpRas` fields of the `RastPort`. Returns 0 on success and -1 on
    /// failure (`ERROR_KIND_STATE` for an unknown handle or a rastport that was not prepared). Call it
    /// after `InitArea` and `InitTmpRas` have been run on the buffers.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. The buffers must have been initialised
    /// by the library first.
    pub fn sdk_gfx_area_attach(context: u64, rastport: u64, error: *mut SdkError) -> c_int;
    /// Frees a rastport and any area buffers that belong to it.
    ///
    /// The `RastPort` memory, `AreaInfo`, vector buffer, `TmpRas` and raster are freed. Returns 0 on
    /// success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Do not use the rastport pointers
    /// afterwards, and do not drop a rastport that a window or a blit still uses.
    pub fn sdk_gfx_rastport_drop(context: u64, rastport: u64, error: *mut SdkError) -> c_int;
    /// Records a bitmap so the bridge can free it if the program does not.
    ///
    /// `base` is the open `graphics.library` base (from [`sdk_library_base`]) and `bitmap` is the pointer
    /// returned by `AllocBitMap`. Both must be non-null, otherwise `ERROR_KIND_INPUT`. Returns a handle, or
    /// 0 on failure. The bridge does not allocate the bitmap and does not own it while the handle exists:
    /// the caller frees it with `FreeBitMap` after [`sdk_gfx_bitmap_release`]. A bitmap still registered at
    /// `sdk_end` is freed there through the library vector.
    ///
    /// # Safety
    ///
    /// `base` and `bitmap` must be valid, and `error` must be null or valid for a write of an `SdkError`.
    /// The library must stay open while the handle exists.
    pub fn sdk_gfx_bitmap_register(
        context: u64,
        base: *mut c_void,
        bitmap: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    /// Forgets a registered bitmap without freeing it.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle). After a
    /// successful release the caller owns the bitmap and frees it with `FreeBitMap`. After a failure it
    /// must not free it, because the bridge may still do so.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_gfx_bitmap_release(context: u64, bitmap: u64, error: *mut SdkError) -> c_int;
    // Intuition windows and public screens. A window handle exists before the window does: it first owns
    // the title text, which Intuition keeps a pointer to, and the opened window is attached afterwards.
    /// Creates a window record that owns a copy of the title text and returns its handle.
    ///
    /// `length` is at most 127 bytes, otherwise `ERROR_KIND_INPUT`, and `text` may be null only for length
    /// 0. The text is not NUL terminated on input; the record stores it with a terminator. No window
    /// exists yet: pass the pointer from [`sdk_intui_title_ptr`] as `WA_Title` to `OpenWindowTagList`, then
    /// call [`sdk_intui_window_attach`], or [`sdk_intui_window_cancel`] if opening failed. Returns 0 on
    /// failure.
    ///
    /// # Safety
    ///
    /// `text` must be valid for reads of `length` bytes when `length` is nonzero, and `error` must be null
    /// or valid for a write of an `SdkError`.
    pub fn sdk_intui_title_new(
        context: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> u64;
    /// Returns a pointer to the NUL-terminated title text stored in a window record, or null.
    ///
    /// Null means the context check failed or the handle is unknown. The pointer is stable until the
    /// record is released with [`sdk_intui_window_close`] or [`sdk_intui_window_cancel`], so Intuition may
    /// keep it. No error record is filled.
    ///
    /// # Safety
    ///
    /// Do not read it after the record is released, and do not write through it.
    pub fn sdk_intui_title_ptr(context: u64, window: u64) -> *const c_char;
    /// Replaces the title text in the record of an attached window.
    ///
    /// The text (at most 127 bytes, `text` null only for length 0; otherwise `ERROR_KIND_INPUT`) is copied
    /// into the same buffer, so the pointer from [`sdk_intui_title_ptr`] stays the same. This does not
    /// tell Intuition: the caller then calls `SetWindowTitles` with that pointer. A record without an
    /// attached window, or an unknown handle, is `ERROR_KIND_STATE`. Returns 0 on success and -1 on
    /// failure.
    ///
    /// # Safety
    ///
    /// `text` must be valid for reads of `length` bytes when `length` is nonzero, and `error` must be null
    /// or valid for a write of an `SdkError`.
    pub fn sdk_intui_window_set_title(
        context: u64,
        window: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Records the opened window in its title record.
    ///
    /// `base` is the open `intuition.library` base and `window` the pointer from `OpenWindowTagList`;
    /// both must be non-null. A null argument, an unknown handle or a record that already has a window is
    /// `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure. From now on the bridge closes the window
    /// (`CloseWindow` through the library vector) in [`sdk_intui_window_close`] or at `sdk_end`.
    ///
    /// # Safety
    ///
    /// `base` and `window` must be the valid library base and a window opened with it, and `error` must
    /// be null or valid for a write of an `SdkError`.
    pub fn sdk_intui_window_attach(
        context: u64,
        window: u64,
        base: *mut c_void,
        native: *mut c_void,
        error: *mut SdkError,
    ) -> c_int;
    /// Discards a window record whose window never opened.
    ///
    /// It is for a record that has no attached window; one with a window, or an unknown handle, is
    /// `ERROR_KIND_STATE`. Nothing is closed. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Intuition must not still hold the
    /// title pointer.
    pub fn sdk_intui_window_cancel(context: u64, window: u64, error: *mut SdkError) -> c_int;
    /// Closes the window of a record and frees the record.
    ///
    /// The record is retired first; if a window is attached it is closed with `CloseWindow` through the
    /// library vector. A record without a window is just freed. Returns 0 on success and -1 on failure
    /// (`ERROR_KIND_STATE` for an unknown handle). The window pointer, its rastport and the title pointer
    /// are invalid afterwards.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Nothing may still use the window or its
    /// rastport.
    pub fn sdk_intui_window_close(context: u64, window: u64, error: *mut SdkError) -> c_int;
    /// Reads the geometry and port information of an attached window into `info`.
    ///
    /// It fills position, size, border widths, mouse position, the size of the window's screen (0 if it has
    /// none), the signal mask of the window's IDCMP port (0 if it has none) and the window's `RastPort`
    /// pointer. A record without a window, an unknown handle or a null `info` is `ERROR_KIND_STATE`.
    /// Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `info` must be valid for a write of an `SdkWindowInfo`, and `error` must be null or valid for a
    /// write of an `SdkError`.
    pub fn sdk_intui_window_info(
        context: u64,
        window: u64,
        info: *mut SdkWindowInfo,
        error: *mut SdkError,
    ) -> c_int;
    /// Takes the next IDCMP message of an attached window, decodes it into `event` and replies to it.
    ///
    /// Returns 1 and fills `event` when a message was waiting, 0 when there is none (or the window has no
    /// IDCMP port), and -1 on failure (`ERROR_KIND_STATE` for a record without a window, an unknown handle
    /// or a null `event`). The message is replied to inside the call, so no Intuition pointer escapes.
    ///
    /// # Safety
    ///
    /// `event` must be valid for a write of an `SdkIntuiEvent`, and `error` must be null or valid for a
    /// write of an `SdkError`.
    pub fn sdk_intui_next_event(
        context: u64,
        window: u64,
        event: *mut SdkIntuiEvent,
        error: *mut SdkError,
    ) -> c_int;
    /// Records a locked public screen so the bridge can unlock it if the program does not.
    ///
    /// `base` is the open `intuition.library` base and `screen` the pointer from `LockPubScreen`; both must
    /// be non-null, otherwise `ERROR_KIND_INPUT`. Returns a handle, or 0 on failure. The bridge does not
    /// lock the screen. A screen still registered at `sdk_end` is unlocked there (`UnlockPubScreen` through
    /// the library vector). Normal release is [`sdk_intui_screen_release`] followed by the caller's own
    /// unlock.
    ///
    /// # Safety
    ///
    /// `base` and `screen` must be valid, and `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_intui_screen_register(
        context: u64,
        base: *mut c_void,
        screen: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    /// Stores the width and height of a registered screen in `width` and `height`.
    ///
    /// An unknown handle, or a null `width` or `height`, is `ERROR_KIND_STATE`. Returns 0 on success and
    /// -1 on failure.
    ///
    /// # Safety
    ///
    /// `width` and `height` must be valid for writes of an `i32`, the screen must still be locked, and
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_intui_screen_size(
        context: u64,
        screen: u64,
        width: *mut i32,
        height: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    /// Forgets a registered screen without unlocking it.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle). After a
    /// successful release the caller owns the lock and calls `UnlockPubScreen`; after a failure it must
    /// not, because the bridge may still do so.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_intui_screen_release(context: u64, screen: u64, error: *mut SdkError) -> c_int;
    /// Copies the Intuition layout oracle values into `values` and returns how many there are.
    ///
    /// The values are computed by the C compiler from the SDK headers: the size, alignment and key offsets
    /// of `SdkWindowInfo` and `SdkIntuiEvent`, the `WA_*` tag numbers, the `IDCMP_*` classes and the mouse
    /// button codes used by the window API. `intuition_layout_values` holds the Rust side to compare with.
    /// The count is always returned; the values are written only when `values` is non-null and `capacity`
    /// is at least the count. No context is needed.
    ///
    /// # Safety
    ///
    /// `values` must be null or valid for writes of `capacity` `u64` values.
    pub fn sdk_intui_layout(values: *mut u64, capacity: usize) -> usize;
    // asl.library file requesters.
    /// Records a file requester so the bridge can free it if the program does not.
    ///
    /// `base` is the open `asl.library` base and `request` the pointer from `AllocAslRequest`; both must be
    /// non-null, otherwise `ERROR_KIND_INPUT`. Returns a handle, or 0 on failure. A requester still
    /// registered at `sdk_end` is freed there (`FreeAslRequest` through the library vector). Normal release
    /// is [`sdk_asl_release`] followed by the caller's own free.
    ///
    /// # Safety
    ///
    /// `base` and `request` must be valid and the request must be a file requester, and `error` must be
    /// null or valid for a write of an `SdkError`.
    pub fn sdk_asl_register(
        context: u64,
        base: *mut c_void,
        request: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    /// Forgets a registered requester without freeing it.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle). After a
    /// successful release the caller frees the requester with `FreeAslRequest`.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_asl_release(context: u64, request: u64, error: *mut SdkError) -> c_int;
    /// Stores in `count` how many paths the last accepted requester call selected.
    ///
    /// It is the length of the multi-selection argument list when there is one, otherwise 1 (the single
    /// drawer and file). An unknown handle or a null `count` is `ERROR_KIND_STATE`. Returns 0 on success
    /// and -1 on failure. It reads the requester's current fields, so call it after `AslRequest` returned
    /// true.
    ///
    /// # Safety
    ///
    /// `count` must be valid for a write of an `i32`, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_asl_count(
        context: u64,
        request: u64,
        count: *mut i32,
        error: *mut SdkError,
    ) -> c_int;
    /// Builds selected path number `index` into `buffer` and stores its length in `length`.
    ///
    /// The path joins the drawer (or the lock of a multi-selected entry) and the file name by DOS rules,
    /// and is written NUL terminated; `*length` excludes the terminator. `capacity` must be at least 2.
    /// Returns 0 on success and -1 on failure: `ERROR_KIND_STATE` for an unknown handle, a null `buffer` or
    /// `length`, a `capacity` under 2 or a negative `index`; `ERROR_KIND_INPUT` for an `index` at or above
    /// the count from [`sdk_asl_count`]; `ERROR_KIND_LIMIT` when the path does not fit in `capacity`.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for writes of `capacity` bytes, `length` for a write of a `usize`, and
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_asl_path(
        context: u64,
        request: u64,
        index: i32,
        buffer: *mut u8,
        capacity: usize,
        length: *mut usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Copies the asl layout oracle values into `values` and returns how many there are.
    ///
    /// The values are the file requester type and the `ASLFR_*` tag numbers the requester builder uses. On
    /// ABI-v11 they come from constants declared in `native/layout.c` because the pinned C SDK has no asl
    /// header; on ABI-v1 they come from the SDK header. `asl_layout_values` holds the Rust side to compare
    /// with. The count is always returned; the values are written only when `values` is non-null and
    /// `capacity` is at least the count. No context is needed.
    ///
    /// # Safety
    ///
    /// `values` must be null or valid for writes of `capacity` `u64` values.
    pub fn sdk_asl_layout(values: *mut u64, capacity: usize) -> usize;
    // locale.library locales and catalogs.
    /// Records a locale or catalog so the bridge can close it if the program does not.
    ///
    /// `kind` is 0 for a locale (from `OpenLocale`) and 1 for a catalog (from `OpenCatalog`); any other
    /// `kind`, or a null `base` or `object`, is `ERROR_KIND_INPUT`. `base` is the open `locale.library`
    /// base. Returns a handle, or 0 on failure. An object still registered at `sdk_end` is closed there
    /// through the library vector, catalogs before locales. Normal release is [`sdk_locale_release`]
    /// followed by the caller's own close.
    ///
    /// # Safety
    ///
    /// `base` and `object` must be valid and match `kind`, and `error` must be null or valid for a write
    /// of an `SdkError`.
    pub fn sdk_locale_register(
        context: u64,
        kind: i32,
        base: *mut c_void,
        object: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    /// Forgets a registered locale or catalog without closing it.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle). After a
    /// successful release the caller closes the object with `CloseLocale` or `CloseCatalog`.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_locale_release(context: u64, object: u64, error: *mut SdkError) -> c_int;
    /// Reads the name, language, preferred languages and GMT offset of a registered locale into `info`.
    ///
    /// The strings are pointers into the `Locale` structure (NUL terminated, possibly null) and stay
    /// valid only while the locale is open. A catalog handle, an unknown handle or a null `info` is
    /// `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `info` must be valid for a write of an `SdkLocaleInfo`, and `error` must be null or valid for a
    /// write of an `SdkError`. Do not use the string pointers after the locale is closed.
    pub fn sdk_locale_info(
        context: u64,
        locale: u64,
        info: *mut SdkLocaleInfo,
        error: *mut SdkError,
    ) -> c_int;
    /// Copies the locale layout oracle values into `values` and returns how many there are.
    ///
    /// The values are the catalog tags (`OC_*`), the string numbers the Rust API uses and the size and key
    /// offsets of `SdkLocaleInfo`. On ABI-v11 they come from constants declared in `native/layout.c`
    /// because the pinned C SDK has no locale header; on ABI-v1 they come from the SDK header.
    /// `locale_layout_values` holds the Rust side to compare with. The count is always returned; the
    /// values are written only when `values` is non-null and `capacity` is at least the count. No context
    /// is needed.
    ///
    /// # Safety
    ///
    /// `values` must be null or valid for writes of `capacity` `u64` values.
    pub fn sdk_locale_layout(values: *mut u64, capacity: usize) -> usize;
    // icon.library disk objects. The bridge can replace the default tool and tool types of an object with
    // copies it owns, and puts the originals back before the object is freed.
    /// Records a disk object so the bridge can free it if the program does not.
    ///
    /// `base` is the open `icon.library` base and `object` the pointer returned by `GetDiskObject` or a
    /// similar call; both must be non-null, otherwise `ERROR_KIND_INPUT`. The current default tool and tool
    /// types pointers are remembered as the originals. Returns a handle, or 0 on failure. An object still
    /// registered at `sdk_end` is freed there (`FreeDiskObject` through the library vector). Normal release
    /// is [`sdk_icon_release`] followed by the caller's own free.
    ///
    /// # Safety
    ///
    /// `base` and `object` must be valid, and `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_icon_register(
        context: u64,
        base: *mut c_void,
        object: *mut c_void,
        error: *mut SdkError,
    ) -> u64;
    /// Reads the type, stack size, position, default tool and tool types of a disk object into `info`.
    ///
    /// The string pointers refer to the object's current default tool and tool-types array (null if the
    /// object has none) and are valid only until the object is changed or freed. An unknown handle or a
    /// null `info` is `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `info` must be valid for a write of an `SdkIconInfo`, and `error` must be null or valid for a write
    /// of an `SdkError`. Do not use the pointers after the object is released or changed.
    pub fn sdk_icon_info(
        context: u64,
        icon: u64,
        info: *mut SdkIconInfo,
        error: *mut SdkError,
    ) -> c_int;
    /// Replaces the default tool of a disk object with a copy of `text`.
    ///
    /// `length` is at most 512 bytes, otherwise `ERROR_KIND_INPUT`, and `text` may be null only for
    /// length 0. The bytes are not NUL terminated on input; the copy is. The copy is owned by the bridge
    /// and replaces an earlier copy; it is freed by [`sdk_icon_release`] and the original pointer is put
    /// back first. An unknown handle is `ERROR_KIND_STATE` and lack of memory `ERROR_KIND_NATIVE`. Returns
    /// 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `text` must be valid for reads of `length` bytes when `length` is nonzero, and `error` must be null
    /// or valid for a write of an `SdkError`.
    pub fn sdk_icon_set_default_tool(
        context: u64,
        icon: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Replaces the tool types of a disk object with copies of `count` strings.
    ///
    /// `items` points to `count` pointers and `lengths` to `count` byte lengths; item `i` is `lengths[i]`
    /// bytes at `items[i]` (at most 512 each), not NUL terminated on input. `count` is at most 64; both
    /// arrays may be null only when `count` is 0, which installs an empty list. The bridge builds a
    /// NULL-terminated array of NUL-terminated copies that it owns; it replaces an earlier one and is freed
    /// by [`sdk_icon_release`] after the original array is put back. Violations are `ERROR_KIND_INPUT`,
    /// an unknown handle is `ERROR_KIND_STATE` and lack of memory `ERROR_KIND_NATIVE`. Returns 0 on
    /// success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `items` and `lengths` must be valid for reads of `count` entries, and every `items[i]` valid for
    /// reads of `lengths[i]` bytes. `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_icon_set_tool_types(
        context: u64,
        icon: u64,
        items: *const *const u8,
        lengths: *const usize,
        count: usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Sets the stack size field of a disk object to `stack`.
    ///
    /// The value is stored as given, with no range check. Returns 0 on success and -1 on failure
    /// (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_icon_set_stack(context: u64, icon: u64, stack: i32, error: *mut SdkError) -> c_int;
    /// Puts the library's own default tool and tool types back and forgets the object without freeing it.
    ///
    /// The bridge's copies are freed. Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an
    /// unknown handle). After a successful release the caller frees the object with `FreeDiskObject`;
    /// after a failure it must not, because the bridge may still do so.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Pointers from [`sdk_icon_info`] taken
    /// before the release must not be used afterwards.
    pub fn sdk_icon_release(context: u64, icon: u64, error: *mut SdkError) -> c_int;
    // Workbench application messages and objects. The port is a message port for messages that
    // Workbench sends to application windows, icons and menu items; an object records one such
    // registration with `workbench.library`.
    /// Creates a message port for Workbench application messages and returns a handle for it.
    ///
    /// The port is created with `CreateMsgPort`. It does not use one of the 32 signal slots of
    /// [`sdk_signal_new`]; its mask is [`sdk_wb_port_mask`]. Returns 0 on failure (`ERROR_KIND_NATIVE`
    /// with `ERROR_NO_FREE_STORE`, or `ERROR_KIND_LIMIT`). Release it with [`sdk_wb_port_drop`]; a port
    /// left at `sdk_end` is deleted there.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_wb_port_new(context: u64, error: *mut SdkError) -> u64;
    /// Returns the `MsgPort` pointer of a Workbench port handle, or null.
    ///
    /// The pointer is what `AddAppWindowA`, `AddAppIconA` and `AddAppMenuItemA` take as the message port.
    /// Null means the context check failed or the handle is unknown. No error record is filled. It is
    /// valid until [`sdk_wb_port_drop`].
    ///
    /// # Safety
    ///
    /// Use the pointer only on the owner task and not after the port is dropped.
    pub fn sdk_wb_port_ptr(context: u64, port: u64) -> *mut c_void;
    /// Returns the signal mask of the port, `1 << signal bit`, or 0.
    ///
    /// It returns 0 when the context check fails or the handle is unknown. Pass it to
    /// [`sdk_signal_wait_mask`] to wait for application messages. No error record is filled.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Use it on the owner task only.
    pub fn sdk_wb_port_mask(context: u64, port: u64) -> u32;
    /// Reports whether a message is waiting on the port, without taking it.
    ///
    /// Returns 1 if the port's message list is not empty and 0 otherwise. It also returns 0 when the
    /// context check fails or the handle is unknown; no error record is filled, so an error cannot be
    /// distinguished from an empty port.
    ///
    /// # Safety
    ///
    /// No pointer is involved. Use it on the owner task only.
    pub fn sdk_wb_port_pending(context: u64, port: u64) -> c_int;
    /// Takes the next application message, decodes it into `message` and replies to it.
    ///
    /// Returns 1 and fills `message` when one was waiting, 0 when there is none, and -1 on failure
    /// (`ERROR_KIND_STATE` for an unknown handle or a null `message`). The record has the type, class,
    /// mouse position, time, id and user data; `total_args` is the number of arguments Workbench sent and
    /// `num_args` the number of paths the bridge kept, at most 8. The paths are kept in the port record,
    /// each at most 255 bytes, and read with [`sdk_wb_path`] until the next call that returns a message. An
    /// argument whose lock or name cannot be turned into a path is kept as an empty path. The message is
    /// replied to inside the call, so no Workbench pointer escapes.
    ///
    /// # Safety
    ///
    /// `message` must be valid for a write of an `SdkAppMessage`, and `error` must be null or valid for a
    /// write of an `SdkError`.
    pub fn sdk_wb_port_next(
        context: u64,
        port: u64,
        message: *mut SdkAppMessage,
        error: *mut SdkError,
    ) -> c_int;
    /// Copies path number `index` of the last message taken from the port into `buffer`.
    ///
    /// The path is written NUL terminated and `*length` is its length without the terminator.
    /// `capacity` must be at least the length plus one, otherwise `ERROR_KIND_LIMIT`. `index` must be below
    /// `SdkAppMessage::num_args` of that message, otherwise `ERROR_KIND_INPUT`. An unknown handle, or a null
    /// `buffer` or `length`, is `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `buffer` must be valid for writes of `capacity` bytes, `length` for a write of a `usize`, and
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_wb_path(
        context: u64,
        port: u64,
        index: i32,
        buffer: *mut u8,
        capacity: usize,
        length: *mut usize,
        error: *mut SdkError,
    ) -> c_int;
    /// Deletes a Workbench port created with [`sdk_wb_port_new`].
    ///
    /// Messages still waiting on it are replied to first, then the port is deleted. Returns 0 on success
    /// and -1 on failure (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Objects created on this port keep a raw
    /// pointer to it, so remove them with [`sdk_wb_object_remove`] before dropping the port.
    pub fn sdk_wb_port_drop(context: u64, port: u64, error: *mut SdkError) -> c_int;
    /// Creates a record for one Workbench registration and returns its handle.
    ///
    /// `kind` is 0 for an application window, 1 for an application icon and 2 for an application menu item,
    /// otherwise `ERROR_KIND_INPUT`. `port` must be a handle from [`sdk_wb_port_new`] (`ERROR_KIND_STATE`
    /// otherwise). `text` is the name or title to register, at most 127 bytes, and may be null only for
    /// length 0; it is copied and not NUL terminated on input. Nothing is registered with Workbench yet:
    /// pass the pointer from [`sdk_wb_object_text`] to the library call, then use [`sdk_wb_object_attach`],
    /// or [`sdk_wb_object_cancel`] if the registration failed. Returns 0 on failure.
    ///
    /// # Safety
    ///
    /// `text` must be valid for reads of `length` bytes when `length` is nonzero, and `error` must be null
    /// or valid for a write of an `SdkError`.
    pub fn sdk_wb_object_new(
        context: u64,
        kind: i32,
        port: u64,
        text: *const u8,
        length: usize,
        error: *mut SdkError,
    ) -> u64;
    /// Returns a pointer to the NUL-terminated text stored in a registration record, or null.
    ///
    /// Null means the context check failed or the handle is unknown. The pointer is stable until the record
    /// is removed or cancelled, so Workbench may keep it. No error record is filled.
    ///
    /// # Safety
    ///
    /// Do not read it after the record is released, and do not write through it.
    pub fn sdk_wb_object_text(context: u64, object: u64) -> *const c_char;
    /// Records the Workbench registration handle in an object record.
    ///
    /// `base` is the open `workbench.library` base and `handle` the pointer returned by `AddAppWindowA`,
    /// `AddAppIconA` or `AddAppMenuItemA`; both must be non-null. A null argument, an unknown handle or a
    /// record that already has a handle is `ERROR_KIND_STATE`. Returns 0 on success and -1 on failure. From
    /// now on the bridge removes the registration through the library vector in [`sdk_wb_object_remove`]
    /// or at `sdk_end`.
    ///
    /// # Safety
    ///
    /// `base` and `handle` must be valid and match the object's `kind`, and `error` must be null or valid
    /// for a write of an `SdkError`.
    pub fn sdk_wb_object_attach(
        context: u64,
        object: u64,
        base: *mut c_void,
        handle: *mut c_void,
        error: *mut SdkError,
    ) -> c_int;
    /// Discards a record whose registration was never attached.
    ///
    /// An attached record, or an unknown handle, is `ERROR_KIND_STATE`; use [`sdk_wb_object_remove`] for an
    /// attached record. Nothing is removed from Workbench. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_wb_object_cancel(context: u64, object: u64, error: *mut SdkError) -> c_int;
    /// Removes a Workbench registration and frees its record.
    ///
    /// The record is retired first. If it is attached, messages already waiting on its port are replied to
    /// (Workbench waits for those replies while it holds a lock the removal needs), and then
    /// `RemoveAppWindow`, `RemoveAppIcon` or `RemoveAppMenuItem` is called through the library vector
    /// according to the kind. An unattached record is simply freed. Returns 0 on success and -1 on failure
    /// (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`. Do not use the text pointer afterwards.
    pub fn sdk_wb_object_remove(context: u64, object: u64, error: *mut SdkError) -> c_int;
    /// Copies the Workbench layout oracle values into `values` and returns how many there are.
    ///
    /// The values are the `WB*` disk object types, the `AMTYPE_APP*` message types and the size and key
    /// offsets of `SdkIconInfo` and `SdkAppMessage`. On ABI-v11 they come from constants declared in
    /// `native/layout.c` because the pinned C SDK has no workbench header; on ABI-v1 they come from the
    /// SDK header. `wb_layout_values` holds the Rust side to compare with. The count is always returned;
    /// the values are written only when `values` is non-null and `capacity` is at least the count. No
    /// context is needed.
    ///
    /// # Safety
    ///
    /// `values` must be null or valid for writes of `capacity` `u64` values.
    pub fn sdk_wb_layout(values: *mut u64, capacity: usize) -> usize;
    // DOS directories, paths, variables and the current directory. Locks taken here are released on every
    // path, and the current directory change is undone at `sdk_end`.
    /// Opens the directory `path` for iteration and returns a handle for it.
    ///
    /// The directory is locked with a shared lock and examined. `path` is a NUL-terminated byte string of
    /// at most 127 bytes (`ERROR_KIND_INPUT` otherwise). A path that is not a directory fails with
    /// `ERROR_KIND_NATIVE` and `native` `ERROR_OBJECT_WRONG_TYPE`; other DOS failures carry the `IoErr`
    /// code. Returns 0 on failure. Release it with [`sdk_dir_close`]; a directory left open at `sdk_end` is
    /// closed there.
    ///
    /// # Safety
    ///
    /// `path` must be valid for reads up to its NUL (within 128 bytes) and `error` must be null or valid
    /// for a write of an `SdkError`.
    pub fn sdk_dir_open(context: u64, path: *const u8, error: *mut SdkError) -> u64;
    /// Reads the next entry of an open directory into `entry`.
    ///
    /// Returns 1 and fills `entry` when there is an entry, 0 at the end of the directory (DOS
    /// `ERROR_NO_MORE_ENTRIES`, not an error), and -1 on failure (`ERROR_KIND_STATE` for an unknown handle,
    /// `ERROR_KIND_INPUT` for a null `entry`, `ERROR_KIND_NATIVE` with the `IoErr` code). The name is
    /// truncated to 107 bytes and stored NUL terminated, `name_length` is its stored length. Negative
    /// `directory_type` is a file. ABI difference: on ABI-v1 with `dos64.library` the entry carries the
    /// exact 64-bit size and `size_exact` is 1. Otherwise (always on ABI-v11) the 32-bit size is used and
    /// `size_exact` is 0 when the size is `0x7fffffff` or more, since it may have been truncated.
    ///
    /// # Safety
    ///
    /// `entry` must be valid for a write of an `SdkEntry`, and `error` must be null or valid for a write
    /// of an `SdkError`.
    pub fn sdk_dir_next(
        context: u64,
        directory: u64,
        entry: *mut SdkEntry,
        error: *mut SdkError,
    ) -> c_int;
    /// Closes a directory opened with [`sdk_dir_open`] and releases its lock.
    ///
    /// Returns 0 on success and -1 on failure (`ERROR_KIND_STATE` for an unknown handle).
    ///
    /// # Safety
    ///
    /// `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_dir_close(context: u64, directory: u64, error: *mut SdkError) -> c_int;
    /// Reads the information of the file or directory `path` into `entry`.
    ///
    /// The object is locked, examined and unlocked inside the call. `path` is a NUL-terminated byte string
    /// of at most 127 bytes, and `entry` must not be null (`ERROR_KIND_INPUT` otherwise). DOS failures are
    /// `ERROR_KIND_NATIVE` with the `IoErr` code (for example the object not existing). The entry fields,
    /// including the name truncation and the `size_exact` rule of the two ABIs, are as for
    /// [`sdk_dir_next`]. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `path` must be valid for reads up to its NUL, `entry` must be valid for a write of an `SdkEntry`,
    /// and `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_entry_info(
        context: u64,
        path: *const u8,
        entry: *mut SdkEntry,
        error: *mut SdkError,
    ) -> c_int;
    /// Creates the directory `path` (DOS `CreateDir`).
    ///
    /// `path` is a NUL-terminated byte string of at most 127 bytes (`ERROR_KIND_INPUT` otherwise). The lock
    /// that `CreateDir` returns is released inside the call. DOS failures are `ERROR_KIND_NATIVE` with the
    /// `IoErr` code. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `path` must be valid for reads up to its NUL, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_make_dir(context: u64, path: *const u8, error: *mut SdkError) -> c_int;
    /// Deletes the file or empty directory `path` (DOS `DeleteFile`).
    ///
    /// `path` is a NUL-terminated byte string of at most 127 bytes (`ERROR_KIND_INPUT` otherwise). DOS
    /// failures, such as a protected file or a directory that is not empty, are `ERROR_KIND_NATIVE` with
    /// the `IoErr` code. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `path` must be valid for reads up to its NUL, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_delete(context: u64, path: *const u8, error: *mut SdkError) -> c_int;
    /// Renames or moves `from` to `to` (DOS `Rename`).
    ///
    /// Both are NUL-terminated byte strings of at most 127 bytes (`ERROR_KIND_INPUT` otherwise). DOS
    /// failures are `ERROR_KIND_NATIVE` with the `IoErr` code. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `from` and `to` must be valid for reads up to their NUL, and `error` must be null or valid for a
    /// write of an `SdkError`.
    pub fn sdk_rename(context: u64, from: *const u8, to: *const u8, error: *mut SdkError) -> c_int;
    /// Writes the full path of the current directory into `out` and returns its length.
    ///
    /// `out` must not be null and `capacity` must be 2 to 4096, otherwise `ERROR_KIND_INPUT`. The path is
    /// produced by `NameFromLock`, written NUL terminated within `capacity`, and the result is its length
    /// without the terminator. Returns -1 on failure: `ERROR_KIND_NATIVE` with the `IoErr` code (for
    /// example when the buffer is too small) or with `ERROR_OBJECT_NOT_FOUND` when the task has no current
    /// directory.
    ///
    /// # Safety
    ///
    /// `out` must be valid for writes of `capacity` bytes, and `error` must be null or valid for a write
    /// of an `SdkError`.
    pub fn sdk_cwd_get(context: u64, out: *mut u8, capacity: usize, error: *mut SdkError) -> i64;
    /// Makes the directory `path` the current directory of the owner task.
    ///
    /// `path` is a NUL-terminated byte string of at most 127 bytes (`ERROR_KIND_INPUT` otherwise). The path
    /// must name a directory: a file fails with `ERROR_KIND_NATIVE` and `native` `ERROR_OBJECT_WRONG_TYPE`,
    /// and other DOS failures carry the `IoErr` code. The bridge keeps the new lock and restores the
    /// original current directory at `sdk_end`, so the launching shell keeps its own. Returns 0 on success
    /// and -1 on failure.
    ///
    /// # Safety
    ///
    /// `path` must be valid for reads up to its NUL, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_cwd_set(context: u64, path: *const u8, error: *mut SdkError) -> c_int;
    /// Copies the value of the variable `name` into `out` and returns its length in bytes.
    ///
    /// `name` is NUL terminated. `out` must not be null and `capacity` must be 2 to 4096; `scope` is 0 for
    /// local then global variables, 1 for local only and 2 for global only (`ENV:`); anything else is
    /// `ERROR_KIND_INPUT`. The value is read as binary (`GVF_BINARY_VAR`) and the result is its length
    /// without the terminator; a terminator is stored too. A value longer than `capacity` is refused
    /// rather than cut: `ERROR_KIND_NATIVE` with `native` 303. A missing variable or other DOS failure is
    /// `ERROR_KIND_NATIVE` with the `IoErr` code. Returns -1 on failure.
    ///
    /// # Safety
    ///
    /// `name` must be valid for reads up to its NUL, `out` must be valid for writes of `capacity` bytes,
    /// and `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_var_get(
        context: u64,
        name: *const u8,
        out: *mut u8,
        capacity: usize,
        scope: i32,
        error: *mut SdkError,
    ) -> i64;
    /// Sets the variable `name` to the `length` bytes at `value`.
    ///
    /// `name` is NUL terminated; `value` is not and must contain no 0 byte; `length` is at most 4096 and
    /// `value` may be null only for length 0, which stores an empty value; `scope` is as for
    /// [`sdk_var_get`]. Violations are `ERROR_KIND_INPUT`. The value is stored as a binary variable. A
    /// DOS failure is `ERROR_KIND_NATIVE` with the `IoErr` code. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `name` must be valid for reads up to its NUL, `value` must be valid for reads of `length` bytes
    /// when `length` is nonzero, and `error` must be null or valid for a write of an `SdkError`.
    pub fn sdk_var_set(
        context: u64,
        name: *const u8,
        value: *const u8,
        length: usize,
        scope: i32,
        error: *mut SdkError,
    ) -> c_int;
    /// Deletes the variable `name` in the given scope (DOS `DeleteVar`).
    ///
    /// `name` is NUL terminated and `scope` is 0, 1 or 2 as for [`sdk_var_get`]; anything else is
    /// `ERROR_KIND_INPUT`. A DOS failure, such as a missing variable, is `ERROR_KIND_NATIVE` with the
    /// `IoErr` code. Returns 0 on success and -1 on failure.
    ///
    /// # Safety
    ///
    /// `name` must be valid for reads up to its NUL, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_var_delete(context: u64, name: *const u8, scope: i32, error: *mut SdkError)
    -> c_int;
    /// Calls `callback(user_data, input)` on the owner task and stores its result in `output`.
    ///
    /// The call is synchronous and the callback runs on the calling task. The Rust `call` function wraps
    /// it. Returns 0 after the callback returned
    /// and -1 on failure without calling it: the context check, a null `callback`, `user_data` or
    /// `output`, or a callback that is already running (nested calls are refused), all with
    /// `ERROR_KIND_OWNER` or `ERROR_KIND_STATE`.
    ///
    /// # Safety
    ///
    /// `callback` must be a valid function for the whole call and must return normally; unwinding out of it
    /// is undefined behaviour. `user_data` must be valid for whatever the callback does with it, `output`
    /// must be valid for a write of a `u64`, and `error` must be null or valid for a write of an
    /// `SdkError`.
    pub fn sdk_callback(
        context: u64,
        callback: SdkCallback,
        user_data: *mut c_void,
        input: u64,
        output: *mut u64,
        error: *mut SdkError,
    ) -> c_int;

    // Layout and scalar oracles, computed by the C compiler from the SDK headers of the selected ABI. The
    // qualification tests compare them with the Rust declarations. They need no context. For the
    // `*_layout` functions the count is always returned and the values are written only when the output
    // pointer is non-null and the capacity is at least the count, so a call with a null pointer or a zero
    // capacity asks for the count.
    /// Copies the core ABI layout oracle values into `values` and returns how many there are.
    ///
    /// The values are, in order, the size, alignment and field offsets of `Node`, `Library`, `Message`,
    /// `List`, `MsgPort` and `FileInfoBlock`, the size and alignment of `IPTR`, `BPTR`, `LONG` and `ULONG`,
    /// `spinlock_t`, and the bridge records `SdkError`, `SdkStats` and `SdkEntry`. ABI difference: the
    /// `spinlock_t` values and the `Library` and `MsgPort` tail fields are present on ABI-v1 only, so the
    /// count is 106 on ABI-v1 and 101 on ABI-v11 (`ABI_LAYOUT_VALUE_COUNT`). `layout_values` holds the
    /// Rust side to compare with.
    ///
    /// # Safety
    ///
    /// `values` must be null or valid for writes of `capacity` `u64` values.
    pub fn sdk_layout(values: *mut u64, capacity: usize) -> usize;
    /// Copies the timer layout oracle values into `values` and returns how many there are.
    ///
    /// The values are the size, alignment and `tr_time` offset of `timerequest`, the size and `ev_lo` offset
    /// of `EClockVal`, the size of the `tr_time` field, the offset of its microseconds member and the size of
    /// `IORequest`. `timerequest` carries a `struct timeval` on ABI-v1 and a `struct timeval32` on
    /// ABI-v11; both are two 32-bit fields. `timer_layout_values` holds the Rust side to compare with.
    ///
    /// # Safety
    ///
    /// `values` must be null or valid for writes of `capacity` `u64` values.
    pub fn sdk_timer_layout(values: *mut u64, capacity: usize) -> usize;
    /// Returns the device base pointer (`io_Device`) of an open device handle, or null.
    ///
    /// The pointer is for raw library-style calls such as the timer functions `ReadEClock`. It stays valid
    /// while the handle is open. Null means the context check failed or the handle is unknown. No error
    /// record is filled.
    ///
    /// # Safety
    ///
    /// Use the pointer only on the owner task, only for the API of the device that was opened and not
    /// after [`sdk_device_close`].
    pub fn sdk_device_base(context: u64, device: u64) -> *mut c_void;
    /// Combines five scalar arguments with exclusive-or and returns the result.
    ///
    /// The result is `((signed as u32 as u64) << 32) ^ unsigned ^ pointer ^ wide ^ size`. The qualification
    /// test uses it to check that integers of each width and a pointer-sized value cross the Rust-to-C call
    /// unchanged. It has no side effects and needs no context.
    ///
    /// # Safety
    ///
    /// No pointer is dereferenced; `pointer` is only a number.
    pub fn sdk_scalar(signed: i32, unsigned: u32, pointer: usize, wide: u64, size: usize) -> u64;
}
