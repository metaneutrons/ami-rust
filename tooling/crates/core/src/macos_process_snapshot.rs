//! Bounded native macOS process sampling for the resource observer.
//!
//! libproc calls are read-only observations of a changing process table. They
//! do not authorize signaling, and this module does not claim an atomic table
//! snapshot. Every kernel call is checked against the observer's two-second
//! sample budget before and after it returns; the caller's Supervisor remains
//! the hard process deadline because a synchronous kernel call cannot be
//! preempted here.

#![allow(
    unsafe_code,
    reason = "macOS libproc and waitid FFI are used only for bounded read-only observation and focused controls."
)]

#[cfg(test)]
use crate::process_spawn::FixtureCommandExt;

use crate::process_snapshot::{self, ProcessRow, ProcessSnapshot};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    mem::size_of,
    time::{Duration, Instant},
};

const MAX_SAMPLE_ATTEMPTS: usize = 3;
const SAMPLE_BUDGET: Duration = Duration::from_secs(2);
const RETRYABLE_PROCESS_TRANSITION_DELAY: Duration = Duration::from_millis(10);
const MAX_PS_CAPTURE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum ProcQueryError {
    Vanished(i32),
    Denied(i32),
    Other(i32),
}

impl ProcQueryError {
    fn from_errno() -> Self {
        Self::from_error_code(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    fn from_error_code(code: i32) -> Self {
        if code == libc::ESRCH {
            Self::Vanished(code)
        } else if code == libc::EPERM || code == libc::EACCES {
            Self::Denied(code)
        } else {
            Self::Other(code)
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Vanished(code) => format!("process or group vanished (errno={code})"),
            Self::Denied(code) => format!("access denied (errno={code})"),
            Self::Other(code) => {
                format!("libproc failure or unexpected result (code/errno={code})")
            }
        }
    }
}

#[derive(Debug)]
struct SampleFailure {
    retryable: bool,
    message: String,
}

impl SampleFailure {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            retryable: false,
            message: message.into(),
        }
    }

    fn retryable(message: impl Into<String>) -> Self {
        Self {
            retryable: true,
            message: message.into(),
        }
    }

    fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self.message)
    }
}

#[derive(Clone, Copy)]
enum Pending {
    Pid(u32),
    Group(u32),
}

#[derive(Clone, Copy)]
struct ProcessInfo {
    uid: libc::uid_t,
    status: u32,
    ppid: u32,
    pgid: u32,
}

#[derive(Clone, Copy)]
struct BsdInfo {
    pid: u32,
    ppid: u32,
    pgid: u32,
    uid: libc::uid_t,
    status: u32,
}

#[repr(C)]
struct NativeProcessTopology {
    pid: i32,
    ppid: i32,
    pgid: i32,
    uid: u32,
    status: i32,
}

const _: () = assert!(size_of::<NativeProcessTopology>() == 20);

unsafe extern "C" {
    fn ami_rust_query_process_topology(
        requested_pid: i32,
        result: *mut NativeProcessTopology,
    ) -> i32;
}

struct Topology {
    snapshot: ProcessSnapshot,
    info_by_pid: BTreeMap<u32, ProcessInfo>,
    missing_linked_pids: BTreeSet<u32>,
}

enum RssFailureAction {
    Retry(String),
    Refuse(String),
}

enum TaskInfoEsrchResolution {
    KnownZombie,
    Gone,
    Live(String),
    Retry(String),
    Refuse(String),
}

enum TaskRss {
    Bytes(u64),
    Gone,
    RetryTopology(String),
}

/// Build a process scope with the same PPID/PGID closure used by the
/// historical `ps` observer. `maximum_bytes` bounds the reusable libproc PID
/// scratch buffer, and the effective row bound is no larger than either the
/// caller's row limit or that byte budget can hold, including one overflow
/// sentinel slot.
pub(super) fn query_process_scope(
    target_pid: u32,
    previously_observed_pids: &[u32],
    previously_observed_groups: &[u32],
    maximum_bytes: usize,
    maximum_rows: usize,
    maximum_history_entries: usize,
) -> io::Result<process_snapshot::ScopeSnapshot> {
    if target_pid == 0 {
        return Err(input_error(
            "target PID must be a positive process identifier",
        ));
    }
    if maximum_bytes == 0 || maximum_rows == 0 || maximum_history_entries == 0 {
        return Err(input_error("process-snapshot bounds must be positive"));
    }
    if previously_observed_pids
        .len()
        .checked_add(previously_observed_groups.len())
        .is_none_or(|entries| entries > maximum_history_entries)
    {
        return Err(input_error(
            "process history exceeds caller entry limit before native sampling",
        ));
    }

    let started = Instant::now();
    let deadline = started
        .checked_add(SAMPLE_BUDGET)
        .ok_or_else(|| input_error("native process-sample deadline overflow"))?;
    let effective_byte_limit = maximum_bytes.min(MAX_PS_CAPTURE_BYTES);
    let (row_limit, buffer_slots) = bounded_pid_buffer_slots(effective_byte_limit, maximum_rows)
        .map_err(SampleFailure::into_io)?;
    let mut pid_buffer = Vec::new();
    pid_buffer
        .try_reserve_exact(buffer_slots)
        .map_err(|_| allocation_error("could not reserve bounded libproc PID buffer"))?;
    pid_buffer.resize(buffer_slots, 0 as libc::pid_t);

    // SAFETY: geteuid reads the caller's effective UID and takes no pointers.
    let effective_uid = unsafe { libc::geteuid() };
    let mut last_retry_reason = String::new();

    for attempt in 1..=MAX_SAMPLE_ATTEMPTS {
        let target_is_unreaped_zombie =
            direct_child_exit_observed(target_pid, deadline).map_err(SampleFailure::into_io)?;
        let topology = match collect_topology(
            target_pid,
            previously_observed_pids,
            previously_observed_groups,
            maximum_history_entries,
            row_limit,
            target_is_unreaped_zombie,
            &mut pid_buffer,
            deadline,
        ) {
            Ok(topology) => topology,
            Err(failure) if failure.retryable && attempt < MAX_SAMPLE_ATTEMPTS => {
                last_retry_reason = failure.message;
                pause_for_process_transition(deadline).map_err(SampleFailure::into_io)?;
                continue;
            }
            Err(failure) if failure.retryable => {
                return Err(input_error(format!(
                    "{}; exhausted {MAX_SAMPLE_ATTEMPTS} bounded attempts",
                    failure.message
                )));
            }
            Err(failure) => return Err(failure.into_io()),
        };

        let mut linkage_seeds = previously_observed_pids.to_vec();
        linkage_seeds.extend(topology.missing_linked_pids.iter().copied());
        linkage_seeds.sort_unstable();
        linkage_seeds.dedup();
        let initial = process_snapshot::observe_scope(
            &topology.snapshot,
            target_pid,
            &linkage_seeds,
            previously_observed_groups,
            maximum_history_entries,
        )
        .map_err(|error| input_error(format!("could not compute process scope: {error}")))?;
        if !initial.root_present {
            let reason = format!("target PID {target_pid} absent after topology collection");
            if attempt < MAX_SAMPLE_ATTEMPTS {
                last_retry_reason = reason;
                pause_for_process_transition(deadline).map_err(SampleFailure::into_io)?;
                continue;
            }
            return Err(input_error(format!(
                "{last_retry_reason}; {reason}; exhausted {MAX_SAMPLE_ATTEMPTS} bounded attempts"
            )));
        }

        let mut rss_bytes_by_pid = BTreeMap::new();
        let mut disappeared_during_rss = BTreeSet::new();
        let mut retry_for_vanished_scope_member = None;
        for row in &initial.rows {
            let info = topology.info_by_pid.get(&row.pid).ok_or_else(|| {
                input_error(format!(
                    "scope PID {} has no corresponding BSD-info identity",
                    row.pid
                ))
            })?;

            // ps reports zero RSS for a zombie retained by WNOWAIT. TASKINFO
            // commonly returns ESRCH for that same known zombie, so the BSD
            // status is the only condition under which missing task RSS is
            // deliberately represented as zero.
            if info.status == libc::SZOMB {
                rss_bytes_by_pid.insert(row.pid, 0_u64);
                continue;
            }

            match read_task_rss(
                row.pid,
                info.uid,
                effective_uid,
                deadline,
                || query_task_info(row.pid, deadline),
                || resolve_taskinfo_esrch(row.pid, *info, deadline),
            )? {
                TaskRss::Bytes(resident_bytes) => {
                    rss_bytes_by_pid.insert(row.pid, resident_bytes);
                }
                TaskRss::Gone if row.pid != target_pid => {
                    // Confirmed absence is not a zero-RSS live row. Keep
                    // the missing member's linkage and observed group.
                    disappeared_during_rss.insert(row.pid);
                }
                TaskRss::Gone => {
                    retry_for_vanished_scope_member = Some(format!(
                        "required target PID {} disappeared during RSS collection",
                        row.pid
                    ));
                    break;
                }
                TaskRss::RetryTopology(reason) => {
                    retry_for_vanished_scope_member = Some(reason);
                    break;
                }
            }
        }
        if let Some(reason) = retry_for_vanished_scope_member {
            last_retry_reason = reason.clone();
            if attempt < MAX_SAMPLE_ATTEMPTS {
                pause_for_process_transition(deadline).map_err(SampleFailure::into_io)?;
                continue;
            }
            return Err(input_error(format!(
                "{last_retry_reason}; exhausted {MAX_SAMPLE_ATTEMPTS} bounded attempts"
            )));
        }

        let result = project_rss_scope(
            topology.snapshot,
            &initial,
            target_pid,
            &linkage_seeds,
            &disappeared_during_rss,
            &rss_bytes_by_pid,
            maximum_history_entries,
        )?;
        check_deadline(deadline).map_err(SampleFailure::into_io)?;
        return Ok(result);
    }

    Err(input_error(format!(
        "bounded native process sampling exhausted: {last_retry_reason}"
    )))
}

/// Remove only kernel-confirmed absent members, retaining their linkage and
/// already observed groups so a surviving child in another group is not lost.
fn project_rss_scope(
    mut snapshot: ProcessSnapshot,
    initial: &process_snapshot::ScopeSnapshot,
    target_pid: u32,
    linkage_seeds: &[u32],
    disappeared: &BTreeSet<u32>,
    rss_bytes_by_pid: &BTreeMap<u32, u64>,
    maximum_history_entries: usize,
) -> io::Result<process_snapshot::ScopeSnapshot> {
    if disappeared.contains(&target_pid) {
        return Err(input_error(
            "required root cannot be omitted from an RSS sample",
        ));
    }
    snapshot.rows.retain(|row| !disappeared.contains(&row.pid));
    for row in &mut snapshot.rows {
        let bytes = rss_bytes_by_pid.get(&row.pid).ok_or_else(|| {
            input_error(format!(
                "linked PID {} has no successful or zombie RSS observation",
                row.pid
            ))
        })?;
        row.rss_kib = bytes / 1024;
    }
    let mut seeds = linkage_seeds.to_vec();
    seeds.extend(disappeared.iter().copied());
    seeds.sort_unstable();
    seeds.dedup();
    let completed = process_snapshot::observe_scope(
        &snapshot,
        target_pid,
        &seeds,
        &initial.process_groups,
        maximum_history_entries,
    )
    .map_err(|error| input_error(format!("could not finalize process scope: {error}")))?;
    let expected_pids: Vec<_> = initial
        .process_ids
        .iter()
        .copied()
        .filter(|pid| !disappeared.contains(pid))
        .collect();
    if expected_pids != completed.process_ids || !completed.root_present {
        return Err(input_error(
            "process scope changed between topology and RSS projection",
        ));
    }
    Ok(completed)
}

#[allow(
    clippy::too_many_arguments,
    reason = "Keep the separately bounded PID/group histories, reusable buffer and deadline explicit at the read-only kernel boundary."
)]
fn collect_topology(
    target_pid: u32,
    previously_observed_pids: &[u32],
    previously_observed_groups: &[u32],
    maximum_history_entries: usize,
    row_limit: usize,
    target_is_unreaped_zombie: bool,
    pid_buffer: &mut [libc::pid_t],
    deadline: Instant,
) -> Result<Topology, SampleFailure> {
    let host_count = count_all_pids(pid_buffer, row_limit, deadline)?;
    if host_count > row_limit {
        return Err(SampleFailure::fatal(format!(
            "host process table exceeds caller row limit ({host_count} > {row_limit})"
        )));
    }

    let pid_entry_limit = row_limit
        .checked_add(previously_observed_pids.len())
        .ok_or_else(|| SampleFailure::fatal("linked PID bound overflows"))?;
    let group_entry_limit = row_limit
        .checked_add(previously_observed_groups.len())
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| SampleFailure::fatal("linked process-group bound overflows"))?;
    let mut pending = VecDeque::new();
    let mut seen_pids = BTreeSet::new();
    let mut seen_groups = BTreeSet::new();
    let mut missing_previous = BTreeSet::new();
    let mut info_by_pid = BTreeMap::<u32, ProcessInfo>::new();

    enqueue_pid(
        target_pid,
        &mut pending,
        &mut seen_pids,
        &missing_previous,
        pid_entry_limit,
    )?;
    for pid in previously_observed_pids {
        enqueue_pid(
            *pid,
            &mut pending,
            &mut seen_pids,
            &missing_previous,
            pid_entry_limit,
        )?;
    }
    enqueue_group(
        target_pid,
        &mut pending,
        &mut seen_groups,
        group_entry_limit,
    )?;
    for group in previously_observed_groups {
        enqueue_group(*group, &mut pending, &mut seen_groups, group_entry_limit)?;
    }

    while let Some(next) = pending.pop_front() {
        match next {
            Pending::Pid(pid) => {
                if !info_by_pid.contains_key(&pid) && !missing_previous.contains(&pid) {
                    match query_bsd_info(pid, deadline) {
                        Ok(info) => {
                            if info.pid != pid {
                                return Err(SampleFailure::fatal(format!(
                                    "BSD-info PID identity mismatch for requested pid={pid}, returned pid={}",
                                    info.pid
                                )));
                            }
                            if pid == target_pid
                                && target_is_unreaped_zombie
                                && info.status != libc::SZOMB
                            {
                                return Err(SampleFailure::retryable(format!(
                                    "waitid observed target PID {pid} exited but BSD-info status was not zombie"
                                )));
                            }
                            info_by_pid.insert(
                                pid,
                                ProcessInfo {
                                    uid: info.uid,
                                    status: info.status,
                                    ppid: info.ppid,
                                    pgid: info.pgid,
                                },
                            );
                            enqueue_group(
                                info.pgid,
                                &mut pending,
                                &mut seen_groups,
                                group_entry_limit,
                            )?;
                        }
                        Err(ProcQueryError::Vanished(errno)) if pid == target_pid => {
                            if target_is_unreaped_zombie {
                                return Err(SampleFailure::retryable(format!(
                                    "WNOWAIT confirms target PID {pid} exited, but native BSD topology is temporarily unavailable (errno={errno}); retrying without inferring PPID/PGID"
                                )));
                            }
                            return Err(SampleFailure::retryable(format!(
                                "required target PID {pid} vanished during BSD-info query (errno={errno})"
                            )));
                        }
                        Err(ProcQueryError::Denied(errno))
                            if pid == target_pid && target_is_unreaped_zombie =>
                        {
                            return Err(SampleFailure::fatal(format!(
                                "WNOWAIT confirms target PID {pid} exited, but native BSD topology is denied (errno={errno}); refusing to infer PPID/PGID"
                            )));
                        }
                        Err(ProcQueryError::Vanished(_)) => {
                            // Child/group enumeration and KERN_PROC_PID are
                            // separate kernel observations. A short-lived
                            // non-root member can disappear between them,
                            // including on its very first observation. Keep
                            // its linkage seed but do not invent a live row
                            // or zero RSS. The wait-owned root is handled
                            // separately above and may never be omitted.
                            missing_previous.insert(pid);
                        }
                        Err(other) => {
                            return Err(SampleFailure::fatal(format!(
                                "BSD topology query failed for linked PID {pid}; cannot determine its PPID/PGID/UID: {}",
                                other.describe()
                            )));
                        }
                    }
                }

                // A missing numeric PID is only a linkage seed. Do not
                // query its children after confirming absence: the PID
                // could have been reused by another process in between.
                if missing_previous.contains(&pid) {
                    continue;
                }
                let known_zombie = info_by_pid
                    .get(&pid)
                    .is_some_and(|info| info.status == libc::SZOMB);
                if known_zombie {
                    // POSIX reparents the zombie's former children as part
                    // of exit; its retained group is queried separately.
                    continue;
                }
                match query_child_pids(pid, pid_buffer, deadline) {
                    Ok(children) => {
                        for child in children {
                            enqueue_pid(
                                child,
                                &mut pending,
                                &mut seen_pids,
                                &missing_previous,
                                pid_entry_limit,
                            )?;
                        }
                    }
                    Err(ProcQueryError::Vanished(_)) if pid != target_pid => {}
                    Err(ProcQueryError::Vanished(errno)) => {
                        return Err(SampleFailure::retryable(format!(
                            "process parent PID {pid} vanished during child-list query (errno={errno})"
                        )));
                    }
                    Err(other) => {
                        return Err(SampleFailure::fatal(format!(
                            "could not enumerate children of linked PID {pid}: {}",
                            other.describe()
                        )));
                    }
                }
            }
            Pending::Group(group) => match query_group_pids(group, pid_buffer, deadline) {
                Ok(members) => {
                    for member in members {
                        if member == 0 {
                            // PID 0 is XNU's kernel pseudo-process, not a
                            // user descendant of a positive process group.
                            continue;
                        }
                        enqueue_pid(
                            member,
                            &mut pending,
                            &mut seen_pids,
                            &missing_previous,
                            pid_entry_limit,
                        )?;
                    }
                }
                // Previously observed groups remain in history after they
                // empty. ESRCH is the native equivalent of an empty group.
                Err(ProcQueryError::Vanished(_)) => {}
                Err(other) => {
                    return Err(SampleFailure::fatal(format!(
                        "could not enumerate members of linked PGID {group}: {}",
                        other.describe()
                    )));
                }
            },
        }
    }

    if info_by_pid.len() > row_limit {
        return Err(SampleFailure::fatal(
            "linked process topology exceeds caller row limit",
        ));
    }
    if seen_pids.len() > maximum_history_entries.saturating_add(row_limit) {
        return Err(SampleFailure::fatal(
            "linked PID topology exceeds caller history and row bounds",
        ));
    }
    if seen_groups.len() > group_entry_limit {
        return Err(SampleFailure::fatal(
            "linked process groups exceed caller history and row bounds",
        ));
    }

    let snapshot_rows = info_by_pid
        .iter()
        .map(|(pid, info)| ProcessRow {
            pid: *pid,
            ppid: info.ppid,
            pgid: info.pgid,
            rss_kib: 0,
        })
        .collect::<Vec<_>>();

    Ok(Topology {
        snapshot: ProcessSnapshot {
            rows: snapshot_rows,
        },
        info_by_pid,
        missing_linked_pids: missing_previous,
    })
}

fn count_all_pids(
    buffer: &mut [libc::pid_t],
    row_limit: usize,
    deadline: Instant,
) -> Result<usize, SampleFailure> {
    check_deadline(deadline)?;
    let byte_capacity = buffer_byte_capacity(buffer)?;
    buffer.fill(0);
    clear_errno();
    // SAFETY: libproc receives a valid writable buffer and its byte capacity.
    let count = unsafe { libc::proc_listallpids(buffer.as_mut_ptr().cast(), byte_capacity) };
    check_deadline(deadline)?;
    if count <= 0 {
        return Err(SampleFailure::fatal(format!(
            "proc_listallpids failed or returned no PIDs: {}",
            io::Error::last_os_error()
        )));
    }
    checked_pid_list_count(count as usize, buffer.len(), row_limit)
        .map_err(|error| SampleFailure::fatal(error.to_string()))
}

fn query_child_pids(
    parent_pid: u32,
    buffer: &mut [libc::pid_t],
    deadline: Instant,
) -> Result<Vec<u32>, ProcQueryError> {
    let parent_pid =
        libc::pid_t::try_from(parent_pid).map_err(|_| ProcQueryError::Other(libc::EINVAL))?;
    query_pid_list(buffer, deadline, |buffer_ptr, size| {
        // SAFETY: `query_pid_list` supplies a valid bounded PID buffer.
        unsafe { libc::proc_listchildpids(parent_pid, buffer_ptr, size) }
    })
}

fn query_group_pids(
    group: u32,
    buffer: &mut [libc::pid_t],
    deadline: Instant,
) -> Result<Vec<u32>, ProcQueryError> {
    let group = libc::pid_t::try_from(group).map_err(|_| ProcQueryError::Other(libc::EINVAL))?;
    query_pid_list(buffer, deadline, |buffer_ptr, size| {
        // SAFETY: `query_pid_list` supplies a valid bounded PID buffer.
        unsafe { libc::proc_listpgrppids(group, buffer_ptr, size) }
    })
}

fn query_pid_list(
    buffer: &mut [libc::pid_t],
    deadline: Instant,
    mut call: impl FnMut(*mut libc::c_void, libc::c_int) -> libc::c_int,
) -> Result<Vec<u32>, ProcQueryError> {
    check_deadline(deadline).map_err(|_| ProcQueryError::Other(libc::ETIMEDOUT))?;
    buffer.fill(0);
    let byte_capacity =
        buffer_byte_capacity(buffer).map_err(|_| ProcQueryError::Other(libc::EINVAL))?;
    clear_errno();
    let count = call(buffer.as_mut_ptr().cast(), byte_capacity);
    check_deadline(deadline).map_err(|_| ProcQueryError::Other(libc::ETIMEDOUT))?;
    if count < 0 {
        return Err(ProcQueryError::from_errno());
    }
    if count == 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == 0 {
            return Ok(Vec::new());
        }
        return Err(if errno == libc::ESRCH {
            ProcQueryError::Vanished(errno)
        } else if errno == libc::EPERM || errno == libc::EACCES {
            ProcQueryError::Denied(errno)
        } else {
            ProcQueryError::Other(errno)
        });
    }
    let count = count as usize;
    let row_limit = buffer.len().saturating_sub(1);
    checked_pid_list_count(count, buffer.len(), row_limit)
        .map_err(|_| ProcQueryError::Other(libc::EOVERFLOW))?;
    let entries = &mut buffer[..count];
    if entries.iter().any(|pid| *pid < 0) {
        return Err(ProcQueryError::Other(libc::EINVAL));
    }
    entries.sort_unstable();
    if entries.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProcQueryError::Other(libc::EEXIST));
    }
    Ok(entries.iter().map(|pid| *pid as u32).collect())
}

fn query_bsd_info(pid: u32, deadline: Instant) -> Result<BsdInfo, ProcQueryError> {
    check_deadline(deadline).map_err(|_| ProcQueryError::Other(libc::ETIMEDOUT))?;
    let requested_pid =
        libc::pid_t::try_from(pid).map_err(|_| ProcQueryError::Other(libc::EINVAL))?;
    let mut topology = NativeProcessTopology {
        pid: 0,
        ppid: 0,
        pgid: 0,
        uid: 0,
        status: 0,
    };
    // SAFETY: the C shim accepts a positive pid_t and writes exactly the
    // fixed-size repr(C) result after validating the SDK kinfo_proc size and
    // returned PID. It uses sysctl(KERN_PROC_PID) only for read-only topology.
    let result = unsafe { ami_rust_query_process_topology(requested_pid, &mut topology) };
    check_deadline(deadline).map_err(|_| ProcQueryError::Other(libc::ETIMEDOUT))?;
    if result != 0 {
        return Err(ProcQueryError::from_error_code(result));
    }
    if topology.pid != requested_pid
        || topology.ppid < 0
        || topology.pgid <= 0
        || topology.status <= 0
    {
        return Err(ProcQueryError::Other(libc::EPROTO));
    }
    Ok(BsdInfo {
        pid: topology.pid as u32,
        ppid: topology.ppid as u32,
        pgid: topology.pgid as u32,
        uid: topology.uid as libc::uid_t,
        status: topology.status as u32,
    })
}

fn query_task_info(pid: u32, deadline: Instant) -> Result<u64, ProcQueryError> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| ProcQueryError::Other(libc::EINVAL))?;
    check_deadline(deadline).map_err(|_| ProcQueryError::Other(libc::ETIMEDOUT))?;
    // SAFETY: proc_pidinfo writes one proc_taskinfo to this initialized buffer.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    clear_errno();
    // SAFETY: the pointer and byte size describe the writable value above.
    let copied = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size_of::<libc::proc_taskinfo>() as libc::c_int,
        )
    };
    check_deadline(deadline).map_err(|_| ProcQueryError::Other(libc::ETIMEDOUT))?;
    if copied == size_of::<libc::proc_taskinfo>() as libc::c_int {
        Ok(info.pti_resident_size)
    } else if copied == 0 {
        Err(ProcQueryError::from_errno())
    } else {
        Err(ProcQueryError::Other(copied))
    }
}

fn resolve_taskinfo_esrch(
    pid: u32,
    sampled: ProcessInfo,
    deadline: Instant,
) -> TaskInfoEsrchResolution {
    match query_bsd_info(pid, deadline) {
        Ok(current) => {
            // An RSS ESRCH is only a known-zombie zero when the SDK topology
            // still identifies the same process in the same scope. A changed
            // PPID or PGID requires a fresh full closure so newly linked
            // descendants or group members are included.
            if current.pid != pid
                || current.uid != sampled.uid
                || current.ppid != sampled.ppid
                || current.pgid != sampled.pgid
            {
                return TaskInfoEsrchResolution::Retry(format!(
                    "PID {pid} topology changed while resolving taskinfo ESRCH (sampled uid={} ppid={} pgid={}, current uid={} ppid={} pgid={}); restarting full topology sample",
                    sampled.uid,
                    sampled.ppid,
                    sampled.pgid,
                    current.uid,
                    current.ppid,
                    current.pgid
                ));
            }
            if current.status == libc::SZOMB {
                TaskInfoEsrchResolution::KnownZombie
            } else {
                TaskInfoEsrchResolution::Live(format!(
                    "PID {pid} taskinfo returned ESRCH while SDK topology still reports live status {}; retrying this PID",
                    current.status
                ))
            }
        }
        Err(ProcQueryError::Vanished(_)) => TaskInfoEsrchResolution::Gone,
        Err(error) => TaskInfoEsrchResolution::Refuse(format!(
            "could not validate PID {pid} topology after taskinfo ESRCH: {}",
            error.describe()
        )),
    }
}

/// Retry transient task-table transitions for this PID, rather than requiring
/// an entire busy process tree to stop changing on the same three passes.
/// Identity/linkage changes still require a fresh full topology observation.
fn read_task_rss(
    pid: u32,
    uid: libc::uid_t,
    effective_uid: libc::uid_t,
    deadline: Instant,
    mut query: impl FnMut() -> Result<u64, ProcQueryError>,
    mut resolve: impl FnMut() -> TaskInfoEsrchResolution,
) -> io::Result<TaskRss> {
    for attempt in 1..=MAX_SAMPLE_ATTEMPTS {
        check_deadline(deadline).map_err(SampleFailure::into_io)?;
        match query() {
            Ok(bytes) => return Ok(TaskRss::Bytes(bytes)),
            Err(ProcQueryError::Vanished(_)) => match resolve() {
                TaskInfoEsrchResolution::KnownZombie => return Ok(TaskRss::Bytes(0)),
                TaskInfoEsrchResolution::Gone => return Ok(TaskRss::Gone),
                TaskInfoEsrchResolution::Retry(reason) => {
                    return Ok(TaskRss::RetryTopology(reason));
                }
                TaskInfoEsrchResolution::Refuse(reason) => return Err(input_error(reason)),
                TaskInfoEsrchResolution::Live(reason) => {
                    if attempt == MAX_SAMPLE_ATTEMPTS {
                        return Err(input_error(format!(
                            "{reason}; exhausted {MAX_SAMPLE_ATTEMPTS} bounded attempts for PID {pid}"
                        )));
                    }
                    pause_for_process_transition(deadline).map_err(SampleFailure::into_io)?;
                }
            },
            Err(error) => match classify_rss_query_error(error, pid, uid, effective_uid, attempt) {
                RssFailureAction::Retry(reason) => {
                    return Ok(TaskRss::RetryTopology(reason));
                }
                RssFailureAction::Refuse(reason) => return Err(input_error(reason)),
            },
        }
    }
    Err(input_error("bounded per-PID RSS observation exhausted"))
}

fn pause_for_process_transition(deadline: Instant) -> Result<(), SampleFailure> {
    check_deadline(deadline)?;
    std::thread::sleep(RETRYABLE_PROCESS_TRANSITION_DELAY);
    check_deadline(deadline)
}

fn direct_child_exit_observed(target_pid: u32, deadline: Instant) -> Result<bool, SampleFailure> {
    check_deadline(deadline)?;
    let target_pid = libc::pid_t::try_from(target_pid)
        .map_err(|_| SampleFailure::fatal("target PID exceeds libproc pid_t range"))?;
    // SAFETY: waitid initializes siginfo on success and WNOWAIT preserves the
    // capture-owned child's wait status for its eventual normal reap.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: P_PID targets only the direct child PID supplied by capture;
    // WNOHANG and WNOWAIT do not block or reap it.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            target_pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    check_deadline(deadline)?;
    if result != 0 {
        return Err(SampleFailure::fatal(format!(
            "could not verify direct-child WNOWAIT state before native process sample: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: successful waitid with P_PID returns SIGCHLD info; si_pid is
    // zero only when WNOHANG found no exited child.
    let observed_pid = unsafe { info.si_pid() } as u32;
    if observed_pid == 0 {
        Ok(false)
    } else if observed_pid == target_pid as u32 {
        Ok(true)
    } else {
        Err(SampleFailure::fatal(format!(
            "waitid returned an unexpected direct-child PID {observed_pid}"
        )))
    }
}

fn classify_rss_query_error(
    error: ProcQueryError,
    pid: u32,
    uid: libc::uid_t,
    effective_uid: libc::uid_t,
    attempt: usize,
) -> RssFailureAction {
    match error {
        ProcQueryError::Vanished(errno) if attempt < MAX_SAMPLE_ATTEMPTS => {
            RssFailureAction::Retry(format!(
                "in-scope PID {pid} vanished during RSS collection (errno={errno})"
            ))
        }
        ProcQueryError::Vanished(errno) => RssFailureAction::Refuse(format!(
            "in-scope PID {pid} vanished during RSS collection (errno={errno}); exhausted {MAX_SAMPLE_ATTEMPTS} bounded attempts"
        )),
        ProcQueryError::Denied(errno) => {
            let uid_class = if uid == effective_uid {
                "same-UID"
            } else {
                "foreign-UID"
            };
            RssFailureAction::Refuse(format!(
                "in-scope RSS is inaccessible for {uid_class} process pid={pid} uid={uid} euid={effective_uid} (errno={errno}); refusing to report an undercount"
            ))
        }
        other => RssFailureAction::Refuse(format!(
            "in-scope RSS query failed for pid={pid} uid={uid} euid={effective_uid}: {}",
            other.describe()
        )),
    }
}

fn enqueue_pid(
    pid: u32,
    pending: &mut VecDeque<Pending>,
    seen: &mut BTreeSet<u32>,
    missing_previous: &BTreeSet<u32>,
    maximum: usize,
) -> Result<(), SampleFailure> {
    if pid == 0 {
        return Err(SampleFailure::fatal(
            "libproc returned PID 0 in a user process tree",
        ));
    }
    if missing_previous.contains(&pid) {
        return Err(SampleFailure::retryable(format!(
            "previously absent PID {pid} reappeared in the linked process topology"
        )));
    }
    if seen.insert(pid) {
        if seen.len() > maximum {
            return Err(SampleFailure::fatal(
                "linked PID count exceeds caller row and history bounds",
            ));
        }
        pending.push_back(Pending::Pid(pid));
    }
    Ok(())
}

fn enqueue_group(
    group: u32,
    pending: &mut VecDeque<Pending>,
    seen: &mut BTreeSet<u32>,
    maximum: usize,
) -> Result<(), SampleFailure> {
    if group == 0 {
        return Err(SampleFailure::fatal(
            "libproc returned PGID 0 for a linked process",
        ));
    }
    if seen.insert(group) {
        if seen.len() > maximum {
            return Err(SampleFailure::fatal(
                "linked PGID count exceeds caller row and history bounds",
            ));
        }
        pending.push_back(Pending::Group(group));
    }
    Ok(())
}

fn bounded_pid_buffer_slots(
    maximum_bytes: usize,
    maximum_rows: usize,
) -> Result<(usize, usize), SampleFailure> {
    if maximum_bytes == 0 || maximum_rows == 0 {
        return Err(SampleFailure::fatal(
            "PID-list byte and row bounds must be positive",
        ));
    }
    let effective_byte_limit = maximum_bytes.min(MAX_PS_CAPTURE_BYTES);
    let c_int_slots = (libc::c_int::MAX as usize) / size_of::<libc::pid_t>();
    let byte_slots = effective_byte_limit / size_of::<libc::pid_t>();
    let available_slots = byte_slots.min(c_int_slots);
    if available_slots < 2 {
        return Err(SampleFailure::fatal(
            "PID-list byte bound cannot hold one row and an overflow sentinel",
        ));
    }
    let requested_slots = maximum_rows.saturating_add(1);
    let slots = available_slots.min(requested_slots);
    let row_limit = slots - 1;
    if row_limit == 0 {
        return Err(SampleFailure::fatal(
            "PID-list bounds cannot hold a process row",
        ));
    }
    Ok((row_limit, slots))
}

fn buffer_byte_capacity(buffer: &[libc::pid_t]) -> Result<libc::c_int, SampleFailure> {
    buffer
        .len()
        .checked_mul(size_of::<libc::pid_t>())
        .and_then(|bytes| libc::c_int::try_from(bytes).ok())
        .ok_or_else(|| SampleFailure::fatal("libproc PID buffer exceeds c_int capacity"))
}

fn checked_pid_list_count(
    count: usize,
    buffer_slots: usize,
    row_limit: usize,
) -> io::Result<usize> {
    if count > row_limit || count > buffer_slots {
        return Err(input_error(format!(
            "libproc process list exceeds caller row bound ({count} > {row_limit})"
        )));
    }
    Ok(count)
}

fn check_deadline(deadline: Instant) -> Result<(), SampleFailure> {
    if Instant::now() >= deadline {
        Err(SampleFailure::fatal(
            "native process-table sampling exceeded its two-second query budget",
        ))
    } else {
        Ok(())
    }
}

fn clear_errno() {
    // SAFETY: __error returns this thread's errno slot on macOS.
    unsafe { *libc::__error() = 0 };
}

fn input_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn allocation_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        io::{BufRead, BufReader, Write},
        os::unix::process::{CommandExt, ExitStatusExt},
        process::{Child, Command, Stdio},
        thread,
    };

    struct LiveTree {
        root: Child,
        root_pgid: u32,
        leaf_pid: u32,
        leaf_pgid: u32,
    }

    impl LiveTree {
        fn start() -> Self {
            let mut child = Command::new(env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--nocapture",
                    "--test-threads=2",
                    "live_tree_fixture",
                ])
                .env("AMI_RUST_MACOS_PROCESS_FIXTURE", "root")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn_guarded()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                assert!(
                    reader.read_line(&mut line).unwrap() > 0,
                    "fixture exited before readiness"
                );
                if line.starts_with("ROOTREADY ") {
                    break;
                }
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "malformed readiness record: {line:?}");
            Self {
                root: child,
                root_pgid: fields[2].parse().unwrap(),
                leaf_pid: fields[3].parse().unwrap(),
                leaf_pgid: fields[4].parse().unwrap(),
            }
        }
    }

    impl Drop for LiveTree {
        fn drop(&mut self) {
            // SAFETY: negative pid addresses only the fixture's known process
            // group, whose ID was emitted by its own setpgid call.
            unsafe {
                libc::kill(-(self.leaf_pgid as libc::pid_t), libc::SIGKILL);
                libc::kill(-(self.root_pgid as libc::pid_t), libc::SIGKILL);
            }
            let _ = self.root.wait();
        }
    }

    struct GroupHolder {
        child: Child,
        pgid: u32,
    }

    impl GroupHolder {
        fn start() -> Self {
            let mut child = Command::new(env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--nocapture",
                    "--test-threads=2",
                    "group_holder_fixture",
                ])
                .env("AMI_RUST_MACOS_PROCESS_FIXTURE", "holder")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn_guarded()
                .unwrap();
            let mut reader = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            loop {
                line.clear();
                assert!(
                    reader.read_line(&mut line).unwrap() > 0,
                    "group-holder fixture exited before readiness"
                );
                if line.starts_with("GROUPREADY ") {
                    break;
                }
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            assert_eq!(fields.len(), 2, "malformed readiness record: {line:?}");
            Self {
                child,
                pgid: fields[1].parse().unwrap(),
            }
        }
    }

    impl Drop for GroupHolder {
        fn drop(&mut self) {
            // SAFETY: this targets only the fixture-owned process group.
            unsafe { libc::kill(-(self.pgid as libc::pid_t), libc::SIGKILL) };
            let _ = self.child.wait();
        }
    }

    #[test]
    fn live_memory_child_in_distinct_group_is_observed_with_rss() {
        let fixture = LiveTree::start();
        assert_ne!(fixture.root_pgid, fixture.leaf_pgid);
        let scope = query_process_scope(
            self::process_id_from_child(&fixture.root),
            &[],
            &[],
            2 * 1024 * 1024,
            32_768,
            32_768,
        )
        .unwrap();
        assert!(
            scope
                .process_ids
                .contains(&self::process_id_from_child(&fixture.root))
        );
        assert!(scope.process_ids.contains(&fixture.leaf_pid));
        assert!(scope.process_groups.contains(&fixture.root_pgid));
        assert!(scope.process_groups.contains(&fixture.leaf_pgid));
        assert!(
            scope.rss_bytes >= 16 * 1024 * 1024,
            "touched 32 MiB child was not measured: {} bytes",
            scope.rss_bytes
        );
    }

    #[test]
    fn exited_unreaped_root_retains_escaped_group_and_zero_rss() {
        let holder = GroupHolder::start();
        let mut child = Command::new(env::current_exe().unwrap())
            .args([
                "--ignored",
                "--nocapture",
                "--test-threads=2",
                "zombie_fixture",
            ])
            .process_group(holder.pgid as libc::pid_t)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_guarded()
            .unwrap();
        let pid = child.id();
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid receives this initialized siginfo and WNOWAIT leaves
        // the direct child as a zombie for the native sample below.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut status,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(
            result,
            0,
            "waitid(WNOWAIT) failed: {}",
            io::Error::last_os_error()
        );
        unsafe { *libc::__error() = 0 };
        let zombie_pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
        assert_eq!(zombie_pgid, -1, "getpgid unexpectedly exposed a zombie");
        assert_eq!(
            unsafe { *libc::__error() },
            libc::ESRCH,
            "getpgid zombie control did not report ESRCH"
        );

        let ps_output = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "pid=,ppid=,pgid=,stat=,rss="])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .output_guarded()
            .unwrap();
        assert!(
            ps_output.status.success(),
            "outside-sandbox ps control failed: {}",
            String::from_utf8_lossy(&ps_output.stderr)
        );
        let ps_line = String::from_utf8(ps_output.stdout).unwrap();
        let ps_fields = ps_line.split_ascii_whitespace().collect::<Vec<_>>();
        assert_eq!(ps_fields.len(), 5, "malformed ps row: {ps_line:?}");
        assert_eq!(ps_fields[0].parse::<u32>().unwrap(), pid);
        assert_eq!(ps_fields[1].parse::<u32>().unwrap(), std::process::id());
        assert_eq!(ps_fields[2].parse::<u32>().unwrap(), holder.pgid);
        assert!(
            ps_fields[3].starts_with('Z'),
            "expected zombie ps row: {ps_line:?}"
        );
        assert_eq!(ps_fields[4].parse::<u64>().unwrap(), 0);

        let snapshot = query_process_scope(pid, &[], &[], 2 * 1024 * 1024, 32_768, 32_768).unwrap();
        let row = snapshot.rows.iter().find(|row| row.pid == pid).unwrap();
        assert_eq!(row.ppid, ps_fields[1].parse::<u32>().unwrap());
        assert_eq!(row.pgid, ps_fields[2].parse::<u32>().unwrap());
        assert_eq!(row.rss_kib, ps_fields[4].parse::<u64>().unwrap());
        eprintln!(
            "outside-sandbox zombie ps parity: ps={} native=pid:{} ppid:{} pgid:{} rss_kib:{} status:SZOMB",
            ps_fields.join(" "),
            row.pid,
            row.ppid,
            row.pgid,
            row.rss_kib
        );
        let scope = snapshot;
        assert!(scope.process_ids.contains(&holder.child.id()));
        assert!(scope.process_groups.contains(&holder.pgid));
        let exit_status = child.wait().unwrap();
        assert_eq!(exit_status.code(), Some(0));
        assert_eq!(exit_status.signal(), None);
    }

    #[test]
    fn pid_buffer_and_list_count_overflow_fail_closed() {
        assert_eq!(bounded_pid_buffer_slots(8, 32).unwrap(), (1, 2));
        assert!(bounded_pid_buffer_slots(4, 32).is_err());
        assert_eq!(checked_pid_list_count(1, 2, 1).unwrap(), 1);
        assert_eq!(
            checked_pid_list_count(2, 2, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn inaccessible_rss_is_refused_and_reports_uid_class() {
        let same_uid =
            classify_rss_query_error(ProcQueryError::Denied(libc::EPERM), 123, 501, 501, 1);
        let RssFailureAction::Refuse(message) = same_uid else {
            panic!("permission denial must not retry or produce zero RSS");
        };
        assert!(message.contains("same-UID"));
        assert!(message.contains("undercount"));

        let foreign_uid =
            classify_rss_query_error(ProcQueryError::Denied(libc::EACCES), 124, 502, 501, 1);
        let RssFailureAction::Refuse(message) = foreign_uid else {
            panic!("foreign-process permission denial must refuse");
        };
        assert!(message.contains("foreign-UID"));
    }

    #[test]
    fn topology_query_classifies_invalid_absent_and_denied_pids() {
        let deadline = Instant::now() + SAMPLE_BUDGET;
        assert!(matches!(
            query_bsd_info(0, deadline),
            Err(ProcQueryError::Other(libc::EINVAL))
        ));
        let mut exited = Command::new("/usr/bin/true").spawn_guarded().unwrap();
        let absent_pid = exited.id();
        assert!(exited.wait().unwrap().success());
        let absent_result = query_bsd_info(absent_pid, deadline);
        assert!(
            matches!(
                &absent_result,
                Err(ProcQueryError::Vanished(code)) if *code == libc::ESRCH
            ),
            "unexpected absent-PID classification: {:?}",
            absent_result.err()
        );
        assert!(matches!(
            ProcQueryError::from_error_code(libc::EPERM),
            ProcQueryError::Denied(libc::EPERM)
        ));
        assert!(matches!(
            ProcQueryError::from_error_code(libc::EACCES),
            ProcQueryError::Denied(libc::EACCES)
        ));
    }

    #[test]
    fn live_esrch_gets_only_three_observations_then_refuses() {
        for attempt in 1..MAX_SAMPLE_ATTEMPTS {
            assert!(matches!(
                classify_rss_query_error(
                    ProcQueryError::Vanished(libc::ESRCH),
                    321,
                    501,
                    501,
                    attempt
                ),
                RssFailureAction::Retry(_)
            ));
        }
        let RssFailureAction::Refuse(message) = classify_rss_query_error(
            ProcQueryError::Vanished(libc::ESRCH),
            321,
            501,
            501,
            MAX_SAMPLE_ATTEMPTS,
        ) else {
            panic!("persistent live ESRCH must stop after three attempts");
        };
        assert!(message.contains("exhausted 3 bounded attempts"));
    }

    #[test]
    fn task_rss_retries_the_same_live_pid_and_never_fills_missing_rss() {
        let mut attempts = 0;
        let result = read_task_rss(
            321,
            501,
            501,
            Instant::now() + SAMPLE_BUDGET,
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(ProcQueryError::Vanished(libc::ESRCH))
                } else {
                    Ok(8192)
                }
            },
            || TaskInfoEsrchResolution::Live("live transition".to_owned()),
        )
        .unwrap();
        assert!(matches!(result, TaskRss::Bytes(8192)));
        assert_eq!(attempts, 3);

        let mut attempts = 0;
        let error = read_task_rss(
            321,
            501,
            501,
            Instant::now() + SAMPLE_BUDGET,
            || {
                attempts += 1;
                Err(ProcQueryError::Vanished(libc::ESRCH))
            },
            || TaskInfoEsrchResolution::Live("persistently live".to_owned()),
        )
        .err()
        .unwrap();
        assert_eq!(attempts, 3);
        assert!(
            error
                .to_string()
                .contains("exhausted 3 bounded attempts for PID 321")
        );

        let result = read_task_rss(
            321,
            501,
            501,
            Instant::now() + SAMPLE_BUDGET,
            || Err(ProcQueryError::Vanished(libc::ESRCH)),
            || TaskInfoEsrchResolution::Gone,
        )
        .unwrap();
        assert!(matches!(result, TaskRss::Gone));
        let error = read_task_rss(
            321,
            501,
            501,
            Instant::now() + SAMPLE_BUDGET,
            || Err(ProcQueryError::Denied(libc::EPERM)),
            || panic!("denial must not be reclassified"),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("undercount"));
    }

    #[test]
    fn missing_parent_projection_preserves_live_child_in_another_group() {
        let snapshot = ProcessSnapshot {
            rows: vec![
                ProcessRow {
                    pid: 100,
                    ppid: 1,
                    pgid: 100,
                    rss_kib: 0,
                },
                ProcessRow {
                    pid: 101,
                    ppid: 100,
                    pgid: 100,
                    rss_kib: 0,
                },
                ProcessRow {
                    pid: 102,
                    ppid: 101,
                    pgid: 102,
                    rss_kib: 0,
                },
            ],
        };
        let initial = process_snapshot::observe_scope(&snapshot, 100, &[], &[], 32).unwrap();
        let missing = BTreeSet::from([101]);
        let rss = BTreeMap::from([(100, 4096), (102, 8192)]);
        let result =
            project_rss_scope(snapshot.clone(), &initial, 100, &[], &missing, &rss, 32).unwrap();
        assert_eq!(result.rss_bytes, 12 * 1024);
        assert!(result.process_groups.contains(&102));
        assert!(result.missing_previous_pids.contains(&101));
        assert_eq!(
            result
                .rows
                .iter()
                .map(|row| (row.pid, row.rss_kib))
                .collect::<Vec<_>>(),
            vec![(100, 4), (102, 8)]
        );
        assert!(
            project_rss_scope(
                snapshot.clone(),
                &initial,
                100,
                &[],
                &BTreeSet::from([100]),
                &rss,
                32
            )
            .is_err()
        );
        assert!(
            project_rss_scope(
                snapshot,
                &initial,
                100,
                &[],
                &missing,
                &BTreeMap::from([(100, 4096)]),
                32
            )
            .is_err(),
            "a live child with no RSS must refuse, not receive zero"
        );
    }

    #[test]
    fn short_lived_children_do_not_require_an_atomic_process_tree() {
        struct UnreapedGroup(Child);
        impl Drop for UnreapedGroup {
            fn drop(&mut self) {
                // No waiter has reaped this direct child; its PID reserves
                // the group ID. Never signal a historical numeric group.
                unsafe {
                    libc::kill(-(self.0.id() as libc::pid_t), libc::SIGKILL);
                }
                let _ = self.0.wait();
            }
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        for _ in 0..8 {
            let root = UnreapedGroup(Command::new("/bin/bash")
                .args(["-c", "i=0; while [ \"$i\" -lt 400 ]; do /usr/bin/true; i=$((i+1)); done; /bin/sleep 0.2"])
                .process_group(0).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn_guarded().unwrap());
            let mut pids = Vec::new();
            let mut groups = Vec::new();
            for _ in 0..80 {
                assert!(
                    Instant::now() < deadline,
                    "churn fixture exceeded its bounded run"
                );
                let scope =
                    query_process_scope(root.0.id(), &pids, &groups, 2 * 1024 * 1024, 32768, 32768)
                        .expect("a vanished child must not require a globally stable process tree");
                assert!(scope.root_present);
                pids.extend(scope.process_ids);
                pids.sort_unstable();
                pids.dedup();
                groups = scope.process_groups;
            }
        }
    }

    #[test]
    fn repeated_fast_failures_accept_only_matching_sdk_zombie_topology() {
        for _ in 0..12 {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r release; exit 23"])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn_guarded()
                .unwrap();
            let pid = child.id();
            let deadline = Instant::now() + SAMPLE_BUDGET;
            let sampled = query_bsd_info(pid, deadline)
                .expect("blocked fast-failure child should have queryable live topology");
            assert_ne!(sampled.status, libc::SZOMB);
            let sampled_info = ProcessInfo {
                uid: sampled.uid,
                status: sampled.status,
                ppid: sampled.ppid,
                pgid: sampled.pgid,
            };
            assert!(
                matches!(
                    resolve_taskinfo_esrch(pid, sampled_info, deadline),
                    TaskInfoEsrchResolution::Live(_)
                ),
                "a live SDK status must never turn ESRCH into zero RSS"
            );

            let mut release = child.stdin.take().unwrap();
            release.write_all(b"exit\n").unwrap();
            release.flush().unwrap();
            drop(release);

            let exit_deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if direct_child_exit_observed(pid, exit_deadline).unwrap() {
                    break;
                }
                assert!(
                    Instant::now() < exit_deadline,
                    "fast-failure child did not become an unreaped zombie"
                );
                thread::sleep(Duration::from_millis(1));
            }

            assert!(matches!(
                resolve_taskinfo_esrch(pid, sampled_info, deadline),
                TaskInfoEsrchResolution::KnownZombie
            ));

            let mut changed_parent = sampled_info;
            changed_parent.ppid = changed_parent.ppid.saturating_add(1);
            let mut changed_group = sampled_info;
            changed_group.pgid = changed_group.pgid.saturating_add(1);
            let mut changed_uid = sampled_info;
            changed_uid.uid = changed_uid.uid.wrapping_add(1);
            for changed_topology in [changed_parent, changed_group, changed_uid] {
                assert!(matches!(
                    resolve_taskinfo_esrch(pid, changed_topology, deadline),
                    TaskInfoEsrchResolution::Retry(_)
                ));
            }

            let snapshot =
                query_process_scope(pid, &[], &[], 2 * 1024 * 1024, 32_768, 32_768).unwrap();
            let row = snapshot.rows.iter().find(|row| row.pid == pid).unwrap();
            assert_eq!(row.ppid, sampled.ppid);
            assert_eq!(row.pgid, sampled.pgid);
            assert_eq!(row.rss_kib, 0, "only SDK-confirmed SZOMB may have zero RSS");
            assert_eq!(child.wait().unwrap().code(), Some(23));
        }
    }

    #[test]
    #[ignore = "spawned only by the native live-tree control"]
    fn live_tree_fixture() {
        if env::var("AMI_RUST_MACOS_PROCESS_FIXTURE").as_deref() != Ok("root") {
            return;
        }
        // SAFETY: this standalone fixture changes only its own process group.
        assert_eq!(unsafe { libc::setpgid(0, 0) }, 0);
        let root_pgid = unsafe { libc::getpgid(0) } as u32;
        let mut leaf = Command::new(env::current_exe().unwrap())
            .args([
                "--ignored",
                "--nocapture",
                "--test-threads=2",
                "live_leaf_fixture",
            ])
            .env("AMI_RUST_MACOS_PROCESS_FIXTURE", "leaf")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn_guarded()
            .unwrap();
        let mut line = String::new();
        let mut reader = BufReader::new(leaf.stdout.take().unwrap());
        loop {
            line.clear();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "leaf exited before readiness"
            );
            if line.starts_with("LEAFREADY ") {
                break;
            }
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 3, "malformed leaf readiness: {line:?}");
        println!(
            "ROOTREADY {} {root_pgid} {} {}",
            std::process::id(),
            fields[1],
            fields[2]
        );
        io::stdout().flush().unwrap();
        loop {
            thread::sleep(Duration::from_secs(30));
            if leaf.try_wait().unwrap().is_some() {
                panic!("leaf exited before the process sample");
            }
        }
    }

    #[test]
    #[ignore = "spawned only by the native live-tree control"]
    fn live_leaf_fixture() {
        if env::var("AMI_RUST_MACOS_PROCESS_FIXTURE").as_deref() != Ok("leaf") {
            return;
        }
        // SAFETY: this standalone fixture changes only its own process group.
        assert_eq!(unsafe { libc::setpgid(0, 0) }, 0);
        let process_id = std::process::id();
        let process_group = unsafe { libc::getpgid(0) } as u32;
        let byte_count = 32 * 1024 * 1024;
        let mut memory = Vec::new();
        memory.try_reserve_exact(byte_count).unwrap();
        memory.resize(byte_count, 0_u8);
        for offset in (0..byte_count).step_by(4096) {
            memory[offset] = 0xa5;
        }
        std::hint::black_box(&memory);
        println!("LEAFREADY {process_id} {process_group}");
        io::stdout().flush().unwrap();
        loop {
            std::hint::black_box(memory.len());
            thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    #[ignore = "spawned only by the escaped-group zombie control"]
    fn group_holder_fixture() {
        if env::var("AMI_RUST_MACOS_PROCESS_FIXTURE").as_deref() != Ok("holder") {
            return;
        }
        // SAFETY: this standalone fixture changes only its own process group.
        assert_eq!(unsafe { libc::setpgid(0, 0) }, 0);
        let process_group = unsafe { libc::getpgid(0) } as u32;
        println!("GROUPREADY {process_group}");
        io::stdout().flush().unwrap();
        loop {
            thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    #[ignore = "spawned only by the unreaped-zombie control"]
    fn zombie_fixture() {}

    fn process_id_from_child(child: &Child) -> u32 {
        child.id()
    }
}
