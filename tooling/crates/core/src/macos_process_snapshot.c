#include <errno.h>
#include <stdint.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

struct ami_rust_zombie_group_observation {
    int32_t group;
    uint32_t effective_uid;
    int32_t complete;
    uint32_t record_count;
    int32_t member_pid;
    int32_t member_group;
    uint32_t member_uid;
    int32_t member_status;
};

_Static_assert(sizeof(struct ami_rust_zombie_group_observation) == 32,
               "Rust and C zombie-group observation layouts must match");

struct ami_rust_process_topology {
    int32_t pid;
    int32_t parent_pid;
    int32_t process_group;
    uint32_t user_id;
    int32_t status;
};

_Static_assert(sizeof(pid_t) == sizeof(int32_t), "macOS pid_t ABI changed");
_Static_assert(sizeof(uid_t) == sizeof(uint32_t), "macOS uid_t ABI changed");
_Static_assert(sizeof(struct ami_rust_process_topology) == 20, "Rust/C topology ABI changed");

int ami_rust_query_process_topology(int32_t requested_pid,
                                    struct ami_rust_process_topology *result) {
    if (requested_pid <= 0 || result == 0) {
        return EINVAL;
    }

    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, requested_pid};
    struct kinfo_proc info = {0};
    size_t returned_size = sizeof(info);
    errno = 0;
    if (sysctl(mib, 4, &info, &returned_size, 0, 0) != 0) {
        return errno != 0 ? errno : EIO;
    }
    if (returned_size == 0) {
        return ESRCH;
    }
    if (returned_size != sizeof(info)) {
        return EPROTO;
    }
    if (info.kp_proc.p_pid != requested_pid) {
        return EPROTO;
    }
    if (info.kp_eproc.e_ppid < 0 || info.kp_eproc.e_pgid <= 0 ||
        info.kp_proc.p_stat <= 0) {
        return EPROTO;
    }

    result->pid = (int32_t)info.kp_proc.p_pid;
    result->parent_pid = (int32_t)info.kp_eproc.e_ppid;
    result->process_group = (int32_t)info.kp_eproc.e_pgid;
    result->user_id = (uint32_t)info.kp_eproc.e_ucred.cr_uid;
    result->status = (int32_t)info.kp_proc.p_stat;
    return 0;
}

int ami_rust_classify_owned_zombie_group_observation(
    const struct ami_rust_zombie_group_observation *observation) {
    return observation != 0 && observation->group > 0 &&
                   observation->complete == 1 &&
                   observation->record_count == 1 &&
                   observation->member_pid == observation->group &&
                   observation->member_group == observation->group &&
                   observation->member_uid == observation->effective_uid &&
                   observation->member_status == SZOMB
               ? 1
               : 0;
}

int ami_rust_process_group_is_owned_zombie_only(int32_t group) {
    if (group <= 0) {
        return 0;
    }

    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PGRP, group};
    struct kinfo_proc processes[2] = {0};
    size_t returned_size = sizeof(processes);
    if (sysctl(mib, 4, processes, &returned_size, 0, 0) != 0) {
        return 0;
    }

    // XNU's KERN_PROC_PGRP result includes both live processes and zombies.
    // Its implementation fails with ENOMEM when the supplied result buffer is
    // too small, so any failed, truncated, or structurally incomplete query
    // must remain non-affirmative.
    const int complete = returned_size <= sizeof(processes) &&
                         returned_size % sizeof(processes[0]) == 0;
    const size_t record_count =
        complete ? returned_size / sizeof(processes[0]) : 0;
    const struct kinfo_proc *member = record_count == 1 ? &processes[0] : 0;
    const struct ami_rust_zombie_group_observation observation = {
        .group = group,
        .effective_uid = (uint32_t)geteuid(),
        .complete = complete,
        .record_count = (uint32_t)record_count,
        .member_pid = member == 0 ? 0 : (int32_t)member->kp_proc.p_pid,
        .member_group = member == 0 ? 0 : (int32_t)member->kp_eproc.e_pgid,
        .member_uid = member == 0 ? 0 : (uint32_t)member->kp_eproc.e_ucred.cr_uid,
        .member_status = member == 0 ? 0 : (int32_t)member->kp_proc.p_stat,
    };

    return ami_rust_classify_owned_zombie_group_observation(&observation);
}
