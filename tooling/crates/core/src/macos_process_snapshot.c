#include <errno.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <sys/types.h>

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
