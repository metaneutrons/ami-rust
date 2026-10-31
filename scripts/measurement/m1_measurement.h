/* Disposable M1 measurement protocol. Never include in an SDK release. */
#ifndef AMI_RUST_M1_MEASUREMENT_H
#define AMI_RUST_M1_MEASUREMENT_H

#include <stdint.h>
#include <stddef.h>
#include <exec/execbase.h>
#include <exec/tasks.h>
#include <proto/exec.h>

#define M0_WATCH_MAGIC UINT64_C(0x4d30574154434831)

/*
 * The first twelve words preserve the M0 r29 debugger protocol. The final
 * word publishes the relocated address of ami_sdk_diagnostic_depth. The
 * debugger watches this field, then installs a watchpoint on the published
 * 64-bit counter before the SDK can enter sdk_begin or a diagnostic call.
 */
struct m0_watch {
    uint64_t magic;
    uint64_t stage;
    uint64_t diag_depth;
    uint64_t diag_expected;
    uint64_t done;
    uint64_t ready;
    uint64_t native_free;
    uint64_t saved_id;
    uint64_t saved_td;
    uint64_t restored_id;
    uint64_t restored_td;
    uint64_t restored;
    uint64_t diagnostic_depth_address;
};

_Static_assert(offsetof(struct m0_watch, stage) == 8, "M0 stage offset");
_Static_assert(offsetof(struct m0_watch, diag_depth) == 16, "M0 depth offset");
_Static_assert(offsetof(struct m0_watch, diag_expected) == 24, "M0 expected offset");
_Static_assert(offsetof(struct m0_watch, done) == 32, "M0 done offset");
_Static_assert(offsetof(struct m0_watch, ready) == 40, "M0 ready offset");
_Static_assert(offsetof(struct m0_watch, native_free) == 48, "M0 free offset");
_Static_assert(offsetof(struct m0_watch, diagnostic_depth_address) == 96,
               "M1 depth-address offset");
_Static_assert(sizeof(struct m0_watch) == 104, "M1 watch record size");

static inline volatile struct m0_watch *m0_watcher(void) {
#ifdef AMI_RUST_ABI11
    /* The pinned ABI-v11 ExecBase has no ThisTask member. */
    struct Task *task = SysBase ? FindTask(0) : 0;
#else
    struct Task *task = SysBase ? SysBase->ThisTask : 0;
#endif
    volatile struct m0_watch *watch = task ? (void *)task->tc_UserData : 0;
    return watch && watch->magic == M0_WATCH_MAGIC ? watch : 0;
}

static inline void ami_test_measurement_stage(uint64_t stage) {
    volatile struct m0_watch *watch = m0_watcher();
    if (watch) watch->stage = stage;
}

static inline void ami_test_measurement_set_expected(uint64_t probe) {
    volatile struct m0_watch *watch = m0_watcher();
    if (watch) watch->diag_expected = probe;
}

/* Test-only C entry points used by the disposable native qualification binary. */
void ami_test_phase(uint64_t phase);
void ami_test_measurement_expected(uint64_t probe);

#endif
