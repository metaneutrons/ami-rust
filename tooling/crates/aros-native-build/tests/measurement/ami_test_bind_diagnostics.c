/* Test-only bridge: publish the relocated M1 counter to the GDB monitor. */
#include "../../scripts/measurement/m1_measurement.h"

void ami_test_bind_diagnostics(volatile uint64_t *depth) {
    volatile struct m0_watch *watch = m0_watcher();
    if (!watch) return;

    uintptr_t address = (uintptr_t)depth;
    if (!depth || (address & (sizeof(uint64_t) - 1))) {
        watch->diagnostic_depth_address = UINT64_MAX;
        return;
    }

    if (!watch->diagnostic_depth_address) {
        watch->diagnostic_depth_address = (uint64_t)address;
    } else if (watch->diagnostic_depth_address != (uint64_t)address) {
        /* A changed symbol address invalidates the whole measurement case. */
        watch->diagnostic_depth_address = UINT64_MAX;
    }
}

void ami_test_phase(uint64_t phase) {
    ami_test_measurement_stage(phase);
}

void ami_test_measurement_expected(uint64_t probe) {
    ami_test_measurement_set_expected(probe);
}
