/* Qualification-only DOS controls; these hooks are absent from the SDK ABI. */
#ifndef AMI_RUST_TEST_FILE_CONTROLS_H
#define AMI_RUST_TEST_FILE_CONTROLS_H

#ifdef AMI_SDK_TESTING
#include <stddef.h>
#include <stdint.h>

/*
 * This header is included by sdk.c after the pinned DOS/Exec headers. Keep
 * these controls confined to the two qualification fixtures and the owner
 * task that runs them. The production SDK ABI does not expose them.
 */
static const uint8_t ami_test_protected_path[] = "RAM:ami-rust-m1/protected.bin";
static const uint8_t ami_test_sentinel_path[] = "RAM:ami-rust-m1/protection-sentinel.bin";

struct AmiTestSavedProtection {
    ULONG original;
    int valid;
};

static struct AmiTestSavedProtection ami_test_saved_protection[2];

static int ami_test_path_equal(const uint8_t *path, const uint8_t *expected, size_t size)
{
    if (!path)
        return 0;
    for (size_t i = 0; i < size; ++i) {
        if (path[i] != expected[i])
            return 0;
        if (expected[i] == 0)
            return 1;
    }
    return 0;
}

static int ami_test_path_index(const uint8_t *path)
{
    if (ami_test_path_equal(path, ami_test_protected_path, sizeof(ami_test_protected_path)))
        return 0;
    if (ami_test_path_equal(path, ami_test_sentinel_path, sizeof(ami_test_sentinel_path)))
        return 1;
    return -1;
}

int64_t sdk_test_attributes(const uint8_t *path, uint32_t *protection, uint64_t *size);

/*
 * Both hooks accept only the exact fixture paths below RAM:ami-rust-m1/.
 * They return 0 on success; native DOS failures return the immediately
 * captured IoErr. Invalid arguments or paths return INT64_MIN. Calling
 * sdk_test_protect(path, 1) denies FIBF_READ; passing 0 restores that path's
 * saved original protection exactly.
 *
 * Attribute reads use the pinned M0 FileInfoBlock32 selected with __DOS64
 * undefined. Each successful Lock is passed to UnLock exactly once on every
 * branch. These test hooks allocate no memory and emit no diagnostics.
 */
int64_t sdk_test_protect(const uint8_t *path, int32_t deny_read)
{
    int index = ami_test_path_index(path);
    if (index < 0 || (deny_read != 0 && deny_read != 1))
        return INT64_MIN;

    struct AmiTestSavedProtection *saved = &ami_test_saved_protection[index];
    ULONG desired;
    if (deny_read) {
        if (!saved->valid) {
            uint32_t protection = 0;
            uint64_t file_size = 0;
            int64_t result = sdk_test_attributes(path, &protection, &file_size);
            if (result != 0)
                return result;
            saved->original = (ULONG)protection;
            /* Keep the restore value if SetProtection reports a failure. */
            saved->valid = 1;
        }
        desired = saved->original | (ULONG)FIBF_READ;
    } else {
        if (!saved->valid)
            return INT64_MIN;
        desired = saved->original;
    }

    if (!SetProtection((CONST_STRPTR)path, desired)) {
        SIPTR error = IoErr();
        return error != 0 ? (int64_t)error : INT64_MIN;
    }

    if (!deny_read)
        saved->valid = 0;
    return 0;
}

int64_t sdk_test_attributes(const uint8_t *path, uint32_t *protection, uint64_t *size)
{
    if (ami_test_path_index(path) < 0 || !protection || !size)
        return INT64_MIN;

    struct FileInfoBlock info;
    BPTR lock = Lock((CONST_STRPTR)path, SHARED_LOCK);
    if (lock == BNULL) {
        SIPTR error = IoErr();
        return error != 0 ? (int64_t)error : INT64_MIN;
    }

    if (!Examine(lock, &info)) {
        /* Capture the primary failure before UnLock can change IoErr. */
        SIPTR error = IoErr();
        if (!UnLock(lock)) {
            SIPTR unlock_error = IoErr();
            if (error == 0)
                error = unlock_error;
        }
        return error != 0 ? (int64_t)error : INT64_MIN;
    }

    ULONG file_protection = (ULONG)info.fib_Protection;
    LONG file_size = info.fib_Size;
    if (!UnLock(lock)) {
        SIPTR error = IoErr();
        return error != 0 ? (int64_t)error : INT64_MIN;
    }
    if (file_size < 0)
        return INT64_MIN;

    *protection = (uint32_t)file_protection;
    *size = (uint64_t)file_size;
    return 0;
}

#endif /* AMI_SDK_TESTING */
#endif /* AMI_RUST_TEST_FILE_CONTROLS_H */
