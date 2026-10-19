// SPDX-License-Identifier: MIT OR Apache-2.0
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: embedded-libpython ABSOLUTE-LIBPYTHON-PATH\n");
        return 2;
    }
    errno = 0;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fprintf(stderr, "DLOPEN_DENIED errno=%d message=%s\n", errno, dlerror());
        return 82;
    }
    void (*initialize)(void) = (void (*)(void))dlsym(library, "Py_Initialize");
    int (*run_string)(const char *) =
        (int (*)(const char *))dlsym(library, "PyRun_SimpleString");
    int (*finalize)(void) = (int (*)(void))dlsym(library, "Py_FinalizeEx");
    if (initialize == NULL || run_string == NULL || finalize == NULL) {
        fprintf(stderr, "embedded Python API is incomplete\n");
        dlclose(library);
        return 3;
    }
    initialize();
    int result = run_string("print('ADAPTER_EMBEDDED_PYTHON_MARKER')");
    int finalization = finalize();
    dlclose(library);
    return result == 0 && finalization == 0 ? 0 : 4;
}
