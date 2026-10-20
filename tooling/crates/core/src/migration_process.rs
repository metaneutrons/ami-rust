//! Deny new executable-image transitions while the CLI migration hashes
//! the legacy interpreter as inert data. Do not call this from core rendering;
//! the CLI must enter it only after parsing an inspection/dry-run or write migration.

use crate::Result;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64 {
    use crate::{Refusal, Result};

    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
    const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: libc::c_long = 1;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JSET_K: u16 = 0x45;
    const BPF_RET_K: u16 = 0x06;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    fn filter() -> Vec<SockFilter> {
        let denied = SECCOMP_RET_ERRNO | libc::EACCES as u32;
        vec![
            // Require the x86-64 syscall ABI; a different ABI is not reviewed.
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_X86_64,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            // Reject x32's syscall-number bit before comparing syscall numbers.
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP_JSET_K,
                jt: 0,
                jf: 1,
                k: X32_SYSCALL_BIT,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: denied,
            },
            // A migration may read/hash the old interpreter, but may not start
            // another image through either Linux executable-image syscall.
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: libc::SYS_execve as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: denied,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: libc::SYS_execveat as u32,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: denied,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ]
    }

    #[allow(
        unsafe_code,
        reason = "Linux migration installs a process-wide seccomp filter through prctl and seccomp syscalls."
    )]
    pub(super) fn install() -> Result<()> {
        // Allocate the complete, immutable BPF program before making this
        // process's security state irreversible.
        let instructions = filter();
        let program = SockFprog {
            len: instructions.len() as u16,
            filter: instructions.as_ptr(),
        };

        // SAFETY: PR_SET_NO_NEW_PRIVS takes scalar arguments and is required
        // before an unprivileged seccomp filter can be installed.
        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(Refusal::new(format!(
                "cannot set no_new_privs for migration: {}",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: `program` points to a valid classic-BPF instruction slice
        // that stays alive for the syscall. TSYNC applies the filter to every
        // thread in the process; this returns 0 on success or a nonzero TID / -1.
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC,
                &program as *const SockFprog,
            )
        };
        if result == -1 {
            return Err(Refusal::new(format!(
                "cannot install migration seccomp filter: {}",
                std::io::Error::last_os_error()
            )));
        }
        if result != 0 {
            return Err(Refusal::new(format!(
                "migration seccomp TSYNC returned unexpected thread id {result}"
            )));
        }
        Ok(())
    }
}

/// Prevent future executable-image transitions for this process on Linux
/// x86-64. The caller must invoke this only in the CLI migration process,
/// after argument parsing and before migration inspection or writing.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn enter() -> Result<()> {
    linux_x86_64::install()
}

/// The supported macOS profile uses its separate no-exec enforcement backend.
/// Unsupported hosts are rejected by host selection before this CLI path.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn enter() -> Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::c_char,
        ptr,
        sync::mpsc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    const EXEC_PATH: &[u8] = b"/bin/sh\0";
    const ARG0: &[u8] = b"sh\0";
    const DASH_C: &[u8] = b"-c\0";
    const EXIT_93: &[u8] = b"exit 93\0";
    const EXIT_94: &[u8] = b"exit 94\0";

    #[allow(
        unsafe_code,
        reason = "The Linux-only regression probe invokes execve directly to verify the installed syscall filter."
    )]
    fn execve_errno(script: &'static [u8]) -> (libc::c_long, libc::c_int) {
        let argv: [*const c_char; 4] = [
            ARG0.as_ptr().cast(),
            DASH_C.as_ptr().cast(),
            script.as_ptr().cast(),
            ptr::null(),
        ];
        let envp: [*const c_char; 1] = [ptr::null()];
        // SAFETY: all C strings and pointer arrays remain live and NUL-terminated
        // during syscall. A successful exec replaces this process/thread image.
        let result = unsafe {
            libc::syscall(
                libc::SYS_execve,
                EXEC_PATH.as_ptr().cast::<c_char>(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        };
        // SAFETY: Linux exposes the calling thread's errno slot at this pointer.
        let error = unsafe { *libc::__errno_location() };
        (result, error)
    }

    #[allow(
        unsafe_code,
        reason = "The Linux-only regression probe invokes execveat directly to verify the installed syscall filter."
    )]
    fn execveat_errno(script: &'static [u8]) -> (libc::c_long, libc::c_int) {
        let argv: [*const c_char; 4] = [
            ARG0.as_ptr().cast(),
            DASH_C.as_ptr().cast(),
            script.as_ptr().cast(),
            ptr::null(),
        ];
        let envp: [*const c_char; 1] = [ptr::null()];
        // SAFETY: all C strings and pointer arrays remain live and NUL-terminated
        // during syscall. AT_FDCWD plus the absolute path is a valid execveat form.
        let result = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                -100,
                EXEC_PATH.as_ptr().cast::<c_char>(),
                argv.as_ptr(),
                envp.as_ptr(),
                0,
            )
        };
        // SAFETY: Linux exposes the calling thread's errno slot at this pointer.
        let error = unsafe { *libc::__errno_location() };
        (result, error)
    }

    #[allow(
        unsafe_code,
        reason = "The isolated Linux regression test forks and waits so it can check seccomp inheritance without risking the test harness."
    )]
    fn fork_inheritance_probe() -> std::result::Result<(), String> {
        // SAFETY: fork is used only after the preexisting worker has joined.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let (exec_result, exec_error) = execve_errno(EXIT_93);
            if exec_result != -1 || exec_error != libc::EACCES {
                // SAFETY: _exit is async-signal-safe and avoids Rust cleanup in
                // the post-fork child if an executable transition was not denied.
                unsafe { libc::_exit(81) }
            }
            let (at_result, at_error) = execveat_errno(EXIT_94);
            if at_result != -1 || at_error != libc::EACCES {
                // SAFETY: _exit is async-signal-safe and avoids Rust cleanup in
                // the post-fork child if execveat was not denied.
                unsafe { libc::_exit(82) }
            }
            // SAFETY: _exit avoids touching inherited Rust runtime state.
            unsafe { libc::_exit(0) }
        }
        if pid < 0 {
            return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
        }
        let mut status = 0;
        // SAFETY: waitpid consumes only the direct child created above.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited != pid {
            return Err(format!(
                "waitpid failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if status & 0x7f != 0 || ((status >> 8) & 0xff) != 0 {
            return Err(format!(
                "forked child did not inherit both denials (wait status {status:#x})"
            ));
        }
        Ok(())
    }

    #[test]
    fn filter_behavior_is_checked_only_in_an_isolated_child() {
        for (test, expected) in [
            ("unfiltered_execve_control", 93),
            ("unfiltered_execveat_control", 94),
        ] {
            let control = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("migration_process::tests::{test}"),
                    "--ignored",
                    "--nocapture",
                ])
                .output()
                .unwrap();
            assert_eq!(
                control.status.code(),
                Some(expected),
                "unfiltered syscall control must execute its marker"
            );
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "migration_process::tests::isolated_filter_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child stdout:\n{}\nchild stderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "replaces the process image; invoked only by the parent positive control"]
    fn unfiltered_execve_control() {
        panic!(
            "unfiltered execve unexpectedly returned: {:?}",
            execve_errno(EXIT_93)
        );
    }

    #[test]
    #[ignore = "replaces the process image; invoked only by the parent positive control"]
    fn unfiltered_execveat_control() {
        panic!(
            "unfiltered execveat unexpectedly returned: {:?}",
            execveat_errno(EXIT_94)
        );
    }

    #[test]
    #[ignore = "installs an irreversible process filter; run only through the isolated parent test"]
    fn isolated_filter_worker() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let file = std::env::temp_dir().join(format!(
            "migration-seccomp-read-{}-{unique}",
            std::process::id()
        ));
        let expected = b"ordinary migration file hashing remains available";
        std::fs::write(&file, expected).unwrap();

        // Park a worker before enter(); TSYNC must install the filter there too.
        let (ready_tx, ready_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            start_rx.recv().unwrap();
            let (result, error) = execve_errno(EXIT_93);
            result_tx.send((result, error)).unwrap();
        });
        ready_rx.recv().unwrap();

        enter().expect("Linux x86-64 seccomp installation must succeed");
        start_tx.send(()).unwrap();
        assert_eq!(result_rx.recv().unwrap(), (-1, libc::EACCES));
        worker.join().unwrap();

        let bytes = std::fs::read(&file).expect("ordinary file read remains permitted");
        assert_eq!(Sha256::digest(bytes), Sha256::digest(expected));
        fork_inheritance_probe().unwrap();
        std::fs::remove_file(file).unwrap();
    }
}
