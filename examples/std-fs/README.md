# std-fs

Native test of the file system in `std` on AROS: files (open, read, write, seek, truncate,
duplicate), metadata and file dates, permissions, directories (`read_dir`, `create_dir`,
`remove_dir`), `copy`, the error kinds, and the behaviours of the C library that `std` has to
work around.
One behaviour per run, chosen by the first argument. Like the other `std` programs it is not
a workspace member: it needs the patched `std` of `host/std-aros/` and a toolchain with the
new target specifications and the bridge of this tree (see `examples/std-runtime/README.md`
for the build). It is listed as in development under #68 because the native matrix cannot
build it yet.

The files are made in `RAM:ami-rust-m1/`, which the run must create (`MakeDir`). The program
starts on the read-only delivery volume, so the run also needs `CD RAM:ami-rust-m1` for the
relative-path check.

## What is implemented, and what is not

Implemented: `File::open`, `File::create`, `OpenOptions` (read, write, append, truncate,
create, create_new), `read`, `write`, `seek`, `stream_position`, `set_len`, `sync_all`,
`sync_data`, `try_clone`, `fs::remove_file`; and, in the second slice, `fs::metadata`,
`symlink_metadata`, `File::metadata`, `Permissions` (read-only), `fs::set_permissions` and
`File::set_permissions`, `fs::read_dir`, `fs::create_dir` and `create_dir_all`, `fs::remove_dir`,
`fs::remove_dir_all`, `fs::copy` and `fs::exists`, with everything built on them.

Everything else in `std::fs` returns `ErrorKind::Unsupported`, which the `unsupported` mode
checks: `File::lock` and `try_lock`, `File::set_modified` and `set_times`, `rename`,
`canonicalize`, `read_link`, `hard_link` and symbolic links. The next slice implements `rename`,
`canonicalize`, file times and `std::path` (AROS path syntax).

What the file metadata contains: the size, the type (file or directory; there is no `symlink`
without symbolic links), the read-only flag, and one date. DOS keeps one date per object, so
`modified()` and `accessed()` return the same value with a resolution of one second, and
`created()` is `Unsupported`. The date is already converted from the DOS epoch (1978) by the C
library, so `std` does not convert it: a file written now is within a second of `SystemTime::now`,
also with the clock set to 2040 and 2100 (`times` mode with a changed clock).

## Behaviours of the C library that `std` works around

Each was found by this test, and each has a check that fails without the workaround.

1. **DOS requesters.** A path on a volume that is not there opens "Please insert volume X in
   any drive" and waits for a person, so a program started from a script never returns (seen on
   a screendump). By default `std` switches requesters off around calls that resolve a path, through
   the bridge function `sdk_proc_window_set`, and restores the setting afterwards. The failure is then
   `NotFound`, at once. A program can change this at any time, see "Requesters" below.
2. **Access modes.** The C library accepted a write on a handle opened for reading and a read on
   one opened for writing. `std` refuses both with `EBADF`.
3. **Append.** A write on a handle opened for append after a `seek` did not go to the end. `std`
   moves to the end before every write of an append handle.
4. **Seek past the end.** The C library extends the file at once, on both ABIs, and for a
   handle that can only read as well: a read-only `seek(Start(3000))` on a 1000-byte file made it
   3000 bytes long. On ABI-v11 it also extends by the wrong amount: `Start(n)` and `Current(n)`
   past the end give the position `n` plus the size of the file (4000 for the case above).
   `End(n)` with `n` at most 0 is right on both ABIs. `std` never hands a seek past the end to the
   C library: it remembers the position, reads there return 0, and the next write extends the file
   with zeros, which is what POSIX does. The result is identical on both ABIs.
5. **Removing an open file.** On ABI-v1 `unlink` of a file that is open fails with "object not
   found" although the file is there; on ABI-v11 it fails with "busy". Code that treats `NotFound`
   from `remove_file` as "already gone" would leave the file behind, so `std` reports a file that
   can still be opened as busy.

6. **Wrong kind of object.** The C library's `rmdir` is `DeleteFile`, so `rmdir` of a **file**
   deletes the file, and `unlink` of an **empty directory** deletes the directory (both measured
   on both ABIs, AROS-NX#132). `std` examines the path first and refuses with `NotADirectory` or
   `IsADirectory`; between the check and the delete there is a race.
7. **`rmdir` of a directory that is not empty.** On ABI-v1 it fails without setting an error, so
   `errno` is whatever an earlier failed call left: 0, "not found" or "exists" (AROS-NX#133).
   ABI-v11 reports "directory not empty". `std` lists the directory after a failed `rmdir` and
   reports `DirectoryNotEmpty` if it has an entry, whatever `errno` says.
8. **Empty path.** DOS takes `""` for the current directory, so `metadata("")` and `read_dir("")`
   succeeded. `std` refuses an empty path with `NotFound`, as Unix does.
9. **`Path::join` after a volume name.** `RAM:` joined with a name is `RAM:/name`, which on AROS is
   the parent of the volume. The entries of `read_dir` build their path without a slash after a
   colon. The path functions of `std` themselves are the next slice.
10. **`struct stat`.** On ABI-v1 the plain `stat` has a 32-bit `st_ino`, which moves `st_mode` and
    `st_size`; the 64-bit `stat64` has the same layout on both ABIs, so `std` uses `stat64`,
    `lstat64`, `fstat64` and `readdir64`, with the layout checked at compile time.

Also: a failure that leaves `errno` at 0 (`fstat` of `NIL:` does, AROS-NX#134) is reported as "the C
library failed without an error code" and not as "Success". The C library reports a DOS error that has no C equivalent as 1000 plus the code, so a full
disk, a write-protected file or a seek error reached `std` as `Uncategorized` with no text.
`std` now maps these to kinds (`ReadOnlyFilesystem`, `PermissionDenied`, `StorageFull`,
`DirectoryNotEmpty`, ...) and gives them a text, for example "file is write protected (DOS error
223)".

## Requesters

The default is off, because a library that blocks a script is worse than one that cannot ask for a
disk. A program that wants the DOS behaviour uses `std::os::aros::fs`, which needs
`#![feature(aros_ext)]` next to `restricted_std`:

- `requesters() -> bool` tells whether they are on.
- `set_requesters(bool)` turns them on or off from now on, at any time.
- `with_requesters(f)` turns them on while `f` runs and restores the previous setting afterwards.

The setting belongs to the whole program, not to a task: a call from another task that starts while
`f` runs sees requesters on. With requesters on, the requester that DOS opens has "Retry" and
"Cancel"; "Cancel" makes the call fail with `NotFound` as usual.

The `requesters` mode checks the state (default off, on, off, the scoped form restores what it found,
1,000 changes in a row, no residue that would make a later call wait). That the requester really comes back
cannot be checked by a run that ends by itself: the `requesterson` mode turns requesters on and opens a
missing volume, and is **expected to wait for a person**. It was run by hand with a timeout on both ABIs, and the
screen dump shows the DOS requester "Please insert volume "NOSUCHVOLUME" in any drive" with Retry and
Cancel. A matrix run must treat that mode as an expected timeout.

## Modes and results

All 22 modes pass on both ABIs, with 210 checks on each (the 23rd mode, `requesterson`, waits by design), every boot on the first attempt.

| Mode | Checks | What it covers |
| --- | --- | --- |
| `rw` | 9 | `fs::write`, `fs::read`, `read_to_string`, `read_exact`, `read_to_end`, reading at the end, `lines` |
| `large` | 4 | 1.2 MB through a `BufWriter`, read back whole and in pieces |
| `seek` | 9 | `Start`, `Current` and `End`, `stream_position`, a seek before the start, overwriting in the middle |
| `seekprobe` | 21 | `Start`, `Current` and `End` at 0, 10, 999, 1000, 1001, 1500 and 5000 on a 1000-byte file: the position is what POSIX says and the file is unchanged |
| `seekro` | 3 | a read-only handle seeking past the end does not change the file |
| `seekwrite` | 9 | a write after a seek past the end extends with zeros and no further, a duplicate shares the position, append ignores it |
| `open` | 18 | every `OpenOptions` combination, the invalid ones, access modes, a missing directory and volume (and that they return at once) |
| `trunc` | 4 | `set_len` shrinks and grows, the new part reads as zeros |
| `dup` | 2 | `try_clone` shares the position and survives the original |
| `unlink` | 6 | `remove_file`, missing files, a file that is open |
| `sync` | 3 | `flush`, `sync_all`, `sync_data` |
| `unsupported` | 6 | the calls above return `Unsupported` |
| `paths` | 5 | names with spaces and dots, `NIL:`, a file at the root of a volume, a relative path |
| `errors` | 5 | a write, `create_dir` and `remove_file` on the read-only volume give a kind and a readable message; the volume can be listed and examined |
| `requesters` | 13 | the window pointer of the process is the same after the calls as before; the setting `std::os::aros::fs`: default, on, off, scoped, 1,000 changes, no residue |
| `requesterson` | - | requesters on, then a missing volume: expected to wait for a person, run by hand (see above) |
| `meta` | 24 | length, type, permissions, `Debug`, a directory, a volume root, missing file, volume and directory, a path through a file, the empty path in six calls, `exists`, a file that is open for writing |
| `times` | 5 | the date of a new file is the time of the write, accessed equals modified, whole seconds, a later write gives a later date; also run with the clock at 2040 and 2100 |
| `dirs` | 20 | `create_dir` and `create_dir_all` (existing, missing parent, over a file, trailing slash), `remove_dir` (empty, not empty after three kinds of earlier failure, missing, a file), `remove_file` on a directory |
| `readdir` | 18 | entries with types and sizes, paths, no `.` or `..`, an entry that outlives its `ReadDir`, an empty directory, `RAM:`, 301 entries, deleting while listing, 300 listings dropped early |
| `perm` | 13 | read-only on and off, through the path and through the handle; writing and appending to a read-only file are refused; it can still be deleted |
| `copy` | 8 | 70,000 bytes, over a longer file, an empty file, permissions are copied, a directory and a missing file |
| `removeall` | 5 | `remove_dir_all` of a tree of 180 files, a missing directory, a file |

Observed facts that the checks do not assert (they print `INFO`):

- A name component of up to 107 characters works; 108 or more is `InvalidInput`, on both ABIs
  (on `RAM:`).
- A byte above 127 in a name passes through unchanged.
- A path that goes through a file is `NotFound`, not `NotADirectory` (`meta` asserts this, so a
  change in the C library is noticed), and `create_dir_all` through a file fails with
  `AlreadyExists`.
- `File::create("NIL:").metadata()` fails (see above).
- The date of a file on the delivery volume is the date of the image.
- Opening a directory for writing, or a volume root, is `IsADirectory`. Opening a directory for
  reading succeeds, as on Unix; reading from it was not tested.
- `ENV:name` of a variable that does not exist is `NotFound`.

## ABI differences

| | ABI-v1 | ABI-v11 |
| --- | --- | --- |
| `open` flags `O_CLOEXEC`, `O_DIRECTORY`, `O_NOFOLLOW` | defined | marked "not implemented" in the SDK header; `std` uses none of them |
| Seek past the end in the C library | extends the file, position right | extends the file, position wrong; worked around, same result as ABI-v1 |
| `unlink` of an open file | "not found" (worked around) | "busy" |
| `rmdir` of a directory that is not empty | no error set, stale `errno` (worked around) | "directory not empty" |
| `struct stat` and `struct dirent` | plain `stat` has a 32-bit `st_ino` and a 1025-byte `d_name`; the 64-bit forms are the same as ABI-v11's | one layout; `fdopendir` is missing (not used) |

## Not verified

- Volumes other than `RAM:` (FAT, FFS, PFS3), and files above 2 GiB: no suitable volume could be
  provisioned (AROS-NX#121). The offsets of `std` are 64-bit; on ABI-v11 `Limit` for such offsets
  was not exercised here.
- Behaviour with more than one task, and file locking (`Unsupported`).
- Whether the requesters stay off if a call is interrupted by a break, and what several tasks that change the setting at once see.
- Reading from a directory that was opened as a file.
- Symbolic links (no way to create one yet), a file or directory on a volume other than `RAM:` and the
  delivery volume, and names with characters above 127 in `read_dir`.
- Time zones other than UTC. The C library adds the zone's offset to file dates as it does to the clock.
