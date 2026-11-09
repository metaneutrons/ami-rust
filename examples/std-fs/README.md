# std-fs

Native test of the file system in `std` on AROS: files (open, read, write, seek, truncate,
duplicate), metadata and file dates, setting the date, permissions, directories (`read_dir`,
`create_dir`, `remove_dir`), `rename`, `canonicalize`, `copy`, the error kinds, and the behaviours of the C library that `std` has to
work around.
One behaviour per run, chosen by the first argument. Like the other `std` programs it is not
a workspace member: it needs a toolchain that ships `std`, built from this tree (see
`examples/std-runtime/README.md` for the build). It is listed as in development under #72, STD-M7 because the native matrix cannot
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

In the third slice: `fs::rename`, `fs::canonicalize`, `fs::set_times`, `File::set_times` and
`File::set_modified`.

Everything else in `std::fs` returns `ErrorKind::Unsupported`, which the `unsupported` mode checks:
`File::lock`, `try_lock` and the shared forms, `read_link`, `hard_link`, symbolic links and
`set_times_nofollow`; setting only the access time (DOS keeps one date); and `env::current_exe`. Paths
(`volume:dir/name`, `.` and `..`, the current directory) are tested by `examples/std-path`.

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
9. **`Path::join` after a volume name** gave `RAM:/name`, the parent of the volume. Fixed in `std::path`
   itself, see `examples/std-path/README.md`; the entries of `read_dir` now use `Path::join`.
10. **`struct stat`.** On ABI-v1 the plain `stat` has a 32-bit `st_ino`, which moves `st_mode` and
    `st_size`; the 64-bit `stat64` has the same layout on both ABIs, so `std` uses `stat64`,
    `lstat64`, `fstat64` and `readdir64`, with the layout checked at compile time.

11. **`rename` deletes the destination first.** For a destination that exists, the C library deletes it
    and then renames. On a volume that ignores case the destination can be the source itself, so on both
    ABIs `rename("a", "a")` and `rename("a", "A")` **deleted the file**; a file also replaced an empty
    directory and a directory replaced a file (AROS-NX#135). `std` never lets the C library see an
    existing destination: the same object is a no-op or, for a change of case, two renames through a
    temporary name; a file and a directory refuse each other (`IsADirectory`, `NotADirectory`); and a
    destination that is replaced is first moved aside, then the source takes its name, then the old
    destination is deleted. If any step fails, the earlier ones are undone. DOS renames a file that is open
    but cannot delete it, so replacing an open destination fails as busy, with nothing changed. ABI-v1 sets
    no error for a failed rename and ABI-v11 a wrong one for some (for example "exists" for a missing
    source), so the cause is found from the file system: the source, the destination's directory, the
    volumes (`CrossesDevices`), a directory into itself (`InvalidInput`). Between the steps another program
    could change the directory; that race is not closed.
12. **`realpath` fails for every path,** on both ABIs, with "not found", even for `RAM:`: it starts with
    `open(".")`, and DOS has no `.` (AROS-NX#136). `canonicalize` asks DOS for the name instead, through the bridge
    function `sdk_path_name` (`Lock` and `NameFromLock`). The result names the volume, not the assign:
    `T:x` is `RAM Disk:T/x`. A file that is open for writing cannot be locked; its name is that of its
    directory and its own name.
13. **Closing a written file sets its date to now,** which undid a `set_modified` made while it was open.
    A handle that can write remembers the date it was given and sets it again after its last duplicate
    is closed; a write after `set_modified` cancels that, because on Unix the write would change the date
    too.

Setting the date: DOS keeps one date per object, so only the modification time can be set, as a whole
second from 1 January 1978 to 7 February 2106 (outside that, `InvalidInput`). `set_times` with only an
access time is `Unsupported`. The C library's `utimes` was exact over that whole range on both ABIs.

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

All 25 modes pass on both ABIs, with 278 checks on each (the 26th mode, `requesterson`, waits by design), every boot on the first attempt.

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
| `unsupported` | 5 | the calls above return `Unsupported` |
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
| `rename` | 31 | a new name, over a file, to itself (also through dots), a change of case and back, file and directory against each other, over an empty and a non-empty directory, into a directory, a directory into itself, a missing source and directory, another volume, an assign, an open destination and an open source, no temporary name left |
| `canon` | 15 | a file, a directory, a volume, an assign and a file below it, relative, dots, other case, missing file and volume, the empty path, the delivery volume, a file open for writing |
| `settimes` | 23 | dates from 1978 to 2106 and past 2038, a fraction of a second, 1977, 1970 and after 2106 refused, both times, none, a directory, a missing file, `File::set_modified` (also after a change of directory, on a written file, with a later write, with a duplicate open, on a clone), now |

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
| A failed `rename` | no error set (worked around) | an error, sometimes the wrong one (worked around) |
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
- Time zones other than UTC. The C library adds the zone's offset to file dates as it does to the clock;
  by its source, `utimes` does not subtract it, so a date set in another zone would read back shifted
  (from reading the source; not reproduced and not reported).
- `rename` to a second writable volume (only the read-only delivery volume was available).
