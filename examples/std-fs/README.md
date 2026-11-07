# std-fs

Native test of files in `std` on AROS: open, read, write, seek, truncate, duplicate and
remove, the error kinds, and the behaviours of the C library that `std` has to work around.
One behaviour per run, chosen by the first argument. Like the other `std` programs it is not
a workspace member: it needs the patched `std` of `host/std-aros/` and a toolchain with the
new target specifications and the bridge of this tree (see `examples/std-runtime/README.md`
for the build). It is listed as in development under #68 because the native matrix cannot
build it yet.

The files are made in `RAM:ami-rust-m1/`, which the run must create (`MakeDir`). The program
starts on the read-only delivery volume, so the run also needs `CD RAM:ami-rust-m1` for the
relative-path check.

## What is implemented, and what is not

Implemented in this slice: `File::open`, `File::create`, `OpenOptions` (read, write, append,
truncate, create, create_new), `read`, `write`, `seek`, `stream_position`, `set_len`,
`sync_all`, `sync_data`, `try_clone` and `fs::remove_file`, with everything built on them
(`fs::read`, `fs::write`, `read_to_string`, `BufReader`, `BufWriter`).

Everything else in `std::fs` returns `ErrorKind::Unsupported`, which the `unsupported` mode
checks: `metadata` (also `File::metadata`), `File::lock` and `try_lock`, `read_dir`,
`create_dir`, `rename`, `canonicalize`, `set_permissions`, `set_times`. The next slices
implement metadata, directories, `rename` and `std::path`.

## Behaviours of the C library that `std` works around

Each was found by this test, and each has a check that fails without the workaround.

1. **DOS requesters.** A path on a volume that is not there opens "Please insert volume X in
   any drive" and waits for a person, so a program started from a script never returns (seen on
   a screendump). `std` switches requesters off around calls that resolve a path, through the
   bridge function `sdk_proc_window_set`, and restores the setting afterwards. The failure is then
   `NotFound`, at once.
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

Also: the C library reports a DOS error that has no C equivalent as 1000 plus the code, so a full
disk, a write-protected file or a seek error reached `std` as `Uncategorized` with no text.
`std` now maps these to kinds (`ReadOnlyFilesystem`, `PermissionDenied`, `StorageFull`,
`DirectoryNotEmpty`, ...) and gives them a text, for example "file is write protected (DOS error
223)".

## Modes and results

All 15 modes pass on both ABIs: 104 checks on each, every boot on the first attempt.

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
| `unsupported` | 7 | the calls above return `Unsupported` |
| `paths` | 5 | names with spaces and dots, `NIL:`, a file at the root of a volume, a relative path |
| `errors` | 2 | a write to the read-only volume gives a kind and a readable message |
| `requesters` | 2 | the window pointer of the process is the same after the calls as before |

Observed facts that the checks do not assert (they print `INFO`):

- A name component of up to 107 characters works; 108 or more is `InvalidInput`, on both ABIs
  (on `RAM:`).
- A byte above 127 in a name passes through unchanged.
- A path that goes through a file is `NotFound`, not `NotADirectory`.
- Opening a directory for writing, or a volume root, is `IsADirectory`. Opening a directory for
  reading succeeds, as on Unix; reading from it was not tested.
- `ENV:name` of a variable that does not exist is `NotFound`.

## ABI differences

| | ABI-v1 | ABI-v11 |
| --- | --- | --- |
| `open` flags `O_CLOEXEC`, `O_DIRECTORY`, `O_NOFOLLOW` | defined | marked "not implemented" in the SDK header; `std` uses none of them |
| Seek past the end in the C library | extends the file, position right | extends the file, position wrong; worked around, same result as ABI-v1 |
| `unlink` of an open file | "not found" (worked around) | "busy" |

## Not verified

- Volumes other than `RAM:` (FAT, FFS, PFS3), and files above 2 GiB: no suitable volume could be
  provisioned (AROS-NX#121). The offsets of `std` are 64-bit; on ABI-v11 `Limit` for such offsets
  was not exercised here.
- Behaviour with more than one task, and file locking (`Unsupported`).
- Whether the requesters stay off if a call is interrupted by a break.
- Reading from a directory that was opened as a file.
