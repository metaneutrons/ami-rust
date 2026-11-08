# std-path

Native test of paths in `std` on AROS: the syntax `volume:dir/name` in `std::path`, the current
directory, `path::absolute`, `.` and `..`, the temporary directory and path lists. One behaviour per
run, chosen by the first argument. Like the other `std` programs it is not a workspace member: it
needs the patched `std` of `host/std-aros/` and a toolchain with the new target specifications (see
`examples/std-runtime/README.md` for the build). It is listed as in development under #72, STD-M7 because the
native matrix cannot build it yet.

The `cwd` and `dots` modes make files in `RAM:ami-rust-m1/`, which the run must create (`MakeDir`), and
must start there (`CD RAM:ami-rust-m1`).

## The path syntax in `std`

- A path starts with a volume or an assign and a colon (`RAM:`, `SYS:`, `T:`), or is relative to the
  current directory. `/` separates names.
- `std` reports the volume with its colon as the prefix of the path, as `Prefix::DeviceNS("RAM:")`.
  Like the drive of Windows (`C:`) it is followed directly by the path, so
  `Path::new("RAM:").join("x")` is `RAM:x` (before, it was `RAM:/x`, which DOS reads as the parent of
  the volume), `Path::new("RAM:T").parent()` is `RAM:`, and `RAM:` has no parent.
- A path with a volume is absolute. `/x` and `:x` are relative: DOS reads a leading `/` as "the parent
  directory" and a leading `:` as "the root of the current volume". `path::absolute` resolves both.
- A colon later in a path (`dir/a:b`) is part of a name, as in DOS.
- Two slashes in a row collapse to one in `Path`, as on Unix. DOS would read them as "up one directory";
  write `..` for that.
- `.` and `..`: DOS knows neither (it reports "not found" for both, on both ABIs). Rust programs use them all
  the time, so `std` resolves them before a path goes to the C library. `.` and empty names are dropped,
  `..` removes the name before it, a `..` with nothing before it becomes a leading `/` (the DOS parent),
  and at the root of a volume `..` stays at the root. This is lexical, like `path::absolute`, so
  `nothere/../file` finds `file` although `nothere` does not exist. A path without `.`, `..` or an empty
  name goes to the C library unchanged.
- `env::current_dir` returns the name of the **volume**, which is not always the name the program used:
  after `CD RAM:x` it is `RAM Disk:x`. Both name the same directory.
- `env::temp_dir()` is `T:`. `env::home_dir()` is `None`. `env::current_exe()` is `Unsupported`.
- `env::split_paths` and `join_paths` use `;`, because `:` belongs to volume names.

## Modes and results

All 8 modes pass on both ABIs: 154 checks on each.

| Mode | Checks | What it covers |
| --- | --- | --- |
| `components` | 18 | components of paths with and without a volume, a leading slash and colon, a colon in a later name, dots, spaces, the prefix kind, `iter`, collecting back |
| `absolute` | 21 | `is_absolute`, `is_relative` and `has_root` for ten paths |
| `parts` | 28 | `parent`, `file_name`, `extension`, `file_stem`, `with_*`, `ancestors`, `strip_prefix`, `starts_with`, `ends_with`, equality and hash, `display` |
| `join` | 16 | `join` below a volume and a directory, another volume, empty paths, `push`, `pop` (a volume cannot be popped), `set_file_name`, `set_extension`, `extend` |
| `cwd` | 17 | `current_dir`, `set_current_dir` to a volume, back, relative, one level down, a leading slash; a missing directory, a file, an empty path, a missing volume (at once); a failed change leaves the directory |
| `make-absolute` | 16 | `path::absolute` of relative paths, absolute ones, dots, a leading colon and one, two and three leading slashes, an empty path |
| `dots` | 30 | `.` and `..` in every position, at the root of a volume, above it, mixed with a DOS leading slash, and through `open`, `create_dir`, `create_dir_all`, `read_dir`, the remove calls, `copy`, `set_permissions` and `set_current_dir` |
| `lists` | 8 | `split_paths`, `join_paths`, `temp_dir` (a file can be written there), `home_dir`, `current_exe` |

## ABI differences

None found: every check gives the same result on ABI-v1 and ABI-v11.

## Not verified

- Assigns with several directories (`LIBS:`), device names without a file system (`CON:`, `PIPE:`) in
  `Path`, and volumes other than `RAM:` and the delivery volume.
- `..` through a soft link, where the lexical result differs from the file system's.
- Names with characters above 127.
