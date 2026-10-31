//! Directory, variable, current-directory and argument-template cases.

use alloc::{format, string::String, vec::Vec};
use core::mem;

use aros::{
    ArgsError, BytePath, Context, Dir, ErrorKind, File, FileMode, ItemKind, Template, VarScope,
    create_dir, current_dir, delete, delete_var, metadata, rename, set_current_dir, set_var, var,
};

use super::{byte_path, expect_error, report_error, same_resources};

const ERROR_OBJECT_NOT_FOUND: i64 = 205;
const ERROR_OBJECT_WRONG_TYPE: i64 = 212;
const ERROR_DIRECTORY_NOT_EMPTY: i64 = 216;

fn expect_native(context: &Context, result: Result<impl Sized, aros::Error>, native: i64) -> bool {
    match result {
        Err(error) => {
            report_error(context, error);
            error.kind == ErrorKind::Native && error.native == native
        }
        Ok(_) => false,
    }
}

fn write_file(context: &Context, path: &BytePath, bytes: &[u8]) -> bool {
    let Ok(mut file) = File::open(context, path, FileMode::CreateTruncate) else {
        return false;
    };
    file.write_all(bytes).is_ok() && file.close().is_ok()
}

fn exists(context: &Context, path: &BytePath) -> bool {
    metadata(context, path).is_ok()
}

fn cleanup_tree(context: &Context) {
    for name in [
        &b"RAM:m2dir/sub/c.txt"[..],
        b"RAM:m2dir/sub",
        b"RAM:m2dir/a.txt",
        b"RAM:m2dir/b.bin",
        b"RAM:m2dir/c.txt",
        b"RAM:m2dir",
    ] {
        if let Some(path) = byte_path(name) {
            let _ = delete(context, &path);
        }
    }
    for index in 0..30 {
        let text = format!("RAM:m2many/f{index}");
        if let Some(path) = byte_path(text.as_bytes()) {
            let _ = delete(context, &path);
        }
    }
    if let Some(path) = byte_path(b"RAM:m2many") {
        let _ = delete(context, &path);
    }
}

/// Directory iteration, entry information, create, delete and rename.
pub fn fs_cases(context: &Context) -> bool {
    cleanup_tree(context);
    let baseline = context.statistics();
    let ok = fs_body(context);
    cleanup_tree(context);
    ok && same_resources(baseline, context.statistics())
}

fn fs_body(context: &Context) -> bool {
    let (Some(dir), Some(sub), Some(a), Some(b), Some(c), Some(sub_c), Some(missing)) = (
        byte_path(b"RAM:m2dir"),
        byte_path(b"RAM:m2dir/sub"),
        byte_path(b"RAM:m2dir/a.txt"),
        byte_path(b"RAM:m2dir/b.bin"),
        byte_path(b"RAM:m2dir/c.txt"),
        byte_path(b"RAM:m2dir/sub/c.txt"),
        byte_path(b"RAM:m2dir/nothing"),
    ) else {
        return false;
    };
    if create_dir(context, &dir).is_err()
        || create_dir(context, &sub).is_err()
        || !write_file(context, &a, b"hello")
        || !write_file(context, &b, b"")
    {
        return false;
    }
    // Creating over an existing entry is refused natively.
    if !expect_error(context, create_dir(context, &dir), ErrorKind::Native) {
        return false;
    }

    // Iteration yields every entry once, with kind and size.
    let mut seen: Vec<(Vec<u8>, bool, u64)> = Vec::new();
    let Ok(listing) = Dir::open(context, &dir) else {
        return false;
    };
    for entry in listing {
        match entry {
            Ok(entry) => seen.push((entry.name().to_vec(), entry.is_dir(), entry.size())),
            Err(error) => {
                report_error(context, error);
                return false;
            }
        }
    }
    seen.sort();
    let expected: [(&[u8], bool, u64); 3] = [
        (b"a.txt", false, 5),
        (b"b.bin", false, 0),
        (b"sub", true, 0),
    ];
    if seen.len() != expected.len()
        || seen
            .iter()
            .zip(expected)
            .any(|((n, d, s), (en, ed, es))| n != en || *d != ed || *s != es)
    {
        context.diagnostic(b"qualification-fs-listing", seen.len() as u64);
        return false;
    }

    // Entry information of a file, a directory and a volume root.
    let Ok(info) = metadata(context, &a) else {
        return false;
    };
    if !info.is_file() || info.is_dir() || info.name() != b"a.txt" || info.size() != 5 {
        return false;
    }
    if info.protection() & 0xf != 0 || info.modified().days <= 0 {
        context.diagnostic(b"qualification-fs-protection", u64::from(info.protection()));
        return false;
    }
    match metadata(context, &sub) {
        Ok(entry) if entry.is_dir() && !entry.is_file() && entry.name() == b"sub" => {}
        _ => return false,
    }
    match byte_path(b"RAM:").map(|root| metadata(context, &root)) {
        Some(Ok(root)) if root.is_dir() => {}
        _ => return false,
    }
    if !expect_native(context, metadata(context, &missing), ERROR_OBJECT_NOT_FOUND)
        || !expect_native(
            context,
            Dir::open(context, &missing),
            ERROR_OBJECT_NOT_FOUND,
        )
        || !expect_native(context, Dir::open(context, &a), ERROR_OBJECT_WRONG_TYPE)
    {
        return false;
    }

    // Rename within a directory and move into another.
    if rename(context, &a, &c).is_err()
        || exists(context, &a)
        || metadata(context, &c).map(|entry| entry.size()) != Ok(5)
        || rename(context, &c, &sub_c).is_err()
        || exists(context, &c)
        || !exists(context, &sub_c)
        || !expect_native(context, rename(context, &a, &c), ERROR_OBJECT_NOT_FOUND)
    {
        return false;
    }

    // Delete: a non-empty directory is refused, then files, then directories.
    if !expect_native(context, delete(context, &sub), ERROR_DIRECTORY_NOT_EMPTY)
        || delete(context, &sub_c).is_err()
        || delete(context, &sub).is_err()
        || delete(context, &b).is_err()
        || delete(context, &dir).is_err()
        || !expect_native(context, delete(context, &dir), ERROR_OBJECT_NOT_FOUND)
    {
        return false;
    }

    // Many entries, and a directory dropped part way releases its lock.
    let Some(many) = byte_path(b"RAM:m2many") else {
        return false;
    };
    if create_dir(context, &many).is_err() {
        return false;
    }
    for index in 0..30 {
        let text = format!("RAM:m2many/f{index}");
        let Some(path) = byte_path(text.as_bytes()) else {
            return false;
        };
        if !write_file(context, &path, &[index as u8]) {
            return false;
        }
    }
    let Ok(listing) = Dir::open(context, &many) else {
        return false;
    };
    let count = listing.filter(|entry| entry.is_ok()).count();
    let before = context.statistics();
    let Ok(mut partial) = Dir::open(context, &many) else {
        return false;
    };
    if context.statistics().directories != before.directories + 1
        || partial.next_entry().ok().flatten().is_none()
    {
        return false;
    }
    drop(partial);
    if context.statistics().directories != before.directories {
        return false;
    }
    count == 30
}

/// Leaves a directory handle and a changed current directory to the native
/// end-of-run cleanup; the exit ledgers and the next program's current
/// directory (`cwd-check`) prove that every lock came back.
pub fn fs_forgotten_cases(context: &Context) -> bool {
    let Some(root) = byte_path(b"RAM:") else {
        return false;
    };
    let Some(dir) = byte_path(b"RAM:m2dir") else {
        return false;
    };
    let _ = create_dir(context, &dir);
    let baseline = context.statistics();
    let Ok(listing) = Dir::open(context, &root) else {
        return false;
    };
    let ok = set_current_dir(context, &dir).is_ok()
        && context.statistics().directories == baseline.directories + 1;
    mem::forget(listing);
    ok
}

/// Passes when the current directory is a volume root, which it is again when
/// the previous program restored what it changed.
pub fn cwd_check(context: &Context) -> bool {
    let mut buffer = [0u8; 256];
    match current_dir(context, &mut buffer) {
        Ok(length) => {
            context.diagnostic(b"qualification-cwd-length", length as u64);
            length > 0 && buffer[length - 1] == b':'
        }
        Err(error) => {
            report_error(context, error);
            false
        }
    }
}

fn name(context: &Context, bytes: &[u8]) -> Option<BytePath> {
    let path = byte_path(bytes);
    if path.is_none() {
        context.diagnostic(b"qualification-bad-name", 0);
    }
    path
}

/// Local and global variables and the current directory.
pub fn env_cases(context: &Context) -> bool {
    let baseline = context.statistics();
    let (Some(local), Some(global), Some(empty)) = (
        name(context, b"ami-m2-local"),
        name(context, b"ami-m2-global"),
        name(context, b"ami-m2-empty"),
    ) else {
        return false;
    };
    let mut buffer = [0u8; 64];

    // Local variable: set, read in both scopes it is visible in, not global.
    if set_var(context, &local, b"value1", VarScope::Local).is_err()
        || var(context, &local, &mut buffer, VarScope::Local) != Ok(6)
        || &buffer[..6] != b"value1"
        || var(context, &local, &mut buffer, VarScope::Any) != Ok(6)
        || !expect_native(
            context,
            var(context, &local, &mut buffer, VarScope::Global),
            ERROR_OBJECT_NOT_FOUND,
        )
    {
        return false;
    }
    // A value that does not fit is an error, not a silent truncation; a value
    // with a newline is kept whole.
    let mut small = [0u8; 3];
    if !expect_native(
        context,
        var(context, &local, &mut small, VarScope::Local),
        303,
    ) || var(context, &local, &mut [0u8; 7], VarScope::Local) != Ok(6)
        || set_var(context, &local, b"line1\nline2", VarScope::Local).is_err()
        || var(context, &local, &mut buffer, VarScope::Local) != Ok(11)
        || &buffer[..11] != b"line1\nline2"
    {
        return false;
    }
    if delete_var(context, &local, VarScope::Local).is_err()
        || !expect_native(
            context,
            var(context, &local, &mut buffer, VarScope::Local),
            ERROR_OBJECT_NOT_FOUND,
        )
    {
        return false;
    }

    // Global variable (ENV:), the empty value, and refusals.
    if set_var(context, &global, b"g", VarScope::Global).is_err()
        || var(context, &global, &mut buffer, VarScope::Global) != Ok(1)
        || var(context, &global, &mut buffer, VarScope::Any) != Ok(1)
        || delete_var(context, &global, VarScope::Global).is_err()
    {
        return false;
    }
    if set_var(context, &empty, b"", VarScope::Local).is_err()
        || var(context, &empty, &mut buffer, VarScope::Local) != Ok(0)
        || delete_var(context, &empty, VarScope::Local).is_err()
    {
        return false;
    }
    if !expect_error(
        context,
        set_var(context, &local, b"a\0b", VarScope::Local),
        ErrorKind::Input,
    ) || !expect_error(
        context,
        set_var(context, &local, &[b'x'; 4097], VarScope::Local),
        ErrorKind::Input,
    ) || !expect_error(
        context,
        var(context, &local, &mut [0u8; 1], VarScope::Any),
        ErrorKind::Input,
    ) {
        return false;
    }

    // Current directory: change, relative access, change again, refuse a file.
    let (Some(dir), Some(sub), Some(file)) = (
        name(context, b"RAM:m2dir"),
        name(context, b"RAM:m2dir/sub"),
        name(context, b"RAM:m2dir/file.txt"),
    ) else {
        return false;
    };
    cleanup_tree(context);
    if create_dir(context, &dir).is_err()
        || create_dir(context, &sub).is_err()
        || !write_file(context, &file, b"x")
    {
        return false;
    }
    let mut original = [0u8; 256];
    let Ok(original_length) = current_dir(context, &mut original) else {
        return false;
    };
    let mut here = [0u8; 256];
    let ok = set_current_dir(context, &dir).is_ok()
        && current_dir(context, &mut here).is_ok_and(|n| here[..n].ends_with(b":m2dir"))
        && byte_path(b"file.txt").is_some_and(|relative| metadata(context, &relative).is_ok())
        && set_current_dir(context, &sub).is_ok()
        && current_dir(context, &mut here).is_ok_and(|n| here[..n].ends_with(b":m2dir/sub"))
        && expect_native(
            context,
            set_current_dir(context, &file),
            ERROR_OBJECT_WRONG_TYPE,
        )
        && current_dir(context, &mut here).is_ok_and(|n| here[..n].ends_with(b":m2dir/sub"))
        && !expect_error(
            context,
            current_dir(context, &mut [0u8; 1]),
            ErrorKind::Native,
        );
    cleanup_tree(context);
    // The directory that was current is gone; leave it for the end-of-run
    // restore and report what the shell had.
    context.diagnostic(b"qualification-cwd-original", original_length as u64);
    ok && context.statistics().files == baseline.files
}

fn kind_code(kind: ItemKind) -> u8 {
    match kind {
        ItemKind::Text => 0,
        ItemKind::Switch => 1,
        ItemKind::Number => 2,
        ItemKind::Multiple => 3,
        ItemKind::MultipleNumber => 4,
        ItemKind::Rest => 5,
    }
}

/// Serialises a parse result in the format of the native oracle.
fn describe(template: &Template<'_>, values: &aros::Values<'_>) -> String {
    let mut text = String::new();
    for item in 0..template.len() {
        if item > 0 {
            text.push('|');
        }
        match template.kind(item) {
            Some(ItemKind::Switch) => text.push(if values.switch(item) { 's' } else { '-' }),
            Some(ItemKind::Number) => match values.number(item) {
                Some(number) => text.push_str(&format!("n={number}")),
                None => text.push('-'),
            },
            Some(ItemKind::Text) => match values.text(item) {
                Some(value) => text.push_str(&format!("t={}", String::from_utf8_lossy(value))),
                None => text.push('-'),
            },
            Some(ItemKind::Rest) => {
                let mut line = [0u8; 256];
                match values.write_line(item, &mut line) {
                    Some(length) => {
                        text.push_str(&format!("t={}", String::from_utf8_lossy(&line[..length])))
                    }
                    None => text.push('-'),
                }
            }
            Some(ItemKind::Multiple) => {
                if values.is_present(item) {
                    let parts: Vec<String> = values
                        .tokens(item)
                        .map(|token| String::from_utf8_lossy(token).into_owned())
                        .collect();
                    text.push_str(&format!("m={}", parts.join(",")));
                } else {
                    text.push('-');
                }
            }
            Some(ItemKind::MultipleNumber) => {
                if values.is_present(item) {
                    let parts: Vec<String> = values
                        .numbers(item)
                        .map(|number| format!("{number}"))
                        .collect();
                    text.push_str(&format!("mn={}", parts.join(",")));
                } else {
                    text.push('-');
                }
            }
            None => {}
        }
    }
    text
}

unsafe extern "C" {
    fn sdk_test_readargs(
        template: *const u8,
        line: *const u8,
        line_length: usize,
        kinds: *const u8,
        count: usize,
        out: *mut u8,
        capacity: usize,
    ) -> i64;
}

const CASES: &[(&str, &[&str])] = &[
    ("FROM/A,TO/K,ALL/S", &["a"]),
    ("FROM/A,TO/K,ALL/S", &["a", "TO", "b"]),
    ("FROM/A,TO/K,ALL/S", &["a", "all"]),
    ("FROM/A,TO/K,ALL/S", &["a", "to=b", "ALL"]),
    ("FROM/A,TO/K,ALL/S", &[]),
    ("FROM/A,TO/K,ALL/S", &["a", "b"]),
    ("FROM/M,TO/K", &["a", "b", "c"]),
    ("FROM/M,TO/K", &["a", "b", "TO", "c"]),
    ("FROM/M,TO/K", &["TO", "c"]),
    ("FROM/M,TO/K", &["a", "TO", "c", "d"]),
    ("NAME/A,TEXT/F", &["n", "hello", "world"]),
    ("NAME/A,TEXT/F", &["n", "hello", "ALL", "world"]),
    ("COUNT/N,NAME", &["5"]),
    ("COUNT/N,NAME", &["-5", "x"]),
    ("COUNT/N,NAME", &["+7"]),
    ("COUNT/N,NAME", &["x"]),
    ("COUNT/N,NAME", &["1x"]),
    ("COUNT/N,NAME", &["2147483648"]),
    ("COUNT/N,NAME", &["-2147483648"]),
    ("A/A/N,B/N/M", &["1", "2", "3"]),
    ("A/A/N,B/N/M", &["1"]),
    ("A/A/N,B/N/M", &["1", "x"]),
    ("QUIET=Q/S,FILE/A", &["q", "f"]),
    ("QUIET=Q/S,FILE/A", &["QUIET", "f"]),
    ("A/K,B/K", &["A", "1", "B", "2"]),
    ("A/K,B/K", &["A", "1", "A", "2"]),
    ("A/K,B/K", &["A"]),
    ("A/K,B/K", &["1"]),
    ("SRC/A/M,DEST/A", &["a", "b", "c"]),
    ("SRC/A/M,DEST/A", &["a", "DEST", "b"]),
    ("A,B,C", &["1", "2", "3"]),
    ("A,B,C", &["1", "2"]),
    ("A,B,C", &["1", "2", "3", "4"]),
    ("T/T", &["T"]),
    ("T/T", &["T", "T"]),
    ("A,B", &["x y", "z"]),
    ("A,B", &["a=b"]),
    ("A,B", &["x", "y=z"]),
    ("FROM/K/A", &["FROM", "x"]),
    ("FROM/K/A", &["x"]),
    ("ALL/S,N/N", &["ALL", "5"]),
    ("ALL/S,N/N", &["5", "ALL"]),
    ("From/A", &["x"]),
    ("ALL/S", &["ALL=1"]),
    (
        "A/A,B/K,C/S,D/N,E/M",
        &["x", "B", "y", "C", "D", "3", "p", "q"],
    ),
    ("A/A,B/K,C/S,D/N,E/M", &["x", "p", "q", "D", "3"]),
    ("A,B,C", &["x=y=z"]),
    ("A,B,C", &["=x"]),
    ("A,B,C", &["x="]),
    ("ALL/S", &["ALL", "ALL"]),
    ("A/K", &["A=1"]),
    ("A/M", &["a=b", "c"]),
    ("A/F", &["x=y", "z"]),
    ("SRC/M,DEST/A", &["a", "b"]),
    ("SRC/M,DEST/A", &["a"]),
    ("SRC/A/M,DEST/A", &["a"]),
    ("A/M,B/A,C/A", &["1", "2", "3", "4"]),
    ("A/M,B/A,C/A", &["1", "2"]),
    ("N/N,M/N", &["1", "2"]),
    ("A/A/M,B/K", &["a", "B", "b", "c"]),
    ("NAME/K,ALL/S", &["NAME", "ALL"]),
    ("TEXT/F,ALL/S", &["ALL", "a", "b"]),
];

/// Cases where the parser deliberately differs from `ReadArgs`: it rejects
/// a `/N` value outside `i32`, where `ReadArgs` wraps it around.
const DIVERGENT: &[(&str, &[&str])] = &[("COUNT/N,NAME", &["2147483648"])];

fn line_for(tokens: &[&str]) -> String {
    let mut line = String::new();
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        if token.contains(' ') || token.contains('"') || token.is_empty() {
            line.push('"');
            line.push_str(token);
            line.push('"');
        } else {
            line.push_str(token);
        }
    }
    line.push('\n');
    line
}

/// Compares the template parser with the real `ReadArgs` on a table of cases.
pub fn args_cases(context: &Context) -> bool {
    let mut mismatches = 0u64;
    for (index, (spec, tokens)) in CASES.iter().enumerate() {
        let Ok(template) = Template::parse(spec.as_bytes()) else {
            context.diagnostic(b"qualification-args-template", index as u64);
            return false;
        };
        let ours: Result<String, ArgsError> = template
            .read(tokens.iter().map(|token| token.as_bytes()))
            .map(|values| describe(&template, &values));
        let mut kinds = [0u8; 32];
        for item in 0..template.len() {
            kinds[item] = template.kind(item).map_or(0, kind_code);
        }
        let mut spec_c = String::from(*spec);
        spec_c.push('\0');
        let line = line_for(tokens);
        let mut out = [0u8; 512];
        let native = unsafe {
            sdk_test_readargs(
                spec_c.as_ptr(),
                line.as_ptr(),
                line.len(),
                kinds.as_ptr(),
                template.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        let theirs =
            (native >= 0).then(|| String::from_utf8_lossy(&out[..native as usize]).into_owned());
        let mut agree = match (&ours, &theirs) {
            (Ok(a), Some(b)) => a == b,
            (Err(_), None) => true,
            _ => false,
        };
        if DIVERGENT
            .iter()
            .any(|(d_spec, d_tokens)| d_spec == spec && d_tokens == tokens)
        {
            // A documented divergence must stay a divergence.
            agree = !agree;
        }
        if !agree {
            mismatches += 1;
            context.diagnostic(b"qualification-args-mismatch", index as u64);
            context.diagnostic(spec.as_bytes(), 0);
            context.diagnostic(line_for(tokens).trim_end().as_bytes(), 0);
            if let Ok(text) = &ours {
                context.diagnostic(text.as_bytes(), 1);
            } else {
                context.diagnostic(b"ours-error", 1);
            }
            match &theirs {
                Some(text) => context.diagnostic(text.as_bytes(), 2),
                None => context.diagnostic(b"readargs-error", 2),
            }
        }
    }
    context.diagnostic(b"qualification-args-cases", CASES.len() as u64);
    mismatches == 0
}
