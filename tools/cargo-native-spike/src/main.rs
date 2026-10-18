//! Internal RC0 linker experiment. This is not the public SDK linker.
//! SPDX-License-Identifier: MIT OR Apache-2.0
use std::{
    env,
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Command, ExitCode},
};

fn selected(name: &str) -> Result<PathBuf, String> {
    let value = env::var_os(name).ok_or_else(|| format!("missing {name}"))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() || !path.exists() {
        return Err(format!("{name} must identify an existing absolute path"));
    }
    Ok(path)
}

fn run(command: &mut Command) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|e| format!("cannot execute {command:?}: {e}"))?;
    if !status.success() {
        return Err(format!("command failed ({status}): {command:?}"));
    }
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end(offset, 2)?)
            .ok_or("truncated ELF")?
            .try_into()
            .map_err(|_| "bad u16")?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end(offset, 4)?)
            .ok_or("truncated ELF")?
            .try_into()
            .map_err(|_| "bad u32")?,
    ))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end(offset, 8)?)
            .ok_or("truncated ELF")?
            .try_into()
            .map_err(|_| "bad u64")?,
    ))
}
fn offset(value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| "ELF offset overflow".into())
}
fn end(start: usize, size: usize) -> Result<usize, String> {
    start.checked_add(size).ok_or("ELF range overflow".into())
}

/// Same explicitly scoped section-name transformation as the frozen recipe.
/// All non-string-table section payloads are compared byte for byte afterward.
fn compact(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.get(..9) != Some(b"\x7fELF\x02\x01\x01\x0f\x01")
        || u16_at(bytes, 16)? != 1
        || u16_at(bytes, 18)? != 62
        || u16_at(bytes, 56)? != 0
        || u16_at(bytes, 58)? != 64
    {
        return Err("expected native ABI-v1 x86-64 ET_REL ELF".into());
    }
    let shoff = offset(u64_at(bytes, 40)?)?;
    let count = usize::from(u16_at(bytes, 60)?);
    let strings = usize::from(u16_at(bytes, 62)?);
    if count == 0 || strings >= count {
        return Err("invalid section table".into());
    }
    let table_end = end(
        shoff,
        count.checked_mul(64).ok_or("section table overflow")?,
    )?;
    if table_end > bytes.len() {
        return Err("truncated section table".into());
    }
    let mut headers = Vec::with_capacity(count);
    for i in 0..count {
        let at = shoff + i * 64;
        headers.push(bytes[at..at + 64].to_vec());
    }
    let oldoff = offset(u64_at(&headers[strings], 24)?)?;
    let oldsize = offset(u64_at(&headers[strings], 32)?)?;
    let oldend = end(oldoff, oldsize)?;
    let names = bytes.get(oldoff..oldend).ok_or("truncated section names")?;
    if shoff < oldend {
        return Err("unsupported section table layout".into());
    }
    let mut newnames = vec![0u8];
    for (i, h) in headers.iter_mut().enumerate() {
        let name_at = usize::try_from(u32_at(h, 0)?).map_err(|_| "name offset overflow")?;
        let tail = names.get(name_at..).ok_or("bad section name offset")?;
        let size = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated section name")?;
        let name = std::str::from_utf8(&tail[..size]).map_err(|_| "non-UTF8 section name")?;
        let families = [
            ".ltext.",
            ".lrodata.",
            ".ldata.",
            ".lbss.",
            ".rela.ltext.",
            ".rela.lrodata.",
            ".rela.ldata.",
            ".rela.lbss.",
        ];
        let shorten = (name.contains("._R") && families.iter().any(|p| name.starts_with(p)))
            || name.starts_with(".lrodata..Lanon.")
            || name.starts_with(".rela.lrodata..Lanon.");
        let label = if shorten {
            format!(".r{i}")
        } else {
            name.to_string()
        };
        let index = if label.is_empty() {
            0
        } else {
            u32::try_from(newnames.len()).map_err(|_| "name table overflow")?
        };
        h[..4].copy_from_slice(&index.to_le_bytes());
        if !label.is_empty() {
            newnames.extend_from_slice(label.as_bytes());
            newnames.push(0);
        }
    }
    if newnames.len() > oldsize {
        return Err("section-name expansion".into());
    }
    let table_size = newnames.len();
    newnames.resize(table_size + (oldsize - table_size) % 8, 0);
    let delta = oldsize - newnames.len();
    let newshoff = shoff - delta;
    let mut result = Vec::with_capacity(bytes.len() - delta);
    result.extend_from_slice(&bytes[..oldoff]);
    result.extend_from_slice(&newnames);
    result.extend_from_slice(&bytes[oldend..]);
    result[40..48].copy_from_slice(&(newshoff as u64).to_le_bytes());
    for (i, h) in headers.iter_mut().enumerate() {
        let old = shoff + i * 64;
        let original_offset = offset(u64_at(bytes, old + 24)?)?;
        let size = offset(u64_at(bytes, old + 32)?)?;
        let kind = u32_at(bytes, old + 4)?;
        let newoff = if i != strings && original_offset >= oldend {
            original_offset - delta
        } else {
            original_offset
        };
        if i == strings {
            h[32..40].copy_from_slice(&(table_size as u64).to_le_bytes());
        }
        h[24..32].copy_from_slice(&(newoff as u64).to_le_bytes());
        let align = offset(u64_at(h, 48)?)?;
        if align > 1 && newoff % align != 0 {
            return Err("section alignment changed".into());
        }
        result[newshoff + i * 64..newshoff + (i + 1) * 64].copy_from_slice(h);
        if i != strings && kind != 8 {
            let original = bytes
                .get(original_offset..end(original_offset, size)?)
                .ok_or("bad original payload")?;
            let after = result
                .get(newoff..end(newoff, size)?)
                .ok_or("bad compacted payload")?;
            if original != after {
                return Err("section payload changed".into());
            }
        }
    }
    Ok(result)
}

fn link(arguments: Vec<OsString>) -> Result<(), String> {
    let collector = selected("AMI_SPIKE_COLLECTOR")?;
    let native = selected("AMI_SPIKE_NATIVE_OBJECTS")?;
    let csdk = selected("AMI_SPIKE_CSDK")?;
    let toolchain = selected("AMI_SPIKE_TOOLCHAIN")?;
    let mut output = None;
    let mut retained = Vec::new();
    let mut iter = arguments.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "-o" {
            if output.is_some() {
                return Err("duplicate output".into());
            }
            output = Some(PathBuf::from(iter.next().ok_or("missing output")?));
        } else if arg == "-flavor" {
            if iter.next().as_deref() != Some(std::ffi::OsStr::new("gnu")) {
                return Err("only rust-lld's explicit GNU flavor is supported".into());
            }
            // rustc passes this to a rust-lld-compatible linker; the selected
            // AROS collector already calls GNU ld.lld, which has no such flag.
        } else {
            retained.push(arg);
        }
    }
    let output = output.ok_or("missing -o output")?;
    let unstripped = output.with_extension("spike-unstripped");
    let stripped = output.with_extension("spike-stripped");
    let mut command = Command::new(collector);
    command
        .arg(format!("--sysroot={}", csdk.display()))
        .args(["-m", "elf_x86_64", "-Map"])
        .arg(output.with_extension("map"))
        .arg("-o")
        .arg(&unstripped);
    for unit in ["entry.o", "startup.o", "sdk.o", "layout.o"] {
        let object = native.join(unit);
        if !object.is_file() {
            return Err(format!("missing native object {unit}"));
        }
        command.arg(object);
    }
    command
        .args(retained)
        .arg("-L")
        .arg(csdk.join("lib"))
        .arg("--start-group");
    for library in [
        "mui",
        "amiga",
        "arossupport",
        "stdcio",
        "stdc",
        "posixc",
        "dos",
        "exec",
        "autoinit",
        "libinit",
        "utility",
        "aros",
        "debug",
    ] {
        command.arg(format!("-l{library}"));
    }
    command
        .arg("--end-group")
        .arg(toolchain.join("lib/clang/11.0.0/lib/aros/libclang_rt.builtins-x86_64.a"));
    fs::write(
        output.with_extension("link-command.txt"),
        format!("{command:?}\n"),
    )
    .map_err(|e| e.to_string())?;
    run(&mut command)?;
    run(Command::new(toolchain.join("bin/llvm-strip"))
        .args(["--strip-unneeded", "--keep-symbol=__startup_entry", "-o"])
        .arg(&stripped)
        .arg(&unstripped))?;
    let bytes = fs::read(&stripped).map_err(|e| e.to_string())?;
    let compacted = compact(&bytes)?;
    // Full symbol/relocation audit is still an RC1/RC2 requirement. The probe
    // only validates identity, bounds and payload-preserving finalisation here.
    fs::write(&output, compacted).map_err(|e| e.to_string())?;
    Ok(())
}

fn main() -> ExitCode {
    match link(env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("RC0 Cargo linker probe: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn native_fixture() -> Vec<u8> {
        let mut names = b"\0.ltext._Rlong_private_rust_symbol_name\0.shstrtab\0".to_vec();
        let second_name = names.iter().skip(1).position(|b| *b == 0).unwrap() + 2;
        names.resize((names.len() + 7) & !7, 0);
        let shoff = 72 + names.len();
        let mut bytes = vec![0u8; shoff + 3 * 64];
        bytes[..9].copy_from_slice(b"\x7fELF\x02\x01\x01\x0f\x01");
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&2u16.to_le_bytes());
        bytes[64..72].copy_from_slice(&[0x90, 0xc3, 1, 2, 3, 4, 5, 6]);
        bytes[72..shoff].copy_from_slice(&names);
        let text = shoff + 64;
        bytes[text..text + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[text + 4..text + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[text + 8..text + 16].copy_from_slice(&6u64.to_le_bytes());
        bytes[text + 24..text + 32].copy_from_slice(&64u64.to_le_bytes());
        bytes[text + 32..text + 40].copy_from_slice(&8u64.to_le_bytes());
        bytes[text + 48..text + 56].copy_from_slice(&8u64.to_le_bytes());
        let strings = shoff + 128;
        bytes[strings..strings + 4].copy_from_slice(&(second_name as u32).to_le_bytes());
        bytes[strings + 4..strings + 8].copy_from_slice(&3u32.to_le_bytes());
        bytes[strings + 24..strings + 32].copy_from_slice(&72u64.to_le_bytes());
        bytes[strings + 32..strings + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        bytes[strings + 48..strings + 56].copy_from_slice(&1u64.to_le_bytes());
        bytes
    }

    #[test]
    fn native_section_names_shrink_without_touching_text() {
        let input = native_fixture();
        let output = compact(&input).unwrap();
        assert_eq!(&output[64..72], &input[64..72]);
        assert_eq!(&output[72..87], b"\0.r1\0.shstrtab\0");
        assert_eq!(u64_at(&output, 40).unwrap(), 88);
        assert_eq!(u64_at(&output, 88 + 128 + 32).unwrap(), 15);
        assert_eq!(output.len(), 88 + 192);
        assert!(output.len() < input.len());
    }

    #[test]
    fn corrupt_realistic_section_ranges_and_abi_are_refused() {
        let mut bad_names = native_fixture();
        let shoff = offset(u64_at(&bad_names, 40).unwrap()).unwrap();
        bad_names[shoff + 128 + 24..shoff + 128 + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(compact(&bad_names).is_err());
        let mut wrong_abi = native_fixture();
        wrong_abi[8] = 0;
        assert!(compact(&wrong_abi).is_err());
    }

    #[test]
    fn malformed_elf_refused() {
        for bytes in [vec![], vec![0u8; 64], b"\x7fELF".to_vec()] {
            assert!(compact(&bytes).is_err());
        }
    }
}
