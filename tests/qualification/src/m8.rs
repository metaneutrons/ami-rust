//! Locale cases: the default locale, date formatting against fixed
//! timestamps, catalog lookup with built-in defaults and a translation from a
//! fixture catalog, bounded memory and cleanup.
//!
//! The fixture catalog `Catalogs/deutsch/ami-rust-m8.catalog` is put on the
//! native medium next to the program, so the library finds it as
//! `PROGDIR:Catalogs/deutsch/ami-rust-m8.catalog`.

use core::mem;

use aros::Context;
use aros_locale::{
    Catalog, CatalogOptions, DateStamp, Error, Locale, Locales, MAX_FORMATTED_BYTES,
};
use aros_sys as sys;

use super::same_resources;

unsafe extern "C" {
    fn sdk_test_avail_mem() -> u64;
}

const CATALOG: &[u8] = b"ami-rust-m8.catalog";

/// Seconds since 1 January 1978 of four instants, and their rendering with the
/// two templates below; computed on the host, not by the library.
const DATES: [(u32, &[u8], &[u8]); 4] = [
    (
        0,
        b"Sunday Sun January Jan 01 001 78 00 00 00 1978",
        b"1978-01-01 00:00:00",
    ),
    (
        699366896,
        b"Tuesday Tue February Feb 29 060 00 12 34 56 2000",
        b"2000-02-29 12:34:56",
    ),
    (
        1541116790,
        b"Sunday Sun November Nov 01 305 26 23 59 50 2026",
        b"2026-11-01 23:59:50",
    ),
    (
        1895022847,
        b"Tuesday Tue January Jan 19 019 38 03 14 07 2038",
        b"2038-01-19 03:14:07",
    ),
];
const WIDE: &[u8] = b"%A %a %B %b %d %j %y %H %M %S %Y";
const ISO: &[u8] = b"%Y-%m-%d %H:%M:%S";

fn layout_matches(context: &Context) -> bool {
    let expected = sys::locale_layout_values();
    let mut actual = [0u64; sys::LOCALE_LAYOUT_VALUE_COUNT];
    // SAFETY: exact writable capacity; C writes only scalar oracle values.
    let count = unsafe { sys::sdk_locale_layout(actual.as_mut_ptr(), actual.len()) };
    if count != actual.len() || actual != expected {
        context.diagnostic(b"qualification-locale-layout-count", count as u64);
        for (index, (a, e)) in actual.iter().zip(expected).enumerate() {
            if *a != e {
                context.diagnostic(b"qualification-locale-layout-index", index as u64);
            }
        }
        return false;
    }
    true
}

fn step(context: &Context, number: u64) -> bool {
    context.diagnostic(b"qualification-locale-step", number);
    false
}

pub fn cases(context: &Context) -> bool {
    let baseline = context.statistics();
    if !layout_matches(context) {
        return step(context, 1);
    }
    let Ok(locales) = Locales::open(context) else {
        return step(context, 2);
    };

    // Argument checks before any native call.
    if Locale::open(&locales, Some(&[b'x'; 128])).err() != Some(Error::Invalid)
        || Locale::open(&locales, Some(b"a\0b")).err() != Some(Error::Invalid)
        || Locale::open(&locales, Some(b"no-such-locale-xyz")).err() != Some(Error::NotFound)
        || Catalog::open(&locales, None, &[b'x'; 128], &CatalogOptions::new()).err()
            != Some(Error::Invalid)
        || Catalog::open(
            &locales,
            None,
            CATALOG,
            &CatalogOptions::new().language(&[b'x'; 64]),
        )
        .err()
            != Some(Error::Invalid)
    {
        return step(context, 3);
    }

    // The default locale: names and fixed dates.
    let Ok(locale) = Locale::open(&locales, None) else {
        return step(context, 4);
    };
    let language = locale.language_name().unwrap_or(b"");
    context.diagnostic(b"language-length", language.len() as u64);
    context.diagnostic(language, 1);
    if language != b"english.language"
        || locale.preferred_language(10).err() != Some(Error::Invalid)
    {
        return step(context, 5);
    }
    let preferred = locale.preferred_language(0).ok().flatten().unwrap_or(b"");
    context.diagnostic(b"preferred-length", preferred.len() as u64);
    context.diagnostic(preferred, 2);
    context.diagnostic(
        b"gmt-offset",
        locale.gmt_offset_minutes().unwrap_or(0x7fff) as i64 as u64,
    );
    let days: [&[u8]; 7] = [
        b"Sunday",
        b"Monday",
        b"Tuesday",
        b"Wednesday",
        b"Thursday",
        b"Friday",
        b"Saturday",
    ];
    let months: [&[u8]; 12] = [
        b"January",
        b"February",
        b"March",
        b"April",
        b"May",
        b"June",
        b"July",
        b"August",
        b"September",
        b"October",
        b"November",
        b"December",
    ];
    for (index, name) in days.iter().enumerate() {
        if locale.day_name(index as u8) != Ok(*name)
            || locale.short_day_name(index as u8) != Ok(&name[..3])
        {
            return step(context, 6);
        }
    }
    for (index, name) in months.iter().enumerate() {
        if locale.month_name(index as u8) != Ok(*name)
            || locale.short_month_name(index as u8) != Ok(&name[..3])
        {
            return step(context, 7);
        }
    }
    if locale.day_name(7) != Err(Error::Invalid) || locale.month_name(12) != Err(Error::Invalid) {
        return step(context, 8);
    }
    for (seconds, wide, iso) in DATES {
        let stamp = DateStamp::from_amiga_seconds(seconds);
        match (
            locale.format_date(WIDE, stamp),
            locale.format_date(ISO, stamp),
        ) {
            (Ok(a), Ok(b)) if a.as_bytes() == wide && b.as_bytes() == iso => {
                // The 12-hour codes are observed, not asserted: this library
                // prints midnight as 00 and writes am and pm in lower case.
                if let Ok(twelve) = locale.format_date(b"%I %p", stamp) {
                    context.diagnostic(twelve.as_bytes(), u64::from(seconds));
                }
            }
            (Ok(a), Ok(_)) => {
                context.diagnostic(b"qualification-locale-date", u64::from(seconds));
                context.diagnostic(a.as_bytes(), a.as_bytes().len() as u64);
                return step(context, 9);
            }
            _ => return step(context, 10),
        }
    }
    // A template that makes more text than fits is refused, not truncated.
    let long = [b'x'; 100];
    let mut template = [0u8; 127];
    template[..100].copy_from_slice(&long);
    template[100..].fill(b'y');
    let repeated = locale.format_date(&template, DateStamp::new(0, 0, 0));
    if repeated.map(|text| text.as_bytes().len()) != Ok(127) {
        return step(context, 11);
    }
    let big = b"%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A%A";
    if locale.format_date(big, DateStamp::new(2, 0, 0)).err() != Some(Error::TooLong) {
        return step(context, 12);
    }
    let _ = MAX_FORMATTED_BYTES;

    // Catalogs. Forcing the language finds the fixture catalog, which has
    // strings 1, 2, 3 and 10: found strings are translated, missing ones keep
    // the built-in default.
    {
        let Ok(catalog) = Catalog::open(
            &locales,
            Some(&locale),
            CATALOG,
            &CatalogOptions::new().language(b"deutsch"),
        ) else {
            return step(context, 13);
        };
        if !catalog.is_translated()
            || catalog.string(1, c"Open file") != c"Datei oeffnen"
            || catalog.string(2, c"Cancel") != c"Abbrechen"
            || catalog.string(3, c"Save as") != c"Datei sichern"
            || catalog.string(10, c"Yes, please") != c"Ja, bitte"
            || catalog.string(99, c"Only in the program") != c"Only in the program"
        {
            return step(context, 14);
        }
        // The same catalog opened again is the same catalog (shared by the
        // library) and is closed once per open.
        let Ok(again) = Catalog::open(
            &locales,
            None,
            CATALOG,
            &CatalogOptions::new().language(b"deutsch"),
        ) else {
            return step(context, 15);
        };
        if again.string(2, c"Cancel") != c"Abbrechen"
            || context.statistics().catalogs != baseline.catalogs + 2
        {
            return step(context, 16);
        }
    }
    if context.statistics().catalogs != baseline.catalogs {
        return step(context, 17);
    }
    // No catalog for the language: defaults.
    let missing = Catalog::open(
        &locales,
        Some(&locale),
        CATALOG,
        &CatalogOptions::new().language(b"francais"),
    );
    let missing_ok = matches!(&missing, Ok(catalog)
        if !catalog.is_translated() && catalog.string(1, c"Open file") == c"Open file");
    drop(missing);
    if !missing_ok {
        return step(context, 18);
    }
    // The built-in language is the language asked for: nothing to load.
    let built_in = Catalog::open(
        &locales,
        Some(&locale),
        CATALOG,
        &CatalogOptions::new()
            .built_in_language(b"deutsch")
            .language(b"deutsch"),
    );
    let built_in_ok = matches!(&built_in, Ok(catalog) if !catalog.is_translated() && catalog.string(1, c"Datei") == c"Datei");
    drop(built_in);
    if !built_in_ok {
        return step(context, 19);
    }
    // The default locale's own language is the program's: defaults.
    match Catalog::open(&locales, Some(&locale), CATALOG, &CatalogOptions::new()) {
        Ok(catalog) if !catalog.is_translated() && catalog.string(2, c"Cancel") == c"Cancel" => {}
        _ => return step(context, 20),
    }
    // Versions: the fixture is version 3.
    match Catalog::open(
        &locales,
        None,
        CATALOG,
        &CatalogOptions::new().language(b"deutsch").version(3),
    ) {
        Ok(catalog) if catalog.is_translated() => {}
        _ => return step(context, 21),
    }
    match Catalog::open(
        &locales,
        None,
        CATALOG,
        &CatalogOptions::new().language(b"deutsch").version(2),
    ) {
        Ok(catalog) if !catalog.is_translated() => {}
        _ => return step(context, 22),
    }
    drop(locale);
    drop(locales);
    if !same_resources(baseline, context.statistics()) {
        return step(context, 23);
    }
    true
}

/// Opens and closes locales and catalogs many times: the Exec free memory and
/// the ledgers end where they started.
pub fn bounded(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(locales) = Locales::open(context) else {
        return step(context, 30);
    };
    // The first round loads the catalog and the library's data; later rounds
    // only reuse them.
    let round = |context: &Context| -> bool {
        let Ok(locale) = Locale::open(&locales, None) else {
            return false;
        };
        let Ok(catalog) = Catalog::open(
            &locales,
            Some(&locale),
            CATALOG,
            &CatalogOptions::new().language(b"deutsch"),
        ) else {
            return false;
        };
        let text = locale.format_date(WIDE, DateStamp::from_amiga_seconds(699_366_896));
        let _ = context;
        catalog.is_translated() && catalog.string(1, c"x") == c"Datei oeffnen" && text.is_ok()
    };
    if !round(context) {
        return step(context, 31);
    }
    // SAFETY: a testing-only native control that reads Exec's free memory.
    let before = unsafe { sdk_test_avail_mem() };
    for _ in 0..200 {
        if !round(context) {
            return step(context, 32);
        }
    }
    // SAFETY: as above.
    let after = unsafe { sdk_test_avail_mem() };
    let lost = before.saturating_sub(after);
    context.diagnostic(b"qualification-locale-lost-bytes", lost);
    if lost > 16 * 1024 {
        return step(context, 33);
    }
    drop(locales);
    if !same_resources(baseline, context.statistics()) {
        return step(context, 34);
    }
    true
}

/// A locale and a catalog are left to the native end-of-run cleanup.
pub fn forgotten(context: &Context) -> bool {
    let baseline = context.statistics();
    let Ok(locales) = Locales::open(context) else {
        return false;
    };
    let Ok(locale) = Locale::open(&locales, None) else {
        return false;
    };
    let Ok(catalog) = Catalog::open(
        &locales,
        Some(&locale),
        CATALOG,
        &CatalogOptions::new().language(b"deutsch"),
    ) else {
        return false;
    };
    let live = context.statistics();
    context.diagnostic(
        b"qualification-locale-forgotten",
        (live.locales * 10 + live.catalogs) as u64,
    );
    let ok = catalog.is_translated()
        && live.locales == baseline.locales + 1
        && live.catalogs == baseline.catalogs + 1;
    mem::forget(catalog);
    mem::forget(locale);
    mem::forget(locales);
    ok
}
