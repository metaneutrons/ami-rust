---
title: The aros-locale crate
description: "Message catalogs with built-in default strings, the user's locale and date formatting on locale.library."
---

`aros-locale` gives a program the user's language for an active `aros::Context`: message catalogs that fall back to the program's own strings, and dates written with the locale's day and month names. `Locales::open` owns `locale.library`, `Locale::open` opens the user's locale and `Catalog::open` looks up a catalog. It is `no_std`, allocates nothing on the Rust heap and is the same on ABI-v1 and ABI-v11. The rules shared by every handle are in the [programming model](/api/); every item is listed in the [reference](/reference/aros_locale/). It is available from the repository after release 0.1.0 and is not part of that release.

| Item | Use |
| --- | --- |
| `Locales::open(context)` | Opens `locale.library` (version 39 or newer) and owns the reference. |
| `Locale::open(&locales, name)` | The user's default locale (`None`) or one by name. |
| `Locale::language_name`, `locale_name`, `preferred_language(i)`, `gmt_offset_minutes` | The language driver, the locale's name, the user's preferred languages (most preferred first) and the offset from GMT. |
| `Locale::day_name`, `short_day_name`, `month_name`, `short_month_name`, `yes_text`, `no_text` | The locale's words. Day 0 is Sunday and month 0 is January. |
| `Locale::format_date(template, DateStamp)` → `Formatted` | Formats a date with the `FormatDate` codes into an owned text of up to 256 bytes. |
| `DateStamp::new(days, minute, tick)`, `from_amiga_seconds(seconds)` | The AmigaDOS date form, and the conversion from the calendar seconds of `aros-timer`. |
| `Catalog::open(&locales, locale, name, &options)` | Looks up a message catalog. Succeeds also when there is none. |
| `Catalog::string(id, default)` | The translation of message `id`, or `default`. `is_translated()` tells which. |
| `CatalogOptions` | `built_in_language` (default `english`), `language` (force a language) and `version`. |

```rust
use aros::{Context, Error};
use aros_locale::{Catalog, CatalogOptions, DateStamp, Locale, Locales};

fn greeting(context: &Context) -> Result<(), aros_locale::Error> {
    let locales = Locales::open(context)?;
    let locale = Locale::open(&locales, None)?;
    // The program's own strings are the English defaults; a catalog for the
    // user's language replaces them where it has the message.
    let catalog = Catalog::open(&locales, Some(&locale), b"myapp.catalog", &CatalogOptions::new())?;
    let title = catalog.string(1, c"Open a file");
    context.diagnostic(b"title bytes", title.to_bytes().len() as u64);

    let when = DateStamp::from_amiga_seconds(699_366_896);
    let text = locale.format_date(b"%A, %d %B %Y %H:%M", when)?;
    context.diagnostic(b"date bytes", text.as_bytes().len() as u64);
    Ok(())
}
```

## Catalogs and default strings

A program keeps its messages as built-in defaults in the source, each with a number, and asks `Catalog::string(number, default)` for the text. A `Catalog` is a handle even when nothing was found, so the same call works in every case: the library looks in `PROGDIR:Catalogs/<language>/<name>` (only for a program started with a home directory, as from a shell) and then in `LOCALE:Catalogs/<language>/<name>` for each language the user prefers, in order. If a catalog is found, a message it has is returned and one it lacks gives the default; if none is found, or the language asked for is the program's own (`built_in_language`), no catalog is loaded and every call gives the default. The returned `&CStr` borrows both the catalog and the default.

`CatalogOptions::language` forces a language instead of the user's preferences, which is what a test or a language selector needs. `CatalogOptions::version` accepts only a catalog of exactly that version: the library compares the version number in the catalog's `FVER` chunk, so a different version gives the defaults. The fixture catalog of the qualification test (`tools/make-test-catalog.py`) is version 3: asking for 3 finds it and asking for 2 does not.

## Dates

`format_date` writes the date with the codes of `locale.library` (`%A` weekday name, `%a` short name, `%B` and `%b` month names, `%d` and `%e` day, `%j` day of year, `%y` and `%Y` year, `%H`, `%M` and `%S` time, `%x` the locale's date format and so on), in the locale's language. Text longer than 256 bytes is refused with `Error::TooLong` and never truncated. A `DateStamp` counts days from 1 January 1978, so `DateStamp::from_amiga_seconds(SystemTime::amiga_seconds)` turns the calendar clock of `aros-timer` into one; the locale's `gmt_offset_minutes` is not applied automatically.

Two details of the library that the qualification run observed on both ABIs: `%I` prints 00 (not 12) at midnight and noon, and `%p` writes `am` and `pm` in lower case. Use `%H` for an unambiguous hour.

## Ownership and cleanup

A `Locale` and a `Catalog` borrow their `Locales`, which stays open while either exists. Dropping a locale or catalog closes it. The native bridge records every locale and catalog with the library base, so ones that the program forgets are closed when it finishes, catalogs before locales and before the libraries close. Memory use is bounded: the library shares a catalog between opens and the crate keeps nothing but the handles. The qualification fixture opened and closed a locale and a catalog 200 times and Exec reported the same free memory afterwards on both ABIs, and a forgotten locale and catalog left the free memory unchanged from the first run on.

## Limits

A catalog name, a template or a locale name is at most 127 bytes and a language name at most 63, with no NUL byte; a day number above 6, a month number above 11 or a preferred-language index above 9 is `Error::Invalid`. Numbers, money, `ParseDate`, string comparison and character classes are not wrapped.

## Native evidence

On the pinned ABI-v1 and ABI-v11 images the default locale is the built-in English one (language driver `english.language`, preferred language `english`, GMT offset 0), and both ABIs gave the same results. All seven day names and twelve month names, full and abbreviated, came back as expected. Four fixed instants were formatted with two templates and compared with strings computed on the host, not by the library: 1 January 1978 00:00:00 (a Sunday), 29 February 2000 12:34:56 (a leap day), 1 November 2026 23:59:50 and 19 January 2038 03:14:07, covering the weekday, day-of-year and time codes. A forced `deutsch` catalog from the fixture file translated four messages and left a fifth, absent one at its default; the same catalog opened twice was shared and closed once per open; a missing language, the built-in language and the user's own language gave defaults; and the version test above held. The ledgers return to zero. These are observations of that profile, not guarantees on another system.

## The pinned SDK headers

The pinned ABI-v11 C SDK has no `libraries/locale.h`. The bridge therefore declares the head of `struct Locale` that it reads (the names, the preferred languages and the GMT offset); on ABI-v1 the declaration is checked against the SDK header at build time, and on ABI-v11 it follows the ABI-v11 SDK's `libraries/locale.h`, whose `struct Locale` is identical to the ABI-v1 header. The catalog tags and string numbers the Rust code uses are compared with the bridge's values on each ABI (`aros_sys::locale_layout_values`).
