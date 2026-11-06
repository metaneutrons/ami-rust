# aros-locale

Catalogs and dates for the selected AROS ABI profile, on top of
`locale.library`. `Locales::open` owns the library reference, `Locale::open`
opens the user's locale (or a named one), `Catalog::open` looks up a message
catalog, and `Catalog::string` returns the translated text for a message number
or the program's built-in default when there is no translation.
`Locale::format_date` formats an AmigaDOS `DateStamp` with the locale's day and
month names.

The crate is `no_std`, allocates nothing on the Rust heap and is the same on
ABI-v1 and ABI-v11. The native bridge records every locale and catalog, so a
forgotten one is closed when the program ends.
