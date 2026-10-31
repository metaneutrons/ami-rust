//! Argument templates in the AmigaDOS `ReadArgs` language.
//!
//! A [`Template`] such as `FROM/A/M,TO/K,ALL/S,COUNT/N` describes keywords and
//! how they take values; [`Template::read`] matches the program's arguments
//! against it. The matching follows `ReadArgs` for argument vectors that the
//! start-up code has already split: quoting and `*` escapes are the C
//! start-up's business, and the prompting `?` form is not supported. Nothing is
//! allocated; results borrow the argument bytes.
//!
//! Item modifiers (case-insensitive):
//!
//! | Modifier | Meaning |
//! | --- | --- |
//! | `/A` | required |
//! | `/K` | the keyword must be given |
//! | `/S` | switch; present or not |
//! | `/T` | toggle, a switch that flips |
//! | `/N` | number (decimal, optional sign, within `i32`) |
//! | `/M` | any number of values |
//! | `/F` | the rest of the line: every remaining argument |
//!
//! An item can have an alias, `FROM=SOURCE`, and a keyword can be written
//! `KEYWORD value` or `KEYWORD=value`. As in `ReadArgs`, every `=` separates
//! arguments, so `a=b` is read as `a` and `b`; quoting is no longer visible
//! once the arguments are split, so a literal `=` needs the raw
//! [`Context::args`](crate::Context::args).

/// Largest number of items in a template.
pub const MAX_TEMPLATE_ITEMS: usize = 32;

/// Largest number of argument tokens [`Template::read`] accepts.
///
/// This is the bridge's limit on program arguments; a token with `=` counts as
/// one argument for each part once it is split.
pub const MAX_ARGUMENT_TOKENS: usize = 32;

const MAX_EXPANDED_TOKENS: usize = 64;

const REQUIRED: u8 = 1;
const KEYWORD: u8 = 2;
const SWITCH: u8 = 4;
const NUMBER: u8 = 8;
const MULTIPLE: u8 = 16;
const FINAL: u8 = 32;
const TOGGLE: u8 = 64;

/// What is wrong with a template or with the arguments matched against it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgsErrorKind {
    /// The template has more than [`MAX_TEMPLATE_ITEMS`] items.
    TooManyItems,
    /// A template item has no name.
    EmptyName,
    /// A template item has an unknown modifier.
    BadModifier,
    /// A template item combines modifiers that cannot be combined.
    ConflictingModifiers,
    /// A keyword that needs a value was last, or had no value after it.
    MissingValue,
    /// A required item (`/A`) was not given.
    MissingRequired,
    /// An argument matched no item.
    UnexpectedArgument,
    /// A keyword was given twice for an item that takes one value.
    DuplicateKeyword,
    /// An argument is empty around an `=`, as in `=x` or `x=`.
    EmptyToken,
    /// A `/N` value is not a number or is out of range.
    BadNumber,
    /// More than [`MAX_ARGUMENT_TOKENS`] arguments were given.
    TooManyArguments,
}

/// A template or argument error with the item or argument it concerns.
///
/// `index` is a template item for every kind except
/// [`UnexpectedArgument`](ArgsErrorKind::UnexpectedArgument) and
/// [`TooManyArguments`](ArgsErrorKind::TooManyArguments), where it is the
/// position of the argument after splitting at `=`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgsError {
    /// What went wrong.
    pub kind: ArgsErrorKind,
    /// The template item or argument position concerned.
    pub index: usize,
}

impl ArgsError {
    const fn new(kind: ArgsErrorKind, index: usize) -> Self {
        Self { kind, index }
    }
}

#[derive(Clone, Copy)]
struct Item<'t> {
    name: &'t [u8],
    alias: &'t [u8],
    flags: u8,
}

const EMPTY_ITEM: Item<'static> = Item {
    name: b"",
    alias: b"",
    flags: 0,
};

/// How an item takes its value; see [`Template::kind`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemKind {
    /// One text value.
    Text,
    /// A switch or toggle (`/S`, `/T`).
    Switch,
    /// One number (`/N`).
    Number,
    /// Any number of text values (`/M`).
    Multiple,
    /// Any number of numbers (`/N/M`).
    MultipleNumber,
    /// The rest of the line (`/F`).
    Rest,
}

/// A parsed argument template.
///
/// # Examples
///
/// ```ignore
/// # use aros::Template;
/// let Ok(template) = Template::parse(b"FROM/A/M,TO/K,ALL/S,COUNT/N") else {
///     return Ok(());
/// };
/// // Everything after the program name is matched against the template.
/// let Ok(values) = template.read(context.args().skip(1)) else {
///     return Ok(());
/// };
/// if values.switch(2) {
///     // ALL was given
/// }
/// for source in values.tokens(0) {
///     // every FROM value, as bytes
///     let _ = source;
/// }
/// ```
#[derive(Clone, Copy)]
pub struct Template<'t> {
    items: [Item<'t>; MAX_TEMPLATE_ITEMS],
    count: usize,
}

fn eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

impl<'t> Template<'t> {
    /// Parses a template such as `FROM/A/M,TO/K,ALL/S`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArgsError`] for too many items, an item without a name, an
    /// unknown modifier or an impossible combination of modifiers.
    pub fn parse(spec: &'t [u8]) -> Result<Self, ArgsError> {
        let mut items = [EMPTY_ITEM; MAX_TEMPLATE_ITEMS];
        let mut count = 0;
        for part in spec.split(|byte| *byte == b',') {
            if count == MAX_TEMPLATE_ITEMS {
                return Err(ArgsError::new(ArgsErrorKind::TooManyItems, count));
            }
            let mut pieces = part.split(|byte| *byte == b'/');
            let names = pieces.next().unwrap_or(b"");
            let (name, alias) = match names.iter().position(|byte| *byte == b'=') {
                Some(at) => (&names[..at], &names[at + 1..]),
                None => (names, &b""[..]),
            };
            if name.is_empty() {
                return Err(ArgsError::new(ArgsErrorKind::EmptyName, count));
            }
            let mut flags = 0;
            for modifier in pieces {
                flags |= match modifier {
                    [m] => match m.to_ascii_uppercase() {
                        b'A' => REQUIRED,
                        b'K' => KEYWORD,
                        b'S' => SWITCH,
                        b'N' => NUMBER,
                        b'M' => MULTIPLE,
                        b'F' => FINAL,
                        b'T' => TOGGLE | SWITCH,
                        _ => return Err(ArgsError::new(ArgsErrorKind::BadModifier, count)),
                    },
                    _ => return Err(ArgsError::new(ArgsErrorKind::BadModifier, count)),
                };
            }
            let value_kinds = flags & (NUMBER | MULTIPLE | FINAL);
            if (flags & SWITCH != 0 && value_kinds != 0)
                || (flags & MULTIPLE != 0 && flags & FINAL != 0)
                || (flags & NUMBER != 0 && flags & FINAL != 0)
            {
                return Err(ArgsError::new(ArgsErrorKind::ConflictingModifiers, count));
            }
            items[count] = Item { name, alias, flags };
            count += 1;
        }
        Ok(Self { items, count })
    }

    /// Returns the number of items.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` for a template without items, which cannot be parsed.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns how item `item` takes its value, or `None` for a position
    /// outside the template.
    pub fn kind(&self, item: usize) -> Option<ItemKind> {
        let flags = (item < self.count).then(|| self.items[item].flags)?;
        Some(if flags & SWITCH != 0 {
            ItemKind::Switch
        } else if flags & FINAL != 0 {
            ItemKind::Rest
        } else if flags & (NUMBER | MULTIPLE) == NUMBER | MULTIPLE {
            ItemKind::MultipleNumber
        } else if flags & MULTIPLE != 0 {
            ItemKind::Multiple
        } else if flags & NUMBER != 0 {
            ItemKind::Number
        } else {
            ItemKind::Text
        })
    }

    /// Returns the position of the item named or aliased `name`, ignoring
    /// ASCII case.
    pub fn index_of(&self, name: &[u8]) -> Option<usize> {
        (0..self.count).find(|&i| {
            let item = &self.items[i];
            eq_ignore_case(item.name, name)
                || (!item.alias.is_empty() && eq_ignore_case(item.alias, name))
        })
    }

    /// Matches `args` (the program's arguments without its name) against the
    /// template.
    ///
    /// # Errors
    ///
    /// Returns an [`ArgsError`] for a missing value, a missing required item,
    /// an argument that fits no item, a repeated keyword, a bad number, an
    /// empty part around `=` or too many arguments.
    pub fn read<'a, I>(&self, args: I) -> Result<Values<'a>, ArgsError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut tokens: [&'a [u8]; MAX_EXPANDED_TOKENS] = [b""; MAX_EXPANDED_TOKENS];
        let mut total = 0;
        let mut given = 0;
        let mut glued = 0u64;
        for token in args {
            given += 1;
            if given > MAX_ARGUMENT_TOKENS {
                return Err(ArgsError::new(ArgsErrorKind::TooManyArguments, total));
            }
            for (position, part) in token.split(|byte| *byte == b'=').enumerate() {
                if position > 0 {
                    glued |= 1 << total;
                }
                if total == MAX_EXPANDED_TOKENS {
                    return Err(ArgsError::new(ArgsErrorKind::TooManyArguments, total));
                }
                if part.is_empty() && token.len() > 1 {
                    return Err(ArgsError::new(ArgsErrorKind::EmptyToken, total));
                }
                tokens[total] = part;
                total += 1;
            }
        }

        let mut slots = [Slot::EMPTY; MAX_TEMPLATE_ITEMS];
        let mut at = 0;
        while at < total {
            let token = tokens[at];
            if let Some(item) = self.index_of(token) {
                let flags = self.items[item].flags;
                if flags & SWITCH != 0 {
                    if slots[item].present {
                        return Err(ArgsError::new(ArgsErrorKind::DuplicateKeyword, item));
                    }
                    slots[item].flag = true;
                    slots[item].present = true;
                    at += 1;
                    continue;
                }
                if slots[item].present && flags & MULTIPLE == 0 {
                    return Err(ArgsError::new(ArgsErrorKind::DuplicateKeyword, item));
                }
                if at + 1 >= total {
                    return Err(ArgsError::new(ArgsErrorKind::MissingValue, item));
                }
                if flags & FINAL != 0 {
                    slots[item].take_range(at + 1, total);
                    at = total;
                } else {
                    // One value follows a keyword, even for `/M`, and even
                    // when that value spells another keyword.
                    slots[item].take_range(at + 1, at + 2);
                    at += 2;
                }
                continue;
            }
            at = self.assign_positional(&tokens, total, at, &mut slots)?;
        }

        let mut values = Values {
            tokens,
            slots,
            glued,
            count: self.count,
        };
        for item in 0..self.count {
            let flags = self.items[item].flags;
            if flags & REQUIRED != 0 && !values.slots[item].present {
                return Err(ArgsError::new(ArgsErrorKind::MissingRequired, item));
            }
            if flags & NUMBER != 0 {
                let mut mask = values.slots[item].mask;
                let mut first = true;
                while mask != 0 {
                    let bit = mask.trailing_zeros() as usize;
                    mask &= mask - 1;
                    let number = parse_number(values.tokens[bit])
                        .ok_or(ArgsError::new(ArgsErrorKind::BadNumber, item))?;
                    if first {
                        values.slots[item].number = number;
                        first = false;
                    }
                }
            }
        }
        Ok(values)
    }

    /// Counts the arguments from `at` on that are not keywords or their values.
    fn count_positional(&self, tokens: &[&[u8]], total: usize, mut at: usize) -> usize {
        let mut count = 0;
        while at < total {
            match self.index_of(tokens[at]) {
                Some(item) => {
                    let flags = self.items[item].flags;
                    if flags & FINAL != 0 {
                        break;
                    }
                    at += if flags & SWITCH != 0 { 1 } else { 2 };
                }
                None => {
                    count += 1;
                    at += 1;
                }
            }
        }
        count
    }

    /// Gives the positional argument at `at` to the first item that takes one.
    ///
    /// A `/M` item leaves the last arguments to the required items after it,
    /// as `ReadArgs` does, and a `/F` item takes everything from `at` on.
    fn assign_positional(
        &self,
        tokens: &[&[u8]],
        total: usize,
        at: usize,
        slots: &mut [Slot; MAX_TEMPLATE_ITEMS],
    ) -> Result<usize, ArgsError> {
        loop {
            let target = (0..self.count).find(|&i| {
                let flags = self.items[i].flags;
                let slot = &slots[i];
                flags & (SWITCH | KEYWORD) == 0
                    && !slot.closed
                    && (!slot.present || (flags & MULTIPLE != 0 && slot.quota != 0))
            });
            let Some(item) = target else {
                return Err(ArgsError::new(ArgsErrorKind::UnexpectedArgument, at));
            };
            let flags = self.items[item].flags;
            if flags & FINAL != 0 {
                slots[item].take_range(at, total);
                return Ok(total);
            }
            if flags & MULTIPLE != 0 {
                if slots[item].quota < 0 {
                    let remaining = self.count_positional(tokens, total, at);
                    let reserved = (item + 1..self.count)
                        .filter(|&j| {
                            let later = self.items[j].flags;
                            later & REQUIRED != 0
                                && later & (SWITCH | KEYWORD | FINAL | MULTIPLE) == 0
                                && !slots[j].present
                                && !tokens[at..total]
                                    .iter()
                                    .any(|token| self.index_of(token) == Some(j))
                        })
                        .count();
                    slots[item].quota = remaining.saturating_sub(reserved) as i32;
                    if slots[item].quota == 0 {
                        slots[item].closed = true;
                        continue;
                    }
                }
                slots[item].quota -= 1;
            }
            slots[item].take_range(at, at + 1);
            return Ok(at + 1);
        }
    }
}

fn parse_number(token: &[u8]) -> Option<i32> {
    let (negative, digits) = match token {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, token),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(digit - b'0');
        if value > i64::from(i32::MAX) + 1 {
            return None;
        }
    }
    let value = if negative { -value } else { value };
    i32::try_from(value).ok()
}

#[derive(Clone, Copy)]
struct Slot {
    present: bool,
    flag: bool,
    mask: u64,
    number: i32,
    quota: i32,
    closed: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        present: false,
        flag: false,
        mask: 0,
        number: 0,
        quota: -1,
        closed: false,
    };

    fn take_range(&mut self, start: usize, end: usize) {
        for bit in start..end {
            self.mask |= 1 << bit;
        }
        self.present = true;
    }
}

/// The result of matching arguments against a [`Template`].
///
/// Items are addressed by their position in the template (see
/// [`Template::index_of`]). Every accessor returns an empty answer for an item
/// that was not given or has the wrong kind.
#[derive(Clone, Copy)]
pub struct Values<'a> {
    tokens: [&'a [u8]; MAX_EXPANDED_TOKENS],
    slots: [Slot; MAX_TEMPLATE_ITEMS],
    glued: u64,
    count: usize,
}

impl<'a> Values<'a> {
    fn slot(&self, item: usize) -> Option<&Slot> {
        (item < self.count).then(|| &self.slots[item])
    }

    /// Returns `true` if the item was given (any kind of item).
    pub fn is_present(&self, item: usize) -> bool {
        self.slot(item).is_some_and(|slot| slot.present)
    }

    /// Returns a switch's state; a toggle that appeared an odd number of times
    /// is `true`.
    pub fn switch(&self, item: usize) -> bool {
        self.slot(item).is_some_and(|slot| slot.flag)
    }

    /// Returns a `/N` item's value, or the first of its values with `/M`.
    pub fn number(&self, item: usize) -> Option<i32> {
        self.slot(item)
            .filter(|slot| slot.present && slot.mask != 0)
            .map(|slot| slot.number)
    }

    /// Returns the first value of a value item.
    pub fn text(&self, item: usize) -> Option<&'a [u8]> {
        self.tokens(item).next()
    }

    /// Iterates over every value of an item: one for a plain item, any number
    /// for `/M`, the rest of the line for `/F`.
    pub fn tokens(&self, item: usize) -> Tokens<'a> {
        Tokens {
            tokens: self.tokens,
            mask: self.slot(item).map_or(0, |slot| slot.mask),
        }
    }

    /// Writes the values of an item into `out` as one line, the way the line
    /// was typed: values are separated by a space, except that the parts of an
    /// argument that was split at `=` are joined by `=` again. Returns the
    /// length written, or `None` if the item was not given or `out` is too
    /// small. This is how a `/F` item's rest of the line is read back.
    pub fn write_line(&self, item: usize, out: &mut [u8]) -> Option<usize> {
        let slot = self.slot(item).filter(|slot| slot.present)?;
        let mut mask = slot.mask;
        let mut written = 0;
        let mut first = true;
        while mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            let separator: &[u8] = if first {
                b""
            } else if self.glued & (1 << bit) != 0 {
                b"="
            } else {
                b" "
            };
            first = false;
            for byte in separator.iter().chain(self.tokens[bit]) {
                *out.get_mut(written)? = *byte;
                written += 1;
            }
        }
        Some(written)
    }

    /// Iterates over every value of a `/N/M` item as numbers.
    pub fn numbers(&self, item: usize) -> impl Iterator<Item = i32> + 'a {
        self.tokens(item).filter_map(parse_number)
    }
}

impl core::fmt::Debug for Values<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Values")
            .field("items", &self.count)
            .finish()
    }
}

impl core::fmt::Debug for Template<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Template")
            .field("items", &self.count)
            .finish()
    }
}

/// Iterator over the values of one item; see [`Values::tokens`].
#[derive(Clone, Copy)]
pub struct Tokens<'a> {
    tokens: [&'a [u8]; MAX_EXPANDED_TOKENS],
    mask: u64,
}

impl<'a> Iterator for Tokens<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.mask == 0 {
            return None;
        }
        let bit = self.mask.trailing_zeros() as usize;
        self.mask &= self.mask - 1;
        Some(self.tokens[bit])
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn read<'a>(template: &'a [u8], args: &[&'a [u8]]) -> Result<Values<'a>, ArgsError> {
        Template::parse(template)?.read(args.iter().copied())
    }

    #[test]
    fn positional_keyword_and_switch() {
        let v = read(b"FROM/A,TO/K,ALL/S", &[b"a", b"TO", b"b", b"all"]).unwrap();
        assert_eq!(v.text(0), Some(&b"a"[..]));
        assert_eq!(v.text(1), Some(&b"b"[..]));
        assert!(v.switch(2));
    }

    #[test]
    fn keyword_equals_value() {
        let v = read(b"FROM/A,TO/K", &[b"x", b"to=dest"]).unwrap();
        assert_eq!(v.text(1), Some(&b"dest"[..]));
    }

    #[test]
    fn multiple_collects_positionals_and_stops_at_keywords() {
        let v = read(b"FROM/M,TO/K", &[b"a", b"b", b"TO", b"c"]).unwrap();
        assert_eq!(v.tokens(0).collect::<std::vec::Vec<_>>(), [&b"a"[..], b"b"]);
        assert_eq!(v.text(1), Some(&b"c"[..]));
    }

    #[test]
    fn final_takes_the_rest() {
        let v = read(b"NAME/A,TEXT/F", &[b"n", b"hello", b"ALL", b"world"]).unwrap();
        assert_eq!(v.tokens(1).count(), 3);
    }

    #[test]
    fn numbers_are_checked() {
        let v = read(b"COUNT/N", &[b"-12"]).unwrap();
        assert_eq!(v.number(0), Some(-12));
        assert_eq!(
            read(b"COUNT/N", &[b"1x"]).unwrap_err().kind,
            ArgsErrorKind::BadNumber
        );
        assert_eq!(
            read(b"COUNT/N", &[b"2147483648"]).unwrap_err().kind,
            ArgsErrorKind::BadNumber
        );
        assert!(read(b"COUNT/N", &[b"-2147483648"]).is_ok());
    }

    #[test]
    fn required_and_unexpected() {
        assert_eq!(
            read(b"A/A", &[]).unwrap_err(),
            ArgsError::new(ArgsErrorKind::MissingRequired, 0)
        );
        assert_eq!(
            read(b"A", &[b"x", b"y"]).unwrap_err(),
            ArgsError::new(ArgsErrorKind::UnexpectedArgument, 1)
        );
        assert_eq!(
            read(b"A/K", &[b"x"]).unwrap_err().kind,
            ArgsErrorKind::UnexpectedArgument
        );
        assert_eq!(
            read(b"A/K", &[b"A"]).unwrap_err().kind,
            ArgsErrorKind::MissingValue
        );
        assert_eq!(
            read(b"A/K", &[b"A", b"1", b"A", b"2"]).unwrap_err().kind,
            ArgsErrorKind::DuplicateKeyword
        );
    }

    #[test]
    fn switch_alias_and_repeats() {
        let v = read(b"QUIET=Q/T", &[b"q"]).unwrap();
        assert!(v.switch(0));
        assert_eq!(
            read(b"ALL/S", &[b"ALL", b"all"]).unwrap_err().kind,
            ArgsErrorKind::DuplicateKeyword
        );
    }

    #[test]
    fn multiple_leaves_the_last_values_to_required_items() {
        let v = read(b"SRC/M,DEST/A", &[b"a", b"b", b"c"]).unwrap();
        assert_eq!(v.tokens(0).count(), 2);
        assert_eq!(v.text(1), Some(&b"c"[..]));
        let v = read(b"SRC/M,DEST/A", &[b"a"]).unwrap();
        assert!(!v.is_present(0));
        assert_eq!(v.text(1), Some(&b"a"[..]));
        assert_eq!(
            read(b"SRC/A/M,DEST/A", &[b"a"]).unwrap_err().kind,
            ArgsErrorKind::MissingRequired
        );
    }

    #[test]
    fn keyword_takes_one_value_and_equals_splits_everywhere() {
        let v = read(b"A/M,B/K", &[b"A", b"B", b"B", b"c"]).unwrap();
        assert_eq!(v.text(0), Some(&b"B"[..]));
        assert_eq!(v.text(1), Some(&b"c"[..]));
        let v = read(b"A,B,C", &[b"x=y=z"]).unwrap();
        assert_eq!(v.tokens(2).next(), Some(&b"z"[..]));
        assert_eq!(
            read(b"A,B", &[b"=x"]).unwrap_err().kind,
            ArgsErrorKind::EmptyToken
        );
        assert_eq!(
            read(b"A,B", &[b"x="]).unwrap_err().kind,
            ArgsErrorKind::EmptyToken
        );
    }

    #[test]
    fn template_errors() {
        assert_eq!(
            Template::parse(b"A/Z").err().map(|e| e.kind),
            Some(ArgsErrorKind::BadModifier)
        );
        assert_eq!(
            Template::parse(b"A/S/N").err().map(|e| e.kind),
            Some(ArgsErrorKind::ConflictingModifiers)
        );
        assert_eq!(
            Template::parse(b"A,,B").err().map(|e| e.kind),
            Some(ArgsErrorKind::EmptyName)
        );
    }
}
