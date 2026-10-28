//! Exact workflow counters shared by authentication metadata and receipts.
//! Only a temporary structural-validation copy receives small placeholders;
//! original input bytes and returned decimal counter strings are preserved.
use crate::{Refusal, Result};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositiveCounter(String);

impl PositiveCounter {
    pub fn as_decimal(&self) -> &str {
        &self.0
    }

    pub(crate) fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty()
            || raw.len() > 4300
            || raw.starts_with('0')
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Refusal::new(
                "workflow counter must be a positive exact JSON integer",
            ));
        }
        Ok(Self(raw.to_owned()))
    }
}

impl<'de> Deserialize<'de> for PositiveCounter {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> std::result::Result<Self, D::Error> {
        let value = u64::deserialize(input)?;
        Self::parse(&value.to_string()).map_err(serde::de::Error::custom)
    }
}

impl Serialize for PositiveCounter {
    fn serialize<S: serde::Serializer>(&self, output: S) -> std::result::Result<S::Ok, S::Error> {
        let raw = RawValue::from_string(self.0.clone()).map_err(serde::ser::Error::custom)?;
        raw.serialize(output)
    }
}

/// Tokens must borrow this already byte/depth-bounded input. The caller must
/// subsequently validate the entire returned copy, including duplicate keys,
/// exact schema and field types, then restore the returned counters by position.
pub(crate) fn validation_copy(
    raw: &[u8],
    tokens: &[&RawValue],
) -> Result<(Vec<u8>, Vec<PositiveCounter>)> {
    let mut counters = Vec::new();
    let mut replacements = Vec::new();
    for token in tokens {
        counters.push(PositiveCounter::parse(token.get())?);
        let start = (token.get().as_ptr() as usize)
            .checked_sub(raw.as_ptr() as usize)
            .ok_or_else(|| Refusal::new("workflow token is outside its source JSON"))?;
        let end = start
            .checked_add(token.get().len())
            .filter(|end| *end <= raw.len())
            .ok_or_else(|| Refusal::new("workflow token range overflow"))?;
        if raw.get(start..end) != Some(token.get().as_bytes()) {
            return Err(Refusal::new("workflow token differs from its source range"));
        }
        if token.get().parse::<u64>().is_err() {
            replacements.push((start, end));
        }
    }
    replacements.sort_unstable();
    let mut copy = Vec::new();
    copy.try_reserve_exact(raw.len())
        .map_err(|_| Refusal::new("could not allocate bounded workflow validation copy"))?;
    let mut previous = 0;
    for (start, end) in replacements {
        if start < previous {
            return Err(Refusal::new("overlapping workflow tokens"));
        }
        copy.extend_from_slice(&raw[previous..start]);
        copy.push(b'1');
        previous = end;
    }
    copy.extend_from_slice(&raw[previous..]);
    Ok((copy, counters))
}
