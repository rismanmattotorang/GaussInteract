// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A minimal, dependency-free JSON value, parser and serializer.
//!
//! The entire Client–Server / Server–Server API is JSON, so the homeserver
//! needs to read request bodies and write responses. The production server uses
//! `serde_json` (via `ruma`); this scaffold pins a small, std-only [`Json`]
//! value with a recursive-descent [`Json::parse`] and a compact serializer, so
//! the request/response handling is testable without pulling a dependency in.
//!
//! It is a faithful JSON reader — objects, arrays, strings (with `\uXXXX` and
//! surrogate pairs), numbers, `true`/`false`/`null` — with a recursion-depth
//! guard against adversarial nesting. Numbers are held as `f64`; Matrix's
//! integers (timestamps, depths, power levels) are well within `f64`'s exact
//! integer range, and [`Json::as_u64`]/[`Json::as_i64`] recover them.

use std::collections::BTreeMap;
use std::fmt;

/// Maximum nesting depth the parser accepts, to bound recursion on hostile input.
const MAX_DEPTH: usize = 128;

/// A parsed JSON value. Objects use a [`BTreeMap`] so serialization is
/// deterministic (key-ordered).
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// A number (held as `f64`).
    Number(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object (key-ordered).
    Object(BTreeMap<String, Json>),
}

/// A JSON parse error, with the character offset where it was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// Input ended unexpectedly.
    UnexpectedEof,
    /// An unexpected character at this offset.
    UnexpectedChar(usize),
    /// A malformed number at this offset.
    InvalidNumber(usize),
    /// A malformed string escape at this offset.
    InvalidEscape(usize),
    /// Trailing content after a complete value, at this offset.
    TrailingData(usize),
    /// Nesting exceeded [`MAX_DEPTH`].
    DepthExceeded,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::UnexpectedEof => write!(f, "unexpected end of input"),
            JsonError::UnexpectedChar(p) => write!(f, "unexpected character at offset {p}"),
            JsonError::InvalidNumber(p) => write!(f, "invalid number at offset {p}"),
            JsonError::InvalidEscape(p) => write!(f, "invalid string escape at offset {p}"),
            JsonError::TrailingData(p) => write!(f, "trailing data at offset {p}"),
            JsonError::DepthExceeded => write!(f, "maximum nesting depth exceeded"),
        }
    }
}

impl std::error::Error for JsonError {}

impl Json {
    /// Parse a JSON document, requiring it to consume the whole input.
    pub fn parse(input: &str) -> Result<Json, JsonError> {
        let chars: Vec<char> = input.chars().collect();
        let mut p = Parser {
            chars: &chars,
            pos: 0,
        };
        p.skip_ws();
        let value = p.parse_value(0)?;
        p.skip_ws();
        if p.pos != p.chars.len() {
            return Err(JsonError::TrailingData(p.pos));
        }
        Ok(value)
    }

    /// The boolean, if this is a [`Json::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number as `f64`, if this is a [`Json::Number`].
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The number as `u64` if it is a non-negative integer within range.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(n) if n.fract() == 0.0 && *n >= 0.0 && *n <= u64::MAX as f64 => {
                Some(*n as u64)
            }
            _ => None,
        }
    }

    /// The number as `i64` if it is an integer within range.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(n)
                if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 =>
            {
                Some(*n as i64)
            }
            _ => None,
        }
    }

    /// The string, if this is a [`Json::String`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// The elements, if this is a [`Json::Array`].
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(v) => Some(v),
            _ => None,
        }
    }

    /// The entries, if this is a [`Json::Object`].
    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    /// A field of an object by key (`None` if not an object or absent).
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object().and_then(|m| m.get(key))
    }

    /// Serialize compactly into `out`. Public serialization is via [`Display`]
    /// (so `json.to_string()` works through the standard `ToString` impl).
    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(n) => out.push_str(&format_number(*n)),
            Json::String(s) => write_json_string(out, s),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

/// Format a number the way JSON expects: integral values without a decimal
/// point (`5`, not `5.0`), others via the shortest round-tripping `f64` repr.
fn format_number(n: f64) -> String {
    if !n.is_finite() {
        // JSON has no NaN/Infinity; emit null-equivalent 0 is wrong, so emit
        // "null" semantics would change the type. We emit 0 only if asked to
        // serialize a non-finite, which the parser never produces.
        return "0".to_owned();
    }
    if n.fract() == 0.0 && n.abs() < 9_007_199_254_740_992.0 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Write `s` as a quoted, escaped JSON string.
fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if matches!(c, ' ' | '\t' | '\n' | '\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > MAX_DEPTH {
            return Err(JsonError::DepthExceeded);
        }
        match self.peek().ok_or(JsonError::UnexpectedEof)? {
            '{' => self.parse_object(depth),
            '[' => self.parse_array(depth),
            '"' => Ok(Json::String(self.parse_string()?)),
            't' | 'f' => self.parse_bool(),
            'n' => self.parse_null(),
            c if c == '-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err(JsonError::UnexpectedChar(self.pos)),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(JsonError::UnexpectedChar(self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(':') {
                return Err(JsonError::UnexpectedChar(self.pos.saturating_sub(1)));
            }
            self.skip_ws();
            let value = self.parse_value(depth + 1)?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => break,
                _ => return Err(JsonError::UnexpectedChar(self.pos.saturating_sub(1))),
            }
        }
        Ok(Json::Object(map))
    }

    fn parse_array(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => break,
                _ => return Err(JsonError::UnexpectedChar(self.pos.saturating_sub(1))),
            }
        }
        Ok(Json::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.pos += 1; // opening '"'
        let mut s = String::new();
        loop {
            match self.bump().ok_or(JsonError::UnexpectedEof)? {
                '"' => return Ok(s),
                '\\' => {
                    let esc_pos = self.pos.saturating_sub(1);
                    match self.bump().ok_or(JsonError::UnexpectedEof)? {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'b' => s.push('\u{08}'),
                        'f' => s.push('\u{0c}'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'u' => s.push(self.parse_unicode_escape(esc_pos)?),
                        _ => return Err(JsonError::InvalidEscape(esc_pos)),
                    }
                }
                c if (c as u32) < 0x20 => return Err(JsonError::UnexpectedChar(self.pos - 1)),
                c => s.push(c),
            }
        }
    }

    /// Parse the four hex digits of a `\u` escape, combining a high+low
    /// surrogate pair into one scalar value.
    fn parse_unicode_escape(&mut self, esc_pos: usize) -> Result<char, JsonError> {
        let cp = self.parse_hex4(esc_pos)?;
        if (0xD800..=0xDBFF).contains(&cp) {
            // High surrogate: expect a following \uXXXX low surrogate.
            if self.bump() != Some('\\') || self.bump() != Some('u') {
                return Err(JsonError::InvalidEscape(esc_pos));
            }
            let low = self.parse_hex4(esc_pos)?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JsonError::InvalidEscape(esc_pos));
            }
            let scalar = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            char::from_u32(scalar).ok_or(JsonError::InvalidEscape(esc_pos))
        } else if (0xDC00..=0xDFFF).contains(&cp) {
            // Lone low surrogate.
            Err(JsonError::InvalidEscape(esc_pos))
        } else {
            char::from_u32(cp).ok_or(JsonError::InvalidEscape(esc_pos))
        }
    }

    fn parse_hex4(&mut self, esc_pos: usize) -> Result<u32, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.bump().ok_or(JsonError::UnexpectedEof)?;
            let digit = c.to_digit(16).ok_or(JsonError::InvalidEscape(esc_pos))?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, JsonError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| JsonError::InvalidNumber(start))
    }

    fn parse_bool(&mut self) -> Result<Json, JsonError> {
        if self.consume_literal("true") {
            Ok(Json::Bool(true))
        } else if self.consume_literal("false") {
            Ok(Json::Bool(false))
        } else {
            Err(JsonError::UnexpectedChar(self.pos))
        }
    }

    fn parse_null(&mut self) -> Result<Json, JsonError> {
        if self.consume_literal("null") {
            Ok(Json::Null)
        } else {
            Err(JsonError::UnexpectedChar(self.pos))
        }
    }

    fn consume_literal(&mut self, literal: &str) -> bool {
        let end = self.pos + literal.len();
        if end <= self.chars.len()
            && self.chars[self.pos..end]
                .iter()
                .copied()
                .eq(literal.chars())
        {
            self.pos = end;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_nested_object() {
        let v = Json::parse(
            r#"{"type":"m.login.password","identifier":{"user":"alice"},"n":42,"ok":true,"x":null}"#,
        )
        .unwrap();
        assert_eq!(
            v.get("type").and_then(Json::as_str),
            Some("m.login.password")
        );
        assert_eq!(
            v.get("identifier")
                .and_then(|i| i.get("user"))
                .and_then(Json::as_str),
            Some("alice")
        );
        assert_eq!(v.get("n").and_then(Json::as_u64), Some(42));
        assert_eq!(v.get("ok").and_then(Json::as_bool), Some(true));
        assert_eq!(v.get("x"), Some(&Json::Null));
    }

    #[test]
    fn parses_arrays_and_numbers() {
        let v = Json::parse("[1, 2.5, -3, 1e3]").unwrap();
        let a = v.as_array().unwrap();
        assert_eq!(a[0].as_u64(), Some(1));
        assert_eq!(a[1].as_f64(), Some(2.5));
        assert_eq!(a[2].as_i64(), Some(-3));
        assert_eq!(a[3].as_u64(), Some(1000));
    }

    #[test]
    fn round_trips_compactly_with_sorted_keys() {
        let v = Json::parse(r#"{ "b": 1 , "a": [true, "x"] }"#).unwrap();
        // Object keys are emitted in sorted order; whitespace is dropped.
        assert_eq!(v.to_string(), r#"{"a":[true,"x"],"b":1}"#);
    }

    #[test]
    fn handles_string_escapes_and_unicode() {
        let v = Json::parse(r#""a\"b\\c\nA😀""#).unwrap();
        assert_eq!(v.as_str(), Some("a\"b\\c\nA😀"));
    }

    #[test]
    fn serializes_strings_with_escaping() {
        let v = Json::String("tab\there\"quote".to_owned());
        assert_eq!(v.to_string(), r#""tab\there\"quote""#);
    }

    #[test]
    fn integral_numbers_serialize_without_a_decimal_point() {
        assert_eq!(Json::Number(5.0).to_string(), "5");
        assert_eq!(Json::Number(-7.0).to_string(), "-7");
        assert_eq!(Json::Number(2.5).to_string(), "2.5");
    }

    #[test]
    fn rejects_trailing_data_and_truncation() {
        assert_eq!(Json::parse("{} {}"), Err(JsonError::TrailingData(3)));
        assert_eq!(Json::parse("{\"a\":"), Err(JsonError::UnexpectedEof));
        assert!(matches!(
            Json::parse("[1,]"),
            Err(JsonError::UnexpectedChar(_))
        ));
        assert!(Json::parse("nul").is_err());
    }

    #[test]
    fn empty_containers_parse() {
        assert_eq!(Json::parse("{}").unwrap(), Json::Object(BTreeMap::new()));
        assert_eq!(Json::parse("[]").unwrap(), Json::Array(Vec::new()));
    }

    #[test]
    fn deeply_nested_input_is_rejected_not_overflowed() {
        let deep = "[".repeat(MAX_DEPTH + 5);
        assert_eq!(Json::parse(&deep), Err(JsonError::DepthExceeded));
    }
}
