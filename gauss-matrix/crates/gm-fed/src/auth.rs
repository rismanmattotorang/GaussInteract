// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Federation request authentication — the `X-Matrix` request signature
//! (spec §III.E, §VI).
//!
//! Every Server–Server request carries an `Authorization: X-Matrix …` header
//! signing the request: a server proves a request really came from it (and was
//! not replayed against a different endpoint) by signing a canonical object over
//! the method, URI, origin, destination and body with its private key. The
//! receiver verifies that signature against the origin's published key.
//!
//! This module parses that header ([`XMatrixAuth`]), builds the canonical
//! [`signing_bytes`] a request is signed over, and [`sign`]/[`verify`] them.
//!
//! ## Signature scheme
//!
//! Signing is **Ed25519** (RFC 8032, see [`crate::ed25519`]): a server signs
//! with its 32-byte secret seed and the verifier holds only the origin's
//! 32-byte *public* key, fetched from `/_matrix/key/v2/server`. Keys and
//! signatures cross the wire as **unpadded base64**, so [`sign`] takes a base64
//! secret seed and [`verify`] takes a base64 public key.

use crate::ed25519;
use gm_api::Json;
use std::collections::BTreeMap;

/// A parsed `X-Matrix` authorization header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XMatrixAuth {
    /// The server that signed the request.
    pub origin: String,
    /// The intended destination server (present in modern headers).
    pub destination: Option<String>,
    /// The signing key id, e.g. `ed25519:1`.
    pub key_id: String,
    /// The signature (verified against the origin's key).
    pub signature: String,
}

impl XMatrixAuth {
    /// Parse an `Authorization` header value of the form
    /// `X-Matrix origin="o",destination="d",key="ed25519:1",sig="…"`.
    /// Values may be quoted or bare; `origin`, `key` and `sig` are required.
    pub fn parse(header: &str) -> Option<Self> {
        let rest = strip_scheme(header)?;
        let mut origin = None;
        let mut destination = None;
        let mut key_id = None;
        let mut signature = None;
        for field in split_fields(rest) {
            let (name, value) = field.split_once('=')?;
            let value = unquote(value.trim());
            match name.trim() {
                "origin" => origin = Some(value),
                "destination" => destination = Some(value),
                "key" => key_id = Some(value),
                "sig" => signature = Some(value),
                _ => {}
            }
        }
        Some(Self {
            origin: origin?,
            destination,
            key_id: key_id?,
            signature: signature?,
        })
    }

    /// Render this auth back to an `Authorization` header value.
    pub fn to_header(&self) -> String {
        let mut out = format!("X-Matrix origin=\"{}\",", self.origin);
        if let Some(destination) = &self.destination {
            out.push_str(&format!("destination=\"{destination}\","));
        }
        out.push_str(&format!(
            "key=\"{}\",sig=\"{}\"",
            self.key_id, self.signature
        ));
        out
    }
}

/// Case-insensitively strip the `X-Matrix` scheme, returning the parameters.
fn strip_scheme(header: &str) -> Option<&str> {
    let header = header.trim_start();
    let scheme = header.get(..8)?;
    if scheme.eq_ignore_ascii_case("X-Matrix") {
        Some(header[8..].trim_start())
    } else {
        None
    }
}

/// Split the comma-separated parameters, ignoring commas inside quotes.
fn split_fields(params: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in params.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        fields.push(current);
    }
    fields
}

/// Strip surrounding double quotes from a value, if present.
fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
        .to_owned()
}

/// The canonical bytes a federation request is signed over (Matrix's request
/// signing object): method, URI, origin, destination, and the parsed content
/// (omitted for a bodyless request). Object keys are sorted, so both sides
/// produce identical bytes.
pub fn signing_bytes(
    method: &str,
    uri: &str,
    origin: &str,
    destination: &str,
    content: Option<&str>,
) -> Vec<u8> {
    let mut obj = BTreeMap::new();
    obj.insert("method".to_owned(), Json::String(method.to_owned()));
    obj.insert("uri".to_owned(), Json::String(uri.to_owned()));
    obj.insert("origin".to_owned(), Json::String(origin.to_owned()));
    obj.insert(
        "destination".to_owned(),
        Json::String(destination.to_owned()),
    );
    if let Some(content) = content {
        if let Ok(parsed) = Json::parse(content) {
            obj.insert("content".to_owned(), parsed);
        }
    }
    Json::Object(obj).to_string().into_bytes()
}

/// Sign `bytes` with the base64 secret `seed`, returning the base64 Ed25519
/// signature (the empty string if the seed is not a 32-byte base64 value).
pub fn sign(bytes: &[u8], seed: &str) -> String {
    ed25519::sign_b64(bytes, seed)
}

/// Verify that `signature` (base64) is a valid Ed25519 signature over `bytes`
/// under the base64 `public_key`.
pub fn verify(bytes: &[u8], signature: &str, public_key: &str) -> bool {
    ed25519::verify_b64(bytes, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_quoted_x_matrix_header() {
        let auth = XMatrixAuth::parse(
            r#"X-Matrix origin="a.tld",destination="b.tld",key="ed25519:1",sig="abc""#,
        )
        .unwrap();
        assert_eq!(auth.origin, "a.tld");
        assert_eq!(auth.destination.as_deref(), Some("b.tld"));
        assert_eq!(auth.key_id, "ed25519:1");
        assert_eq!(auth.signature, "abc");
    }

    #[test]
    fn header_round_trips() {
        let auth = XMatrixAuth {
            origin: "a.tld".to_owned(),
            destination: Some("b.tld".to_owned()),
            key_id: "ed25519:1".to_owned(),
            signature: "abc".to_owned(),
        };
        assert_eq!(XMatrixAuth::parse(&auth.to_header()), Some(auth));
    }

    #[test]
    fn non_x_matrix_or_incomplete_headers_are_rejected() {
        assert!(XMatrixAuth::parse("Bearer token").is_none());
        // Missing the signature field.
        assert!(XMatrixAuth::parse(r#"X-Matrix origin="a",key="ed25519:1""#).is_none());
    }

    #[test]
    fn sign_then_verify_round_trips_and_detects_tampering() {
        // Asymmetric: sign with the secret seed, verify with the public key.
        let seed = ed25519::seed_from_material("a.tld:ed25519:1");
        let public = ed25519::public_key_b64(&seed).unwrap();
        let bytes = signing_bytes(
            "PUT",
            "/_matrix/federation/v1/send/t1",
            "a.tld",
            "b.tld",
            Some(r#"{"pdus":[]}"#),
        );
        let sig = sign(&bytes, &seed);
        assert!(verify(&bytes, &sig, &public));
        // Wrong key, tampered bytes, or tampered signature all fail.
        let other_public = ed25519::public_key_b64(&ed25519::seed_from_material("evil")).unwrap();
        assert!(!verify(&bytes, &sig, &other_public));
        let other = signing_bytes("PUT", "/different/uri", "a.tld", "b.tld", Some("{}"));
        assert!(!verify(&other, &sig, &public));
        assert!(!verify(&bytes, "AAAA", &public));
    }

    #[test]
    fn signing_bytes_are_independent_of_content_key_order() {
        // The canonical object sorts keys, so equivalent content signs the same.
        let a = signing_bytes("PUT", "/u", "o", "d", Some(r#"{"a":1,"b":2}"#));
        let b = signing_bytes("PUT", "/u", "o", "d", Some(r#"{"b":2,"a":1}"#));
        assert_eq!(a, b);
    }
}
