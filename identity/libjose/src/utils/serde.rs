// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::str;

use crate::error::Error;
use crate::error::Result;
use crate::jose::JoseHeader;
use crate::jwe::JweHeader;
use crate::jws::JwsHeader;
use crate::lib::*;
use crate::utils::decode_b64;

// The default value of the "b64" header parameter
const DEFAULT_B64: bool = true;

// Claims defined in the base JWE/JWS RFCs
const PREDEFINED: &[&str] = &[
  "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#s256", "typ", "cty", "crit", "enc", "zip", "epk", "apu", "apv",
  "iv", "tag", "p2s", "p2c",
];

pub fn parse_utf8(slice: &(impl AsRef<[u8]> + ?Sized)) -> Result<&str> {
  str::from_utf8(slice.as_ref()).map_err(Error::InvalidUtf8)
}

pub fn check_slice_param<T>(name: &'static str, slice: Option<&[T]>, value: &T) -> Result<()>
where
  T: PartialEq,
{
  if slice.map(|slice| slice.contains(value)).unwrap_or(true) {
    Ok(())
  } else {
    Err(Error::InvalidParam(name))
  }
}

pub fn filter_non_empty_bytes<'a, T, U: 'a>(value: T) -> Option<&'a [u8]>
where
  T: Into<Option<&'a U>>,
  U: AsRef<[u8]> + ?Sized,
{
  value.into().map(AsRef::as_ref).filter(|value| !value.is_empty())
}

pub fn create_aad<T, U>(header: Option<&T>, data: Option<&U>) -> Vec<u8>
where
  T: AsRef<[u8]> + ?Sized,
  U: AsRef<[u8]> + ?Sized,
{
  let header: &[u8] = header.map(AsRef::as_ref).unwrap_or_default();
  let data: &[u8] = data.map(AsRef::as_ref).unwrap_or_default();

  if data.is_empty() {
    header.to_vec()
  } else {
    create_message(header, data)
  }
}

pub fn parse_cek(cek: Option<&str>) -> Result<Vec<u8>> {
  cek.ok_or(Error::EncError("CEK (missing)")).and_then(decode_b64)
}

pub fn create_pbes2_salt(algorithm: &str, p2s: &[u8]) -> Vec<u8> {
  let capacity: usize = algorithm.len() + 1 + p2s.len();
  let mut salt: Vec<u8> = Vec::with_capacity(capacity);

  // The salt value used is (UTF8(Alg) || 0x00 || Salt Input)
  salt.extend_from_slice(algorithm.as_bytes());
  salt.push(0x0);
  salt.extend_from_slice(p2s);
  salt
}

pub fn create_message(header: &[u8], claims: &[u8]) -> Vec<u8> {
  let capacity: usize = header.len() + 1 + claims.len();
  let mut message: Vec<u8> = Vec::with_capacity(capacity);

  message.extend(header);
  message.push(b'.');
  message.extend(claims);
  message
}

pub fn extract_b64(header: Option<&JwsHeader>) -> bool {
  header.and_then(JwsHeader::b64).unwrap_or(DEFAULT_B64)
}

pub fn validate_jws_headers(
  protected: Option<&JwsHeader>,
  unprotected: Option<&JwsHeader>,
  permitted: Option<&[String]>,
) -> Result<()> {
  // TODO: Validate Disjoint

  validate_crit(protected, unprotected, permitted)?;
  validate_b64(protected, unprotected)?;

  Ok(())
}

pub fn validate_jwe_headers<'a>(
  protected: Option<&JweHeader>,
  unprotected: Option<&JweHeader>,
  recipients: impl Iterator<Item = Option<&'a JweHeader>>,
  permitted: Option<&[String]>,
) -> Result<()> {
  // TODO: Validate Disjoint

  for recipient in recipients {
    // TODO: Validate Disjoint

    let unprotected: Option<Cow<'_, JweHeader>> = match (unprotected, recipient) {
      (Some(header), None) => Some(Cow::Borrowed(header)),
      (None, Some(header)) => Some(Cow::Borrowed(header)),
      (Some(_lhs), Some(_rhs)) => todo!("Merge Headers"),
      (None, None) => None,
    };

    validate_crit(protected, unprotected.as_deref(), permitted)?;

    // The "zip" parameter MUST be integrity protected
    if unprotected.map(|header| header.has("zip")).unwrap_or_default() {
      return Err(Error::InvalidParam("zip (unprotected)"));
    }
  }

  Ok(())
}

pub fn validate_crit<T>(protected: Option<&T>, unprotected: Option<&T>, permitted: Option<&[String]>) -> Result<()>
where
  T: JoseHeader,
{
  // The "crit" parameter MUST be integrity protected
  if unprotected.map(|header| header.has_claim("crit")).unwrap_or_default() {
    return Err(Error::InvalidParam("crit (unprotected)"));
  }

  let values: Option<&[String]> = protected.and_then(|header| header.common().crit());

  // The "crit" parameter MUST NOT be an empty list
  if values.map(|values| values.is_empty()).unwrap_or_default() {
    return Err(Error::InvalidParam("crit (empty)"));
  }

  let permitted: &[String] = permitted.unwrap_or_default();
  let values: &[String] = values.unwrap_or_default();

  for value in values {
    // The "crit" parameter MUST NOT contain any header parameters defined by
    // the JOSE JWS/JWA specifications.
    if PREDEFINED.contains(&&**value) {
      return Err(Error::InvalidParam("crit (pre-defined)"));
    }

    // The "crit" parameter MUST be understood by the application.
    if !permitted.contains(value) {
      return Err(Error::InvalidParam("crit (unpermitted)"));
    }

    let exists: bool = protected
      .map(|header| header.has_claim(value))
      .or_else(|| unprotected.map(|header| header.has_claim(value)))
      .unwrap_or_default();

    if !exists {
      return Err(Error::InvalidParam("crit"));
    }
  }

  Ok(())
}

pub fn validate_b64(protected: Option<&JwsHeader>, unprotected: Option<&JwsHeader>) -> Result<()> {
  // The "b64" parameter MUST be integrity protected
  if unprotected.and_then(JwsHeader::b64).is_some() {
    return Err(Error::InvalidParam("b64 (unprotected)"));
  }

  let b64: Option<bool> = protected.and_then(|header| header.b64());
  let crit: Option<&[String]> = protected.and_then(|header| header.crit());

  // The "b64" parameter MUST be included in the "crit" parameter values
  match (b64, crit) {
    (Some(_), Some(values)) if values.iter().any(|value| value == "b64") => Ok(()),
    (Some(_), None) => Err(Error::InvalidParam("b64 (non-critical)")),
    _ => Ok(()),
  }
}
