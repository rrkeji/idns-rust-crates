// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;

use core::str::FromStr;
use std::cmp::Ordering;
use std::convert::TryInto;
use std::hash::Hash;
use std::hash::Hasher;

use did_url::DID as BaseDIDUrl;

use identity_core::diff::Diff;
use identity_core::diff::DiffString;

use crate::did::did::is_char_method_id;
use crate::did::CoreDID;
use crate::did::DIDError;
use crate::did::DID;

pub type CoreDIDUrl = DIDUrl<CoreDID>;

/// A [DID Url]: a [DID] with [RelativeDIDUrl] components.
///
/// E.g. "did:iota:H3C2AVvLMv6gmMNam3uVAjZar3cJCwDwnZn6z3wXmqPV/path?query1=a&query2=b#fragment"
///
/// [DID Url]: https://www.w3.org/TR/did-core/#did-url-syntax
#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct DIDUrl<T>
where
  Self: Sized,
  T: DID + Sized,
{
  did: T,
  url: RelativeDIDUrl,
}

/// A [relative DID Url] with the [path], [query], and [fragment] components defined according
/// to [URI syntax](https://datatracker.ietf.org/doc/html/rfc5234).
///
/// E.g.
/// - `"/path?query#fragment"`
/// - `"/path"`
/// - `"?query"`
/// - `"#fragment"`
///
/// [relative DID Url]: https://www.w3.org/TR/did-core/#relative-did-urls
/// [path]: https://www.w3.org/TR/did-core/#path
/// [query]: https://www.w3.org/TR/did-core/#query
/// [fragment]: https://www.w3.org/TR/did-core/#fragment
#[derive(Clone, Default)]
pub struct RelativeDIDUrl {
  // Path including the leading '/'
  path: Option<String>,
  // Query including the leading '?'
  query: Option<String>,
  // Fragment including the leading '#'
  fragment: Option<String>,
}

impl RelativeDIDUrl {
  /// Create an empty [`RelativeDIDUrl`].
  pub fn new() -> Self {
    Self {
      path: None,
      query: None,
      fragment: None,
    }
  }

  /// Returns whether all URL segments are empty.
  pub fn is_empty(&self) -> bool {
    self.path.as_deref().unwrap_or_default().is_empty()
      && self.query.as_deref().unwrap_or_default().is_empty()
      && self.fragment.as_deref().unwrap_or_default().is_empty()
  }

  /// Return the [path](https://www.w3.org/TR/did-core/#path) component,
  /// including the leading '/'.
  ///
  /// E.g. `"/path/sub-path/resource"`
  pub fn path(&self) -> Option<&str> {
    self.path.as_deref()
  }

  /// Attempt to set the [path](https://www.w3.org/TR/did-core/#path) component.
  /// The path must start with a '/'.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::did::RelativeDIDUrl;
  /// # let mut url = RelativeDIDUrl::new();
  /// url.set_path(Some("/path/sub-path/resource")).unwrap();
  /// assert_eq!(url.path().unwrap(), "/path/sub-path/resource");
  /// assert_eq!(url.to_string(), "/path/sub-path/resource");
  /// ```
  pub fn set_path(&mut self, value: Option<&str>) -> Result<(), DIDError> {
    self.path = value
      .filter(|s| !s.is_empty())
      .map(|s| {
        if s.starts_with('/') && s.chars().all(is_char_path) {
          Ok(s.to_owned())
        } else {
          Err(DIDError::InvalidPath)
        }
      })
      .transpose()?;
    Ok(())
  }

  /// Return the [path](https://www.w3.org/TR/did-core/#query) component,
  /// excluding the leading '?' delimiter.
  ///
  /// E.g. `"?query1=a&query2=b" -> "query1=a&query2=b"`
  pub fn query(&self) -> Option<&str> {
    self.query.as_deref().map(|query| query.strip_prefix('?')).flatten()
  }

  /// Attempt to set the [query](https://www.w3.org/TR/did-core/#query) component.
  /// A leading '?' is ignored.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::did::RelativeDIDUrl;
  /// # let mut url = RelativeDIDUrl::new();
  /// // Set the query with a leading '?'
  /// url.set_query(Some("?query1=a")).unwrap();
  /// assert_eq!(url.query().unwrap(), "query1=a");
  /// assert_eq!(url.to_string(), "?query1=a");
  ///
  /// // Set the query without a leading '?'
  /// url.set_query(Some("query1=a&query2=b")).unwrap();
  /// assert_eq!(url.query().unwrap(), "query1=a&query2=b");
  /// assert_eq!(url.to_string(), "?query1=a&query2=b");
  /// ```
  pub fn set_query(&mut self, value: Option<&str>) -> Result<(), DIDError> {
    self.query = value
      .filter(|s| !s.is_empty())
      .map(|mut s| {
        // Ignore leading '?' during validation.
        s = s.strip_prefix('?').unwrap_or(s);
        if s.is_empty() || !s.chars().all(is_char_query) {
          return Err(DIDError::InvalidQuery);
        }
        Ok(format!("?{}", s))
      })
      .transpose()?;
    Ok(())
  }

  /// Return an iterator of `(name, value)` pairs in the query string.
  ///
  /// E.g. `"query1=a&query2=b" -> [("query1", "a"), ("query2", "b")]`
  ///
  /// See [form_urlencoded::parse].
  pub fn query_pairs(&self) -> form_urlencoded::Parse<'_> {
    form_urlencoded::parse(self.query().unwrap_or_default().as_bytes())
  }

  /// Return the [fragment](https://www.w3.org/TR/did-core/#fragment) component,
  /// excluding the leading '#' delimiter.
  ///
  /// E.g. `"#fragment" -> "fragment"`
  pub fn fragment(&self) -> Option<&str> {
    self
      .fragment
      .as_deref()
      .map(|fragment| fragment.strip_prefix('#'))
      .flatten()
  }

  /// Attempt to set the [fragment](https://www.w3.org/TR/did-core/#fragment) component.
  /// A leading '#' is ignored.
  ///
  /// # Example
  ///
  /// ```
  /// # use identity_did::did::RelativeDIDUrl;
  /// # let mut url = RelativeDIDUrl::new();
  /// // Set the fragment with a leading '#'
  /// url.set_fragment(Some("#fragment1")).unwrap();
  /// assert_eq!(url.fragment().unwrap(), "fragment1");
  /// assert_eq!(url.to_string(), "#fragment1");
  ///
  /// // Set the fragment without a leading '#'
  /// url.set_fragment(Some("fragment2")).unwrap();
  /// assert_eq!(url.fragment().unwrap(), "fragment2");
  /// assert_eq!(url.to_string(), "#fragment2");
  /// ```
  pub fn set_fragment(&mut self, value: Option<&str>) -> Result<(), DIDError> {
    self.fragment = value
      .filter(|s| !s.is_empty())
      .map(|mut s| {
        // Ignore leading '#' during validation.
        s = s.strip_prefix('#').unwrap_or(s);
        if s.is_empty() || !s.chars().all(is_char_fragment) {
          return Err(DIDError::InvalidFragment);
        }
        Ok(format!("#{}", s))
      })
      .transpose()?;
    Ok(())
  }
}

impl Display for RelativeDIDUrl {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!(
      "{}{}{}",
      self.path.as_deref().unwrap_or_default(),
      self.query.as_deref().unwrap_or_default(),
      self.fragment.as_deref().unwrap_or_default()
    ))
  }
}

impl Debug for RelativeDIDUrl {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{}", self))
  }
}

impl PartialEq for RelativeDIDUrl {
  fn eq(&self, other: &Self) -> bool {
    self.path.as_deref().unwrap_or_default() == other.path.as_deref().unwrap_or_default()
      && self.query.as_deref().unwrap_or_default() == other.query.as_deref().unwrap_or_default()
      && self.fragment.as_deref().unwrap_or_default() == other.fragment.as_deref().unwrap_or_default()
  }
}

impl Eq for RelativeDIDUrl {}

impl PartialOrd for RelativeDIDUrl {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    // Compare path, query, then fragment in that order
    let path_cmp = self
      .path
      .as_deref()
      .unwrap_or_default()
      .cmp(other.path.as_deref().unwrap_or_default());

    if path_cmp == Ordering::Equal {
      let query_cmp = self
        .query
        .as_deref()
        .unwrap_or_default()
        .cmp(other.query.as_deref().unwrap_or_default());

      if query_cmp == Ordering::Equal {
        return Some(
          self
            .fragment
            .as_deref()
            .unwrap_or_default()
            .cmp(other.fragment.as_deref().unwrap_or_default()),
        );
      }

      return Some(query_cmp);
    }

    Some(path_cmp)
  }
}

impl Ord for RelativeDIDUrl {
  fn cmp(&self, other: &Self) -> Ordering {
    self
      .partial_cmp(other)
      .expect("RelativeDIDUrl partial_cmp should always be Some")
  }
}

impl Hash for RelativeDIDUrl {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_string().hash(state)
  }
}

impl<T> DIDUrl<T>
where
  T: DID + Sized,
{
  /// Construct a new [`DIDUrl`] with optional [`RelativeDIDUrl`].
  pub fn new(did: T, url: Option<RelativeDIDUrl>) -> Self {
    Self {
      did,
      url: url.unwrap_or_default(),
    }
  }

  /// Parse a [`DIDUrl`] from a string.
  pub fn parse(input: impl AsRef<str>) -> Result<Self, DIDError> {
    let did_url: BaseDIDUrl = BaseDIDUrl::parse(input)?;
    Self::from_base_did_url(did_url)
  }

  fn from_base_did_url(did_url: BaseDIDUrl) -> Result<Self, DIDError> {
    // Extract relative DID URL
    let url: RelativeDIDUrl = {
      let mut url: RelativeDIDUrl = RelativeDIDUrl::new();
      url.set_path(Some(did_url.path()))?;
      url.set_query(did_url.query())?;
      url.set_fragment(did_url.fragment())?;
      url
    };

    // Extract base DID
    let did: T = {
      let mut base_did: BaseDIDUrl = did_url;
      base_did.set_path("");
      base_did.set_query(None);
      base_did.set_fragment(None);
      T::try_from(base_did).map_err(|_| DIDError::Other("invalid DID"))?
    };

    Ok(Self { did, url })
  }

  /// Returns the [`did`][DID].
  pub fn did(&self) -> &T {
    &self.did
  }

  /// Returns the [`RelativeDIDUrl`].
  pub fn url(&self) -> &RelativeDIDUrl {
    &self.url
  }

  /// Sets the [`RelativeDIDUrl`].
  pub fn set_url(&mut self, url: RelativeDIDUrl) {
    self.url = url
  }

  /// Returns the [`DIDUrl`] `fragment` component.
  ///
  /// See [`RelativeDIDUrl::fragment`].
  pub fn fragment(&self) -> Option<&str> {
    self.url.fragment()
  }

  /// Sets the `fragment` component of the [`DIDUrl`].
  ///
  /// See [`RelativeDIDUrl::set_fragment`].
  pub fn set_fragment(&mut self, value: Option<&str>) -> Result<(), DIDError> {
    self.url.set_fragment(value)
  }

  /// Returns the [`DIDUrl`] `path` component.
  ///
  /// See [`RelativeDIDUrl::path`].
  pub fn path(&self) -> Option<&str> {
    self.url.path()
  }

  /// Sets the `path` component of the [`DIDUrl`].
  ///
  /// See [`RelativeDIDUrl::set_path`].
  pub fn set_path(&mut self, value: Option<&str>) -> Result<(), DIDError> {
    self.url.set_path(value)
  }

  /// Returns the [`DIDUrl`] `query` component.
  ///
  /// See [`RelativeDIDUrl::query`].
  pub fn query(&self) -> Option<&str> {
    self.url.query()
  }

  /// Sets the `query` component of the [`DIDUrl`].
  ///
  /// See [`RelativeDIDUrl::set_query`].
  pub fn set_query(&mut self, value: Option<&str>) -> Result<(), DIDError> {
    self.url.set_query(value)
  }

  /// Parses the [`DIDUrl`] query and returns an iterator of (key, value) pairs.
  ///
  /// See [`RelativeDIDUrl::query_pairs`].
  pub fn query_pairs(&self) -> form_urlencoded::Parse<'_> {
    self.url.query_pairs()
  }

  /// Append a string representing a `path`, `query`, and/or `fragment` to this [`DIDUrl`].
  ///
  /// Must begin with a valid delimiter character: '/', '?', '#'. Overwrites the existing URL
  /// segment and any following segments in order of path, query, then fragment.
  ///
  /// I.e.
  /// - joining a path will overwrite the path and clear the query and fragment.
  /// - joining a query will overwrite the query and clear the fragment.
  /// - joining a fragment will only overwrite the fragment.
  pub fn join(self, segment: impl AsRef<str>) -> Result<Self, DIDError> {
    let segment: &str = segment.as_ref();

    // Accept only a relative path, query, or fragment to reject altering the method id segment.
    if !segment.starts_with('/') && !segment.starts_with('?') && !segment.starts_with('#') {
      return Err(DIDError::InvalidPath);
    }

    // Parse DID Url.
    let base_did_url: BaseDIDUrl = BaseDIDUrl::parse(self.to_string())?.join(segment)?;
    Self::from_base_did_url(base_did_url)
  }

  /// Construct a [`DIDUrl<T>`] from a [`DIDUrl<U>`] of a different DID method.
  ///
  /// Workaround for lack of specialisation preventing a generic `From` implementation.
  pub fn from<U>(other: DIDUrl<U>) -> Self
  where
    U: DID + Into<T>,
  {
    let did: T = other.did.into();
    Self { did, url: other.url }
  }

  /// Attempt to construct a [`DIDUrl<T>`](DIDUrl) from a [`DIDUrl<U>`](DIDUrl) of a different
  /// DID method.
  ///
  /// Workaround for lack of specialisation preventing a generic `TryFrom` implementation.
  pub fn try_from<U>(other: DIDUrl<U>) -> Result<Self, <U as TryInto<T>>::Error>
  where
    U: DID + TryInto<T>,
  {
    let did: T = other.did.try_into()?;
    Ok(Self { did, url: other.url })
  }
}

impl<T> From<T> for DIDUrl<T>
where
  T: DID,
{
  fn from(did: T) -> Self {
    Self::new(did, None)
  }
}

impl<T> FromStr for DIDUrl<T>
where
  T: DID,
{
  type Err = DIDError;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    Self::parse(string)
  }
}

impl<T> TryFrom<String> for DIDUrl<T>
where
  T: DID,
{
  type Error = DIDError;

  fn try_from(other: String) -> Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl<T> From<DIDUrl<T>> for String
where
  T: DID,
{
  fn from(did_url: DIDUrl<T>) -> Self {
    did_url.to_string()
  }
}

impl<T> AsRef<T> for DIDUrl<T>
where
  T: DID,
{
  fn as_ref(&self) -> &T {
    &self.did
  }
}

impl<T: DID> AsRef<DIDUrl<T>> for DIDUrl<T> {
  fn as_ref(&self) -> &DIDUrl<T> {
    self
  }
}

impl<T> PartialEq for DIDUrl<T>
where
  T: DID,
{
  fn eq(&self, other: &Self) -> bool {
    self.did().eq(other.did()) && self.url() == other.url()
  }
}

impl<T> Eq for DIDUrl<T> where T: DID {}

impl<T> PartialOrd for DIDUrl<T>
where
  T: DID,
{
  #[inline]
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    match self.did().partial_cmp(other.did()) {
      None => None,
      Some(Ordering::Equal) => self.url().partial_cmp(other.url()),
      Some(ord) => Some(ord),
    }
  }
}

impl<T> Ord for DIDUrl<T>
where
  T: DID,
{
  #[inline]
  fn cmp(&self, other: &Self) -> Ordering {
    match self.did().cmp(other.did()) {
      Ordering::Equal => self.url().cmp(other.url()),
      ord => ord,
    }
  }
}

impl<T> Hash for DIDUrl<T>
where
  T: DID,
{
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_string().hash(state)
  }
}

impl<T> Debug for DIDUrl<T>
where
  T: DID,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{}", self))
  }
}

impl<T> Display for DIDUrl<T>
where
  T: DID,
{
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    f.write_fmt(format_args!("{}{}", self.did.as_str(), self.url))
  }
}

impl<T> Diff for DIDUrl<T>
where
  T: DID,
{
  type Type = DiffString;

  fn diff(&self, other: &Self) -> identity_core::diff::Result<Self::Type> {
    self.to_string().diff(&other.to_string())
  }

  fn merge(&self, diff: Self::Type) -> identity_core::diff::Result<Self> {
    self
      .to_string()
      .merge(diff)
      .and_then(|this| Self::parse(&this).map_err(identity_core::diff::Error::merge))
  }

  fn from_diff(diff: Self::Type) -> identity_core::diff::Result<Self> {
    String::from_diff(diff).and_then(|this| Self::parse(&this).map_err(identity_core::diff::Error::convert))
  }

  fn into_diff(self) -> identity_core::diff::Result<Self::Type> {
    self.to_string().into_diff()
  }
}

/// Checks whether a character satisfies DID Url path constraints.
#[inline(always)]
#[rustfmt::skip]
pub(crate) const fn is_char_path(ch: char) -> bool {
  // Allow percent encoding or not?
  is_char_method_id(ch) || matches!(ch, '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | '@' | '/' /* | '%' */)
}

/// Checks whether a character satisfies DID Url query constraints.
#[inline(always)]
pub(crate) const fn is_char_query(ch: char) -> bool {
  is_char_path(ch) || ch == '?'
}

/// Checks whether a character satisfies DID Url fragment constraints.
#[inline(always)]
pub(crate) const fn is_char_fragment(ch: char) -> bool {
  is_char_path(ch) || ch == '?'
}

#[cfg(test)]
mod tests {
  use super::*;

  #[rustfmt::skip]
  #[test]
  fn test_did_url_parse_valid() {
    let did_url = CoreDIDUrl::parse("did:example:1234567890").unwrap();
    assert_eq!(did_url.to_string(), "did:example:1234567890");
    assert!(did_url.url().is_empty());
    assert!(did_url.path().is_none());
    assert!(did_url.query().is_none());
    assert!(did_url.fragment().is_none());

    assert_eq!(CoreDIDUrl::parse("did:example:1234567890/path").unwrap().to_string(), "did:example:1234567890/path");
    assert_eq!(CoreDIDUrl::parse("did:example:1234567890?query").unwrap().to_string(), "did:example:1234567890?query");
    assert_eq!(CoreDIDUrl::parse("did:example:1234567890#fragment").unwrap().to_string(), "did:example:1234567890#fragment");

    assert_eq!(CoreDIDUrl::parse("did:example:1234567890/path?query").unwrap().to_string(), "did:example:1234567890/path?query");
    assert_eq!(CoreDIDUrl::parse("did:example:1234567890/path#fragment").unwrap().to_string(), "did:example:1234567890/path#fragment");
    assert_eq!(CoreDIDUrl::parse("did:example:1234567890?query#fragment").unwrap().to_string(), "did:example:1234567890?query#fragment");

    let did_url = CoreDIDUrl::parse("did:example:1234567890/path?query#fragment").unwrap();
    assert!(!did_url.url().is_empty());
    assert_eq!(did_url.to_string(), "did:example:1234567890/path?query#fragment");
    assert_eq!(did_url.path().unwrap(), "/path");
    assert_eq!(did_url.query().unwrap(), "query");
    assert_eq!(did_url.fragment().unwrap(), "fragment");
  }

  #[rustfmt::skip]
  #[test]
  fn test_join_valid() {
    let did_url = CoreDIDUrl::parse("did:example:1234567890").unwrap();
    assert_eq!(did_url.clone().join("/path").unwrap().to_string(), "did:example:1234567890/path");
    assert_eq!(did_url.clone().join("?query").unwrap().to_string(), "did:example:1234567890?query");
    assert_eq!(did_url.clone().join("#fragment").unwrap().to_string(), "did:example:1234567890#fragment");

    assert_eq!(did_url.clone().join("/path?query").unwrap().to_string(), "did:example:1234567890/path?query");
    assert_eq!(did_url.clone().join("/path#fragment").unwrap().to_string(), "did:example:1234567890/path#fragment");
    assert_eq!(did_url.clone().join("?query#fragment").unwrap().to_string(), "did:example:1234567890?query#fragment");

    let did_url = did_url.join("/path?query#fragment").unwrap();
    assert_eq!(did_url.to_string(), "did:example:1234567890/path?query#fragment");
    assert_eq!(did_url.path().unwrap(), "/path");
    assert_eq!(did_url.query().unwrap(), "query");
    assert_eq!(did_url.fragment().unwrap(), "fragment");
  }

  #[test]
  fn test_did_url_invalid() {
    assert!(CoreDIDUrl::parse("did:example:1234567890/invalid{path}").is_err());
    assert!(CoreDIDUrl::parse("did:example:1234567890?invalid{query}").is_err());
    assert!(CoreDIDUrl::parse("did:example:1234567890#invalid{fragment}").is_err());

    let did_url = CoreDIDUrl::parse("did:example:1234567890").unwrap();
    assert!(did_url.clone().join("noleadingdelimiter").is_err());
    assert!(did_url.clone().join("/invalid{path}").is_err());
    assert!(did_url.clone().join("?invalid{query}").is_err());
    assert!(did_url.join("#invalid{fragment}").is_err());
  }

  #[test]
  fn test_did_url_basic_comparisons() {
    let did_url1 = CoreDIDUrl::parse("did:example:1234567890").unwrap();
    let did_url1_copy = CoreDIDUrl::parse("did:example:1234567890").unwrap();
    assert_eq!(did_url1, did_url1_copy);

    let did_url2 = CoreDIDUrl::parse("did:example:0987654321").unwrap();
    assert_ne!(did_url1, did_url2);
    assert!(did_url1 > did_url2);

    let did_url3 = CoreDIDUrl::parse("did:fxample:1234567890").unwrap();
    assert_ne!(did_url1, did_url3);
    assert!(did_url1 < did_url3);

    let did_url4 = CoreDIDUrl::parse("did:example:1234567890/path").unwrap();
    assert_ne!(did_url1, did_url4);
    assert_ne!(did_url1.url(), did_url4.url());
    assert_eq!(did_url1.did(), did_url4.did());
    assert!(did_url1 < did_url4);

    let did_url5 = CoreDIDUrl::parse("did:example:1234567890/zero").unwrap();
    assert_ne!(did_url4, did_url5);
    assert_ne!(did_url4.url(), did_url5.url());
    assert_eq!(did_url4.did(), did_url5.did());
    assert!(did_url4 < did_url5);
  }

  #[test]
  fn test_path_valid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Simple path.
    assert!(relative_url.set_path(Some("/path")).is_ok());
    assert_eq!(relative_url.path().unwrap(), "/path");
    assert!(relative_url.set_path(Some("/path/sub-path/resource")).is_ok());
    assert_eq!(relative_url.path().unwrap(), "/path/sub-path/resource");

    // Empty path.
    assert!(relative_url.set_path(Some("")).is_ok());
    assert!(relative_url.path().is_none());
    assert!(relative_url.set_path(None).is_ok());
    assert!(relative_url.path().is_none());
  }

  #[rustfmt::skip]
  #[test]
  fn test_path_invalid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Invalid symbols.
    assert!(matches!(relative_url.set_path(Some("/white space")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/white\tspace")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/white\nspace")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path{invalid_brackets}")), Err(DIDError::InvalidPath)));

    // Missing leading '/'.
    assert!(matches!(relative_url.set_path(Some("path")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("p/")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("p/ath")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("path/")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("path/sub-path/")), Err(DIDError::InvalidPath)));

    // Reject query delimiter '?'.
    assert!(matches!(relative_url.set_path(Some("?query")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("some?query")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path?")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path?query")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path/query?")), Err(DIDError::InvalidPath)));

    // Reject fragment delimiter '#'.
    assert!(matches!(relative_url.set_path(Some("#fragment")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("some#fragment")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path#")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path#fragment")), Err(DIDError::InvalidPath)));
    assert!(matches!(relative_url.set_path(Some("/path/fragment#")), Err(DIDError::InvalidPath)));
  }

  #[test]
  fn test_query_valid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Empty query.
    assert!(relative_url.set_query(Some("")).is_ok());
    assert!(relative_url.query().is_none());

    // With leading '?'.
    assert!(relative_url.set_query(Some("?query")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "query");
    assert!(relative_url.set_query(Some("?name=value")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value");
    assert!(relative_url.set_query(Some("?name=value&name2=value2")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value&name2=value2");
    assert!(relative_url.set_query(Some("?name=value&name2=value2&3=true")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value&name2=value2&3=true");

    // Without leading '?'.
    assert!(relative_url.set_query(Some("query")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "query");
    assert!(relative_url.set_query(Some("name=value&name2=value2&3=true")).is_ok());
    assert_eq!(relative_url.query().unwrap(), "name=value&name2=value2&3=true");
  }

  #[rustfmt::skip]
  #[test]
  fn test_query_invalid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Delimiter-only.
    assert!(matches!(relative_url.set_query(Some("?")), Err(DIDError::InvalidQuery)));

    // Invalid symbols.
    assert!(matches!(relative_url.set_query(Some("?white space")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?white\tspace")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?white\nspace")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query{invalid_brackets}")), Err(DIDError::InvalidQuery)));

    // Reject fragment delimiter '#'.
    assert!(matches!(relative_url.set_query(Some("#fragment")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("some#fragment")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query#fragment")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=a#fragment")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=#fragment")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=frag#ment")), Err(DIDError::InvalidQuery)));
    assert!(matches!(relative_url.set_query(Some("?query=fragment#")), Err(DIDError::InvalidQuery)));
  }

  #[rustfmt::skip]
  #[test]
  fn test_fragment_valid() {
    let mut relative_url = RelativeDIDUrl::new();

    // With leading '#'.
    assert!(relative_url.set_fragment(Some("#fragment")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "fragment");
    assert!(relative_url.set_fragment(Some("#longer_fragment?and/other-delimiters:valid")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "longer_fragment?and/other-delimiters:valid");

    // Without leading '#'.
    assert!(relative_url.set_fragment(Some("fragment")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "fragment");
    assert!(relative_url.set_fragment(Some("longer_fragment?and/other-delimiters:valid")).is_ok());
    assert_eq!(relative_url.fragment().unwrap(), "longer_fragment?and/other-delimiters:valid");

    // Empty fragment.
    assert!(relative_url.set_fragment(Some("")).is_ok());
    assert!(relative_url.fragment().is_none());
    assert!(relative_url.set_fragment(None).is_ok());
    assert!(relative_url.fragment().is_none());
  }

  #[rustfmt::skip]
  #[test]
  fn test_fragment_invalid() {
    let mut relative_url = RelativeDIDUrl::new();

    // Delimiter only.
    assert!(matches!(relative_url.set_fragment(Some("#")), Err(DIDError::InvalidFragment)));

    // Invalid symbols.
    assert!(matches!(relative_url.set_fragment(Some("#white space")), Err(DIDError::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#white\tspace")), Err(DIDError::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#white\nspace")), Err(DIDError::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#fragment{invalid_brackets}")), Err(DIDError::InvalidFragment)));
    assert!(matches!(relative_url.set_fragment(Some("#fragment\"other\"")), Err(DIDError::InvalidFragment)));
  }

  proptest::proptest! {
    #[test]
    fn test_fuzz_join_no_panic(s in "\\PC*") {
      let did_url = CoreDIDUrl::parse("did:example:1234567890").unwrap();
      let _ = did_url.join(&s);
    }

    #[test]
    fn test_fuzz_path_no_panic(s in "\\PC*") {
      let mut url = RelativeDIDUrl::new();
      let _ = url.set_path(Some(&s));
    }

    #[test]
    fn test_fuzz_query_no_panic(s in "\\PC*") {
      let mut url = RelativeDIDUrl::new();
      let _ = url.set_query(Some(&s));
    }

    #[test]
    fn test_fuzz_fragment_no_panic(s in "\\PC*") {
      let mut url = RelativeDIDUrl::new();
      let _ = url.set_fragment(Some(&s));
    }
  }
}
