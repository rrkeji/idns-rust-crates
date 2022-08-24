// Copyright 2020-2021 Runnerc Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;

use core::str::FromStr;
use std::convert::TryInto;

use crypto::hashes::blake2b::Blake2b256;
use crypto::hashes::Digest;
use serde;
use serde::Deserialize;
use serde::Serialize;

use identity_core::utils::decode_b58;
use identity_core::utils::encode_b58;
use identity_did::did::BaseDIDUrl;
use identity_did::did::CoreDID;
use identity_did::did::DIDError;
use identity_did::did::DIDUrl;
use identity_did::did::DID;

use crate::did::Segments;
use crate::error::Error;
use crate::error::Result;
use crate::runnerc::Network;
use crate::runnerc::NetworkName;
use crate::try_construct_did;

// The hash size of BLAKE2b-256 (32-bytes)
const BLAKE2B_256_LEN: usize = 32;

/// A DID URL conforming to the Runnerc DID method specification.
///
/// See [`DIDUrl`].
pub type RunnercDIDUrl = DIDUrl<RunnercDID>;

/// A DID conforming to the Runnerc DID method specification.
///
/// This is a thin wrapper around the [`DID`][`CoreDID`] type from the
/// [`identity_did`][`identity_did`] crate.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[repr(transparent)]
#[serde(into = "CoreDID", try_from = "CoreDID")]
pub struct RunnercDID(CoreDID);

// unsafe impl std::marker::Send for RunnercDID{}

impl RunnercDID {
  /// The URL scheme for Decentralized Identifiers.
  pub const SCHEME: &'static str = CoreDID::SCHEME;

  /// The Runnerc DID method name (`"Runnerc"`).
  pub const METHOD: &'static str = "runnerc";

  /// The default Tangle network (`"main"`).
  pub const DEFAULT_NETWORK: &'static str = "main";

  /// Converts a borrowed [`CoreDID`] to a borrowed [`RunnercDID`].
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  pub fn try_from_borrowed(did: &CoreDID) -> Result<&Self> {
    Self::check_validity(did)?;

    // SAFETY: we performed the necessary validation in `check_validity`.
    Ok(unsafe { Self::new_unchecked_ref(did) })
  }

  /// Converts an owned `DID` to an [`RunnercDID`].
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  pub fn try_from_owned(did: CoreDID) -> Result<Self> {
    Self::check_validity(&did)?;

    Ok(Self(Self::normalize(did)))
  }

  /// Converts a `DID` reference to an [`RunnercDID`] reference without performing
  /// validation checks.
  ///
  /// # Safety
  ///
  /// This must be guaranteed safe by the caller.
  pub unsafe fn new_unchecked_ref(did: &CoreDID) -> &Self {
    // SAFETY: This is guaranteed safe by the caller.
    &*(did as *const CoreDID as *const RunnercDID)
  }

  /// Parses an [`RunnercDID`] from the given `input`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  pub fn parse(input: impl AsRef<str>) -> Result<Self> {
    CoreDID::parse(input).map_err(Into::into).and_then(Self::try_from_owned)
  }

  /// Creates a new [`RunnercDID`] with a tag derived from the given `public` key.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input does not form a valid [`RunnercDID`].
  pub fn new(public: &[u8]) -> Result<Self> {
    try_construct_did!(public).map_err(Into::into)
  }

  /// Creates a new [`RunnercDID`] from the given `public` key and `network`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input does not form a valid [`RunnercDID`] or the `network` is invalid.
  /// See [`NetworkName`] for validation requirements.
  pub fn new_with_network(public: &[u8], network: impl TryInto<NetworkName>) -> Result<Self> {
    let network_name = network.try_into().map_err(|_| Error::InvalidNetworkName)?;
    try_construct_did!(public, network_name.as_ref()).map_err(Into::into)
  }

  /// Checks if the given `DID` has a valid Runnerc DID `method` (i.e. `"runnerc"`).
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  pub fn check_method(did: &CoreDID) -> Result<()> {
    if did.method() != Self::METHOD {
      Err(Error::InvalidDID(DIDError::InvalidMethodName))
    } else {
      Ok(())
    }
  }

  /// Checks if the given `DID` has a valid [`RunnercDID`] `method_id`.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  pub fn check_method_id(did: &CoreDID) -> Result<()> {
    let segments: Vec<&str> = did.method_id().split(':').collect();

    if segments.is_empty() || segments.len() > 3 {
      return Err(Error::InvalidDID(DIDError::InvalidMethodId));
    }

    // We checked if `id_segments` was empty so this should not panic
    let mid: &str = segments.last().unwrap();
    let len: usize = decode_b58(mid)?.len();

    if len == BLAKE2B_256_LEN {
      Ok(())
    } else {
      Err(Error::InvalidDID(DIDError::InvalidMethodId))
    }
  }

  /// Checks if the given `DID` has a valid [`RunnercDID`] network name, e.g. "main", "dev".
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  /// See [`NetworkName`] for validation requirements.
  pub fn check_network(did: &CoreDID) -> Result<()> {
    let network_name = Segments(did.method_id()).network();
    NetworkName::validate_network_name(network_name)
  }

  /// Checks if the given `DID` is valid according to the [`RunnercDID`] method specification.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the input is not a valid [`RunnercDID`].
  pub fn check_validity(did: &CoreDID) -> Result<()> {
    Self::check_method(did)?;
    Self::check_method_id(did)?;
    Self::check_network(did)?;

    Ok(())
  }

  /// Returns a `bool` indicating if the given `DID` is valid according to the
  /// [`RunnercDID`] method specification.
  pub fn is_valid(did: &CoreDID) -> bool {
    Self::check_validity(did).is_ok()
  }

  /// Returns the Tangle `network` of the `DID`, if it is valid.
  pub fn network(&self) -> Result<Network> {
    Network::try_from_name(self.network_str().to_owned())
  }

  /// Returns the Tangle `network` name of the `DID`.
  pub fn network_str(&self) -> &str {
    self.segments().network()
  }

  /// Returns the unique Tangle tag of the `DID`.
  pub fn tag(&self) -> &str {
    self.segments().tag()
  }

  #[doc(hidden)]
  pub fn segments(&self) -> Segments<'_> {
    Segments(self.method_id())
  }

  /// Normalizes the DID `method_id` by removing the default network segment if present.
  ///
  /// E.g.
  /// - `"did:idns:main:123" -> "did:idns:123"` is normalized
  /// - `"did:idns:dev:123" -> "did:idns:dev:123"` is unchanged
  fn normalize(mut did: CoreDID) -> CoreDID {
    let segments: Segments<'_> = Segments(did.method_id());

    if segments.count() == 2 && segments.network() == Self::DEFAULT_NETWORK {
      let method_id: String = segments.tag().to_string();
      let _ = did
        .set_method_id(method_id)
        .expect("this method_id is from a valid did");
    }

    did
  }

  // Note: Must be `pub` for the `did` macro.
  #[doc(hidden)]
  pub fn encode_key(key: &[u8]) -> String {
    encode_b58(&Blake2b256::digest(key))
  }
}

impl DID for RunnercDID {
  /// Returns the [`RunnercDID`] scheme. See [`DID::SCHEME`].
  fn scheme(&self) -> &'static str {
    self.0.scheme()
  }

  /// Returns the [`RunnercDID`] authority.
  fn authority(&self) -> &str {
    self.0.authority()
  }

  /// Returns the [`RunnercDID`] method name.
  fn method(&self) -> &str {
    self.0.method()
  }

  /// Returns the [`RunnercDID`] method-specific ID.
  fn method_id(&self) -> &str {
    self.0.method_id()
  }

  /// Returns the serialized [`RunnercDID`].
  ///
  /// This is fast since the serialized value is stored in the [`DID`].
  fn as_str(&self) -> &str {
    self.0.as_str()
  }

  /// Consumes the [`RunnercDID`] and returns the serialization.
  fn into_string(self) -> String {
    self.0.into_string()
  }

  /// Creates a new [`RunnercDIDUrl`] by joining with a relative DID Url string.
  ///
  /// # Errors
  ///
  /// Returns `Err` if any base or relative DID segments are invalid.
  fn join(self, segment: impl AsRef<str>) -> std::result::Result<DIDUrl<Self>, DIDError> {
    self.into_url().join(segment)
  }

  fn to_url(&self) -> DIDUrl<Self> {
    DIDUrl::new(self.clone(), None)
  }

  fn into_url(self) -> DIDUrl<Self> {
    DIDUrl::new(self, None)
  }
}

impl Display for RunnercDID {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl Debug for RunnercDID {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}", self.0)
  }
}

impl AsRef<CoreDID> for RunnercDID {
  fn as_ref(&self) -> &CoreDID {
    &self.0
  }
}

impl From<RunnercDID> for CoreDID {
  fn from(other: RunnercDID) -> Self {
    other.0
  }
}

impl TryFrom<BaseDIDUrl> for RunnercDID {
  type Error = Error;

  fn try_from(other: BaseDIDUrl) -> Result<Self, Self::Error> {
    let core_did: CoreDID = CoreDID::try_from(other)?;
    Self::try_from(core_did)
  }
}

impl TryFrom<CoreDID> for RunnercDID {
  type Error = Error;

  fn try_from(other: CoreDID) -> Result<Self, Self::Error> {
    Self::try_from_owned(other)
  }
}

impl<'a> TryFrom<&'a CoreDID> for &'a RunnercDID {
  type Error = Error;

  fn try_from(other: &'a CoreDID) -> Result<Self, Self::Error> {
    RunnercDID::try_from_borrowed(other)
  }
}

impl FromStr for RunnercDID {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    Self::parse(string)
  }
}

impl TryFrom<&str> for RunnercDID {
  type Error = Error;

  fn try_from(other: &str) -> Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl TryFrom<String> for RunnercDID {
  type Error = Error;

  fn try_from(other: String) -> Result<Self, Self::Error> {
    Self::parse(other)
  }
}

impl From<RunnercDID> for String {
  fn from(did: RunnercDID) -> Self {
    did.into_string()
  }
}

#[cfg(test)]
mod tests {
  use identity_core::crypto::KeyPair;
  use identity_did::did::CoreDID;
  use identity_did::did::DID;

  use crate::did::RunnercDID;
  use crate::did::RunnercDIDUrl;

  const TAG: &str = "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV";

  #[test]
  fn test_parse_did_valid() {
    assert!(RunnercDID::parse(format!("did:idns:{}", TAG)).is_ok());
    assert!(RunnercDID::parse(format!("did:idns:main:{}", TAG)).is_ok());
    assert!(RunnercDID::parse(format!("did:idns:dev:{}", TAG)).is_ok());
    assert!(RunnercDID::parse(format!("did:idns:custom:{}", TAG)).is_ok());
  }

  #[test]
  fn test_parse_did_url_valid() {
    assert!(RunnercDIDUrl::parse(format!("did:idns:{}", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:{}#fragment", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:{}?somequery=somevalue", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:{}?somequery=somevalue#fragment", TAG)).is_ok());

    assert!(RunnercDIDUrl::parse(format!("did:idns:main:{}", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:main:{}#fragment", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:main:{}?somequery=somevalue", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:main:{}?somequery=somevalue#fragment", TAG)).is_ok());

    assert!(RunnercDIDUrl::parse(format!("did:idns:dev:{}", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:dev:{}#fragment", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:dev:{}?somequery=somevalue", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:dev:{}?somequery=somevalue#fragment", TAG)).is_ok());

    assert!(RunnercDIDUrl::parse(format!("did:idns:custom:{}", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:custom:{}#fragment", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:custom:{}?somequery=somevalue", TAG)).is_ok());
    assert!(RunnercDIDUrl::parse(format!("did:idns:custom:{}?somequery=somevalue#fragment", TAG)).is_ok());
  }

  #[test]
  fn test_parse_did_invalid() {
    // A non-"runnerc" DID method is invalid.
    assert!(RunnercDID::parse("did:foo::").is_err());
    // An empty DID method is invalid.
    assert!(RunnercDID::parse("did:::").is_err());
    assert!(RunnercDID::parse(format!("did::main:{}", TAG)).is_err());
    // A non-"runnerc" DID method is invalid.
    assert!(RunnercDID::parse("did:idns---::").is_err());
    // An empty `runnerc-specific-idstring` is invalid.
    assert!(RunnercDID::parse("did:idns:").is_err());
    // Too many components is invalid.
    assert!(RunnercDID::parse(format!("did:idns:custom:shard-1:random:{}", TAG)).is_err());
    // Explicit empty network name is invalid (omitting it is still fine)
    assert!(RunnercDID::parse(format!("did:idns::{}", TAG)).is_err());
    // Invalid network name is invalid.
    assert!(RunnercDID::parse(format!("did:idns:Invalid-Network:{}", TAG)).is_err());
  }

  #[test]
  fn test_from_did() {
    let key: String = RunnercDID::encode_key(b"123");

    let did: CoreDID = format!("did:idns:{}", key).parse().unwrap();
    let iota_did = RunnercDID::try_from_owned(did).unwrap();
    assert_eq!(iota_did.network_str(), "main");
    assert_eq!(iota_did.tag(), key);

    let did: CoreDID = "did:idns:123".parse().unwrap();
    assert!(RunnercDID::try_from_owned(did).is_err());

    let did: CoreDID = format!("did:web:{}", key).parse().unwrap();
    assert!(RunnercDID::try_from_owned(did).is_err());
  }

  #[test]
  fn test_network() {
    let key: String = RunnercDID::encode_key(b"123");

    let did: RunnercDID = format!("did:idns:{}", key).parse().unwrap();
    assert_eq!(did.network_str(), "main");

    let did: RunnercDID = format!("did:idns:dev:{}", key).parse().unwrap();
    assert_eq!(did.network_str(), "dev");

    let did: RunnercDID = format!("did:idns:test:{}", key).parse().unwrap();
    assert_eq!(did.network_str(), "test");

    let did: RunnercDID = format!("did:idns:custom:{}", key).parse().unwrap();
    assert_eq!(did.network_str(), "custom");
  }

  #[test]
  fn test_tag() {
    let did: RunnercDID = format!("did:idns:{}", TAG).parse().unwrap();
    assert_eq!(did.tag(), TAG);

    let did: RunnercDID = format!("did:idns:main:{}", TAG).parse().unwrap();
    assert_eq!(did.tag(), TAG);
  }

  #[test]
  fn test_new() {
    let key: KeyPair = KeyPair::new_ed25519().unwrap();
    let tag: String = RunnercDID::encode_key(key.public().as_ref());

    let did: RunnercDID = RunnercDID::new(key.public().as_ref()).unwrap();
    assert_eq!(did.tag(), tag);
    assert_eq!(did.network_str(), RunnercDID::DEFAULT_NETWORK);
  }

  #[test]
  fn test_new_with_network() {
    let key: KeyPair = KeyPair::new_ed25519().unwrap();
    let did: RunnercDID = RunnercDID::new_with_network(key.public().as_ref(), "foo").unwrap();
    let tag: String = RunnercDID::encode_key(key.public().as_ref());

    assert_eq!(did.tag(), tag);
    assert_eq!(did.network_str(), "foo");
  }

  #[test]
  fn test_normalize() {
    let key: KeyPair = KeyPair::new_ed25519().unwrap();
    let tag: String = RunnercDID::encode_key(key.public().as_ref());

    // An RunnercDID with "main" as the network can be normalized ("main" removed)
    let did1: RunnercDID = format!("did:idns:{}", tag).parse().unwrap();
    let did2: RunnercDID = format!("did:idns:main:{}", tag).parse().unwrap();
    assert_eq!(did1, did2);
  }

  #[test]
  fn test_setter() {
    let key: KeyPair = KeyPair::new_ed25519().unwrap();
    let did: RunnercDID = RunnercDID::new(key.public().as_ref()).unwrap();
    let mut did_url: RunnercDIDUrl = did.into_url();

    did_url.set_path(Some("/foo")).unwrap();
    did_url.set_query(Some("diff=true")).unwrap();
    did_url.set_fragment(Some("foo")).unwrap();

    assert_eq!(did_url.path(), Some("/foo"));
    assert_eq!(did_url.query(), Some("diff=true"));
    assert_eq!(did_url.fragment(), Some("foo"));
  }
}
