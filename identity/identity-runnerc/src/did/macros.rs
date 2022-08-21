// Copyright 2020-2021 Runnerc Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Creates a new IOTA DID from a `public` key and optional `network`.
///
/// # Errors
///
/// Errors if the [`RunnercDID`][crate::did::RunnercDID] is invalid.
///
/// # Example
///
/// ```
/// # use identity_did::did::DID;
/// # use identity_iota::try_construct_did;
/// #
/// let did = try_construct_did!(b"public-key")?;
/// assert_eq!(did.as_str(), "did:iota:2xQiiGHDq5gCi1H7utY1ni7cf65fTay3G11S4xKp1vkS");
///
/// let did = try_construct_did!(b"public-key", "com")?;
/// assert_eq!(
///   did.as_str(),
///   "did:runnerc:com:2xQiiGHDq5gCi1H7utY1ni7cf65fTay3G11S4xKp1vkS"
/// );
/// # Ok::<(), identity_iota::Error>(())
/// ```
#[macro_export]
macro_rules! try_construct_did {
  // Defining explicit branches rather than `$($tt:tt)+` gives much better docs.
  ($public:expr, $network:expr) => {
    $crate::did::RunnercDID::parse(format!(
      "{}:{}:{}:{}",
      $crate::did::RunnercDID::SCHEME,
      $crate::did::RunnercDID::METHOD,
      $network,
      $crate::did::RunnercDID::encode_key($public),
    ))
  };
  ($public:expr) => {
    $crate::did::RunnercDID::parse(format!(
      "{}:{}:{}",
      $crate::did::RunnercDID::SCHEME,
      $crate::did::RunnercDID::METHOD,
      $crate::did::RunnercDID::encode_key($public),
    ))
  };
}
