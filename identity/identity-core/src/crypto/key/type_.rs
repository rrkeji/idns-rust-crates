// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

use crate::crypto::merkle_key::MerkleDigest;
use crate::crypto::merkle_key::MerkleKey;
use crate::crypto::merkle_tree::Hash;
use crate::crypto::Ed25519;
use crate::error::Error;
use crate::error::Result;

/// Supported cryptographic key types.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum KeyType {
  /// Identifies an `Ed25519` public/private key.
  #[serde(rename = "ed25519")]
  Ed25519,
}

impl KeyType {
  /// Returns the [`KeyType`] name as a static `str`.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Ed25519 => "ed25519",
    }
  }

  /// Creates a DID Document public key value for the given Merkle `root`.
  pub fn encode_merkle_key<D>(&self, root: &Hash<D>) -> Vec<u8>
  where
    D: MerkleDigest,
  {
    match self {
      Self::Ed25519 => MerkleKey::encode_key::<D, Ed25519>(root),
    }
  }
}

impl FromStr for KeyType {
  type Err = Error;

  fn from_str(string: &str) -> Result<Self, Self::Err> {
    if string.eq_ignore_ascii_case("ed25519") {
      Ok(Self::Ed25519)
    } else {
      Err(Error::InvalidKeyFormat)
    }
  }
}
