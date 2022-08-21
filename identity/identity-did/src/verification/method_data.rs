// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Formatter;

use identity_core::common::Object;
use identity_core::utils::decode_b58;
use identity_core::utils::decode_multibase;
use identity_core::utils::encode_b58;
use identity_core::utils::encode_multibase;

use crate::error::Error;
use crate::error::Result;

/// Supported verification method data formats.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MethodData {
  PublicKeyMultibase(String),
  PublicKeyBase58(String),
  PublicKeyJwk(Object),
}

impl MethodData {
  /// Creates a new `MethodData` variant with base58-encoded content.
  pub fn new_b58(data: impl AsRef<[u8]>) -> Self {
    Self::PublicKeyBase58(encode_b58(&data))
  }

  /// Creates a new `MethodData` variant with [Multibase]-encoded content.
  ///
  /// [Multibase]: https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
  pub fn new_multibase(data: impl AsRef<[u8]>) -> Self {
    Self::PublicKeyMultibase(encode_multibase(&data, None))
  }

  /// Returns a `Vec<u8>` containing the decoded bytes of the `MethodData`.
  ///
  /// This is generally a public key identified by a `MethodType` value.
  ///
  /// # Errors
  ///
  /// Decoding can fail if `MethodData` has invalid content or cannot be
  /// represented as a vector of bytes.
  pub fn try_decode(&self) -> Result<Vec<u8>> {
    match self {
      Self::PublicKeyMultibase(input) => decode_multibase(input).map_err(|_| Error::InvalidKeyDataMultibase),
      Self::PublicKeyBase58(input) => decode_b58(input).map_err(|_| Error::InvalidKeyDataBase58),
      Self::PublicKeyJwk(_) => Err(Error::InvalidKeyData),
    }
  }
}

impl Debug for MethodData {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::PublicKeyMultibase(inner) => f.write_fmt(format_args!("PublicKeyMultibase({})", inner)),
      Self::PublicKeyBase58(inner) => f.write_fmt(format_args!("PublicKeyBase58({})", inner)),
      Self::PublicKeyJwk(inner) => f.debug_tuple("PublicKeyJwk").field(inner).finish(),
    }
  }
}
