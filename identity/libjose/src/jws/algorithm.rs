// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported algorithms for the JSON Web Signatures `alg` claim.
///
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum JwsAlgorithm {
  /// HMAC using SHA-256
  HS256,
  /// HMAC using SHA-384
  HS384,
  /// HMAC using SHA-512
  HS512,
  /// RSASSA-PKCS1-v1_5 using SHA-256
  RS256,
  /// RSASSA-PKCS1-v1_5 using SHA-384
  RS384,
  /// RSASSA-PKCS1-v1_5 using SHA-512
  RS512,
  /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  PS256,
  /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  PS384,
  /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  PS512,
  /// ECDSA using P-256 and SHA-256
  ES256,
  /// ECDSA using P-384 and SHA-384
  ES384,
  /// ECDSA using P-521 and SHA-512
  ES512,
  /// ECDSA using secp256k1 curve and SHA-256
  ES256K,
  #[serde(rename = "none")]
  /// No digital signature or MAC performed
  NONE,
  /// EdDSA signature algorithms
  EdDSA,
}

impl JwsAlgorithm {
  pub const ALL: &'static [Self] = &[
    Self::HS256,
    Self::HS384,
    Self::HS512,
    Self::RS256,
    Self::RS384,
    Self::RS512,
    Self::PS256,
    Self::PS384,
    Self::PS512,
    Self::ES256,
    Self::ES384, // unsupported
    Self::ES512, // unsupported
    Self::ES256K,
    Self::NONE, // unsupported
    Self::EdDSA,
  ];

  /// Returns the JWS algorithm as a `str` slice.
  pub const fn name(self) -> &'static str {
    match self {
      Self::HS256 => "HS256",
      Self::HS384 => "HS384",
      Self::HS512 => "HS512",
      Self::RS256 => "RS256",
      Self::RS384 => "RS384",
      Self::RS512 => "RS512",
      Self::PS256 => "PS256",
      Self::PS384 => "PS384",
      Self::PS512 => "PS512",
      Self::ES256 => "ES256",
      Self::ES384 => "ES384",
      Self::ES512 => "ES512",
      Self::ES256K => "ES256K",
      Self::NONE => "none",
      Self::EdDSA => "EdDSA",
    }
  }
}

impl Display for JwsAlgorithm {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
