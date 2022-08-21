// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported types for the JSON Web Key `typ` property.
///
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-types)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum JwkType {
  /// Elliptic Curve.
  #[serde(rename = "EC")]
  Ec,
  /// RSA.
  #[serde(rename = "RSA")]
  Rsa,
  /// Octet sequence.
  #[serde(rename = "oct")]
  Oct,
  /// Octet string key pairs.
  #[serde(rename = "OKP")]
  Okp,
}

impl JwkType {
  /// Returns the JWK "typ" as a `str` slice.
  pub const fn name(self) -> &'static str {
    match self {
      Self::Ec => "EC",
      Self::Rsa => "RSA",
      Self::Oct => "oct",
      Self::Okp => "OKP",
    }
  }
}

impl Display for JwkType {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
