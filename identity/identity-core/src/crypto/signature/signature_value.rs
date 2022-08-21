// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::fmt::Debug;
use core::fmt::Formatter;
use core::fmt::Result;

/// A DID Document signature with a dynamic JSON field name.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum SignatureValue {
  /// An empty signature value.
  #[serde(skip)]
  None,
  /// A signature value with the property name `jws`.
  #[serde(rename = "jws")]
  Jws(String),
  /// A signature value with the property name `proofValue`.
  #[serde(rename = "proofValue")]
  Proof(String),
  /// A signature value with the property name `signatureValue`.
  #[serde(rename = "signatureValue")]
  Signature(String),
}

impl SignatureValue {
  /// Returns `true` if the signature data is a `None` type.
  pub const fn is_none(&self) -> bool {
    matches!(self, Self::None)
  }

  /// Returns `true` if the signature data is a `Jws` type.
  pub const fn is_jws(&self) -> bool {
    matches!(self, Self::Jws(_))
  }

  /// Returns `true` if the signature data is a `Proof` type.
  pub const fn is_proof(&self) -> bool {
    matches!(self, Self::Proof(_))
  }

  /// Returns `true` if the signature data is a `Signature` type.
  pub const fn is_signature(&self) -> bool {
    matches!(self, Self::Signature(_))
  }

  /// Returns the signature data as a string slice.
  pub fn as_str(&self) -> &str {
    match self {
      Self::None => "",
      Self::Jws(inner) => &*inner,
      Self::Proof(inner) => &*inner,
      Self::Signature(inner) => &*inner,
    }
  }

  /// Consumes the [`SignatureValue`] and returns the data as a [`String`].
  pub fn into_string(self) -> String {
    match self {
      Self::None => String::new(),
      Self::Jws(inner) => inner,
      Self::Proof(inner) => inner,
      Self::Signature(inner) => inner,
    }
  }

  /// Returns the `Jws` type signature data as a string slice.
  pub fn as_jws(&self) -> Option<&str> {
    match self {
      Self::Jws(inner) => Some(&*inner),
      _ => None,
    }
  }

  /// Returns the `Proof` type signature data as a string slice.
  pub fn as_proof(&self) -> Option<&str> {
    match self {
      Self::Proof(inner) => Some(&*inner),
      _ => None,
    }
  }

  /// Returns the `Signature` type signature data as a string slice.
  pub fn as_signature(&self) -> Option<&str> {
    match self {
      Self::Signature(inner) => Some(&*inner),
      _ => None,
    }
  }
}

impl Debug for SignatureValue {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    match self {
      Self::None => f.write_str("None"),
      Self::Jws(inner) => f.write_fmt(format_args!("Jws({})", inner)),
      Self::Proof(inner) => f.write_fmt(format_args!("Proof({})", inner)),
      Self::Signature(inner) => f.write_fmt(format_args!("Signature({})", inner)),
    }
  }
}
