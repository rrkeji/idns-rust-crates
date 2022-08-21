// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use core::marker::PhantomData;
use serde::Serialize;
use std::borrow::Cow;

use crate::convert::ToJson;
use crate::crypto::merkle_key::MerkleDigest;
use crate::crypto::merkle_key::MerkleKey;
use crate::crypto::merkle_key::MerkleSignature;
use crate::crypto::merkle_tree::Proof;
use crate::crypto::Named;
use crate::crypto::PrivateKey;
use crate::crypto::PublicKey;
use crate::crypto::Sign;
use crate::crypto::SignatureValue;
use crate::crypto::Signer;
use crate::error::Result;
use crate::utils::encode_b58;

/// Key components used to create a Merkle Key Collection signature.
#[derive(Clone)]
pub struct SigningKey<'key, D>
where
  D: MerkleDigest,
{
  public: &'key PublicKey,
  private: &'key PrivateKey,
  proof: Cow<'key, Proof<D>>,
}

impl<'key, D> SigningKey<'key, D>
where
  D: MerkleDigest,
{
  /// Creates a new [`SigningKey`] instance.
  pub fn new(public: &'key PublicKey, private: &'key PrivateKey, proof: Cow<'key, Proof<D>>) -> Self {
    Self { public, private, proof }
  }

  /// Creates a new [`SigningKey`] from a borrowed [`proof`][`Proof`].
  pub fn from_borrowed(public: &'key PublicKey, private: &'key PrivateKey, proof: &'key Proof<D>) -> Self {
    Self::new(public, private, Cow::Borrowed(proof))
  }

  /// Creates a new [`SigningKey`] from an owned [`proof`][`Proof`].
  pub fn from_owned(public: &'key PublicKey, private: &'key PrivateKey, proof: Proof<D>) -> Self {
    Self::new(public, private, Cow::Owned(proof))
  }
}

impl<'key, D, S> MerkleSigningKey<D, S> for SigningKey<'key, D>
where
  D: MerkleDigest,
  S: Sign,
  PrivateKey: AsRef<S::Private>,
{
  fn proof(&self) -> String {
    encode_b58(&self.proof.encode())
  }

  fn public(&self) -> String {
    encode_b58(self.public.as_ref())
  }

  fn private(&self) -> &S::Private {
    self.private.as_ref()
  }
}

// =============================================================================
// =============================================================================

/// A common interface for Merkle Key Collection signing keys.
pub trait MerkleSigningKey<D, S>
where
  D: MerkleDigest,
  S: Sign,
{
  /// Returns a Merkle proof of the signing key as a base58-encoded string.
  fn proof(&self) -> String;

  /// Returns the target public key as a base58-encoded string.
  fn public(&self) -> String;

  /// Returns a reference to the private key of the underlying
  /// [`signature`][`Sign`] implementation.
  fn private(&self) -> &S::Private;
}

// =============================================================================
// =============================================================================

/// A signature creation helper for Merkle Key Collection Signatures.
///
/// Users should use the [`Signer`] trait to access this
/// implementation.
#[derive(Clone)]
pub struct MerkleSigner<D, S>
where
  D: MerkleDigest,
  S: MerkleSignature,
{
  marker_d: PhantomData<D>,
  marker_s: PhantomData<S>,
}

impl<D, S> Named for MerkleSigner<D, S>
where
  D: MerkleDigest,
  S: MerkleSignature,
{
  const NAME: &'static str = MerkleKey::TYPE_SIG;
}

impl<D, S, K> Signer<K> for MerkleSigner<D, S>
where
  D: MerkleDigest,
  S: MerkleSignature + Sign,
  K: MerkleSigningKey<D, S>,
  S::Output: AsRef<[u8]>,
{
  fn sign<X>(data: &X, private: &K) -> Result<SignatureValue>
  where
    X: Serialize,
  {
    let message: Vec<u8> = data.to_jcs()?;
    let signature: S::Output = S::sign(&message, private.private())?;
    let signature: String = encode_b58(signature.as_ref());
    let formatted: String = format!("{}.{}.{}", private.public(), private.proof(), signature);

    Ok(SignatureValue::Signature(formatted))
  }
}
