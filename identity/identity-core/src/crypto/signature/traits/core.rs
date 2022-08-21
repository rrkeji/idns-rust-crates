// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::crypto::SetSignature;
use crate::crypto::Signature;
use crate::crypto::SignatureValue;
use crate::crypto::TrySignature;
use crate::error::Error;
use crate::error::Result;

/// A common interface for digital signature creation.
pub trait Sign {
  /// The private key type of this signature implementation.
  type Private: ?Sized;

  /// The output type of this signature implementation.
  type Output;

  /// Signs the given `message` with `key` and returns a digital signature.
  fn sign(message: &[u8], key: &Self::Private) -> Result<Self::Output>;
}

// =============================================================================
// =============================================================================

/// A common interface for digital signature verification
pub trait Verify {
  /// The public key type of this signature implementation.
  type Public: ?Sized;

  /// Verifies the authenticity of `data` and `signature` with `key`.
  fn verify(message: &[u8], signature: &[u8], key: &Self::Public) -> Result<()>;
}

// =============================================================================
// =============================================================================

/// A common interface for named signature suites.
pub trait Named {
  /// A unique identifier for the signatures created by this suite.
  const NAME: &'static str;
}

// =============================================================================
// =============================================================================

/// A common interface for digital signature creation.
pub trait Signer<Secret: ?Sized>: Named {
  /// Signs the given `data` and returns a digital signature.
  fn sign<T>(data: &T, secret: &Secret) -> Result<SignatureValue>
  where
    T: Serialize;

  /// Creates and applies a [signature][`Signature`] to the given `data`.
  fn create_signature<T>(data: &mut T, method: impl Into<String>, secret: &Secret) -> Result<()>
  where
    T: Serialize + SetSignature,
  {
    data.set_signature(Signature::new(Self::NAME, method));

    let value: SignatureValue = Self::sign(&data, secret)?;
    let write: &mut Signature = data.try_signature_mut()?;

    write.set_value(value);

    Ok(())
  }
}

// =============================================================================
// =============================================================================

/// A common interface for digital signature verification
pub trait Verifier<Public: ?Sized>: Named {
  /// Verifies the authenticity of `data` and `signature`.
  fn verify<T>(data: &T, signature: &SignatureValue, public: &Public) -> Result<()>
  where
    T: Serialize;

  /// Extracts and verifies a [signature][`Signature`] from the given `data`.
  fn verify_signature<T>(data: &T, public: &Public) -> Result<()>
  where
    T: Serialize + TrySignature,
  {
    let signature: &Signature = data.try_signature()?;

    if signature.type_() != Self::NAME {
      return Err(Error::InvalidProofValue("signature name"));
    }

    signature.hide_value();

    Self::verify(&data, signature.value(), public)?;

    signature.show_value();

    Ok(())
  }
}
