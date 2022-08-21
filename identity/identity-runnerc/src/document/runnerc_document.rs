// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::convert::TryFrom;
use core::convert::TryInto;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;

use serde;
use serde::Deserialize;
use serde::Serialize;

use identity_core::common::Object;
use identity_core::common::Timestamp;
use identity_core::common::Url;
use identity_core::convert::SerdeInto;
use identity_core::crypto::Ed25519;
use identity_core::crypto::JcsEd25519;
use identity_core::crypto::KeyPair;
use identity_core::crypto::PrivateKey;
use identity_core::crypto::PublicKey;
use identity_core::crypto::SetSignature;
use identity_core::crypto::Signature;
use identity_core::crypto::Signer;
use identity_core::crypto::TrySignature;
use identity_core::crypto::TrySignatureMut;
use identity_core::crypto::Verifier;
use identity_did::did::CoreDIDUrl;
use identity_did::did::DID;
use identity_did::document::CoreDocument;
use identity_did::service::Service;
use identity_did::utils::OrderedSet;
use identity_did::verifiable::DocumentSigner;
use identity_did::verifiable::DocumentVerifier;
use identity_did::verifiable::Properties as VerifiableProperties;
use identity_did::verification::MethodQuery;
use identity_did::verification::MethodRef;
use identity_did::verification::MethodRelationship;
use identity_did::verification::MethodScope;
use identity_did::verification::MethodType;
use identity_did::verification::MethodUriType;
use identity_did::verification::TryMethod;
use identity_did::verification::VerificationMethod;

use crate::did::RunnercDID;
use crate::did::RunnercDIDUrl;
use crate::document::DiffMessage;
use crate::document::Properties as BaseProperties;
use crate::document::RunnercVerificationMethod;
use crate::error::Error;
use crate::error::Result;
use crate::runnerc::MessageId;
use crate::runnerc::MessageIdExt;
use crate::runnerc::NetworkName;
use crate::runnerc::TangleRef;

type Properties = VerifiableProperties<BaseProperties>;
type BaseDocument = CoreDocument<Properties, Object, Object>;

pub type RunnercDocumentSigner<'a, 'b, 'c> = DocumentSigner<'a, 'b, 'c, Properties, Object, Object>;
pub type RunnercDocumentVerifier<'a> = DocumentVerifier<'a, Properties, Object, Object>;

/// A DID Document adhering to the IOTA DID method specification.
///
/// This is a thin wrapper around [`CoreDocument`].
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "CoreDocument", into = "BaseDocument")]
pub struct RunnercDocument {
  document: BaseDocument,
  message_id: MessageId,
}

// unsafe impl std::marker::Send for RunnercDocument{}

impl TryMethod for RunnercDocument {
  const TYPE: MethodUriType = MethodUriType::Absolute;
}

impl RunnercDocument {
  pub const DEFAULT_METHOD_FRAGMENT: &'static str = "sign-0";

  /// Creates a new DID Document from the given [`KeyPair`].
  ///
  /// The DID Document will be pre-populated with a single verification method
  /// derived from the provided [`KeyPair`] embedded as a capability invocation
  /// verification relationship. This method will have the DID URL fragment
  /// `#sign-0` and can be easily retrieved with [`RunnercDocument::default_signing_method`].
  ///
  /// NOTE: the generated document is unsigned, see [`RunnercDocument::sign_self`].
  ///
  /// Example:
  ///
  /// ```
  /// # use identity_core::crypto::KeyPair;
  /// # use identity_iota::document::RunnercDocument;
  /// #
  /// // Create a DID Document from a new Ed25519 keypair.
  /// let keypair = KeyPair::new_ed25519().unwrap();
  /// let document = RunnercDocument::new(&keypair).unwrap();
  /// ```
  pub fn new(keypair: &KeyPair) -> Result<Self> {
    Self::new_with_options(keypair, None, None)
  }

  /// Creates a new DID Document from the given [`KeyPair`], network, and verification method
  /// fragment name.
  ///
  /// See [`RunnercDocument::new`].
  ///
  /// Arguments:
  ///
  /// * keypair: the initial verification method is derived from the public key of this [`KeyPair`].
  /// * network: Tangle network to use for the DID; default [`Network::Mainnet`](crate::runnerc::Network::Mainnet).
  /// * fragment: name of the initial verification method; default [`DEFAULT_METHOD_FRAGMENT`].
  ///
  /// Example:
  ///
  /// ```
  /// # use identity_core::crypto::KeyPair;
  /// # use identity_iota::document::RunnercDocument;
  /// # use identity_iota::runnerc::Network;
  /// #
  /// // Create a new DID Document for the devnet from a new Ed25519 keypair.
  /// let keypair = KeyPair::new_ed25519().unwrap();
  /// let document = RunnercDocument::new_with_options(&keypair, Some(Network::Devnet.name()), Some("auth-key")).unwrap();
  /// assert_eq!(document.id().network_str(), "dev");
  /// assert_eq!(
  ///   document.default_signing_method().unwrap().try_into_fragment().unwrap(),
  ///   "#auth-key"
  /// );
  /// ```
  pub fn new_with_options(keypair: &KeyPair, network: Option<NetworkName>, fragment: Option<&str>) -> Result<Self> {
    let public_key: &PublicKey = keypair.public();

    let did: RunnercDID = if let Some(network_name) = network {
      RunnercDID::new_with_network(public_key.as_ref(), network_name)?
    } else {
      RunnercDID::new(public_key.as_ref())?
    };

    let method: RunnercVerificationMethod = RunnercVerificationMethod::from_did(
      did,
      keypair.type_(),
      keypair.public(),
      fragment.unwrap_or(Self::DEFAULT_METHOD_FRAGMENT),
    )?;

    Self::from_verification_method(method)
  }

  /// Creates a new DID Document from the given [`RunnercVerificationMethod`], inserting it as the
  /// default capability invocation method.
  ///
  /// NOTE: the generated document is unsigned, see [`RunnercDocument::sign_self`].
  pub fn from_verification_method(method: RunnercVerificationMethod) -> Result<Self> {
    Self::check_signing_method(&method)?;
    CoreDocument::builder(Default::default())
      .id(method.id_core().did().clone())
      .capability_invocation(MethodRef::Embed(method.into()))
      .build()
      .map(CoreDocument::into_verifiable)
      .map(TryInto::try_into)?
  }

  /// Converts a generic DID [`CoreDocument`] to an IOTA DID Document.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the document is not a valid IOTA DID Document.
  pub fn try_from_core(document: CoreDocument) -> Result<Self> {
    RunnercDocument::validate_core_document(&document)?;

    Ok(Self {
      document: document.serde_into()?,
      message_id: MessageId::new(String::from(document.id().as_str())),
    })
  }

  /// Converts a generic DID [`Document`](BaseDocument) to an IOTA DID Document.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the document is not a valid IOTA DID Document.
  pub fn try_from_base(document: BaseDocument) -> Result<Self> {
    RunnercDocument::validate_core_document(&document)?;

    Ok(Self {
      document: document.serde_into()?,
      message_id: MessageId::new(String::from(document.id().as_str())),
    })
  }

  /// Performs validation that a [`CoreDocument`] adheres to the IOTA spec.
  ///
  /// # Errors
  ///
  /// Returns `Err` if the document is not a valid IOTA DID Document.
  fn validate_core_document<T, U, V>(document: &CoreDocument<T, U, V>) -> Result<()> {
    // Validate that the DID conforms to the RunnercDID specification.
    // This check is required to ensure the correctness of the `RunnercDocument::id()` method which
    // creates an `RunnercDID::new_unchecked_ref()` from the underlying DID.
    let _ = RunnercDID::try_from_borrowed(document.id())?;

    // Validate that the document controller (if any) conforms to the RunnercDID specification.
    // This check is required to ensure the correctness of the `RunnercDocument::controller()` method
    // which creates an `RunnercDID::new_unchecked_ref()` from the underlying controller.
    document.controller().map_or(Ok(()), RunnercDID::check_validity)?;

    // Validate that the verification methods conform to the RunnercDID specification.
    // This check is required to ensure the correctness of the
    // - `RunnercDocument::methods()`,
    // - `RunnercDocument::resolve_method()`,
    // - `RunnercDocument::try_resolve_method()`,
    // - `RunnercDocument::resolve_method_mut()`,
    // - `RunnercDocument::try_resolve_method_mut()`,
    // methods which create an `RunnercDID::new_unchecked_ref()` from the underlying controller.
    //
    // We check `document.verification_method()` and `document.verification_relationships()`
    // separately because they have separate types.
    for verification_method in document.verification_method().iter() {
      RunnercVerificationMethod::check_validity(&*verification_method)?;
    }
    for method_ref in document.verification_relationships() {
      match method_ref {
        MethodRef::Embed(method) => RunnercVerificationMethod::check_validity(method)?,
        MethodRef::Refer(did_url) => RunnercDID::check_validity(did_url.did())?,
      }
    }

    Ok(())
  }

  /// Validates whether the verification method is a valid [`RunnercVerificationMethod`] and that
  /// its key type is allowed to sign document updates.
  fn check_signing_method<T>(method: &VerificationMethod<T>) -> Result<()> {
    RunnercVerificationMethod::check_validity(method)?;

    // Ensure the verification method type is supported
    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {}
      MethodType::MerkleKeyCollection2021 => return Err(Error::InvalidDocumentSigningMethodType),
    }

    Ok(())
  }

  /// Returns a reference to the underlying [`CoreDocument`].
  pub fn as_document(&self) -> &BaseDocument {
    &self.document
  }

  /// Returns a mutable reference to the underlying [`CoreDocument`].
  ///
  /// # Safety
  ///
  /// This function is unsafe because it does not check that modifications
  /// made to the [`CoreDocument`] maintain a valid IOTA DID Document.
  ///
  /// If this constraint is violated, it may cause issues with future uses of
  /// the DID Document.
  pub unsafe fn as_document_mut(&mut self) -> &mut BaseDocument {
    &mut self.document
  }

  // ===========================================================================
  // Properties
  // ===========================================================================

  /// Returns the DID document [`id`](RunnercDID).
  pub fn id(&self) -> &RunnercDID {
    // SAFETY: We checked the validity of the DID Document ID in the
    // DID Document constructors; we don't provide mutable references so
    // the value cannot change with typical "safe" Rust.
    unsafe { RunnercDID::new_unchecked_ref(self.document.id()) }
  }

  /// Returns a reference to the `RunnercDocument` controller.
  pub fn controller(&self) -> Option<&RunnercDID> {
    // SAFETY: Validity of controller checked in DID Document constructors.
    unsafe { self.document.controller().map(|did| RunnercDID::new_unchecked_ref(did)) }
  }

  /// Returns a reference to the [`CoreDocument`] alsoKnownAs set.
  pub fn also_known_as(&self) -> &[Url] {
    self.document.also_known_as()
  }

  /// Returns the first [`RunnercVerificationMethod`] with a capability invocation relationship
  /// capable of signing this DID document.
  pub fn default_signing_method(&self) -> Result<&RunnercVerificationMethod> {
    self
      .as_document()
      .capability_invocation()
      .head()
      .map(|method_ref| self.as_document().resolve_method_ref(method_ref))
      .flatten()
      .map(|method: &VerificationMethod<_>|
        // SAFETY: validity of methods checked in `RunnercVerificationMethod::check_validity`.
        unsafe { RunnercVerificationMethod::new_unchecked_ref(method) })
      .ok_or(Error::MissingSigningKey)
  }

  /// Returns the [`Timestamp`] of when the DID document was created.
  pub fn created(&self) -> Timestamp {
    self.document.properties().created
  }

  /// Sets the [`Timestamp`] of when the DID document was created.
  pub fn set_created(&mut self, value: Timestamp) {
    self.document.properties_mut().created = value;
  }

  /// Returns the [`Timestamp`] of the last DID document update.
  pub fn updated(&self) -> Timestamp {
    self.document.properties().updated
  }

  /// Sets the [`Timestamp`] of the last DID document update.
  pub fn set_updated(&mut self, value: Timestamp) {
    self.document.properties_mut().updated = value;
  }

  /// Returns the Tangle [`MessageId`] of the previous DID document, if any.
  ///
  /// Returns [`MessageId::null`] if not set.
  pub fn previous_message_id(&self) -> &MessageId {
    &self.document.properties().previous_message_id
  }

  /// Sets the Tangle [`MessageId`] the previous DID document.
  pub fn set_previous_message_id(&mut self, value: impl Into<MessageId>) {
    self.document.properties_mut().previous_message_id = value.into();
  }

  /// Returns a reference to the custom DID Document properties.
  pub fn properties(&self) -> &Object {
    &self.document.properties().properties
  }

  /// Returns a mutable reference to the custom DID Document properties.
  pub fn properties_mut(&mut self) -> &mut Object {
    &mut self.document.properties_mut().properties
  }

  /// Returns a reference to the [`proof`](Signature), if one exists.
  pub fn proof(&self) -> Option<&Signature> {
    self.document.proof()
  }

  // ===========================================================================
  // Services
  // ===========================================================================

  /// Return a set of all [`Service`]s in the document.
  pub fn service(&self) -> &OrderedSet<Service> {
    self.document.service()
  }

  /// Add a new [`Service`] to the document.
  pub fn insert_service(&mut self, service: Service) -> bool {
    if service.id().fragment().is_none() {
      false
    } else {
      self.document.service_mut().append(service)
    }
  }

  /// Remove a [`Service`] identified by the given [`RunnercDIDUrl`] from the document.
  pub fn remove_service(&mut self, did_url: RunnercDIDUrl) -> Result<()> {
    let core_did_url: CoreDIDUrl = CoreDIDUrl::from(did_url);
    self.document.service_mut().remove(&core_did_url);
    Ok(())
  }

  // ===========================================================================
  // Verification Methods
  // ===========================================================================

  /// Returns an iterator over all [`IotaVerificationMethods`][RunnercVerificationMethod] in the DID Document.
  pub fn methods(&self) -> impl Iterator<Item = &RunnercVerificationMethod> {
    self.document.methods().map(|m|
      // SAFETY: Validity of verification methods checked in `RunnercVerificationMethod::check_validity`.
      unsafe { RunnercVerificationMethod::new_unchecked_ref(m) })
  }

  /// Adds a new [`RunnercVerificationMethod`] to the document in the given [`MethodScope`].
  ///
  /// # Errors
  ///
  /// Returns an error if a method with the same fragment already exists.
  pub fn insert_method(&mut self, method: RunnercVerificationMethod, scope: MethodScope) -> Result<()> {
    Ok(self.document.insert_method(method.into(), scope)?)
  }

  /// Removes all references to the specified [`VerificationMethod`].
  ///
  /// # Errors
  ///
  /// Returns an error if the method does not exist.
  pub fn remove_method(&mut self, did_url: RunnercDIDUrl) -> Result<()> {
    let core_did_url: CoreDIDUrl = CoreDIDUrl::from(did_url);
    Ok(self.document.remove_method(&core_did_url)?)
  }

  /// Attaches the relationship to the given method, if the method exists.
  ///
  /// Note: The method needs to be in the set of verification methods,
  /// so it cannot be an embedded one.
  pub fn attach_method_relationship(
    &mut self,
    did_url: RunnercDIDUrl,
    relationship: MethodRelationship,
  ) -> Result<bool> {
    let core_did_url: CoreDIDUrl = CoreDIDUrl::from(did_url);
    Ok(self.document.attach_method_relationship(core_did_url, relationship)?)
  }

  /// Detaches the given relationship from the given method, if the method exists.
  pub fn detach_method_relationship(
    &mut self,
    did_url: RunnercDIDUrl,
    relationship: MethodRelationship,
  ) -> Result<bool> {
    let core_did_url: CoreDIDUrl = CoreDIDUrl::from(did_url);
    Ok(self.document.detach_method_relationship(core_did_url, relationship)?)
  }

  /// Returns the first [`RunnercVerificationMethod`] with an `id` property
  /// matching the provided `query`.
  pub fn resolve_method<'query, Q>(&self, query: Q) -> Option<&RunnercVerificationMethod>
  where
    Q: Into<MethodQuery<'query>>,
  {
    // SAFETY: Validity of verification methods checked in `RunnercVerificationMethod::check_validity`.
    unsafe {
      self
        .document
        .resolve_method(query)
        .map(|m| RunnercVerificationMethod::new_unchecked_ref(m))
    }
  }

  /// Returns the first [`RunnercVerificationMethod`] with an `id` property
  /// matching the provided `query`.
  ///
  /// # Errors
  ///
  /// Fails if no matching verification [`RunnercVerificationMethod`] is found.
  pub fn try_resolve_method<'query, Q>(&self, query: Q) -> Result<&RunnercVerificationMethod>
  where
    Q: Into<MethodQuery<'query>>,
  {
    // SAFETY: Validity of verification methods checked in `RunnercVerificationMethod::check_validity`.
    unsafe {
      self
        .document
        .try_resolve_method(query)
        .map(|m| RunnercVerificationMethod::new_unchecked_ref(m))
        .map_err(Error::InvalidDoc)
    }
  }

  #[doc(hidden)]
  pub fn try_resolve_method_mut<'query, Q>(&mut self, query: Q) -> Result<&mut VerificationMethod>
  where
    Q: Into<MethodQuery<'query>>,
  {
    self.document.try_resolve_method_mut(query).map_err(Into::into)
  }

  // ===========================================================================
  // Signatures
  // ===========================================================================

  /// Signs this DID document with the verification method specified by `method_query`.
  /// The `method_query` may be the full [`RunnercDIDUrl`] of the method or just its fragment,
  /// e.g. "#sign-0". The signing method must have a capability invocation verification
  /// relationship.
  ///
  /// NOTE: does not validate whether `private_key` corresponds to the verification method.
  /// See [`RunnercDocument::verify_document`].
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used or the signature operation fails.
  pub fn sign_self<'query, Q>(&mut self, private_key: &PrivateKey, method_query: Q) -> Result<()>
  where
    Q: Into<MethodQuery<'query>>,
  {
    // Ensure signing method has a capability invocation verification relationship.
    let method: &VerificationMethod<_> = self
      .as_document()
      .try_resolve_method_with_scope(method_query.into(), MethodScope::capability_invocation())?;
    let _ = Self::check_signing_method(method)?;

    // Specify the full method DID Url if the verification method id does not match the document id.
    let method_did: &RunnercDID = RunnercDID::try_from_borrowed(method.id().did())?;
    let method_id: String = if method_did == self.id() {
      method.try_into_fragment()?
    } else {
      method.id().to_string()
    };

    // Sign document.
    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {
        JcsEd25519::<Ed25519>::create_signature(self, method_id, private_key.as_ref())?;
      }
      MethodType::MerkleKeyCollection2021 => {
        // Merkle Key Collections cannot be used to sign documents.
        return Err(Error::InvalidDocumentSigningMethodType);
      }
    }

    Ok(())
  }

  /// Creates a new [`RunnercDocumentSigner`] that can be used to create digital
  /// signatures from verification methods in this DID Document.
  pub fn signer<'base>(&'base self, private_key: &'base PrivateKey) -> RunnercDocumentSigner<'base, 'base, 'base> {
    self.document.signer(private_key)
  }

  /// Verifies that the signature on the DID document `signed` was generated by a valid method from
  /// the `signer` DID document.
  ///
  /// # Errors
  ///
  /// Fails if:
  /// - The signature proof section is missing in the `signed` document.
  /// - The method is not found in the `signer` document.
  /// - An unsupported verification method is used.
  /// - The signature verification operation fails.
  pub fn verify_document(signed: &RunnercDocument, signer: &RunnercDocument) -> Result<()> {
    // Ensure signing key has a capability invocation verification relationship.
    let signature: &Signature = signed.try_signature()?;
    let method: &VerificationMethod<_> = signer
      .as_document()
      .try_resolve_method_with_scope(signature, MethodScope::capability_invocation())?;

    // Verify signature.
    let public: PublicKey = method.key_data().try_decode()?.into();
    match method.key_type() {
      MethodType::Ed25519VerificationKey2018 => {
        JcsEd25519::<Ed25519>::verify_signature(signed, public.as_ref())?;
      }
      MethodType::MerkleKeyCollection2021 => {
        // Merkle Key Collections cannot be used to sign documents.
        return Err(identity_did::error::Error::InvalidMethodType.into());
      }
    }

    Ok(())
  }

  /// Verifies a self-signed signature on this DID document.
  ///
  /// Equivalent to `RunnercDocument::verify_document(&doc, &doc)`.
  ///
  /// See [`RunnercDocument::verify_document`].
  pub fn verify_self_signed(&self) -> Result<()> {
    Self::verify_document(self, self)
  }

  /// Verifies whether `document` is a valid root DID document according to the IOTA DID method
  /// specification.
  ///
  /// It must be signed using a verification method with a public key whose BLAKE2b-256 hash matches
  /// the DID tag.
  pub fn verify_root_document(document: &RunnercDocument) -> Result<()> {
    // The previous message id must be null.
    if !document.previous_message_id().is_null() {
      return Err(Error::InvalidRootDocument);
    }

    // Validate the hash of the public key matches the DID tag.
    let signature: &Signature = document.try_signature()?;
    let method: &VerificationMethod<_> = document.as_document().try_resolve_method(signature)?;
    let public: PublicKey = method.key_data().try_decode()?.into();
    if document.id().tag() != RunnercDID::encode_key(public.as_ref()) {
      return Err(Error::InvalidRootDocument);
    }
    log::debug!("====");
    // Validate the document is signed correctly.
    document.verify_self_signed()
  }

  /// Creates a new [`RunnercDocumentVerifier`] that can be used to verify signatures
  /// created with this DID Document.
  pub fn verifier(&self) -> RunnercDocumentVerifier<'_> {
    self.document.verifier()
  }

  /// Signs the provided `data` with the verification method specified by `method_query`.
  ///
  /// NOTE: does not validate whether `private_key` corresponds to the verification method.
  /// See [`RunnercDocument::verify_data`].
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, data
  /// serialization fails, or the signature operation fails.
  pub fn sign_data<'query, 's: 'query, X, Q>(
    &'s self,
    data: &mut X,
    private_key: &'query PrivateKey,
    method_query: Q,
  ) -> Result<()>
  where
    X: Serialize + SetSignature + TryMethod,
    Q: Into<MethodQuery<'query>>,
  {
    self
      .signer(private_key)
      .method(method_query)
      .sign(data)
      .map_err(Into::into)
  }

  /// Verifies the signature of the provided `data` was created using a verification method
  /// in this DID Document.
  ///
  /// NOTE: does not restrict which verification relationship signed the data.
  /// See [`RunnercDocument::verify_data_with_scope`].
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used, document
  /// serialization fails, or the verification operation fails.
  pub fn verify_data<X>(&self, data: &X) -> Result<()>
  where
    X: Serialize + TrySignature,
  {
    self.verifier().verify(data).map_err(Into::into)
  }

  /// Verifies the signature of the provided `data` was created using a verification method
  /// in this DID Document with the verification relationship specified by `scope`.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used or the verification operation fails.
  pub fn verify_data_with_scope<X>(&self, data: &X, scope: MethodScope) -> Result<()>
  where
    X: Serialize + TrySignature,
  {
    self.verifier().verify_with_scope(data, scope).map_err(Into::into)
  }

  // ===========================================================================
  // Diffs
  // ===========================================================================

  /// Creates a `DiffMessage` representing the changes between `self` and `other`.
  ///
  /// The returned `DiffMessage` will have a digital signature created using the
  /// specified `private_key` and `method_query`.
  ///
  /// NOTE: the method must be a capability invocation method.
  ///
  /// # Errors
  ///
  /// Fails if the diff operation or signature operation fails.
  pub fn diff<'query, 's: 'query, Q>(
    &'query self,
    other: &Self,
    message_id: MessageId,
    private_key: &'query PrivateKey,
    method_query: Q,
  ) -> Result<DiffMessage>
  where
    Q: Into<MethodQuery<'query>>,
  {
    let mut diff: DiffMessage = DiffMessage::new(self, other, message_id)?;

    // Ensure the signing method has a capability invocation verification relationship.
    let method_query = method_query.into();
    let _ = self
      .as_document()
      .try_resolve_method_with_scope(method_query.clone(), MethodScope::capability_invocation())?;

    self.sign_data(&mut diff, private_key, method_query)?;

    Ok(diff)
  }

  /// Verifies the signature of the `diff` was created using a capability invocation method
  /// in this DID Document.
  ///
  /// # Errors
  ///
  /// Fails if an unsupported verification method is used or the verification operation fails.
  pub fn verify_diff(&self, diff: &DiffMessage) -> Result<()> {
    self.verify_data_with_scope(diff, MethodScope::capability_invocation())
  }

  /// Verifies a `DiffMessage` signature and merges the changes into `self`.
  ///
  /// If merging fails `self` remains unmodified, otherwise `self` represents
  /// the merged document state.
  ///
  /// See [`RunnercDocument::verify_diff`].
  ///
  /// # Errors
  ///
  /// Fails if the merge operation or signature operation fails.
  pub fn merge(&mut self, diff: &DiffMessage) -> Result<()> {
    self.verify_diff(diff)?;

    *self = diff.merge(self)?;

    Ok(())
  }

  // ===========================================================================
  // Publishing
  // ===========================================================================

  /// Returns the Tangle index of the integration chain for this DID.
  ///
  /// This is equivalent to the tag segment of the [`RunnercDID`].
  ///
  /// E.g.
  /// For an [`RunnercDocument`] `doc` with `"did:iota:1234567890abcdefghijklmnopqrstuvxyzABCDEFGHI"`,
  /// `doc.integration_index() == "1234567890abcdefghijklmnopqrstuvxyzABCDEFGHI"`
  pub fn integration_index(&self) -> &str {
    self.did().tag()
  }

  /// Returns the Tangle index of the DID diff chain. This should only be called on messages
  /// from documents published on the integration chain.
  ///
  /// This is the Base58-btc encoded SHA-256 digest of the hex-encoded message id.
  pub fn diff_index(message_id: &MessageId) -> Result<String> {
    if message_id.is_null() {
      return Err(Error::InvalidDocumentMessageId);
    }

    Ok(RunnercDID::encode_key(message_id.encode_hex().as_bytes()))
  }
}

impl<'a, 'b, 'c> RunnercDocument {}

impl Display for RunnercDocument {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    Display::fmt(&self.document, f)
  }
}

impl Debug for RunnercDocument {
  fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
    Debug::fmt(&self.document, f)
  }
}

impl TryFrom<BaseDocument> for RunnercDocument {
  type Error = Error;

  fn try_from(other: BaseDocument) -> Result<Self, Self::Error> {
    RunnercDocument::try_from_base(other)
  }
}

impl From<RunnercDocument> for BaseDocument {
  fn from(other: RunnercDocument) -> Self {
    other.document
  }
}

impl TryFrom<CoreDocument> for RunnercDocument {
  type Error = Error;

  fn try_from(other: CoreDocument) -> Result<Self, Self::Error> {
    Self::try_from_core(other)
  }
}

impl TrySignature for RunnercDocument {
  fn signature(&self) -> Option<&Signature> {
    self.document.proof()
  }
}

impl TrySignatureMut for RunnercDocument {
  fn signature_mut(&mut self) -> Option<&mut Signature> {
    self.document.proof_mut()
  }
}

impl SetSignature for RunnercDocument {
  fn set_signature(&mut self, signature: Signature) {
    self.document.set_proof(signature)
  }
}

impl TangleRef for RunnercDocument {
  fn did(&self) -> &RunnercDID {
    self.id()
  }

  fn message_id(&self) -> &MessageId {
    &self.message_id
  }

  fn set_message_id(&mut self, message_id: MessageId) {
    self.message_id = message_id;
  }

  fn previous_message_id(&self) -> &MessageId {
    RunnercDocument::previous_message_id(self)
  }

  fn set_previous_message_id(&mut self, message_id: MessageId) {
    RunnercDocument::set_previous_message_id(self, message_id)
  }
}
