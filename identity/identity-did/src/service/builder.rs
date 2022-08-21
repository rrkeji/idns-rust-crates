// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use identity_core::common::Object;

use crate::did::CoreDIDUrl;
use crate::error::Result;
use crate::service::Service;
use crate::service::ServiceEndpoint;

/// A `ServiceBuilder` is used to generate a customized `Service`.
#[derive(Clone, Debug, Default)]
pub struct ServiceBuilder<T = Object> {
  pub(crate) id: Option<CoreDIDUrl>,
  pub(crate) type_: Option<String>,
  pub(crate) service_endpoint: Option<ServiceEndpoint>,
  pub(crate) properties: T,
}

impl<T> ServiceBuilder<T> {
  /// Creates a new `ServiceBuilder`.
  pub fn new(properties: T) -> Self {
    Self {
      id: None,
      type_: None,
      service_endpoint: None,
      properties,
    }
  }

  /// Sets the `id` value of the generated `Service`.
  #[must_use]
  pub fn id(mut self, value: CoreDIDUrl) -> Self {
    self.id = Some(value);
    self
  }

  /// Sets the `type` value of the generated `Service`.
  #[must_use]
  pub fn type_(mut self, value: impl Into<String>) -> Self {
    self.type_ = Some(value.into());
    self
  }

  /// Sets the `serviceEndpoint` value of the generated `Service`.
  #[must_use]
  pub fn service_endpoint(mut self, value: ServiceEndpoint) -> Self {
    self.service_endpoint = Some(value);
    self
  }

  /// Returns a new `Service` based on the `ServiceBuilder` configuration.
  pub fn build(self) -> Result<Service<T>> {
    Service::from_builder(self)
  }
}

#[cfg(test)]
mod tests {
  use identity_core::common::Url;

  use super::*;

  #[test]
  #[should_panic = "InvalidServiceId"]
  fn test_missing_id() {
    let _: Service = ServiceBuilder::default()
      .type_("ServiceType")
      .service_endpoint(Url::parse("https://example.com").unwrap().into())
      .build()
      .unwrap();
  }

  #[test]
  #[should_panic = "InvalidServiceType"]
  fn test_missing_type_() {
    let _: Service = ServiceBuilder::default()
      .id("did:example:123".parse().unwrap())
      .service_endpoint(Url::parse("https://example.com").unwrap().into())
      .build()
      .unwrap();
  }

  #[test]
  #[should_panic = "InvalidServiceEndpoint"]
  fn test_missing_service_endpoint() {
    let _: Service = ServiceBuilder::default()
      .id("did:example:123".parse().unwrap())
      .type_("ServiceType")
      .build()
      .unwrap();
  }
}
