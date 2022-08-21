// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg, extended_key_value_attributes))]
#![cfg_attr(not(docsrs), doc = "")]
#![allow(clippy::upper_case_acronyms)]
#![warn(
  rust_2018_idioms,
  unreachable_pub,
  // missing_docs,
  rustdoc::missing_crate_level_docs,
  rustdoc::broken_intra_doc_links,
  rustdoc::private_intra_doc_links,
  rustdoc::private_doc_tests,
  clippy::missing_safety_doc,
  // clippy::missing_errors_doc,
)]

pub use ipfs_api_backend_hyper as ipfs_api;

pub use self::error::Error;
pub use self::error::Result;

mod resolver;

pub(crate) mod utils;
pub(crate) mod constants;
pub mod credential;
pub mod did;
pub mod document;
pub mod error;
pub mod runnerc;
