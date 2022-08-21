// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(docsrs, feature(doc_cfg, extended_key_value_attributes))]
#![cfg_attr(not(docsrs), doc = "")]
#![allow(clippy::upper_case_acronyms)]
#![warn(
  rust_2018_idioms,
  unreachable_pub,
  missing_docs,
  rustdoc::missing_crate_level_docs,
  rustdoc::broken_intra_doc_links,
  rustdoc::private_intra_doc_links,
  rustdoc::private_doc_tests,
  clippy::missing_safety_doc,
  // clippy::missing_errors_doc
)]

#[macro_use]
extern crate serde;

#[doc(inline)]
pub use serde_json::json;

#[doc(inline)]
pub use identity_diff as diff;

pub mod common;
pub mod convert;
pub mod crypto;
pub mod error;
pub mod utils;

pub use self::error::Error;
pub use self::error::Result;
