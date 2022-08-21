// Copyright 2020-2021 Runnerc
// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::from_slice;
use serde_json::to_vec;

use crate::error::Result;
use crate::lib::*;

pub fn encode_b64(data: impl AsRef<[u8]>) -> String {
  base64::encode_config(data.as_ref(), base64::URL_SAFE_NO_PAD)
}

pub fn encode_b64_into(data: impl AsRef<[u8]>, buffer: &mut String) {
  base64::encode_config_buf(data.as_ref(), base64::URL_SAFE_NO_PAD, buffer)
}

pub fn decode_b64(data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
  base64::decode_config(data.as_ref(), base64::URL_SAFE_NO_PAD).map_err(Into::into)
}

pub fn decode_b64_into(data: impl AsRef<[u8]>, buffer: &mut Vec<u8>) -> Result<()> {
  base64::decode_config_buf(data.as_ref(), base64::URL_SAFE_NO_PAD, buffer).map_err(Into::into)
}

pub fn encode_b64_json<T>(data: &T) -> Result<String>
where
  T: Serialize,
{
  to_vec(data).map(encode_b64).map_err(Into::into)
}

pub fn decode_b64_json<T>(data: impl AsRef<[u8]>) -> Result<T>
where
  T: DeserializeOwned,
{
  decode_b64(data).and_then(|data| from_slice(&data).map_err(Into::into))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn smoke() {
    assert!(decode_b64(encode_b64(b"libjose")).is_ok());
  }
}
