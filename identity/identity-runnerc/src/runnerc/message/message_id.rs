use crate::Error;

use core::str::FromStr;

/// The length of a message identifier.
pub const MESSAGE_ID_LENGTH: usize = 32;

/// A message identifier, the BLAKE2b-256 hash of the message bytes.
/// See <https://www.blake2.net/> for more information.
#[derive(Clone, Eq, Hash, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct MessageId(String);

// impl std::marker::Copy for MessageId {}

impl MessageId {
	/// Creates a new `MessageId`.
	pub fn new(id: String) -> Self {
		MessageId(id)
	}

	/// Create a null `MessageId`.
	pub fn null() -> Self {
		Self(String::new())
	}

	pub fn string_id(&self) -> String {
		self.0.clone()
	}

	pub fn is_null(&self) -> bool {
		self.0 == String::new()
	}
}

impl From<[u8; MESSAGE_ID_LENGTH]> for MessageId {
	fn from(bytes: [u8; MESSAGE_ID_LENGTH]) -> Self {
		Self(String::from_utf8_lossy(&bytes).to_string())
	}
}

impl FromStr for MessageId {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(MessageId::new(String::from(s)))
	}
}

impl AsRef<[u8]> for MessageId {
	fn as_ref(&self) -> &[u8] {
		&self.0.as_bytes()
	}
}

impl core::fmt::Display for MessageId {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl core::fmt::Debug for MessageId {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "MessageId({})", self)
	}
}
