// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use self::message_ext::MessageExt;
pub use self::message_ext::MessageIdExt;
pub use self::message_ext::TryFromMessage;
pub use self::message_index::MessageIndex;
pub use self::message_version::DIDMessageVersion;

mod message;
mod message_ext;
mod message_id;
mod message_index;
mod message_version;

pub use message::*;
pub use message_id::*;
