pub mod core {
    pub use identity_core::common::*;
    pub use identity_core::convert::*;
    #[doc(inline)]
    pub use identity_core::diff;
    pub use identity_core::error::*;
    #[doc(inline)]
    pub use identity_core::json;
    pub use identity_core::utils::*;
}

pub mod crypto {
    pub use identity_core::crypto::*;
}

pub mod credential {

    pub use identity_credential::credential::*;
    pub use identity_credential::error::*;
    pub use identity_credential::presentation::*;
}

pub mod did {
    pub use identity_did::document::*;
    pub use identity_did::error::*;
    pub use identity_did::service::*;
    pub use identity_did::utils::*;
    pub use identity_did::verification::*;

    pub use identity_did::did::*;

    pub use identity_did::resolution;
    pub use identity_did::verifiable;
}

pub mod runnerc {
    pub use identity_runnerc::credential::*;
    pub use identity_runnerc::did::*;
    pub use identity_runnerc::document::*;
    pub use identity_runnerc::error::*;
    pub use identity_runnerc::runnerc::*;

    #[doc(inline)]
    pub use identity_runnerc::try_construct_did;
}

// #[cfg(feature = "account")]
// #[cfg_attr(docsrs, doc(cfg(feature = "account")))]
// pub mod account {
//     //! Secure storage for Decentralized Identifiers

//     pub use identity_account::account::*;
//     pub use identity_account::crypto::*;
//     pub use identity_account::error::*;
//     pub use identity_account::identity::*;
//     pub use identity_account::storage::*;
//     pub use identity_account::types::*;
//     pub use identity_account::updates::*;
//     pub use identity_account::utils::*;
// }

pub mod comm {
    pub use identity_comm::envelope::*;
    pub use identity_comm::error::*;
    pub use identity_comm::message::*;
}

pub mod prelude {
    pub use identity_core::crypto::KeyPair;
    pub use identity_runnerc::document::RunnercDocument;
    pub use identity_runnerc::runnerc::Client;
    pub use identity_runnerc::Result;
}
