pub mod mls_protocol;
pub mod release_provenance;
mod release_root;
pub mod secure_protocol;

#[derive(Debug, PartialEq, thiserror::Error, uniffi::Error)]
pub enum AbyssalError {
    #[error("{detail}")]
    Failure { detail: String },
}

impl From<String> for AbyssalError {
    fn from(message: String) -> Self {
        Self::Failure { detail: message }
    }
}

uniffi::setup_scaffolding!();
