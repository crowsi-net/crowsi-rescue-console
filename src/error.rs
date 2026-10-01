use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RescueError {
    #[error("runtime trust boundaries overlap")]
    BoundaryOverlap,
    #[error("invalid closed contract")]
    Contract,
    #[error("OS peer attestation rejected")]
    PeerAttestation,
    #[error("management lifeline is unverified")]
    Lifeline,
    #[error("authorization authentication rejected")]
    Authentication,
    #[error("request binding rejected")]
    Binding,
    #[error("authorization signature rejected")]
    Signature,
    #[error("authorization expired or clock invalid")]
    Time,
    #[error("two-person recovery control not satisfied")]
    TwoPersonControl,
    #[error("one-use authorization replay rejected")]
    Replay,
    #[error("durable security state unavailable")]
    Storage,
}

impl From<rusqlite::Error> for RescueError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
