//! Out-of-band containment and independently approved recovery authority.
//!
//! Kernel peer evidence cannot be constructed or passed through the public API.
//!
//! ```compile_fail
//! use crowsi_rescue_console::PeerIdentity;
//! ```

mod boundary;
mod canonical;
mod clock;
mod console;
mod error;
mod ledger;
mod ledger_schema;
mod model;
mod peer;
mod readiness;
mod recovery_evidence;
mod recovery_validation;
mod secure_state;
mod trust;
mod validation;

#[cfg(test)]
mod tests;

pub use boundary::SeparationConfig;
pub use canonical::{
    canonical_emergency_authorization, canonical_lifeline_evidence, canonical_recovery_approval,
    recovery_request_digest, sha256_digest,
};
pub use clock::{SystemTrustedClock, TrustedClock};
pub use console::RescueConsole;
pub use error::RescueError;
pub use ledger::RescueLedger;
pub use model::{
    BoundaryIdentity, EmergencyAction, EmergencyAuthorizationV1, EmergencyRequestV1,
    LifelineEvidence, RecoveryApproval, RecoveryRequestV1, RecoveryTicket, RescueTicket,
    SignedEmergencyAuthorization, SignedLifelineEvidence,
};
pub use readiness::{RescueReadiness, RescueReadinessChecks};
pub use recovery_evidence::RecoveryProofBundleV1;
pub use trust::{RecoveryProofTrust, RescueTrust};
