use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RescueReadiness {
    pub schema: &'static str,
    pub state: &'static str,
    pub checks: RescueReadinessChecks,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct RescueReadinessChecks {
    pub normal_boundary_separated: bool,
    pub rescue_identity_separated: bool,
    pub recovery_authority_separated: bool,
    pub management_lifeline_verified: bool,
    pub durable_replay_ledger: bool,
    pub two_person_recovery: bool,
}
