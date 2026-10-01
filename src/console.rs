use std::os::unix::net::UnixStream;

use crate::{
    RescueError, RescueLedger, RescueReadiness, RescueReadinessChecks, RescueTicket, RescueTrust,
    SeparationConfig, SignedEmergencyAuthorization, SignedLifelineEvidence, TrustedClock,
    canonical_emergency_authorization, canonical_lifeline_evidence, model::PeerIdentity,
    peer::attest_unix_peer, sha256_digest, validation,
};

mod recovery;

pub struct RescueConsole<C = crate::SystemTrustedClock> {
    config: SeparationConfig,
    trust: RescueTrust,
    ledger: RescueLedger,
    clock: C,
}

impl<C: TrustedClock> RescueConsole<C> {
    #[must_use]
    pub const fn new(
        config: SeparationConfig,
        trust: RescueTrust,
        ledger: RescueLedger,
        clock: C,
    ) -> Self {
        Self {
            config,
            trust,
            ledger,
            clock,
        }
    }

    /// Authorizes a one-use contain or credential-revoke request.
    ///
    /// # Errors
    ///
    /// Rejects failed peer, lifeline, binding, time, signature, or replay checks.
    pub(crate) fn authorize_emergency_attested(
        &mut self,
        request: &crate::EmergencyRequestV1,
        authorization: &SignedEmergencyAuthorization,
        peer: &PeerIdentity,
        lifeline: &SignedLifelineEvidence,
    ) -> Result<RescueTicket, RescueError> {
        let now = self.now()?;
        validation::peer(self.config.rescue(), peer)?;
        self.validate_lifeline(lifeline, now)?;
        if authorization.document.issuer_key_id != self.trust.rescue_key_id {
            return Err(RescueError::Authentication);
        }
        validation::emergency(request, &authorization.document, now)?;
        validation::signature(
            &self.trust.rescue_key,
            &canonical_emergency_authorization(&authorization.document),
            &authorization.signature_hex,
        )?;
        self.ledger.consume(
            &authorization.document.nonce,
            &request.request_id,
            "emergency",
            now,
        )?;
        Ok(RescueTicket {
            schema: "crowsi://rescue/dispatch-ticket/v1",
            request_id: request.request_id.clone(),
            action: request.action,
            resource: request.resource.clone(),
            command_digest: sha256_digest(&canonical_emergency_authorization(
                &authorization.document,
            )),
        })
    }

    /// Authorizes an emergency request only for the kernel-attested Unix peer.
    ///
    /// # Errors
    ///
    /// Rejects failed peer attestation, lifeline, or authorization checks.
    pub fn authorize_emergency_from_stream(
        &mut self,
        request: &crate::EmergencyRequestV1,
        authorization: &SignedEmergencyAuthorization,
        stream: &UnixStream,
        lifeline: &SignedLifelineEvidence,
    ) -> Result<RescueTicket, RescueError> {
        let peer = attest_unix_peer(stream)?;
        self.authorize_emergency_attested(request, authorization, &peer, lifeline)
    }

    #[must_use]
    pub fn readiness(&self) -> RescueReadiness {
        RescueReadiness {
            schema: "crowsi://rescue/readiness/v1",
            state: "unavailable",
            checks: RescueReadinessChecks {
                normal_boundary_separated: false,
                rescue_identity_separated: false,
                recovery_authority_separated: false,
                management_lifeline_verified: false,
                durable_replay_ledger: false,
                two_person_recovery: false,
            },
        }
    }

    pub(super) fn now(&self) -> Result<i64, RescueError> {
        if !self.clock.healthy() {
            return Err(RescueError::Time);
        }
        Ok(self.clock.now_epoch_s())
    }

    pub(super) fn validate_lifeline(
        &self,
        value: &SignedLifelineEvidence,
        now: i64,
    ) -> Result<(), RescueError> {
        if value.document.issuer_key_id != self.trust.lifeline_key_id {
            return Err(RescueError::Lifeline);
        }
        validation::lifeline(&value.document, now)?;
        validation::signature(
            &self.trust.lifeline_key,
            &canonical_lifeline_evidence(&value.document),
            &value.signature_hex,
        )
        .map_err(|_| RescueError::Lifeline)
    }
}

#[cfg(test)]
impl RescueConsole<crate::clock::TestClock> {
    pub(crate) const fn clock_mut(&mut self) -> &mut crate::clock::TestClock {
        &mut self.clock
    }
}
