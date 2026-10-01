use std::{collections::BTreeSet, os::unix::net::UnixStream};

use crate::{
    RecoveryApproval, RecoveryProofBundleV1, RecoveryRequestV1, RecoveryTicket, RescueError,
    SignedLifelineEvidence, TrustedClock, canonical_recovery_approval, model::PeerIdentity,
    peer::attest_unix_peer, recovery_request_digest, recovery_validation, validation,
};

use super::RescueConsole;

impl<C: TrustedClock> RescueConsole<C> {
    /// Authorizes restore only after two distinct hardware-bound approvals.
    ///
    /// # Errors
    ///
    /// Rejects failed separation, lifeline, approval, signature, or replay checks.
    pub(crate) fn authorize_restore_attested(
        &mut self,
        request: &RecoveryRequestV1,
        evidence: &RecoveryProofBundleV1,
        approvals: &[RecoveryApproval],
        peer: &PeerIdentity,
        lifeline: &SignedLifelineEvidence,
    ) -> Result<RecoveryTicket, RescueError> {
        let now = self.now()?;
        validation::peer(self.config.recovery(), peer)?;
        self.validate_lifeline(lifeline, now)?;
        recovery_validation::validate(request, evidence, now)?;
        self.verify_recovery_proof(evidence)?;
        if approvals.len() != 2 {
            return Err(RescueError::TwoPersonControl);
        }
        let digest = recovery_request_digest(request);
        let subjects = approvals
            .iter()
            .map(|approval| &approval.subject_id)
            .collect::<BTreeSet<_>>();
        let keys = approvals
            .iter()
            .map(|approval| &approval.key_id)
            .collect::<BTreeSet<_>>();
        if subjects.len() != 2 || keys.len() != 2 {
            return Err(RescueError::TwoPersonControl);
        }
        for approval in approvals {
            validation::recovery(request, approval, &digest, now)?;
            let key = self
                .trust
                .recovery_keys
                .get(&approval.key_id)
                .ok_or(RescueError::Authentication)?;
            validation::signature(
                key,
                &canonical_recovery_approval(approval),
                &approval.signature_hex,
            )?;
        }
        self.ledger
            .consume(&request.nonce, &request.request_id, "recovery", now)?;
        Ok(RecoveryTicket {
            schema: "crowsi://rescue/recovery-ticket/v1",
            request_id: request.request_id.clone(),
            resource: request.resource.clone(),
            approver_count: 2,
            command_digest: digest,
        })
    }

    /// Authorizes restore only for an independently attested recovery peer.
    ///
    /// # Errors
    ///
    /// Rejects failed kernel attestation, lifeline, approval, or replay checks.
    pub fn authorize_restore_from_stream(
        &mut self,
        request: &RecoveryRequestV1,
        evidence: &RecoveryProofBundleV1,
        approvals: &[RecoveryApproval],
        stream: &UnixStream,
        lifeline: &SignedLifelineEvidence,
    ) -> Result<RecoveryTicket, RescueError> {
        let peer = attest_unix_peer(stream)?;
        self.authorize_restore_attested(request, evidence, approvals, &peer, lifeline)
    }

    fn verify_recovery_proof(&self, value: &RecoveryProofBundleV1) -> Result<(), RescueError> {
        self.trust.verify_receipt(&value.quarantine_receipt)?;
        self.trust.verify_readback(&value.independent_readback)
    }
}
