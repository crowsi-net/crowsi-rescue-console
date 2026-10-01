use std::{collections::BTreeSet, path::Path};

use crate::{BoundaryIdentity, RescueError};

#[derive(Clone, Debug)]
pub struct SeparationConfig {
    pub(crate) rescue: BoundaryIdentity,
    pub(crate) recovery: BoundaryIdentity,
}

impl SeparationConfig {
    /// Establishes non-overlapping normal, rescue, and recovery boundaries.
    ///
    /// # Errors
    ///
    /// Rejects invalid identities or any shared runtime boundary.
    pub fn new(
        normal: &BoundaryIdentity,
        rescue: BoundaryIdentity,
        recovery: BoundaryIdentity,
    ) -> Result<Self, RescueError> {
        for boundary in [normal, &rescue, &recovery] {
            validate_boundary(boundary)?;
        }
        unique(&[
            normal.uid.to_string(),
            rescue.uid.to_string(),
            recovery.uid.to_string(),
        ])?;
        unique(&[
            normal.gid.to_string(),
            rescue.gid.to_string(),
            recovery.gid.to_string(),
        ])?;
        unique(&[
            normal.socket_path.clone(),
            rescue.socket_path.clone(),
            recovery.socket_path.clone(),
        ])?;
        unique(&[
            normal.signing_key_id.clone(),
            rescue.signing_key_id.clone(),
            recovery.signing_key_id.clone(),
        ])?;
        unique(&[
            normal.network_namespace_id.clone(),
            rescue.network_namespace_id.clone(),
            recovery.network_namespace_id.clone(),
        ])?;
        unique(&[
            normal.ipc_namespace_id.clone(),
            rescue.ipc_namespace_id.clone(),
            recovery.ipc_namespace_id.clone(),
        ])?;
        unique(&[
            normal.executable_sha256.clone(),
            rescue.executable_sha256.clone(),
            recovery.executable_sha256.clone(),
        ])?;
        Ok(Self { rescue, recovery })
    }

    pub(crate) const fn rescue(&self) -> &BoundaryIdentity {
        &self.rescue
    }

    pub(crate) const fn recovery(&self) -> &BoundaryIdentity {
        &self.recovery
    }
}

fn validate_boundary(value: &BoundaryIdentity) -> Result<(), RescueError> {
    if value.uid == 0
        || value.gid == 0
        || !Path::new(&value.socket_path).is_absolute()
        || !Path::new(&value.socket_path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sock"))
        || !valid_id(&value.signing_key_id)
        || !valid_digest(&value.executable_sha256)
        || !valid_id(&value.network_namespace_id)
        || !valid_id(&value.ipc_namespace_id)
    {
        return Err(RescueError::Contract);
    }
    Ok(())
}

fn unique<const N: usize>(values: &[String; N]) -> Result<(), RescueError> {
    if values.iter().collect::<BTreeSet<_>>().len() != N {
        return Err(RescueError::BoundaryOverlap);
    }
    Ok(())
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._/-".contains(&byte))
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
