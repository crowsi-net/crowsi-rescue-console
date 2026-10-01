use std::{
    fs::{File, read_link, read_to_string},
    io::Read,
    os::unix::net::UnixStream,
};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use sha2::{Digest, Sha256};

use crate::{RescueError, model::PeerIdentity};

#[cfg(test)]
mod tests;

/// Attests a rescue caller from kernel Unix credentials and process evidence.
///
/// # Errors
///
/// Fails closed when credentials or executable evidence cannot be read
/// consistently.
pub(crate) fn attest_unix_peer(stream: &UnixStream) -> Result<PeerIdentity, RescueError> {
    let credentials =
        getsockopt(stream, PeerCredentials).map_err(|_| RescueError::PeerAttestation)?;
    let pid = u32::try_from(credentials.pid()).map_err(|_| RescueError::PeerAttestation)?;
    let before = process_start_ticks(pid)?;
    let executable_sha256 = executable_digest(pid)?;
    let network_namespace_id = namespace_id(pid, "net")?;
    let ipc_namespace_id = namespace_id(pid, "ipc")?;
    if before != process_start_ticks(pid)? {
        return Err(RescueError::PeerAttestation);
    }
    Ok(PeerIdentity {
        uid: credentials.uid(),
        gid: credentials.gid(),
        executable_sha256,
        network_namespace_id,
        ipc_namespace_id,
    })
}

fn executable_digest(pid: u32) -> Result<String, RescueError> {
    let mut executable =
        File::open(format!("/proc/{pid}/exe")).map_err(|_| RescueError::PeerAttestation)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = executable
            .read(&mut buffer)
            .map_err(|_| RescueError::PeerAttestation)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn namespace_id(pid: u32, kind: &str) -> Result<String, RescueError> {
    let value = read_link(format!("/proc/{pid}/ns/{kind}"))
        .map_err(|_| RescueError::PeerAttestation)?
        .to_str()
        .map(str::to_owned)
        .ok_or(RescueError::PeerAttestation)?;
    let inode = value
        .strip_prefix(&format!("{kind}:["))
        .and_then(|rest| rest.strip_suffix(']'))
        .filter(|rest| rest.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(RescueError::PeerAttestation)?;
    Ok(format!("namespace:{kind}:{inode}"))
}

fn process_start_ticks(pid: u32) -> Result<u64, RescueError> {
    let stat =
        read_to_string(format!("/proc/{pid}/stat")).map_err(|_| RescueError::PeerAttestation)?;
    let close = stat.rfind(')').ok_or(RescueError::PeerAttestation)?;
    stat.get(close + 2..)
        .and_then(|tail| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or(RescueError::PeerAttestation)
}
