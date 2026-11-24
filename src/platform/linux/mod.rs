//! The Linux implementation: iproute2, nftables, systemd(-resolved), polkit.

pub(crate) mod cmd;
pub mod exit;
pub mod files;
pub mod ipc;
pub mod net;
mod netlink;
pub mod service;
pub mod tunnel;

/// Linux interface names: at most 15 characters, no quotes or spaces. Checked because
/// the WAN name is written into the nftables ruleset.
pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
}

/// Whether another process named `dvpn` that may be lending shares our network
/// namespace: one run by root (`dvpn run --exit`, `dvpn connect`) or by our own user
/// (the service runs as `dvpn`, with CAP_NET_ADMIN). Other users' can't lend.
pub(crate) fn other_dvpn_in_this_namespace() -> bool {
    use std::os::unix::fs::MetadataExt;
    let ours = std::fs::read_link("/proc/self/ns/net").ok();
    let me = std::process::id().to_string();
    let my_uid = std::fs::metadata("/proc/self").map(|m| m.uid()).ok();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        pid.chars().all(|c| c.is_ascii_digit())
            && pid != me
            && std::fs::metadata(entry.path()).is_ok_and(|m| m.uid() == 0 || Some(m.uid()) == my_uid)
            && std::fs::read_to_string(entry.path().join("comm")).is_ok_and(|c| c.trim() == "dvpn")
            // Unreadable (the sandboxed service lacks CAP_SYS_PTRACE): assume it's here,
            // rather than remove rules another dvpn may be using.
            && std::fs::read_link(entry.path().join("ns/net")).map_or(true, |ns| Some(ns) == ours)
    })
}

/// Fails if `nft` (when installed) can't parse `rules`. Parsing needs no privileges;
/// applying them does, so the error that follows a successful parse is ignored.
#[cfg(test)]
pub(crate) fn assert_nft_parses(rules: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let Ok(mut child) = Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return; // nft isn't installed here
    };
    child.stdin.take().unwrap().write_all(rules.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let parse_errors: Vec<&str> = stderr.lines().filter(|l| l.contains("Error:") && !l.starts_with("netlink:")).collect();
    assert!(parse_errors.is_empty(), "nft can't parse the ruleset:\n{stderr}\n{rules}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names_are_checked() {
        assert!(valid_interface_name("eth0"));
        assert!(valid_interface_name("wlp2s0"));
        assert!(!valid_interface_name(""));
        assert!(!valid_interface_name("eth0\" drop; #"));
        assert!(!valid_interface_name("averyveryverylongname"));
    }
}
