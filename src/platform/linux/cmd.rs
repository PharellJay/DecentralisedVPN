//! Running `ip`, `nft` and `resolvectl`. Route, rule and address changes need root.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

pub fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    run_with_stdin(program, args, None)
}

/// Like [`run`], feeding `stdin` to the program (e.g. a ruleset to `nft -f -`).
///
/// Waiting for the program blocks the thread. On a Tokio worker the runtime first moves
/// its other tasks elsewhere, so the node and the control socket keep running meanwhile.
pub fn run_with_stdin(program: &str, args: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| run_blocking(program, args, stdin))
        }
        // No runtime, or a single-threaded one (tests), where there is nothing to move.
        _ => run_blocking(program, args, stdin),
    }
}

fn run_blocking(program: &str, args: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not run {program}"))?;
    if let Some(input) = stdin {
        child.stdin.take().expect("piped stdin").write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        // Arguments can hold peers' addresses (an entry relay's route), and this message
        // can reach the logs and the app.
        let message = format!("`{program} {}` failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        bail!("{}", crate::addrs::redact_ips(&message));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

