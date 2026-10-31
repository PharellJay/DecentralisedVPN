use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use dvpn::circuit::MTU;
use dvpn::client::{self, ConnectOptions};
use dvpn::config::{FileConfig, default_data_dir};
use dvpn::control::{self, SharedState};
use dvpn::device::TunDevice;
use dvpn::exit::{self, EXIT_TUN_ADDR, EXIT_TUN_PREFIX, ExitOptions};
use dvpn::identity::Identity;
use dvpn::node::{self, ExitConfig, NodeConfig, Reachability};
use dvpn::policy::{DEFAULT_BLOCKED_TCP_PORTS, ExitPolicy};
use dvpn::system;
use ipnet::Ipv4Net;
use libp2p::Multiaddr;
use tracing::warn;
use tracing_subscriber::EnvFilter;

const EXIT_ACK_FILE: &str = "exit-risk-accepted";
const EXIT_WARNING: &str = "\
Running an exit lends your IP address to strangers. Their traffic, including any abuse,
will appear to come from you, and you may receive complaints or legal requests about it.
The exit policy blocks private networks and SMTP, but it cannot make this risk go away.";

#[derive(Parser)]
#[command(version, about = "Decentralised peer-to-peer VPN")]
struct Cli {
    /// Directory holding keys, config and peer cache [default: ~/.local/share/dvpn]
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Verbose logging (peer addresses are still never logged)
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct NetworkArgs {
    /// Bootstrap peer, ending in /p2p/<peer-id> (repeatable)
    #[arg(long)]
    bootstrap: Vec<Multiaddr>,
    /// Disable LAN discovery via mDNS
    #[arg(long)]
    no_mdns: bool,
    /// Do not read or write the local peer cache
    #[arg(long)]
    no_peer_cache: bool,
    /// Treat loopback/private addresses as usable (LAN-only networks, local testing)
    #[arg(long)]
    allow_private_addrs: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new node identity
    Init,
    /// Join the network as a relay and, with --exit, as an exit
    Run {
        #[command(flatten)]
        net: NetworkArgs,
        /// Address to listen on (repeatable)
        #[arg(long, default_values = ["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic-v1"])]
        listen: Vec<Multiaddr>,
        /// auto: detect with AutoNAT; public: known reachable; private: behind NAT
        #[arg(long, default_value = "auto")]
        reachability: Reachability,
        /// Do not relay traffic for other peers
        #[arg(long)]
        no_relay: bool,
        /// Bandwidth cap per relayed circuit and direction, in Mbit/s (0 = unlimited)
        #[arg(long, default_value_t = 20)]
        relay_rate_mbps: u64,
        /// Act as an exit: other users' traffic leaves the internet from your IP (needs root)
        #[arg(long)]
        exit: bool,
        /// Confirm you understand the risks of running an exit (needed once)
        #[arg(long)]
        accept_exit_risk: bool,
        /// Extra destination network the exit refuses (repeatable)
        #[arg(long)]
        exit_deny: Vec<Ipv4Net>,
        /// Maximum concurrent exit sessions
        #[arg(long, default_value_t = 64)]
        exit_max_sessions: usize,
        /// Bandwidth cap per exit session and direction, in Mbit/s (0 = unlimited)
        #[arg(long, default_value_t = 20)]
        exit_rate_mbps: u64,
    },
    /// Route this machine's traffic through the network (needs root)
    Connect {
        #[command(flatten)]
        net: NetworkArgs,
        /// DNS server used through the tunnel via systemd-resolved, or "none"
        #[arg(long, default_value = "9.9.9.9")]
        dns: String,
        /// Name of the TUN device
        #[arg(long, default_value = "dvpn0")]
        tun_name: String,
    },
    /// Show the state of the running node
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Third-party crates stay at `warn` even with --debug, since their debug output includes addresses.
    // libp2p_kad warns on every first start with an empty routing table, which is expected.
    let filter = if cli.debug { "dvpn=debug,libp2p_kad=error,warn" } else { "dvpn=info,libp2p_kad=error,warn" };
    tracing_subscriber::fmt().with_env_filter(EnvFilter::new(filter)).init();

    let data_dir = match cli.data_dir {
        Some(dir) => dir,
        None => default_data_dir()?,
    };

    match cli.command {
        Command::Init => {
            let identity = Identity::init(&data_dir)?;
            println!("created identity {} in {}", identity.peer_id(), data_dir.display());
        }
        Command::Run {
            net,
            listen,
            reachability,
            no_relay,
            relay_rate_mbps,
            exit,
            accept_exit_risk,
            exit_deny,
            exit_max_sessions,
            exit_rate_mbps,
        } => {
            if exit {
                confirm_exit_risk(&data_dir, accept_exit_risk)?;
            }
            let identity = Identity::load(&data_dir)?;
            let listener = control::bind(&data_dir).await?;
            let config = NodeConfig {
                listen,
                reachability,
                relay: !no_relay,
                relay_rate_mbps,
                exit: exit.then(|| ExitConfig {
                    max_sessions: exit_max_sessions,
                    blocked_tcp_ports: DEFAULT_BLOCKED_TCP_PORTS.to_vec(),
                }),
                ..network_config(&data_dir, net)?
            };

            // Create the exit TUN before joining, so a missing privilege fails fast.
            let exit_device = if exit {
                Some(Arc::new(TunDevice::create("dvpn-exit", EXIT_TUN_ADDR, EXIT_TUN_PREFIX, MTU)?))
            } else {
                None
            };
            let mut node = node::spawn(identity, config)?;
            let mut state = SharedState::default();

            if let (Some(device), Some(sessions)) = (exit_device, node.exit_sessions.take()) {
                check_ip_forwarding();
                // Never let clients reach this host or the networks it's attached to.
                let mut deny = system::local_ipv4_networks()?;
                deny.extend(exit_deny);
                let options = Arc::new(ExitOptions {
                    policy: ExitPolicy::new(deny, DEFAULT_BLOCKED_TCP_PORTS.to_vec()),
                    rate_mbps: exit_rate_mbps,
                });
                let active = Arc::new(AtomicUsize::new(0));
                state.exit_sessions = Some(active.clone());
                tokio::spawn(exit::forward(device, sessions, options, active));
                println!("exit enabled on dvpn-exit ({EXIT_TUN_ADDR}/{EXIT_TUN_PREFIX})");
            }

            tokio::spawn(control::serve(listener, node.handle.clone(), state));
            println!("node {} running; press Ctrl-C to stop", node.handle.peer_id());
            tokio::select! {
                result = node.task => result??,
                _ = tokio::signal::ctrl_c() => node.handle.shutdown().await?,
            }
        }
        Command::Connect { net, dns, tun_name } => {
            let dns = match dns.as_str() {
                "none" => None,
                ip => Some(ip.parse::<Ipv4Addr>().context("--dns must be an IPv4 address or \"none\"")?),
            };
            let identity = Identity::load(&data_dir)?;
            let listener = control::bind(&data_dir).await?;
            let config = NodeConfig {
                listen: vec![],
                reachability: Reachability::Outbound,
                relay: false,
                relay_rate_mbps: 0,
                exit: None,
                ..network_config(&data_dir, net)?
            };
            let node = node::spawn(identity, config)?;
            let state = SharedState::default();
            tokio::spawn(control::serve(listener, node.handle.clone(), state.clone()));
            println!("node {} connecting; press Ctrl-C to disconnect", node.handle.peer_id());

            // Dropping the client future (on Ctrl-C or error) restores routing.
            let options = ConnectOptions { tun_name, dns };
            let outcome = tokio::select! {
                result = client::run(node.handle.clone(), options, state) => result,
                result = node.task => result?,
                _ = tokio::signal::ctrl_c() => Ok(()),
            };
            let _ = node.handle.shutdown().await;
            outcome?;
        }
        Command::Status => {
            let report = control::query(&data_dir).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

/// Settings shared by `run` and `connect`.
fn network_config(data_dir: &Path, net: NetworkArgs) -> anyhow::Result<NodeConfig> {
    let mut bootstrap = net.bootstrap;
    for addr in FileConfig::load(data_dir)?.bootstrap {
        bootstrap.push(addr.parse().with_context(|| format!("invalid bootstrap address {addr} in config.json"))?);
    }
    Ok(NodeConfig {
        data_dir: data_dir.to_path_buf(),
        listen: vec![],
        bootstrap,
        mdns: !net.no_mdns,
        peer_cache: !net.no_peer_cache,
        reachability: Reachability::Auto,
        relay: false,
        relay_rate_mbps: 0,
        exit: None,
        allow_private_addrs: net.allow_private_addrs,
    })
}

/// Requires `--accept-exit-risk` the first time an exit is enabled for this identity.
fn confirm_exit_risk(data_dir: &Path, accepted_now: bool) -> anyhow::Result<()> {
    let marker = data_dir.join(EXIT_ACK_FILE);
    if marker.exists() {
        return Ok(());
    }
    eprintln!("{EXIT_WARNING}");
    if !accepted_now {
        bail!("re-run with --accept-exit-risk to enable the exit");
    }
    dvpn::identity::write_private(&marker, b"accepted\n")?;
    Ok(())
}

fn check_ip_forwarding() {
    let enabled = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|v| v.trim() == "1");
    if !enabled {
        warn!("IPv4 forwarding is off; run scripts/exit-setup.sh <wan-interface> so exit traffic can leave");
    }
}
