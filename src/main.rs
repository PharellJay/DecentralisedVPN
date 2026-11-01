use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use dvpn::client::{self, ConnectOptions};
use dvpn::config::{FileConfig, default_data_dir};
use dvpn::control::{self, SharedState};
use dvpn::identity::{Identity, IdentityError};
use dvpn::install;
use dvpn::lend::{self, LendOptions, Lending};
use dvpn::node::{self, ExitConfig, Node, NodeConfig, Reachability};
use dvpn::policy::DEFAULT_BLOCKED_TCP_PORTS;
use dvpn::records::ExitKind;
use dvpn::select::Selection;
use dvpn::system;
use dvpn::tui::{self, LogBuffer, Session};
use ipnet::Ipv4Net;
use libp2p::Multiaddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Decentralised peer-to-peer VPN. Without a command, starts the dashboard (tui).")]
struct Cli {
    /// Directory holding keys, config and peer cache [default: ~/.local/share/dvpn]
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Verbose logging (peer addresses are still never logged)
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Command>,
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

/// Settings for lending your IP as an exit.
#[derive(Args)]
struct LendArgs {
    /// Confirm you understand the risks of lending your IP (needed once)
    #[arg(long)]
    accept_exit_risk: bool,
    /// Extra destination network your exit refuses (repeatable)
    #[arg(long)]
    exit_deny: Vec<Ipv4Net>,
    /// Internet-facing interface for exit traffic [default: the default route's]
    #[arg(long)]
    wan: Option<String>,
}

#[derive(Args)]
struct ConnectArgs {
    #[command(flatten)]
    net: NetworkArgs,
    #[command(flatten)]
    lend: LendArgs,
    /// Address to listen on (repeatable); others reach your exit here
    #[arg(long, default_values = ["/ip4/0.0.0.0/tcp/4001", "/ip4/0.0.0.0/udp/4001/quic-v1"])]
    listen: Vec<Multiaddr>,
    /// auto: detect with AutoNAT; public: known reachable; private: behind NAT
    #[arg(long, default_value = "auto")]
    reachability: Reachability,
    /// Maximum concurrent sessions on your exit
    #[arg(long, default_value_t = 16)]
    exit_max_sessions: usize,
    /// Bandwidth cap per session on your exit and direction, in Mbit/s (0 = unlimited)
    #[arg(long, default_value_t = 10)]
    exit_rate_mbps: u64,
    /// DNS server used through the tunnel via systemd-resolved, or "none"
    #[arg(long, default_value = "9.9.9.9")]
    dns: String,
    /// Name of the TUN device
    #[arg(long, default_value = "dvpn0")]
    tun_name: String,
    /// Pick a random exit among those with at most this round-trip time in ms,
    /// measured through test circuits. Without it, any exit is picked at random
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    max_ping: Option<u64>,
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
        #[command(flatten)]
        lend: LendArgs,
        /// Maximum concurrent exit sessions
        #[arg(long, default_value_t = 64)]
        exit_max_sessions: usize,
        /// Bandwidth cap per exit session and direction, in Mbit/s (0 = unlimited)
        #[arg(long, default_value_t = 20)]
        exit_rate_mbps: u64,
    },
    /// Route this machine's traffic through the network while lending your IP as an
    /// exit in return (needs root)
    Connect(ConnectArgs),
    /// Terminal dashboard: lend, connect and choose exits interactively (needs root)
    Tui(ConnectArgs),
    /// Show the state of the running node
    Status,
    /// Install the dvpn command to /usr/local/bin, so `dvpn` starts the dashboard from
    /// any terminal (needs root)
    Install,
    /// Remove the installed dvpn command (keys and settings are kept)
    Uninstall,
}

impl Command {
    /// Commands re-run themselves through sudo when started without root.
    fn escalates(&self) -> bool {
        matches!(self, Self::Tui(_) | Self::Install | Self::Uninstall)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    // Bare `dvpn` starts the dashboard with its default options.
    let implicit_tui = cli.command.is_none();
    if implicit_tui {
        cli = Cli::parse_from(std::env::args_os().chain(["tui".into()]));
    }
    let command = cli.command.expect("set above");
    if command.escalates() && !is_root() {
        return Err(rerun_with_sudo(implicit_tui));
    }
    // Third-party crates stay at `warn` even with --debug, since their debug output includes addresses.
    // libp2p_kad warns on every first start with an empty routing table, which is expected.
    let filter = if cli.debug { "dvpn=debug,libp2p_kad=error,warn" } else { "dvpn=info,libp2p_kad=error,warn" };
    // The TUI owns the terminal, so its log lines go to its log panel instead.
    let tui_logs = LogBuffer::default();
    if matches!(command, Command::Tui(_)) {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(tui_logs.clone())
            .with_ansi(false)
            .without_time()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(EnvFilter::new(filter)).init();
    }

    let data_dir = match cli.data_dir {
        Some(dir) => dir,
        None => default_data_dir()?,
    };

    match command {
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
            lend,
            exit_max_sessions,
            exit_rate_mbps,
        } => {
            if exit {
                confirm_exit_risk(&data_dir, lend.accept_exit_risk)?;
            }
            // Before any system changes, so a signal during setup still cleans up.
            let shutdown = system::shutdown_signal()?;
            let identity = Identity::load(&data_dir)?;
            let listener = control::bind(&data_dir).await?;
            let config = NodeConfig {
                listen: listen.clone(),
                reachability,
                relay: !no_relay,
                relay_rate_mbps,
                exit: exit.then(|| exit_config(ExitKind::Dedicated, exit_max_sessions)),
                ..network_config(&data_dir, net)?
            };
            let mut node = node::spawn(identity, config)?;
            let mut state = SharedState::default();
            let _lending = if exit {
                let lending = start_lending(&mut node, lend, listen, exit_max_sessions, exit_rate_mbps)?;
                state.lending = Some(lending.handle());
                Some(lending)
            } else {
                None
            };

            tokio::spawn(control::serve(listener, node.handle.clone(), state));
            println!("node {} running; press Ctrl-C to stop", node.handle.peer_id());
            tokio::select! {
                result = node.task => result??,
                () = shutdown => node.handle.shutdown().await?,
            }
        }
        Command::Connect(args) => {
            confirm_exit_risk(&data_dir, args.lend.accept_exit_risk)?;
            // Before any system changes, so a signal during setup still cleans up.
            let shutdown = system::shutdown_signal()?;
            let session = start_session(&data_dir, args).await?;
            let selection = *session.state.selection.lock().expect("state lock");
            println!(
                "node {} lending and connecting (exit selection: {selection}); press Ctrl-C to disconnect",
                session.node.handle.peer_id()
            );

            // Dropping the client future (on Ctrl-C or error) restores routing; dropping
            // `lending` afterwards restores the firewall.
            let Session {
                node,
                lending,
                state,
                options,
            } = session;
            let outcome = tokio::select! {
                result = client::run(node.handle.clone(), options, state) => result,
                result = node.task => result?,
                () = shutdown => Ok(()),
            };
            let _ = node.handle.shutdown().await;
            drop(lending);
            outcome?;
        }
        Command::Tui(args) => {
            // Consent is asked on the TUI's own screen; `--accept-exit-risk` skips it.
            if args.lend.accept_exit_risk && !lend::consent_given(&data_dir) {
                lend::record_consent(&data_dir)?;
            }
            // The first run creates the identity; any other problem stops us before
            // the terminal is taken over.
            match Identity::load(&data_dir) {
                Ok(_) => {}
                Err(IdentityError::NotFound(_)) => {
                    Identity::init(&data_dir)?;
                }
                Err(e) => return Err(e.into()),
            }
            tui::run(&data_dir, tui_logs, || start_session(&data_dir, args)).await?;
        }
        Command::Install => {
            let path = install::install()?;
            println!("installed {}; start the dashboard from any terminal with `dvpn`", path.display());
        }
        Command::Uninstall => match install::uninstall()? {
            true => println!("removed {}", install::INSTALL_PATH),
            false => println!("{} was not installed", install::INSTALL_PATH),
        },
        Command::Status => {
            let report = control::query(&data_dir).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

/// The effective user owns `/proc/self`.
fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

/// Replaces this process with `sudo <this binary> <same arguments>`; returns only on failure.
fn rerun_with_sudo(implicit_tui: bool) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return anyhow::Error::new(e).context("finding the running executable"),
    };
    eprintln!("dvpn needs root to set up network devices; running it with sudo");
    let mut sudo = std::process::Command::new("sudo");
    sudo.arg("--").arg(exe).args(std::env::args_os().skip(1));
    if implicit_tui {
        sudo.arg("tui");
    }
    anyhow::Error::new(sudo.exec()).context("running sudo (or run dvpn as root)")
}

/// Starts the node, lending and the status socket for `connect` and `tui`.
async fn start_session(data_dir: &Path, args: ConnectArgs) -> anyhow::Result<Session> {
    let dns = match args.dns.as_str() {
        "none" => None,
        ip => Some(ip.parse::<Ipv4Addr>().context("--dns must be an IPv4 address or \"none\"")?),
    };
    let identity = Identity::load(data_dir)?;
    let listener = control::bind(data_dir).await?;
    let config = NodeConfig {
        listen: args.listen.clone(),
        reachability: args.reachability,
        relay: false,
        relay_rate_mbps: 0,
        exit: Some(exit_config(ExitKind::User, args.exit_max_sessions)),
        ..network_config(data_dir, args.net)?
    };
    let mut node = node::spawn(identity, config)?;
    let lending = start_lending(&mut node, args.lend, args.listen, args.exit_max_sessions, args.exit_rate_mbps)?;
    let selection = match args.max_ping {
        Some(ms) => Selection::MaxPing(Duration::from_millis(ms)),
        None => Selection::Random,
    };
    let state = SharedState {
        lending: Some(lending.handle()),
        selection: Arc::new(Mutex::new(selection)),
        ..SharedState::default()
    };
    tokio::spawn(control::serve(listener, node.handle.clone(), state.clone()));
    Ok(Session {
        node,
        lending,
        state,
        options: ConnectOptions {
            tun_name: args.tun_name,
            dns,
        },
    })
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

fn exit_config(kind: ExitKind, max_sessions: usize) -> ExitConfig {
    ExitConfig {
        max_sessions,
        kind,
        blocked_tcp_ports: DEFAULT_BLOCKED_TCP_PORTS.to_vec(),
    }
}

/// Brings up lending for a node spawned with [`exit_config`].
fn start_lending(
    node: &mut Node,
    lend: LendArgs,
    listen: Vec<Multiaddr>,
    max_sessions: usize,
    rate_mbps: u64,
) -> anyhow::Result<Lending> {
    let sessions = node.exit_sessions.take().context("node has no exit")?;
    let pool = node.exit_pool.take().context("node has no exit")?;
    Lending::start(
        sessions,
        pool,
        LendOptions {
            wan: lend.wan,
            extra_deny: lend.exit_deny,
            blocked_tcp_ports: DEFAULT_BLOCKED_TCP_PORTS.to_vec(),
            rate_mbps,
            max_sessions,
            listen,
        },
    )
}

/// Requires `--accept-exit-risk` the first time an exit is enabled for this identity.
fn confirm_exit_risk(data_dir: &Path, accepted_now: bool) -> anyhow::Result<()> {
    if lend::consent_given(data_dir) {
        return Ok(());
    }
    eprintln!("{}", lend::LENDING_WARNING);
    if !accepted_now {
        bail!("to accept and lend your connection (required to use dvpn), re-run with --accept-exit-risk");
    }
    lend::record_consent(data_dir)
}
