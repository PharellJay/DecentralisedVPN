use std::io::IsTerminal;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use dvpn::client::{self, ConnectOptions};
use dvpn::config::{FileConfig, default_data_dir};
use dvpn::control::{self, Client, Phase, Request, Response, SharedState};
use dvpn::controller::{Action, Controller, Session, StartFn, View};
use dvpn::daemon::{self, Probe, SERVICE_DATA_DIR, SERVICE_SOCKET};
use dvpn::identity::{Identity, IdentityError};
use dvpn::install;
use dvpn::lend::{self, LendOptions, Lending};
use dvpn::logs::LogBuffer;
use dvpn::node::{self, ExitConfig, Node, NodeConfig, Reachability};
use dvpn::policy::DEFAULT_BLOCKED_TCP_PORTS;
use dvpn::records::ExitKind;
use dvpn::select::Selection;
use dvpn::system;
use dvpn::tui::{self, Backend};
use ipnet::Ipv4Net;
use libp2p::Multiaddr;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

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

#[derive(Args, Clone)]
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
#[derive(Args, Clone)]
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

#[derive(Args, Clone)]
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
    /// Terminal dashboard: lend, connect and choose exits interactively. Uses the dvpn
    /// service when it's installed; otherwise runs in-process (needs root)
    Tui {
        #[command(flatten)]
        args: ConnectArgs,
        /// Run in-process even if the dvpn service is installed (needs root)
        #[arg(long)]
        local: bool,
    },
    /// Run as the background service that the desktop app, `dvpn ctl` and the dashboard
    /// control (needs root; normally started by systemd). Idle until a client connects
    Daemon {
        #[command(flatten)]
        args: ConnectArgs,
        /// Control socket, unless systemd passes one [default: /run/dvpn/control.sock]
        #[arg(long, default_value = SERVICE_SOCKET)]
        socket: PathBuf,
    },
    /// Control the dvpn service from the command line
    Ctl {
        #[command(subcommand)]
        command: CtlCommand,
        /// The service's control socket
        #[arg(long, default_value = SERVICE_SOCKET)]
        socket: PathBuf,
    },
    /// Show the state of the running node (the service's, if it's installed)
    Status,
    /// Install the dvpn command to /usr/local/bin, so `dvpn` starts the dashboard from
    /// any terminal (needs root)
    Install,
    /// Remove the installed dvpn command (keys and settings are kept)
    Uninstall,
}

#[derive(Subcommand)]
enum CtlCommand {
    /// Show what the service is doing
    Status {
        /// Print the full state as JSON
        #[arg(long)]
        json: bool,
    },
    /// Lend your connection to others without connecting the VPN yourself
    Lend,
    /// Whether the service starts lending when the computer starts
    LendAtBoot {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Start lending (if needed) and connect the VPN
    Connect,
    /// Disconnect the VPN; lending keeps running
    Disconnect,
    /// Disconnect and stop lending
    Off,
    /// Pick any exit at random (the most private)
    Random,
    /// Pick a random exit among those within this round-trip time
    MaxPing {
        #[arg(value_parser = clap::value_parser!(u64).range(1..=60_000))]
        ms: u64,
    },
    /// Measure exits again
    Measure,
    /// Accept the lending terms (shown with `dvpn ctl terms`)
    AcceptExitRisk,
    /// Show the lending terms
    Terms,
    /// Remember a bootstrap peer (ending in /p2p/<peer-id>); used from the next start
    AddBootstrap { addr: String },
    /// Show the service's recent log
    Logs,
}

impl Command {
    /// Commands re-run themselves through sudo when started without root.
    fn escalates(&self) -> bool {
        matches!(self, Self::Tui { .. } | Self::Install | Self::Uninstall)
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
    // With the service installed, the dashboard is its client and needs no root.
    let service = match &command {
        Command::Tui { local: false, .. } if cli.data_dir.is_none() => daemon::probe(Path::new(SERVICE_SOCKET)).await,
        _ => Probe::Absent,
    };
    if let Probe::PermissionDenied = service {
        bail!("{}\n\nOr run the dashboard without the service: sudo dvpn tui --local", daemon::permission_help());
    }
    if command.escalates() && !is_root() && !matches!(service, Probe::Available(_)) {
        return Err(rerun_with_sudo(implicit_tui));
    }
    // Third-party crates stay at `warn` even with --debug, since their debug output includes addresses.
    // libp2p_kad warns on every first start with an empty routing table, which is expected.
    let filter = if cli.debug { "dvpn=debug,libp2p_kad=error,warn" } else { "dvpn=info,libp2p_kad=error,warn" };
    // The TUI owns the terminal, so its log lines go to its log panel instead; the
    // service logs to the journal and keeps recent lines for its clients.
    let logs = LogBuffer::default();
    let to_buffer = tracing_subscriber::fmt::layer()
        .with_writer(logs.clone())
        .with_ansi(false)
        .without_time();
    match &command {
        Command::Tui { .. } => tracing_subscriber::registry().with(to_buffer).with(EnvFilter::new(filter)).init(),
        Command::Daemon { .. } => {
            let journal = tracing_subscriber::fmt::layer().with_ansi(std::io::stdout().is_terminal());
            tracing_subscriber::registry()
                .with(to_buffer.and_then(journal))
                .with(EnvFilter::new(filter))
                .init()
        }
        _ => tracing_subscriber::fmt().with_env_filter(EnvFilter::new(filter)).init(),
    }

    let cli_had_data_dir = cli.data_dir.is_some();
    let data_dir = match (cli.data_dir, &command) {
        (Some(dir), _) => dir,
        (None, Command::Daemon { .. }) => PathBuf::from(SERVICE_DATA_DIR),
        (None, _) => default_data_dir()?,
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
            let session = start_session(&data_dir, args, true).await?;
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
                status_server: _,
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
        Command::Tui { args, .. } => {
            if let Probe::Available(stream) = service {
                // Consent is asked on the TUI's own screen; `--accept-exit-risk` skips it.
                let mut setup = Vec::new();
                if args.lend.accept_exit_risk {
                    setup.push(Action::AcceptExitRisk);
                }
                setup.extend(args.net.bootstrap.iter().map(|addr| Action::AddBootstrap { addr: addr.to_string() }));
                if let Some(ms) = args.max_ping {
                    setup.push(Action::SetSelection { max_ping_ms: Some(ms) });
                }
                tui::run(&data_dir, Backend::Service(Client::new(stream)), setup).await?;
            } else {
                if args.lend.accept_exit_risk && !lend::consent_given(&data_dir) {
                    lend::record_consent(&data_dir)?;
                }
                // Any problem with the identity stops us before the terminal is taken over.
                let controller = controller(&data_dir, args, logs, true)?;
                tui::run(&data_dir, Backend::Local(Box::new(controller)), Vec::new()).await?;
            }
        }
        Command::Daemon { args, socket } => {
            // Before any system changes, so a signal during setup still cleans up.
            let shutdown = system::shutdown_signal()?;
            if args.lend.accept_exit_risk && !lend::consent_given(&data_dir) {
                lend::record_consent(&data_dir)?;
            }
            // A previous service that crashed or was killed may have left its firewall
            // and routing rules behind; the kill switch's routes went with its device.
            if let Err(e) = lend::recover_stale_state() {
                tracing::warn!("{e:#}");
            }
            let controller = controller(&data_dir, args, logs, false)?;
            let listener = daemon::listen(&socket).await?;
            daemon::run(controller, listener, shutdown).await;
        }
        Command::Ctl { command, socket } => ctl(&socket, command).await?,
        Command::Install => {
            let path = install::install()?;
            println!("installed {}; start the dashboard from any terminal with `dvpn`", path.display());
        }
        Command::Uninstall => match install::uninstall()? {
            true => println!("removed {}", install::INSTALL_PATH),
            false => println!("{} was not installed", install::INSTALL_PATH),
        },
        Command::Status => {
            // Without --data-dir, the service's node if it runs, else this user's.
            let service = match cli_had_data_dir {
                false => daemon::probe(Path::new(SERVICE_SOCKET)).await,
                true => Probe::Absent,
            };
            let report = match service {
                Probe::Available(stream) => match Client::new(stream).send(&Request::Status).await? {
                    Response::Status(report) => *report,
                    Response::Error(e) => bail!("{e}"),
                    other => bail!("unexpected answer: {other:?}"),
                },
                Probe::PermissionDenied => bail!("{}", daemon::permission_help()),
                Probe::Absent => control::query(&data_dir).await?,
            };
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

/// A controller for the in-process dashboard (`status_socket`: it serves
/// `<data-dir>/control.sock` while lending) or the service (which has its own socket).
/// Creates the identity on first use.
fn controller(data_dir: &Path, args: ConnectArgs, logs: LogBuffer, status_socket: bool) -> anyhow::Result<Controller> {
    parse_dns(&args.dns)?; // Checked now rather than at the first connect.
    let identity = match Identity::load(data_dir) {
        Ok(identity) => identity,
        Err(IdentityError::NotFound(_)) => Identity::init(data_dir)?,
        Err(e) => return Err(e.into()),
    };
    let selection = match args.max_ping {
        Some(ms) => Selection::MaxPing(Duration::from_millis(ms)),
        None => Selection::Random,
    };
    let dir = data_dir.to_path_buf();
    let start: StartFn = Box::new(move || {
        let (dir, args) = (dir.clone(), args.clone());
        Box::pin(async move { start_session(&dir, args, status_socket).await })
    });
    Ok(Controller::new(data_dir, identity.peer_id().to_string(), selection, logs, start))
}

fn parse_dns(dns: &str) -> anyhow::Result<Option<Ipv4Addr>> {
    match dns {
        "none" => Ok(None),
        ip => Ok(Some(ip.parse::<Ipv4Addr>().context("--dns must be an IPv4 address or \"none\"")?)),
    }
}

/// Starts the node and lending for `connect`, `tui` and the service, and with
/// `status_socket` the `<data-dir>/control.sock` status socket.
async fn start_session(data_dir: &Path, args: ConnectArgs, status_socket: bool) -> anyhow::Result<Session> {
    let dns = parse_dns(&args.dns)?;
    let identity = Identity::load(data_dir)?;
    let listener = match status_socket {
        true => Some(control::bind(data_dir).await?),
        false => None,
    };
    let config = NodeConfig {
        listen: args.listen.clone(),
        reachability: args.reachability,
        relay: false,
        relay_rate_mbps: 0,
        exit: Some(exit_config(ExitKind::User, args.exit_max_sessions)),
        ..network_config(data_dir, args.net)?
    };
    let mut node = node::spawn(identity, config)?;
    let lending = match start_lending(&mut node, args.lend, args.listen, args.exit_max_sessions, args.exit_rate_mbps) {
        Ok(lending) => lending,
        Err(e) => {
            // Frees the listen ports, so the service can try again.
            let _ = node.handle.shutdown().await;
            let _ = tokio::time::timeout(Duration::from_secs(5), node.task).await;
            return Err(e);
        }
    };
    let selection = match args.max_ping {
        Some(ms) => Selection::MaxPing(Duration::from_millis(ms)),
        None => Selection::Random,
    };
    let state = SharedState {
        lending: Some(lending.handle()),
        selection: Arc::new(Mutex::new(selection)),
        ..SharedState::default()
    };
    let status_server = listener.map(|listener| tokio::spawn(control::serve(listener, node.handle.clone(), state.clone())));
    Ok(Session {
        node,
        lending,
        state,
        options: ConnectOptions {
            tun_name: args.tun_name,
            dns,
        },
        status_server,
    })
}

/// `dvpn ctl`: one request to the service.
async fn ctl(socket: &Path, command: CtlCommand) -> anyhow::Result<()> {
    if let CtlCommand::Terms = command {
        println!("{}", lend::LENDING_WARNING);
        return Ok(());
    }
    let mut client = match daemon::probe(socket).await {
        Probe::Available(stream) => Client::new(stream),
        Probe::PermissionDenied => bail!("{}", daemon::permission_help()),
        Probe::Absent => bail!("the dvpn service isn't running (start it with `sudo systemctl start dvpn`)"),
    };
    let action = match command {
        CtlCommand::Status { json } => {
            let mut view = client.view().await?;
            view.logs.clear();
            match json {
                true => println!("{}", serde_json::to_string_pretty(&view)?),
                false => print!("{}", summary(&view)),
            }
            return Ok(());
        }
        CtlCommand::Logs => {
            for line in client.view().await?.logs {
                println!("{line}");
            }
            return Ok(());
        }
        CtlCommand::Terms => unreachable!("handled above"),
        CtlCommand::Lend => Action::Lend,
        CtlCommand::LendAtBoot { state } => Action::SetLendAtBoot { enabled: state == "on" },
        CtlCommand::Connect => Action::Connect,
        CtlCommand::Disconnect => Action::Disconnect,
        CtlCommand::Off => Action::Stop,
        CtlCommand::Random => Action::SetSelection { max_ping_ms: None },
        CtlCommand::MaxPing { ms } => Action::SetSelection { max_ping_ms: Some(ms) },
        CtlCommand::Measure => Action::Measure,
        CtlCommand::AcceptExitRisk => Action::AcceptExitRisk,
        CtlCommand::AddBootstrap { addr } => Action::AddBootstrap { addr },
    };
    let needs_consent = matches!(action, Action::Connect | Action::Lend | Action::SetLendAtBoot { enabled: true });
    if needs_consent && !client.view().await?.consent_given {
        let again = match action {
            Action::Connect => "connect",
            _ => "try",
        };
        bail!(
            "using dvpn means lending your connection to others first:\n\n{}\n\n\
             To accept, run `dvpn ctl accept-exit-risk`, then {again} again.",
            lend::LENDING_WARNING
        );
    }
    client.act(action).await
}

/// `dvpn ctl status`, for people.
fn summary(view: &View) -> String {
    let lending = match (view.running, view.lending.ready) {
        (false, _) => "off".to_string(),
        (true, true) => format!("ready ({} of {} sessions)", view.lending.sessions, view.lending.max_sessions),
        (true, false) => "starting".to_string(),
    };
    let vpn = match (view.vpn.running, view.vpn.phase) {
        (false, _) => "disconnected",
        (true, Phase::Idle) => "starting",
        (true, Phase::WaitingForLending) => "waiting for lending",
        (true, Phase::Connecting) => "connecting (not protected yet)",
        (true, Phase::Connected) => "connected",
        (true, Phase::Reconnecting) => "reconnecting (traffic blocked)",
        (true, Phase::Paused) => "paused: lending is down (traffic blocked)",
    };
    let at_boot = if view.lend_at_boot { "on" } else { "off" };
    let mut out = format!("lending  {lending} (at boot: {at_boot})\nvpn      {vpn}\n");
    if let Some(c) = view.circuit_if_connected() {
        out += &format!("tunnel   {} via exit {}\n", c.assigned_ip, c.exit);
    }
    out += &format!("exits    {}\n", view.selection);
    if !view.consent_given {
        out += "\nThe lending terms haven't been accepted yet: see `dvpn ctl terms`.\n";
    }
    for warning in &view.vpn.warnings {
        out += &format!("warning  {warning}\n");
    }
    if let Some(error) = view.error.as_ref().or(view.vpn.last_error.as_ref()) {
        out += &format!("error    {error}\n");
    }
    out
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
