use std::io::IsTerminal;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use dvpn::client::{self, ConnectOptions};
use dvpn::config::{FileConfig, default_data_dir};
use dvpn::control::{self, Client, Request, Response, SharedState};
use dvpn::controller::{Controller, KillSwitchGuard, Session, StartFn};
use dvpn::daemon::{self, Probe, SERVICE_DATA_DIR, SERVICE_SOCKET};
use dvpn::identity::{self, Identity};
use dvpn::lend::{self, LendOptions, Lending};
use dvpn::logs::LogBuffer;
use dvpn::node::{self, ExitConfig, Node, NodeConfig, Reachability};
use dvpn::policy::{DEFAULT_BLOCKED_TCP_PORTS, Ports};
use dvpn::records::ExitKind;
use dvpn::dns::DnsOverTls;
use dvpn::platform::service::shutdown_signal;
use dvpn::platform::{self, tunnel::KillSwitch};
use dvpn::select::Selection;
use ipnet::Ipv4Net;
use libp2p::Multiaddr;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

#[derive(Parser)]
#[command(
    version,
    about = "The dvpn service, used by the dvpn app. Not meant to be run by hand: systemd starts \
             `daemon`, and the other commands are for servers (bootstrap peers, dedicated exits) \
             and the end-to-end tests."
)]
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

#[derive(Args, Clone)]
struct NetworkArgs {
    /// Bootstrap peer, ending in /p2p/<peer-id> (repeatable)
    #[arg(long)]
    bootstrap: Vec<Multiaddr>,
    /// Find peers on the local network via mDNS. Off by default: it announces this
    /// computer to everyone on the network
    #[arg(long)]
    mdns: bool,
    /// Do not read or write the local peer cache
    #[arg(long)]
    no_peer_cache: bool,
    /// Treat loopback/private addresses as usable (LAN-only networks, local testing)
    #[arg(long)]
    allow_private_addrs: bool,
    /// UDP port for sending circuits' packets as datagrams (0: any free port). Relays
    /// must be reachable on it; if it's taken, any free port is used
    #[arg(long, default_value_t = dvpn::datagram::DEFAULT_PORT)]
    datagram_port: u16,
    /// Carry circuits' packets over streams only (no UDP datagram path)
    #[arg(long)]
    no_datagrams: bool,
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
    /// Encrypt DNS through the tunnel (DNS-over-TLS), so the exit can't read it:
    /// yes, opportunistic or no
    #[arg(long, default_value = "yes")]
    dns_over_tls: DnsOverTls,
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
    /// Generate a stable node identity, for `run` (bootstrap peers, dedicated exits).
    /// `connect` and `daemon` use a new identity for every session instead
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
        /// With --exit: serve a web page on this machine's address explaining that it's a
        /// dvpn exit, for whoever looks it up after seeing traffic from it
        #[arg(long, requires = "exit")]
        exit_notice: bool,
        /// Contact for the exit notice (e.g. an abuse address)
        #[arg(long, requires = "exit_notice")]
        exit_contact: Option<String>,
        /// Where the exit notice is served
        #[arg(long, default_value = "0.0.0.0:80", requires = "exit_notice")]
        exit_notice_listen: std::net::SocketAddr,
    },
    /// Route this machine's traffic through the network while lending your IP as an
    /// exit in return (needs root)
    Connect(ConnectArgs),
    /// Run as the background service that the desktop app controls (needs CAP_NET_ADMIN;
    /// started by systemd). Idle until the app asks it to lend or connect
    Daemon {
        #[command(flatten)]
        args: ConnectArgs,
        /// Control socket, unless systemd passes one [default: /run/dvpn/control.sock]
        #[arg(long, default_value = SERVICE_SOCKET)]
        socket: PathBuf,
    },
    /// Show the state of the running node (the service's, if it's installed)
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = cli.command;
    // Third-party crates stay at `warn` even with --debug, since their debug output includes addresses.
    // libp2p_kad warns on every first start with an empty routing table, which is expected.
    let filter = if cli.debug { "dvpn=debug,libp2p_kad=error,warn" } else { "dvpn=info,libp2p_kad=error,warn" };
    // The service keeps recent lines in memory for the app. The journal is written to
    // disk, so it only gets warnings: info lines tell when the VPN was used and through
    // which peers, which shouldn't outlive the session (--debug sends everything).
    let logs = LogBuffer::default();
    match &command {
        Command::Daemon { .. } => {
            let to_buffer = tracing_subscriber::fmt::layer()
                .with_writer(logs.clone())
                .with_ansi(false)
                .without_time()
                .with_filter(EnvFilter::new(filter));
            let journal_filter = if cli.debug { filter } else { "warn,libp2p_kad=error" };
            let journal = tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stdout().is_terminal())
                .with_filter(EnvFilter::new(journal_filter));
            tracing_subscriber::registry().with(to_buffer).with(journal).init()
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
            exit_notice,
            exit_contact,
            exit_notice_listen,
        } => {
            if exit {
                confirm_exit_risk(&data_dir, lend.accept_exit_risk)?;
            }
            // Bound first: a port that's taken or needs root fails before anything starts.
            let notice = match exit_notice {
                true => Some(dvpn::notice::bind(exit_notice_listen).await?),
                false => None,
            };
            // Before any system changes, so a signal during setup still cleans up.
            let shutdown = shutdown_signal()?;
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
                let lending =
                    start_lending(&mut node, ExitKind::Dedicated, lend, listen, exit_max_sessions, exit_rate_mbps)?;
                lend::watch_own_addresses(node.handle.clone(), lending.handle());
                state.lending = Some(lending.handle());
                Some(lending)
            } else {
                None
            };

            tokio::spawn(control::serve(listener, node.handle.clone(), state));
            if let Some(notice) = notice {
                tokio::spawn(dvpn::notice::serve(notice, dvpn::notice::page(exit_contact.as_deref())));
            }
            println!("node {} running; press Ctrl-C to stop", node.handle.peer_id());
            tokio::select! {
                result = node.task => result??,
                () = shutdown => node.handle.shutdown().await?,
            }
        }
        Command::Connect(args) => {
            identity::ensure_data_dir(&data_dir)?;
            confirm_exit_risk(&data_dir, args.lend.accept_exit_risk)?;
            // Before any system changes, so a signal during setup still cleans up.
            let shutdown = shutdown_signal()?;
            let session = start_session(&data_dir, args, true).await?;
            // Blocks traffic outside the tunnel from now until Ctrl-C (dropped last).
            let kill_switch = KillSwitch::install(&session.options.tun_name)?;
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
            drop(kill_switch);
            drop(lending);
            outcome?;
        }
        Command::Daemon { args, socket } => {
            // Before any system changes, so a signal during setup still cleans up.
            let shutdown = shutdown_signal()?;
            if args.lend.accept_exit_risk && !lend::consent_given(&data_dir) {
                lend::record_consent(&data_dir)?;
            }
            // A previous service that crashed or was killed may have left its firewall
            // and routing rules behind; the kill switch's routes went with its device.
            if let Err(e) = platform::exit::recover_stale_state() {
                tracing::warn!("{e:#}");
            }
            // A kill switch left behind means it crashed while connected: keep blocking
            // and connect again, rather than silently unprotecting the user.
            let resume = platform::tunnel::kill_switch_left_behind();
            if !resume {
                platform::tunnel::recover_stale_state();
            }
            let mut controller = controller(&data_dir, args, logs)?;
            if resume {
                controller.resume_after_crash();
            }
            let listener = daemon::listen(&socket).await?;
            daemon::run(controller, listener, shutdown).await;
        }
        Command::Status => {
            // Without --data-dir, the service's node if it runs, else this user's.
            let service = match cli_had_data_dir {
                false => daemon::probe(Path::new(SERVICE_SOCKET)).await,
                true => Probe::Absent,
            };
            let report = match service {
                Probe::Available(stream) => match Client::new(stream).send(&Request::Status).await? {
                    Response::Status(report) => *report,
                    Response::Error(e) | Response::Denied(e) => bail!("{e}"),
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

/// The service's controller.
fn controller(data_dir: &Path, args: ConnectArgs, logs: LogBuffer) -> anyhow::Result<Controller> {
    parse_dns(&args.dns)?; // Checked now rather than at the first connect.
    identity::ensure_data_dir(data_dir)?;
    let selection = match args.max_ping {
        Some(ms) => Selection::MaxPing(Duration::from_millis(ms)),
        None => Selection::Random,
    };
    let tun_name = args.tun_name.clone();
    let dir = data_dir.to_path_buf();
    let start: StartFn = Box::new(move || {
        let (dir, args) = (dir.clone(), args.clone());
        // The service has its own socket, so no `<data-dir>/control.sock`.
        Box::pin(async move { start_session(&dir, args, false).await })
    });
    let kill_switch = Box::new(move || {
        let switch = KillSwitch::install(&tun_name)?;
        Ok(KillSwitchGuard {
            filters_output: switch.filters_output(),
            warnings: switch.warnings.clone(),
            blocker: Box::new(switch),
        })
    });
    Ok(Controller::new(data_dir, selection, logs, start).with_kill_switch(kill_switch))
}

fn parse_dns(dns: &str) -> anyhow::Result<Option<Ipv4Addr>> {
    match dns {
        "none" => Ok(None),
        ip => Ok(Some(ip.parse::<Ipv4Addr>().context("--dns must be an IPv4 address or \"none\"")?)),
    }
}

/// Starts the node and lending for `connect` and the service, and with
/// `status_socket` the `<data-dir>/control.sock` status socket. Every session is a new
/// node to the network: a fresh identity, so it can't be linked to earlier ones.
async fn start_session(data_dir: &Path, args: ConnectArgs, status_socket: bool) -> anyhow::Result<Session> {
    let dns = parse_dns(&args.dns)?;
    let identity = Identity::ephemeral()?;
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
    let lending = match start_lending(
        &mut node,
        ExitKind::User,
        args.lend,
        args.listen,
        args.exit_max_sessions,
        args.exit_rate_mbps,
    ) {
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
    lend::watch_own_addresses(node.handle.clone(), lending.handle());
    let status_server = listener.map(|listener| tokio::spawn(control::serve(listener, node.handle.clone(), state.clone())));
    Ok(Session {
        node,
        lending,
        state,
        options: ConnectOptions {
            tun_name: args.tun_name,
            dns,
            dns_over_tls: args.dns_over_tls,
        },
        status_server,
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
        mdns: net.mdns,
        peer_cache: !net.no_peer_cache,
        reachability: Reachability::Auto,
        relay: false,
        relay_rate_mbps: 0,
        exit: None,
        allow_private_addrs: net.allow_private_addrs,
        datagram_port: (!net.no_datagrams).then_some(net.datagram_port),
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
    kind: ExitKind,
    lend: LendArgs,
    listen: Vec<Multiaddr>,
    max_sessions: usize,
    rate_mbps: u64,
) -> anyhow::Result<Lending> {
    let sessions = node.exit_sessions.take().context("node has no exit")?;
    let pool = node.exit_pool.take().context("node has no exit")?;
    // Our datagrams to relays bypass our own tunnel, like replies from the listen ports.
    let mut listen = listen;
    if let Some(port) = node.handle.datagram_port() {
        listen.push(format!("/ip4/0.0.0.0/udp/{port}").parse().expect("valid multiaddr"));
    }
    Lending::start(
        sessions,
        pool,
        LendOptions {
            wan: lend.wan,
            extra_deny: lend.exit_deny,
            ports: Ports::for_kind(kind),
            rate_mbps,
            max_sessions,
            listen,
            // Users' exits carry a handful of sessions; servers spread theirs over cores.
            tun_queues: match kind {
                ExitKind::User => 1,
                ExitKind::Dedicated => std::thread::available_parallelism().map_or(1, |n| n.get().min(4)),
            },
        },
    )
}

/// Requires `--accept-exit-risk` the first time an exit is enabled for this identity.
fn confirm_exit_risk(data_dir: &Path, accepted_now: bool) -> anyhow::Result<()> {
    if lend::consent_given(data_dir) {
        return Ok(());
    }
    eprintln!("{}", lend::LENDING_WARNING);
    eprintln!(
        "\nA dedicated exit (`run --exit`) carries more: every port except SMTP (TCP 25), \
         and protocols other than TCP, UDP and ICMP.\n"
    );
    if !accepted_now {
        bail!("to accept and lend your connection (required to use dvpn), re-run with --accept-exit-risk");
    }
    lend::record_consent(data_dir)
}
