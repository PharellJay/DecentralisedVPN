//! `dvpn tui`: a terminal dashboard to lend, connect and choose exits.
//!
//! It runs in one of two ways:
//! - **as a client of the dvpn service** (`dvpn daemon`), when the service is installed:
//!   no root needed, and closing the dashboard leaves the VPN as it is;
//! - **in-process** (`sudo dvpn tui`), when it isn't: lending runs for the whole session,
//!   and quitting disconnects and restores the network.
//!
//! Either way the VPN is started and stopped with keys. With the service, lending can also
//! be started on its own, without connecting. The exit selection mode can be
//! changed at any time, and in max-ping mode the dashboard shows how many measured exits
//! fit the limit before you connect.
//!
//! Rendering is a pure function of [`View`], so it is tested without a terminal.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tracing::{info, warn};

use crate::control::{Client, Phase};
use crate::controller::{Action, Controller, PING_STEP, View, VpnView, selection_action};
use crate::install::{self, INSTALL_PATH};
use crate::lend::{self, LENDING_WARNING};
use crate::node::NatState;
use crate::records::now_secs;
use crate::select::{Availability, Selection};
use crate::system;

const TICK: Duration = Duration::from_millis(250);

/// Where the dashboard's state comes from and its actions go.
pub enum Backend {
    /// This process lends and connects itself (needs root).
    Local(Box<Controller>),
    /// The dvpn service does, and this process only shows and asks.
    Service(Client),
}

impl Backend {
    fn is_service(&self) -> bool {
        matches!(self, Self::Service(_))
    }

    async fn act(&mut self, action: Action) -> anyhow::Result<()> {
        match self {
            Self::Local(controller) => controller.act(action).await,
            Self::Service(client) => client.act(action).await,
        }
    }

    async fn view(&mut self) -> anyhow::Result<View> {
        match self {
            Self::Local(controller) => {
                controller.poll().await;
                controller.view().await
            }
            Self::Service(client) => client.view().await.context("lost the connection to the dvpn service"),
        }
    }
}

/// The first-run screen: lending is required to use the VPN.
pub fn draw_consent(frame: &mut Frame) {
    let area = frame.area();
    let mut lines = vec![
        Line::from("Using dvpn means lending your connection to other users while you use theirs.".bold()),
        Line::from(""),
    ];
    lines.extend(LENDING_WARNING.lines().map(Line::from));
    lines.extend([
        Line::from(""),
        Line::from(vec![key("y"), " accept and continue   ".into(), key("q"), " quit".into()]),
    ]);
    let block = Block::bordered().title(" dvpn: lending your connection ".bold());
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), area);
}

/// Offered once, after consent: install the command so the TUI starts from anywhere.
pub fn draw_install_offer(frame: &mut Frame) {
    let lines = vec![
        Line::from("Install the dvpn command?".bold()),
        Line::from(""),
        Line::from(format!("This copies dvpn to {INSTALL_PATH}, so from any terminal you can start")),
        Line::from(vec!["this dashboard by typing ".into(), "dvpn".bold(), " (it asks for your password via sudo).".into()]),
        Line::from(""),
        Line::from(vec![
            key("y"),
            " install   ".into(),
            key("n"),
            " not now (won't ask again; ".into(),
            "sudo dvpn install".bold(),
            " does it later)".into(),
        ]),
    ];
    let block = Block::bordered().title(" dvpn ".bold());
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block), frame.area());
}

pub fn draw_starting(frame: &mut Frame, message: &str) {
    let block = Block::bordered().title(" dvpn ".bold());
    frame.render_widget(Paragraph::new(message).block(block), frame.area());
}

/// The dashboard. `service`: shown as a client of the dvpn service, where closing it
/// leaves the VPN running.
pub fn draw(frame: &mut Frame, view: &View, service: bool) {
    let [header, top, selection, logs, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(9),
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let [lending, vpn] = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(top);

    let nat = match (view.running, view.nat) {
        (false, _) => "off",
        (true, NatState::Unknown) => "detecting",
        (true, NatState::Public) => "public",
        (true, NatState::Private) => "behind NAT",
    };
    let source = if service { "  ·  service" } else { "" };
    frame.render_widget(
        Line::from(vec![
            " dvpn ".bold().reversed(),
            format!("  you {}  ·  NAT: {nat}  ·  {} peers{source}", short(&view.peer_id), view.routing_peers).into(),
        ]),
        header,
    );
    frame.render_widget(lending_panel(view, service), lending);
    frame.render_widget(vpn_panel(&view.vpn), vpn);
    frame.render_widget(selection_panel(view), selection);
    frame.render_widget(log_panel(&view.logs, logs), logs);
    let mut keys = Vec::new();
    if service && !view.running {
        keys.extend([key("l"), " lend only  ".into()]);
    }
    keys.extend([
        key("c"),
        " connect  ".into(),
        key("d"),
        " disconnect  ".into(),
        key("m"),
        " mode  ".into(),
        key("+/-"),
        " ping limit  ".into(),
        key("r"),
        " measure  ".into(),
    ]);
    if service {
        keys.extend([key("x"), " turn off  ".into(), key("q"), " close (VPN keeps running)".into()]);
    } else {
        keys.extend([key("q"), " quit".into()]);
    }
    frame.render_widget(Line::from(keys), footer);
}

fn lending_panel(view: &View, service: bool) -> Paragraph<'static> {
    let l = &view.lending;
    if !view.running {
        let mut lines = if service {
            vec![
                Line::from(vec!["○ Off  ".dim(), "press ".dim(), key("l"), " to lend without connecting".dim()]),
                Line::from(vec!["Connecting (".dim(), key("c"), ") lends too.".dim()]),
            ]
        } else {
            vec![
                Line::from(vec!["○ Off  ".dim(), "starts when you press ".dim(), key("c")]),
                Line::from("Your exit is lent only while dvpn runs.".dim()),
            ]
        };
        if service {
            lines.push(at_boot_line(view));
        }
        if let Some(error) = &view.error {
            lines.push(Line::from(format!("Stopped: {error}").fg(Color::Red)));
        }
        return Paragraph::new(lines).wrap(Wrap { trim: true }).block(Block::bordered().title(" Lending "));
    }
    let status = if l.ready {
        Line::from("● Lending: others can use your exit".fg(Color::Green).bold())
    } else if !l.published {
        Line::from("◌ Starting: publishing your exit…".fg(Color::Yellow))
    } else {
        Line::from("◌ Published, not reachable yet".fg(Color::Yellow))
    };
    let reachable = if l.publicly_reachable {
        "directly".to_string()
    } else if l.relay_reservations > 0 {
        format!("through {} relay{}", l.relay_reservations, plural(l.relay_reservations))
    } else {
        "not yet".to_string()
    };
    let mut lines = vec![
        status,
        Line::from(format!("Reachable  {reachable}")),
        Line::from(format!("Sessions   {} / {}", l.sessions, l.max_sessions)),
        Line::from(format!("Limit      {} Mbit/s per session", l.rate_mbps)),
        Line::from(format!("WAN        {}", l.wan)),
    ];
    if service {
        lines.push(at_boot_line(view));
    }
    Paragraph::new(lines).wrap(Wrap { trim: true }).block(Block::bordered().title(" Lending "))
}

/// Whether the service lends from boot, and the key that changes it.
fn at_boot_line(view: &View) -> Line<'static> {
    let state = if view.lend_at_boot { "on".fg(Color::Green) } else { "off".dim() };
    Line::from(vec!["At boot    ".into(), state, "  ".into(), key("b"), " change".dim()])
}

fn vpn_panel(v: &VpnView) -> Paragraph<'static> {
    let status = match (v.running, v.phase) {
        (false, _) => Line::from(vec!["○ Disconnected  ".dim(), "press ".dim(), key("c"), " to connect".dim()]),
        (true, Phase::Idle) => Line::from("◌ Starting…".fg(Color::Yellow)),
        (true, Phase::WaitingForLending) => Line::from("◌ Waiting for your exit to be lent first".fg(Color::Yellow)),
        (true, Phase::Connecting) => Line::from("◌ Connecting…".fg(Color::Yellow)),
        (true, Phase::Connected) => Line::from("● Connected".fg(Color::Green).bold()),
        (true, Phase::Reconnecting) => Line::from("◌ Reconnecting: traffic is blocked".fg(Color::Yellow)),
        (true, Phase::Paused) => Line::from("■ Paused: lending is down, traffic is blocked".fg(Color::Red).bold()),
    };
    let mut lines = vec![status];
    if v.running && !v.protected {
        lines.push(Line::from("Not protected yet: traffic goes out normally until the first connection".fg(Color::Yellow)));
    }
    if let Some(c) = v.circuit.as_ref().filter(|_| v.running) {
        let kind = if c.exit_is_user { "another user's" } else { "dedicated" };
        let up = now_secs().saturating_sub(c.connected_since);
        lines.extend([
            Line::from(format!("Exit       {} ({kind})", short(&c.exit))),
            Line::from(format!("Relay      {}", short(&c.relay))),
            Line::from(format!("Tunnel IP  {}  ·  up {}", c.assigned_ip, hms(up))),
        ]);
    }
    for warning in &v.warnings {
        lines.push(Line::from(format!("⚠ {warning}").fg(Color::Yellow)));
    }
    if let Some(error) = &v.last_error {
        lines.push(Line::from(format!("Last error: {error}").fg(Color::Red)));
    }
    Paragraph::new(lines).wrap(Wrap { trim: true }).block(Block::bordered().title(" VPN "))
}

fn selection_panel(view: &View) -> Paragraph<'static> {
    let mode = match view.selection {
        Selection::Random => Line::from(vec![
            "Mode  ".into(),
            "random".bold(),
            ": any exit, most private".into(),
        ]),
        Selection::MaxPing(limit) => Line::from(vec![
            "Mode  ".into(),
            format!("max ping {} ms", limit.as_millis()).bold(),
            ": a random exit within the limit".into(),
        ]),
    };
    let detail = match (view.selection, view.measuring, view.availability) {
        (Selection::Random, _, _) => Line::from("Other users' exits are used only if no dedicated exit works.".dim()),
        (Selection::MaxPing(_), true, _) => Line::from("Measuring exits through test circuits…".fg(Color::Yellow)),
        (Selection::MaxPing(_), false, None) => Line::from(vec!["Not measured yet: press ".into(), key("r")]),
        (Selection::MaxPing(limit), false, Some(a)) => availability_line(limit, a),
    };
    let mut lines = vec![mode, detail];
    if view.measured_while_connected && view.availability.is_some() {
        lines.push(Line::from("Measured while connected: some times may read high; press r after disconnecting to re-check".dim()));
    }
    Paragraph::new(lines).wrap(Wrap { trim: true }).block(Block::bordered().title(" Exit selection "))
}

fn availability_line(limit: Duration, a: Availability) -> Line<'static> {
    let ms = limit.as_millis();
    if a.measured == 0 {
        return Line::from("No exit could be measured yet; press r to try again".fg(Color::Yellow));
    }
    let fastest = a.fastest_ms.map(|f| format!(", fastest {f} ms")).unwrap_or_default();
    let counts = format!(
        "Within {ms} ms: {} dedicated · {} lent by users  ({} measured{fastest})",
        a.dedicated, a.user, a.measured
    );
    match (a.dedicated, a.user) {
        (0, 0) => Line::from(format!("No exit within {ms} ms ({} measured{fastest}): raise the limit or use random", a.measured).fg(Color::Red)),
        (0, _) => Line::from(vec![counts.into(), "  → would use another user's exit".fg(Color::Yellow)]),
        _ => Line::from(counts.fg(Color::Green)),
    }
}

fn log_panel(logs: &[String], area: Rect) -> Paragraph<'static> {
    let visible = area.height.saturating_sub(2) as usize;
    let tail = &logs[logs.len().saturating_sub(visible)..];
    let lines: Vec<Line> = tail.iter().map(|l| Line::from(l.clone()).dim()).collect();
    Paragraph::new(lines).block(Block::bordered().title(" Log "))
}

fn key(k: &'static str) -> Span<'static> {
    Span::styled(k, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// `12D3Ko…4FNU`: enough to tell peers apart on screen.
fn short(peer: &str) -> String {
    if peer.len() <= 12 {
        return peer.to_string();
    }
    format!("{}…{}", &peer[..6], &peer[peer.len() - 4..])
}

fn hms(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

// ------------------------------------------------------------------ app

/// Runs the dashboard until the user quits (or, for the service, closes it).
pub async fn run(data_dir: &Path, backend: Backend, setup: Vec<Action>) -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    let result = run_in(&mut terminal, data_dir, backend, setup).await;
    ratatui::restore();
    result
}

async fn run_in(terminal: &mut DefaultTerminal, data_dir: &Path, mut backend: Backend, setup: Vec<Action>) -> anyhow::Result<()> {
    // Before any system changes: closing the terminal (SIGHUP) or SIGTERM must still
    // lead to a clean shutdown rather than leftover routes and firewall rules.
    let shutdown = system::shutdown_signal()?;
    tokio::pin!(shutdown);
    let mut events = EventStream::new();

    let consent_given = match &mut backend {
        Backend::Local(_) => lend::consent_given(data_dir),
        Backend::Service(client) => client.view().await?.consent_given,
    };
    if !consent_given {
        loop {
            terminal.draw(draw_consent)?;
            match next_key(&mut events).await? {
                KeyCode::Char('y') | KeyCode::Char('Y') => break,
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                _ => {}
            }
        }
        backend.act(Action::AcceptExitRisk).await?;
    }
    for action in setup {
        backend.act(action).await?;
    }

    if let Backend::Local(controller) = &mut backend {
        if !install::is_installed() && !install::declined(data_dir) {
            loop {
                terminal.draw(draw_install_offer)?;
                match next_key(&mut events).await? {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        // Shown in the log panel; a failure doesn't stop the VPN.
                        match install::install() {
                            Ok(path) => info!("installed {}: start dvpn from any terminal by typing `dvpn`", path.display()),
                            Err(e) => warn!("could not install the dvpn command: {e:#}"),
                        }
                        break;
                    }
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                        install::record_declined(data_dir)?;
                        break;
                    }
                    KeyCode::Char('q') => return Ok(()),
                    _ => {}
                }
            }
        }
        // In-process, lending runs for the whole session.
        terminal.draw(|f| draw_starting(f, "Starting your node and exit…"))?;
        controller.start().await?;
    }

    let service = backend.is_service();
    let mut notice: Option<String> = None;
    let mut view = backend.view().await?;
    let mut tick = tokio::time::interval(TICK);
    let result = loop {
        let mut quit = false;
        tokio::select! {
            _ = tick.tick() => {}
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => match command(key, &view, service) {
                    Command::Quit => quit = true,
                    Command::Act(action) => {
                        notice = backend.act(action).await.err().map(|e| format!("{e:#}"));
                    }
                    Command::None => {}
                },
                Some(Ok(_)) => {}
                Some(Err(e)) => break Err(e).context("reading terminal input"),
                None => break Ok(()),
            },
            () = &mut shutdown => quit = true,
        }
        if quit {
            break Ok(());
        }
        view = match backend.view().await {
            Ok(view) => view,
            Err(e) => break Err(e),
        };
        if let Some(notice) = &notice {
            view.error = Some(notice.clone());
        }
        // The terminal may be gone (window closed): stop drawing, but still shut down.
        if let Err(e) = terminal.draw(|f| draw(f, &view, service)) {
            break Err(e).context("drawing the dashboard");
        }
    };

    if let Backend::Local(mut controller) = backend {
        let _ = terminal.draw(|f| draw_starting(f, "Disconnecting and restoring your network…"));
        controller.stop().await;
    }
    result
}

enum Command {
    Act(Action),
    Quit,
    None,
}

fn command(key: KeyEvent, view: &View, service: bool) -> Command {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let step = PING_STEP.as_millis() as i64;
    match key.code {
        KeyCode::Char('c') if ctrl => Command::Quit,
        KeyCode::Char('q') | KeyCode::Esc => Command::Quit,
        KeyCode::Char('c') => Command::Act(Action::Connect),
        KeyCode::Char('l') if service => Command::Act(Action::Lend),
        KeyCode::Char('b') if service => Command::Act(Action::SetLendAtBoot { enabled: !view.lend_at_boot }),
        KeyCode::Char('d') => Command::Act(Action::Disconnect),
        KeyCode::Char('x') if service => Command::Act(Action::Stop),
        KeyCode::Char('m') => Command::Act(selection_action(view.toggled_selection())),
        KeyCode::Char('+') | KeyCode::Char('=') => view.adjusted_selection(step).map_or(Command::None, |s| Command::Act(selection_action(s))),
        KeyCode::Char('-') => view.adjusted_selection(-step).map_or(Command::None, |s| Command::Act(selection_action(s))),
        KeyCode::Char('r') => Command::Act(Action::Measure),
        _ => Command::None,
    }
}

async fn next_key(events: &mut EventStream) -> anyhow::Result<KeyCode> {
    loop {
        match events.next().await {
            Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    return Ok(KeyCode::Char('q'));
                }
                return Ok(key.code);
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e.into()),
            None => return Ok(KeyCode::Char('q')),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::CircuitReport;
    use crate::controller::LendingView;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(f: impl FnOnce(&mut Frame)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
        terminal.draw(f).unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn view() -> View {
        View {
            peer_id: "12D3KooWAbCdEfGhIjKlMnOpQrStUvWxYz".into(),
            consent_given: true,
            lend_at_boot: false,
            running: true,
            error: None,
            nat: NatState::Private,
            routing_peers: 5,
            lending: LendingView {
                ready: true,
                published: true,
                publicly_reachable: false,
                relay_reservations: 1,
                sessions: 2,
                max_sessions: 16,
                rate_mbps: 10,
                wan: "eth0".into(),
            },
            vpn: VpnView::default(),
            selection: Selection::Random,
            ping_limit_ms: 100,
            measuring: false,
            availability: None,
            measured_while_connected: false,
            logs: vec!["INFO lending is ready".into()],
        }
    }

    #[test]
    fn consent_screen_explains_lending_and_offers_a_way_out() {
        let screen = render(draw_consent);
        assert!(screen.contains("lending your connection to other users"));
        // Calm, but the risk is still stated.
        assert!(screen.contains("complaints may reach you first"));
        assert!(screen.contains("keeps no logs"));
        assert!(screen.contains("accept and continue"));
        assert!(screen.contains("quit"));
    }

    #[test]
    fn install_offer_says_where_and_how_to_decline() {
        let screen = render(draw_install_offer);
        assert!(screen.contains("/usr/local/bin/dvpn"));
        assert!(screen.contains("by typing dvpn"));
        assert!(screen.contains("not now"));
    }

    #[test]
    fn dashboard_shows_lending_and_a_disconnected_vpn() {
        let screen = render(|f| draw(f, &view(), false));
        assert!(screen.contains("Lending: others can use your exit"));
        assert!(screen.contains("through 1 relay"));
        assert!(screen.contains("Sessions   2 / 16"));
        assert!(screen.contains("Disconnected"));
        assert!(screen.contains("random"));
        assert!(screen.contains("12D3Ko…WxYz"));
        assert!(screen.contains("lending is ready"), "log lines are shown");
    }

    #[test]
    fn dashboard_shows_waiting_for_lending() {
        let mut v = view();
        v.lending.ready = false;
        v.lending.published = false;
        v.vpn.running = true;
        v.vpn.phase = Phase::WaitingForLending;
        let screen = render(|f| draw(f, &v, false));
        assert!(screen.contains("Starting: publishing your exit"));
        assert!(screen.contains("Waiting for your exit to be lent first"));
        assert!(screen.contains("Not protected yet"), "no kill switch before the first circuit");
    }

    #[test]
    fn dashboard_shows_the_circuit_when_connected() {
        let mut v = view();
        v.vpn.running = true;
        v.vpn.phase = Phase::Connected;
        v.vpn.protected = true;
        v.vpn.warnings = vec!["DNS may go to your local resolver".into()];
        v.vpn.circuit = Some(CircuitReport {
            relay: "12D3KooWRelayRelayRelayRelay1234".into(),
            exit: "12D3KooWExitExitExitExitExit9876".into(),
            exit_is_user: false,
            assigned_ip: "10.77.12.3".into(),
            connected_since: now_secs() - 3725,
        });
        let screen = render(|f| draw(f, &v, false));
        assert!(screen.contains("● Connected"));
        assert!(screen.contains("12D3Ko…9876 (dedicated)"));
        assert!(screen.contains("10.77.12.3"));
        assert!(screen.contains("up 01:02:0"), "uptime is shown");
        assert!(!screen.contains("Not protected yet"));
        assert!(screen.contains("⚠ DNS may go to your local resolver"));
    }

    #[test]
    fn dashboard_shows_a_pause_as_blocked() {
        let mut v = view();
        v.vpn.running = true;
        v.vpn.phase = Phase::Paused;
        v.vpn.protected = true;
        v.vpn.last_error = Some("lending is down".into());
        let screen = render(|f| draw(f, &v, false));
        assert!(screen.contains("Paused: lending is down, traffic is blocked"));
        assert!(screen.contains("Last error: lending is down"));
    }

    #[test]
    fn max_ping_mode_shows_how_many_exits_fit() {
        let mut v = view();
        v.selection = Selection::MaxPing(Duration::from_millis(80));
        let fits = |dedicated, user| Availability {
            dedicated,
            user,
            measured: 6,
            fastest_ms: Some(23),
        };

        v.availability = Some(fits(3, 1));
        let screen = render(|f| draw(f, &v, false));
        assert!(screen.contains("max ping 80 ms"));
        assert!(screen.contains("Within 80 ms: 3 dedicated · 1 lent by users  (6 measured, fastest 23 ms)"));

        v.availability = Some(fits(0, 2));
        assert!(render(|f| draw(f, &v, false)).contains("would use another user's exit"));

        v.availability = Some(fits(0, 0));
        assert!(render(|f| draw(f, &v, false)).contains("No exit within 80 ms"));

        v.availability = None;
        v.measuring = true;
        assert!(render(|f| draw(f, &v, false)).contains("Measuring exits"));
    }

    #[test]
    fn dashboard_shows_lending_off_and_why_it_stopped() {
        let mut v = view();
        v.running = false;
        v.routing_peers = 0;
        v.error = Some("the node stopped".into());
        let screen = render(|f| draw(f, &v, false));
        assert!(screen.contains("○ Off"));
        assert!(screen.contains("NAT: off"));
        assert!(screen.contains("Stopped: the node stopped"));
        assert!(!screen.contains("Sessions"));
    }

    #[test]
    fn as_a_service_client_lending_can_start_without_connecting() {
        let mut v = view();
        v.running = false;
        let screen = render(|f| draw(f, &v, true));
        assert!(screen.contains("to lend without connecting"));
        assert!(screen.contains("lend only"));
        // Once lending runs, the key isn't offered again.
        assert!(!render(|f| draw(f, &view(), true)).contains("lend only"));
        // In-process, lending runs for the whole session, so there is nothing to start.
        assert!(!render(|f| draw(f, &v, false)).contains("lend only"));
    }

    #[test]
    fn as_a_service_client_lending_at_boot_is_shown() {
        let mut v = view();
        assert!(render(|f| draw(f, &v, true)).contains("At boot    off"));
        v.lend_at_boot = true;
        assert!(render(|f| draw(f, &v, true)).contains("At boot    on"));
        v.running = false;
        assert!(render(|f| draw(f, &v, true)).contains("At boot    on"), "shown while lending is off too");
        assert!(!render(|f| draw(f, &v, false)).contains("At boot"), "only the service starts at boot");
    }

    #[test]
    fn as_a_service_client_closing_keeps_the_vpn_running() {
        let screen = render(|f| draw(f, &view(), true));
        assert!(screen.contains("·  service"));
        assert!(screen.contains("turn off"));
        assert!(screen.contains("close (VPN keeps running)"));
        assert!(!render(|f| draw(f, &view(), false)).contains("turn off"));
    }

    #[test]
    fn keys_become_actions() {
        let press = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
        let act = |c, v: &View, service| match command(press(c), v, service) {
            Command::Act(action) => Some(action),
            _ => None,
        };
        let mut v = view();
        assert_eq!(act('c', &v, false), Some(Action::Connect));
        assert_eq!(act('x', &v, true), Some(Action::Stop));
        assert_eq!(act('l', &v, true), Some(Action::Lend));
        assert_eq!(act('l', &v, false), None, "in-process, lending always runs");
        assert_eq!(act('b', &v, true), Some(Action::SetLendAtBoot { enabled: true }));
        assert_eq!(act('b', &v, false), None, "only the service starts at boot");
        assert_eq!(act('x', &v, false), None, "in-process, quitting turns it off");
        assert_eq!(act('m', &v, false), Some(Action::SetSelection { max_ping_ms: Some(100) }));
        assert_eq!(act('+', &v, false), None, "no limit to change in random mode");

        v.selection = Selection::MaxPing(Duration::from_millis(5));
        assert_eq!(act('m', &v, false), Some(Action::SetSelection { max_ping_ms: None }));
        assert_eq!(act('+', &v, false), Some(Action::SetSelection { max_ping_ms: Some(15) }));
        assert_eq!(act('-', &v, false), Some(Action::SetSelection { max_ping_ms: Some(1) }), "never below 1 ms");
        assert!(matches!(command(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL), &v, true), Command::Quit));
    }
}
