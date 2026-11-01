//! `sudo dvpn tui`: a terminal dashboard that lends and connects in one process.
//!
//! Lending runs for the whole session; the VPN is started and stopped with keys. The
//! exit selection mode can be changed at any time, and in max-ping mode the dashboard
//! shows how many measured exits fit the limit before you connect.
//!
//! Rendering is a pure function of [`View`], so it is tested without a terminal.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use tracing_subscriber::fmt::MakeWriter;

use crate::client::{self, ConnectOptions};
use crate::control::{CircuitReport, Phase, SharedState};
use crate::install::{self, INSTALL_PATH};
use crate::lend::{self, LENDING_WARNING, Lending};
use crate::node::{NatState, Node};
use crate::records::now_secs;
use crate::select::{self, Availability, Measurement, Selection};
use crate::system;

const TICK: Duration = Duration::from_millis(250);
const LOG_LINES: usize = 500;
const PING_STEP: Duration = Duration::from_millis(10);
const MIN_PING: Duration = Duration::from_millis(1);
const MAX_PING: Duration = Duration::from_secs(60);
/// The limit offered when switching to max-ping mode for the first time.
pub const DEFAULT_PING_LIMIT: Duration = Duration::from_millis(100);

/// Everything the TUI drives, started after the user has given consent.
pub struct Session {
    pub node: Node,
    pub lending: Lending,
    pub state: SharedState,
    pub options: ConnectOptions,
}

/// Recent log lines, written by `tracing` instead of stderr while the TUI is up.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<VecDeque<String>>>);

impl LogBuffer {
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().expect("log lock").iter().cloned().collect()
    }
}

pub struct LogWriter {
    buffer: LogBuffer,
    pending: Vec<u8>,
}

impl io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.pending);
        let mut lines = self.buffer.0.lock().expect("log lock");
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            lines.push_back(line.trim_end().to_string());
        }
        while lines.len() > LOG_LINES {
            lines.pop_front();
        }
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> LogWriter {
        LogWriter {
            buffer: self.clone(),
            pending: Vec::new(),
        }
    }
}

// ------------------------------------------------------------------ view model

#[derive(Clone, Debug, Default)]
pub struct LendingView {
    pub ready: bool,
    pub published: bool,
    pub publicly_reachable: bool,
    pub relay_reservations: usize,
    pub sessions: usize,
    pub max_sessions: usize,
    pub rate_mbps: u64,
    pub wan: String,
}

#[derive(Clone, Debug, Default)]
pub struct VpnView {
    /// The client task is running (from `c` until `d` or an error).
    pub running: bool,
    pub phase: Phase,
    /// The kill switch is in place (see [`crate::control::StatusReport::protected`]).
    pub protected: bool,
    pub warnings: Vec<String>,
    pub circuit: Option<CircuitReport>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct View {
    pub peer_id: String,
    pub nat: NatState,
    pub routing_peers: usize,
    pub lending: LendingView,
    pub vpn: VpnView,
    pub selection: Selection,
    pub measuring: bool,
    /// From the last measurement, for the current limit.
    pub availability: Option<Availability>,
    /// Some test circuits may have gone through our own tunnel, so times read high.
    pub measured_while_connected: bool,
    pub logs: Vec<String>,
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

pub fn draw(frame: &mut Frame, view: &View) {
    let [header, top, selection, logs, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(9),
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    let [lending, vpn] = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(top);

    let nat = match view.nat {
        NatState::Unknown => "detecting",
        NatState::Public => "public",
        NatState::Private => "behind NAT",
    };
    frame.render_widget(
        Line::from(vec![
            " dvpn ".bold().reversed(),
            format!("  you {}  ·  NAT: {nat}  ·  {} peers", short(&view.peer_id), view.routing_peers).into(),
        ]),
        header,
    );
    frame.render_widget(lending_panel(&view.lending), lending);
    frame.render_widget(vpn_panel(&view.vpn), vpn);
    frame.render_widget(selection_panel(view), selection);
    frame.render_widget(log_panel(&view.logs, logs), logs);
    frame.render_widget(
        Line::from(vec![
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
            key("q"),
            " quit".into(),
        ]),
        footer,
    );
}

fn lending_panel(l: &LendingView) -> Paragraph<'static> {
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
    let lines = vec![
        status,
        Line::from(format!("Reachable  {reachable}")),
        Line::from(format!("Sessions   {} / {}", l.sessions, l.max_sessions)),
        Line::from(format!("Limit      {} Mbit/s per session", l.rate_mbps)),
        Line::from(format!("WAN        {}", l.wan)),
    ];
    Paragraph::new(lines).block(Block::bordered().title(" Lending "))
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

struct App {
    session: Session,
    logs: LogBuffer,
    client: Option<JoinHandle<anyhow::Result<()>>>,
    client_error: Option<String>,
    measurement: Option<JoinHandle<Vec<Measurement>>>,
    measurements: Option<Vec<Measurement>>,
    /// Whether the VPN was running when the running/last measurement started.
    measuring_connected: bool,
    measured_while_connected: bool,
    /// Kept when switching to random, so switching back restores it.
    ping_limit: Duration,
    quit: bool,
}

/// Runs the TUI. Shows the consent screen if needed, then calls `start` to bring up
/// the node and lending, then the dashboard until the user quits.
pub async fn run<F, Fut>(data_dir: &Path, logs: LogBuffer, start: F) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<Session>>,
{
    let mut terminal = ratatui::init();
    let result = run_in(&mut terminal, data_dir, logs, start).await;
    ratatui::restore();
    result
}

async fn run_in<F, Fut>(terminal: &mut DefaultTerminal, data_dir: &Path, logs: LogBuffer, start: F) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<Session>>,
{
    // Before any system changes: closing the terminal (SIGHUP) or SIGTERM must still
    // lead to a clean shutdown rather than leftover routes and firewall rules.
    let shutdown = system::shutdown_signal()?;
    tokio::pin!(shutdown);
    let mut events = EventStream::new();
    if !lend::consent_given(data_dir) {
        loop {
            terminal.draw(draw_consent)?;
            match next_key(&mut events).await? {
                KeyCode::Char('y') | KeyCode::Char('Y') => break,
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                _ => {}
            }
        }
        lend::record_consent(data_dir)?;
    }
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

    terminal.draw(|f| draw_starting(f, "Starting your node and exit…"))?;
    let session = start().await?;
    let ping_limit = match *session.state.selection.lock().expect("state lock") {
        Selection::MaxPing(limit) => limit,
        Selection::Random => DEFAULT_PING_LIMIT,
    };
    let mut app = App {
        session,
        logs,
        client: None,
        client_error: None,
        measurement: None,
        measurements: None,
        measuring_connected: false,
        measured_while_connected: false,
        ping_limit,
        quit: false,
    };

    let mut tick = tokio::time::interval(TICK);
    let result = loop {
        tokio::select! {
            _ = tick.tick() => {}
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => app.on_key(key).await,
                Some(Ok(_)) => {}
                Some(Err(e)) => break Err(e).context("reading terminal input"),
                None => break Ok(()),
            },
            () = &mut shutdown => app.quit = true,
            result = &mut app.session.node.task => break Err(anyhow::anyhow!("node stopped: {:?}", result)),
        }
        if app.quit {
            break Ok(());
        }
        app.poll_tasks().await;
        let view = match app.view().await {
            Ok(view) => view,
            Err(e) => break Err(e),
        };
        // The terminal may be gone (window closed): stop drawing, but still shut down.
        if let Err(e) = terminal.draw(|f| draw(f, &view)) {
            break Err(e).context("drawing the dashboard");
        }
    };

    let _ = terminal.draw(|f| draw_starting(f, "Disconnecting and restoring your network…"));
    app.shutdown().await;
    result
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

impl App {
    async fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => self.quit = true,
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') => self.connect(),
            KeyCode::Char('d') => self.disconnect().await,
            KeyCode::Char('m') => {
                let next = match self.selection() {
                    Selection::Random => Selection::MaxPing(self.ping_limit),
                    Selection::MaxPing(_) => Selection::Random,
                };
                self.set_selection(next);
                if matches!(next, Selection::MaxPing(_)) && self.measurements.is_none() {
                    self.measure();
                }
            }
            KeyCode::Char('+') | KeyCode::Char('=') => self.adjust_limit(|l| (l + PING_STEP).min(MAX_PING)),
            KeyCode::Char('-') => self.adjust_limit(|l| l.saturating_sub(PING_STEP).max(MIN_PING)),
            KeyCode::Char('r') => self.measure(),
            _ => {}
        }
    }

    fn selection(&self) -> Selection {
        *self.session.state.selection.lock().expect("state lock")
    }

    /// Takes effect at the next circuit: reconnects, and the switch to a dedicated exit.
    fn set_selection(&self, selection: Selection) {
        *self.session.state.selection.lock().expect("state lock") = selection;
    }

    fn adjust_limit(&mut self, f: impl Fn(Duration) -> Duration) {
        if let Selection::MaxPing(limit) = self.selection() {
            self.ping_limit = f(limit);
            self.set_selection(Selection::MaxPing(self.ping_limit));
        }
    }

    fn connect(&mut self) {
        if self.client.is_some() {
            return;
        }
        self.client_error = None;
        let state = &self.session.state;
        state.set_error(None);
        state.set_phase(Phase::Idle);
        self.client = Some(tokio::spawn(client::run(
            self.session.node.handle.clone(),
            self.session.options.clone(),
            state.clone(),
        )));
    }

    /// Dropping the client restores routing and DNS; waits until it has.
    async fn disconnect(&mut self) {
        if let Some(task) = self.client.take() {
            task.abort();
            let _ = task.await;
        }
        let state = &self.session.state;
        state.set_phase(Phase::Idle);
        *state.circuit.lock().expect("state lock") = None;
    }

    fn measure(&mut self) {
        if self.measurement.is_some() {
            return;
        }
        let handle = self.session.node.handle.clone();
        self.measuring_connected = self.session.state.protected.load(Ordering::Relaxed);
        self.measurement = Some(tokio::spawn(async move {
            let (Ok(exits), Ok(relays)) = (handle.find_exits().await, handle.find_relays().await) else {
                return Vec::new();
            };
            select::measure_exits(&handle, exits, relays, &|_, _| Ok(())).await
        }));
    }

    async fn poll_tasks(&mut self) {
        if self.client.as_ref().is_some_and(JoinHandle::is_finished) {
            let task = self.client.take().expect("checked");
            self.client_error = match task.await {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(format!("{e:#}")),
                Err(e) => Some(format!("client task failed: {e}")),
            };
            self.session.state.set_phase(Phase::Idle);
        }
        if self.measurement.as_ref().is_some_and(JoinHandle::is_finished) {
            let task = self.measurement.take().expect("checked");
            self.measurements = Some(task.await.unwrap_or_default());
            self.measured_while_connected = self.measuring_connected;
        }
    }

    async fn view(&self) -> anyhow::Result<View> {
        let handle = &self.session.node.handle;
        let status = handle.status().await.context("node stopped")?;
        let routing_peers = handle.routing_peers().await.context("node stopped")?.len();
        let state = &self.session.state;
        let lending = self.session.lending.handle();
        let selection = self.selection();
        let availability = match (selection, &self.measurements) {
            (Selection::MaxPing(limit), Some(m)) => Some(select::availability(m, limit)),
            _ => None,
        };
        Ok(View {
            peer_id: handle.peer_id().to_string(),
            nat: status.nat,
            routing_peers,
            lending: LendingView {
                ready: lending.ready(&status),
                published: status.exit_published,
                publicly_reachable: status.publicly_reachable || status.nat == NatState::Public,
                relay_reservations: status.relay_reservations,
                sessions: lending.active.load(Ordering::Relaxed),
                max_sessions: lending.max_sessions,
                rate_mbps: lending.rate_mbps,
                wan: lending.wan.clone(),
            },
            vpn: VpnView {
                running: self.client.is_some(),
                phase: *state.phase.lock().expect("state lock"),
                protected: state.protected.load(Ordering::Relaxed),
                warnings: state.warnings.lock().expect("state lock").clone(),
                circuit: state.circuit.lock().expect("state lock").clone(),
                last_error: self.client_error.clone().or_else(|| state.last_error.lock().expect("state lock").clone()),
            },
            selection,
            measuring: self.measurement.is_some(),
            availability,
            measured_while_connected: self.measured_while_connected,
            logs: self.logs.lines(),
        })
    }

    /// The VPN first (restores routes), then lending (restores the firewall), then the node.
    async fn shutdown(mut self) {
        self.disconnect().await;
        if let Some(task) = self.measurement.take() {
            task.abort();
        }
        drop(self.session.lending);
        let _ = self.session.node.handle.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let screen = render(|f| draw(f, &view()));
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
        let screen = render(|f| draw(f, &v));
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
        let screen = render(|f| draw(f, &v));
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
        let screen = render(|f| draw(f, &v));
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
        let screen = render(|f| draw(f, &v));
        assert!(screen.contains("max ping 80 ms"));
        assert!(screen.contains("Within 80 ms: 3 dedicated · 1 lent by users  (6 measured, fastest 23 ms)"));

        v.availability = Some(fits(0, 2));
        assert!(render(|f| draw(f, &v)).contains("would use another user's exit"));

        v.availability = Some(fits(0, 0));
        assert!(render(|f| draw(f, &v)).contains("No exit within 80 ms"));

        v.availability = None;
        v.measuring = true;
        assert!(render(|f| draw(f, &v)).contains("Measuring exits"));
    }

    #[test]
    fn log_buffer_keeps_the_most_recent_lines() {
        use std::io::Write;
        let logs = LogBuffer::default();
        for i in 0..LOG_LINES + 10 {
            let mut writer = logs.make_writer();
            writeln!(writer, "line {i}").unwrap();
        }
        let lines = logs.lines();
        assert_eq!(lines.len(), LOG_LINES);
        assert_eq!(lines.last().unwrap(), &format!("line {}", LOG_LINES + 9));
    }
}
