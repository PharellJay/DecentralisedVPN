//! dvpn desktop app: a tray icon and a window, both clients of the dvpn service
//! (`dvpn daemon`) over its control socket. The app itself needs no privileges and
//! changes nothing on the system; closing it leaves the VPN as it is.
//!
//! One connection watches the service, which pushes its state when it changes and new
//! log lines as they're written; the tray follows it and passes it on to the window
//! (event `update`). Actions go over connections of their own.
//!
//! A `dvpn://join?…` argument (an invite link the desktop hands over; see
//! `packaging/dvpn.desktop`) opens the window with the link ready to add.
//!
//! `--hidden` (used at login, from /etc/xdg/autostart) starts with only the tray icon,
//! and exits quietly if this user can't use the service. `DVPN_SOCKET` points the app
//! at another service socket (for development).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use dvpn::control::{Client, PermissionDenied, Phase, Update};
use dvpn::controller::{Action, View};
use dvpn::daemon::{self, Probe, SERVICE_SOCKET};
use serde::Serialize;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent, Wry};
use tauri_plugin_notification::NotificationExt;

/// How long to wait before trying again to reach the service.
const RETRY: Duration = Duration::from_secs(2);
/// Log lines the app keeps for the window (as many as the service keeps).
const LOG_LINES: usize = dvpn::logs::LOG_LINES;

/// What the window shows: the service's state, or why it can't be reached.
#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Snapshot {
    Ready { view: Box<View> },
    /// The service isn't installed or isn't running.
    Absent,
    /// The service runs, but this user isn't in the dvpn group.
    Denied { help: String },
    Error { message: String },
}

fn socket() -> PathBuf {
    std::env::var_os("DVPN_SOCKET").map_or_else(|| PathBuf::from(SERVICE_SOCKET), PathBuf::from)
}

async fn client() -> Result<Client, Snapshot> {
    match daemon::probe(&socket()).await {
        Probe::Available(stream) => Ok(Client::new(stream)),
        Probe::PermissionDenied => Err(Snapshot::Denied {
            help: daemon::permission_help(),
        }),
        Probe::Absent => Err(Snapshot::Absent),
    }
}

fn snapshot_of_error(e: &anyhow::Error) -> Snapshot {
    match e.downcast_ref::<PermissionDenied>() {
        Some(denied) => Snapshot::Denied { help: denied.0.clone() },
        None => Snapshot::Error {
            message: format!("{e:#}"),
        },
    }
}

async fn take_snapshot() -> Snapshot {
    let mut client = match client().await {
        Ok(client) => client,
        Err(snapshot) => return snapshot,
    };
    match client.view().await {
        Ok(view) => Snapshot::Ready { view: Box::new(view) },
        Err(e) => snapshot_of_error(&e),
    }
}

/// The latest state from the service, as the watch connection last saw it.
#[derive(Default)]
struct Latest {
    snapshot: Option<Snapshot>,
    logs: VecDeque<String>,
    /// An invite link the app was opened with, until the window takes it.
    invite: Option<String>,
}

fn invite_arg(args: &[String]) -> Option<String> {
    args.iter().find(|a| a.starts_with(dvpn::config::INVITE_PREFIX)).cloned()
}

/// Hands an invite link to the window (now, or when it next asks), and shows it.
fn offer_invite(app: &AppHandle, link: String) {
    app.state::<Mutex<Latest>>().lock().expect("state lock").invite = Some(link.clone());
    show_window(app);
    let _ = app.emit_to("main", "invite", link);
}

/// The invite link the app was opened with, once.
#[tauri::command]
fn take_invite(latest: State<'_, Mutex<Latest>>) -> Option<String> {
    latest.lock().expect("state lock").invite.take()
}

/// What the window gets: the state, and log lines (new ones, or all with `reset_logs`).
#[derive(Clone, Serialize)]
struct WindowUpdate {
    snapshot: Snapshot,
    logs: Vec<String>,
    reset_logs: bool,
}

/// Everything the window needs to start: the state and all log lines kept.
#[tauri::command]
async fn snapshot(latest: State<'_, Mutex<Latest>>) -> Result<WindowUpdate, ()> {
    let cached = {
        let latest = latest.lock().expect("state lock");
        latest.snapshot.clone().map(|s| (s, latest.logs.iter().cloned().collect()))
    };
    let (snapshot, logs) = match cached {
        Some(cached) => cached,
        // Before the watch connection's first update.
        None => (take_snapshot().await, Vec::new()),
    };
    Ok(WindowUpdate {
        snapshot,
        logs,
        reset_logs: true,
    })
}

#[tauri::command]
async fn act(action: Action) -> Result<(), String> {
    let mut client = client().await.map_err(|_| "the dvpn service isn't reachable".to_string())?;
    client.act(action).await.map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn terms() -> &'static str {
    dvpn::lend::LENDING_WARNING
}

/// The tray menu's items that change with the service's state.
struct Tray {
    icon: TrayIcon<Wry>,
    status: MenuItem<Wry>,
    toggle: MenuItem<Wry>,
    lend: MenuItem<Wry>,
    off: MenuItem<Wry>,
    quit: MenuItem<Wry>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Look {
    Off,
    Busy,
    On,
    Blocked,
}

impl Look {
    fn image(self) -> Image<'static> {
        let bytes: &[u8] = match self {
            Self::Off => include_bytes!("../icons/tray-off.png"),
            Self::Busy => include_bytes!("../icons/tray-busy.png"),
            Self::On => include_bytes!("../icons/tray-on.png"),
            Self::Blocked => include_bytes!("../icons/tray-blocked.png"),
        };
        Image::from_bytes(bytes).expect("bundled tray icon")
    }
}

/// What the tray shows for a snapshot: icon, status line, toggle label, and whether
/// the VPN or lending is running.
fn tray_state(snapshot: &Snapshot) -> (Look, String, &'static str, bool) {
    let Snapshot::Ready { view } = snapshot else {
        let status = match snapshot {
            Snapshot::Denied { .. } => "dvpn: not allowed for this account",
            _ => "dvpn: service not running",
        };
        return (Look::Off, status.into(), "Connect", false);
    };
    let running = view.running || view.vpn.running;
    if !view.vpn.running {
        let status = if view.running { "Lending (VPN not connected)" } else { "Disconnected" };
        return (Look::Off, status.into(), "Connect", running);
    }
    let (look, status) = match view.vpn.phase {
        Phase::Connected => {
            let circuit = view.vpn.circuit.as_ref();
            let kind = match circuit {
                Some(c) if c.exit_is_user => " (another user's exit)",
                _ => "",
            };
            let ip = circuit.and_then(|c| c.exit_ip.as_deref()).map(|ip| format!(" as {ip}")).unwrap_or_default();
            (Look::On, format!("Connected{ip}{kind}"))
        }
        Phase::Reconnecting => (Look::Blocked, "Reconnecting: traffic blocked".into()),
        Phase::Paused => (Look::Blocked, "Paused: lending is down, traffic blocked".into()),
        Phase::WaitingForLending => (Look::Busy, "Getting ready: traffic blocked".into()),
        Phase::Idle | Phase::Connecting => (Look::Busy, "Connecting: traffic blocked".into()),
    };
    (look, status, "Disconnect", running)
}

fn build_tray(app: &AppHandle) -> tauri::Result<Tray> {
    let status = MenuItem::with_id(app, "status", "dvpn", false, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Connect", true, None::<&str>)?;
    let lend = MenuItem::with_id(app, "lend", "Lend without connecting", true, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open dvpn", true, None::<&str>)?;
    let off = MenuItem::with_id(app, "off", "Turn off (stop lending)", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &lend,
            &open,
            &off,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;
    let icon = TrayIconBuilder::with_id("dvpn")
        .icon(Look::Off.image())
        .tooltip("dvpn")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "toggle" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { toggle_vpn(&app).await });
            }
            "lend" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { start_lending(&app).await });
            }
            "open" => show_window(app),
            "off" => {
                tauri::async_runtime::spawn(async {
                    let _ = act(Action::Stop).await;
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(Tray {
        icon,
        status,
        toggle,
        lend,
        off,
        quit,
    })
}

/// The latest state, or a fresh one before the first update.
async fn current_snapshot(app: &AppHandle) -> Snapshot {
    let cached = app.state::<Mutex<Latest>>().lock().expect("state lock").snapshot.clone();
    match cached {
        Some(snapshot) => snapshot,
        None => take_snapshot().await,
    }
}

/// Connects or disconnects. The first connect needs the lending terms accepted, which
/// only the window can show.
async fn toggle_vpn(app: &AppHandle) {
    match current_snapshot(app).await {
        Snapshot::Ready { view } if !view.consent_given => show_window(app),
        Snapshot::Ready { view } => {
            let action = if view.vpn.running { Action::Disconnect } else { Action::Connect };
            let _ = act(action).await;
        }
        _ => show_window(app),
    }
}

/// Starts lending without the VPN. Like connecting, it needs the terms accepted first.
async fn start_lending(app: &AppHandle) {
    match current_snapshot(app).await {
        Snapshot::Ready { view } if view.consent_given => {
            let _ = act(Action::Lend).await;
        }
        _ => show_window(app),
    }
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// A desktop notification for a change the user should hear about even with the window
/// closed: the VPN coming up, or traffic being blocked by a failure.
fn notification(before: Option<Look>, after: Look, status: &str) -> Option<String> {
    match (before, after) {
        (Some(Look::Blocked | Look::Busy), Look::On) => Some("Connected: your traffic goes through dvpn.".into()),
        (Some(Look::On), Look::Blocked) => Some(format!("{status}. Nothing leaves this computer until dvpn reconnects.")),
        _ => None,
    }
}

/// Follows the service: keeps the tray, the latest state and the window up to date.
async fn watch(app: AppHandle, tray: Tray) {
    let mut follower = Follower { app, tray, last: None };
    loop {
        let client = match client().await {
            Ok(client) => client,
            Err(snapshot) => {
                follower.show(snapshot, Vec::new(), true);
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        let mut watcher = match client.watch(true).await {
            Ok(watcher) => watcher,
            Err(e) => {
                follower.show(snapshot_of_error(&e), Vec::new(), true);
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        // A new connection starts with the recent log again, so it replaces ours.
        let mut reset_logs = true;
        let mut view = None;
        loop {
            match watcher.next().await {
                Ok(Update { view: new_view, logs }) => {
                    if let Some(new_view) = new_view {
                        view = Some(Box::new(new_view));
                    }
                    if let Some(view) = &view {
                        follower.show(Snapshot::Ready { view: view.clone() }, logs, std::mem::take(&mut reset_logs));
                    }
                }
                Err(e) => {
                    // Denied, or the service stopped: a new connection finds out which.
                    if e.downcast_ref::<PermissionDenied>().is_some() {
                        follower.show(snapshot_of_error(&e), Vec::new(), true);
                    }
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

struct Follower {
    app: AppHandle,
    tray: Tray,
    last: Option<(Look, String, &'static str, bool)>,
}

impl Follower {
    fn show(&mut self, snapshot: Snapshot, logs: Vec<String>, reset_logs: bool) {
        {
            let state = self.app.state::<Mutex<Latest>>();
            let mut latest = state.lock().expect("state lock");
            if reset_logs {
                latest.logs.clear();
            }
            latest.logs.extend(logs.iter().cloned());
            while latest.logs.len() > LOG_LINES {
                latest.logs.pop_front();
            }
            latest.snapshot = Some(snapshot.clone());
        }
        self.update_tray(&snapshot);
        let _ = self.app.emit_to("main", "update", WindowUpdate { snapshot, logs, reset_logs });
    }

    fn update_tray(&mut self, snapshot: &Snapshot) {
        let state = tray_state(snapshot);
        if let Some(body) = notification(self.last.as_ref().map(|s| s.0), state.0, &state.1) {
            let _ = self.app.notification().builder().title("dvpn").body(body).show();
        }
        if self.last.as_ref() == Some(&state) {
            return;
        }
        let tray = &self.tray;
        let (look, status, toggle, running) = &state;
        let _ = tray.icon.set_icon(Some(look.image()));
        let _ = tray.icon.set_tooltip(Some(format!("dvpn: {status}")));
        let _ = tray.status.set_text(status);
        let _ = tray.toggle.set_text(*toggle);
        let _ = tray.lend.set_enabled(!*running);
        let _ = tray.off.set_enabled(*running);
        let _ = tray.quit.set_text(if *running { "Quit (VPN keeps running)" } else { "Quit" });
        self.last = Some(state);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let invite = invite_arg(&args);
    let hidden = invite.is_none() && args.iter().any(|a| a == "--hidden");
    if hidden {
        // At login: only for accounts that can use the service.
        let usable = tauri::async_runtime::block_on(async { matches!(take_snapshot().await, Snapshot::Ready { .. }) });
        if !usable {
            return;
        }
    }

    tauri::Builder::default()
        // A second start (e.g. from the menu while the login instance runs in the tray)
        // shows the running app's window instead of adding another tray icon.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if let Some(link) = invite_arg(&args) {
                offer_invite(app, link);
            } else if !args.iter().any(|a| a == "--hidden") {
                show_window(app);
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .manage(Mutex::new(Latest::default()))
        .invoke_handler(tauri::generate_handler![snapshot, act, terms, take_invite])
        .setup(move |app| {
            let tray = build_tray(app.handle())?;
            tauri::async_runtime::spawn(watch(app.handle().clone(), tray));
            if let Some(link) = invite.clone() {
                offer_invite(app.handle(), link);
            } else if !hidden {
                show_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the tray icon; Quit is in its menu.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running the dvpn app");
}
