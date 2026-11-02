//! dvpn desktop app: a tray icon and a window, both clients of the dvpn service
//! (`dvpn daemon`) over its control socket. The app itself needs no privileges and
//! changes nothing on the system; closing it leaves the VPN as it is.
//!
//! `--hidden` (used at login, from /etc/xdg/autostart) starts with only the tray icon,
//! and exits quietly if this user can't use the service. `DVPN_SOCKET` points the app
//! at another service socket (for development).

use std::path::PathBuf;
use std::time::Duration;

use dvpn::control::{Client, Phase};
use dvpn::controller::{Action, View};
use dvpn::daemon::{self, Probe, SERVICE_SOCKET};
use serde::Serialize;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Manager, WindowEvent, Wry};

const TRAY_POLL: Duration = Duration::from_secs(2);

/// What the window shows: the service's state, or why it can't be reached.
#[derive(Serialize)]
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

async fn take_snapshot() -> Snapshot {
    let mut client = match client().await {
        Ok(client) => client,
        Err(snapshot) => return snapshot,
    };
    match client.view().await {
        Ok(view) => Snapshot::Ready { view: Box::new(view) },
        Err(e) => Snapshot::Error {
            message: format!("{e:#}"),
        },
    }
}

#[tauri::command]
async fn snapshot() -> Snapshot {
    take_snapshot().await
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
            let exit = view.vpn.circuit.as_ref().map(|c| c.assigned_ip.clone()).unwrap_or_default();
            (Look::On, format!("Connected  {exit}").trim_end().to_string())
        }
        Phase::Reconnecting => (Look::Blocked, "Reconnecting: traffic blocked".into()),
        Phase::Paused => (Look::Blocked, "Paused: lending is down, traffic blocked".into()),
        Phase::WaitingForLending => (Look::Busy, "Waiting for lending…".into()),
        Phase::Idle | Phase::Connecting => (Look::Busy, "Connecting…".into()),
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

/// Connects or disconnects. The first connect needs the lending terms accepted, which
/// only the window can show.
async fn toggle_vpn(app: &AppHandle) {
    match take_snapshot().await {
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
    match take_snapshot().await {
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

/// Keeps the tray in step with the service.
async fn watch(tray: Tray) {
    let mut last: Option<(Look, String, &'static str, bool)> = None;
    loop {
        let state = tray_state(&take_snapshot().await);
        if last.as_ref() != Some(&state) {
            let (look, status, toggle, running) = &state;
            let _ = tray.icon.set_icon(Some(look.image()));
            let _ = tray.icon.set_tooltip(Some(format!("dvpn: {status}")));
            let _ = tray.status.set_text(status);
            let _ = tray.toggle.set_text(*toggle);
            let _ = tray.lend.set_enabled(!*running);
            let _ = tray.off.set_enabled(*running);
            let _ = tray.quit.set_text(if *running { "Quit (VPN keeps running)" } else { "Quit" });
            last = Some(state);
        }
        tokio::time::sleep(TRAY_POLL).await;
    }
}

fn main() {
    let hidden = std::env::args().any(|a| a == "--hidden");
    if hidden {
        // At login: only for accounts that can use the service.
        let usable = tauri::async_runtime::block_on(async {
            matches!(daemon::probe(&socket()).await, Probe::Available(_))
        });
        if !usable {
            return;
        }
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![snapshot, act, terms])
        .setup(move |app| {
            let tray = build_tray(app.handle())?;
            tauri::async_runtime::spawn(watch(tray));
            if !hidden {
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
