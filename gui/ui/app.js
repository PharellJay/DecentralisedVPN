// dvpn window: renders the service's state (polled from the Rust side) and sends
// actions. All networking happens in the dvpn service; this only shows and asks.
"use strict";

const { invoke } = window.__TAURI__.core;
const POLL_MS = 1000;
const $ = (id) => document.getElementById(id);

let view = null;
let busy = false; // an action is in flight

function show(screen) {
  for (const s of document.querySelectorAll(".screen")) s.hidden = s.id !== `screen-${screen}`;
}

function short(peer) {
  return peer && peer.length > 12 ? `${peer.slice(0, 6)}…${peer.slice(-4)}` : peer || "";
}

function hms(secs) {
  const p = (n) => String(n).padStart(2, "0");
  return `${p(Math.floor(secs / 3600))}:${p(Math.floor(secs / 60) % 60)}:${p(secs % 60)}`;
}

const isRandom = (v) => v.selection === "Random";

async function act(action, fields = {}) {
  busy = true;
  render();
  try {
    await invoke("act", { action: { action, ...fields } });
    setError(null);
  } catch (e) {
    setError(String(e));
  } finally {
    busy = false;
    await refresh();
  }
}

let actionError = null;
function setError(message) {
  actionError = message;
}

async function refresh() {
  let snap;
  try {
    snap = await invoke("snapshot");
  } catch (e) {
    snap = { state: "error", message: String(e) };
  }
  switch (snap.state) {
    case "absent":
      view = null;
      show("absent");
      break;
    case "denied":
      view = null;
      $("denied-help").textContent = snap.help;
      show("denied");
      break;
    case "error":
      view = null;
      $("error-message").textContent = snap.message;
      show("error");
      break;
    case "ready":
      view = snap.view;
      if (!view.consent_given) {
        show("consent");
      } else {
        show("main");
        render();
      }
      $("who").textContent = `you ${short(view.peer_id)}`;
      break;
  }
}

function vpnState(v) {
  const vpn = v.vpn;
  if (!vpn.running) {
    return { cls: "off", title: "Disconnected", sub: v.running ? "Lending your connection to others" : "" };
  }
  switch (vpn.phase) {
    case "Connected": {
      const c = vpn.circuit;
      const kind = c && c.exit_is_user ? "another user's exit" : "a dedicated exit";
      return { cls: "on", title: "Connected", sub: c ? `Your traffic leaves from ${kind}` : "" };
    }
    case "Reconnecting":
      return { cls: "blocked", title: "Reconnecting", sub: "Traffic is blocked until a new connection is up" };
    case "Paused":
      return { cls: "blocked", title: "Paused", sub: "Lending is down, so traffic is blocked until it recovers" };
    case "WaitingForLending":
      return { cls: "busy", title: "Getting ready", sub: "Waiting for your own exit to be reachable by others" };
    default:
      return { cls: "busy", title: "Connecting", sub: "Building a two-hop circuit" };
  }
}

function render() {
  const v = view;
  if (!v) return;

  // VPN
  const s = vpnState(v);
  $("hero").className = `hero ${s.cls}`;
  $("vpn-title").textContent = s.title;
  $("vpn-sub").textContent = s.sub;
  const toggle = $("toggle");
  toggle.textContent = v.vpn.running ? "Disconnect" : "Connect";
  toggle.className = v.vpn.running ? "secondary big" : "primary big";
  toggle.disabled = busy;
  $("unprotected").hidden = !(v.vpn.running && !v.vpn.protected);

  const warnings = $("warnings");
  warnings.replaceChildren(
    ...v.vpn.warnings.map((w) => {
      const div = document.createElement("div");
      div.className = "banner warn";
      div.textContent = w;
      return div;
    }),
  );
  const error = actionError || v.error || v.vpn.last_error;
  $("error").hidden = !error;
  $("error").textContent = error || "";

  // Circuit
  const c = v.vpn.running ? v.vpn.circuit : null;
  $("circuit-card").hidden = !c;
  if (c) {
    $("c-ip").textContent = c.assigned_ip;
    $("c-exit").textContent = `${short(c.exit)} (${c.exit_is_user ? "another user's" : "dedicated"})`;
    $("c-relay").textContent = short(c.relay);
    $("c-up").textContent = hms(Math.max(0, Math.floor(Date.now() / 1000) - c.connected_since));
  }

  // Exit selection
  const random = isRandom(v);
  $("mode-random").setAttribute("aria-checked", String(random));
  $("mode-ping").setAttribute("aria-checked", String(!random));
  $("mode-random").disabled = $("mode-ping").disabled = busy;
  $("mode-hint").textContent = random
    ? "Any exit, picked at random: the most private choice. Other users' exits are used only if no dedicated exit works."
    : "A random exit among those within your ping limit, measured through encrypted test circuits.";
  $("ping-controls").hidden = random;
  const limit = v.ping_limit_ms;
  if (document.activeElement !== $("ping-input")) $("ping-input").value = limit;
  if (document.activeElement !== $("ping-range")) $("ping-range").value = Math.min(500, limit);
  $("availability").textContent = availability(v);
  $("measure").disabled = busy || v.measuring;
  $("measure").textContent = v.measuring ? "Measuring…" : "Measure exits";

  // Lending
  const l = v.lending;
  const ls = $("lending-state");
  if (!v.running) {
    ls.className = "lending-state off";
    ls.textContent = "Off";
  } else if (l.ready) {
    ls.className = "lending-state on";
    ls.textContent = "Others can use your exit";
  } else {
    ls.className = "lending-state busy";
    ls.textContent = l.published ? "Published, not reachable yet" : "Starting: publishing your exit…";
  }
  $("lending-details").hidden = !v.running;
  if (v.running) {
    $("l-reach").textContent = l.publicly_reachable
      ? "directly"
      : l.relay_reservations > 0
        ? `through ${l.relay_reservations} relay${l.relay_reservations === 1 ? "" : "s"}`
        : "not yet";
    $("l-sessions").textContent = `${l.sessions} of ${l.max_sessions}`;
    $("l-limit").textContent = l.rate_mbps ? `${l.rate_mbps} Mbit/s per session` : "unlimited";
    $("l-wan").textContent = l.wan;
    const nat = { Public: "public", Private: "behind NAT", Unknown: "detecting" }[v.nat];
    $("l-net").textContent = `${nat}, ${v.routing_peers} peer${v.routing_peers === 1 ? "" : "s"}`;
  }
  $("lend").hidden = $("lend-hint").hidden = v.running;
  $("lend").disabled = busy;
  $("lend-at-boot").checked = v.lend_at_boot;
  $("lend-at-boot").disabled = busy;
  $("lend-at-boot-hint").hidden = !v.lend_at_boot;
  $("off").hidden = !v.running;
  $("off").disabled = busy;

  // With nobody to talk to, the bootstrap peer is what's needed.
  if (v.running && v.routing_peers === 0 && !$("network-card").dataset.opened) {
    $("network-card").open = true;
    $("network-card").dataset.opened = "1";
  }

  // Log
  const log = $("log");
  const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
  log.textContent = v.logs.join("\n");
  if (atBottom) log.scrollTop = log.scrollHeight;
}

function availability(v) {
  if (v.measuring) return "Measuring exits through test circuits…";
  const a = v.availability;
  if (!a) return v.running ? "Not measured yet." : "Exits are measured once dvpn is running.";
  if (a.measured === 0) return "No exit could be measured yet. Try again in a moment.";
  const fastest = a.fastest_ms != null ? `, fastest ${a.fastest_ms} ms` : "";
  let text = `Within ${v.ping_limit_ms} ms: ${a.dedicated} dedicated, ${a.user} lent by users (${a.measured} measured${fastest}).`;
  if (a.dedicated === 0 && a.user === 0) text += " Raise the limit or use random.";
  else if (a.dedicated === 0) text += " Would use another user's exit.";
  if (v.measured_while_connected) text += " Measured while connected, so times may read high.";
  return text;
}

function setPingLimit(ms) {
  const value = Math.max(1, Math.min(60000, Math.round(Number(ms) || 0)));
  if (value) act("set_selection", { max_ping_ms: value });
}

function wire() {
  $("accept").addEventListener("click", () => act("accept_exit_risk"));
  $("toggle").addEventListener("click", () => act(view && view.vpn.running ? "disconnect" : "connect"));
  $("lend").addEventListener("click", () => act("lend"));
  $("lend-at-boot").addEventListener("change", (e) => act("set_lend_at_boot", { enabled: e.target.checked }));
  $("off").addEventListener("click", () => act("stop"));
  $("measure").addEventListener("click", () => act("measure"));
  $("mode-random").addEventListener("click", () => act("set_selection", { max_ping_ms: null }));
  $("mode-ping").addEventListener("click", () => view && setPingLimit(view.ping_limit_ms));
  $("ping-range").addEventListener("input", (e) => ($("ping-input").value = e.target.value));
  $("ping-range").addEventListener("change", (e) => setPingLimit(e.target.value));
  $("ping-input").addEventListener("change", (e) => setPingLimit(e.target.value));
  $("bootstrap-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const addr = $("bootstrap").value.trim();
    if (!addr) return;
    try {
      await invoke("act", { action: { action: "add_bootstrap", addr } });
      $("bootstrap").value = "";
      $("bootstrap-result").textContent = view && view.running
        ? "Saved. It's used the next time dvpn starts: turn off and connect again."
        : "Saved. It's used when you lend or connect.";
    } catch (err) {
      $("bootstrap-result").textContent = String(err);
    }
  });
}

async function main() {
  // The terms are wrapped for the terminal; reflow them, keeping paragraphs.
  $("terms").textContent = (await invoke("terms")).replace(/([^\n])\n(?!\n)/g, "$1 ");
  wire();
  await refresh();
  setInterval(() => {
    if (!busy) refresh();
  }, POLL_MS);
}

main();
