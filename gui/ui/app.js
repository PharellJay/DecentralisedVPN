// dvpn window: renders the service's state (pushed by the Rust side, event `update`)
// and sends actions. All networking happens in the dvpn service; this only shows and asks.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const LOG_LINES = 500;
const $ = (id) => document.getElementById(id);

let view = null;
let logLines = [];
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

function bytes(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}

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
    render(); // the new state is pushed as soon as the service has it
  }
}

let actionError = null;
function setError(message) {
  actionError = message;
}

// An update from the Rust side: the state, and new log lines (all of them with reset_logs).
function apply(update) {
  logLines = update.reset_logs ? update.logs : logLines.concat(update.logs);
  if (logLines.length > LOG_LINES) logLines = logLines.slice(-LOG_LINES);
  const snap = update.snapshot;
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
      // The node ID is new every session, so it's only shown while running.
      $("who").textContent = view.peer_id ? `you ${short(view.peer_id)}` : "";
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
      if (!c) return { cls: "on", title: "Connected", sub: "" };
      const sub = c.exit_is_user
        ? "Your traffic leaves from another user's exit, which only carries common services (web, email, chat, SSH)"
        : "Your traffic leaves from a dedicated exit";
      return { cls: "on", title: "Connected", sub };
    }
    case "Reconnecting":
      return { cls: "blocked", title: "Reconnecting", sub: "Traffic is blocked until a new connection is up" };
    case "Paused":
      return { cls: "blocked", title: "Paused", sub: "Lending is down, so traffic is blocked until it recovers" };
    case "WaitingForLending":
      return { cls: "busy", title: "Getting ready", sub: "Waiting for your own exit to be reachable by others. Traffic is blocked until connected." };
    default:
      return { cls: "busy", title: "Connecting", sub: "Building a two-hop circuit. Traffic is blocked until connected." };
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
    // What websites see: the exit's address. An exit reached only through a relay
    // doesn't publish it.
    $("c-ip").textContent = c.exit_ip || "the exit's (not published)";
    $("c-exit").textContent = c.exit_is_user ? "another user's" : "dedicated";
    $("c-exit").title = `exit ${c.exit}\nentry relay ${c.relay}\ntunnel address ${c.assigned_ip}`;
    $("c-rtt").textContent = c.rtt_ms != null ? `${c.rtt_ms} ms` : "measuring…";
    $("c-data").textContent = `↑ ${bytes(c.bytes_sent)}  ↓ ${bytes(c.bytes_received)} since connecting`;
    $("c-transport").textContent = c.datagrams ? "UDP datagrams" : "stream (TCP or QUIC)";
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

  renderBootstrap(v.bootstrap || []);
  $("invite-box").hidden = !v.invite;
  if (v.invite && $("invite").value !== v.invite) $("invite").value = v.invite;

  // Log
  const log = $("log");
  const text = logLines.join("\n");
  if (log.textContent !== text) {
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 4;
    log.textContent = text;
    if (atBottom) log.scrollTop = log.scrollHeight;
  }
}

// The connection's age counts up between updates.
function tick() {
  const c = view && view.vpn.running ? view.vpn.circuit : null;
  if (c) $("c-up").textContent = hms(Math.max(0, Math.floor(Date.now() / 1000) - c.connected_since));
}

function renderBootstrap(peers) {
  const list = $("bootstrap-list");
  const key = JSON.stringify(peers) + busy;
  if (list.dataset.key === key) return; // keeps focus and avoids flicker
  list.dataset.key = key;
  list.replaceChildren(
    ...peers.map((addr) => {
      const li = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = addr;
      code.title = addr;
      const remove = document.createElement("button");
      remove.className = "secondary small";
      remove.textContent = "Remove";
      remove.disabled = busy;
      remove.addEventListener("click", () => act("remove_bootstrap", { addr }));
      li.append(code, remove);
      return li;
    }),
  );
  list.hidden = peers.length === 0;
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
  $("accept").addEventListener("click", async () => {
    await act("accept_exit_risk");
    await act("set_lend_at_boot", { enabled: $("consent-boot").checked });
  });
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
        ? "Saved, and dvpn is contacting it now."
        : "Saved. It's used when you lend or connect.";
      $("bootstrap").placeholder = "dvpn://join?… or /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW…";
    } catch (err) {
      $("bootstrap-result").textContent = String(err);
    }
  });
}

// An invite link opened from elsewhere (a browser, a chat): shown for the user to
// confirm, since a link from a stranger could point at a hostile peer.
function offerInvite(link) {
  if (!link) return;
  $("network-card").open = true;
  $("network-card").dataset.opened = "1";
  $("bootstrap").value = link;
  $("bootstrap-result").textContent = "Opened from an invite link. Add it if you trust whoever sent it.";
  $("bootstrap").focus();
}

function wireInvites() {
  $("copy-invite").addEventListener("click", async () => {
    const input = $("invite");
    input.select();
    try {
      await navigator.clipboard.writeText(input.value);
    } catch {
      document.execCommand("copy");
    }
    $("copy-invite").textContent = "Copied";
    setTimeout(() => ($("copy-invite").textContent = "Copy"), 1500);
  });
}

async function main() {
  // The terms are wrapped for the terminal; reflow them, keeping paragraphs.
  $("terms").textContent = (await invoke("terms")).replace(/([^\n])\n(?!\n)/g, "$1 ");
  wire();
  wireInvites();
  await listen("invite", (e) => offerInvite(e.payload));
  // Listen first, so nothing pushed while the first state loads is missed.
  let first = null;
  const early = [];
  await listen("update", (e) => (first ? apply(e.payload) : early.push(e.payload)));
  first = await invoke("snapshot");
  apply(first);
  // Lines in earlier updates are already in the first state; a reset replaces it.
  for (const update of early) if (update.reset_logs) apply(update);
  offerInvite(await invoke("take_invite"));
  setInterval(tick, 1000);
}

main();
