// Komms desktop frontend. No framework, no bundler: talks to the Rust
// backend through Tauri IPC (`invoke`) and listens for node events. All
// state of record lives in the node's encrypted store — this file only
// renders it and never invents delivery states.

"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  dataDir: "",
  address: "",
  contacts: [],
  current: null, // peer id of the open conversation
  unread: new Map(), // peer id → count
  msgEls: new Map(), // message id → bubble element (for state updates)
  statusTimer: null,
};

// ── small utilities ─────────────────────────────────────────────────────

function toast(text, isError = false) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = text;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), isError ? 8000 : 4000);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (err) {
    toast(String(err), true);
    throw err;
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch {
    // WebKitGTK can refuse the async clipboard; fall back.
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast("Copied");
  }
}

function fmtTime(unixSecs) {
  const d = new Date(unixSecs * 1000);
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

const STATE_GLYPH = { queued: "queued ○", sent: "sent ✓", delivered: "delivered ✓✓" };

// ── gate (create / unlock / restore) ────────────────────────────────────

let gateMode = "open";

function readSettings() {
  const lines = (el) => el.value.split("\n").map((s) => s.trim()).filter(Boolean);
  const opt = (el) => (el.value.trim() ? el.value.trim() : null);
  return {
    listen: lines($("#set-listen")),
    bootstrap: lines($("#set-bootstrap")),
    relay: opt($("#set-relay")),
    mailboxes: lines($("#set-mailboxes")),
    serve_mailbox: $("#set-serve-mailbox").checked,
    mdns: $("#set-mdns").checked,
    spool: opt($("#set-spool")),
    meshtastic_serial: opt($("#set-mesh-serial")),
    meshtastic_tcp: opt($("#set-mesh-tcp")),
    bridge: $("#set-bridge").checked,
  };
}

function fillSettings(s) {
  $("#set-listen").value = s.listen.join("\n");
  $("#set-bootstrap").value = s.bootstrap.join("\n");
  $("#set-relay").value = s.relay ?? "";
  $("#set-mailboxes").value = s.mailboxes.join("\n");
  $("#set-serve-mailbox").checked = s.serve_mailbox;
  $("#set-mdns").checked = s.mdns;
  $("#set-spool").value = s.spool ?? "";
  $("#set-mesh-serial").value = s.meshtastic_serial ?? "";
  $("#set-mesh-tcp").value = s.meshtastic_tcp ?? "";
  $("#set-bridge").checked = s.bridge;
}

async function probeGate(dir) {
  const probe = await call("probe", { dataDir: dir ?? null });
  state.dataDir = probe.data_dir ?? probe.dataDir;
  $("#gate-dir").value = state.dataDir;
  fillSettings(probe.settings);
  const exists = probe.exists;
  $("#gate-tabs").hidden = exists;
  if (exists) setGateMode("open");
  $("#gate-go").textContent = exists ? "Unlock" : gateMode === "restore" ? "Restore" : "Create";
  $("#gate-note").textContent = exists
    ? "This directory holds an existing encrypted store."
    : "No store here yet — a new identity will be created, or restore one from a backup.";
  $("#gate-pass-label").textContent = exists ? "Passphrase" : "New passphrase (encrypts the local store)";
}

function setGateMode(mode) {
  gateMode = mode;
  $$("#gate-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === mode));
  $("#restore-fields").hidden = mode !== "restore";
  const exists = $("#gate-tabs").hidden;
  $("#gate-go").textContent = exists ? "Unlock" : mode === "restore" ? "Restore" : "Create";
}

$("#gate-tabs").addEventListener("click", (e) => {
  const tab = e.target.closest(".tab");
  if (tab) setGateMode(tab.dataset.tab);
});

let probeDebounce;
$("#gate-dir").addEventListener("input", () => {
  clearTimeout(probeDebounce);
  probeDebounce = setTimeout(() => probeGate($("#gate-dir").value).catch(() => {}), 400);
});

$("#gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#gate-go");
  const errEl = $("#gate-error");
  errEl.hidden = true;
  btn.disabled = true;
  btn.textContent = "Opening… (key derivation takes a moment)";
  try {
    const args = {
      dataDir: $("#gate-dir").value.trim(),
      passphrase: $("#gate-pass").value,
      settings: readSettings(),
    };
    let address;
    if (gateMode === "restore" && !$("#gate-tabs").hidden) {
      address = await invoke("restore", {
        ...args,
        backupPath: $("#gate-backup").value.trim(),
        mnemonic: $("#gate-mnemonic").value.trim(),
      });
    } else {
      address = await invoke("unlock", args);
    }
    state.dataDir = args.dataDir;
    enterApp(address);
  } catch (err) {
    errEl.textContent = String(err);
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
    probeGate($("#gate-dir").value).catch(() => {});
  }
});

// ── main app ────────────────────────────────────────────────────────────

function enterApp(address) {
  state.address = address;
  $("#gate").hidden = true;
  $("#app").hidden = false;
  $("#my-address").textContent = address;
  $("#gate-pass").value = "";
  $("#gate-mnemonic").value = "";
  refreshContacts();
  refreshStatus();
  state.statusTimer = setInterval(refreshStatus, 5000);
}

async function leaveApp() {
  clearInterval(state.statusTimer);
  state.statusTimer = null;
  state.current = null;
  state.contacts = [];
  state.unread.clear();
  state.msgEls.clear();
  $("#app").hidden = true;
  $("#gate").hidden = false;
  $("#chat-pane").hidden = true;
  $("#chat-empty").hidden = false;
  await probeGate(state.dataDir).catch(() => {});
}

$("#btn-lock").addEventListener("click", async () => {
  await call("lock");
  leaveApp();
});

$("#btn-copy-address").addEventListener("click", () => copyText(state.address));

async function refreshStatus() {
  let s;
  try {
    s = await invoke("status");
  } catch {
    return; // locked or shutting down — the poll just goes quiet
  }
  const nat = $("#stat-nat");
  nat.textContent = `NAT: ${s.nat}`;
  nat.className = "stat " + (s.nat === "public" ? "good" : s.nat === "private" ? "warn" : "");
  nat.title = `Listening on:\n${s.listen.join("\n") || "(binding…)"}`;
  const lan = $("#stat-lan");
  lan.textContent = `LAN: ${s.lan_peers.length}`;
  lan.className = "stat " + (s.lan_peers.length ? "good" : "");
  lan.title = s.lan_peers.length ? `Peers on this network:\n${s.lan_peers.join("\n")}` : "No peers found on this network";
  $("#stat-queued").textContent = `Queued: ${s.queued}`;
  const transit = $("#stat-transit");
  transit.hidden = s.transit === 0;
  transit.textContent = `Bridging: ${s.transit}`;
}

// ── contacts ────────────────────────────────────────────────────────────

async function refreshContacts() {
  state.contacts = await call("contacts");
  const list = $("#contact-list");
  list.textContent = "";
  for (const c of state.contacts) {
    const btn = document.createElement("button");
    btn.className = "contact" + (c.peer === state.current ? " active" : "");
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = (c.name || "?").slice(0, 1).toUpperCase();
    const name = document.createElement("span");
    name.className = "c-name";
    name.textContent = c.name || c.peer.slice(0, 12) + "…";
    btn.append(avatar, name);
    if (c.verified) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = "✓";
      badge.title = "Safety number verified";
      btn.append(badge);
    }
    const unread = state.unread.get(c.peer) ?? 0;
    if (unread > 0 && c.peer !== state.current) {
      const b = document.createElement("span");
      b.className = "unread";
      b.textContent = String(unread);
      btn.append(b);
    }
    btn.addEventListener("click", () => openChat(c.peer));
    list.append(btn);
  }
  if (state.current) updateChatHead();
}

function contactName(peer) {
  return state.contacts.find((c) => c.peer === peer)?.name ?? peer.slice(0, 12) + "…";
}

function updateChatHead() {
  const c = state.contacts.find((x) => x.peer === state.current);
  $("#chat-name").textContent = c ? c.name : "";
  $("#chat-verified").hidden = !c?.verified;
}

// ── conversation ────────────────────────────────────────────────────────

async function openChat(peer) {
  state.current = peer;
  state.unread.delete(peer);
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  updateChatHead();
  await renderMessages();
  refreshContacts();
  $("#composer-input").focus();
}

function bubble(m) {
  const el = document.createElement("div");
  el.className = "msg " + (m.outbound ? "out" : "in");
  el.textContent = m.body;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.append(fmtTime(m.timestamp));
  if (m.outbound) {
    const st = document.createElement("span");
    st.className = "state" + (m.state === "delivered" ? " state-delivered" : "");
    st.textContent = " · " + (STATE_GLYPH[m.state] ?? m.state);
    meta.append(st);
  }
  el.append(meta);
  state.msgEls.set(m.id, el);
  return el;
}

async function renderMessages() {
  const msgs = await call("messages", { peer: state.current });
  const box = $("#messages");
  box.textContent = "";
  state.msgEls.clear();
  for (const m of msgs) box.append(bubble(m));
  box.scrollTop = box.scrollHeight;
}

$("#composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#composer-input");
  const body = input.value.trim();
  if (!body || !state.current) return;
  input.value = "";
  await call("send", { peer: state.current, body });
  await renderMessages();
});

// ── node events ─────────────────────────────────────────────────────────

listen("node-event", async ({ payload: ev }) => {
  switch (ev.type) {
    case "delivery_updated": {
      const el = state.msgEls.get(ev.id);
      if (el) {
        const st = el.querySelector(".state");
        if (st) {
          st.textContent = " · " + (STATE_GLYPH[ev.state] ?? ev.state);
          st.className = "state" + (ev.state === "delivered" ? " state-delivered" : "");
        }
      }
      break;
    }
    case "message_received": {
      if (ev.peer === state.current) {
        await renderMessages();
      } else {
        state.unread.set(ev.peer, (state.unread.get(ev.peer) ?? 0) + 1);
        toast(`${contactName(ev.peer)}: ${ev.body.slice(0, 80)}`);
        refreshContacts();
      }
      break;
    }
    case "contact_added":
      toast("New contact from an incoming handshake — unverified");
      await refreshContacts();
      break;
    case "session_established": {
      const known = state.contacts.some((c) => c.peer === ev.peer);
      toast(
        known
          ? `Encrypted session renewed with ${contactName(ev.peer)} — their key or device changed; re-verify if unexpected`
          : "Encrypted session established"
      );
      await refreshContacts();
      break;
    }
    case "awaiting_faster_link": {
      const el = state.msgEls.get(ev.id);
      const st = el?.querySelector(".state");
      if (st) {
        st.textContent = " · held — will send when a faster link exists";
        st.className = "state state-held";
      }
      break;
    }
  }
});

// ── modals ──────────────────────────────────────────────────────────────

function openModal(title, tplId) {
  const body = $("#modal-body");
  body.textContent = "";
  $("#modal-title").textContent = title;
  body.append($("#" + tplId).content.cloneNode(true));
  $("#modal-backdrop").hidden = false;
  return body;
}

function closeModal() {
  $("#modal-backdrop").hidden = true;
  $("#modal-body").textContent = "";
}

$("#modal-close").addEventListener("click", closeModal);
$("#modal-backdrop").addEventListener("click", (e) => {
  if (e.target === $("#modal-backdrop")) closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#modal-backdrop").hidden) closeModal();
});

function showError(root, err) {
  const el = root.querySelector('[data-f="error"]');
  if (el) {
    el.textContent = String(err);
    el.hidden = false;
  }
}

// hint-row editing, shared by "add contact" and "delivery hints"
function addHintRow(rowsEl, kind = "multiaddr", value = "") {
  const row = $("#tpl-hint-row").content.cloneNode(true);
  row.querySelector('[data-f="kind"]').value = kind;
  row.querySelector('[data-f="value"]').value = value;
  rowsEl.append(row);
}

function wireHints(root) {
  const rows = root.querySelector(".hint-rows");
  addHintRow(rows);
  root.addEventListener("click", (e) => {
    if (e.target.matches('[data-act="add-hint"]')) addHintRow(rows);
    if (e.target.matches('[data-act="del-hint"]')) e.target.closest(".hint-row").remove();
  });
  return () =>
    $$(".hint-row", root)
      .map((r) => ({
        kind: r.querySelector('[data-f="kind"]').value,
        value: r.querySelector('[data-f="value"]').value.trim(),
      }))
      .filter((h) => h.value);
}

// share (pairing) modal
$("#btn-share").addEventListener("click", async () => {
  const root = openModal("Share your identity", "tpl-share");
  const bundle = await call("my_bundle");
  const addrSvg = await call("address_qr");
  root.querySelector('[data-pane="bundle"]').innerHTML = bundle.qr_svg;
  root.querySelector('[data-pane="address"]').innerHTML = addrSvg;
  root.querySelector(".share-hex").value = bundle.hex;
  root.addEventListener("click", async (e) => {
    const tab = e.target.closest("[data-share]");
    if (tab) {
      $$(".qr-tabs .tab", root).forEach((t) => t.classList.toggle("active", t === tab));
      $$("[data-pane]", root).forEach((p) => (p.hidden = p.dataset.pane !== tab.dataset.share));
    }
    if (e.target.matches('[data-act="copy-hex"]')) copyText(bundle.hex);
    if (e.target.matches('[data-act="publish"]')) {
      await call("publish");
      toast("Prekey bundle published to the DHT");
    }
  });
});

// add-contact modal
$("#btn-add-contact").addEventListener("click", () => {
  const root = openModal("Add contact", "tpl-add");
  let mode = "bundle";
  const getHints = wireHints(root);
  root.addEventListener("click", async (e) => {
    const tab = e.target.closest("[data-add]");
    if (tab) {
      mode = tab.dataset.add;
      $$(".tabs .tab", root).forEach((t) => t.classList.toggle("active", t === tab));
      $$("[data-pane]", root).forEach((p) => (p.hidden = p.dataset.pane !== mode));
      root.querySelector(".hints").hidden = mode === "address";
    }
    if (!e.target.matches('[data-act="save"]')) return;
    const name = root.querySelector('[data-f="name"]').value.trim();
    try {
      if (!name) throw "give this contact a name";
      let peer;
      if (mode === "bundle") {
        peer = await invoke("add_contact", {
          name,
          bundleHex: root.querySelector('[data-f="bundle"]').value,
          hints: getHints(),
        });
      } else {
        peer = await invoke("add_contact_by_address", {
          name,
          address: root.querySelector('[data-f="address"]').value.trim(),
        });
      }
      closeModal();
      await refreshContacts();
      openChat(peer);
    } catch (err) {
      showError(root, err);
    }
  });
});

// verify (safety number) modal
$("#btn-verify").addEventListener("click", async () => {
  const peer = state.current;
  const root = openModal(`Verify ${contactName(peer)}`, "tpl-verify");
  const sn = await call("safety_number", { peer });
  root.querySelector(".safety-digits").textContent = sn.display;
  root.querySelector(".safety-qr").innerHTML = sn.qr_svg;
  root.addEventListener("click", async (e) => {
    if (!e.target.matches('[data-act="verified"]')) return;
    await call("mark_verified", { peer });
    closeModal();
    toast("Marked verified");
    await refreshContacts();
  });
});

// delivery-hints modal
$("#btn-hints").addEventListener("click", () => {
  const peer = state.current;
  const root = openModal(`Delivery hints for ${contactName(peer)}`, "tpl-hints");
  const getHints = wireHints(root);
  root.addEventListener("click", async (e) => {
    if (!e.target.matches('[data-act="save"]')) return;
    try {
      await invoke("set_hints", { peer, hints: getHints() });
      closeModal();
      toast("Delivery hints replaced");
    } catch (err) {
      showError(root, err);
    }
  });
});

// backup modal → one-time mnemonic
$("#btn-backup").addEventListener("click", () => {
  const root = openModal("Encrypted backup", "tpl-backup");
  const stamp = new Date().toISOString().slice(0, 10);
  root.querySelector('[data-f="path"]').value = `${state.dataDir}/komms-${stamp}.kkr`;
  root.addEventListener("click", async (e) => {
    if (!e.target.matches('[data-act="export"]')) return;
    try {
      const mnemonic = await invoke("export_backup", {
        path: root.querySelector('[data-f="path"]').value.trim(),
      });
      const shown = openModal("Recovery mnemonic — shown once", "tpl-mnemonic");
      const ol = shown.querySelector(".mnemonic");
      for (const word of mnemonic.split(/\s+/)) {
        const li = document.createElement("li");
        li.textContent = word;
        ol.append(li);
      }
      shown.addEventListener("click", (ev) => {
        if (ev.target.matches('[data-act="done"]')) closeModal();
      });
    } catch (err) {
      showError(root, err);
    }
  });
});

// ── boot ────────────────────────────────────────────────────────────────

probeGate().catch((err) => {
  $("#gate-error").textContent = String(err);
  $("#gate-error").hidden = false;
});
