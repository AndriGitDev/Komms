// Komms desktop frontend. No framework, no bundler: talks to the Rust
// backend through Tauri IPC (`invoke`) and listens for node events. All
// state of record lives in the node's encrypted store — this file only
// renders it and never invents delivery states.

"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { open: openPath, save: savePath } = window.__TAURI__.dialog;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  dataDir: "",
  address: "",
  peer: "",
  contacts: [],
  groups: [],
  noteToSelfId: null,
  currentKind: null, // "contact", "group", or "note"
  currentId: null,
  unread: new Map(), // peer id → count
  groupUnread: new Map(), // group id → count
  msgEls: new Map(), // message id → bubble element (for state updates)
  attachmentNotified: new Set(), // inbound transfer ids already announced
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

function dateTimeLocalValue(unixSecs) {
  const date = new Date(unixSecs * 1000);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

const STATE_GLYPH = { queued: "queued ○", sent: "sent ✓", delivered: "delivered ✓✓" };

const MIME_BY_EXTENSION = {
  txt: "text/plain",
  json: "application/json",
  pdf: "application/pdf",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  mp3: "audio/mpeg",
  m4a: "audio/mp4",
  wav: "audio/wav",
  mp4: "video/mp4",
  mov: "video/quicktime",
  zip: "application/zip",
};

function pathBasename(path) {
  return String(path).replace(/\\/g, "/").split("/").filter(Boolean).pop() ?? "attachment";
}

function guessedMime(filename) {
  const extension = filename.includes(".") ? filename.split(".").pop().toLowerCase() : "";
  return MIME_BY_EXTENSION[extension] ?? "application/octet-stream";
}

function exactBytes(verified, total) {
  return `${Number(verified).toLocaleString()} / ${Number(total).toLocaleString()} bytes`;
}

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
  refreshGroups();
  call("note_to_self_id").then((id) => { state.noteToSelfId = id; });
  refreshStatus();
  state.statusTimer = setInterval(refreshStatus, 5000);
}

async function leaveApp() {
  clearInterval(state.statusTimer);
  state.statusTimer = null;
  state.currentKind = null;
  state.currentId = null;
  state.contacts = [];
  state.groups = [];
  state.noteToSelfId = null;
  state.unread.clear();
  state.groupUnread.clear();
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
  state.peer = s.peer;
  const nat = $("#stat-nat");
  nat.textContent = `NAT: ${s.nat}`;
  nat.className = "stat " + (s.nat === "public" ? "good" : s.nat === "private" ? "warn" : "");
  nat.title = `Listening on:\n${s.listen.join("\n") || "(binding…)"}`;
  const lan = $("#stat-lan");
  lan.textContent = `LAN: ${s.lan_peers.length}`;
  lan.className = "stat " + (s.lan_peers.length ? "good" : "");
  lan.title = s.lan_peers.length ? `Peers on this network:\n${s.lan_peers.join("\n")}` : "No peers found on this network";
  $("#stat-queued").textContent = `Queued: ${s.queued}`;
  $("#stat-scheduled").textContent = `Scheduled: ${s.scheduled}`;
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
    btn.className = "contact" + (state.currentKind === "contact" && c.peer === state.currentId ? " active" : "");
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
    if (unread > 0 && !(state.currentKind === "contact" && c.peer === state.currentId)) {
      const b = document.createElement("span");
      b.className = "unread";
      b.textContent = String(unread);
      btn.append(b);
    }
    btn.addEventListener("click", () => openChat(c.peer));
    list.append(btn);
  }
  if (state.currentKind === "contact") updateChatHead();
}

function contactName(peer) {
  return state.contacts.find((c) => c.peer === peer)?.name ?? peer.slice(0, 12) + "…";
}

function memberName(peer) {
  return peer === state.peer ? "You" : contactName(peer);
}

async function refreshGroups() {
  state.groups = await call("groups");
  const list = $("#group-list");
  list.textContent = "";
  for (const group of state.groups) {
    const btn = document.createElement("button");
    btn.className = "contact group" + (state.currentKind === "group" && group.id === state.currentId ? " active" : "");
    btn.dataset.group = group.id;
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = (group.name || "G").slice(0, 1).toUpperCase();
    const name = document.createElement("span");
    name.className = "c-name";
    name.textContent = group.name || "Unnamed group";
    const detail = document.createElement("span");
    detail.className = "c-detail";
    detail.textContent = `${group.members.length} members`;
    btn.append(avatar, name, detail);
    const unread = state.groupUnread.get(group.id) ?? 0;
    if (unread > 0 && !(state.currentKind === "group" && group.id === state.currentId)) {
      const badge = document.createElement("span");
      badge.className = "unread";
      badge.textContent = String(unread);
      btn.append(badge);
    }
    btn.addEventListener("click", () => openGroup(group.id));
    list.append(btn);
  }
  if (state.currentKind === "group") updateChatHead();
}

function currentGroup() {
  return state.groups.find((group) => group.id === state.currentId);
}

function updateChatHead() {
  const isNote = state.currentKind === "note";
  const isGroup = state.currentKind === "group";
  const contact = isGroup || isNote ? null : state.contacts.find((x) => x.peer === state.currentId);
  const group = isGroup ? currentGroup() : null;
  $("#chat-name").textContent = isNote ? "Note to self" : isGroup ? (group?.name ?? "") : (contact?.name ?? "");
  $("#chat-verified").hidden = isGroup || isNote || !contact?.verified;
  $("#btn-verify").hidden = isGroup || isNote;
  $("#btn-hints").hidden = isGroup || isNote;
  $("#btn-group-details").hidden = !isGroup;
  $("#btn-attach").hidden = isNote;
  $("#btn-schedule").hidden = isNote;
  $("#note-to-self").classList.toggle("active", isNote);
}

// ── conversation ────────────────────────────────────────────────────────

async function openChat(peer) {
  state.currentKind = "contact";
  state.currentId = peer;
  state.unread.delete(peer);
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  updateChatHead();
  await renderMessages();
  refreshContacts();
  $("#composer-input").focus();
}

async function openGroup(group) {
  state.currentKind = "group";
  state.currentId = group;
  state.groupUnread.delete(group);
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  updateChatHead();
  await renderMessages();
  refreshGroups();
  $("#composer-input").focus();
}

async function openNoteToSelf() {
  state.noteToSelfId ??= await call("note_to_self_id");
  state.currentKind = "note";
  state.currentId = state.noteToSelfId;
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  updateChatHead();
  await renderMessages();
  $("#composer-input").focus();
}

$("#note-to-self").addEventListener("click", openNoteToSelf);

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

function noteBubble(m) {
  const el = document.createElement("div");
  el.className = "msg out";
  el.textContent = m.body;
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = `${fmtTime(m.timestamp)} · local only`;
  el.append(meta);
  state.msgEls.set(m.id, el);
  return el;
}

function groupBubble(m) {
  const el = document.createElement("div");
  el.className = "msg " + (m.outbound ? "out" : "in");
  if (!m.outbound) {
    const sender = document.createElement("span");
    sender.className = "sender";
    sender.textContent = memberName(m.sender);
    el.append(sender);
  }
  el.append(m.body);
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = fmtTime(m.timestamp);
  el.append(meta);
  if (m.outbound) {
    const deliveries = document.createElement("span");
    deliveries.className = "deliveries";
    for (const delivery of m.deliveries) {
      const item = document.createElement("span");
      item.className = "delivery" + (delivery.state === "delivered" ? " state-delivered" : "");
      item.dataset.peer = delivery.peer;
      item.textContent = `${memberName(delivery.peer)} · ${STATE_GLYPH[delivery.state] ?? delivery.state}`;
      deliveries.append(item);
    }
    el.append(deliveries);
  }
  state.msgEls.set(m.id, el);
  return el;
}

function scheduledBubble(message) {
  const el = document.createElement("div");
  el.className = "msg out scheduled";
  el.append(message.body);
  const meta = document.createElement("span");
  meta.className = "meta scheduled-meta";
  meta.textContent = `scheduled for ${fmtTime(message.not_before)}`;
  const actions = document.createElement("span");
  actions.className = "scheduled-actions";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "ghost";
  edit.textContent = "Edit";
  edit.addEventListener("click", () => openScheduleModal(message));
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "danger";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", async () => {
    if (!window.confirm("Cancel this scheduled message?")) return;
    await call("cancel_scheduled", { message: message.id });
    await renderMessages();
    await refreshStatus();
  });
  actions.append(edit, cancel);
  el.append(meta, actions);
  return el;
}

function attachmentBelongsHere(attachment) {
  if (state.currentKind === "contact") {
    return attachment.conversation === "pairwise" && attachment.peer === state.currentId;
  }
  if (state.currentKind === "group") {
    return attachment.conversation === "group" && attachment.group === state.currentId;
  }
  return false;
}

function attachmentButton(label, className, action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", action);
  return button;
}

async function runAttachmentAction(command, transfer) {
  await call(command, { transfer });
  await renderMessages();
}

async function exportAttachment(attachment) {
  const primary = attachment.objects.find((object) => !object.preview) ?? attachment.objects[0];
  const path = await savePath({
    title: "Export attachment",
    defaultPath: primary?.filename ?? "attachment",
  });
  if (!path) return;
  await call("export_attachment", { transfer: attachment.transfer_id, path });
  toast(`Exported ${primary?.filename ?? "attachment"}`);
}

function attachmentRow(attachment) {
  const primary = attachment.objects.find((object) => !object.preview) ?? attachment.objects[0];
  const row = document.createElement("article");
  row.className = "attachment-transfer";

  const head = document.createElement("div");
  head.className = "attachment-head";
  const title = document.createElement("span");
  title.className = "attachment-title";
  title.textContent = primary?.filename ?? "Attachment";
  const transferState = document.createElement("span");
  transferState.className = `attachment-state ${attachment.state}`;
  transferState.textContent = `${attachment.direction} · ${attachment.state.replaceAll("_", " ")}`;
  head.append(title, transferState);
  row.append(head);

  for (const object of attachment.objects) {
    const objectRow = document.createElement("div");
    objectRow.className = "attachment-object";
    const objectHead = document.createElement("div");
    objectHead.className = "attachment-object-head";
    const description = document.createElement("span");
    description.textContent = `${object.preview ? "Preview" : "Primary"} · ${object.media_type}`;
    const progressText = document.createElement("span");
    progressText.textContent = `${exactBytes(object.verified_bytes, object.total_bytes)} · ${object.state.replaceAll("_", " ")}`;
    objectHead.append(description, progressText);
    const progress = document.createElement("progress");
    progress.max = Math.max(1, Number(object.total_bytes));
    progress.value = Math.min(Number(object.verified_bytes), progress.max);
    progress.setAttribute("aria-label", `${object.preview ? "Preview" : "Primary"} verified progress`);
    objectRow.append(objectHead, progress);
    row.append(objectRow);
  }

  const actions = document.createElement("div");
  actions.className = "attachment-actions";
  const inbound = attachment.direction === "inbound";
  const awaitingConsent = inbound && ["offered", "awaiting_consent"].includes(attachment.state);
  const active = ["offered", "awaiting_consent", "queued", "transferring", "paused"].includes(attachment.state);

  if (awaitingConsent) {
    actions.append(
      attachmentButton("Accept", "primary", () => runAttachmentAction("accept_attachment", attachment.transfer_id)),
      attachmentButton("Reject", "danger", () => runAttachmentAction("reject_attachment", attachment.transfer_id))
    );
  } else {
    if (attachment.state === "paused") {
      actions.append(attachmentButton("Resume", "ghost", () => runAttachmentAction("resume_attachment", attachment.transfer_id)));
    } else if (["offered", "queued", "transferring"].includes(attachment.state)) {
      actions.append(attachmentButton("Pause", "ghost", () => runAttachmentAction("pause_attachment", attachment.transfer_id)));
    }
    if (active) {
      actions.append(attachmentButton("Cancel", "danger", () => runAttachmentAction("cancel_attachment", attachment.transfer_id)));
    }
  }
  if (inbound && attachment.state === "complete") {
    actions.append(attachmentButton("Export…", "primary", () => exportAttachment(attachment)));
  }
  if (actions.childElementCount > 0) row.append(actions);
  return row;
}

function renderAttachments(attachments) {
  const panel = $("#attachment-transfers");
  panel.textContent = "";
  const matching = attachments.filter(attachmentBelongsHere);
  panel.hidden = matching.length === 0;
  for (const attachment of matching) panel.append(attachmentRow(attachment));
}

async function renderMessages() {
  const isNote = state.currentKind === "note";
  const isGroup = state.currentKind === "group";
  const [msgs, scheduled, attachments] = await Promise.all([
    isNote
      ? call("note_to_self_messages")
      : isGroup
      ? call("group_messages", { group: state.currentId })
      : call("messages", { peer: state.currentId }),
    isNote ? Promise.resolve([]) : call("scheduled_messages"),
    isNote ? Promise.resolve([]) : call("attachments"),
  ]);
  const box = $("#messages");
  box.textContent = "";
  state.msgEls.clear();
  for (const m of msgs.filter((message) => message.content_kind !== "attachment")) {
    box.append(isNote ? noteBubble(m) : isGroup ? groupBubble(m) : bubble(m));
  }
  for (const message of scheduled
    .filter((item) => item.destination === state.currentId
      && item.conversation === (isGroup ? "group" : "peer"))
    .sort((a, b) => a.not_before - b.not_before)) {
    box.append(scheduledBubble(message));
  }
  renderAttachments(attachments);
  box.scrollTop = box.scrollHeight;
}

$("#composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#composer-input");
  const body = input.value.trim();
  if (!body || !state.currentId) return;
  input.value = "";
  if (state.currentKind === "group") {
    await call("send_group", { group: state.currentId, body });
  } else if (state.currentKind === "note") {
    await call("send_note_to_self", { body });
  } else {
    await call("send", { peer: state.currentId, body });
  }
  await renderMessages();
});

function openScheduleModal(message = null) {
  if (!state.currentId || state.currentKind === "note") return;
  const editing = message !== null;
  const root = openModal(editing ? "Edit scheduled message" : "Schedule message", "tpl-schedule");
  const body = root.querySelector('[data-f="body"]');
  const notBefore = root.querySelector('[data-f="not-before"]');
  body.value = message?.body ?? $("#composer-input").value.trim();
  const earliest = Math.floor(Date.now() / 1000) + 60;
  notBefore.min = dateTimeLocalValue(Math.min(message?.not_before ?? earliest, earliest));
  notBefore.value = dateTimeLocalValue(message?.not_before ?? earliest + 29 * 60);
  root.querySelector('[data-act="save"]').textContent = editing ? "Save changes" : "Schedule message";
  root.addEventListener("click", async (event) => {
    if (!event.target.matches('[data-act="save"]')) return;
    const text = body.value.trim();
    const instant = Math.floor(new Date(notBefore.value).getTime() / 1000);
    try {
      if (!text) throw "write a message first";
      if (!Number.isFinite(instant)) throw "choose a send time";
      if (editing) {
        await invoke("edit_scheduled", {
          message: message.id,
          body: text,
          notBefore: instant,
        });
      } else if (state.currentKind === "group") {
        await invoke("schedule_group", {
          group: state.currentId,
          body: text,
          notBefore: instant,
        });
      } else {
        await invoke("schedule", {
          peer: state.currentId,
          body: text,
          notBefore: instant,
        });
      }
      if (!editing) $("#composer-input").value = "";
      closeModal();
      await renderMessages();
      await refreshStatus();
    } catch (err) {
      showError(root, err);
    }
  });
  body.focus();
}

$("#btn-schedule").addEventListener("click", () => openScheduleModal());

$("#btn-attach").addEventListener("click", async () => {
  if (!state.currentId || state.currentKind === "note") return;
  const path = await openPath({
    title: state.currentKind === "group" ? "Choose a group attachment" : "Choose an attachment",
    multiple: false,
    directory: false,
  });
  if (!path || typeof path !== "string") return;

  const selectedName = pathBasename(path);
  const root = openModal("Send attachment", "tpl-attachment-send");
  root.querySelector('[data-f="selected-name"]').textContent = selectedName;
  root.querySelector('[data-f="filename"]').value = selectedName;
  root.querySelector('[data-f="media-type"]').value = guessedMime(selectedName);
  root.addEventListener("click", async (event) => {
    if (!event.target.matches('[data-act="send-attachment"]')) return;
    const button = event.target;
    const filename = root.querySelector('[data-f="filename"]').value.trim();
    const mediaType = root.querySelector('[data-f="media-type"]').value.trim();
    try {
      if (!mediaType) throw "enter a MIME type";
      button.disabled = true;
      if (state.currentKind === "group") {
        await invoke("send_group_attachment", {
          group: state.currentId,
          path,
          mediaType,
          filename: filename || null,
        });
      } else {
        await invoke("send_attachment", {
          peer: state.currentId,
          path,
          mediaType,
          filename: filename || null,
        });
      }
      closeModal();
      await renderMessages();
    } catch (err) {
      button.disabled = false;
      showError(root, err);
    }
  });
});

// ── node events ─────────────────────────────────────────────────────────

listen("node-event", async ({ payload: ev }) => {
  switch (ev.type) {
    case "scheduled_message_updated":
    case "scheduled_message_cancelled":
    case "scheduled_message_activated": {
      if (state.currentKind && state.currentKind !== "note") await renderMessages();
      await refreshStatus();
      break;
    }
    case "note_to_self_message_added": {
      if (state.currentKind === "note" && ev.conversation === state.currentId) {
        await renderMessages();
      }
      break;
    }
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
      if (ev.content_kind === "attachment") {
        if (state.currentKind === "contact" && ev.peer === state.currentId) await renderMessages();
        break;
      }
      if (state.currentKind === "contact" && ev.peer === state.currentId) {
        await renderMessages();
      } else {
        state.unread.set(ev.peer, (state.unread.get(ev.peer) ?? 0) + 1);
        toast(`${contactName(ev.peer)}: ${ev.body.slice(0, 80)}`);
        refreshContacts();
      }
      break;
    }
    case "attachment_updated": {
      const attachment = ev.attachment;
      if (attachmentBelongsHere(attachment)) await renderMessages();
      if (
        attachment.direction === "inbound"
        && ["offered", "awaiting_consent"].includes(attachment.state)
        && !state.attachmentNotified.has(attachment.transfer_id)
      ) {
        state.attachmentNotified.add(attachment.transfer_id);
        const primary = attachment.objects.find((object) => !object.preview) ?? attachment.objects[0];
        toast(`Attachment offered: ${primary?.filename ?? "attachment"}`);
      }
      break;
    }
    case "group_updated": {
      await refreshGroups();
      if (state.currentKind === "group" && ev.group === state.currentId) {
        if (currentGroup()) {
          updateChatHead();
          await renderMessages();
        } else {
          state.currentKind = null;
          state.currentId = null;
          $("#chat-pane").hidden = true;
          $("#chat-empty").hidden = false;
        }
      }
      break;
    }
    case "group_message_received": {
      if (ev.content_kind === "attachment") {
        if (state.currentKind === "group" && ev.group === state.currentId) await renderMessages();
        break;
      }
      if (state.currentKind === "group" && ev.group === state.currentId) {
        await renderMessages();
      } else {
        state.groupUnread.set(ev.group, (state.groupUnread.get(ev.group) ?? 0) + 1);
        const group = state.groups.find((item) => item.id === ev.group);
        toast(`${group?.name ?? "Group"} · ${memberName(ev.sender)}: ${ev.body.slice(0, 80)}`);
        await refreshGroups();
      }
      break;
    }
    case "group_delivery_updated": {
      const el = state.msgEls.get(ev.id);
      const delivery = el?.querySelector(`.delivery[data-peer="${ev.peer}"]`);
      if (delivery) {
        delivery.textContent = `${memberName(ev.peer)} · ${STATE_GLYPH[ev.state] ?? ev.state}`;
        delivery.className = "delivery" + (ev.state === "delivered" ? " state-delivered" : "");
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

// create-group modal
$("#btn-create-group").addEventListener("click", () => {
  const root = openModal("Create group", "tpl-create-group");
  const members = root.querySelector('[data-f="members"]');
  if (state.contacts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "modal-note";
    empty.textContent = "Add at least one contact before creating a group.";
    members.append(empty);
  }
  for (const contact of state.contacts) {
    const label = document.createElement("label");
    label.className = "member-option";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = contact.peer;
    checkbox.dataset.member = contact.peer;
    const name = document.createElement("span");
    name.textContent = contact.name || contact.peer.slice(0, 12) + "…";
    label.append(checkbox, name);
    members.append(label);
  }
  root.addEventListener("click", async (event) => {
    if (!event.target.matches('[data-act="create"]')) return;
    const name = root.querySelector('[data-f="name"]').value.trim();
    const selected = $$('input[type="checkbox"]:checked', members).map((input) => input.value);
    try {
      if (!name) throw "give this group a name";
      if (selected.length === 0) throw "choose at least one member";
      const group = await invoke("create_group", { name, members: selected });
      closeModal();
      await refreshGroups();
      await openGroup(group);
    } catch (err) {
      showError(root, err);
    }
  });
});

async function openGroupDetails() {
  const group = currentGroup();
  if (!group) return;
  if (!state.peer) state.peer = (await call("status")).peer;
  const isCreator = group.creator === state.peer;
  const root = openModal(`Members of ${group.name}`, "tpl-group-details");
  root.querySelector(".group-summary").textContent = isCreator
    ? `${group.members.length} members · You manage this group.`
    : `${group.members.length} members · ${memberName(group.creator)} manages this group.`;
  const roster = root.querySelector('[data-f="roster"]');
  for (const peer of group.members) {
    const row = document.createElement("div");
    row.className = "member-row";
    row.dataset.peer = peer;
    const name = document.createElement("span");
    name.className = "member-name";
    name.textContent = memberName(peer);
    const role = document.createElement("span");
    role.className = "member-role";
    role.textContent = peer === group.creator ? "creator" : "member";
    row.append(name, role);
    if (isCreator && peer !== state.peer) {
      const remove = document.createElement("button");
      remove.className = "danger";
      remove.dataset.act = "remove-member";
      remove.dataset.peer = peer;
      remove.textContent = "Remove";
      row.append(remove);
    }
    roster.append(row);
  }

  const candidates = state.contacts.filter((contact) => !group.members.includes(contact.peer));
  const addWrap = root.querySelector('[data-f="add-wrap"]');
  if (isCreator && candidates.length > 0) {
    addWrap.hidden = false;
    const select = root.querySelector('[data-f="add-peer"]');
    for (const contact of candidates) {
      const option = document.createElement("option");
      option.value = contact.peer;
      option.textContent = contact.name || contact.peer.slice(0, 12) + "…";
      select.append(option);
    }
  }

  root.addEventListener("click", async (event) => {
    const action = event.target.dataset.act;
    if (action === "close") closeModal();
    if (action === "add-member") {
      try {
        await invoke("add_group_member", {
          group: group.id,
          peer: root.querySelector('[data-f="add-peer"]').value,
        });
        closeModal();
        await refreshGroups();
        await openGroupDetails();
      } catch (err) {
        showError(root, err);
      }
    }
    if (action === "remove-member") {
      const peer = event.target.dataset.peer;
      if (!window.confirm(`Remove ${memberName(peer)}? Group keys rotate immediately.`)) return;
      try {
        await invoke("remove_group_member", { group: group.id, peer });
        closeModal();
        await refreshGroups();
        await openGroupDetails();
      } catch (err) {
        showError(root, err);
      }
    }
    if (action === "leave") {
      if (!window.confirm(`Leave ${group.name}? Its history stays on this device.`)) return;
      try {
        await invoke("leave_group", { group: group.id });
        closeModal();
        state.currentKind = null;
        state.currentId = null;
        $("#chat-pane").hidden = true;
        $("#chat-empty").hidden = false;
        await refreshGroups();
      } catch (err) {
        showError(root, err);
      }
    }
  });
}

$("#btn-group-details").addEventListener("click", openGroupDetails);

// verify (safety number) modal
$("#btn-verify").addEventListener("click", async () => {
  const peer = state.currentId;
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
  const peer = state.currentId;
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
