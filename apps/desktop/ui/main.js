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

// B15: apply every webview input-privacy hint to each explicitly classified
// textual editor. The webview/OS may ignore these hints, which is surfaced in
// the shared policy instead of being presented as a guarantee.
function applyIncognitoInputPrivacy(root = document) {
  $$('[data-incognito-input]', root).forEach((editor) => {
    editor.setAttribute("autocomplete", "off");
    editor.setAttribute("autocorrect", "off");
    editor.setAttribute("autocapitalize", "off");
    editor.setAttribute("spellcheck", "false");
  });
}

applyIncognitoInputPrivacy();

const THEME_KEY = "komms.appearance.theme";
const THEME_VALUES = new Set(["system", "light", "dark"]);
const systemTheme = matchMedia("(prefers-color-scheme: dark)");

function cachedTheme() {
  const value = localStorage.getItem(THEME_KEY);
  return THEME_VALUES.has(value) ? value : "system";
}

function applyTheme(preference, cache = true) {
  const safe = THEME_VALUES.has(preference) ? preference : "system";
  if (cache) localStorage.setItem(THEME_KEY, safe);
  document.documentElement.dataset.theme = safe;
  document.documentElement.dataset.resolvedTheme = safe === "system"
    ? (systemTheme.matches ? "dark" : "light") : safe;
  const gate = $("#gate-theme");
  if (gate) gate.value = safe;
}

systemTheme.addEventListener("change", () => {
  if (document.documentElement.dataset.theme === "system") applyTheme("system", false);
});

const state = {
  dataDir: "",
  address: "",
  peer: "",
  contacts: [],
  groups: [],
  folders: [],
  folderSelection: { kind: "all", id: null },
  folderMatches: null,
  labels: [],
  labelFilter: { selected: [], mode: "any", matches: null },
  pins: [],
  pinRows: [],
  icons: new Map(),
  noteToSelfId: null,
  currentKind: null, // "contact", "group", or "note"
  currentId: null,
  unread: new Map(), // peer id → count
  groupUnread: new Map(), // group id → count
  msgEls: new Map(), // message id → bubble element (for state updates)
  attachmentNotified: new Set(), // inbound transfer ids already announced
  recording: null,
  audioDraft: null,
  imageDraft: null,
  mentionDraft: { group: null, spans: [], capability: null, lastText: "", suppressInput: false },
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

const LABEL_COLORS = ["neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink"];
const LABEL_COLOR_NAMES = Object.fromEntries(LABEL_COLORS.map((color) => [color, color[0].toUpperCase() + color.slice(1)]));

function labelCue(label) {
  return `${LABEL_COLOR_NAMES[label.color] ?? "Neutral"}, label ${label.order + 1}`;
}

function labelAccessibleName(label) {
  return `${label.name}, ${labelCue(label)}`;
}

function labelChip(label) {
  const chip = document.createElement("span");
  const color = LABEL_COLORS.includes(label.color) ? label.color : "neutral";
  chip.className = `label-chip label-color-${color}`;
  chip.title = labelAccessibleName(label);
  chip.setAttribute("aria-label", labelAccessibleName(label));
  const name = document.createElement("bdi");
  name.dir = "auto";
  name.textContent = label.name;
  chip.append(name);
  return chip;
}

function labelTarget(kind = state.currentKind, id = state.currentId) {
  if (kind === "contact") return { kind: "peer", id };
  if (kind === "group") return { kind: "group", id };
  if (kind === "note") return { kind: "note_to_self", id: null };
  return null;
}

function labelTargetKey(target) {
  return `${target.kind}:${target.id ?? ""}`;
}

function folderTarget(kind = state.currentKind, id = state.currentId) {
  if (kind === "contact") return { kind: "peer", id };
  if (kind === "group") return { kind: "group", id };
  if (kind === "note") return { kind: "note_to_self", id: null };
  return null;
}

const ICON_GLYPHS = ["person", "group", "folder", "note", "star", "heart", "shield", "compass"];

function customIconTarget(kind = state.currentKind, id = state.currentId) {
  if (kind === "contact") return { kind: "contact", id };
  if (kind === "group") return { kind: "group", id };
  if (kind === "folder") return { kind: "folder", id };
  if (kind === "note") return { kind: "note_to_self", id: null };
  return null;
}

function customIconKey(target) {
  return `${target.kind}:${target.id ?? ""}`;
}

function generatedInitials(name) {
  const words = String(name ?? "").trim().split(/\s+/u).filter(Boolean);
  if (words.length === 0) return "?";
  const first = [...words[0]][0] ?? "?";
  const last = words.length > 1 ? ([...words.at(-1)][0] ?? "") : "";
  return `${first}${last}`.toLocaleUpperCase();
}

async function loadCustomIcon(target) {
  const key = customIconKey(target);
  if (state.icons.has(key)) return state.icons.get(key);
  const icon = await invoke("custom_icon", { target });
  state.icons.set(key, icon);
  return icon;
}

async function applyCustomIcon(avatar, target, fallback, accessibleName) {
  avatar.dataset.iconKind = target.kind;
  avatar.dataset.iconId = target.id ?? "";
  avatar.dataset.iconFallback = fallback;
  avatar.dataset.iconName = accessibleName;
  avatar.replaceChildren();
  avatar.textContent = fallback;
  try {
    const icon = await loadCustomIcon(target);
    if (!icon || !avatar.isConnected) return;
    const image = document.createElement("img");
    image.src = icon.data_url;
    image.alt = "";
    image.width = icon.width;
    image.height = icon.height;
    avatar.replaceChildren(image);
    avatar.title = `Private local icon for ${accessibleName}`;
  } catch {
    // Missing, corrupt, or concurrently removed icons always retain initials.
  }
}

async function refreshVisibleCustomIcons(clearCache = false) {
  if (clearCache) state.icons.clear();
  const work = $$('[data-icon-kind]').map((avatar) => {
    const target = {
      kind: avatar.dataset.iconKind,
      id: avatar.dataset.iconKind === "note_to_self" ? null : avatar.dataset.iconId,
    };
    return applyCustomIcon(
      avatar,
      target,
      avatar.dataset.iconFallback || "?",
      avatar.dataset.iconName || "conversation",
    );
  });
  await Promise.all(work);
}

function folderAccessibleName(folder) {
  return `${folder.name}, folder ${folder.order + 1}`;
}

function exactFolderNameValid(name) {
  return exactLabelNameValid(name);
}

function currentTargetName() {
  if (state.currentKind === "contact") return contactName(state.currentId);
  if (state.currentKind === "group") return currentGroup()?.name ?? "Unavailable group";
  return "Note to self";
}

function exactLabelNameValid(name) {
  if (!name || new TextEncoder().encode(name).length > 256) return false;
  const whitespace = new Set([0x09,0x0a,0x0b,0x0c,0x0d,0x20,0x85,0x200e,0x200f,0x2028,0x2029]);
  return ![...name].every((character) => whitespace.has(character.codePointAt(0)));
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

function formatDuration(milliseconds) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function waveformFromSamples(samples) {
  const peaks = new Array(64).fill(0);
  for (let i = 0; i < samples.length; i += 1) {
    const bin = Math.min(63, Math.floor((i * 64) / samples.length));
    peaks[bin] = Math.max(peaks[bin], Math.abs(samples[i]));
  }
  return peaks.map((peak) => Math.round(peak * 32768));
}

function renderWaveform(peaks, label) {
  const waveform = document.createElement("div");
  waveform.className = "audio-waveform";
  waveform.setAttribute("role", "img");
  waveform.setAttribute("aria-label", label);
  const max = Math.max(1, ...peaks);
  for (const peak of peaks) {
    const bar = document.createElement("span");
    bar.style.height = `${Math.max(5, Math.round((peak / max) * 100))}%`;
    waveform.append(bar);
  }
  return waveform;
}

function renderAudioPlayer(container, source, durationMs, waveform, label) {
  const meta = document.createElement("div");
  meta.className = "audio-meta";
  meta.textContent = `${formatDuration(durationMs)} · mono PCM WAV · 16 kHz`;
  const audio = document.createElement("audio");
  audio.controls = true;
  audio.preload = "metadata";
  audio.src = source;
  audio.setAttribute("aria-label", label);
  container.append(meta, renderWaveform(waveform, `${label} waveform`), audio);
}

function resampleMono(samples, sourceRate) {
  if (sourceRate === 16000) return samples;
  const length = Math.max(1, Math.floor((samples.length * 16000) / sourceRate));
  const output = new Float32Array(length);
  const ratio = sourceRate / 16000;
  for (let i = 0; i < length; i += 1) {
    const at = i * ratio;
    const left = Math.floor(at);
    const right = Math.min(samples.length - 1, left + 1);
    const fraction = at - left;
    output[i] = samples[left] * (1 - fraction) + samples[right] * fraction;
  }
  return output;
}

function canonicalWave(samples) {
  if (samples.length === 0 || samples.length > 16000 * 60) {
    throw new Error("recording is empty or exceeds 60 seconds");
  }
  const bytes = new Uint8Array(44 + samples.length * 2);
  const view = new DataView(bytes.buffer);
  const ascii = (offset, text) => [...text].forEach((character, index) => {
    bytes[offset + index] = character.charCodeAt(0);
  });
  ascii(0, "RIFF");
  view.setUint32(4, bytes.length - 8, true);
  ascii(8, "WAVE");
  ascii(12, "fmt ");
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, 16000, true);
  view.setUint32(28, 32000, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  ascii(36, "data");
  view.setUint32(40, samples.length * 2, true);
  samples.forEach((sample, index) => {
    const bounded = Math.max(-1, Math.min(1, sample));
    view.setInt16(44 + index * 2, bounded < 0 ? bounded * 32768 : bounded * 32767, true);
  });
  return bytes;
}

function bytesBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  }
  return btoa(binary);
}

function discardAudioDraft() {
  if (!state.audioDraft) return;
  URL.revokeObjectURL(state.audioDraft.url);
  state.audioDraft = null;
  $("#recording-status").textContent = "Audio recording discarded.";
}

function discardImageDraft() {
  const token = state.imageDraft?.token;
  state.imageDraft = null;
  if (token) invoke("discard_image_edit", { token }).catch(() => {});
}

function releaseRecorder(recorder) {
  clearInterval(recorder.timer);
  recorder.processor.onaudioprocess = null;
  recorder.source.disconnect();
  recorder.processor.disconnect();
  recorder.stream.getTracks().forEach((track) => {
    track.onended = null;
    track.stop();
  });
  recorder.context.close().catch(() => {});
  state.recording = null;
  const button = $("#btn-record");
  button.classList.remove("recording");
  button.setAttribute("aria-pressed", "false");
  button.textContent = "Record audio";
}

function abortRecording(reason) {
  const recorder = state.recording;
  if (!recorder) return;
  releaseRecorder(recorder);
  recorder.chunks.length = 0;
  $("#recording-status").textContent = reason;
  toast(reason, true);
}

async function stopRecording(capped = false) {
  const recorder = state.recording;
  if (!recorder) return;
  releaseRecorder(recorder);
  const sourceSamples = new Float32Array(recorder.sampleCount);
  let offset = 0;
  for (const chunk of recorder.chunks) {
    sourceSamples.set(chunk, offset);
    offset += chunk.length;
  }
  recorder.chunks.length = 0;
  try {
    const samples = resampleMono(sourceSamples, recorder.context.sampleRate);
    const bytes = canonicalWave(samples);
    discardAudioDraft();
    const url = URL.createObjectURL(new Blob([bytes], { type: "audio/wav" }));
    state.audioDraft = {
      bytes,
      url,
      durationMs: Math.floor((samples.length * 1000) / 16000),
      waveform: waveformFromSamples(samples),
    };
    $("#recording-status").textContent = capped
      ? "Maximum duration reached. Recording stopped; review before sending."
      : "Recording stopped. Review before sending.";
    const carrier = await call("audio_carrier_explanation", {
      conversation: state.currentKind === "group" ? "group" : "pairwise",
      destination: state.currentId,
    });
    const root = openModal("Review audio message", "tpl-audio-review");
    renderAudioPlayer(
      root.querySelector('[data-f="audio-review"]'),
      url,
      state.audioDraft.durationMs,
      state.audioDraft.waveform,
      "Review recorded audio"
    );
    const carrierText = root.querySelector('[data-f="carrier"]');
    carrierText.textContent = carrier;
    carrierText.dataset.snapshot = carrier;
    root.addEventListener("click", async (event) => {
      if (event.target.matches('[data-act="discard-audio"]')) {
        discardAudioDraft();
        closeModal();
      }
      if (!event.target.matches('[data-act="send-audio"]')) return;
      const button = event.target;
      button.disabled = true;
      try {
        const latestCarrier = await call("audio_carrier_explanation", {
          conversation: state.currentKind === "group" ? "group" : "pairwise",
          destination: state.currentId,
        });
        if (latestCarrier !== carrierText.dataset.snapshot) {
          carrierText.textContent = latestCarrier;
          carrierText.dataset.snapshot = latestCarrier;
          button.disabled = false;
          showError(root, "Carrier state changed. Review the updated explanation, then choose Send audio again.");
          return;
        }
        const encoded = bytesBase64(state.audioDraft.bytes);
        if (state.currentKind === "group") {
          await invoke("send_group_recorded_audio", { group: state.currentId, encoded });
        } else {
          await invoke("send_recorded_audio", { peer: state.currentId, encoded });
        }
        discardAudioDraft();
        closeModal();
        await renderMessages();
      } catch (error) {
        button.disabled = false;
        showError(root, error);
      }
    });
  } catch (error) {
    discardAudioDraft();
    $("#recording-status").textContent = `Recording failed: ${error}`;
    toast(String(error), true);
  }
}

async function startRecording() {
  if (!state.currentId || state.currentKind === "note" || state.recording) return;
  discardAudioDraft();
  let stream;
  let context;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true },
      video: false,
    });
    context = new AudioContext();
    await context.resume();
    const source = context.createMediaStreamSource(stream);
    const processor = context.createScriptProcessor(4096, 1, 1);
    const recorder = {
      stream,
      context,
      source,
      processor,
      chunks: [],
      sampleCount: 0,
      started: performance.now(),
      timer: null,
      stopping: false,
    };
    const maximum = context.sampleRate * 60;
    processor.onaudioprocess = (event) => {
      if (recorder.stopping) return;
      const input = event.inputBuffer.getChannelData(0);
      const remaining = maximum - recorder.sampleCount;
      const take = Math.min(remaining, input.length);
      if (take > 0) {
        recorder.chunks.push(new Float32Array(input.slice(0, take)));
        recorder.sampleCount += take;
      }
      if (recorder.sampleCount >= maximum) {
        recorder.stopping = true;
        setTimeout(() => stopRecording(true), 0);
      }
    };
    source.connect(processor);
    processor.connect(context.destination);
    stream.getAudioTracks().forEach((track) => {
      track.onended = () => abortRecording("Microphone input was interrupted; recording discarded.");
    });
    state.recording = recorder;
    const button = $("#btn-record");
    button.classList.add("recording");
    button.setAttribute("aria-pressed", "true");
    button.textContent = "Stop 0:00";
    $("#recording-status").textContent = "Recording audio. Activate Stop when finished.";
    recorder.timer = setInterval(() => {
      const elapsed = Math.min(60, Math.floor((performance.now() - recorder.started) / 1000));
      button.textContent = `Stop ${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, "0")}`;
      $("#recording-status").textContent = `Recording audio, ${elapsed} seconds elapsed.`;
    }, 1000);
  } catch (error) {
    stream?.getTracks().forEach((track) => track.stop());
    if (context && context.state !== "closed") await context.close().catch(() => {});
    $("#recording-status").textContent = "Microphone permission was denied or unavailable.";
    toast(`Microphone unavailable: ${error}`, true);
  }
}

$("#btn-record").addEventListener("click", () => {
  if (state.recording) stopRecording();
  else startRecording();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) return;
  abortRecording("Recording stopped and discarded because Komms was hidden or locked.");
  if (state.audioDraft) {
    closeModal();
    $("#recording-status").textContent = "Audio review discarded because Komms was hidden or locked.";
  }
  if (state.imageDraft) closeModal();
});
window.addEventListener("pagehide", () => {
  abortRecording("Recording discarded on shutdown.");
  discardAudioDraft();
  discardImageDraft();
});

// ── gate (create / unlock / restore) ────────────────────────────────────

let gateMode = "open";

applyTheme(cachedTheme(), false);
$("#gate-theme").addEventListener("change", (event) => applyTheme(event.target.value));

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
  refreshFolders();
  refreshLabels();
  call("note_to_self_id").then((id) => { state.noteToSelfId = id; });
  applyCustomIcon(
    $("#note-to-self .avatar"),
    { kind: "note_to_self", id: null },
    "N",
    "Note to self",
  );
  syncThemeAfterUnlock();
  refreshStatus();
  state.statusTimer = setInterval(refreshStatus, 5000);
}

async function syncThemeAfterUnlock() {
  try {
    const sealed = await invoke("theme");
    if (sealed.persisted) {
      applyTheme(sealed.preference);
      return;
    }
    const preference = cachedTheme();
    await invoke("set_theme", { preference });
    applyTheme(preference);
  } catch (error) {
    toast(String(error), true);
  }
}

async function leaveApp() {
  abortRecording("Recording stopped and discarded because Komms was locked.");
  closeModal();
  clearInterval(state.statusTimer);
  state.statusTimer = null;
  state.currentKind = null;
  state.currentId = null;
  state.contacts = [];
  state.groups = [];
  state.folders = [];
  state.folderSelection = { kind: "all", id: null };
  state.folderMatches = null;
  state.labels = [];
  state.labelFilter = { selected: [], mode: "any", matches: null };
  state.pins = [];
  state.pinRows = [];
  state.icons.clear();
  state.noteToSelfId = null;
  state.unread.clear();
  state.groupUnread.clear();
  state.msgEls.clear();
  $("#messages").replaceChildren();
  $("#attachment-transfers").replaceChildren();
  $("#app").hidden = true;
  $("#gate").hidden = false;
  $("#chat-pane").hidden = true;
  $("#chat-empty").hidden = false;
  await probeGate(state.dataDir).catch(() => {});
}

let rapidLockInFlight = false;
async function rapidLock() {
  if (rapidLockInFlight || $("#app").hidden) return;
  rapidLockInFlight = true;
  try {
    await call("lock");
    await leaveApp();
  } finally {
    rapidLockInFlight = false;
  }
}

$("#btn-lock").addEventListener("click", rapidLock);

document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLocaleLowerCase() === "l") {
    event.preventDefault();
    rapidLock();
  }
});

const privacyShield = $("#screen-privacy-shield");
listen("screen-security-focus", ({ payload: focused }) => {
  privacyShield.hidden = Boolean(focused);
});

invoke("screen_security_policy").then((policy) => {
  $("#screen-security-mechanism").textContent = policy.mechanism;
  const limits = $("#screen-security-limitations");
  limits.replaceChildren(...policy.limitations.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
}).catch((error) => {
  $("#screen-security-mechanism").textContent = `Protection status unavailable: ${String(error)}`;
});

invoke("incognito_keyboard_policy").then((policy) => {
  $("#incognito-keyboard-mechanism").textContent = policy.mechanism;
  const limits = $("#incognito-keyboard-limitations");
  limits.replaceChildren(...policy.limitations.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
}).catch((error) => {
  $("#incognito-keyboard-mechanism").textContent = `Input privacy status unavailable: ${String(error)}`;
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

async function targetLabels(target) {
  return invoke("labels_for_conversation", { target });
}

async function renderTargetBadges(container, target) {
  container.replaceChildren();
  try {
    for (const label of await targetLabels(target)) container.append(labelChip(label));
  } catch {
    // A target can disappear between list and badge reads. The next refresh
    // removes the row; no stale relationship is guessed from its name.
  }
}

function applyLabelFilterVisibility() {
  const matches = state.folderMatches;
  const visible = (target) => matches === null || matches.has(labelTargetKey(target));
  const pinned = new Set(state.pinRows.filter((row) => row.pinned).map((row) => labelTargetKey(row.target)));
  for (const button of $$("#contact-list .contact")) {
    const target = { kind: "peer", id: button.dataset.peer };
    button.hidden = !visible(target) || pinned.has(labelTargetKey(target));
  }
  for (const button of $$("#group-list .contact")) {
    const target = { kind: "group", id: button.dataset.group };
    button.hidden = !visible(target) || pinned.has(labelTargetKey(target));
  }
  const note = { kind: "note_to_self", id: null };
  $("#note-to-self").hidden = !visible(note) || pinned.has(labelTargetKey(note));
}

function openPinTarget(target) {
  if (target.kind === "peer") return openChat(target.id);
  if (target.kind === "group") return openGroup(target.id);
  return openNoteToSelf();
}

async function reorderPinTarget(target, delta) {
  const index = state.pins.findIndex((pin) => labelTargetKey(pin.target) === labelTargetKey(target));
  const next = index + delta;
  if (index < 0 || next < 0 || next >= state.pins.length) return;
  const ordered = state.pins.map((pin) => pin.target);
  [ordered[index], ordered[next]] = [ordered[next], ordered[index]];
  await call("reorder_pins", { targets: ordered });
  await runLabelFilter(true);
}

async function renderPinnedList() {
  const list = $("#pinned-list");
  list.replaceChildren();
  const rows = state.pinRows.filter((row) => row.pinned);
  const stale = state.pins.filter((pin) => !pin.active);
  $("#pinned-section").hidden = rows.length === 0 && stale.length === 0;
  for (const row of rows) {
    const wrap = document.createElement("div");
    wrap.className = "pinned-row";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "contact";
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = row.target.kind === "note_to_self" ? "N" : row.target.kind === "group" ? "G" : (row.display_name?.[0] ?? "?").toUpperCase();
    const name = document.createElement("span");
    name.className = "c-name";
    name.textContent = row.target.kind === "note_to_self" ? "Note to self" : (row.display_name ?? "Unavailable");
    const iconTarget = row.target.kind === "peer"
      ? { kind: "contact", id: row.target.id }
      : { kind: row.target.kind, id: row.target.id };
    applyCustomIcon(avatar, iconTarget, generatedInitials(name.textContent), name.textContent);
    const badges = document.createElement("span");
    badges.className = "label-badges";
    button.append(avatar, name, badges);
    button.addEventListener("click", () => openPinTarget(row.target));
    renderTargetBadges(badges, row.target);
    const up = document.createElement("button");
    up.type = "button";
    up.className = "ghost";
    up.textContent = "↑";
    up.title = "Move pin earlier";
    up.setAttribute("aria-label", `Move ${name.textContent} pin earlier`);
    up.addEventListener("click", () => reorderPinTarget(row.target, -1));
    const down = document.createElement("button");
    down.type = "button";
    down.className = "ghost";
    down.textContent = "↓";
    down.title = "Move pin later";
    down.setAttribute("aria-label", `Move ${name.textContent} pin later`);
    down.addEventListener("click", () => reorderPinTarget(row.target, 1));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost";
    remove.textContent = "Unpin";
    remove.addEventListener("click", async () => {
      await call("unpin_conversation", { target: row.target });
      await runLabelFilter(true);
    });
    wrap.append(button, up, down, remove);
    list.append(wrap);
  }
  for (const pin of stale) {
    const wrap = document.createElement("div");
    wrap.className = "pinned-row stale-pin-row";
    const description = document.createElement("span");
    const targetName = pin.target.kind === "note_to_self" ? "note-to-self" : `${pin.target.kind} conversation`;
    description.textContent = `Unavailable ${targetName} pin`;
    const cleanup = document.createElement("button");
    cleanup.type = "button";
    cleanup.className = "danger";
    cleanup.textContent = "Clean up";
    cleanup.setAttribute("aria-label", `Clean up unavailable ${targetName} pin`);
    cleanup.addEventListener("click", async () => {
      try {
        await call("cleanup_stale_pin", { target: pin.target });
        $("#pin-status").textContent = `Unavailable ${targetName} pin removed.`;
        await runLabelFilter(true);
      } catch (error) {
        $("#pin-status").textContent = String(error);
      }
    });
    wrap.append(description, cleanup);
    list.append(wrap);
  }
}

async function runLabelFilter(announce = false) {
  const prior = state.labelFilter.selected.length;
  const result = await call("pin_conversations", {
    selection: state.folderSelection,
    labels: state.labelFilter.selected,
    mode: state.labelFilter.mode,
  });
  state.folderSelection = result.selection;
  state.labelFilter.selected = result.selected_labels;
  state.labelFilter.matches = new Set(result.conversations.map((conversation) => labelTargetKey(conversation.target)));
  state.folderMatches = state.labelFilter.matches;
  state.pinRows = result.conversations;
  state.pins = await call("pins");
  if (result.unavailable_labels.length > 0) {
    $("#label-filter-status").textContent = `${result.unavailable_labels.length} unavailable selected label ${result.unavailable_labels.length === 1 ? "was" : "were"} removed.`;
  } else if (announce) {
    $("#label-filter-status").textContent = state.labelFilter.selected.length === 0
      ? "Label filter cleared; every conversation is shown."
      : `${result.conversations.length} conversation ${result.conversations.length === 1 ? "matches" : "match"} ${state.labelFilter.mode === "any" ? "any" : "all"} selected labels.`;
  } else if (prior !== result.selected.length) {
    $("#label-filter-status").textContent = "Unavailable label selections were removed.";
  }
  $("#btn-clear-label-filter").hidden = state.labelFilter.selected.length === 0;
  applyLabelFilterVisibility();
  await renderPinnedList();
}

async function refreshFolders(announce = false) {
  state.folders = await call("folders");
  if (state.folderSelection.kind === "folder" && !state.folders.some((folder) => folder.id === state.folderSelection.id)) {
    state.folderSelection = { kind: "all", id: null };
    $("#folder-navigation-status").textContent = "The selected folder is unavailable; showing All conversations.";
  }
  const items = $("#folder-navigation-items");
  items.replaceChildren();
  for (const folder of state.folders) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.dataset.folderKind = "folder";
    button.dataset.folderId = folder.id;
    button.setAttribute("aria-label", `Show ${folderAccessibleName(folder)}`);
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    const fallback = generatedInitials(folder.name);
    avatar.textContent = fallback;
    const name = document.createElement("bdi");
    name.dir = "auto";
    name.textContent = folder.name;
    button.append(avatar, name);
    applyCustomIcon(
      avatar,
      { kind: "folder", id: folder.id },
      fallback,
      `folder ${folder.name}`,
    );
    button.addEventListener("click", async () => {
      state.folderSelection = { kind: "folder", id: folder.id };
      await runLabelFilter(true);
      renderFolderNavigationSelection();
      $("#folder-navigation-status").textContent = `Showing ${folderAccessibleName(folder)}.`;
    });
    items.append(button);
  }
  renderFolderNavigationSelection();
  await runLabelFilter(announce);
}

function renderFolderNavigationSelection() {
  for (const button of $$("#folder-navigation button")) {
    const selected = button.dataset.folderKind === state.folderSelection.kind
      && (button.dataset.folderKind !== "folder" || button.dataset.folderId === state.folderSelection.id);
    button.classList.toggle("active", selected);
    button.setAttribute("aria-current", selected ? "true" : "false");
  }
}

for (const button of $$('#folder-navigation > button[data-folder-kind]')) {
  button.addEventListener("click", async () => {
    state.folderSelection = { kind: button.dataset.folderKind, id: null };
    await runLabelFilter(true);
    renderFolderNavigationSelection();
    $("#folder-navigation-status").textContent = `Showing ${button.textContent}.`;
  });
}

$("#folder-navigation").addEventListener("keydown", (event) => {
  if (!["ArrowDown", "ArrowUp"].includes(event.key)) return;
  const buttons = $$("button", event.currentTarget).filter((button) => !button.hidden);
  const index = buttons.indexOf(document.activeElement);
  if (index < 0) return;
  event.preventDefault();
  buttons[(index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length].focus();
});

async function refreshLabels(announce = false) {
  state.labels = await call("labels");
  const options = $("#label-filter-options");
  options.replaceChildren();
  if (state.labels.length === 0) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "No labels yet";
    options.append(empty);
  }
  for (const label of state.labels) {
    const row = document.createElement("label");
    row.className = "label-filter-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = label.id;
    input.checked = state.labelFilter.selected.includes(label.id);
    input.setAttribute("aria-label", `Filter by ${labelAccessibleName(label)}`);
    input.addEventListener("change", async () => {
      state.labelFilter.selected = $$('input[type="checkbox"]', options).filter((item) => item.checked).map((item) => item.value);
      await runLabelFilter(true);
      await refreshConversationBadges();
    });
    row.append(input, labelChip(label));
    options.append(row);
  }
  await runLabelFilter(announce);
  await refreshConversationBadges();
}

async function refreshConversationBadges() {
  const work = [];
  for (const button of $$("#contact-list .contact")) {
    work.push(renderTargetBadges($(".label-badges", button), { kind: "peer", id: button.dataset.peer }));
  }
  for (const button of $$("#group-list .contact")) {
    work.push(renderTargetBadges($(".label-badges", button), { kind: "group", id: button.dataset.group }));
  }
  work.push(renderTargetBadges($("#note-to-self .label-badges"), { kind: "note_to_self", id: null }));
  await Promise.all(work);
  const target = labelTarget();
  if (target) await renderTargetBadges($("#chat-label-badges"), target);
}

$("#label-filter-options").addEventListener("keydown", (event) => {
  if (!['ArrowDown', 'ArrowUp'].includes(event.key)) return;
  const inputs = $$('input[type="checkbox"]', event.currentTarget);
  const index = inputs.indexOf(document.activeElement);
  if (index < 0 || inputs.length === 0) return;
  event.preventDefault();
  inputs[(index + (event.key === 'ArrowDown' ? 1 : -1) + inputs.length) % inputs.length].focus();
});

$$('input[name="label-filter-mode"]').forEach((input) => input.addEventListener("change", async () => {
  if (!input.checked) return;
  state.labelFilter.mode = input.value;
  await runLabelFilter(true);
}));

$("#btn-clear-label-filter").addEventListener("click", async () => {
  state.labelFilter.selected = [];
  await refreshLabels(true);
  $("#label-filter-options input")?.focus();
});

async function refreshContacts() {
  state.contacts = await call("contacts");
  const list = $("#contact-list");
  list.textContent = "";
  for (const c of state.contacts) {
    const btn = document.createElement("button");
    btn.className = "contact" + (state.currentKind === "contact" && c.peer === state.currentId ? " active" : "");
    btn.dataset.peer = c.peer;
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    const fallback = generatedInitials(c.name);
    avatar.textContent = fallback;
    const name = document.createElement("span");
    name.className = "c-name";
    name.textContent = c.name || c.peer.slice(0, 12) + "…";
    applyCustomIcon(avatar, { kind: "contact", id: c.peer }, fallback, name.textContent);
    const labels = document.createElement("span");
    labels.className = "label-badges";
    btn.append(avatar, name, labels);
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
  applyLabelFilterVisibility();
  await refreshConversationBadges();
  if (state.currentKind === "contact") updateChatHead();
}

function contactName(peer) {
  return state.contacts.find((c) => c.peer === peer)?.name ?? peer.slice(0, 12) + "…";
}

function memberName(peer) {
  if (peer === state.peer) return "You";
  const contact = state.contacts.find((candidate) => candidate.peer === peer);
  if (contact) return contact.name;
  const position = (currentGroup()?.members ?? []).indexOf(peer);
  return position >= 0 ? `Group member ${position + 1}` : "Unavailable group member";
}

function resetMentionDraft(message = "") {
  state.mentionDraft = {
    group: state.currentKind === "group" ? state.currentId : null,
    spans: [],
    capability: null,
    lastText: $("#composer-input").value,
    suppressInput: false,
  };
  closeMentionPicker(false);
  renderMentionTokens();
  $("#mention-status").textContent = message;
}

function memberLabel(peer, group = currentGroup()) {
  const base = memberName(peer);
  const sameName = (group?.members ?? []).filter((member) => memberName(member) === base);
  if (sameName.length < 2) return base;
  const position = (group?.members ?? []).indexOf(peer) + 1;
  return `\u2068${base}\u2069, group member ${position}`;
}

function hasUnpairedSurrogate(text) {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function utf8Offset(text, utf16Offset) {
  return new TextEncoder().encode(text.slice(0, utf16Offset)).length;
}

function utf16Offset(text, byteOffset) {
  let bytes = 0;
  let units = 0;
  for (const character of text) {
    if (bytes === byteOffset) return units;
    bytes += new TextEncoder().encode(character).length;
    units += character.length;
    if (bytes > byteOffset) return null;
  }
  return bytes === byteOffset ? units : null;
}

function reconcileMentionEdit(oldText, newText) {
  if (state.mentionDraft.suppressInput || oldText === newText) return;
  let prefix = 0;
  while (prefix < oldText.length && prefix < newText.length && oldText[prefix] === newText[prefix]) {
    prefix += 1;
  }
  let suffix = 0;
  while (
    suffix < oldText.length - prefix
    && suffix < newText.length - prefix
    && oldText[oldText.length - 1 - suffix] === newText[newText.length - 1 - suffix]
  ) {
    suffix += 1;
  }
  const oldEnd = oldText.length - suffix;
  const newEnd = newText.length - suffix;
  const delta = newEnd - oldEnd;
  let removed = 0;
  state.mentionDraft.spans = state.mentionDraft.spans.flatMap((span) => {
    if (prefix === oldEnd) {
      if (prefix <= span.start) return [{ ...span, start: span.start + delta, end: span.end + delta }];
      if (prefix >= span.end) return [span];
      removed += 1;
      return [];
    }
    if (oldEnd <= span.start) return [{ ...span, start: span.start + delta, end: span.end + delta }];
    if (prefix >= span.end) return [span];
    removed += 1;
    return [];
  });
  if (removed > 0) {
    $("#mention-status").textContent = `${removed} semantic mention ${removed === 1 ? "link was" : "links were"} removed because its text was edited.`;
  }
  renderMentionTokens();
}

function replaceDraftRange(start, end, replacement) {
  const input = $("#composer-input");
  const oldText = input.value;
  const newText = oldText.slice(0, start) + replacement + oldText.slice(end);
  reconcileMentionEdit(oldText, newText);
  state.mentionDraft.suppressInput = true;
  input.value = newText;
  state.mentionDraft.lastText = newText;
  state.mentionDraft.suppressInput = false;
  const caret = start + replacement.length;
  input.setSelectionRange(caret, caret);
  return caret;
}

function renderMentionTokens() {
  const root = $("#mention-tokens");
  root.replaceChildren();
  root.hidden = state.mentionDraft.spans.length === 0;
  state.mentionDraft.spans.forEach((span, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "mention-token";
    button.textContent = `Mention ${memberLabel(span.target)} ×`;
    button.setAttribute("aria-label", `Remove mention of ${memberLabel(span.target)}`);
    button.addEventListener("click", () => {
      state.mentionDraft.spans.splice(index, 1);
      replaceDraftRange(span.start, span.end, "");
      $("#mention-status").textContent = `Mention of ${memberLabel(span.target)} removed with its visible text.`;
      renderMentionTokens();
      $("#composer-input").focus();
    });
    root.append(button);
  });
}

function closeMentionPicker(focusInput = true) {
  const picker = $("#mention-picker");
  picker.hidden = true;
  $("#btn-mention").setAttribute("aria-expanded", "false");
  if (focusInput && state.currentKind === "group") $("#composer-input").focus();
}

async function openMentionPicker() {
  const group = currentGroup();
  if (!group) return;
  const capability = await call("group_mention_capability", { group: group.id });
  state.mentionDraft.capability = capability;
  state.mentionDraft.group = group.id;
  const blockers = capability.issues.map((issue) => `${memberLabel(issue.peer, group)} (${issue.reason})`);
  $("#mention-status").textContent = capability.supported
    ? "All current members support semantic mentions. Review the exact final text before Send."
    : `Semantic mentions cannot be sent now: ${blockers.join(", ")}. Send will offer plain-text fallback with no mention notification.`;

  const picker = $("#mention-picker");
  picker.replaceChildren();
  group.members.forEach((peer) => {
    const option = document.createElement("button");
    option.type = "button";
    option.setAttribute("role", "option");
    option.setAttribute("aria-selected", "false");
    option.dataset.peer = peer;
    option.textContent = memberLabel(peer, group);
    option.addEventListener("click", () => insertMention(peer));
    picker.append(option);
  });
  picker.hidden = false;
  $("#btn-mention").setAttribute("aria-expanded", "true");
  picker.querySelector('[role="option"]')?.focus();
}

async function refreshMentionReview(reason) {
  if (
    state.currentKind !== "group"
    || state.mentionDraft.spans.length === 0
    || state.mentionDraft.group !== state.currentId
  ) return;
  const fresh = await call("group_mention_capability", { group: state.currentId });
  if (!state.mentionDraft.capability || fresh.review_token !== state.mentionDraft.capability.review_token) {
    state.mentionDraft.capability = fresh;
    $("#mention-status").textContent = `${reason} Review the exact text and mention tokens before sending.`;
  }
}

function insertMention(peer) {
  const input = $("#composer-input");
  const start = input.selectionStart ?? input.value.length;
  const end = input.selectionEnd ?? start;
  const displayName = memberName(peer);
  const visible = `@${displayName}`;
  const caret = replaceDraftRange(start, end, visible);
  state.mentionDraft.spans.push({ start, end: caret, target: peer });
  state.mentionDraft.spans.sort((left, right) => left.start - right.start || left.end - right.end);
  renderMentionTokens();
  closeMentionPicker();
  $("#mention-status").textContent = `Mention of ${memberLabel(peer)} inserted. Review the exact final text before Send.`;
}

function appendMentionBody(container, message) {
  if (message.content_kind !== "mention" || !message.mention_spans?.length) {
    container.append(document.createTextNode(message.body));
    return;
  }
  let cursor = 0;
  for (const span of message.mention_spans) {
    const start = utf16Offset(message.body, span.start);
    const end = utf16Offset(message.body, span.end);
    if (start === null || end === null || start < cursor || end <= start) {
      container.replaceChildren(document.createTextNode("Unsupported message — update Komms"));
      return;
    }
    container.append(document.createTextNode(message.body.slice(cursor, start)));
    const mark = document.createElement("mark");
    mark.className = "mention-highlight";
    mark.tabIndex = 0;
    mark.textContent = message.body.slice(start, end);
    mark.setAttribute("aria-label", `Mention of ${memberLabel(span.target)}`);
    container.append(mark);
    cursor = end;
  }
  container.append(document.createTextNode(message.body.slice(cursor)));
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
    const fallback = generatedInitials(group.name || "Group");
    avatar.textContent = fallback;
    const name = document.createElement("span");
    name.className = "c-name";
    name.textContent = group.name || "Unnamed group";
    applyCustomIcon(avatar, { kind: "group", id: group.id }, fallback, name.textContent);
    const detail = document.createElement("span");
    detail.className = "c-detail";
    detail.textContent = `${group.members.length} members`;
    const labels = document.createElement("span");
    labels.className = "label-badges";
    btn.append(avatar, name, labels, detail);
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
  applyLabelFilterVisibility();
  await refreshConversationBadges();
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
  $("#btn-mention").hidden = !isGroup;
  $("#btn-attach").hidden = isNote;
  $("#btn-record").hidden = isNote;
  $("#btn-schedule").hidden = isNote;
  $("#note-to-self").classList.toggle("active", isNote);
  const target = labelTarget();
  const isPinned = target && state.pins.some((pin) => labelTargetKey(pin.target) === labelTargetKey(target));
  $("#btn-conversation-pin").textContent = isPinned ? "Unpin" : "Pin";
  $("#btn-conversation-pin").setAttribute("aria-pressed", isPinned ? "true" : "false");
  if (target) renderTargetBadges($("#chat-label-badges"), target);
  else $("#chat-label-badges").replaceChildren();
}

$("#btn-conversation-pin").addEventListener("click", async () => {
  const target = labelTarget();
  if (!target) return;
  const isPinned = state.pins.some((pin) => labelTargetKey(pin.target) === labelTargetKey(target));
  await call(isPinned ? "unpin_conversation" : "pin_conversation", { target });
  await runLabelFilter(true);
  updateChatHead();
  $("#pin-status").textContent = isPinned ? "Conversation unpinned." : "Conversation pinned.";
});

// ── conversation ────────────────────────────────────────────────────────

async function openChat(peer) {
  state.currentKind = "contact";
  state.currentId = peer;
  state.unread.delete(peer);
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  $("#composer-input").value = "";
  resetMentionDraft();
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
  $("#composer-input").value = "";
  resetMentionDraft("Use Mention member to choose an exact current roster identity.");
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
  $("#composer-input").value = "";
  resetMentionDraft();
  updateChatHead();
  await renderMessages();
  $("#composer-input").focus();
}

$("#note-to-self").addEventListener("click", openNoteToSelf);

$("#composer-input").addEventListener("input", (event) => {
  const oldText = state.mentionDraft.lastText;
  const newText = event.currentTarget.value;
  reconcileMentionEdit(oldText, newText);
  state.mentionDraft.lastText = newText;
});

$("#btn-mention").addEventListener("click", () => {
  if ($("#mention-picker").hidden) openMentionPicker();
  else closeMentionPicker();
});

$("#btn-mention").addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown") {
    event.preventDefault();
    openMentionPicker();
  }
});

$("#mention-picker").addEventListener("keydown", (event) => {
  const options = $$('[role="option"]', event.currentTarget);
  const index = options.indexOf(document.activeElement);
  if (event.key === "Escape") {
    event.preventDefault();
    closeMentionPicker();
  } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    const direction = event.key === "ArrowDown" ? 1 : -1;
    options[(index + direction + options.length) % options.length]?.focus();
  } else if (event.key === "Enter" && document.activeElement?.matches('[role="option"]')) {
    event.preventDefault();
    document.activeElement.click();
  }
});

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
  appendMentionBody(el, m);
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
  const isAudio = primary?.media_type === "audio/wav";
  title.textContent = isAudio ? "Audio message" : (primary?.filename ?? "Attachment");
  const transferState = document.createElement("span");
  transferState.className = `attachment-state ${attachment.state}`;
  transferState.textContent = `${attachment.direction} · ${attachment.state.replaceAll("_", " ")}`;
  head.append(title, transferState);
  row.append(head);

  const preview = attachment.objects.find((object) => object.preview && object.state === "complete");
  if (preview) {
    const image = document.createElement("img");
    image.className = "attachment-preview";
    image.alt = `Local preview of ${primary?.filename ?? "attachment"}`;
    image.hidden = true;
    row.append(image);
    invoke("attachment_preview", { transfer: attachment.transfer_id })
      .then((source) => {
        if (!image.isConnected) return;
        image.src = source;
        image.hidden = false;
      })
      .catch(() => image.remove());
  }
  if (!preview && primary?.media_type === "image/png" && attachment.state === "complete") {
    const image = document.createElement("img");
    image.className = "attachment-preview";
    image.alt = `Protected exact image from ${attachment.direction === "inbound" ? "sender" : "you"}`;
    row.append(image);
    invoke("attachment_image", { transfer: attachment.transfer_id })
      .then((source) => { image.src = source; })
      .catch(() => image.remove());
  }

  if (isAudio && attachment.state === "complete") {
    const audioCard = document.createElement("div");
    audioCard.className = "audio-card";
    audioCard.setAttribute("aria-busy", "true");
    audioCard.textContent = "Preparing protected audio playback…";
    row.append(audioCard);
    invoke("attachment_audio", { transfer: attachment.transfer_id })
      .then((media) => {
        if (!audioCard.isConnected) return;
        audioCard.textContent = "";
        audioCard.setAttribute("aria-busy", "false");
        renderAudioPlayer(
          audioCard,
          media.data_url,
          media.duration_ms,
          media.waveform,
          `Audio message from ${attachment.direction === "inbound" ? "sender" : "you"}`
        );
      })
      .catch((error) => {
        if (!audioCard.isConnected) return;
        audioCard.setAttribute("aria-busy", "false");
        audioCard.textContent = `Audio unavailable: ${error}`;
      });
  }

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
  if (matching.length > 0) {
    const policy = document.createElement("p");
    policy.className = "attachment-background-policy";
    policy.textContent = "Transfers continue while Komms is open or minimized. Closing the app pauses network work; verified progress resumes after unlock.";
    panel.append(policy);
  }
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
  const visibleText = input.value;
  if (!visibleText.trim() || !state.currentId) return;
  if (state.currentKind === "group" && state.mentionDraft.spans.length > 0) {
    if (hasUnpairedSurrogate(visibleText)) {
      toast("The draft contains invalid Unicode and cannot be sent.", true);
      return;
    }
    const fresh = await call("group_mention_capability", { group: state.currentId });
    if (
      state.mentionDraft.group !== state.currentId
      || !state.mentionDraft.capability
      || fresh.review_token !== state.mentionDraft.capability.review_token
    ) {
      state.mentionDraft.capability = fresh;
      state.mentionDraft.group = state.currentId;
      $("#mention-status").textContent = "The roster, identity mapping, or capability support changed. Review the exact text and selected mention tokens, then press Send again.";
      $("#composer-input").focus();
      return;
    }
    if (!fresh.supported) {
      const blockers = fresh.issues.map((issue) => `${memberLabel(issue.peer)} (${issue.reason})`).join(", ");
      const plain = window.confirm(
        `Semantic mentions are unavailable for ${blockers}. Send the exact visible text as ordinary plain text? It will carry no semantic mention and trigger no mention notification.`
      );
      if (!plain) return;
      await call("send_group", { group: state.currentId, body: visibleText });
    } else {
      const spans = state.mentionDraft.spans.map((span) => ({
        start: utf8Offset(visibleText, span.start),
        end: utf8Offset(visibleText, span.end),
        target: span.target,
      }));
      await call("send_group_mention", {
        group: state.currentId,
        text: visibleText,
        spans,
        reviewToken: fresh.review_token,
      });
    }
  } else if (state.currentKind === "group") {
    await call("send_group", { group: state.currentId, body: visibleText.trim() });
  } else if (state.currentKind === "note") {
    await call("send_note_to_self", { body: visibleText.trim() });
  } else {
    await call("send", { peer: state.currentId, body: visibleText.trim() });
  }
  input.value = "";
  resetMentionDraft(state.currentKind === "group" ? "Use Mention member to choose an exact current roster identity." : "");
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

function attachmentConversation() {
  return state.currentKind === "group" ? "group" : "pairwise";
}

async function freshAttachmentCarrier(conversation, destination) {
  return call("attachment_carrier_explanation", { conversation, destination });
}

function carrierChangedText(error) {
  const text = String(error);
  const marker = "carrier_changed:";
  const at = text.indexOf(marker);
  return at < 0 ? null : text.slice(at + marker.length);
}

function cloneRecipe(recipe) {
  return JSON.parse(JSON.stringify(recipe));
}

function imageNumber(root, field) {
  const value = Number(root.querySelector(`[data-f="${field}"]`).value);
  if (!Number.isInteger(value) || value < 0) throw new Error(`${field.replaceAll("-", " ")} must be a whole number`);
  return value;
}

function centeredCrop(width, height, ratio) {
  let cropWidth = width;
  let cropHeight = Math.floor(width / ratio);
  if (cropHeight > height) {
    cropHeight = height;
    cropWidth = Math.floor(height * ratio);
  }
  return {
    x: Math.floor((width - cropWidth) / 2),
    y: Math.floor((height - cropHeight) / 2),
    width: cropWidth,
    height: cropHeight,
  };
}

function setCropFields(root, crop) {
  const chosen = crop ?? { x: 0, y: 0, width: state.imageDraft.orientedWidth, height: state.imageDraft.orientedHeight };
  for (const key of ["x", "y", "width", "height"]) {
    root.querySelector(`[data-f="crop-${key}"]`).value = chosen[key];
  }
}

function cropFromControls(root) {
  const preset = root.querySelector('[data-f="crop-preset"]').value;
  if (preset === "original") return null;
  if (preset !== "free") {
    const [wide, high] = preset.split(":").map(Number);
    return centeredCrop(state.imageDraft.orientedWidth, state.imageDraft.orientedHeight, wide / high);
  }
  return {
    x: imageNumber(root, "crop-x"),
    y: imageNumber(root, "crop-y"),
    width: imageNumber(root, "crop-width"),
    height: imageNumber(root, "crop-height"),
  };
}

function renderImageReview(root) {
  const draft = state.imageDraft;
  root.querySelector('[data-f="image-review"]').src = draft.review.data_url;
  root.querySelector('[data-f="image-info"]').textContent =
    `${draft.review.width} × ${draft.review.height} pixels · ${Number(draft.review.encoded_bytes).toLocaleString()} bytes · exact metadata-free PNG`;
  const regions = root.querySelector('[data-f="regions"]');
  regions.replaceChildren();
  draft.recipe.regions.forEach((region, index) => {
    const item = document.createElement("li");
    item.textContent = `${region.kind}, x ${region.x}, y ${region.y}, ${region.width} × ${region.height}, strength ${region.strength} `;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost";
    remove.dataset.removeRegion = index;
    remove.textContent = "Remove";
    remove.setAttribute("aria-label", `Remove privacy region ${index + 1}`);
    item.append(remove);
    regions.append(item);
  });
}

async function applyImageRecipe(root, recipe, remember = true) {
  const draft = state.imageDraft;
  const previous = cloneRecipe(draft.recipe);
  const review = await invoke("update_image_edit", { token: draft.token, recipe });
  if (remember) draft.history.push(previous);
  draft.recipe = cloneRecipe(recipe);
  draft.review = review;
  renderImageReview(root);
}

async function openImageEditor(selectedName, initial) {
  const conversation = attachmentConversation();
  const destination = state.currentId;
  let carrier;
  try {
    carrier = await freshAttachmentCarrier(conversation, destination);
  } catch (error) {
    await invoke("discard_image_edit", { token: initial.token }).catch(() => {});
    throw error;
  }
  const root = openModal("Edit and review image", "tpl-image-edit");
  $("#modal").classList.add("image-editing");
  state.imageDraft = {
    token: initial.token,
    review: initial,
    orientedWidth: initial.width,
    orientedHeight: initial.height,
    recipe: { crop: null, rotation_quarter_turns: 0, regions: [] },
    history: [],
    conversation,
    destination,
  };
  root.querySelector('[data-f="filename"]').value =
    (selectedName.includes(".") ? selectedName.replace(/\.[^.]+$/, "") : selectedName) + ".png";
  const carrierText = root.querySelector('[data-f="carrier"]');
  carrierText.textContent = carrier;
  carrierText.dataset.snapshot = carrier;
  setCropFields(root, null);
  renderImageReview(root);

  root.querySelector('[data-f="crop-preset"]').addEventListener("change", (event) => {
    const preset = event.target.value;
    if (preset === "original") setCropFields(root, null);
    else if (preset !== "free") {
      const [wide, high] = preset.split(":").map(Number);
      setCropFields(root, centeredCrop(initial.width, initial.height, wide / high));
    }
  });
  root.addEventListener("click", async (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    try {
      if (button.matches('[data-act="discard-image"]')) {
        closeModal();
        return;
      }
      if (button.dataset.removeRegion !== undefined) {
        const recipe = cloneRecipe(state.imageDraft.recipe);
        recipe.regions.splice(Number(button.dataset.removeRegion), 1);
        await applyImageRecipe(root, recipe);
        return;
      }
      if (button.matches('[data-act="apply-image"]')) {
        const recipe = cloneRecipe(state.imageDraft.recipe);
        recipe.crop = cropFromControls(root);
        await applyImageRecipe(root, recipe);
        return;
      }
      if (button.matches('[data-act="rotate-left"], [data-act="rotate-right"]')) {
        const recipe = cloneRecipe(state.imageDraft.recipe);
        const delta = button.matches('[data-act="rotate-left"]') ? 3 : 1;
        recipe.rotation_quarter_turns = (recipe.rotation_quarter_turns + delta) % 4;
        recipe.regions = [];
        await applyImageRecipe(root, recipe);
        return;
      }
      if (button.matches('[data-act="add-region"]')) {
        const recipe = cloneRecipe(state.imageDraft.recipe);
        recipe.regions.push({
          kind: root.querySelector('[data-f="region-kind"]').value,
          x: imageNumber(root, "region-x"),
          y: imageNumber(root, "region-y"),
          width: imageNumber(root, "region-width"),
          height: imageNumber(root, "region-height"),
          strength: imageNumber(root, "region-strength"),
        });
        await applyImageRecipe(root, recipe);
        return;
      }
      if (button.matches('[data-act="undo-image"]')) {
        const recipe = state.imageDraft.history.pop();
        if (recipe) await applyImageRecipe(root, recipe, false);
        return;
      }
      if (button.matches('[data-act="reset-image"]')) {
        const recipe = { crop: null, rotation_quarter_turns: 0, regions: [] };
        root.querySelector('[data-f="crop-preset"]').value = "original";
        setCropFields(root, null);
        await applyImageRecipe(root, recipe);
        return;
      }
      if (!button.matches('[data-act="send-image"]')) return;
      button.disabled = true;
      const draft = state.imageDraft;
      try {
        await invoke("send_image_edit", {
          token: draft.token,
          conversation: draft.conversation,
          destination: draft.destination,
          filename: root.querySelector('[data-f="filename"]').value.trim() || null,
          expectedCarrier: carrierText.dataset.snapshot,
        });
        state.imageDraft = null;
        closeModal();
        await renderMessages();
      } catch (error) {
        const changed = carrierChangedText(error);
        if (changed !== null) {
          carrierText.textContent = changed;
          carrierText.dataset.snapshot = changed;
          showError(root, "Carrier state changed. Review the updated explanation, then choose Send exact final image again.");
        } else {
          showError(root, error);
        }
        button.disabled = false;
      }
    } catch (error) {
      button.disabled = false;
      showError(root, error);
    }
  });
}

async function openGenericAttachment(path, selectedName) {
  const conversation = attachmentConversation();
  const destination = state.currentId;
  const carrier = await freshAttachmentCarrier(conversation, destination);
  const root = openModal("Send attachment", "tpl-attachment-send");
  root.querySelector('[data-f="selected-name"]').textContent = selectedName;
  root.querySelector('[data-f="filename"]').value = selectedName;
  root.querySelector('[data-f="media-type"]').value = guessedMime(selectedName);
  const carrierText = root.querySelector('[data-f="carrier"]');
  carrierText.textContent = carrier;
  carrierText.dataset.snapshot = carrier;
  root.addEventListener("click", async (event) => {
    if (event.target.matches('[data-act="discard-attachment"]')) {
      closeModal();
      return;
    }
    if (!event.target.matches('[data-act="send-attachment"]')) return;
    const button = event.target;
    const filename = root.querySelector('[data-f="filename"]').value.trim();
    const mediaType = root.querySelector('[data-f="media-type"]').value.trim();
    try {
      if (!mediaType) throw "enter a MIME type";
      button.disabled = true;
      const latest = await freshAttachmentCarrier(conversation, destination);
      if (latest !== carrierText.dataset.snapshot) {
        carrierText.textContent = latest;
        carrierText.dataset.snapshot = latest;
        button.disabled = false;
        showError(root, "Carrier state changed. Review the updated explanation, then choose Send attachment again.");
        return;
      }
      try {
        await invoke("send_confirmed_attachment", {
          conversation,
          destination,
          path,
          mediaType,
          filename: filename || null,
          expectedCarrier: latest,
        });
      } catch (error) {
        const changed = carrierChangedText(error);
        if (changed === null) throw error;
        carrierText.textContent = changed;
        carrierText.dataset.snapshot = changed;
        button.disabled = false;
        showError(root, "Carrier state changed. Review the updated explanation, then choose Send attachment again.");
        return;
      }
      closeModal();
      await renderMessages();
    } catch (err) {
      button.disabled = false;
      showError(root, err);
    }
  });
}

$("#btn-attach").addEventListener("click", async () => {
  if (!state.currentId || state.currentKind === "note") return;
  const path = await openPath({
    title: state.currentKind === "group" ? "Choose a group attachment" : "Choose an attachment",
    multiple: false,
    directory: false,
  });
  if (!path || typeof path !== "string") return;
  const selectedName = pathBasename(path);
  const claimedImage = ["image/jpeg", "image/png"].includes(guessedMime(selectedName));
  try {
    const initial = await invoke("begin_image_edit", { path });
    await openImageEditor(selectedName, initial);
  } catch (error) {
    if (claimedImage || !String(error).includes("only content-verified JPEG and PNG")) {
      toast(String(error), true);
      return;
    }
    await openGenericAttachment(path, selectedName);
  }
});

// ── node events ─────────────────────────────────────────────────────────

listen("node-event", async ({ payload: ev }) => {
  switch (ev.type) {
    case "theme_changed": {
      const theme = await invoke("theme");
      applyTheme(theme.preference);
      break;
    }
    case "custom_icons_changed": {
      await refreshVisibleCustomIcons(true);
      break;
    }
    case "folders_changed": {
      await refreshFolders(true);
      break;
    }
    case "labels_changed": {
      await refreshLabels(true);
      break;
    }
    case "pins_changed": {
      await runLabelFilter(true);
      updateChatHead();
      break;
    }
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
          await refreshMentionReview("The current group roster or identity mapping changed.");
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
    case "mention_received": {
      toast("You were mentioned in a group.");
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
      if (currentGroup()?.members.includes(ev.peer)) {
        await refreshMentionReview("A member session changed, so mention support was revalidated.");
      }
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

let modalReturnFocus = null;

function modalFocusable() {
  return [...$("#modal").querySelectorAll(
    'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  )].filter((element) => !element.hidden && element.getClientRects().length > 0);
}

function openModal(title, tplId) {
  modalReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const body = $("#modal-body");
  body.textContent = "";
  $("#modal-title").textContent = title;
  body.append($("#" + tplId).content.cloneNode(true));
  applyIncognitoInputPrivacy(body);
  $("#modal-backdrop").hidden = false;
  requestAnimationFrame(() => (modalFocusable()[0] ?? $("#modal-close")).focus());
  return body;
}

function closeModal() {
  discardAudioDraft();
  discardImageDraft();
  $("#modal").classList.remove("image-editing");
  $("#modal-backdrop").hidden = true;
  $("#modal-body").textContent = "";
  modalReturnFocus?.focus();
  modalReturnFocus = null;
}

$("#modal-close").addEventListener("click", closeModal);
$("#modal-backdrop").addEventListener("click", (e) => {
  if (e.target === $("#modal-backdrop")) closeModal();
});
document.addEventListener("keydown", (e) => {
  if ($("#modal-backdrop").hidden) return;
  if (e.key === "Escape") {
    closeModal();
    return;
  }
  if (e.key !== "Tab") return;
  const focusable = modalFocusable();
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
});

function showError(root, err) {
  const el = root.querySelector('[data-f="error"]');
  if (el) {
    el.textContent = String(err);
    el.hidden = false;
  }
}

function customIconChoices() {
  return [
    { target: { kind: "note_to_self", id: null }, label: "Note to self" },
    ...state.contacts.map((contact) => ({
      target: { kind: "contact", id: contact.peer },
      label: `Contact · ${contact.name || contact.peer.slice(0, 12) + "…"}`,
    })),
    ...state.groups.map((group) => ({
      target: { kind: "group", id: group.id },
      label: `Group · ${group.name || "Unnamed group"}`,
    })),
    ...state.folders.map((folder) => ({
      target: { kind: "folder", id: folder.id },
      label: `Folder ${folder.order + 1} · ${folder.name}`,
    })),
  ];
}

function selectedCustomIconChoice(root) {
  const select = root.querySelector('[data-f="icon-target"]');
  return JSON.parse(select.value);
}

async function refreshIconManager(root, clearCache = false) {
  if (clearCache) state.icons.clear();
  const select = root.querySelector('[data-f="icon-target"]');
  const target = selectedCustomIconChoice(root);
  const label = select.selectedOptions[0]?.textContent ?? "selected target";
  const fallback = generatedInitials(label.replace(/^[^·]+·\s*/u, ""));
  const preview = root.querySelector('[data-f="preview"]');
  await applyCustomIcon(preview, target, fallback, label);
  const icon = await loadCustomIcon(target);
  root.querySelector('[data-f="preview-description"]').textContent = icon
    ? `Private local icon · ${Number(icon.encoded_bytes).toLocaleString()} bytes`
    : `Generated initials fallback · ${fallback}`;
  root.querySelector('[data-act="clear-icon"]').disabled = !icon;
  const usage = await invoke("custom_icon_usage");
  root.querySelector('[data-f="usage"]').textContent = `${usage.records.toLocaleString()} / 1,024 sealed icons · ${usage.bytes.toLocaleString()} / 67,108,864 encoded bytes`;
}

async function openIconManager() {
  const root = openModal("Private custom icons", "tpl-icon-manager");
  const select = root.querySelector('[data-f="icon-target"]');
  for (const choice of customIconChoices()) {
    const option = document.createElement("option");
    option.value = JSON.stringify(choice.target);
    option.textContent = choice.label;
    select.append(option);
  }
  const glyphs = root.querySelector('[data-f="glyphs"]');
  for (const glyph of ICON_GLYPHS) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.textContent = glyph;
    button.setAttribute("aria-label", `Use bundled ${glyph} glyph`);
    button.addEventListener("click", async () => {
      try {
        const target = selectedCustomIconChoice(root);
        const icon = await invoke("set_bundled_custom_icon", { target, glyph });
        state.icons.set(customIconKey(target), icon);
        root.querySelector('[data-f="result"]').textContent = `Bundled ${glyph} icon saved locally.`;
        root.querySelector('[data-f="error"]').hidden = true;
        await Promise.all([refreshIconManager(root), refreshVisibleCustomIcons()]);
      } catch (error) { showError(root, error); }
    });
    glyphs.append(button);
  }
  select.addEventListener("change", () => {
    root.querySelector('[data-f="result"]').textContent = "";
    refreshIconManager(root).catch((error) => showError(root, error));
  });
  root.querySelector('[data-act="choose-icon-image"]').addEventListener("click", async () => {
    const path = await openPath({
      title: "Choose a private local icon",
      multiple: false,
      directory: false,
      filters: [{ name: "JPEG or PNG", extensions: ["jpg", "jpeg", "png"] }],
    });
    if (!path || typeof path !== "string") return;
    try {
      const target = selectedCustomIconChoice(root);
      const icon = await invoke("set_custom_icon_from_path", { target, path, crop: null });
      state.icons.set(customIconKey(target), icon);
      root.querySelector('[data-f="result"]').textContent = "Selected image cropped, sanitized, and sealed locally.";
      root.querySelector('[data-f="error"]').hidden = true;
      await Promise.all([refreshIconManager(root), refreshVisibleCustomIcons()]);
    } catch (error) { showError(root, error); }
  });
  root.querySelector('[data-act="clear-icon"]').addEventListener("click", async () => {
    try {
      const target = selectedCustomIconChoice(root);
      await invoke("clear_custom_icon", { target });
      state.icons.set(customIconKey(target), null);
      root.querySelector('[data-f="result"]').textContent = "Generated initials restored.";
      root.querySelector('[data-f="error"]').hidden = true;
      await Promise.all([refreshIconManager(root), refreshVisibleCustomIcons()]);
    } catch (error) { showError(root, error); }
  });
  await refreshIconManager(root);
}

$("#btn-icon-manager").addEventListener("click", openIconManager);

function resetFolderEditor(root) {
  root.querySelector('[data-f="folder-id"]').value = "";
  root.querySelector('[data-f="folder-name"]').value = "";
  root.querySelector('[data-act="save-folder"]').textContent = "Create folder";
  root.querySelector('[data-act="cancel-edit"]').hidden = true;
  root.querySelector('[data-f="error"]').hidden = true;
}

async function renderFolderManager(root) {
  state.folders = await invoke("folders");
  const list = root.querySelector('[data-f="folders"]');
  list.replaceChildren();
  if (state.folders.length === 0) {
    const empty = document.createElement("p");
    empty.className = "modal-note";
    empty.textContent = "No folders. Create one above.";
    list.append(empty);
  }
  for (const [index, folder] of state.folders.entries()) {
    const row = document.createElement("div");
    row.className = "folder-manager-row";
    const avatar = document.createElement("span");
    avatar.className = "avatar icon-manager-row-avatar";
    const fallback = generatedInitials(folder.name);
    avatar.textContent = fallback;
    applyCustomIcon(avatar, { kind: "folder", id: folder.id }, fallback, `folder ${folder.name}`);
    const description = document.createElement("span");
    description.className = "folder-description";
    const name = document.createElement("bdi");
    name.dir = "auto";
    name.textContent = folder.name;
    description.append(name, document.createTextNode(` · folder ${index + 1}`));
    const actions = document.createElement("span");
    actions.className = "folder-actions";
    for (const [label, delta] of [["Move up", -1], ["Move down", 1]]) {
      const reorder = document.createElement("button");
      reorder.type = "button";
      reorder.className = "ghost";
      reorder.textContent = delta < 0 ? "↑" : "↓";
      reorder.disabled = index + delta < 0 || index + delta >= state.folders.length;
      reorder.setAttribute("aria-label", `${label} ${folderAccessibleName(folder)}`);
      reorder.addEventListener("click", async () => {
        try {
          const ids = state.folders.map((item) => item.id);
          [ids[index], ids[index + delta]] = [ids[index + delta], ids[index]];
          await invoke("reorder_folders", { folders: ids });
          root.querySelector('[data-f="result"]').textContent = `${folderAccessibleName(folder)} ${delta < 0 ? "moved up" : "moved down"}.`;
          await renderFolderManager(root);
          await refreshFolders(true);
          root.querySelector(`[data-folder-action="${delta < 0 ? "up" : "down"}"][data-folder-position="${Math.max(0, index + delta)}"]`)?.focus();
        } catch (error) { showError(root, error); }
      });
      reorder.dataset.folderAction = delta < 0 ? "up" : "down";
      reorder.dataset.folderPosition = String(index);
      actions.append(reorder);
    }
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "ghost";
    edit.textContent = "Edit";
    edit.setAttribute("aria-label", `Rename ${folderAccessibleName(folder)}`);
    edit.addEventListener("click", () => {
      root.querySelector('[data-f="folder-id"]').value = folder.id;
      root.querySelector('[data-f="folder-name"]').value = folder.name;
      root.querySelector('[data-act="save-folder"]').textContent = "Save folder";
      root.querySelector('[data-act="cancel-edit"]').hidden = false;
      root.querySelector('[data-f="folder-name"]').focus();
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.setAttribute("aria-label", `Delete ${folderAccessibleName(folder)}`);
    remove.addEventListener("click", async () => {
      try {
        const count = await invoke("folder_delete_assignment_count", { folder: folder.id });
        const reviewed = window.confirm(`Delete “${folder.name}” (folder ${index + 1})? ${count} conversation${count === 1 ? "" : "s"} will become Unfiled; messages and conversations are unchanged.`);
        if (!reviewed) {
          root.querySelector('[data-f="result"]').textContent = "Folder deletion cancelled.";
          remove.focus();
          return;
        }
        const deleted = await invoke("delete_folder", { folder: folder.id, confirm: true });
        root.querySelector('[data-f="result"]').textContent = `Folder deleted; ${deleted} conversation${deleted === 1 ? " is" : "s are"} now Unfiled.`;
        resetFolderEditor(root);
        await renderFolderManager(root);
        await refreshFolders(true);
        root.querySelector('[data-f="folder-name"]').focus();
      } catch (error) { showError(root, error); }
    });
    actions.append(edit, remove);
    row.append(avatar, description, actions);
    list.append(row);
  }

  const stale = await invoke("stale_folders");
  const section = root.querySelector('[data-f="stale-section"]');
  const staleList = root.querySelector('[data-f="stale"]');
  section.hidden = stale.length === 0;
  staleList.replaceChildren();
  for (const record of stale) {
    const row = document.createElement("div");
    row.className = "stale-folder-row";
    const reason = document.createElement("span");
    const targetName = record.target.kind === "note_to_self" ? "note-to-self" : `${record.target.kind} conversation`;
    reason.textContent = `${record.reason.replaceAll("_", " ")} · ${targetName}`;
    const cleanup = document.createElement("button");
    cleanup.type = "button";
    cleanup.className = "danger";
    cleanup.textContent = "Clean up";
    cleanup.setAttribute("aria-label", `Clean up selected stale ${targetName} folder assignment`);
    cleanup.addEventListener("click", async () => {
      try {
        await invoke("cleanup_stale_folder", { folder: record.folder, target: record.target });
        root.querySelector('[data-f="result"]').textContent = `Selected stale ${targetName} assignment removed.`;
        await renderFolderManager(root);
        await refreshFolders(true);
      } catch (error) { showError(root, error); }
    });
    row.append(reason, cleanup);
    staleList.append(row);
  }
}

async function openFolderManager() {
  const root = openModal("Private conversation folders", "tpl-folder-manager");
  const form = root.querySelector('[data-f="folder-form"]');
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = root.querySelector('[data-f="folder-name"]').value;
    const id = root.querySelector('[data-f="folder-id"]').value;
    try {
      if (!exactFolderNameValid(name)) throw new Error("Name must contain a non-Pattern-White-Space character and be at most 256 UTF-8 bytes.");
      const saved = id
        ? await invoke("rename_folder", { folder: id, name })
        : await invoke("create_folder", { name });
      root.querySelector('[data-f="result"]').textContent = `${id ? "Renamed" : "Created"} ${folderAccessibleName(saved)}.`;
      resetFolderEditor(root);
      await renderFolderManager(root);
      await refreshFolders(true);
      root.querySelector('[data-f="folder-name"]').focus();
    } catch (error) { showError(root, error); }
  });
  root.querySelector('[data-act="cancel-edit"]').addEventListener("click", () => {
    resetFolderEditor(root);
    root.querySelector('[data-f="result"]').textContent = "Rename cancelled; the folder is unchanged.";
    root.querySelector('[data-f="folder-name"]').focus();
  });
  await renderFolderManager(root);
}

$("#btn-folder-manager").addEventListener("click", openFolderManager);

async function openConversationFolder() {
  const target = folderTarget();
  if (!target) return;
  const exactTarget = currentTargetName();
  const root = openModal(`Move ${exactTarget}`, "tpl-conversation-folder");
  root.querySelector('[data-f="target-summary"]').textContent = `Choose the exact final folder for ${exactTarget}. This changes local navigation only.`;
  const current = await invoke("conversation_folder", { target });
  const list = root.querySelector('[data-f="folders"]');
  const choices = [{ id: null, name: "Unfiled", order: -1 }, ...state.folders];
  for (const folder of choices) {
    const row = document.createElement("label");
    row.className = "folder-assignment-option";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "conversation-folder";
    input.checked = folder.id === (current?.id ?? null);
    const cue = folder.id ? folderAccessibleName(folder) : "Unfiled virtual view";
    input.setAttribute("aria-label", `Move ${exactTarget} to ${cue}`);
    const name = document.createElement("bdi");
    name.dir = "auto";
    name.textContent = folder.name;
    input.addEventListener("change", async () => {
      if (!input.checked) return;
      input.disabled = true;
      try {
        if (folder.id) await invoke("move_to_folder", { folder: folder.id, target });
        else await invoke("unfile_conversation", { target });
        const finalFolder = await invoke("conversation_folder", { target });
        root.querySelector('[data-f="result"]').textContent = `${exactTarget} is now in ${finalFolder ? folderAccessibleName(finalFolder) : "Unfiled"}.`;
        await refreshFolders(true);
      } catch (error) { showError(root, error); }
      finally { input.disabled = false; input.focus(); }
    });
    row.append(input, name, document.createTextNode(folder.id ? ` · folder ${folder.order + 1}` : ""));
    list.append(row);
  }
  root.querySelector('[data-act="done"]').addEventListener("click", closeModal);
}

$("#btn-conversation-folder").addEventListener("click", openConversationFolder);

function resetLabelEditor(root) {
  root.querySelector('[data-f="label-id"]').value = "";
  root.querySelector('[data-f="label-name"]').value = "";
  root.querySelector('[data-f="label-color"]').value = "neutral";
  root.querySelector('[data-act="save-label"]').textContent = "Create label";
  root.querySelector('[data-act="cancel-edit"]').hidden = true;
  root.querySelector('[data-f="error"]').hidden = true;
}

async function renderLabelManager(root) {
  state.labels = await invoke("labels");
  const list = root.querySelector('[data-f="labels"]');
  list.replaceChildren();
  if (state.labels.length === 0) {
    const empty = document.createElement("p");
    empty.className = "modal-note";
    empty.textContent = "No labels. Create one above.";
    list.append(empty);
  }
  for (const label of state.labels) {
    const row = document.createElement("div");
    row.className = "label-manager-row";
    const description = document.createElement("span");
    description.className = "label-description";
    description.append(labelChip(label), document.createTextNode(` · ${labelCue(label)}`));
    const actions = document.createElement("span");
    actions.className = "label-actions";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "ghost";
    edit.textContent = "Edit";
    edit.setAttribute("aria-label", `Edit ${labelAccessibleName(label)}`);
    edit.addEventListener("click", () => {
      root.querySelector('[data-f="label-id"]').value = label.id;
      root.querySelector('[data-f="label-name"]').value = label.name;
      root.querySelector('[data-f="label-color"]').value = label.color;
      root.querySelector('[data-act="save-label"]').textContent = "Save label";
      root.querySelector('[data-act="cancel-edit"]').hidden = false;
      root.querySelector('[data-f="label-name"]').focus();
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.setAttribute("aria-label", `Delete ${labelAccessibleName(label)}`);
    remove.addEventListener("click", async () => {
      try {
        const count = await invoke("label_delete_assignment_count", { label: label.id });
        const reviewed = window.confirm(`Delete “${label.name}” (${labelCue(label)})? This atomically removes ${count} conversation assignment${count === 1 ? "" : "s"}.`);
        if (!reviewed) {
          root.querySelector('[data-f="result"]').textContent = "Label deletion cancelled.";
          remove.focus();
          return;
        }
        const deleted = await invoke("delete_label", { label: label.id, confirm: true });
        root.querySelector('[data-f="result"]').textContent = `Label deleted with ${deleted} assignment${deleted === 1 ? "" : "s"}.`;
        resetLabelEditor(root);
        await renderLabelManager(root);
        await refreshLabels(true);
        root.querySelector('[data-f="label-name"]').focus();
      } catch (error) { showError(root, error); }
    });
    actions.append(edit, remove);
    row.append(description, actions);
    list.append(row);
  }

  const stale = await invoke("stale_labels");
  const section = root.querySelector('[data-f="stale-section"]');
  const staleList = root.querySelector('[data-f="stale"]');
  section.hidden = stale.length === 0;
  staleList.replaceChildren();
  for (const record of stale) {
    const row = document.createElement("div");
    row.className = "stale-label-row";
    const reason = document.createElement("span");
    const targetName = record.target.kind === "note_to_self" ? "note-to-self" : `${record.target.kind} conversation`;
    reason.textContent = `${record.reason.replaceAll("_", " ")} · ${targetName}`;
    const cleanup = document.createElement("button");
    cleanup.type = "button";
    cleanup.className = "danger";
    cleanup.textContent = "Clean up";
    cleanup.setAttribute("aria-label", `Clean up stale ${targetName} membership`);
    cleanup.addEventListener("click", async () => {
      try {
        await invoke("cleanup_stale_label", { label: record.label, target: record.target });
        root.querySelector('[data-f="result"]').textContent = `Stale ${targetName} membership removed.`;
        await renderLabelManager(root);
      } catch (error) { showError(root, error); }
    });
    row.append(reason, cleanup);
    staleList.append(row);
  }
}

async function openLabelManager() {
  const root = openModal("Private labels", "tpl-label-manager");
  const form = root.querySelector('[data-f="label-form"]');
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = root.querySelector('[data-f="label-name"]').value;
    const color = root.querySelector('[data-f="label-color"]').value;
    const id = root.querySelector('[data-f="label-id"]').value;
    try {
      if (!exactLabelNameValid(name)) throw new Error("Name must contain a non-Pattern-White-Space character and be at most 256 UTF-8 bytes.");
      if (!LABEL_COLORS.includes(color)) throw new Error("Choose a supported label color.");
      const saved = id
        ? await invoke("update_label", { label: id, name, color })
        : await invoke("create_label", { name, color });
      root.querySelector('[data-f="result"]').textContent = `${id ? "Updated" : "Created"} ${labelAccessibleName(saved)}.`;
      resetLabelEditor(root);
      await renderLabelManager(root);
      await refreshLabels(true);
      root.querySelector('[data-f="label-name"]').focus();
    } catch (error) { showError(root, error); }
  });
  root.querySelector('[data-act="cancel-edit"]').addEventListener("click", () => {
    resetLabelEditor(root);
    root.querySelector('[data-f="result"]').textContent = "Edit cancelled; the label is unchanged.";
    root.querySelector('[data-f="label-name"]').focus();
  });
  await renderLabelManager(root);
}

$("#btn-label-manager").addEventListener("click", openLabelManager);

async function openConversationLabels() {
  const target = labelTarget();
  if (!target) return;
  const exactTarget = currentTargetName();
  const root = openModal(`Labels for ${exactTarget}`, "tpl-conversation-labels");
  root.querySelector('[data-f="target-summary"]').textContent = `Apply or remove sealed local labels for exactly ${exactTarget}.`;
  const assigned = new Set((await invoke("labels_for_conversation", { target })).map((label) => label.id));
  const list = root.querySelector('[data-f="labels"]');
  list.replaceChildren();
  if (state.labels.length === 0) {
    const empty = document.createElement("p");
    empty.className = "modal-note";
    empty.textContent = "No labels exist. Use Manage labels to create one.";
    list.append(empty);
  }
  for (const label of state.labels) {
    const row = document.createElement("label");
    row.className = "label-assignment-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = assigned.has(label.id);
    input.setAttribute("aria-label", `${input.checked ? "Remove" : "Apply"} ${labelAccessibleName(label)} for ${exactTarget}`);
    input.addEventListener("change", async () => {
      input.disabled = true;
      try {
        const command = input.checked ? "assign_label" : "unassign_label";
        await invoke(command, { label: label.id, target });
        const finalLabels = await invoke("labels_for_conversation", { target });
        const final = finalLabels.some((item) => item.id === label.id);
        input.checked = final;
        input.setAttribute("aria-label", `${final ? "Remove" : "Apply"} ${labelAccessibleName(label)} for ${exactTarget}`);
        root.querySelector('[data-f="result"]').textContent = `${labelAccessibleName(label)} is now ${final ? "applied to" : "removed from"} ${exactTarget}. Final membership: ${finalLabels.length} label${finalLabels.length === 1 ? "" : "s"}.`;
        await refreshLabels(false);
      } catch (error) {
        input.checked = !input.checked;
        showError(root, error);
      } finally { input.disabled = false; input.focus(); }
    });
    row.append(input, labelChip(label), document.createTextNode(labelCue(label)));
    list.append(row);
  }
  list.addEventListener("keydown", (event) => {
    if (!['ArrowDown', 'ArrowUp'].includes(event.key)) return;
    const inputs = $$('input[type="checkbox"]', list);
    const index = inputs.indexOf(document.activeElement);
    if (index < 0) return;
    event.preventDefault();
    inputs[(index + (event.key === 'ArrowDown' ? 1 : -1) + inputs.length) % inputs.length]?.focus();
  });
  root.querySelector('[data-act="done"]').addEventListener("click", closeModal);
}

$("#btn-conversation-labels").addEventListener("click", openConversationLabels);

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

// appearance is applied immediately and sealed through the shared F5 record
$("#btn-theme").addEventListener("click", async () => {
  const root = openModal("Appearance", "tpl-theme");
  const info = await call("theme");
  const checked = root.querySelector('input[value="' + info.preference + '"]');
  if (checked) checked.checked = true;
  root.addEventListener("change", async (event) => {
    if (!event.target.matches('input[name="theme-preference"]')) return;
    applyTheme(event.target.value);
    try {
      await invoke("set_theme", { preference: event.target.value });
    } catch (error) {
      showError(root, error);
    }
  });
  root.addEventListener("click", (event) => {
    if (event.target.matches('[data-act="close"]')) closeModal();
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
