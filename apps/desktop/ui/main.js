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
  messageRequests: [],
  groupInvitations: [],
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
  currentAuthority: null,
  call: null,
  callPrompted: new Set(),
  callMedia: null,
  pendingCallStream: null,
  statusTimer: null,
  messageRenderGeneration: 0,
};

// ── small utilities ─────────────────────────────────────────────────────

function toast(text, isError = false) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.setAttribute("role", isError ? "alert" : "status");
  el.setAttribute("aria-live", isError ? "assertive" : "polite");
  el.setAttribute("aria-atomic", "true");
  el.textContent = text;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), isError ? 8000 : 4000);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (err) {
    toast(localizedError(err), true);
    throw err;
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(l10n("clipboard_copied"));
  } catch {
    // WebKitGTK can refuse the async clipboard; fall back.
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    toast(l10n("clipboard_copied"));
  }
}

function fmtTime(unixSecs) {
  const d = new Date(unixSecs * 1000);
  const today = new Date().toDateString() === d.toDateString();
  return today
    ? d.toLocaleTimeString(
      KommsLocalization.activeLocale(),
      { hour: "2-digit", minute: "2-digit" },
    )
    : d.toLocaleString(
      KommsLocalization.activeLocale(),
      { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" },
    );
}

function fmtExpiry(unixSecs) {
  return new Date(unixSecs * 1000).toLocaleString(KommsLocalization.activeLocale(), {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

const LABEL_COLORS = ["neutral", "red", "orange", "yellow", "green", "teal", "blue", "purple", "pink"];
const LABEL_COLOR_IDS = Object.freeze({
  neutral: "label_color_neutral",
  red: "label_color_red",
  orange: "label_color_orange",
  yellow: "label_color_yellow",
  green: "label_color_green",
  teal: "label_color_teal",
  blue: "label_color_blue",
  purple: "label_color_purple",
  pink: "label_color_pink",
});

function labelCue(label) {
  return l10n(
    "label_cue",
    l10n(LABEL_COLOR_IDS[label.color] ?? "label_color_neutral"),
    label.order + 1,
  );
}

function labelAccessibleName(label) {
  return l10n(
    "label_accessible_summary",
    label.name,
    l10n(LABEL_COLOR_IDS[label.color] ?? "label_color_neutral"),
    label.order + 1,
  );
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
    avatar.title = l10n("icons_private_for", accessibleName);
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
      avatar.dataset.iconName || l10nSource("Conversation"),
    );
  });
  await Promise.all(work);
}

function folderAccessibleName(folder) {
  return l10n("folder_accessible_summary", folder.name, folder.order + 1);
}

function exactFolderNameValid(name) {
  return exactLabelNameValid(name);
}

function currentTargetName() {
  if (state.currentKind === "contact") return contactName(state.currentId);
  if (state.currentKind === "group") {
    return currentGroup()?.name ?? l10n("group_unavailable");
  }
  return l10n("note_to_self_title");
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

function deliveryState(stateValue) {
  const id = {
    queued: "state_queued",
    sent: "state_sent",
    delivered: "state_delivered",
    received: "state_received",
    failed: "state_failed",
  }[stateValue];
  return id ? l10n(id) : l10n("state_unknown");
}

function attachmentDirection(direction) {
  return l10n(
    direction === "inbound" ? "attachment_inbound" : "attachment_outbound",
  );
}

function attachmentState(stateValue) {
  const id = {
    offered: "attachment_state_offered",
    awaiting_consent: "attachment_state_awaiting_consent",
    queued: "attachment_state_queued",
    transferring: "attachment_state_transferring",
    paused: "attachment_state_paused",
    complete: "attachment_state_complete",
    rejected: "attachment_state_rejected",
    cancelled: "attachment_state_cancelled",
    corrupt: "attachment_state_corrupt",
    unavailable: "attachment_state_unavailable",
  }[stateValue];
  return l10n(id ?? "attachment_state_unavailable");
}

function modeName(mode) {
  return l10n({
    private: "mode_private",
    sovereign: "mode_sovereign",
    standard: "mode_standard",
  }[mode] ?? "mode_standard");
}

function connectionName(connection) {
  return l10n({
    connected: "connection_connected",
    fallback_ready: "connection_fallback_ready",
    waiting_for_route: "connection_waiting",
  }[connection] ?? "connection_waiting");
}

function directoryName(status) {
  return l10n({
    current: "directory_current",
    retained_last_valid: "directory_retained",
    stale: "directory_stale",
    conflict: "directory_conflict",
    unavailable: "directory_unavailable",
    not_configured: "directory_not_configured",
  }[status] ?? "directory_unavailable");
}

function natName(nat) {
  return l10n({
    public: "nat_public",
    private: "nat_private",
    unknown: "nat_unknown",
  }[nat] ?? "nat_unknown");
}

function conversationKindName(kind) {
  return l10n({
    contact: "label_contact_conversation",
    pairwise: "label_contact_conversation",
    group: "label_group_conversation",
    note_to_self: "note_to_self_title",
  }[kind] ?? "conversation_unavailable");
}

function staleReasonName(reason) {
  return l10n({
    folder_missing: "stale_folder_missing",
    label_missing: "stale_label_missing",
    target_missing: "stale_target_missing",
    conversation_missing: "stale_target_missing",
  }[reason] ?? "stale_record_unavailable");
}

function groupRoleName(role) {
  return l10n({
    owner: "group_role_owner",
    admin: "group_role_admin",
    member: "group_role_member",
  }[role] ?? "group_role_member");
}

function groupOriginName(security) {
  return l10n({
    recipient_authenticated: "group_origin_authenticated",
    upgrading: "group_origin_upgrade_in_progress",
  }[security] ?? "group_origin_upgrade_required");
}

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
  return String(path).replace(/\\/g, "/").split("/").filter(Boolean).pop()
    ?? l10n("attachment_default_name");
}

function guessedMime(filename) {
  const extension = filename.includes(".") ? filename.split(".").pop().toLowerCase() : "";
  return MIME_BY_EXTENSION[extension] ?? "application/octet-stream";
}

function exactBytes(verified, total) {
  return l10n(
    "attachment_exact_bytes",
    Number(verified),
    Number(total),
  );
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
  meta.textContent = l10n("attachment_audio_summary", formatDuration(durationMs));
  const audio = document.createElement("audio");
  audio.controls = true;
  audio.preload = "metadata";
  audio.src = source;
  audio.setAttribute("aria-label", label);
  container.append(
    meta,
    renderWaveform(waveform, l10n("audio_waveform_for", label)),
    audio,
  );
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
  $("#recording-status").textContent = l10n("audio_discarded");
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
  button.textContent = l10n("audio_record");
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
      ? l10n("audio_limit_reached")
      : l10n("audio_review_ready");
    const carrier = await call("audio_carrier_explanation", {
      conversation: state.currentKind === "group" ? "group" : "pairwise",
      destination: state.currentId,
    });
    const root = openModal(l10n("audio_review_title"), "tpl-audio-review");
    renderAudioPlayer(
      root.querySelector('[data-f="audio-review"]'),
      url,
      state.audioDraft.durationMs,
      state.audioDraft.waveform,
      l10n("audio_review_recorded"),
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
          showError(root, l10n("audio_carrier_changed"));
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
    $("#recording-status").textContent = l10n("audio_record_failed");
    toast(localizedError(error), true);
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
      track.onended = () => abortRecording(l10n("audio_interrupted_discarded"));
    });
    state.recording = recorder;
    const button = $("#btn-record");
    button.classList.add("recording");
    button.setAttribute("aria-pressed", "true");
    button.textContent = `${l10n("audio_stop")} 0:00`;
    $("#recording-status").textContent = l10n("audio_recording");
    recorder.timer = setInterval(() => {
      const elapsed = Math.min(60, Math.floor((performance.now() - recorder.started) / 1000));
      button.textContent = `${l10n("audio_stop")} ${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, "0")}`;
      $("#recording-status").textContent = l10nPlural(
        "recording_elapsed",
        elapsed,
        elapsed,
      );
    }, 1000);
  } catch (error) {
    stream?.getTracks().forEach((track) => track.stop());
    if (context && context.state !== "closed") await context.close().catch(() => {});
    $("#recording-status").textContent = l10n("audio_permission_denied");
    toast(localizedError(error), true);
  }
}

$("#btn-record").addEventListener("click", () => {
  if (state.recording) stopRecording();
  else startRecording();
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) return;
  abortRecording(l10n("audio_interrupted_discarded"));
  if (state.audioDraft) {
    closeModal();
    $("#recording-status").textContent = l10n("audio_interrupted_discarded");
  }
  if (state.imageDraft) closeModal();
});
window.addEventListener("pagehide", () => {
  abortRecording(l10n("audio_interrupted_discarded"));
  discardAudioDraft();
  discardImageDraft();
});

// ── gate (create / unlock / restore) ────────────────────────────────────

let gateMode = "open";

applyTheme(cachedTheme(), false);
$("#gate-theme").addEventListener("change", (event) => applyTheme(event.target.value));
$("#gate-locale").value = KommsLocalization.localePreference();
$("#gate-locale").addEventListener("change", (event) => {
  KommsLocalization.setLocale(event.target.value);
});

function readSettings() {
  const lines = (el) => el.value.split("\n").map((s) => s.trim()).filter(Boolean);
  const opt = (el) => (el.value.trim() ? el.value.trim() : null);
  const rendezvous = lines($("#set-rendezvous")).map((line) => {
    const [origin, static_key, access, extra] = line.split(",").map((part) => part.trim());
    if (!origin?.startsWith("https://") || !/^[0-9a-f]{64}$/.test(static_key || "") ||
        !["standard", "private", "both"].includes(access) || extra !== undefined) {
      throw new Error("Each rendezvous line must be origin, 64-character lowercase certificate digest, and standard, private, or both.");
    }
    return {
      origin,
      static_key,
      standard: access === "standard" || access === "both",
      private_via_tor: access === "private" || access === "both",
    };
  });
  const wake = lines($("#set-wake")).map((line) => {
    const [origin, static_key, access, extra] = line.split(",").map((part) => part.trim());
    if (!origin?.startsWith("https://") || !/^[0-9a-f]{64}$/.test(static_key || "") ||
        !["standard", "private", "both"].includes(access) || extra !== undefined) {
      throw new Error("Each wake-gateway line must be origin, 64-character lowercase certificate digest, and standard, private, or both.");
    }
    return {
      origin,
      static_key,
      standard: access === "standard" || access === "both",
      private_via_tor: access === "private" || access === "both",
    };
  });
  return {
    mode: document.querySelector('input[name="set-mode"]:checked')?.value ?? "standard",
    standard_disclosure_confirmed: $("#set-standard-disclosure").checked,
    sovereign_publish_direct_routes: $("#set-sovereign-direct").checked,
    provider_directory: opt($("#set-provider-directory")),
    provider_directory_roots: lines($("#set-provider-roots")),
    rendezvous,
    wake,
    tor_proxy: opt($("#set-tor-proxy")),
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
  const mode = s.mode ?? "standard";
  const modeInput = document.querySelector(`input[name="set-mode"][value="${mode}"]`);
  if (modeInput) modeInput.checked = true;
  $("#set-standard-disclosure").checked = s.standard_disclosure_confirmed ?? false;
  $("#set-sovereign-direct").checked = s.sovereign_publish_direct_routes ?? false;
  $("#set-provider-directory").value = s.provider_directory ?? "";
  $("#set-provider-roots").value = (s.provider_directory_roots ?? []).join("\n");
  $("#set-rendezvous").value = (s.rendezvous ?? []).map((provider) => {
    const access = provider.standard && provider.private_via_tor
      ? "both" : provider.private_via_tor ? "private" : "standard";
    return `${provider.origin},${provider.static_key},${access}`;
  }).join("\n");
  $("#set-wake").value = (s.wake ?? []).map((provider) => {
    const access = provider.standard && provider.private_via_tor
      ? "both" : provider.private_via_tor ? "private" : "standard";
    return `${provider.origin},${provider.static_key},${access}`;
  }).join("\n");
  $("#set-tor-proxy").value = s.tor_proxy ?? "";
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
  updateModeDisclosure();
}

function updateModeDisclosure() {
  const mode = document.querySelector('input[name="set-mode"]:checked')?.value ?? "standard";
  const messageIds = {
    standard: "set_mode_standard_disclosure",
    private: "set_mode_private_disclosure",
    sovereign: "set_mode_sovereign_disclosure",
  };
  $("#mode-disclosure").textContent = l10n(messageIds[mode]);
  $("#standard-disclosure-row").hidden = mode !== "standard";
  $("#sovereign-direct-row").hidden = mode !== "sovereign";
}

document.querySelectorAll('input[name="set-mode"]').forEach((input) => {
  input.addEventListener("change", updateModeDisclosure);
});

async function probeGate(dir) {
  const probe = await call("probe", { dataDir: dir ?? null });
  state.dataDir = probe.data_dir ?? probe.dataDir;
  $("#gate-dir").value = state.dataDir;
  fillSettings(probe.settings);
  const exists = probe.exists;
  $("#gate-tabs").hidden = exists;
  if (exists) setGateMode("open");
  $("#gate-go").textContent = exists
    ? l10n("gate_unlock")
    : gateMode === "restore"
      ? l10n("gate_restore")
      : l10n("gate_create");
  $("#gate-note").textContent = exists
    ? l10n("gate_existing_store")
    : l10n("gate_new_store");
  $("#gate-pass-label").textContent = exists
    ? l10n("gate_passphrase")
    : l10n("gate_new_passphrase");
}

function setGateMode(mode) {
  gateMode = mode;
  $$("#gate-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === mode));
  $("#restore-fields").hidden = mode !== "restore";
  const exists = $("#gate-tabs").hidden;
  $("#gate-go").textContent = exists
    ? l10n("gate_unlock")
    : mode === "restore"
      ? l10n("gate_restore")
      : l10n("gate_create");
}

$("#gate-tabs").addEventListener("click", (e) => {
  const tab = e.target.closest(".tab");
  if (tab) setGateMode(tab.dataset.tab);
});

$("#gate-legacy-backup").addEventListener("change", (event) => {
  const legacy = event.target.checked;
  $("#gate-legacy-warning").hidden = !legacy;
  $("#gate-current-authority-fields").hidden = legacy;
});

let probeDebounce;
$("#gate-dir").addEventListener("input", () => {
  clearTimeout(probeDebounce);
  probeDebounce = setTimeout(() => probeGate($("#gate-dir").value).catch(() => {}), 400);
});

$("#startup-dialog").addEventListener("cancel", (event) => event.preventDefault());

function authorityUpgradeKind(error) {
  const text = String(error);
  if (text.includes("explicit offline-authority migration is required")) return "migration";
  if (text.includes("authority reset with a new identity is required")) return "reset";
  return null;
}

function openAuthorityUpgrade(kind, args) {
  const legacyBackupReset = kind === "legacy-backup-reset";
  const reset = kind === "reset" || legacyBackupReset;
  const root = openModal(
    legacyBackupReset
      ? l10n("gate_upgrade_legacy_title")
      : reset
        ? l10n("gate_upgrade_reset_title")
        : l10n("gate_upgrade_migration_title"),
    "tpl-authority-upgrade",
  );
  root.querySelector('[data-f="explanation"]').textContent = legacyBackupReset
    ? l10n("gate_upgrade_legacy_explanation")
    : reset
      ? l10n("gate_upgrade_reset_explanation")
      : l10n("gate_upgrade_migration_explanation");
  root.querySelector('[data-f="consequence"]').textContent = reset
    ? l10n("gate_upgrade_reset_words")
    : l10n("gate_upgrade_same_identity_words");
  root.querySelector('[data-f="identity-confirm-row"]').hidden = !reset;
  root.querySelector('[data-act="reset-instead"]').hidden = reset;
  if (legacyBackupReset) {
    root.querySelector('[data-act="prepare"]').textContent =
      l10n("gate_upgrade_prepare_fresh");
    root.querySelector('[data-act="complete"]').textContent =
      l10n("gate_upgrade_import_action");
  }
  const path = root.querySelector('[data-f="path"]');
  let mnemonic = "";
  root.addEventListener("click", async (event) => {
    if (event.target.matches('[data-act="reset-instead"]')) {
      closeModal();
      openAuthorityUpgrade("reset", args);
      return;
    }
    if (event.target.matches('[data-act="prepare"]')) {
      const error = root.querySelector('[data-f="error"]');
      error.hidden = true;
      if (!path.value.trim()) {
        error.textContent = l10n("gate_upgrade_choose_destination");
        error.hidden = false;
        return;
      }
      event.target.disabled = true;
      try {
        if (reset) {
          const prepared = await invoke(
            legacyBackupReset
              ? "prepare_legacy_backup_authority_reset"
              : "prepare_authority_reset",
            legacyBackupReset
              ? { recoveryPath: path.value.trim() }
              : {
                  dataDir: args.dataDir,
                  passphrase: args.passphrase,
                  recoveryPath: path.value.trim(),
                },
          );
          mnemonic = prepared.recovery_mnemonic ?? prepared.recoveryMnemonic;
          root.querySelector('[data-f="new-address"]').textContent =
            prepared.new_address ?? prepared.newAddress;
          root.querySelector('[data-f="new-address-row"]').hidden = false;
        } else {
          mnemonic = await invoke("prepare_authority_migration", {
            dataDir: args.dataDir,
            passphrase: args.passphrase,
            recoveryPath: path.value.trim(),
          });
        }
        const list = root.querySelector('[data-f="mnemonic"]');
        list.replaceChildren(...mnemonic.split(/\s+/).map((word) => {
          const item = document.createElement("li");
          item.textContent = word;
          return item;
        }));
        root.querySelector('[data-f="prepare-stage"]').hidden = true;
        root.querySelector('[data-f="confirm-stage"]').hidden = false;
      } catch (failure) {
        error.textContent = localizedError(failure);
        error.hidden = false;
        event.target.disabled = false;
      }
    }
    if (event.target.matches('[data-act="complete"]')) {
      const error = root.querySelector('[data-f="complete-error"]');
      error.hidden = true;
      const saved = root.querySelector('[data-f="saved"]').checked;
      const identityConfirmed =
        !reset || root.querySelector('[data-f="identity-confirm"]').checked;
      if (!saved || !identityConfirmed) {
        error.textContent = l10n("authority_upgrade_confirmation_required");
        error.hidden = false;
        return;
      }
      event.target.disabled = true;
      try {
        const address = await invoke(
          legacyBackupReset ? "restore" : reset ? "reset_authority" : "migrate_authority",
          {
            ...args,
            recoveryPackagePath: path.value.trim(),
            recoveryMnemonic: mnemonic,
          },
        );
        closeModal();
        state.dataDir = args.dataDir;
        enterApp(address);
        if (reset) {
          toast(l10n("gate_upgrade_reset_done"));
        }
      } catch (failure) {
        error.textContent = localizedError(failure);
        error.hidden = false;
        event.target.disabled = false;
      }
    }
  });
}

$("#gate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#gate-go");
  const errEl = $("#gate-error");
  const startupDialog = $("#startup-dialog");
  errEl.hidden = true;
  btn.disabled = true;
  btn.textContent = l10n("gate_opening_short");
  if (!startupDialog.open) startupDialog.showModal();
  let deferredUpgrade = null;
  try {
    const creatingFresh =
      gateMode !== "restore" && !$("#gate-tabs").hidden;
    const args = {
      dataDir: $("#gate-dir").value.trim(),
      passphrase: $("#gate-pass").value,
      settings: readSettings(),
    };
    let address;
    if (gateMode === "restore" && !$("#gate-tabs").hidden) {
      if ($("#gate-legacy-backup").checked) {
        deferredUpgrade = ["legacy-backup-reset", {
          ...args,
          backupPath: $("#gate-backup").value.trim(),
          mnemonic: $("#gate-mnemonic").value.trim(),
        }];
      } else {
        address = await invoke("restore", {
          ...args,
          backupPath: $("#gate-backup").value.trim(),
          mnemonic: $("#gate-mnemonic").value.trim(),
          recoveryPackagePath: $("#gate-recovery-package").value.trim(),
          recoveryMnemonic: $("#gate-recovery-mnemonic").value.trim(),
        });
      }
    } else {
      address = await invoke("unlock", args);
    }
    if (address) {
      state.dataDir = args.dataDir;
      enterApp(address);
      if (creatingFresh) openRecoveryAuthorityOnboarding();
    }
  } catch (err) {
    const upgrade = authorityUpgradeKind(err);
    if (upgrade) {
      deferredUpgrade = [upgrade, {
        dataDir: $("#gate-dir").value.trim(),
        passphrase: $("#gate-pass").value,
        settings: readSettings(),
      }];
    } else {
      errEl.textContent = localizedError(err);
      errEl.hidden = false;
    }
  } finally {
    if (startupDialog.open) startupDialog.close();
    btn.disabled = false;
    probeGate($("#gate-dir").value).catch(() => {});
  }
  if (deferredUpgrade) openAuthorityUpgrade(...deferredUpgrade);
});

// ── main app ────────────────────────────────────────────────────────────

function enterApp(address) {
  state.address = address;
  $("#gate").hidden = true;
  $("#app").hidden = false;
  $("#my-address").textContent = address;
  $("#gate-pass").value = "";
  $("#gate-mnemonic").value = "";
  $("#gate-recovery-mnemonic").value = "";
  // Transport status is essential, so start it before optional list, icon,
  // and theme setup. A failure in any independent UI surface must not leave
  // these indicators at the static HTML placeholders.
  $("#stat-discovery").textContent = l10n("status_discovery_starting");
  $("#stat-nat").textContent = l10n("status_nat_checking");
  clearInterval(state.statusTimer);
  refreshStatus();
  state.statusTimer = setInterval(refreshStatus, 5000);
  refreshContacts();
  refreshGroups();
  refreshRequestInboxBadge();
  refreshFolders();
  refreshLabels();
  refreshAuthorityResetHistory();
  call("note_to_self_id").then((id) => { state.noteToSelfId = id; });
  applyCustomIcon(
    $("#note-to-self .avatar"),
    { kind: "note_to_self", id: null },
    "N",
    l10n("note_to_self_title"),
  );
  syncThemeAfterUnlock();
}

async function refreshAuthorityResetHistory() {
  const banner = $("#authority-reset-banner");
  try {
    const record = await invoke("authority_reset_history");
    if (!record) {
      banner.hidden = true;
      return;
    }
    const pending = record.pending_reverification ?? record.pendingReverification ?? [];
    const pairwise =
      record.preserved_pairwise_messages ?? record.preservedPairwiseMessages ?? 0;
    const notes = record.preserved_note_messages ?? record.preservedNoteMessages ?? 0;
    const omittedGroups = record.omitted_groups ?? record.omittedGroups ?? 0;
    const omittedMessages =
      record.omitted_group_messages ?? record.omittedGroupMessages ?? 0;
    $("#authority-reset-summary").textContent = l10n(
      "authority_reset_archive_summary",
      l10n("authority_reset_archive_title"),
      Number(pairwise),
      Number(notes),
      Number(omittedGroups),
      Number(omittedMessages),
      pending.length,
    );
    banner.hidden = false;
  } catch {
    banner.hidden = true;
  }
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
    toast(localizedError(error), true);
  }
}

async function leaveApp() {
  abortRecording(l10n("audio_interrupted_discarded"));
  stopCallMedia();
  closeModal();
  clearInterval(state.statusTimer);
  state.statusTimer = null;
  state.currentKind = null;
  state.currentId = null;
  state.call = null;
  state.callPrompted.clear();
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
  $("#authority-reset-banner").hidden = true;
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
  $("#screen-security-mechanism").textContent = l10nSource(policy.mechanism);
  const limits = $("#screen-security-limitations");
  limits.replaceChildren(...policy.limitations.map((text) => {
    const item = document.createElement("li");
    item.textContent = l10nSource(text);
    return item;
  }));
}).catch(() => {
  $("#screen-security-mechanism").textContent = l10n("screen_security_status_unavailable");
});

invoke("incognito_keyboard_policy").then((policy) => {
  $("#incognito-keyboard-mechanism").textContent = l10nSource(policy.mechanism);
  const limits = $("#incognito-keyboard-limitations");
  limits.replaceChildren(...policy.limitations.map((text) => {
    const item = document.createElement("li");
    item.textContent = l10nSource(text);
    return item;
  }));
}).catch(() => {
  $("#incognito-keyboard-mechanism").textContent = l10n("input_privacy_status_unavailable");
});

$("#btn-copy-address").addEventListener("click", () => copyText(state.address));

async function refreshStatus() {
  let s;
  try {
    s = await invoke("status");
  } catch (error) {
    if ($("#app").hidden) return; // locked or shutting down
    const message = l10n("status_unavailable");
    const discovery = $("#stat-discovery");
    discovery.textContent = l10n("status_discovery_unavailable");
    discovery.className = "stat warn";
    discovery.title = message;
    const nat = $("#stat-nat");
    nat.textContent = l10n("status_nat_unavailable");
    nat.className = "stat warn";
    nat.title = message;
    return;
  }
  state.peer = s.peer;
  state.address = s.connect_code;
  $("#my-address").textContent = s.connect_code;
  const nat = $("#stat-nat");
  nat.textContent = l10n("status_nat_value", natName(s.nat));
  nat.className = "stat " + (s.nat === "public" ? "good" : s.nat === "private" ? "warn" : "");
  nat.title = l10n(
    "status_listening_on",
    s.listen.join("\n") || l10n("status_binding"),
  );
  const lan = $("#stat-lan");
  lan.textContent = l10n("status_lan_count", s.lan_peers.length);
  lan.className = "stat " + (s.lan_peers.length ? "good" : s.mdns_enabled ? "" : "warn");
  lan.title = s.lan_peers.length
    ? l10n("status_lan_peers", s.lan_peers.join("\n"))
    : s.mdns_enabled
      ? l10n("status_lan_empty")
      : l10n("status_lan_disabled");
  const mode = $("#stat-mode");
  mode.textContent = modeName(s.mode);
  mode.className = "stat good";
  mode.title = s.mode === "private"
    ? l10n("set_mode_private_disclosure")
    : s.mode === "sovereign"
      ? l10n("set_mode_sovereign_disclosure")
      : l10n("set_mode_standard_disclosure");
  const discovery = $("#stat-discovery");
  discovery.textContent = connectionName(s.connection);
  discovery.className = "stat " + (s.connection === "connected" ? "good" :
    s.connection === "fallback_ready" ? "" : "warn");
  discovery.title = l10nPlural(
    "status_directory_peers",
    s.connected_peers,
    directoryName(s.provider_directory),
    s.connected_peers,
  );
  $("#stat-queued").textContent = l10n("status_queued_count", s.queued);
  $("#stat-scheduled").textContent = l10n(
    "status_scheduled_count",
    s.scheduled,
  );
  const transit = $("#stat-transit");
  transit.hidden = s.transit === 0;
  transit.textContent = l10n("status_bridging_count", s.transit);
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
    name.textContent = row.target.kind === "note_to_self"
      ? l10n("note_to_self_title")
      : (row.display_name ?? l10n("pin_unavailable"));
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
    up.title = l10n("pins_earlier");
    up.setAttribute("aria-label", l10n("pin_move_earlier", name.textContent));
    up.addEventListener("click", () => reorderPinTarget(row.target, -1));
    const down = document.createElement("button");
    down.type = "button";
    down.className = "ghost";
    down.textContent = "↓";
    down.title = l10n("pins_later");
    down.setAttribute("aria-label", l10n("pin_move_later", name.textContent));
    down.addEventListener("click", () => reorderPinTarget(row.target, 1));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost";
    remove.textContent = l10n("pins_unpin");
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
    description.textContent = l10n("pin_unavailable");
    const cleanup = document.createElement("button");
    cleanup.type = "button";
    cleanup.className = "danger";
    cleanup.textContent = l10n("pins_cleanup");
    cleanup.setAttribute("aria-label", l10n("pin_cleanup_accessibility"));
    cleanup.addEventListener("click", async () => {
      try {
        await call("cleanup_stale_pin", { target: pin.target });
        $("#pin-status").textContent = l10n("pin_cleanup_done");
        await runLabelFilter(true);
      } catch (error) {
        $("#pin-status").textContent = localizedError(error);
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
    $("#label-filter-status").textContent = l10nPlural(
      "label_filter_unavailable",
      result.unavailable_labels.length,
      result.unavailable_labels.length,
    );
  } else if (announce) {
    $("#label-filter-status").textContent = state.labelFilter.selected.length === 0
      ? l10n("label_filter_cleared")
      : l10nPlural(
        "label_filter_result",
        result.conversations.length,
        result.conversations.length,
        l10n(
          state.labelFilter.mode === "any"
            ? "label_filter_mode_any"
            : "label_filter_mode_all",
        ),
      );
  } else if (prior !== result.selected.length) {
    const removed = Math.max(1, prior - result.selected.length);
    $("#label-filter-status").textContent = l10nPlural(
      "label_filter_unavailable",
      removed,
      removed,
    );
  }
  $("#btn-clear-label-filter").hidden = state.labelFilter.selected.length === 0;
  applyLabelFilterVisibility();
  await renderPinnedList();
}

async function refreshFolders(announce = false) {
  state.folders = await call("folders");
  if (state.folderSelection.kind === "folder" && !state.folders.some((folder) => folder.id === state.folderSelection.id)) {
    state.folderSelection = { kind: "all", id: null };
    $("#folder-navigation-status").textContent =
      l10n("folder_selection_unavailable");
  }
  const items = $("#folder-navigation-items");
  items.replaceChildren();
  for (const folder of state.folders) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.dataset.folderKind = "folder";
    button.dataset.folderId = folder.id;
    button.setAttribute(
      "aria-label",
      l10n("folder_filter_description", folderAccessibleName(folder)),
    );
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
      folderAccessibleName(folder),
    );
    button.addEventListener("click", async () => {
      state.folderSelection = { kind: "folder", id: folder.id };
      await runLabelFilter(true);
      renderFolderNavigationSelection();
      $("#folder-navigation-status").textContent = l10n(
        "folder_showing",
        folderAccessibleName(folder),
      );
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
    $("#folder-navigation-status").textContent = l10n(
      "folder_showing",
      button.textContent,
    );
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
    empty.textContent = l10n("labels_empty");
    options.append(empty);
  }
  for (const label of state.labels) {
    const row = document.createElement("label");
    row.className = "label-filter-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = label.id;
    input.checked = state.labelFilter.selected.includes(label.id);
    input.setAttribute(
      "aria-label",
      l10n("label_filter_by", labelAccessibleName(label)),
    );
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
      badge.title = l10n("verify_safety_verified");
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
  const name = state.contacts.find((c) => c.peer === peer)?.name?.trim();
  return name || peer.slice(0, 12) + "…";
}

function memberName(peer) {
  if (peer === state.peer) return l10n("group_you");
  const contact = state.contacts.find((candidate) => candidate.peer === peer);
  if (contact) return contact.name;
  const position = (currentGroup()?.members ?? []).indexOf(peer);
  return position >= 0
    ? l10n("group_member_position", position + 1)
    : l10n("group_member_unavailable");
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
  return l10n("group_member_disambiguated", base, position);
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
    $("#mention-status").textContent = l10nPlural(
      "mention_links_removed",
      removed,
      removed,
    );
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
    button.textContent = `${l10n("mention_label", memberLabel(span.target))} ×`;
    button.setAttribute(
      "aria-label",
      l10n("mention_remove_action", memberLabel(span.target)),
    );
    button.addEventListener("click", () => {
      state.mentionDraft.spans.splice(index, 1);
      replaceDraftRange(span.start, span.end, "");
      $("#mention-status").textContent = l10n(
        "mention_removed_with_text",
        memberLabel(span.target),
      );
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
  const blockers = capability.issues.map((issue) => l10n(
    "mention_blocker",
    memberLabel(issue.peer, group),
    l10n(
      issue.reason === "unsupported"
        ? "mention_capability_unsupported"
        : "mention_capability_unknown",
    ),
  ));
  $("#mention-status").textContent = capability.supported
    ? l10n("mention_ready")
    : l10n("mention_unavailable", blockers.join(", "));

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

async function refreshMentionReview(_reason) {
  if (
    state.currentKind !== "group"
    || state.mentionDraft.spans.length === 0
    || state.mentionDraft.group !== state.currentId
  ) return;
  const fresh = await call("group_mention_capability", { group: state.currentId });
  if (!state.mentionDraft.capability || fresh.review_token !== state.mentionDraft.capability.review_token) {
    state.mentionDraft.capability = fresh;
    $("#mention-status").textContent = l10n("mention_review_again");
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
  $("#mention-status").textContent = l10n(
    "mention_inserted",
    memberLabel(peer),
  );
}

function formattingHighlights(message) {
  if (message.content_kind !== "mention" || !message.mention_spans?.length) return [];
  return message.mention_spans.map(({ start, end }) => ({ start, end }));
}

function styledRun(run) {
  let node = document.createTextNode(run.text);
  for (const style of run.styles) {
    const wrapper = document.createElement(
      style === "strong" ? "strong"
        : style === "emphasis" ? "em"
        : style === "inline_code" ? "code"
        : "mark"
    );
    if (style === "highlight") {
      wrapper.className = "mention-highlight";
      wrapper.tabIndex = 0;
      wrapper.setAttribute("aria-label", l10n("mention_highlighted"));
    }
    wrapper.append(node);
    node = wrapper;
  }
  return node;
}

function appendFormattedBody(container, formatted) {
  const body = document.createElement("div");
  body.className = "formatted-text";
  body.dataset.formatFallback = formatted.used_fallback ? "true" : "false";
  for (const block of formatted.blocks) {
    const blockElement = document.createElement(
      block.kind === "quote" ? "blockquote"
        : block.kind === "code_block" ? "pre"
        : "div"
    );
    blockElement.className = `format-block format-${block.kind}`;
    if (block.kind.endsWith("list_item")) {
      blockElement.setAttribute("role", "listitem");
      blockElement.style.setProperty("--list-depth", String(block.depth));
      const marker = document.createElement("span");
      marker.className = "format-list-marker";
      marker.setAttribute("aria-hidden", "true");
      marker.textContent = block.kind === "ordered_list_item" ? `${block.ordinal}.` : "•";
      blockElement.append(marker);
    }
    const runs = document.createElement(block.kind === "code_block" ? "code" : "span");
    for (const run of block.runs) runs.append(styledRun(run));
    blockElement.append(runs);
    body.append(blockElement);
  }
  body.addEventListener("copy", (event) => {
    if (!event.clipboardData) return;
    event.clipboardData.setData("text/plain", formatted.plain_text);
    event.preventDefault();
  });
  container.append(body);
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
    const fallback = generatedInitials(group.name || l10n("group_default_name"));
    avatar.textContent = fallback;
    const name = document.createElement("span");
    name.className = "c-name";
    name.textContent = group.name || l10n("group_unnamed");
    applyCustomIcon(avatar, { kind: "group", id: group.id }, fallback, name.textContent);
    const detail = document.createElement("span");
    detail.className = "c-detail";
    detail.textContent = l10nPlural(
      "group_member_count",
      group.members.length,
      group.members.length,
    );
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
  $("#chat-name").textContent = isNote
    ? l10n("note_to_self_title")
    : isGroup
      ? (group?.name ?? "")
      : contactName(state.currentId);
  $("#chat-verified").hidden = isGroup || isNote || !contact?.verified;
  $("#btn-verify").hidden = isGroup || isNote;
  $("#btn-rename-contact").hidden = isGroup || isNote;
  $("#btn-hints").hidden = isGroup || isNote;
  $("#btn-call").hidden = isGroup || isNote;
  $("#btn-group-details").hidden = !isGroup;
  $("#btn-mention").hidden = !isGroup;
  $("#btn-poll").hidden = !isGroup;
  $("#btn-attach").hidden = isNote;
  $("#btn-record").hidden = isNote;
  $("#btn-schedule").hidden = isNote;
  $("#expiry-control").hidden = isNote;
  $("#expiry-honesty").hidden = isNote || $("#composer-expiry").value === "0";
  $("#note-to-self").classList.toggle("active", isNote);
  const target = labelTarget();
  const isPinned = target && state.pins.some((pin) => labelTargetKey(pin.target) === labelTargetKey(target));
  $("#btn-conversation-pin").textContent = isPinned
    ? l10n("pins_unpin")
    : l10nSource("Pin");
  $("#btn-conversation-pin").setAttribute("aria-pressed", isPinned ? "true" : "false");
  if (target) renderTargetBadges($("#chat-label-badges"), target);
  else $("#chat-label-badges").replaceChildren();
  updateCallButton().catch((error) => toast(localizedError(error), true));
}

function callMediaSupported() {
  return Boolean(
    navigator.mediaDevices?.getUserMedia
      && globalThis.AudioEncoder
      && globalThis.AudioDecoder
      && globalThis.AudioData
      && globalThis.EncodedAudioChunk
      && globalThis.MediaStreamTrackProcessor,
  );
}

function callEndText(reason) {
  return l10n({
    declined: "call_declined",
    busy: "call_busy",
    cancelled: "call_cancelled",
    hung_up: "call_ended",
    expired: "call_expired",
    answered_elsewhere: "call_answered_elsewhere",
    route_lost: "call_route_lost",
  }[reason] ?? "call_ended");
}

function callUnavailableText(reason) {
  return l10n({
    offline_or_unknown: "call_offline",
    bulk_only: "call_bulk_only",
    mesh_only: "call_mesh_only",
    missing_session: "call_missing_session",
    unsupported: "call_unsupported",
    already_in_call: "call_already_active",
  }[reason] ?? "call_unavailable");
}

function showCallStatus(text, className = "") {
  const status = $("#call-status");
  status.hidden = !text;
  status.textContent = text;
  status.className = `call-status ${className}`.trim();
}

async function updateCallButton() {
  const button = $("#btn-call");
  if (state.currentKind !== "contact" || !state.currentId) {
    button.hidden = true;
    showCallStatus("");
    return;
  }
  button.hidden = false;
  const current = state.call && state.call.peer === state.currentId && state.call.phase !== "ended"
    ? state.call : null;
  if (current) {
    button.disabled = false;
    button.textContent = current.phase === "ringing" && current.direction === "outgoing"
      ? l10n("call_cancel") : l10n("call_hangup");
    button.title = l10n("call_direct_quic_note");
    showCallStatus(
      current.phase === "ringing" ? l10n("call_ringing")
        : current.phase === "connecting" ? l10n("call_connecting")
          : l10n("call_active"),
      current.phase === "active" ? "active" : "",
    );
    return;
  }
  button.textContent = l10n("call_start");
  if (!callMediaSupported()) {
    button.disabled = true;
    button.title = l10n("call_webview_unsupported");
    showCallStatus(l10n("call_webview_unsupported"));
    return;
  }
  const availability = await invoke("call_availability", { peer: state.currentId });
  button.disabled = !availability.available;
  button.title = availability.available
    ? l10n("call_start_description")
    : callUnavailableText(availability.unavailable);
  showCallStatus(availability.available ? "" : callUnavailableText(availability.unavailable));
}

async function acquireCallStream() {
  return navigator.mediaDevices.getUserMedia({
    video: false,
    audio: {
      channelCount: 1,
      sampleRate: 48_000,
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    },
  });
}

function stopCallMedia() {
  const media = state.callMedia;
  state.callMedia = null;
  if (media) {
    media.stopped = true;
    clearInterval(media.pollTimer);
    media.reader?.cancel().catch(() => {});
    try { media.encoder?.close(); } catch {}
    try { media.decoder?.close(); } catch {}
    media.stream?.getTracks().forEach((track) => track.stop());
    media.context?.close().catch(() => {});
  }
  if (state.pendingCallStream) {
    state.pendingCallStream.getTracks().forEach((track) => track.stop());
    state.pendingCallStream = null;
  }
}

async function startCallMedia(snapshot) {
  if (state.callMedia?.call === snapshot.id) return;
  if (!callMediaSupported()) {
    await invoke("hangup_call", { call: snapshot.id }).catch(() => {});
    toast(l10n("call_webview_unsupported"), true);
    return;
  }
  const stream = state.pendingCallStream ?? await acquireCallStream();
  state.pendingCallStream = null;
  const context = new AudioContext({ sampleRate: 48_000, latencyHint: "interactive" });
  await context.resume();
  const media = {
    call: snapshot.id,
    stream,
    context,
    encoder: null,
    decoder: null,
    reader: null,
    pollTimer: null,
    nextPlayback: context.currentTime + 0.06,
    polling: false,
    stopped: false,
  };
  state.callMedia = media;

  media.decoder = new AudioDecoder({
    error: () => toast(l10n("call_media_failed"), true),
    output: (audio) => {
      if (media.stopped) { audio.close(); return; }
      const buffer = context.createBuffer(audio.numberOfChannels, audio.numberOfFrames, audio.sampleRate);
      for (let channel = 0; channel < audio.numberOfChannels; channel += 1) {
        const samples = new Float32Array(audio.numberOfFrames);
        audio.copyTo(samples, { planeIndex: channel, format: "f32-planar" });
        buffer.copyToChannel(samples, channel);
        samples.fill(0);
      }
      audio.close();
      const source = context.createBufferSource();
      source.buffer = buffer;
      source.connect(context.destination);
      const startsAt = Math.max(context.currentTime + 0.02, media.nextPlayback);
      source.start(startsAt);
      media.nextPlayback = startsAt + buffer.duration;
    },
  });
  media.decoder.configure({ codec: "opus", sampleRate: 48_000, numberOfChannels: 1 });

  media.encoder = new AudioEncoder({
    error: () => toast(l10n("call_media_failed"), true),
    output: async (chunk) => {
      if (media.stopped || chunk.byteLength > 1_275) return;
      const packet = new Uint8Array(chunk.byteLength);
      chunk.copyTo(packet);
      try {
        await invoke("send_call_audio", {
          call: snapshot.id,
          timestampMs: Math.max(0, Math.floor(chunk.timestamp / 1_000)),
          opusPacket: [...packet],
        });
      } catch (error) {
        if (!media.stopped) toast(localizedError(error), true);
      } finally {
        packet.fill(0);
      }
    },
  });
  media.encoder.configure({
    codec: "opus",
    sampleRate: 48_000,
    numberOfChannels: 1,
    bitrate: 24_000,
    opus: { frameDuration: 20_000 },
  });
  const processor = new MediaStreamTrackProcessor({ track: stream.getAudioTracks()[0] });
  media.reader = processor.readable.getReader();
  (async () => {
    while (!media.stopped) {
      const { done, value } = await media.reader.read();
      if (done || media.stopped) break;
      media.encoder.encode(value);
      value.close();
    }
  })().catch((error) => {
    if (!media.stopped) toast(l10n("call_media_failed"), true);
  });

  media.pollTimer = setInterval(async () => {
    if (media.stopped || media.polling) return;
    media.polling = true;
    try {
      for (let count = 0; count < 3; count += 1) {
        const frame = await invoke("take_call_audio", { call: snapshot.id });
        if (!frame) break;
        const packet = new Uint8Array(frame.opus_packet);
        media.decoder.decode(new EncodedAudioChunk({
          type: "key",
          timestamp: frame.timestamp_ms * 1_000,
          data: packet,
        }));
        packet.fill(0);
      }
    } catch (error) {
      if (!media.stopped && !String(error).includes("invalid call")) {
        toast(localizedError(error), true);
      }
    } finally {
      media.polling = false;
    }
  }, 10);
}

async function handleCallUpdate(snapshot) {
  state.call = snapshot;
  if (snapshot.phase === "ringing" && snapshot.direction === "incoming"
      && !state.callPrompted.has(snapshot.id)) {
    state.callPrompted.add(snapshot.id);
    const answer = window.confirm(
      l10n("call_incoming_prompt", contactName(snapshot.peer)),
    );
    if (answer) {
      try {
        state.pendingCallStream = await acquireCallStream();
        await invoke("answer_call", { call: snapshot.id });
      } catch (error) {
        stopCallMedia();
        await invoke("decline_call", { call: snapshot.id }).catch(() => {});
        toast(localizedError(error), true);
      }
    } else {
      await invoke("decline_call", { call: snapshot.id });
    }
  } else if (snapshot.phase === "active") {
    await startCallMedia(snapshot);
  } else if (snapshot.phase === "ended") {
    stopCallMedia();
    showCallStatus(callEndText(snapshot.end_reason), "ended");
    setTimeout(() => {
      if (state.call?.id === snapshot.id) updateCallButton().catch(() => {});
    }, 3_000);
  }
  await updateCallButton();
}

$("#btn-call").addEventListener("click", async () => {
  const snapshot = state.call?.phase !== "ended" ? state.call : null;
  try {
    if (snapshot?.phase === "ringing" && snapshot.direction === "outgoing") {
      stopCallMedia();
      await invoke("cancel_call", { call: snapshot.id });
    } else if (snapshot && ["connecting", "active"].includes(snapshot.phase)) {
      stopCallMedia();
      await invoke("hangup_call", { call: snapshot.id });
    } else {
      state.pendingCallStream = await acquireCallStream();
      const callId = await invoke("start_call", { peer: state.currentId });
      state.call = (await invoke("calls")).find((call) => call.id === callId) ?? {
        id: callId, peer: state.currentId, direction: "outgoing", phase: "ringing",
      };
      await updateCallButton();
    }
  } catch (error) {
    stopCallMedia();
    toast(localizedError(error), true);
  }
});

function contactNameWarningText(assessment) {
  const messages = [];
  if (assessment.warnings.includes("duplicate_name")) {
    messages.push(l10nPlural(
      "contact_warning_duplicate",
      assessment.duplicate_count,
      assessment.duplicate_count,
    ));
  }
  if (assessment.warnings.includes("confusable_name")) {
    messages.push(l10n("contact_warning_confusable"));
  }
  if (assessment.warnings.includes("bidirectional_control")) {
    messages.push(l10n("contact_warning_bidi"));
  }
  if (assessment.warnings.includes("invisible_character")) {
    messages.push(l10n("contact_warning_invisible"));
  }
  return messages.join("\n");
}

$("#btn-rename-contact").addEventListener("click", () => {
  const peer = state.currentId;
  const contact = state.contacts.find((candidate) => candidate.peer === peer);
  if (!peer || !contact) return;
  const root = openModal(l10n("contact_rename_title"), "tpl-rename-contact");
  const input = root.querySelector('[data-f="name"]');
  input.value = contact.name;
  root.querySelector('[data-act="save"]').addEventListener("click", async () => {
    const error = root.querySelector('[data-f="error"]');
    error.hidden = true;
    try {
      const proposed = input.value;
      const assessment = await invoke("assess_contact_name", { peer, name: proposed });
      let acceptWarnings = false;
      if (assessment.warnings.length > 0) {
        const warning = contactNameWarningText(assessment);
        acceptWarnings = window.confirm(
          `${warning}\n\n${l10n(
            "contact_warning_identity",
            assessment.normalized_name,
          )}`,
        );
        if (!acceptWarnings) return;
      }
      const renamed = await invoke("rename_contact", {
        peer,
        name: proposed,
        acceptWarnings,
      });
      closeModal();
      await refreshContacts();
      await refreshGroups();
      toast(l10n("contact_rename_done", renamed.normalized_name));
    } catch (e) {
      error.textContent = localizedError(e);
      error.hidden = false;
    }
  });
});

$("#btn-conversation-pin").addEventListener("click", async () => {
  const target = labelTarget();
  if (!target) return;
  const isPinned = state.pins.some((pin) => labelTargetKey(pin.target) === labelTargetKey(target));
  await call(isPinned ? "unpin_conversation" : "pin_conversation", { target });
  await runLabelFilter(true);
  updateChatHead();
  $("#pin-status").textContent = l10n(
    isPinned ? "pin_unpinned_status" : "pin_pinned_status",
  );
});

// ── conversation ────────────────────────────────────────────────────────

async function clearActiveContact(nextPeer = null) {
  if (
    state.currentKind === "contact"
    && state.currentId
    && state.currentId !== nextPeer
  ) {
    await invoke("set_rendezvous_conversation_active", {
      peer: state.currentId,
      active: false,
    }).catch(() => {});
  }
}

async function openChat(peer) {
  await clearActiveContact(peer);
  state.currentKind = "contact";
  state.currentId = peer;
  state.unread.delete(peer);
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  $("#composer-input").value = "";
  resetMentionDraft();
  updateChatHead();
  await invoke("set_rendezvous_conversation_active", {
    peer,
    active: true,
  }).catch(() => {});
  await renderMessages();
  refreshContacts();
  $("#composer-input").focus();
}

async function openGroup(group) {
  await clearActiveContact();
  state.currentKind = "group";
  state.currentId = group;
  state.groupUnread.delete(group);
  $("#chat-empty").hidden = true;
  $("#chat-pane").hidden = false;
  $("#composer-input").value = "";
  resetMentionDraft(l10n("mention_member_description"));
  updateChatHead();
  await renderMessages();
  refreshGroups();
  $("#composer-input").focus();
}

async function openNoteToSelf() {
  await clearActiveContact();
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

$(".chat-more").addEventListener("click", (event) => {
  if (event.target.closest("button")) event.currentTarget.open = false;
});

function messageDayKey(unixSecs) {
  const date = new Date(unixSecs * 1000);
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

function messageDaySeparator(unixSecs) {
  const date = new Date(unixSecs * 1000);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  const separator = document.createElement("div");
  separator.className = "message-day";
  separator.setAttribute("role", "separator");
  separator.textContent = date.toDateString() === today.toDateString()
    ? l10n("date_today")
    : date.toDateString() === yesterday.toDateString()
      ? l10n("date_yesterday")
      : date.toLocaleDateString(KommsLocalization.activeLocale(), {
        month: "long",
        day: "numeric",
        year: "numeric",
      });
  return separator;
}

function bubble(m, formatted) {
  const el = document.createElement("div");
  el.className = "msg " + (m.outbound ? "out" : "in");
  appendFormattedBody(el, formatted);
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.append(fmtTime(m.timestamp));
  appendExpiryMetadata(meta, m);
  if (m.outbound) {
    const st = document.createElement("span");
    st.className = "state"
      + (m.state === "delivered" ? " state-delivered" : "")
      + (m.state === "failed" ? " state-failed" : "");
    st.textContent = ` · ${deliveryState(m.state)}`;
    meta.append(st);
  }
  el.append(meta);
  appendEditMetadata(el, meta, m, false);
  state.msgEls.set(m.id, el);
  return el;
}

function noteBubble(m, formatted) {
  const el = document.createElement("div");
  el.className = "msg out";
  appendFormattedBody(el, formatted);
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = `${fmtTime(m.timestamp)} · ${l10n("note_local_only")}`;
  el.append(meta);
  state.msgEls.set(m.id, el);
  return el;
}

function groupBubble(m, formatted) {
  const el = document.createElement("div");
  el.className = "msg " + (m.outbound ? "out" : "in");
  if (!m.outbound) {
    const sender = document.createElement("span");
    sender.className = "sender";
    sender.textContent = memberName(m.sender);
    el.append(sender);
  }
  appendFormattedBody(el, formatted);
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = fmtTime(m.timestamp);
  appendExpiryMetadata(meta, m);
  if (m.authentication === "legacy_membership") {
    const authentication = document.createElement("span");
    authentication.textContent = ` · ${l10n("group_message_legacy_origin")}`;
    authentication.title = l10n("group_message_legacy_origin_detail");
    meta.append(authentication);
  } else if (m.authentication === "pending_recipient_authentication") {
    const authentication = document.createElement("span");
    authentication.textContent = ` · ${l10n("group_message_pending_origin")}`;
    authentication.title = l10n("group_message_pending_origin_detail");
    meta.append(authentication);
  }
  el.append(meta);
  appendEditMetadata(el, meta, m, true);
  if (m.outbound) {
    const deliveries = document.createElement("span");
    deliveries.className = "deliveries";
    for (const delivery of m.deliveries) {
      const item = document.createElement("span");
      item.className = "delivery"
        + (delivery.state === "delivered" ? " state-delivered" : "")
        + (delivery.state === "failed" ? " state-failed" : "");
      item.dataset.peer = delivery.peer;
      item.textContent = l10n(
        "group_delivery_row",
        memberName(delivery.peer),
        deliveryState(delivery.state),
      );
      deliveries.append(item);
    }
    el.append(deliveries);
  }
  state.msgEls.set(m.id, el);
  return el;
}

function appendExpiryMetadata(meta, message) {
  if (message.content_kind !== "disappearing_text" || !message.expires_at) return;
  const marker = document.createElement("span");
  marker.className = "expiry-marker";
  marker.textContent = ` · ${l10n("ephemeral_remove_at", fmtExpiry(message.expires_at))}`;
  marker.title = l10n("ephemeral_honesty");
  meta.append(marker);
}

function appendEditMetadata(container, meta, message, group) {
  if (message.edited) {
    const marker = document.createElement("span");
    marker.className = "edited-marker";
    marker.textContent = ` · ${l10n("message_edited_revision", message.edit_revision)}`;
    meta.append(marker);
  }
  if (message.outbound && message.content_kind === "text") {
    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "message-edit ghost";
    edit.textContent = l10n("message_edit_action");
    edit.setAttribute("aria-label", l10n("message_edit_action_description"));
    edit.addEventListener("click", () => openMessageEdit(message, group));
    meta.append(" · ", edit);
  }
  if (!message.edited || !message.versions?.length) return;
  const history = document.createElement("details");
  history.className = "edit-history";
  const summary = document.createElement("summary");
  summary.textContent = l10nPlural(
    "message_version_history",
    message.versions.length,
    message.versions.length,
  );
  history.append(summary);
  const list = document.createElement("ol");
  for (const version of [...message.versions].reverse()) {
    const item = document.createElement("li");
    const label = document.createElement("strong");
    label.textContent = version.revision === 0
      ? l10n("message_history_original")
      : l10n("message_history_revision", version.revision);
    const time = document.createElement("span");
    time.className = "version-time";
    time.textContent = ` · ${fmtTime(version.timestamp)}`;
    const body = document.createElement("div");
    body.className = "version-body";
    body.textContent = version.body;
    item.append(label, time, body);
    list.append(item);
  }
  history.append(list);
  container.append(history);
}

function openMessageEdit(message, group) {
  if (!message.outbound || message.content_kind !== "text") return;
  const conversation = state.currentId;
  const root = openModal(l10n("message_edit_title"), "tpl-message-edit");
  const body = root.querySelector('[data-f="body"]');
  body.value = message.body;
  root.addEventListener("click", async (event) => {
    if (!event.target.matches('[data-act="save"]')) return;
    event.preventDefault();
    try {
      if (body.value.length === 0) throw l10n("message_edit_empty");
      const exact = {
        targetAuthor: state.peer,
        targetContentId: message.id,
        text: body.value,
      };
      if (group) {
        await invoke("edit_group_message", { group: conversation, ...exact });
      } else {
        await invoke("edit_message", { peer: conversation, ...exact });
      }
      closeModal();
      await renderMessages();
    } catch (error) {
      showError(root, error);
    }
  });
  body.focus();
  body.select();
}

function scheduledBubble(message, formatted) {
  const el = document.createElement("div");
  el.className = "msg out scheduled";
  appendFormattedBody(el, formatted);
  const meta = document.createElement("span");
  meta.className = "meta scheduled-meta";
  meta.textContent = l10n("scheduled_send_at", fmtTime(message.not_before));
  const actions = document.createElement("span");
  actions.className = "scheduled-actions";
  const edit = document.createElement("button");
  edit.type = "button";
  edit.className = "ghost";
  edit.textContent = l10n("scheduled_edit");
  edit.addEventListener("click", () => openScheduleModal(message));
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "danger";
  cancel.textContent = l10n("scheduled_cancel");
  cancel.addEventListener("click", async () => {
    if (!window.confirm(l10n("scheduled_cancel_title"))) return;
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
    title: l10n("attachment_export_title"),
    defaultPath: primary?.filename ?? l10n("attachment_default_name"),
  });
  if (!path) return;
  await call("export_attachment", { transfer: attachment.transfer_id, path });
  toast(l10n(
    "attachment_exported_name",
    primary?.filename ?? l10n("attachment_default_name"),
  ));
}

async function consumeViewOnceAttachment(attachment) {
  const primary = attachment.objects.find((object) => !object.preview) ?? attachment.objects[0];
  const name = primary?.filename ?? l10n("attachment_view_once_filename");
  if (!window.confirm(l10n("attachment_reveal_once_named_confirmation", name))) return;
  const path = await savePath({ title: l10n("attachment_reveal_once_title"), defaultPath: name });
  if (!path) return;
  await call("consume_view_once_attachment", { transfer: attachment.transfer_id, path });
  toast(l10n("attachment_revealed_once", name));
  await renderMessages();
}

async function openAttachment(attachment) {
  const primary = attachment.objects.find((object) => !object.preview) ?? attachment.objects[0];
  const name = primary?.filename ?? l10n("attachment_default_name");
  if (!window.confirm(l10n("attachment_open_confirmation", name))) return;
  await call("open_attachment", { transfer: attachment.transfer_id });
  toast(l10n("attachment_opened", name));
}

function attachmentWarningText(warning) {
  switch (warning) {
    case "media_type_mismatch": return l10n("attachment_warning_mismatch");
    case "dangerous_type": return l10n("attachment_warning_dangerous");
    case "unrecognized_type": return l10n("attachment_warning_unrecognized");
    case "missing_filename": return l10n("attachment_warning_missing_name");
    default: return l10n("attachment_warning_unknown");
  }
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
  title.textContent = attachment.view_once
    ? l10n(
      "attachment_view_once_named",
      primary?.filename ?? l10n("attachment_default_name"),
    )
    : isAudio
      ? l10n("attachment_audio_message")
      : (primary?.filename ?? l10n("attachment_default_name"));
  const transferState = document.createElement("span");
  transferState.className = `attachment-state ${attachment.state}`;
  transferState.textContent = l10n(
    "attachment_direction_state",
    attachmentDirection(attachment.direction),
    attachmentState(attachment.state),
  );
  head.append(title, transferState);
  row.append(head);

  const safety = document.createElement("div");
  safety.className = "attachment-safety";
  const noScan = document.createElement("p");
  noScan.textContent = attachment.view_once
    ? attachment.expires_at
      ? l10n("attachment_view_once_expiry_safety", fmtExpiry(attachment.expires_at))
      : l10n("attachment_view_once_safety")
    : l10n("attachment_safety_notice");
  safety.append(noScan);
  for (const warning of primary?.presentation?.warnings ?? []) {
    const message = document.createElement("p");
    message.className = "attachment-warning";
    message.textContent = attachmentWarningText(warning);
    safety.append(message);
  }
  row.append(safety);

  const preview = attachment.objects.find((object) => object.preview && object.state === "complete");
  if (preview && !attachment.view_once) {
    const image = document.createElement("img");
    image.className = "attachment-preview";
    image.alt = l10n(
      "attachment_preview_named",
      primary?.filename ?? l10n("attachment_default_name"),
    );
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
  if (!attachment.view_once && !preview && primary?.media_type === "image/png" && attachment.state === "complete") {
    const image = document.createElement("img");
    image.className = "attachment-preview";
    image.alt = l10n(
      "attachment_protected_image",
      attachment.direction === "inbound"
        ? l10n("attachment_sender")
        : l10n("group_you"),
    );
    row.append(image);
    invoke("attachment_image", { transfer: attachment.transfer_id })
      .then((source) => { image.src = source; })
      .catch(() => image.remove());
  }

  if (!attachment.view_once && isAudio && attachment.state === "complete") {
    const audioCard = document.createElement("div");
    audioCard.className = "audio-card";
    audioCard.setAttribute("aria-busy", "true");
    audioCard.textContent = l10n("attachment_preparing_audio");
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
          l10n(
            "attachment_audio_from",
            attachment.direction === "inbound"
              ? l10n("attachment_sender")
              : l10n("group_you"),
          ),
        );
      })
      .catch((error) => {
        if (!audioCard.isConnected) return;
        audioCard.setAttribute("aria-busy", "false");
        audioCard.textContent = l10n("attachment_audio_unavailable");
      });
  }

  for (const object of attachment.objects) {
    const objectRow = document.createElement("div");
    objectRow.className = "attachment-object";
    const objectHead = document.createElement("div");
    objectHead.className = "attachment-object-head";
    const description = document.createElement("span");
    const objectKind = object.preview
      ? l10n("attachment_preview")
      : l10n("attachment_primary");
    description.textContent = l10n("attachment_object_kind", objectKind, object.media_type);
    const progressText = document.createElement("span");
    progressText.textContent = l10n(
      "attachment_progress",
      Number(object.verified_bytes),
      Number(object.total_bytes),
      attachmentState(object.state),
    );
    objectHead.append(description, progressText);
    const progress = document.createElement("progress");
    progress.max = Math.max(1, Number(object.total_bytes));
    progress.value = Math.min(Number(object.verified_bytes), progress.max);
    progress.setAttribute(
      "aria-label",
      l10n("attachment_progress_named", objectKind),
    );
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
      attachmentButton(l10n("attachment_accept"), "primary", () => runAttachmentAction("accept_attachment", attachment.transfer_id)),
      attachmentButton(l10n("attachment_reject"), "danger", () => runAttachmentAction("reject_attachment", attachment.transfer_id))
    );
  } else {
    if (attachment.state === "paused") {
      actions.append(attachmentButton(l10n("attachment_resume"), "ghost", () => runAttachmentAction("resume_attachment", attachment.transfer_id)));
    } else if (["offered", "queued", "transferring"].includes(attachment.state)) {
      actions.append(attachmentButton(l10n("attachment_pause"), "ghost", () => runAttachmentAction("pause_attachment", attachment.transfer_id)));
    }
    if (active) {
      actions.append(attachmentButton(l10n("attachment_cancel"), "danger", () => runAttachmentAction("cancel_attachment", attachment.transfer_id)));
    }
  }
  if (inbound && attachment.state === "complete") {
    if (attachment.view_once) {
      actions.append(attachmentButton(l10n("attachment_reveal_once"), "primary", () => consumeViewOnceAttachment(attachment)));
    } else if (primary?.presentation?.open_policy === "external_open") {
      actions.append(attachmentButton(l10n("attachment_open"), "ghost", () => openAttachment(attachment)));
    }
    if (!attachment.view_once) actions.append(attachmentButton(l10n("attachment_export"), "primary", () => exportAttachment(attachment)));
  }
  if (actions.childElementCount > 0) row.append(actions);
  return row;
}

// Collapsed by default: completed transfer records stay reachable (export
// lives there) without the panel permanently occupying the conversation. A
// transfer needing attention re-opens it; otherwise the user's choice stands.
let attachmentsPanelExpanded = false;

function renderAttachments(attachments) {
  const panel = $("#attachment-transfers");
  panel.textContent = "";
  const matching = attachments.filter(attachmentBelongsHere);
  panel.hidden = matching.length === 0;
  if (matching.length === 0) return;
  const anyActive = matching.some((attachment) =>
    ["offered", "awaiting_consent", "queued", "transferring", "paused"].includes(attachment.state));
  if (anyActive) attachmentsPanelExpanded = true;
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "ghost attachment-panel-toggle";
  toggle.textContent = l10n(
    "attachment_transfers_toggle",
    attachmentsPanelExpanded ? "▾" : "▸",
    matching.length,
  );
  toggle.setAttribute("aria-expanded", String(attachmentsPanelExpanded));
  toggle.addEventListener("click", () => {
    attachmentsPanelExpanded = !attachmentsPanelExpanded;
    renderAttachments(attachments);
  });
  panel.append(toggle);
  if (!attachmentsPanelExpanded) return;
  const policy = document.createElement("p");
  policy.className = "attachment-background-policy";
  policy.textContent = l10n("attachment_background_policy");
  panel.append(policy);
  for (const attachment of matching) panel.append(attachmentRow(attachment));
}

function renderPolls(polls, authority) {
  const panel = $("#group-polls");
  panel.replaceChildren();
  panel.hidden = state.currentKind !== "group" || polls.length === 0;
  for (const poll of polls) {
    const card = document.createElement("article");
    card.className = "poll-card";
    card.setAttribute("aria-label", l10n("poll_accessibility", poll.question));
    const question = document.createElement("h3");
    question.textContent = poll.question;
    const policy = document.createElement("p");
    policy.className = "poll-policy";
    policy.textContent = poll.closed
      ? (poll.moderated_by
        ? l10n("poll_moderated_policy", memberLabel(poll.moderated_by))
        : l10n("poll_closed_policy"))
      : l10n("poll_open_policy");
    const choices = document.createElement("div");
    choices.className = "poll-options";
    choices.setAttribute("role", "group");
    choices.setAttribute("aria-label", poll.question);
    for (const option of poll.options) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "poll-option";
      button.disabled = poll.closed || !poll.eligible;
      button.setAttribute("aria-pressed", option.selected_by_me ? "true" : "false");
      button.setAttribute(
        "aria-label",
        l10nPlural(
          option.selected_by_me ? "poll_option_selected" : "poll_option",
          option.votes,
          option.text,
          option.votes,
        ),
      );
      const label = document.createElement("span");
      label.textContent = option.text;
      const count = document.createElement("strong");
      count.textContent = String(option.votes);
      button.append(label, count);
      button.addEventListener("click", async () => {
        try {
          await call("vote_group_poll", {
            group: poll.group,
            pollAuthor: poll.author,
            pollId: poll.id,
            optionId: option.id,
          });
          await renderMessages();
          toast(l10n("poll_voted"));
        } catch (error) { toast(String(error), true); }
      });
      choices.append(button);
    }
    const voters = document.createElement("p");
    voters.className = "poll-voters";
    voters.textContent = poll.votes.length === 0
      ? l10n("poll_no_votes")
      : l10n(
        "poll_visible_votes",
        poll.votes.map((vote) => {
          const choice = poll.options.find((option) => option.id === vote.option_id)?.text
            ?? l10n("poll_unavailable_choice");
          return `${memberLabel(vote.voter)} → ${choice}`;
        }).join(", "),
      );
    card.append(question, policy, choices, voters);
    if (poll.can_close) {
      const close = document.createElement("button");
      close.type = "button";
      close.className = "ghost";
      close.textContent = l10n("poll_close_action");
      close.addEventListener("click", async () => {
        if (!confirm(l10n("poll_close_confirm", poll.question))) return;
        try {
          await call("close_group_poll", {
            group: poll.group,
            pollAuthor: poll.author,
            pollId: poll.id,
          });
          await renderMessages();
          toast(l10n("poll_closed"));
        } catch (error) { toast(String(error), true); }
      });
      card.append(close);
    }
    if (!poll.closed && ["owner", "admin"].includes(authority?.my_role)) {
      const moderate = document.createElement("button");
      moderate.type = "button";
      moderate.className = "ghost";
      moderate.textContent = authority.my_role === "owner"
        ? l10n("poll_moderate_action")
        : l10n("poll_moderate_request_action");
      moderate.addEventListener("click", async () => {
        if (!confirm(l10n("poll_moderate_confirm", poll.question))) return;
        try {
          await call("moderate_group_poll_close", {
            group: poll.group,
            pollAuthor: poll.author,
            pollId: poll.id,
          });
          await renderMessages();
          toast(l10n("poll_moderate_sent"));
        } catch (error) { toast(String(error), true); }
      });
      card.append(moderate);
    }
    panel.append(card);
  }
}

async function renderMessages() {
  const renderGeneration = ++state.messageRenderGeneration;
  const isNote = state.currentKind === "note";
  const isGroup = state.currentKind === "group";
  const [msgs, scheduled, attachments, polls, authority, groupSecurity] = await Promise.all([
    isNote
      ? call("note_to_self_messages")
      : isGroup
      ? call("group_messages", { group: state.currentId })
      : call("messages", { peer: state.currentId }),
    isNote ? Promise.resolve([]) : call("scheduled_messages"),
    isNote ? Promise.resolve([]) : call("attachments"),
    isGroup ? call("group_polls", { group: state.currentId }) : Promise.resolve([]),
    isGroup ? call("group_authority", { group: state.currentId }) : Promise.resolve(null),
    isGroup ? invoke("group_security", { group: state.currentId }) : Promise.resolve(null),
  ]);
  if (renderGeneration !== state.messageRenderGeneration) return;
  const visibleMessages = msgs.filter((message) => !["attachment", "view_once_attachment"].includes(message.content_kind));
  const visibleScheduled = scheduled
    .filter((item) => item.destination === state.currentId
      && item.conversation === (isGroup ? "group" : "peer"))
    .sort((a, b) => a.not_before - b.not_before);
  const [formattedMessages, formattedScheduled] = await Promise.all([
    Promise.all(visibleMessages.map((message) => call("format_text", {
      source: message.body,
      highlights: formattingHighlights(message),
    }))),
    Promise.all(visibleScheduled.map((message) => call("format_text", {
      source: message.body,
      highlights: [],
    }))),
  ]);
  if (renderGeneration !== state.messageRenderGeneration) return;

  state.currentAuthority = authority;
  renderGroupSecurity(groupSecurity);
  const box = $("#messages");
  box.textContent = "";
  state.msgEls.clear();
  let visibleDay = "";
  for (let index = 0; index < visibleMessages.length; index += 1) {
    const m = visibleMessages[index];
    const formatted = formattedMessages[index];
    const day = messageDayKey(m.timestamp);
    if (day !== visibleDay) {
      box.append(messageDaySeparator(m.timestamp));
      visibleDay = day;
    }
    box.append(isNote ? noteBubble(m, formatted) : isGroup ? groupBubble(m, formatted) : bubble(m, formatted));
  }
  for (let index = 0; index < visibleScheduled.length; index += 1) {
    box.append(scheduledBubble(visibleScheduled[index], formattedScheduled[index]));
  }
  renderAttachments(attachments);
  renderPolls(polls, authority);
  box.scrollTop = box.scrollHeight;
}

function renderGroupSecurity(security) {
  const panel = $("#group-security");
  const upgrade = $("#btn-group-security-upgrade");
  const composer = $("#composer-input");
  if (!security || state.currentKind !== "group") {
    panel.hidden = true;
    composer.disabled = false;
    $("#btn-mention").disabled = false;
    $("#btn-poll").disabled = false;
    $("#btn-attach").disabled = false;
    $("#btn-schedule").disabled = false;
    return;
  }
  const blocked = security.level !== "recipient_authenticated";
  composer.disabled = blocked;
  $("#btn-mention").disabled = blocked;
  $("#btn-poll").disabled = blocked;
  $("#btn-attach").disabled = blocked;
  $("#btn-schedule").disabled = blocked;
  if (security.level === "upgrade_required") {
    panel.hidden = false;
    $("#group-security-title").textContent = `${l10n("group_origin_upgrade_required")}. `;
    $("#group-security-detail").textContent = l10n("group_security_upgrade_required");
    upgrade.hidden = false;
  } else if (security.level === "upgrading") {
    panel.hidden = false;
    $("#group-security-title").textContent = `${l10n("group_origin_upgrade_in_progress")}. `;
    $("#group-security-detail").textContent = l10n(
      "group_security_upgrading",
      security.pending_devices.length,
    );
    upgrade.hidden = true;
  } else if (security.legacy_history_rows > 0) {
    panel.hidden = false;
    $("#group-security-title").textContent = `${l10n("group_origin_authenticated")}. `;
    $("#group-security-detail").textContent = l10n(
      "group_security_authenticated_with_legacy",
      security.legacy_history_rows,
    );
    upgrade.hidden = true;
  } else {
    panel.hidden = true;
    upgrade.hidden = true;
  }
}

$("#btn-group-security-upgrade").addEventListener("click", async () => {
  if (state.currentKind !== "group" || !state.currentId) return;
  try {
    await invoke("upgrade_group_security", { group: state.currentId });
    await renderMessages();
    await refreshGroups();
  } catch (error) {
    toast(String(error), true);
  }
});

$("#composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#composer-input");
  const visibleText = input.value;
  if (!visibleText.trim() || !state.currentId) return;
  const lifetimeSecs = Number($("#composer-expiry").value);
  if (lifetimeSecs > 0) {
    if (state.currentKind === "group") {
      await call("send_group_disappearing", { group: state.currentId, body: visibleText.trim(), lifetimeSecs });
    } else if (state.currentKind === "contact") {
      await call("send_disappearing", { peer: state.currentId, body: visibleText.trim(), lifetimeSecs });
    } else {
      await call("send_note_to_self", { body: visibleText.trim() });
    }
  } else if (state.currentKind === "group" && state.mentionDraft.spans.length > 0) {
    if (hasUnpairedSurrogate(visibleText)) {
      toast(l10n("mention_invalid_unicode"), true);
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
      $("#mention-status").textContent = l10n("mention_review_again");
      $("#composer-input").focus();
      return;
    }
    if (!fresh.supported) {
      const blockers = fresh.issues.map((issue) => `${memberLabel(issue.peer)} (${issue.reason})`).join(", ");
      const plain = window.confirm(
        `${l10n("mention_unavailable", blockers)}\n\n${l10n("mention_plain_message")}`,
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
  resetMentionDraft(
    state.currentKind === "group" ? l10n("mention_member_description") : "",
  );
  await renderMessages();
});

$("#composer-expiry").addEventListener("change", (event) => {
  const active = event.currentTarget.value !== "0";
  $("#expiry-honesty").hidden = !active || state.currentKind === "note";
  if (active && state.mentionDraft.spans.length > 0) {
    state.mentionDraft.spans = [];
    renderMentionTokens();
    $("#mention-status").textContent = l10n("mention_disappearing_removed");
  }
});

function openScheduleModal(message = null) {
  if (!state.currentId || state.currentKind === "note") return;
  const editing = message !== null;
  const root = openModal(
    l10n(editing ? "scheduled_dialog_edit" : "scheduled_dialog_new"),
    "tpl-schedule",
  );
  const body = root.querySelector('[data-f="body"]');
  const notBefore = root.querySelector('[data-f="not-before"]');
  body.value = message?.body ?? $("#composer-input").value.trim();
  const earliest = Math.floor(Date.now() / 1000) + 60;
  notBefore.min = dateTimeLocalValue(Math.min(message?.not_before ?? earliest, earliest));
  notBefore.value = dateTimeLocalValue(message?.not_before ?? earliest + 29 * 60);
  root.querySelector('[data-act="save"]').textContent = l10n(
    editing ? "save_changes" : "scheduled_dialog_new",
  );
  root.addEventListener("click", async (event) => {
    if (!event.target.matches('[data-act="save"]')) return;
    const text = body.value.trim();
    const instant = Math.floor(new Date(notBefore.value).getTime() / 1000);
    try {
      if (!text) throw l10n("scheduled_need_body");
      if (!Number.isFinite(instant)) throw l10n("scheduled_need_future");
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
  root.querySelector('[data-f="image-info"]').textContent = l10n(
    "attachment_image_summary",
    Number(draft.review.width),
    Number(draft.review.height),
    Number(draft.review.encoded_bytes),
  );
  const regions = root.querySelector('[data-f="regions"]');
  regions.replaceChildren();
  draft.recipe.regions.forEach((region, index) => {
    const item = document.createElement("li");
    const kind = l10n(
      region.kind === "blur" ? "privacy_region_blur" : "privacy_region_pixelate",
    );
    item.textContent = `${l10n(
      "attachment_privacy_region_summary",
      kind,
      Number(region.x),
      Number(region.y),
      Number(region.width),
      Number(region.height),
      Number(region.strength),
    )} `;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost";
    remove.dataset.removeRegion = index;
    remove.textContent = l10n("remove_action");
    remove.setAttribute(
      "aria-label",
      l10n("attachment_remove_privacy_region", kind),
    );
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
  const root = openModal(l10n("attachment_review_image_title"), "tpl-image-edit");
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
  const viewOnce = root.querySelector('[data-f="view-once"]');
  const lifetime = root.querySelector('[data-f="lifetime"]');
  const lifetimeRow = root.querySelector('[data-f="view-once-lifetime"]');
  const viewOnceWarning = root.querySelector('[data-f="view-once-warning"]');
  viewOnce.addEventListener("change", () => {
    lifetimeRow.hidden = !viewOnce.checked;
    viewOnceWarning.hidden = !viewOnce.checked;
  });
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
          viewOnce: viewOnce.checked,
          lifetimeSecs: Number(lifetime.value),
        });
        state.imageDraft = null;
        closeModal();
        await renderMessages();
      } catch (error) {
        const changed = carrierChangedText(error);
        if (changed !== null) {
          carrierText.textContent = changed;
          carrierText.dataset.snapshot = changed;
          showError(root, l10n("attachment_carrier_changed_confirm"));
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
  const root = openModal(l10n("attachment_review_title"), "tpl-attachment-send");
  root.querySelector('[data-f="selected-name"]').textContent = selectedName;
  root.querySelector('[data-f="filename"]').value = selectedName;
  root.querySelector('[data-f="media-type"]').value = guessedMime(selectedName);
  const carrierText = root.querySelector('[data-f="carrier"]');
  const viewOnce = root.querySelector('[data-f="view-once"]');
  const lifetime = root.querySelector('[data-f="lifetime"]');
  const lifetimeRow = root.querySelector('[data-f="view-once-lifetime"]');
  const viewOnceWarning = root.querySelector('[data-f="view-once-warning"]');
  viewOnce.addEventListener("change", () => {
    lifetimeRow.hidden = !viewOnce.checked;
    viewOnceWarning.hidden = !viewOnce.checked;
  });
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
      if (!mediaType) throw l10n("attachment_mime_required");
      button.disabled = true;
      const latest = await freshAttachmentCarrier(conversation, destination);
      if (latest !== carrierText.dataset.snapshot) {
        carrierText.textContent = latest;
        carrierText.dataset.snapshot = latest;
        button.disabled = false;
        showError(root, l10n("attachment_carrier_changed_confirm"));
        return;
      }
      try {
        if (viewOnce.checked) {
          const command = conversation === "group" ? "send_group_view_once_attachment" : "send_view_once_attachment";
          const destinationArgs = conversation === "group" ? { group: destination } : { peer: destination };
          await invoke(command, {
            ...destinationArgs,
            path,
            mediaType,
            filename: filename || null,
            lifetimeSecs: Number(lifetime.value),
          });
        } else {
          await invoke("send_confirmed_attachment", {
            conversation,
            destination,
            path,
            mediaType,
            filename: filename || null,
            expectedCarrier: latest,
          });
        }
      } catch (error) {
        const changed = carrierChangedText(error);
        if (changed === null) throw error;
        carrierText.textContent = changed;
        carrierText.dataset.snapshot = changed;
        button.disabled = false;
        showError(root, l10n("attachment_carrier_changed_confirm"));
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
    title: l10n(
      state.currentKind === "group"
        ? "attachment_choose_group"
        : "attachment_choose",
    ),
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
      toast(localizedError(error), true);
      return;
    }
    await openGenericAttachment(path, selectedName);
  }
});

// ── node events ─────────────────────────────────────────────────────────

async function resynchronizePresentation() {
  await refreshStatus();
  await refreshContacts();
  await refreshGroups();
  await refreshRequestInboxBadge();
  await refreshFolders();
  await refreshLabels();
  await refreshVisibleCustomIcons(true);
  const theme = await invoke("theme");
  applyTheme(theme.preference);
  if (state.currentKind) await renderMessages();
  if (
    !$("#modal-backdrop").hidden
    && $("#modal-title").textContent === l10n("settings_devices_title")
  ) {
    await renderLinkedDevices($("#modal-body"));
  }
}

document.addEventListener("kommslocalechange", () => {
  $("#gate-locale").value = KommsLocalization.localePreference();
  const modalLocale = $('#modal-body [data-f="locale"]');
  if (modalLocale) {
    modalLocale.value = KommsLocalization.localePreference();
    $("#modal-title").textContent = l10n("appearance_title");
  }
  const refresh = $("#app").hidden
    ? probeGate($("#gate-dir").value)
    : resynchronizePresentation();
  refresh.catch((error) => toast(localizedError(error), true));
});

listen("node-event", async ({ payload: ev }) => {
  switch (ev.type) {
    case "state_resync_required": {
      await resynchronizePresentation();
      break;
    }
    case "devices_changed": {
      if (
        !$("#modal-backdrop").hidden
        && $("#modal-title").textContent === l10n("settings_devices_title")
      ) {
        await renderLinkedDevices($("#modal-body"));
      }
      break;
    }
    case "device_authority_fork":
    case "device_recovery_conflict": {
      toast(
        ev.type === "device_recovery_conflict"
          ? l10n("device_recovery_conflict_event")
          : l10n("device_authority_fork_event"),
        true
      );
      if (
        !$("#modal-backdrop").hidden
        && $("#modal-title").textContent === l10n("settings_devices_title")
      ) {
        await renderLinkedDevices($("#modal-body"));
      }
      break;
    }
    case "device_link_completed": {
      await refreshStatus();
      break;
    }
    case "rendezvous_conflict": {
      toast(l10n("rendezvous_conflict"), true);
      break;
    }
    case "wake_conflict": {
      toast(l10n("wake_conflict"), true);
      break;
    }
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
    case "call_updated": {
      await handleCallUpdate(ev.call);
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
          st.textContent = ` · ${deliveryState(ev.state)}`;
          st.className = "state"
            + (ev.state === "delivered" ? " state-delivered" : "")
            + (ev.state === "failed" ? " state-failed" : "");
        }
      }
      break;
    }
    case "message_received": {
      if (["attachment", "view_once_attachment"].includes(ev.content_kind)) {
        if (state.currentKind === "contact" && ev.peer === state.currentId) await renderMessages();
        break;
      }
      if (state.currentKind === "contact" && ev.peer === state.currentId) {
        await renderMessages();
      } else {
        state.unread.set(ev.peer, (state.unread.get(ev.peer) ?? 0) + 1);
        toast(l10n("message_received_preview", contactName(ev.peer), ev.body.slice(0, 80)));
        refreshContacts();
      }
      break;
    }
    case "message_edited": {
      if (state.currentKind === "contact" && ev.peer === state.currentId) await renderMessages();
      break;
    }
    case "message_request_received": {
      await refreshRequestInboxBadge();
      toast(l10n("message_request_received"));
      break;
    }
    case "message_request_accepted":
    case "message_request_deleted":
    case "message_request_blocked":
    case "message_request_expired": {
      await refreshRequestInboxBadge();
      if (ev.type === "message_request_accepted") await refreshContacts();
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
        toast(l10n(
          "attachment_offered",
          primary?.filename ?? l10n("attachment_default_name"),
        ));
      }
      break;
    }
    case "group_updated": {
      await refreshGroups();
      if (state.currentKind === "group" && ev.group === state.currentId) {
        if (currentGroup()) {
          updateChatHead();
          await refreshMentionReview(l10n("mention_group_changed"));
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
    case "group_invitation_received": {
      await refreshRequestInboxBadge();
      toast(l10n("group_invitation_received"));
      break;
    }
    case "group_invitation_accepted":
    case "group_invitation_deleted":
    case "group_invitation_expired": {
      await refreshRequestInboxBadge();
      if (ev.type === "group_invitation_accepted") await refreshGroups();
      break;
    }
    case "mention_received": {
      toast(l10n("mention_notification_private"));
      break;
    }
    case "group_message_received": {
      if (["attachment", "view_once_attachment"].includes(ev.content_kind)) {
        if (state.currentKind === "group" && ev.group === state.currentId) await renderMessages();
        break;
      }
      if (state.currentKind === "group" && ev.group === state.currentId) {
        await renderMessages();
      } else {
        state.groupUnread.set(ev.group, (state.groupUnread.get(ev.group) ?? 0) + 1);
        const group = state.groups.find((item) => item.id === ev.group);
        toast(l10n(
          "group_message_received_preview",
          group?.name ?? l10n("group_default_name"),
          memberName(ev.sender),
          ev.body.slice(0, 80),
        ));
        await refreshGroups();
      }
      break;
    }
    case "group_message_edited": {
      if (state.currentKind === "group" && ev.group === state.currentId) await renderMessages();
      break;
    }
    case "poll_updated": {
      if (state.currentKind === "group" && ev.group === state.currentId) {
        await renderMessages();
      } else {
        const group = state.groups.find((item) => item.id === ev.group);
        toast(l10n(
          "poll_updated",
          group?.name ?? l10n("group_default_name"),
        ));
      }
      break;
    }
    case "group_authority_updated": {
      await refreshGroups();
      if (state.currentKind === "group" && ev.group === state.currentId) {
        updateChatHead();
        await renderMessages();
      }
      break;
    }
    case "group_admin_request_resolved": {
      if (state.currentKind === "group" && ev.group === state.currentId) await renderMessages();
      toast(
        ev.accepted
          ? l10n("group_admin_request_accepted")
          : l10n("group_admin_request_rejected", ev.reason),
        !ev.accepted,
      );
      break;
    }
    case "ephemeral_removed": {
      const matches = (ev.conversation_kind === "pairwise" && state.currentKind === "contact" && ev.conversation_id === state.currentId)
        || (ev.conversation_kind === "group" && state.currentKind === "group" && ev.conversation_id === state.currentId);
      if (matches) await renderMessages();
      toast(l10n(
        ev.reason === "consumed"
          ? "ephemeral_consumed"
          : "ephemeral_expired",
      ));
      break;
    }
    case "group_delivery_updated": {
      const el = state.msgEls.get(ev.id);
      const delivery = el?.querySelector(`.delivery[data-peer="${ev.peer}"]`);
      if (delivery) {
        delivery.textContent = l10n(
          "group_delivery_row",
          memberName(ev.peer),
          deliveryState(ev.state),
        );
        delivery.className = "delivery"
          + (ev.state === "delivered" ? " state-delivered" : "")
          + (ev.state === "failed" ? " state-failed" : "");
      }
      break;
    }
    case "contact_added":
      toast(l10n("contact_added_unverified"));
      await refreshContacts();
      break;
    case "contact_renamed":
      await refreshContacts();
      await refreshGroups();
      break;
    case "session_established": {
      const known = state.contacts.some((c) => c.peer === ev.peer);
      toast(
        known
          ? l10n("session_renewed", contactName(ev.peer))
          : l10n("session_established"),
      );
      if (currentGroup()?.members.includes(ev.peer)) {
        await refreshMentionReview(l10n("mention_session_changed"));
      }
      await refreshContacts();
      break;
    }
    case "awaiting_faster_link": {
      const el = state.msgEls.get(ev.id);
      const st = el?.querySelector(".state");
      if (st) {
        st.textContent = ` · ${l10n("state_held")}`;
        st.className = "state state-held";
      }
      break;
    }
  }
});

// ── modals ──────────────────────────────────────────────────────────────

let modalReturnFocus = null;
let recoveryOnboardingPending = false;

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
  KommsLocalization.localizeRoot(body, true);
  applyIncognitoInputPrivacy(body);
  $("#modal-backdrop").hidden = false;
  requestAnimationFrame(() => (modalFocusable()[0] ?? $("#modal-close")).focus());
  return body;
}

function closeModal() {
  if (recoveryOnboardingPending) return;
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
    el.textContent = localizedError(err);
    el.hidden = false;
  }
}

async function refreshRequestInboxBadge() {
  const [messageRequests, groupInvitations] = await Promise.all([
    call("message_requests"),
    call("group_invitations"),
  ]);
  state.messageRequests = messageRequests;
  state.groupInvitations = groupInvitations;
  const count = messageRequests.length + groupInvitations.length;
  const badge = $("#request-count");
  badge.hidden = count === 0;
  badge.textContent = String(count);
  $("#request-summary").textContent = count === 0
    ? l10n("message_requests_empty")
    : l10nPlural("request_summary_pending", count, count);
  $("#btn-message-requests").setAttribute(
    "aria-label",
    count === 0
      ? l10n("message_requests_none_accessibility")
      : l10nPlural("message_requests_pending_accessibility", count, count),
  );
  return count;
}

let requestCardSequence = 0;

function requestCard(title, detail) {
  const card = document.createElement("article");
  card.className = "request-card";
  card.setAttribute("role", "listitem");
  const heading = document.createElement("h3");
  heading.id = `request-heading-${++requestCardSequence}`;
  heading.textContent = title;
  card.setAttribute("aria-labelledby", heading.id);
  const description = document.createElement("p");
  description.className = "modal-note";
  description.textContent = detail;
  card.append(heading, description);
  return card;
}

function focusFirstRequestControl(root) {
  requestAnimationFrame(() => {
    root.querySelector(".request-card input, .request-card button")?.focus();
  });
}

async function renderMessageRequests(root, announcement = "") {
  await refreshRequestInboxBadge();
  const direct = root.querySelector('[data-f="direct-requests"]');
  const groups = root.querySelector('[data-f="group-requests"]');
  const status = root.querySelector('[data-f="request-status"]');
  direct.replaceChildren();
  groups.replaceChildren();
  status.textContent = announcement;

  for (const request of state.messageRequests) {
    const card = requestCard(
      l10n("message_request_from_new"),
      l10n("message_request_expires", fmtExpiry(request.expires_at)),
    );
    const preview = document.createElement("blockquote");
    preview.className = "request-preview";
    preview.dir = "auto";
    preview.textContent = request.preview || l10n("message_request_no_preview");
    const safety = document.createElement("p");
    safety.className = "request-safety";
    safety.textContent = l10n("message_request_safety", request.safety_number);
    const name = document.createElement("input");
    name.type = "text";
    name.value = l10n("message_request_default_name");
    name.maxLength = 256;
    name.dataset.incognitoInput = "name";
    name.setAttribute("aria-label", l10n("message_request_name_hint"));
    const actions = document.createElement("div");
    actions.className = "row request-actions";
    const accept = document.createElement("button");
    accept.type = "button";
    accept.className = "primary";
    accept.textContent = l10n("message_request_accept");
    accept.setAttribute("aria-label", l10n("message_request_accept"));
    const discard = document.createElement("button");
    discard.type = "button";
    discard.className = "ghost";
    discard.textContent = l10n("message_request_delete");
    discard.setAttribute("aria-label", l10n("message_request_delete"));
    const block = document.createElement("button");
    block.type = "button";
    block.className = "danger";
    block.textContent = l10n("message_request_block");
    block.setAttribute("aria-label", l10n("message_request_block"));
    actions.append(accept, discard, block);
    card.append(preview, safety, name, actions);
    direct.append(card);
    const act = async (operation) => {
      if (
        operation === "block"
        && !confirm(
          `${l10n("message_request_block_title")}\n\n${
            l10n("message_request_block_explanation")
          }`,
        )
      ) return;
      actions.querySelectorAll("button").forEach((button) => { button.disabled = true; });
      try {
        if (operation === "accept") {
          const localName = name.value.trim();
          if (!localName) throw new Error(l10n("message_request_name_required"));
          const peer = await call("accept_message_request", {
            request: request.id,
            name: localName,
          });
          await refreshContacts();
          await renderMessageRequests(root);
          closeModal();
          await openChat(peer);
        } else if (operation === "delete") {
          await call("delete_message_request", { request: request.id });
          await renderMessageRequests(root, l10n("request_deleted_status"));
          focusFirstRequestControl(root);
        } else {
          await call("block_message_request", { request: request.id });
          await renderMessageRequests(root, l10n("request_blocked_status"));
          focusFirstRequestControl(root);
        }
      } catch (error) {
        status.textContent = l10n("request_change_failed");
        actions.querySelectorAll("button").forEach((button) => { button.disabled = false; });
      }
    };
    accept.addEventListener("click", () => act("accept"));
    discard.addEventListener("click", () => act("delete"));
    block.addEventListener("click", () => act("block"));
  }

  for (const invitation of state.groupInvitations) {
    const card = requestCard(
      l10n("group_invitation_title"),
      l10nPlural(
        "group_invitation_members_expiry",
        invitation.member_count,
        invitation.member_count,
        fmtExpiry(invitation.expires_at),
      ),
    );
    const name = document.createElement("p");
    name.className = "request-group-name";
    name.dir = "auto";
    name.textContent = invitation.name || l10n("group_default_name");
    const note = document.createElement("p");
    note.className = "modal-note";
    note.textContent = l10n("group_invitation_explanation");
    const actions = document.createElement("div");
    actions.className = "row request-actions";
    const accept = document.createElement("button");
    accept.type = "button";
    accept.className = "primary";
    accept.textContent = l10n("group_invitation_accept");
    accept.setAttribute("aria-label", l10n("group_invitation_accept"));
    const discard = document.createElement("button");
    discard.type = "button";
    discard.className = "ghost";
    discard.textContent = l10n("message_request_delete");
    discard.setAttribute("aria-label", l10n("group_invitation_delete"));
    actions.append(accept, discard);
    card.append(name, note, actions);
    groups.append(card);
    accept.addEventListener("click", async () => {
      actions.querySelectorAll("button").forEach((button) => { button.disabled = true; });
      try {
        const group = await call("accept_group_invitation", { invitation: invitation.id });
        await refreshGroups();
        await renderMessageRequests(root);
        closeModal();
        await openGroup(group);
      } catch (error) {
        status.textContent = l10n("group_invitation_accept_failed");
        actions.querySelectorAll("button").forEach((button) => { button.disabled = false; });
      }
    });
    discard.addEventListener("click", async () => {
      actions.querySelectorAll("button").forEach((button) => { button.disabled = true; });
      try {
        await call("delete_group_invitation", { invitation: invitation.id });
        await renderMessageRequests(root, l10n("group_invitation_deleted_status"));
        focusFirstRequestControl(root);
      } catch (error) {
        status.textContent = l10n("group_invitation_delete_failed");
        actions.querySelectorAll("button").forEach((button) => { button.disabled = false; });
      }
    });
  }
  applyIncognitoInputPrivacy(root);
  root.querySelector('[data-f="request-empty"]').hidden =
    state.messageRequests.length + state.groupInvitations.length !== 0;
}

async function openMessageRequests() {
  const body = openModal(l10n("message_requests_title"), "tpl-message-requests");
  try {
    await renderMessageRequests(body);
  } catch (error) {
    body.querySelector('[data-f="request-status"]').textContent =
      l10n("message_requests_unavailable");
  }
}

$("#btn-message-requests").addEventListener("click", openMessageRequests);

function customIconChoices() {
  return [
    { target: { kind: "note_to_self", id: null }, label: l10n("note_to_self_title") },
    ...state.contacts.map((contact) => ({
      target: { kind: "contact", id: contact.peer },
      label: l10n(
        "icons_contact_target",
        contact.name || `${contact.peer.slice(0, 12)}…`,
      ),
    })),
    ...state.groups.map((group) => ({
      target: { kind: "group", id: group.id },
      label: l10n(
        "icons_group_target",
        group.name || l10n("group_default_name"),
      ),
    })),
    ...state.folders.map((folder) => ({
      target: { kind: "folder", id: folder.id },
      label: l10n("folder_accessible_summary", folder.name, folder.order + 1),
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
  const label = select.selectedOptions[0]?.textContent ?? l10n("icons_selected_target");
  const fallback = generatedInitials(label.replace(/^[^·]+·\s*/u, ""));
  const preview = root.querySelector('[data-f="preview"]');
  await applyCustomIcon(preview, target, fallback, label);
  const icon = await loadCustomIcon(target);
  root.querySelector('[data-f="preview-description"]').textContent = icon
    ? l10n("icons_private_summary", Number(icon.encoded_bytes))
    : l10n("icons_initials_fallback", fallback);
  root.querySelector('[data-act="clear-icon"]').disabled = !icon;
  const usage = await invoke("custom_icon_usage");
  root.querySelector('[data-f="usage"]').textContent = l10n(
    "icons_usage",
    Number(usage.records),
    Number(usage.bytes),
  );
}

async function openIconManager() {
  const root = openModal(l10n("icons_title"), "tpl-icon-manager");
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
    button.setAttribute("aria-label", l10n("icons_use_bundled", glyph));
    button.addEventListener("click", async () => {
      try {
        const target = selectedCustomIconChoice(root);
        const icon = await invoke("set_bundled_custom_icon", { target, glyph });
        state.icons.set(customIconKey(target), icon);
        root.querySelector('[data-f="result"]').textContent = l10n("icons_saved");
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
      title: l10n("icons_choose_image"),
      multiple: false,
      directory: false,
      filters: [{ name: "JPEG or PNG", extensions: ["jpg", "jpeg", "png"] }],
    });
    if (!path || typeof path !== "string") return;
    try {
      const target = selectedCustomIconChoice(root);
      const icon = await invoke("set_custom_icon_from_path", { target, path, crop: null });
      state.icons.set(customIconKey(target), icon);
      root.querySelector('[data-f="result"]').textContent = l10n("icons_saved");
      root.querySelector('[data-f="error"]').hidden = true;
      await Promise.all([refreshIconManager(root), refreshVisibleCustomIcons()]);
    } catch (error) { showError(root, error); }
  });
  root.querySelector('[data-act="clear-icon"]').addEventListener("click", async () => {
    try {
      const target = selectedCustomIconChoice(root);
      await invoke("clear_custom_icon", { target });
      state.icons.set(customIconKey(target), null);
      root.querySelector('[data-f="result"]').textContent = l10n("icons_cleared");
      root.querySelector('[data-f="error"]').hidden = true;
      await Promise.all([refreshIconManager(root), refreshVisibleCustomIcons()]);
    } catch (error) { showError(root, error); }
  });
  await refreshIconManager(root);
}

function resetFolderEditor(root) {
  root.querySelector('[data-f="folder-id"]').value = "";
  root.querySelector('[data-f="folder-name"]').value = "";
  root.querySelector('[data-act="save-folder"]').textContent = l10n("folder_create");
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
    empty.textContent = l10n("folders_empty");
    list.append(empty);
  }
  for (const [index, folder] of state.folders.entries()) {
    const row = document.createElement("div");
    row.className = "folder-manager-row";
    const avatar = document.createElement("span");
    avatar.className = "avatar icon-manager-row-avatar";
    const fallback = generatedInitials(folder.name);
    avatar.textContent = fallback;
    applyCustomIcon(
      avatar,
      { kind: "folder", id: folder.id },
      fallback,
      folderAccessibleName(folder),
    );
    const description = document.createElement("span");
    description.className = "folder-description";
    const name = document.createElement("bdi");
    name.dir = "auto";
    name.textContent = folder.name;
    description.append(
      name,
      document.createTextNode(` · ${l10n("folder_position", index + 1)}`),
    );
    const actions = document.createElement("span");
    actions.className = "folder-actions";
    for (const delta of [-1, 1]) {
      const reorder = document.createElement("button");
      reorder.type = "button";
      reorder.className = "ghost";
      reorder.textContent = delta < 0 ? "↑" : "↓";
      reorder.disabled = index + delta < 0 || index + delta >= state.folders.length;
      reorder.setAttribute(
        "aria-label",
        l10n(
          delta < 0 ? "folder_move_up" : "folder_move_down",
          folderAccessibleName(folder),
        ),
      );
      reorder.addEventListener("click", async () => {
        try {
          const ids = state.folders.map((item) => item.id);
          [ids[index], ids[index + delta]] = [ids[index + delta], ids[index]];
          await invoke("reorder_folders", { folders: ids });
          root.querySelector('[data-f="result"]').textContent = l10n(
            "folder_reordered",
            folder.name,
            index + delta + 1,
          );
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
    edit.textContent = l10n("folder_edit");
    edit.setAttribute(
      "aria-label",
      l10n("folder_edit_description", folderAccessibleName(folder)),
    );
    edit.addEventListener("click", () => {
      root.querySelector('[data-f="folder-id"]').value = folder.id;
      root.querySelector('[data-f="folder-name"]').value = folder.name;
      root.querySelector('[data-act="save-folder"]').textContent = l10n("folder_save");
      root.querySelector('[data-act="cancel-edit"]').hidden = false;
      root.querySelector('[data-f="folder-name"]').focus();
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = l10n("folder_delete");
    remove.setAttribute(
      "aria-label",
      l10n("folder_delete_description", folderAccessibleName(folder)),
    );
    remove.addEventListener("click", async () => {
      try {
        const count = await invoke("folder_delete_assignment_count", { folder: folder.id });
        const reviewed = window.confirm(
          l10n("folder_delete_review", folderAccessibleName(folder), count),
        );
        if (!reviewed) {
          root.querySelector('[data-f="result"]').textContent = l10n("folder_delete_cancelled");
          remove.focus();
          return;
        }
        const deleted = await invoke("delete_folder", { folder: folder.id, confirm: true });
        root.querySelector('[data-f="result"]').textContent = l10n(
          "folder_deleted",
          deleted,
        );
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
    const targetName = conversationKindName(record.target.kind);
    reason.textContent = l10n(
      "stale_assignment_summary",
      staleReasonName(record.reason),
      targetName,
    );
    const cleanup = document.createElement("button");
    cleanup.type = "button";
    cleanup.className = "danger";
    cleanup.textContent = l10n("cleanup_action");
    cleanup.setAttribute(
      "aria-label",
      l10n("folder_stale_cleanup_description", targetName),
    );
    cleanup.addEventListener("click", async () => {
      try {
        await invoke("cleanup_stale_folder", { folder: record.folder, target: record.target });
        root.querySelector('[data-f="result"]').textContent = l10n(
          "folder_stale_cleaned",
          targetName,
        );
        await renderFolderManager(root);
        await refreshFolders(true);
      } catch (error) { showError(root, error); }
    });
    row.append(reason, cleanup);
    staleList.append(row);
  }
}

async function openFolderManager() {
  const root = openModal(l10n("folders_title"), "tpl-folder-manager");
  const form = root.querySelector('[data-f="folder-form"]');
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = root.querySelector('[data-f="folder-name"]').value;
    const id = root.querySelector('[data-f="folder-id"]').value;
    try {
      if (!exactFolderNameValid(name)) throw new Error(l10n("folder_invalid_name"));
      const saved = id
        ? await invoke("rename_folder", { folder: id, name })
        : await invoke("create_folder", { name });
      root.querySelector('[data-f="result"]').textContent = l10n(
        id ? "folder_updated" : "folder_created",
        folderAccessibleName(saved),
      );
      resetFolderEditor(root);
      await renderFolderManager(root);
      await refreshFolders(true);
      root.querySelector('[data-f="folder-name"]').focus();
    } catch (error) { showError(root, error); }
  });
  root.querySelector('[data-act="cancel-edit"]').addEventListener("click", () => {
    resetFolderEditor(root);
    root.querySelector('[data-f="result"]').textContent = l10n("folder_edit_cancelled");
    root.querySelector('[data-f="folder-name"]').focus();
  });
  await renderFolderManager(root);
}

$("#btn-folder-manager").addEventListener("click", openFolderManager);

async function openConversationFolder() {
  const target = folderTarget();
  if (!target) return;
  const exactTarget = currentTargetName();
  const root = openModal(
    l10n("folder_assignment_title", exactTarget),
    "tpl-conversation-folder",
  );
  root.querySelector('[data-f="target-summary"]').textContent = l10n(
    "folder_assignment_explanation",
    exactTarget,
  );
  const current = await invoke("conversation_folder", { target });
  const list = root.querySelector('[data-f="folders"]');
  const choices = [
    { id: null, name: l10n("folder_unfiled"), order: -1 },
    ...state.folders,
  ];
  for (const folder of choices) {
    const row = document.createElement("label");
    row.className = "folder-assignment-option";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "conversation-folder";
    input.checked = folder.id === (current?.id ?? null);
    const cue = folder.id
      ? folderAccessibleName(folder)
      : l10n("folder_unfiled_accessibility");
    input.setAttribute(
      "aria-label",
      l10n("folder_move_target", exactTarget, cue),
    );
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
        root.querySelector('[data-f="result"]').textContent = l10n(
          "folder_assignment_result",
          exactTarget,
          finalFolder
            ? folderAccessibleName(finalFolder)
            : l10n("folder_unfiled"),
        );
        await refreshFolders(true);
      } catch (error) { showError(root, error); }
      finally { input.disabled = false; input.focus(); }
    });
    row.append(
      input,
      name,
      document.createTextNode(
        folder.id ? ` · ${l10n("folder_position", folder.order + 1)}` : "",
      ),
    );
    list.append(row);
  }
  root.querySelector('[data-act="done"]').addEventListener("click", closeModal);
}

$("#btn-conversation-folder").addEventListener("click", openConversationFolder);

function resetLabelEditor(root) {
  root.querySelector('[data-f="label-id"]').value = "";
  root.querySelector('[data-f="label-name"]').value = "";
  root.querySelector('[data-f="label-color"]').value = "neutral";
  root.querySelector('[data-act="save-label"]').textContent = l10n("label_create");
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
    empty.textContent = l10n("labels_empty");
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
    edit.textContent = l10n("label_edit");
    edit.setAttribute(
      "aria-label",
      l10n("label_edit_description", labelAccessibleName(label)),
    );
    edit.addEventListener("click", () => {
      root.querySelector('[data-f="label-id"]').value = label.id;
      root.querySelector('[data-f="label-name"]').value = label.name;
      root.querySelector('[data-f="label-color"]').value = label.color;
      root.querySelector('[data-act="save-label"]').textContent = l10n("label_save");
      root.querySelector('[data-act="cancel-edit"]').hidden = false;
      root.querySelector('[data-f="label-name"]').focus();
    });
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = l10n("label_delete");
    remove.setAttribute(
      "aria-label",
      l10n("label_delete_description", labelAccessibleName(label)),
    );
    remove.addEventListener("click", async () => {
      try {
        const count = await invoke("label_delete_assignment_count", { label: label.id });
        const reviewed = window.confirm(
          l10n("label_delete_review", labelAccessibleName(label), count),
        );
        if (!reviewed) {
          root.querySelector('[data-f="result"]').textContent = l10n("label_delete_cancelled");
          remove.focus();
          return;
        }
        const deleted = await invoke("delete_label", { label: label.id, confirm: true });
        root.querySelector('[data-f="result"]').textContent = l10n(
          "label_deleted",
          deleted,
        );
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
    const targetName = conversationKindName(record.target.kind);
    reason.textContent = l10n(
      "stale_assignment_summary",
      staleReasonName(record.reason),
      targetName,
    );
    const cleanup = document.createElement("button");
    cleanup.type = "button";
    cleanup.className = "danger";
    cleanup.textContent = l10n("cleanup_action");
    cleanup.setAttribute(
      "aria-label",
      l10n("label_stale_cleanup_description", targetName),
    );
    cleanup.addEventListener("click", async () => {
      try {
        await invoke("cleanup_stale_label", { label: record.label, target: record.target });
        root.querySelector('[data-f="result"]').textContent = l10n(
          "label_stale_cleaned",
          targetName,
        );
        await renderLabelManager(root);
      } catch (error) { showError(root, error); }
    });
    row.append(reason, cleanup);
    staleList.append(row);
  }
}

async function openLabelManager() {
  const root = openModal(l10n("labels_title"), "tpl-label-manager");
  const form = root.querySelector('[data-f="label-form"]');
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = root.querySelector('[data-f="label-name"]').value;
    const color = root.querySelector('[data-f="label-color"]').value;
    const id = root.querySelector('[data-f="label-id"]').value;
    try {
      if (!exactLabelNameValid(name)) throw new Error(l10n("label_invalid_name"));
      if (!LABEL_COLORS.includes(color)) throw new Error(l10n("label_invalid_color"));
      const saved = id
        ? await invoke("update_label", { label: id, name, color })
        : await invoke("create_label", { name, color });
      root.querySelector('[data-f="result"]').textContent = l10n(
        id ? "label_updated" : "label_created",
        labelAccessibleName(saved),
      );
      resetLabelEditor(root);
      await renderLabelManager(root);
      await refreshLabels(true);
      root.querySelector('[data-f="label-name"]').focus();
    } catch (error) { showError(root, error); }
  });
  root.querySelector('[data-act="cancel-edit"]').addEventListener("click", () => {
    resetLabelEditor(root);
    root.querySelector('[data-f="result"]').textContent = l10n("label_edit_cancelled");
    root.querySelector('[data-f="label-name"]').focus();
  });
  await renderLabelManager(root);
}

$("#btn-label-manager").addEventListener("click", openLabelManager);

async function openConversationLabels() {
  const target = labelTarget();
  if (!target) return;
  const exactTarget = currentTargetName();
  const root = openModal(
    l10n("label_assignment_title", exactTarget),
    "tpl-conversation-labels",
  );
  root.querySelector('[data-f="target-summary"]').textContent = l10n(
    "label_assignment_list_description",
    exactTarget,
  );
  const assigned = new Set((await invoke("labels_for_conversation", { target })).map((label) => label.id));
  const list = root.querySelector('[data-f="labels"]');
  list.replaceChildren();
  if (state.labels.length === 0) {
    const empty = document.createElement("p");
    empty.className = "modal-note";
    empty.textContent = l10n("labels_assignment_empty");
    list.append(empty);
  }
  for (const label of state.labels) {
    const row = document.createElement("label");
    row.className = "label-assignment-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = assigned.has(label.id);
    input.setAttribute(
      "aria-label",
      l10n(
        input.checked ? "label_remove_for" : "label_apply_for",
        labelAccessibleName(label),
        exactTarget,
      ),
    );
    input.addEventListener("change", async () => {
      input.disabled = true;
      try {
        const command = input.checked ? "assign_label" : "unassign_label";
        await invoke(command, { label: label.id, target });
        const finalLabels = await invoke("labels_for_conversation", { target });
        const final = finalLabels.some((item) => item.id === label.id);
        input.checked = final;
        input.setAttribute(
          "aria-label",
          l10n(
            final ? "label_remove_for" : "label_apply_for",
            labelAccessibleName(label),
            exactTarget,
          ),
        );
        root.querySelector('[data-f="result"]').textContent = l10n(
          "label_assignment_result",
          labelAccessibleName(label),
          exactTarget,
          l10n(final ? "label_applied" : "label_removed"),
          finalLabels.length,
        );
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
  const root = openModal(l10n("share_title"), "tpl-share");
  const view = root.querySelector('[data-f="share-dialog"]');
  const status = view.querySelector('[data-f="share-status"]');
  const content = view.querySelector('[data-f="share-content"]');
  let bundle;
  let addrSvg;
  let nodeStatus;
  try {
    [bundle, addrSvg, nodeStatus] = await Promise.all([
      invoke("my_bundle"),
      invoke("address_qr"),
      invoke("status"),
    ]);
  } catch (err) {
    if (!view.isConnected) return;
    status.className = "error";
    status.textContent = l10n("share_unavailable");
    toast(localizedError(err), true);
    return;
  }
  if (!view.isConnected) return;
  const bundlePane = view.querySelector('[data-pane="bundle"]');
  const bundleFrames = bundle.qr_svgs?.length ? bundle.qr_svgs : [bundle.qr_svg];
  const frameProgress = view.querySelector('[data-f="qr-progress"]');
  let frameIndex = 0;
  const renderBundleFrame = () => {
    bundlePane.innerHTML = bundleFrames[frameIndex];
    frameProgress.textContent = bundleFrames.length === 1
      ? l10n("pairing_scan_code")
      : l10n(
        "pairing_frame_progress",
        frameIndex + 1,
        bundleFrames.length,
      );
  };
  renderBundleFrame();
  if (bundleFrames.length > 1) {
    const frameTimer = window.setInterval(() => {
      if (!view.isConnected) {
        window.clearInterval(frameTimer);
        return;
      }
      frameIndex = (frameIndex + 1) % bundleFrames.length;
      renderBundleFrame();
    }, 1100);
  }
  view.querySelector('[data-pane="address"]').innerHTML = addrSvg;
  view.querySelector(".share-connect-code").value = nodeStatus.connect_code;
  view.querySelector(".share-account-fingerprint").value = nodeStatus.address;
  view.querySelector('[data-act="retire-legacy"]').hidden = !nodeStatus.legacy_discovery;
  view.querySelector(".share-hex").value = bundle.hex;
  status.remove();
  content.hidden = false;
  view.addEventListener("click", async (e) => {
    const tab = e.target.closest("[data-share]");
    if (tab) {
      $$(".qr-tabs .tab", root).forEach((t) => t.classList.toggle("active", t === tab));
      $$("[data-pane]", root).forEach((p) => (p.hidden = p.dataset.pane !== tab.dataset.share));
    }
    if (e.target.matches('[data-act="copy-hex"]')) copyText(bundle.hex);
    if (e.target.matches('[data-act="copy-connect"]')) {
      copyText(view.querySelector(".share-connect-code").value);
    }
    if (e.target.matches('[data-act="rotate-connect"]')) {
      if (!window.confirm(
        `${l10n("rotate_connect_code")}\n\n${l10n("rotate_connect_code_warning")}`,
      )) return;
      const code = await invoke("rotate_connect_code");
      const svg = await invoke("address_qr");
      view.querySelector(".share-connect-code").value = code;
      view.querySelector('[data-pane="address"]').innerHTML = svg;
      view.querySelector('[data-act="retire-legacy"]').hidden = true;
      state.address = code;
      $("#my-address").textContent = code;
      toast(l10n("rotate_connect_code_done"));
    }
    if (e.target.matches('[data-act="retire-legacy"]')) {
      if (!window.confirm(l10n("legacy_discovery_retire_warning"))) return;
      const code = await invoke("retire_legacy_discovery");
      view.querySelector(".share-connect-code").value = code;
      e.target.hidden = true;
      toast(l10n("legacy_discovery_retired"));
    }
    if (e.target.matches('[data-act="publish"]')) {
      await call("publish");
      toast(l10n("reachability_republished"));
    }
  });
});

// add-contact modal
$("#btn-add-contact").addEventListener("click", () => {
  const root = openModal(l10n("add_title"), "tpl-add");
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
      if (!name) throw l10n("add_need_name");
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
  const root = openModal(l10n("group_create_title"), "tpl-create-group");
  const members = root.querySelector('[data-f="members"]');
  if (state.contacts.length === 0) {
    const empty = document.createElement("p");
    empty.className = "modal-note";
    empty.textContent = l10n("group_no_contacts");
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
      if (!name) throw l10n("group_need_name");
      if (selected.length === 0) throw l10n("group_need_member");
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
  const authority = await call("group_authority", { group: group.id });
  const isOwner = authority.my_role === "owner";
  const isAdmin = authority.my_role === "admin";
  const root = openModal(
    l10n("group_members_title", group.name),
    "tpl-group-details",
  );
  root.querySelector(".group-summary").textContent = l10n(
    "group_authority_security_summary",
    l10nPlural("group_member_count", group.members.length, group.members.length),
    memberName(authority.owner),
    Number(authority.generation),
    l10n(
      authority.signed ? "group_authority_signed" : "group_authority_legacy",
    ),
    groupOriginName(group.security),
  );
  const manage = root.querySelector('[data-f="manage"]');
  if (isOwner || isAdmin) {
    manage.hidden = false;
    root.querySelector('[data-f="rename"]').value = group.name;
    root.querySelector('[data-act="rename"]').textContent = l10n(
      isOwner ? "group_rename_action" : "group_rename_request_action",
    );
  }
  const roster = root.querySelector('[data-f="roster"]');
  for (const member of authority.members) {
    const peer = member.peer;
    const row = document.createElement("div");
    row.className = "member-row";
    row.dataset.peer = peer;
    const name = document.createElement("span");
    name.className = "member-name";
    name.textContent = memberName(peer);
    const role = document.createElement("span");
    role.className = "member-role";
    role.textContent = groupRoleName(member.role);
    row.append(name, role);
    if (isOwner && member.role !== "owner") {
      const roleButton = document.createElement("button");
      roleButton.className = "ghost";
      roleButton.dataset.act = "set-role";
      roleButton.dataset.peer = peer;
      roleButton.dataset.role = member.role === "admin" ? "member" : "admin";
      roleButton.textContent = l10n(
        member.role === "admin" ? "group_make_member" : "group_make_admin",
      );
      row.append(roleButton);
      const transfer = document.createElement("button");
      transfer.className = "ghost";
      transfer.dataset.act = "transfer-owner";
      transfer.dataset.peer = peer;
      transfer.textContent = l10n("group_make_owner");
      row.append(transfer);
    }
    if ((isOwner && member.role !== "owner") || (isAdmin && member.role === "member")) {
      const remove = document.createElement("button");
      remove.className = "danger";
      remove.dataset.act = "remove-member";
      remove.dataset.peer = peer;
      remove.textContent = l10n("group_remove_action");
      row.append(remove);
    }
    roster.append(row);
  }

  const candidates = state.contacts.filter((contact) => !group.members.includes(contact.peer));
  const addWrap = root.querySelector('[data-f="add-wrap"]');
  if ((isOwner || isAdmin) && candidates.length > 0) {
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
    if (action === "rename") {
      try {
        const name = root.querySelector('[data-f="rename"]').value.trim();
        if (!name) throw l10n("group_need_name");
        await invoke("rename_group", { group: group.id, name });
        closeModal();
        await refreshGroups();
        toast(l10n(isOwner ? "group_renamed" : "group_rename_requested"));
      } catch (err) { showError(root, err); }
    }
    if (action === "set-role") {
      try {
        await invoke("set_group_role", {
          group: group.id,
          peer: event.target.dataset.peer,
          role: event.target.dataset.role,
        });
        closeModal();
        await refreshGroups();
        await openGroupDetails();
      } catch (err) { showError(root, err); }
    }
    if (action === "transfer-owner") {
      const peer = event.target.dataset.peer;
      if (!confirm(l10n("group_transfer_owner_warning", memberName(peer)))) return;
      try {
        await invoke("transfer_group_owner", { group: group.id, peer });
        closeModal();
        await refreshGroups();
        await openGroupDetails();
      } catch (err) { showError(root, err); }
    }
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
      if (!window.confirm(l10n("group_remove_warning", memberName(peer)))) return;
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
      if (isOwner) { showError(root, l10n("group_owner_must_transfer")); return; }
      if (!window.confirm(l10n("group_leave_warning", group.name))) return;
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

function openCreatePoll() {
  const group = currentGroup();
  if (!group) return;
  const root = openModal(l10n("poll_create_title", group.name), "tpl-create-poll");
  const options = root.querySelector('[data-f="poll-options"]');
  const add = root.querySelector('[data-act="add-option"]');

  const refreshOptionControls = () => {
    const rows = $$(".poll-option-edit-row", options);
    for (const remove of $$('[data-act="remove-option"]', options)) {
      remove.disabled = rows.length <= 2;
    }
    add.disabled = rows.length >= 12;
  };

  const addOption = (value = "") => {
    if ($$(".poll-option-edit-row", options).length >= 12) return;
    const row = document.createElement("div");
    row.className = "poll-option-edit-row";
    const label = document.createElement("label");
    const number = $$(".poll-option-edit-row", options).length + 1;
    label.textContent = l10n("poll_choice_hint", number);
    const input = document.createElement("input");
    input.type = "text";
    input.value = value;
    input.autocomplete = "off";
    input.dataset.incognitoInput = "message";
    input.setAttribute("aria-label", l10n("poll_choice_accessibility", number));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost";
    remove.dataset.act = "remove-option";
    remove.textContent = l10n("remove_action");
    remove.setAttribute("aria-label", l10n("poll_remove_choice", number));
    remove.addEventListener("click", () => {
      row.remove();
      $$(".poll-option-edit-row", options).forEach((item, index) => {
        item.querySelector("label").firstChild.textContent = l10n(
          "poll_choice_hint",
          index + 1,
        );
        item.querySelector("input").setAttribute(
          "aria-label",
          l10n("poll_choice_accessibility", index + 1),
        );
        item.querySelector("button").setAttribute(
          "aria-label",
          l10n("poll_remove_choice", index + 1),
        );
      });
      refreshOptionControls();
    });
    label.append(input);
    row.append(label, remove);
    options.append(row);
    refreshOptionControls();
    return input;
  };

  addOption();
  addOption();
  add.addEventListener("click", () => addOption()?.focus());
  root.querySelector('[data-act="create-poll"]').addEventListener("click", async () => {
    const error = root.querySelector('[data-f="error"]');
    error.hidden = true;
    const question = root.querySelector('[data-f="poll-question"]').value;
    const choices = $$("input", options).map((input) => input.value);
    const bytes = (value) => new TextEncoder().encode(value).length;
    try {
      if (!question.trim()) throw l10n("poll_need_question");
      if (bytes(question) > 1024) throw l10n("poll_question_too_long");
      if (choices.length < 2 || choices.some((choice) => !choice.trim())) {
        throw l10n("poll_need_choices");
      }
      if (choices.some((choice) => bytes(choice) > 256)) {
        throw l10n("poll_choice_too_long");
      }
      await call("create_group_poll", { group: group.id, question, options: choices });
      closeModal();
      await renderMessages();
      toast(l10n("poll_created"));
    } catch (err) {
      error.textContent = String(err);
      error.hidden = false;
    }
  });
  root.querySelector('[data-f="poll-question"]').focus();
}

$("#btn-poll").addEventListener("click", openCreatePoll);

// verify (safety number) modal
$("#btn-verify").addEventListener("click", async () => {
  const peer = state.currentId;
  const root = openModal(l10n("verify_title", contactName(peer)), "tpl-verify");
  const digits = root.querySelector(".safety-digits");
  const qr = root.querySelector(".safety-qr");
  const mark = root.querySelector('[data-act="verified"]');
  digits.textContent = l10n("verify_calculating");
  mark.disabled = true;
  try {
    const sn = await call("safety_number", { peer });
    digits.textContent = sn.display;
    qr.innerHTML = sn.qr_svg;
    mark.disabled = false;
  } catch (error) {
    digits.textContent = l10n("verify_unavailable");
    qr.replaceChildren();
    return;
  }
  root.addEventListener("click", async (e) => {
    if (!e.target.matches('[data-act="verified"]')) return;
    await call("mark_verified", { peer });
    closeModal();
    toast(l10n("verify_done"));
    await Promise.all([refreshContacts(), refreshAuthorityResetHistory()]);
  });
});

// delivery-hints modal
$("#btn-hints").addEventListener("click", () => {
  const peer = state.currentId;
  const root = openModal(
    l10n("hints_for", contactName(peer)),
    "tpl-hints",
  );
  const getHints = wireHints(root);
  root.addEventListener("click", async (e) => {
    if (!e.target.matches('[data-act="save"]')) return;
    try {
      await invoke("set_hints", { peer, hints: getHints() });
      closeModal();
      toast(l10n("hints_saved"));
    } catch (err) {
      showError(root, err);
    }
  });
});

// appearance is applied immediately and sealed through the shared F5 record
async function openAppearanceSettings() {
  const root = openModal(l10n("appearance_title"), "tpl-theme");
  const info = await call("theme");
  const checked = root.querySelector('input[value="' + info.preference + '"]');
  if (checked) checked.checked = true;
  root.querySelector('[data-f="locale"]').value =
    KommsLocalization.localePreference();
  root.addEventListener("change", async (event) => {
    if (event.target.matches('[data-f="locale"]')) {
      KommsLocalization.setLocale(event.target.value);
      return;
    }
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
}

async function renderLinkedDevices(root) {
  const list = root.querySelector('[data-f="device-list"]');
  const [devices, conflicts, contactConflicts] = await Promise.all([
    invoke("linked_devices"),
    invoke("device_authority_conflicts"),
    invoke("contact_authority_conflicts"),
  ]);
  const conflictView = root.querySelector('[data-f="authority-conflicts"]');
  if (conflicts.length || contactConflicts.length) {
    conflictView.hidden = false;
    const ownWarnings = conflicts.map((conflict) =>
      conflict.kind === "recovery"
        ? l10n(
          "device_authority_recovery_conflict",
          Number(conflict.recovery_epoch),
        )
        : l10n("device_authority_fork", Number(conflict.recovery_epoch))
    );
    const contactWarnings = contactConflicts.map((conflict) => {
      const name = contactName(conflict.account);
      return conflict.kind === "recovery"
        ? l10n(
          "device_authority_contact_recovery_conflict",
          name,
          Number(conflict.recovery_epoch),
        )
        : l10n(
          "device_authority_contact_fork",
          name,
          Number(conflict.recovery_epoch),
        );
    });
    conflictView.textContent = ownWarnings.concat(contactWarnings).join(" ");
  } else {
    conflictView.hidden = true;
    conflictView.textContent = "";
  }
  list.replaceChildren();
  for (const device of devices) {
    const row = document.createElement("div");
    row.className = "member-row";
    const summary = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = device.name;
    const detail = document.createElement("small");
    const stateText = device.revoked_at
      ? l10n("device_revoked_at", fmtTime(device.revoked_at))
      : device.current
        ? l10n("device_row_current")
        : l10n("device_active_seen", fmtTime(device.last_seen));
    detail.textContent = l10n("device_detail", stateText, device.id);
    summary.append(name, document.createElement("br"), detail);
    const actions = document.createElement("div");
    if (!device.revoked_at) {
      const rename = document.createElement("button");
      rename.className = "ghost";
      rename.type = "button";
      rename.textContent = l10n("device_rename_action", device.name);
      rename.setAttribute("aria-label", l10n("device_rename_action", device.name));
      rename.addEventListener("click", async () => {
        const next = window.prompt(l10n("device_signed_name"), device.name);
        if (next === null) return;
        try {
          await invoke("rename_linked_device", { device: device.id, name: next });
          await renderLinkedDevices(root);
        } catch (error) { showError(root, error); }
      });
      actions.append(rename);
      if (!device.current) {
        const sync = document.createElement("button");
        sync.className = "ghost";
        sync.type = "button";
        sync.textContent = l10n("device_export_sync_action", device.name);
        sync.setAttribute(
          "aria-label",
          l10n("device_export_sync_action", device.name),
        );
        sync.addEventListener("click", async () => {
          try {
            const bundle = await invoke("export_device_sync", { device: device.id });
            await copyText(bundle);
            toast(l10n("device_sync_copied", device.name));
          } catch (error) { showError(root, error); }
        });
        const revoke = document.createElement("button");
        revoke.className = "danger";
        revoke.type = "button";
        revoke.textContent = l10n("device_revoke_action", device.name);
        revoke.setAttribute(
          "aria-label",
          l10n("device_revoke_action", device.name),
        );
        revoke.addEventListener("click", async () => {
          const confirmed = window.confirm(
            l10n("device_revoke_confirmation", device.name),
          );
          if (!confirmed) return;
          try {
            await invoke("revoke_linked_device", { device: device.id, confirmed: true });
            await renderLinkedDevices(root);
          } catch (error) { showError(root, error); }
        });
        actions.append(sync, revoke);
      }
    }
    row.append(summary, actions);
    list.append(row);
  }
}

async function openDeviceLinkSource() {
  const root = openModal(l10n("device_link_source_title"), "tpl-device-link-source");
  try {
    const offer = await invoke("begin_device_link");
    const pane = root.querySelector('[data-f="offer-qr"]');
    const frames = offer.qr_svgs?.length ? offer.qr_svgs : [offer.qr_svg];
    let frame = 0;
    pane.innerHTML = frames[frame];
    if (frames.length > 1) {
      const timer = window.setInterval(() => {
        if (!root.isConnected) {
          window.clearInterval(timer);
          return;
        }
        frame = (frame + 1) % frames.length;
        pane.innerHTML = frames[frame];
        pane.setAttribute(
          "aria-label",
          l10n("device_link_frame_accessibility", frame + 1, frames.length),
        );
      }, 1100);
    }
    root.querySelector('[data-f="offer"]').value = offer.hex;
  } catch (error) { showError(root, error); }
  root.addEventListener("click", async (event) => {
    try {
      if (event.target.matches('[data-act="copy-offer"]')) {
        await copyText(root.querySelector('[data-f="offer"]').value);
      }
      if (event.target.matches('[data-act="compare"]')) {
        const responseHex = root.querySelector('[data-f="response"]').value.trim();
        const code = await invoke("device_link_confirmation_code", { responseHex });
        root.querySelector('[data-f="code"]').textContent = code;
        root.querySelector('[data-f="approval"]').hidden = false;
      }
      if (event.target.matches('[data-act="approve"]')) {
        const confirmed = root.querySelector('[data-f="confirmed"]').checked;
        if (!confirmed) throw l10n("device_compare_required");
        const responseHex = root.querySelector('[data-f="response"]').value.trim();
        const selection = {
          contacts: root.querySelector('[data-f="contacts"]').checked,
          organization: root.querySelector('[data-f="organization"]').checked,
          history: root.querySelector('[data-f="history"]').checked,
        };
        try {
          const packageHex = await invoke("approve_device_link", {
            responseHex, selection, confirmed: true
          });
          root.querySelector('[data-f="package"]').value = packageHex;
          root.querySelector('[data-f="package-wrap"]').hidden = false;
        } catch (failure) {
          if (!String(failure).includes("additional active-device approval")) throw failure;
          const request = await invoke("device_link_approval_request");
          root.querySelector('[data-f="approval-request"]').value = request;
          root.querySelector('[data-f="quorum"]').hidden = false;
        }
      }
      if (event.target.matches('[data-act="copy-approval-request"]')) {
        await copyText(root.querySelector('[data-f="approval-request"]').value);
      }
      if (event.target.matches('[data-act="accept-additional-approval"]')) {
        const packageHex = await invoke("accept_device_link_approval", {
          approvalHex: root.querySelector('[data-f="additional-approval"]').value.trim(),
        });
        if (!packageHex) {
          toast(l10n("device_approval_more_required"));
          return;
        }
        root.querySelector('[data-f="package"]').value = packageHex;
        root.querySelector('[data-f="package-wrap"]').hidden = false;
        root.querySelector('[data-f="quorum"]').hidden = true;
      }
      if (event.target.matches('[data-act="copy-package"]')) {
        await copyText(root.querySelector('[data-f="package"]').value);
      }
    } catch (error) { showError(root, error); }
  });
}

function openDeviceApproval(kind) {
  const isLink = kind === "link";
  const root = openModal(
    l10n(isLink ? "device_approval_link_title" : "device_approval_change_title"),
    "tpl-device-approval"
  );
  root.querySelector('[data-f="explanation"]').textContent = isLink
    ? l10n("device_approval_link_body")
    : l10n("device_approval_change_body");
  root.addEventListener("click", async (event) => {
    try {
      if (event.target.matches('[data-act="approve-request"]')) {
        const command = isLink
          ? "approve_device_link_request"
          : "approve_device_authority_request";
        const approval = await invoke(command, {
          requestHex: root.querySelector('[data-f="request"]').value.trim(),
        });
        root.querySelector('[data-f="approval"]').value = approval;
        root.querySelector('[data-f="result"]').hidden = false;
      }
      if (event.target.matches('[data-act="copy-approval"]')) {
        await copyText(root.querySelector('[data-f="approval"]').value);
      }
    } catch (error) { showError(root, error); }
  });
}

async function openPendingAuthorityApproval() {
  const root = openModal(
    l10n("device_pending_change_title"),
    "tpl-pending-authority",
  );
  try {
    root.querySelector('[data-f="request"]').value =
      await invoke("device_authority_approval_request");
  } catch (error) {
    showError(root, error);
  }
  root.addEventListener("click", async (event) => {
    try {
      if (event.target.matches('[data-act="copy-request"]')) {
        await copyText(root.querySelector('[data-f="request"]').value);
      }
      if (event.target.matches('[data-act="accept-approval"]')) {
        const committed = await invoke("accept_device_authority_approval", {
          approvalHex: root.querySelector('[data-f="approval"]').value.trim(),
        });
        if (committed) {
          closeModal();
          toast(l10n("device_authority_committed"));
        } else {
          toast(l10n("device_approval_more_required"));
        }
      }
    } catch (error) { showError(root, error); }
  });
}

function openDeviceLinkTarget() {
  const root = openModal(l10n("device_link_target_title"), "tpl-device-link-target");
  root.addEventListener("click", async (event) => {
    try {
      if (event.target.matches('[data-act="accept"]')) {
        const accepted = await invoke("accept_device_link", {
          offerHex: root.querySelector('[data-f="offer"]').value.trim(),
          deviceName: root.querySelector('[data-f="name"]').value.trim(),
        });
        root.querySelector('[data-f="code"]').textContent = accepted.confirmation_code;
        root.querySelector('[data-f="response"]').value = accepted.response_hex;
        root.querySelector('[data-f="accepted"]').hidden = false;
      }
      if (event.target.matches('[data-act="copy-response"]')) {
        await copyText(root.querySelector('[data-f="response"]').value);
      }
      if (event.target.matches('[data-act="complete"]')) {
        const confirmed = root.querySelector('[data-f="confirmed"]').checked;
        if (!confirmed) throw l10n("device_compare_required");
        await invoke("complete_device_link", {
          packageHex: root.querySelector('[data-f="package"]').value.trim(),
          confirmed: true,
        });
        closeModal();
        await refreshStatus();
        await Promise.all([refreshContacts(), refreshGroups(), refreshFolders(), refreshLabels()]);
        toast(l10n("device_linked_success"));
      }
    } catch (error) { showError(root, error); }
  });
}

function openDeviceSyncImport() {
  const root = openModal(l10n("device_sync_import_title"), "tpl-device-sync");
  root.addEventListener("click", async (event) => {
    if (!event.target.matches('[data-act="import"]')) return;
    try {
      const inserted = await invoke("import_device_sync", {
        bundleHex: root.querySelector('[data-f="bundle"]').value.trim(),
      });
      closeModal();
      await Promise.all([refreshContacts(), refreshGroups(), refreshFolders(), refreshLabels()]);
      toast(l10nPlural(
        "device_imported_sync_events",
        inserted,
        inserted,
      ));
    } catch (error) { showError(root, error); }
  });
}

async function openLinkedDevicesSettings() {
  const root = openModal(l10n("settings_devices_title"), "tpl-devices");
  try { await renderLinkedDevices(root); } catch (error) { showError(root, error); }
  root.addEventListener("click", (event) => {
    if (event.target.matches('[data-act="begin-link"]')) openDeviceLinkSource();
    if (event.target.matches('[data-act="join-link"]')) openDeviceLinkTarget();
    if (event.target.matches('[data-act="approve-link"]')) openDeviceApproval("link");
    if (event.target.matches('[data-act="approve-authority"]')) openDeviceApproval("authority");
    if (event.target.matches('[data-act="continue-authority"]')) openPendingAuthorityApproval();
    if (event.target.matches('[data-act="import-sync"]')) openDeviceSyncImport();
  });
}

// First-run-only offline account authority. The modal cannot be dismissed
// until the encrypted package is written and its separate phrase acknowledged.
function openRecoveryAuthorityOnboarding() {
  recoveryOnboardingPending = true;
  const root = openModal(
    l10n("recovery_authority_required_title"),
    "tpl-recovery-authority",
  );
  $("#modal-close").hidden = true;
  root.addEventListener("click", async (event) => {
    if (event.target.matches('[data-act="export-authority"]')) {
      const error = root.querySelector('[data-f="error"]');
      error.hidden = true;
      try {
        const mnemonic = await invoke("export_account_recovery_authority", {
          path: root.querySelector('[data-f="path"]').value.trim(),
        });
        const list = root.querySelector('[data-f="mnemonic"]');
        list.replaceChildren(...mnemonic.split(/\s+/).map((word) => {
          const item = document.createElement("li");
          item.textContent = word;
          return item;
        }));
        root.querySelector('[data-f="export-stage"]').hidden = true;
        root.querySelector('[data-f="result-stage"]').hidden = false;
      } catch (failure) {
        error.textContent = localizedError(failure);
        error.hidden = false;
      }
    }
    if (event.target.matches('[data-act="authority-done"]')) {
      recoveryOnboardingPending = false;
      $("#modal-close").hidden = false;
      closeModal();
      toast(l10n("recovery_authority_done_title"));
    }
  });
}

// backup modal → one-time mnemonic
function openBackupSettings() {
  const root = openModal(l10n("settings_backup_title"), "tpl-backup");
  const stamp = new Date().toISOString().slice(0, 10);
  root.querySelector('[data-f="path"]').value = `${state.dataDir}/komms-${stamp}.kkr`;
  root.addEventListener("click", async (e) => {
    if (!e.target.matches('[data-act="export"]')) return;
    try {
      const mnemonic = await invoke("export_backup", {
        path: root.querySelector('[data-f="path"]').value.trim(),
      });
      const shown = openModal(l10n("backup_mnemonic_title"), "tpl-mnemonic");
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
}

$("#btn-settings").addEventListener("click", () => {
  const root = openModal(l10n("settings_title"), "tpl-settings");
  root.addEventListener("click", (event) => {
    const action = event.target.closest("[data-settings-action]")?.dataset.settingsAction;
    if (action === "backup") openBackupSettings();
    if (action === "devices") openLinkedDevicesSettings();
    if (action === "appearance") openAppearanceSettings();
    if (action === "folders") openFolderManager();
    if (action === "labels") openLabelManager();
    if (action === "icons") openIconManager();
  });
});

// ── boot ────────────────────────────────────────────────────────────────

probeGate().catch((err) => {
  $("#gate-error").textContent = localizedError(err);
  $("#gate-error").hidden = false;
});
