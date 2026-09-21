"use strict";

// Read-only presentation of node status. Never a reachability or delivery verdict.
globalThis.KommsConnectionGuide = Object.freeze({
  nextStep(status) {
    if (!status || typeof status !== "object") return "connection_guide_unavailable";
    if (status.provider_directory === "conflict") return "connection_guide_conflict";
    if (status.connection === "connected") return "connection_guide_connected";
    // Private mode deliberately has no ordinary LAN discovery advice.
    if (status.mode === "private") return "connection_guide_private";
    if (status.mdns_enabled === true && Array.isArray(status.lan_peers)
        && status.lan_peers.length > 0) return "connection_guide_lan";
    return "connection_guide_waiting";
  },
});
