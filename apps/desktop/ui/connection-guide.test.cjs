"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
require("./connection-guide.js");
const { nextStep } = globalThis.KommsConnectionGuide;

test("fresh install and fallback availability do not imply a reachable recipient", () => {
  for (const connection of ["waiting_for_route", "fallback_ready", "future_state"]) {
    assert.equal(nextStep({ connection, mode: "standard", provider_directory: "not_configured", mdns_enabled: true, lan_peers: [] }), "connection_guide_waiting");
  }
});
test("visible LAN peers yield local test advice only with discovery enabled", () => {
  const status = { connection: "fallback_ready", mode: "sovereign", mdns_enabled: true, lan_peers: ["test-peer"] };
  assert.equal(nextStep(status), "connection_guide_lan");
  assert.equal(nextStep({ ...status, mdns_enabled: false }), "connection_guide_waiting");
});
test("private mode does not suggest leaking onto a normal LAN route", () => {
  assert.equal(nextStep({ mode: "private", connection: "waiting_for_route", mdns_enabled: true, lan_peers: ["stale-peer"] }), "connection_guide_private");
});
test("directory conflict takes precedence even when a peer is connected", () => {
  assert.equal(nextStep({ connection: "connected", provider_directory: "conflict" }), "connection_guide_conflict");
});
test("peer connectivity remains distinct from message state and does not mutate status", () => {
  const status = Object.freeze({ connection: "connected", queued: 7, delivered: 0 });
  assert.equal(nextStep(status), "connection_guide_connected");
  assert.equal(status.queued, 7);
  assert.equal(status.delivered, 0);
});
test("unavailable or partial responses fail to non-delivery guidance", () => {
  assert.equal(nextStep(null), "connection_guide_unavailable");
  assert.equal(nextStep(undefined), "connection_guide_unavailable");
  assert.equal(nextStep({ lan_peers: null }), "connection_guide_waiting");
});
