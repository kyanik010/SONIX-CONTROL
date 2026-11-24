import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateDeviceToken,
  sha256Hex,
  timingSafeEqualHex,
  evaluateDeviceAccess,
  extractAssignedServers,
  resolveAssignedServer,
  filterPendingMessages,
  normalizeAppSettings,
  selectCompatibleRelease,
} from "./core.ts";

describe("sonix-device-api core logic", () => {
  it("generates unique stx_ device tokens and verifies hashes in constant time", async () => {
    const t1 = generateDeviceToken();
    const t2 = generateDeviceToken();
    assert.ok(t1.startsWith("stx_"));
    assert.equal(t1.length, 68);
    assert.notEqual(t1, t2);

    const h1 = await sha256Hex(t1);
    const h2 = await sha256Hex(t2);
    assert.equal(h1.length, 64);
    assert.equal(timingSafeEqualHex(h1, await sha256Hex(t1)), true);
    assert.equal(timingSafeEqualHex(h1, h2), false);
    assert.equal(timingSafeEqualHex("", h1), false);
  });

  it("evaluates device status and subscription/trial entitlements strictly", () => {
    const now = Date.parse("2026-11-24T12:00:00Z");
    const activeSub = {
      id: "sub-1",
      status: "active",
      starts_at: "2026-11-01T00:00:00Z",
      ends_at: "2026-12-24T12:00:00Z",
      subscription_plans: { id: "p1", code: "yearly", name: "سنوي", duration_days: 365 },
    };
    const activeTrial = {
      id: "trial-1",
      status: "active",
      started_at: "2026-11-15T00:00:00Z",
      ends_at: "2026-12-01T00:00:00Z",
    };
    const expiredTrial = {
      id: "trial-old",
      status: "active",
      started_at: "2026-10-01T00:00:00Z",
      ends_at: "2026-11-01T00:00:00Z",
    };

    const paid = evaluateDeviceAccess("active", [activeSub], [activeTrial], now);
    assert.equal(paid.access_allowed, true);
    assert.equal(paid.access_status, "active");
    assert.equal(paid.subscription?.is_trial, false);
    assert.equal(paid.subscription?.plan_name, "سنوي");
    assert.equal(paid.subscription?.days_remaining, 30);

    const trial = evaluateDeviceAccess("active", [], [activeTrial], now);
    assert.equal(trial.access_allowed, true);
    assert.equal(trial.subscription?.is_trial, true);

    const expired = evaluateDeviceAccess("active", [], [expiredTrial], now);
    assert.equal(expired.access_allowed, false);
    assert.equal(expired.access_status, "expired");
    assert.equal(expired.subscription?.status, "expired");

    const blocked = evaluateDeviceAccess("blocked", [activeSub], [], now);
    assert.equal(blocked.access_allowed, false);
    assert.equal(blocked.access_status, "blocked");

    const revoked = evaluateDeviceAccess("revoked", [activeSub], [], now);
    assert.equal(revoked.access_allowed, false);
    assert.equal(revoked.access_status, "revoked");
  });

  it("isolates servers to active assignments and resolves only assigned server IDs", () => {
    const rows = [
      {
        server_id: "srv-2",
        servers: { id: "srv-2", name: "EU 2", region: "DE", priority: 20, is_active: true, server_url: "http://eu2.example:8080" },
      },
      {
        server_id: "srv-1",
        servers: { id: "srv-1", name: "ME 1", region: "AE", priority: 5, is_active: true, server_url: "http://me1.example:8080" },
      },
      {
        server_id: "srv-off",
        servers: { id: "srv-off", name: "Disabled", region: "US", priority: 1, is_active: false, server_url: "http://off.example:8080" },
      },
    ];

    const list = extractAssignedServers(rows);
    assert.deepEqual(
      list.map((s) => s.id),
      ["srv-1", "srv-2"],
    );
    assert.equal("server_url" in list[0], false);

    const resolved = resolveAssignedServer(rows, "srv-1");
    assert.equal(resolved?.server_url, "http://me1.example:8080");
    assert.equal(resolveAssignedServer(rows, "srv-off"), null);
    assert.equal(resolveAssignedServer(rows, "srv-unassigned"), null);
  });

  it("filters pending broadcast and device-targeted messages properly", () => {
    const now = Date.parse("2026-11-24T12:00:00Z");
    const messages = [
      {
        id: "m1",
        title: "Broadcast",
        body: "Hello all",
        message_type: "info",
        publish_at: "2026-11-01T00:00:00Z",
        expires_at: "2026-12-01T00:00:00Z",
        is_published: true,
        target_type: "all",
      },
      {
        id: "m2",
        title: "Other Device",
        body: "Only dev-2",
        message_type: "warning",
        publish_at: "2026-11-20T00:00:00Z",
        is_published: true,
        target_type: "device",
        target_device_id: "dev-2",
      },
      {
        id: "m3",
        title: "My Device",
        body: "Only dev-1",
        message_type: "urgent",
        publish_at: "2026-11-20T00:00:00Z",
        is_published: true,
        target_type: "device",
        target_device_id: "dev-1",
      },
      {
        id: "m4",
        title: "Acked",
        body: "Already seen",
        message_type: "info",
        publish_at: "2026-11-20T00:00:00Z",
        is_published: true,
        target_type: "all",
      },
      {
        id: "m5",
        title: "Expired",
        body: "Too old",
        message_type: "info",
        publish_at: "2026-10-01T00:00:00Z",
        expires_at: "2026-11-01T00:00:00Z",
        is_published: true,
        target_type: "all",
      },
    ];

    const pending = filterPendingMessages(messages, new Set(["m4"]), "dev-1", now);
    assert.deepEqual(
      pending.map((m) => m.id),
      ["m1", "m3"],
    );
  });

  it("normalizes app settings and selects highest compatible release with mandatory policy", () => {
    const settings = normalizeAppSettings([
      { config_key: "trial_duration_days", config_value: "14" },
      { config_key: "maintenance_mode", config_value: true },
      { config_key: "maintenance_message", config_value: "صيانة مجدولة" },
      { config_key: "allow_normal_url_login", config_value: false },
    ]);
    assert.equal(settings.trial_duration_days, 14);
    assert.equal(settings.maintenance_mode, true);
    assert.equal(settings.maintenance_message, "صيانة مجدولة");
    assert.equal(settings.allow_normal_url_login, false);
    assert.equal(settings.allow_panel_servers, true);

    const release = selectCompatibleRelease(
      [
        {
          id: "rel-old",
          channel: "stable",
          version_name: "1.1.0",
          version_code: 2,
          apk_url: "https://cdn.example/1.1.0.apk",
          release_url: "https://cdn.example/rel-2",
          sha256: "abc",
          apk_size_bytes: 1000,
          release_notes: "old",
          update_policy: "optional",
          target_platform: "all",
          target_abis: ["arm64-v8a"],
          min_supported_version_code: 1,
          published_at: "2026-11-20T00:00:00Z",
          app_release_targets: [],
        },
        {
          id: "rel-wrong-abi",
          channel: "stable",
          version_name: "1.3.0",
          version_code: 4,
          apk_url: "https://cdn.example/1.3.0-x86.apk",
          release_url: "https://cdn.example/rel-4",
          sha256: "def",
          apk_size_bytes: 1000,
          release_notes: "x86 only",
          update_policy: "optional",
          target_platform: "android_tv",
          target_abis: ["x86_64"],
          min_supported_version_code: 1,
          published_at: "2026-11-24T00:00:00Z",
          app_release_targets: [],
        },
        {
          id: "rel-match",
          channel: "stable",
          version_name: "1.2.0",
          version_code: 3,
          apk_url: "https://cdn.example/1.2.0.apk",
          release_url: "https://cdn.example/rel-3",
          sha256: "123",
          apk_size_bytes: 2048,
          release_notes: "new release",
          update_policy: "optional",
          target_platform: "android_tv",
          target_abis: ["arm64-v8a"],
          min_supported_version_code: 2,
          published_at: "2026-11-22T00:00:00Z",
          app_release_targets: [{ device_id: "dev-1" }],
        },
      ],
      {
        deviceId: "dev-1",
        platform: "android_tv",
        deviceAbis: ["arm64-v8a"],
        currentVersionCode: 1,
      },
    );

    assert.equal(release?.id, "rel-match");
    assert.equal(release?.update_policy, "mandatory");
  });
});
