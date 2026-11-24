export type DeviceStatus = "active" | "blocked" | "revoked";
export type AccessStatus = "active" | "expired" | "blocked" | "revoked";

export interface SubscriptionRow {
  id: string;
  status: string;
  starts_at: string | null;
  ends_at: string;
  notes?: string | null;
  subscription_plans?: {
    id?: string;
    code?: string;
    name?: string;
    duration_days?: number;
  } | Array<{
    id?: string;
    code?: string;
    name?: string;
    duration_days?: number;
  }> | null;
}

export interface TrialRow {
  id?: string;
  status: string;
  started_at?: string | null;
  ends_at: string;
}

export interface SubscriptionSummary {
  id: string | null;
  plan_name: string;
  plan_code: string;
  status: "active" | "expired" | "revoked";
  is_trial: boolean;
  starts_at: string | null;
  ends_at: string | null;
  days_remaining: number;
}

export interface AccessEvaluation {
  device_status: DeviceStatus;
  access_status: AccessStatus;
  access_allowed: boolean;
  subscription: SubscriptionSummary | null;
}

export interface ServerRecord {
  id: string;
  name: string;
  region?: string | null;
  server_url?: string | null;
  priority?: number | null;
  is_active?: boolean;
}

export interface AssignmentRow {
  server_id: string;
  assigned_at?: string | null;
  servers?: ServerRecord | ServerRecord[] | null;
}

export interface AppConfigRow {
  config_key: string;
  config_value: unknown;
}

export interface AppSettingsPayload {
  trial_duration_days: number;
  maintenance_mode: boolean;
  maintenance_message: string;
  support_notice: string;
  allow_normal_url_login: boolean;
  allow_panel_servers: boolean;
}

export interface MessageRow {
  id: string;
  title: string;
  body: string;
  message_type: string;
  publish_at: string;
  expires_at?: string | null;
  is_published?: boolean;
  target_type?: string;
  target_device_id?: string | null;
}

export interface ReleaseCandidate {
  id: string;
  channel: string;
  version_name: string;
  version_code: number;
  apk_url: string;
  release_url: string;
  sha256: string;
  apk_size_bytes: number | null;
  release_notes: string;
  update_policy: string;
  target_platform: string;
  target_abis: string[];
  min_supported_version_code: number;
  published_at: string | null;
  app_release_targets?: Array<{ device_id: string }> | null;
}

export function generateDeviceToken(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `stx_${hex}`;
}

export async function sha256Hex(raw: string): Promise<string> {
  const encoded = new TextEncoder().encode(raw);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function unwrapSingle<T>(val: T | T[] | null | undefined): T | null {
  if (!val) return null;
  return Array.isArray(val) ? (val[0] ?? null) : val;
}

export function evaluateDeviceAccess(
  rawStatus: string,
  subscriptions: SubscriptionRow[] = [],
  trials: TrialRow[] = [],
  nowMs: number = Date.now(),
): AccessEvaluation {
  const deviceStatus: DeviceStatus =
    rawStatus === "blocked" || rawStatus === "revoked" ? rawStatus : "active";

  const sortedSubs = [...subscriptions].sort(
    (a, b) => Date.parse(b.ends_at || "") - Date.parse(a.ends_at || ""),
  );
  const sortedTrials = [...trials].sort(
    (a, b) => Date.parse(b.ends_at || "") - Date.parse(a.ends_at || ""),
  );

  const activeSub = sortedSubs.find((sub) => {
    if (sub.status !== "active") return false;
    const startsAt = sub.starts_at ? Date.parse(sub.starts_at) : 0;
    const endsAt = Date.parse(sub.ends_at);
    return Number.isFinite(endsAt) && startsAt <= nowMs && endsAt > nowMs;
  });

  const activeTrial = sortedTrials.find((trial) => {
    if (trial.status !== "active") return false;
    const endsAt = Date.parse(trial.ends_at);
    return Number.isFinite(endsAt) && endsAt > nowMs;
  });

  let summary: SubscriptionSummary | null = null;
  if (activeSub) {
    const plan = unwrapSingle(activeSub.subscription_plans);
    const endsAt = Date.parse(activeSub.ends_at);
    summary = {
      id: activeSub.id,
      plan_name: plan?.name ?? "اشتراك مفعّل",
      plan_code: plan?.code ?? "subscription",
      status: "active",
      is_trial: false,
      starts_at: activeSub.starts_at ?? null,
      ends_at: activeSub.ends_at,
      days_remaining: Math.max(0, Math.ceil((endsAt - nowMs) / 86400000)),
    };
  } else if (activeTrial) {
    const endsAt = Date.parse(activeTrial.ends_at);
    summary = {
      id: activeTrial.id ?? null,
      plan_name: "فترة تجريبية",
      plan_code: "trial",
      status: "active",
      is_trial: true,
      starts_at: activeTrial.started_at ?? null,
      ends_at: activeTrial.ends_at,
      days_remaining: Math.max(0, Math.ceil((endsAt - nowMs) / 86400000)),
    };
  } else if (sortedSubs.length > 0) {
    const latest = sortedSubs[0];
    const plan = unwrapSingle(latest.subscription_plans);
    summary = {
      id: latest.id,
      plan_name: plan?.name ?? "اشتراك",
      plan_code: plan?.code ?? "subscription",
      status: latest.status === "revoked" ? "revoked" : "expired",
      is_trial: false,
      starts_at: latest.starts_at ?? null,
      ends_at: latest.ends_at,
      days_remaining: 0,
    };
  } else if (sortedTrials.length > 0) {
    const latest = sortedTrials[0];
    summary = {
      id: latest.id ?? null,
      plan_name: "فترة تجريبية",
      plan_code: "trial",
      status: latest.status === "revoked" ? "revoked" : "expired",
      is_trial: true,
      starts_at: latest.started_at ?? null,
      ends_at: latest.ends_at,
      days_remaining: 0,
    };
  }

  if (deviceStatus === "blocked" || deviceStatus === "revoked") {
    return {
      device_status: deviceStatus,
      access_status: deviceStatus,
      access_allowed: false,
      subscription: summary,
    };
  }

  const hasValidEntitlement = Boolean(activeSub || activeTrial);
  return {
    device_status: deviceStatus,
    access_status: hasValidEntitlement ? "active" : "expired",
    access_allowed: hasValidEntitlement,
    subscription: summary,
  };
}

export function extractAssignedServers(
  assignmentRows: AssignmentRow[] = [],
): Array<{ id: string; name: string; region: string | null; priority: number }> {
  const byId = new Map<string, { id: string; name: string; region: string | null; priority: number }>();
  for (const row of assignmentRows) {
    const server = unwrapSingle(row.servers);
    if (!server || server.is_active === false || !server.id) continue;
    byId.set(server.id, {
      id: server.id,
      name: server.name,
      region: server.region ?? null,
      priority: Number(server.priority ?? 100),
    });
  }
  return Array.from(byId.values()).sort((a, b) => a.priority - b.priority);
}

export function resolveAssignedServer(
  assignmentRows: AssignmentRow[] = [],
  requestedServerId: string,
): { id: string; name: string; region: string | null; server_url: string } | null {
  const cleanId = requestedServerId.trim();
  if (!cleanId) return null;
  for (const row of assignmentRows) {
    const server = unwrapSingle(row.servers);
    if (!server || server.is_active === false) continue;
    if ((server.id === cleanId || row.server_id === cleanId) && server.server_url) {
      return {
        id: server.id,
        name: server.name,
        region: server.region ?? null,
        server_url: server.server_url,
      };
    }
  }
  return null;
}

export function filterPendingMessages(
  messages: MessageRow[] = [],
  acknowledgedIds: Set<string>,
  deviceId: string,
  nowMs: number = Date.now(),
): MessageRow[] {
  return messages.filter((msg) => {
    if (msg.is_published === false) return false;
    if (acknowledgedIds.has(msg.id)) return false;
    const pubMs = Date.parse(msg.publish_at);
    if (Number.isFinite(pubMs) && pubMs > nowMs) return false;
    if (msg.expires_at) {
      const expMs = Date.parse(msg.expires_at);
      if (Number.isFinite(expMs) && expMs <= nowMs) return false;
    }
    const targetType = msg.target_type ?? "all";
    if (targetType === "device") {
      return msg.target_device_id === deviceId;
    }
    return true;
  });
}

function parseBoolConfig(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const lowered = value.trim().toLowerCase();
    if (lowered === "true" || lowered === "1" || lowered === "yes") return true;
    if (lowered === "false" || lowered === "0" || lowered === "no") return false;
  }
  return fallback;
}

export function normalizeAppSettings(rows: AppConfigRow[] = []): AppSettingsPayload {
  const map = new Map<string, unknown>();
  for (const row of rows) {
    if (row?.config_key) map.set(row.config_key, row.config_value);
  }
  const rawDays = Number(map.get("trial_duration_days") ?? 30);
  const trialDays = Number.isFinite(rawDays) ? Math.max(1, Math.min(365, Math.round(rawDays))) : 30;
  return {
    trial_duration_days: trialDays,
    maintenance_mode: parseBoolConfig(map.get("maintenance_mode"), false),
    maintenance_message: String(map.get("maintenance_message") ?? "").slice(0, 500),
    support_notice: String(map.get("support_notice") ?? "").slice(0, 500),
    allow_normal_url_login: parseBoolConfig(map.get("allow_normal_url_login"), true),
    allow_panel_servers: parseBoolConfig(map.get("allow_panel_servers"), true),
  };
}

export function selectCompatibleRelease(
  candidates: ReleaseCandidate[] = [],
  params: {
    deviceId: string;
    platform: "android" | "android_tv";
    deviceAbis: string[];
    currentVersionCode: number;
  },
): {
  id: string;
  channel: string;
  version_name: string;
  version_code: number;
  apk_url: string;
  release_url: string;
  sha256: string;
  apk_size_bytes: number | null;
  release_notes: string;
  update_policy: "mandatory" | "optional";
  min_supported_version_code: number;
  published_at: string | null;
} | null {
  const sorted = [...candidates]
    .filter((r) => r.version_code > params.currentVersionCode)
    .sort((a, b) => b.version_code - a.version_code);

  const match = sorted.find((release) => {
    const platformMatches = release.target_platform === "all" || release.target_platform === params.platform;
    const abiMatches =
      release.target_abis.includes("all") ||
      release.target_abis.some((abi) => params.deviceAbis.includes(abi));
    const targets = release.app_release_targets ?? [];
    const deviceMatches = targets.length === 0 || targets.some((t) => t.device_id === params.deviceId);
    return platformMatches && abiMatches && deviceMatches;
  });

  if (!match) return null;
  const mandatory =
    match.update_policy === "mandatory" ||
    params.currentVersionCode < Number(match.min_supported_version_code ?? 0);

  return {
    id: match.id,
    channel: match.channel,
    version_name: match.version_name,
    version_code: match.version_code,
    apk_url: match.apk_url,
    release_url: match.release_url,
    sha256: match.sha256,
    apk_size_bytes: match.apk_size_bytes,
    release_notes: match.release_notes,
    update_policy: mandatory ? "mandatory" : "optional",
    min_supported_version_code: match.min_supported_version_code,
    published_at: match.published_at,
  };
}
