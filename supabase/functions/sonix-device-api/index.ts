import { createClient } from "npm:@supabase/supabase-js@2.119.0";
import {
  evaluateDeviceAccess,
  extractAssignedServers,
  filterPendingMessages,
  generateDeviceToken,
  normalizeAppSettings,
  selectCompatibleRelease,
  sha256Hex,
  timingSafeEqualHex,
} from "./core.ts";

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type, x-sonix-device-token",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

const reply = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers });

const fail = (error: string, status = 400, detail?: string) =>
  reply({ error, ...(detail ? { detail } : {}) }, status);

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "POST") return fail("method_not_allowed", 405);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return fail("invalid_json");
  }

  const uid = String(body.device_uid ?? "").trim();
  if (uid.length < 8 || uid.length > 128) return fail("invalid_device_uid");

  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return fail("server_configuration_error", 500);

  const db = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    const action = String(body.action ?? "sync");
    const incomingToken = String(
      req.headers.get("x-sonix-device-token") ?? body.device_token ?? "",
    ).trim();

    let { data: device, error: findError } = await db
      .from("devices")
      .select("id,device_uid,status,first_seen_at,device_code,device_token_hash")
      .eq("device_uid", uid)
      .maybeSingle();
    if (findError) return fail("device_lookup_failed", 500, findError.message);

    const { data: configRows } = await db
      .from("app_config")
      .select("config_key,config_value");
    const settings = normalizeAppSettings(configRows ?? []);

    let issuedToken: string | null = null;

    if (!device) {
      const freshToken = generateDeviceToken();
      const tokenHash = await sha256Hex(freshToken);
      const nowIso = new Date().toISOString();

      const { data: created, error: createError } = await db
        .from("devices")
        .insert({
          device_uid: uid,
          device_name: String(body.device_name ?? "").slice(0, 120) || null,
          platform: body.platform === "android_tv" ? "android_tv" : "android",
          manufacturer: String(body.manufacturer ?? "").slice(0, 120) || null,
          model: String(body.model ?? "").slice(0, 120) || null,
          os_version: String(body.os_version ?? "").slice(0, 80) || null,
          app_version: String(body.app_version ?? "").slice(0, 80) || null,
          status: "active",
          device_token_hash: tokenHash,
          device_token_issued_at: nowIso,
        })
        .select("id,device_uid,status,first_seen_at,device_code,device_token_hash")
        .single();

      if (createError) {
        if (createError.code === "23505") {
          return fail("invalid_device_credentials", 401);
        }
        return fail("device_register_failed", 500, createError.message);
      }

      device = created;
      issuedToken = freshToken;

      const ends = new Date(Date.now() + settings.trial_duration_days * 86400000);
      const { error: trialError } = await db.from("device_trials").insert({
        device_id: device.id,
        status: "active",
        started_at: nowIso,
        ends_at: ends.toISOString(),
      });
      if (trialError) console.error("device_trial_create_failed", trialError.message);
    } else if (!device.device_token_hash) {
      // Pre-registered or admin-reset device: claim cryptographic device token once
      const freshToken = generateDeviceToken();
      const tokenHash = await sha256Hex(freshToken);
      const nowIso = new Date().toISOString();
      const { data: claimed, error: claimError } = await db
        .from("devices")
        .update({
          device_token_hash: tokenHash,
          device_token_issued_at: nowIso,
        })
        .eq("id", device.id)
        .is("device_token_hash", null)
        .select("id,device_uid,status,first_seen_at,device_code,device_token_hash")
        .maybeSingle();

      if (claimError) return fail("device_auth_claim_failed", 500, claimError.message);
      if (!claimed) return fail("invalid_device_credentials", 401);
      device = claimed;
      issuedToken = freshToken;
    } else {
      if (!incomingToken) return fail("invalid_device_credentials", 401);
      const incomingHash = await sha256Hex(incomingToken);
      if (!timingSafeEqualHex(incomingHash, device.device_token_hash)) {
        return fail("invalid_device_credentials", 401);
      }
    }

    const versionCodeRaw = Number(body.app_version_code);
    const abiRaw = String(body.app_abi ?? "");
    await db
      .from("devices")
      .update({
        last_seen_at: new Date().toISOString(),
        device_name: String(body.device_name ?? "").slice(0, 120) || undefined,
        platform: body.platform === "android_tv" ? "android_tv" : body.platform === "android" ? "android" : undefined,
        manufacturer: String(body.manufacturer ?? "").slice(0, 120) || undefined,
        model: String(body.model ?? "").slice(0, 120) || undefined,
        os_version: String(body.os_version ?? "").slice(0, 80) || undefined,
        app_version: String(body.app_version ?? "").slice(0, 80) || undefined,
        app_version_code:
          Number.isSafeInteger(versionCodeRaw) && versionCodeRaw > 0 ? versionCodeRaw : undefined,
        app_abi: ["armeabi-v7a", "arm64-v8a", "x86", "x86_64", "unknown"].includes(abiRaw)
          ? abiRaw
          : undefined,
      })
      .eq("id", device.id);

    const [{ data: subscriptions, error: subError }, { data: trials, error: trialError }] =
      await Promise.all([
        db
          .from("subscriptions")
          .select("id,status,starts_at,ends_at,notes,subscription_plans(id,code,name,duration_days)")
          .eq("device_id", device.id)
          .order("ends_at", { ascending: false })
          .limit(20),
        db
          .from("device_trials")
          .select("id,status,started_at,ends_at")
          .eq("device_id", device.id)
          .order("ends_at", { ascending: false })
          .limit(10),
      ]);

    if (subError || trialError) {
      return fail("entitlement_lookup_failed", 500, subError?.message ?? trialError?.message);
    }

    const access = evaluateDeviceAccess(
      device.status,
      subscriptions ?? [],
      trials ?? [],
      Date.now(),
    );

    if (device.status !== "active") {
      if (action === "sync" || action === "device.register") {
        return reply({
          status: access.access_status,
          device_status: access.device_status,
          access_status: access.access_status,
          access_allowed: false,
          device_id: device.id,
          device_uid: device.device_uid,
          device_code: device.device_code,
          ...(issuedToken ? { device_token: issuedToken } : {}),
          subscription: access.subscription,
          settings,
          servers: [],
          messages: [],
          themes: [],
        });
      }
      return fail(`device_${device.status}`, 403);
    }

    if (action === "app.update.check") {
      const currentVersionCode =
        Number.isSafeInteger(Number(body.app_version_code))
          ? Math.max(0, Number(body.app_version_code))
          : 0;
      const platform = body.platform === "android_tv" ? "android_tv" : "android";
      const abi = ["armeabi-v7a", "arm64-v8a", "x86", "x86_64"].includes(String(body.app_abi))
        ? String(body.app_abi)
        : "unknown";
      const deviceAbis = Array.isArray(body.app_abis)
        ? body.app_abis
            .map(String)
            .filter((value: string) =>
              ["armeabi-v7a", "arm64-v8a", "x86", "x86_64"].includes(value),
            )
        : [abi];
      const channel = body.channel === "beta" ? "beta" : "stable";
      const { data: candidates, error: releaseError } = await db
        .from("app_releases")
        .select(
          "id,channel,version_name,version_code,apk_url,release_url,sha256,apk_size_bytes,release_notes,update_policy,target_platform,target_abis,min_supported_version_code,published_at,app_release_targets(device_id)",
        )
        .eq("channel", channel)
        .eq("status", "published")
        .gt("version_code", currentVersionCode)
        .order("version_code", { ascending: false })
        .limit(100);

      if (releaseError) return fail("update_check_failed", 500, releaseError.message);
      const update = selectCompatibleRelease(candidates ?? [], {
        deviceId: device.id,
        platform,
        deviceAbis,
        currentVersionCode,
      });

      if (!update) {
        return reply({
          status: access.access_status,
          access_allowed: access.access_allowed,
          update_available: false,
          current_version_code: currentVersionCode,
          channel,
        });
      }

      return reply({
        status: access.access_status,
        access_allowed: access.access_allowed,
        update_available: true,
        current_version_code: currentVersionCode,
        update,
      });
    }

    if (!access.access_allowed) {
      if (action === "sync" || action === "device.register") {
        const [{ data: receipts }, { data: messages }] = await Promise.all([
          db
            .from("device_message_receipts")
            .select("message_id")
            .eq("device_id", device.id)
            .not("acknowledged_at", "is", null),
          db
            .from("app_messages")
            .select("id,title,body,message_type,publish_at,expires_at,is_published,target_type,target_device_id")
            .eq("is_published", true)
            .lte("publish_at", new Date().toISOString())
            .order("publish_at", { ascending: true })
            .limit(200),
        ]);
        const acknowledged = new Set((receipts ?? []).map((r: { message_id: string }) => r.message_id));
        const pendingMessages = filterPendingMessages(messages ?? [], acknowledged, device.id, Date.now());
        return reply({
          status: access.access_status,
          device_status: access.device_status,
          access_status: access.access_status,
          access_allowed: false,
          device_id: device.id,
          device_uid: device.device_uid,
          device_code: device.device_code,
          ...(issuedToken ? { device_token: issuedToken } : {}),
          subscription: access.subscription,
          settings,
          servers: [],
          messages: pendingMessages,
          themes: [],
        });
      }
      if (action === "message.ack") {
        const messageId = String(body.message_id ?? "").trim();
        if (!messageId) return fail("message_id_required");
        const { error } = await db.from("device_message_receipts").upsert(
          {
            message_id: messageId,
            device_id: device.id,
            acknowledged_at: new Date().toISOString(),
          },
          { onConflict: "message_id,device_id" },
        );
        if (error) return fail("message_ack_failed", 500, error.message);
        return reply({ success: true });
      }
      return fail("subscription_expired", 403);
    }

    if (action === "servers.catalog") {
      const { data: servers, error: serverError } = await db
        .from("servers")
        .select("id,name,region,priority,is_active")
        .eq("is_active", true)
        .order("priority", { ascending: true })
        .order("name", { ascending: true });
      if (serverError) return fail("servers_fetch_failed", 500, serverError.message);
      return reply({
        status: access.access_status,
        access_allowed: true,
        servers: (servers ?? []).map((server) => ({
          id: server.id,
          name: server.name,
          region: server.region ?? null,
          priority: Number(server.priority ?? 100),
        })),
      });
    }

    if (action === "servers.list") {
      const { data: assignmentRows, error: serverError } = await db
        .from("device_server_assignments")
        .select("server_id,assigned_at,servers!inner(id,name,region,priority,is_active)")
        .eq("device_id", device.id)
        .eq("servers.is_active", true);
      if (serverError) return fail("servers_fetch_failed", 500, serverError.message);
      return reply({
        status: access.access_status,
        access_allowed: true,
        servers: extractAssignedServers(assignmentRows ?? []),
      });
    }

    if (action === "server.resolve") {
      const serverId = String(body.server_id ?? "").trim();
      if (!serverId) return fail("server_id_required");
      const { data: server, error: serverError } = await db
        .from("servers")
        .select("id,name,region,server_url,is_active")
        .eq("id", serverId)
        .eq("is_active", true)
        .maybeSingle();
      if (serverError) return fail("server_resolve_failed", 500, serverError.message);
      if (!server || !server.server_url) return fail("server_not_assigned", 404);
      return reply({
        status: access.access_status,
        access_allowed: true,
        server: {
          id: server.id,
          name: server.name,
          region: server.region ?? null,
          server_url: server.server_url,
        },
      });
    }

    if (action === "audio.sources") {
      const { data, error } = await db
        .from("device_audio_sources")
        .select("m3u_url,updated_at")
        .eq("device_id", device.id)
        .maybeSingle();
      if (error) return fail("audio_sources_fetch_failed", 500, error.message);
      return reply({
        status: "active",
        configured: Boolean(data?.m3u_url),
        m3u_url: data?.m3u_url ?? null,
        updated_at: data?.updated_at ?? null,
      });
    }

    if (action === "message.ack") {
      const messageId = String(body.message_id ?? "").trim();
      if (!messageId) return fail("message_id_required");
      const { error } = await db.from("device_message_receipts").upsert(
        {
          message_id: messageId,
          device_id: device.id,
          acknowledged_at: new Date().toISOString(),
        },
        { onConflict: "message_id,device_id" },
      );
      if (error) return fail("message_ack_failed", 500, error.message);
      return reply({ success: true });
    }

    if (action === "theme.set") {
      const themeId = String(body.theme_id ?? "");
      if (!themeId) return fail("theme_id_required");
      const { data: theme, error: themeError } = await db
        .from("app_themes")
        .select("id")
        .eq("id", themeId)
        .eq("is_active", true)
        .maybeSingle();
      if (themeError || !theme) return fail("theme_not_found", 404);
      const { error } = await db.from("device_theme_preferences").upsert(
        {
          device_id: device.id,
          theme_id: themeId,
          updated_at: new Date().toISOString(),
        },
        { onConflict: "device_id" },
      );
      if (error) return fail("theme_preference_failed", 500, error.message);
      return reply({ success: true });
    }

    // Default: sync / device.register
    const [
      { data: assignmentRows, error: serverError },
      { data: themes, error: themeError },
      { data: preference },
      { data: receipts, error: receiptError },
      { data: audioRow },
      { data: messages, error: messageError },
    ] = await Promise.all([
      db
        .from("device_server_assignments")
        .select("server_id,assigned_at,servers!inner(id,name,region,priority,is_active)")
        .eq("device_id", device.id)
        .eq("servers.is_active", true),
      db
        .from("app_themes")
        .select("id,name,palette,is_default")
        .eq("is_active", true)
        .order("sort_order"),
      db.from("device_theme_preferences").select("theme_id").eq("device_id", device.id).maybeSingle(),
      db
        .from("device_message_receipts")
        .select("message_id")
        .eq("device_id", device.id)
        .not("acknowledged_at", "is", null),
      db
        .from("device_audio_sources")
        .select("m3u_url,updated_at")
        .eq("device_id", device.id)
        .maybeSingle(),
      db
        .from("app_messages")
        .select("id,title,body,message_type,publish_at,expires_at,is_published,target_type,target_device_id")
        .eq("is_published", true)
        .lte("publish_at", new Date().toISOString())
        .order("publish_at", { ascending: true })
        .limit(200),
    ]);

    if (serverError || themeError || receiptError || messageError) {
      return fail(
        "device_sync_failed",
        500,
        serverError?.message ?? themeError?.message ?? receiptError?.message ?? messageError?.message,
      );
    }

    const acknowledged = new Set((receipts ?? []).map((r: { message_id: string }) => r.message_id));
    const pendingMessages = filterPendingMessages(messages ?? [], acknowledged, device.id, Date.now());
    const assignedServers = extractAssignedServers(assignmentRows ?? []);

    const theme =
      (themes ?? []).find((t: { id: string; is_default: boolean }) => t.id === preference?.theme_id) ??
      (themes ?? []).find((t: { is_default: boolean }) => t.is_default) ??
      (themes ?? [])[0] ??
      null;

    return reply({
      status: access.access_status,
      device_status: access.device_status,
      access_status: access.access_status,
      access_allowed: true,
      device_id: device.id,
      device_uid: device.device_uid,
      device_code: device.device_code,
      ...(issuedToken ? { device_token: issuedToken } : {}),
      subscription: access.subscription,
      settings,
      servers: assignedServers,
      messages: pendingMessages,
      audio_source: {
        configured: Boolean(audioRow?.m3u_url),
        m3u_url: audioRow?.m3u_url ?? null,
        updated_at: audioRow?.updated_at ?? null,
      },
      themes: themes ?? [],
      theme,
    });
  } catch (error) {
    console.error("sonix_device_api_error", error);
    return fail("internal_error", 500, error instanceof Error ? error.message : "unknown");
  }
});
