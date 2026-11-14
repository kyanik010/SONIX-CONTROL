import { createClient } from "npm:@supabase/supabase-js@2.119.0";

const allowedOrigin = "https://kyanik010.github.io";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
  "Vary": "Origin",
  "Content-Type": "application/json",
};
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });
const fail = (error: string, status = 400, detail?: string) =>
  reply({ error, ...(detail ? { detail } : {}) }, status);

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (!["GET", "POST", "PATCH"].includes(req.method)) return fail("method_not_allowed", 405);
  const origin = req.headers.get("origin");
  if (origin && origin !== allowedOrigin) return fail("origin_not_allowed", 403);

  const authHeader = req.headers.get("authorization") ?? "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) return fail("missing_session", 401);

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceKey) return fail("server_configuration_error", 500);

  const userClient = createClient(url, anonKey, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const db = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: authData, error: authError } = await userClient.auth.getUser(token);
  const user = authData?.user;
  if (authError || !user) return fail("invalid_session", 401);

  const { data: admin, error: adminError } = await db
    .from("admin_users").select("role,is_active").eq("user_id", user.id).maybeSingle();
  if (adminError) return fail("admin_lookup_failed", 500, adminError.message);
  if (!admin || !admin.is_active) return fail("admin_access_denied", 403);
  const role = admin.role as string;
  const canWrite = role === "owner" || role === "admin" || role === "operator";

  let body: Record<string, unknown> = {};
  if (req.method !== "GET") {
    try { body = await req.json(); } catch { return fail("invalid_json", 400); }
  }
  const urlParams = new URL(req.url).searchParams;
  const action = String(body.action ?? urlParams.get("action") ?? "");
  const payload = (body.payload && typeof body.payload === "object" ? body.payload : body) as Record<string, unknown>;
  const requireWrite = () => canWrite ? null : fail("read_only_role", 403);

  const audit = async (actionName: string, entityType: string, entityId?: string, details: Record<string, unknown> = {}) => {
    const { error } = await db.from("audit_logs").insert({
      actor_user_id: user.id, action: actionName, entity_type: entityType,
      entity_id: entityId ?? null, details,
    });
    if (error) console.error("audit_write_failed", error.message);
  };

  try {
    switch (action) {
      case "dashboard.summary": {
        const [devices, activeDevices, blockedDevices, subscriptions, expiredSubscriptions, servers, recentLogs] = await Promise.all([
          db.from("devices").select("id", { count: "exact", head: true }),
          db.from("devices").select("id", { count: "exact", head: true }).eq("status", "active"),
          db.from("devices").select("id", { count: "exact", head: true }).eq("status", "blocked"),
          db.from("subscriptions").select("id", { count: "exact", head: true }).eq("status", "active"),
          db.from("subscriptions").select("id", { count: "exact", head: true }).or("status.eq.expired,ends_at.lt." + new Date().toISOString()),
          db.from("servers").select("id", { count: "exact", head: true }).eq("is_active", true),
          db.from("audit_logs").select("*").order("created_at", { ascending: false }).limit(8),
        ]);
        for (const result of [devices, activeDevices, blockedDevices, subscriptions, expiredSubscriptions, servers, recentLogs]) {
          if (result.error) return fail("summary_query_failed", 500, result.error.message);
        }
        return reply({ data: {
          devices: devices.count ?? 0, activeDevices: activeDevices.count ?? 0,
          blockedDevices: blockedDevices.count ?? 0, activeSubscriptions: subscriptions.count ?? 0,
          expiredSubscriptions: expiredSubscriptions.count ?? 0, activeServers: servers.count ?? 0,
          recentActivity: recentLogs.data ?? [],
        }});
      }
      case "devices.list": {
        const { data, error } = await db.from("devices").select("*,subscriptions(id,status,starts_at,ends_at,subscription_plans(name,code,duration_days)),device_trials(status,started_at,ends_at),device_server_assignments(server_id,servers(id,name,region,is_active)),device_audio_sources(m3u_url,updated_at)").order("last_seen_at", { ascending: false }).limit(500);
        if (error) return fail("devices_query_failed", 500, error.message);
        return reply({ data });
      }
      case "devices.create": {
        const denied = requireWrite(); if (denied) return denied;
        const device_uid = String(payload.device_uid ?? "").trim();
        if (device_uid.length < 8 || device_uid.length > 128) return fail("invalid_device_uid");
        const row = {
          device_uid,
          device_name: payload.device_name ? String(payload.device_name).slice(0,120) : null,
          platform: ["android","android_tv","other"].includes(String(payload.platform)) ? payload.platform : "android",
          manufacturer: payload.manufacturer ? String(payload.manufacturer).slice(0,120) : null,
          model: payload.model ? String(payload.model).slice(0,120) : null,
          os_version: payload.os_version ? String(payload.os_version).slice(0,80) : null,
          app_version: payload.app_version ? String(payload.app_version).slice(0,80) : null,
          status: "active",
        };
        const { data, error } = await db.from("devices").insert(row).select().single();
        if (error) return fail("device_create_failed", 400, error.message);
        const { data: trialConfig } = await db.from("app_config").select("config_value").eq("config_key", "trial_duration_days").maybeSingle();
        const trialDays = Math.max(1, Math.min(365, Number(trialConfig?.config_value ?? 30) || 30));
        const trialEnds = new Date(Date.now() + trialDays * 86400000).toISOString();
        const { error: trialError } = await db.from("device_trials").insert({
          device_id: data.id, status: "active", started_at: new Date().toISOString(), ends_at: trialEnds,
        });
        if (trialError) {
          await db.from("devices").delete().eq("id", data.id);
          return fail("device_trial_create_failed", 500, trialError.message);
        }
        await audit("device_created_with_trial", "devices", data.id, { device_uid, trial_days: trialDays, trial_ends_at: trialEnds });
        return reply({ data: { ...data, trial: { status: "active", ends_at: trialEnds } } }, 201);
      }
      case "devices.update": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("device_id_required");
        const patch: Record<string, unknown> = {};
        for (const key of ["device_name","platform","manufacturer","model","os_version","app_version","status"]) {
          if (payload[key] !== undefined) patch[key] = payload[key];
        }
        if (patch.status && !["active","blocked","revoked"].includes(String(patch.status))) return fail("invalid_status");
        const { data, error } = await db.from("devices").update(patch).eq("id", id).select().single();
        if (error) return fail("device_update_failed", 400, error.message);
        await audit("device_updated", "devices", id, patch);
        return reply({ data });
      }
      case "devices.assign_server": {
        const denied = requireWrite(); if (denied) return denied;
        const deviceId = String(payload.device_id ?? "");
        const serverId = String(payload.server_id ?? "");
        if (!deviceId || !serverId) return fail("device_and_server_required");
        const { data, error } = await db.from("device_server_assignments").upsert({
          device_id: deviceId, server_id: serverId, assigned_by: user.id, assigned_at: new Date().toISOString(),
        }, { onConflict: "device_id,server_id", ignoreDuplicates: true }).select().single();
        if (error) return fail("server_assignment_failed", 400, error.message);
        await audit("server_assigned_to_device", "device_server_assignments", data.id, { device_id: deviceId, server_id: serverId });
        return reply({ data });
      }
      case "devices.unassign_server": {
        const denied = requireWrite(); if (denied) return denied;
        const deviceId = String(payload.device_id ?? "");
        const serverId = String(payload.server_id ?? "");
        if (!deviceId || !serverId) return fail("device_and_server_required");
        const { error } = await db.from("device_server_assignments")
          .delete().eq("device_id", deviceId).eq("server_id", serverId);
        if (error) return fail("server_unassignment_failed", 400, error.message);
        await audit("server_unassigned_from_device", "device_server_assignments", deviceId + ":" + serverId, {
          device_id: deviceId, server_id: serverId,
        });
        return reply({ success: true });
      }
      case "audio_sources.set": {
        const denied = requireWrite(); if (denied) return denied;
        const deviceId = String(payload.device_id ?? "");
        const m3uUrl = String(payload.m3u_url ?? "").trim();
        if (!deviceId) return fail("device_id_required");
        if (m3uUrl.length < 10 || m3uUrl.length > 4096 || !/^https?:\/\//i.test(m3uUrl)) {
          return fail("invalid_m3u_url");
        }
        const { data: device, error: deviceError } = await db.from("devices")
          .select("id,device_uid").eq("id", deviceId).maybeSingle();
        if (deviceError) return fail("device_lookup_failed", 500, deviceError.message);
        if (!device) return fail("device_not_found", 404);
        const { data, error } = await db.from("device_audio_sources").upsert({
          device_id: deviceId, m3u_url: m3uUrl, updated_at: new Date().toISOString(), updated_by: user.id,
        }, { onConflict: "device_id" }).select("device_id,updated_at").single();
        if (error) return fail("audio_source_save_failed", 400, error.message);
        await audit("device_audio_m3u_updated", "device_audio_sources", deviceId, {
          device_uid: device.device_uid, url_configured: true,
        });
        return reply({ data });
      }
      case "audio_sources.delete": {
        const denied = requireWrite(); if (denied) return denied;
        const deviceId = String(payload.device_id ?? "");
        if (!deviceId) return fail("device_id_required");
        const { error } = await db.from("device_audio_sources").delete().eq("device_id", deviceId);
        if (error) return fail("audio_source_delete_failed", 400, error.message);
        await audit("device_audio_m3u_removed", "device_audio_sources", deviceId);
        return reply({ success: true });
      }
      case "plans.list": {
        const { data, error } = await db.from("subscription_plans").select("*").order("duration_days");
        if (error) return fail("plans_query_failed", 500, error.message);
        return reply({ data });
      }
      case "plans.create": {
        const denied = requireWrite(); if (denied) return denied;
        const row = {
          code: String(payload.code ?? "").trim().toLowerCase(),
          name: String(payload.name ?? "").trim(),
          duration_days: Number(payload.duration_days),
          price_minor_units: payload.price_minor_units == null ? null : Number(payload.price_minor_units),
          currency_code: String(payload.currency_code ?? "USD").toUpperCase(),
          is_active: payload.is_active !== false,
        };
        const { data, error } = await db.from("subscription_plans").insert(row).select().single();
        if (error) return fail("plan_create_failed", 400, error.message);
        await audit("plan_created", "subscription_plans", data.id, { code: row.code });
        return reply({ data }, 201);
      }
      case "subscriptions.list": {
        const { data, error } = await db.from("subscriptions").select("*,devices(id,device_uid,device_name,platform),subscription_plans(id,code,name,duration_days)").order("created_at", { ascending: false }).limit(500);
        if (error) return fail("subscriptions_query_failed", 500, error.message);
        return reply({ data });
      }
      case "subscriptions.create": {
        const denied = requireWrite(); if (denied) return denied;
        const deviceId = String(payload.device_id ?? "");
        const planId = String(payload.plan_id ?? "");
        if (!deviceId || !planId) return fail("device_and_plan_required");
        const { data: plan, error: planError } = await db.from("subscription_plans").select("duration_days").eq("id", planId).eq("is_active", true).single();
        if (planError || !plan) return fail("active_plan_not_found", 400, planError?.message);
        const starts = payload.starts_at ? new Date(String(payload.starts_at)) : new Date();
        if (Number.isNaN(starts.getTime())) return fail("invalid_start_date");
        const ends = new Date(starts.getTime() + Number(plan.duration_days) * 86400000);
        const { data, error } = await db.from("subscriptions").insert({
          device_id: deviceId, plan_id: planId, status: "active",
          starts_at: starts.toISOString(), ends_at: ends.toISOString(),
          notes: payload.notes ? String(payload.notes).slice(0,1000) : null,
          created_by: user.id,
        }).select().single();
        if (error) return fail("subscription_create_failed", 400, error.message);
        await audit("subscription_created", "subscriptions", data.id, { device_id: deviceId, ends_at: ends.toISOString() });
        return reply({ data }, 201);
      }
      case "subscriptions.revoke": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("subscription_id_required");
        const { data, error } = await db.from("subscriptions").update({ status: "revoked" }).eq("id", id).select().single();
        if (error) return fail("subscription_revoke_failed", 400, error.message);
        await audit("subscription_revoked", "subscriptions", id);
        return reply({ data });
      }
      case "servers.list": {
        const { data, error } = await db.from("servers").select("id,name,server_url,region,priority,is_active,notes,created_at").order("priority");
        if (error) return fail("servers_query_failed", 500, error.message);
        return reply({ data });
      }
      case "servers.create": {
        const denied = requireWrite(); if (denied) return denied;
        const row = {
          name: String(payload.name ?? "").trim(),
          server_url: String(payload.server_url ?? "").trim(),
          region: payload.region ? String(payload.region).slice(0,80) : null,
          priority: Number(payload.priority ?? 100),
          is_active: payload.is_active !== false,
          notes: payload.notes ? String(payload.notes).slice(0,1000) : null,
          created_by: user.id,
        };
        const { data, error } = await db.from("servers").insert(row).select("id,name,server_url,region,priority,is_active,notes,created_at").single();
        if (error) return fail("server_create_failed", 400, error.message);
        await audit("server_created", "servers", data.id, { name: row.name });
        return reply({ data }, 201);
      }
      case "servers.update": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("server_id_required");
        const patch: Record<string, unknown> = {};
        for (const key of ["name","server_url","region","priority","is_active","notes"]) if (payload[key] !== undefined) patch[key] = payload[key];
        const { data, error } = await db.from("servers").update(patch).eq("id", id).select("id,name,server_url,region,priority,is_active,notes,created_at").single();
        if (error) return fail("server_update_failed", 400, error.message);
        await audit("server_updated", "servers", id, { changed_fields: Object.keys(patch) });
        return reply({ data });
      }
      case "themes.list": {
        const { data, error } = await db.from("app_themes").select("*").order("sort_order").order("created_at");
        if (error) return fail("themes_query_failed", 500, error.message);
        return reply({ data });
      }
      case "themes.create": {
        const denied = requireWrite(); if (denied) return denied;
        const name = String(payload.name ?? "").trim();
        const palette = payload.palette && typeof payload.palette === "object" ? payload.palette : {};
        if (name.length < 2 || name.length > 80) return fail("invalid_theme_name");
        const row = { name, palette, is_active: payload.is_active !== false, is_default: false, sort_order: Number(payload.sort_order ?? 100), created_by: user.id };
        const { data, error } = await db.from("app_themes").insert(row).select().single();
        if (error) return fail("theme_create_failed", 400, error.message);
        await audit("theme_created", "app_themes", data.id, { name });
        return reply({ data }, 201);
      }
      case "themes.update": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("theme_id_required");
        const patch: Record<string, unknown> = {};
        for (const key of ["name","palette","is_active","sort_order"]) if (payload[key] !== undefined) patch[key] = payload[key];
        if (patch.name !== undefined && (String(patch.name).trim().length < 2 || String(patch.name).trim().length > 80)) return fail("invalid_theme_name");
        patch.updated_at = new Date().toISOString();
        const { data, error } = await db.from("app_themes").update(patch).eq("id", id).select().single();
        if (error) return fail("theme_update_failed", 400, error.message);
        await audit("theme_updated", "app_themes", id, { changed_fields: Object.keys(patch) });
        return reply({ data });
      }
      case "themes.set_default": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("theme_id_required");
        const { data: target, error: targetError } = await db.from("app_themes").select("id,is_active").eq("id", id).single();
        if (targetError || !target || !target.is_active) return fail("active_theme_not_found", 400, targetError?.message);
        const { error: clearError } = await db.from("app_themes").update({ is_default: false }).eq("is_default", true);
        if (clearError) return fail("theme_default_clear_failed", 500, clearError.message);
        const { data, error } = await db.from("app_themes").update({ is_default: true, updated_at: new Date().toISOString() }).eq("id", id).select().single();
        if (error) return fail("theme_default_update_failed", 400, error.message);
        await audit("theme_set_default", "app_themes", id);
        return reply({ data });
      }
      case "messages.list": {
        const { data, error } = await db.from("app_messages").select("*,devices(id,device_uid,device_name)").order("created_at", { ascending: false }).limit(300);
        if (error) return fail("messages_query_failed", 500, error.message);
        return reply({ data });
      }
      case "messages.create": {
        const denied = requireWrite(); if (denied) return denied;
        const title = String(payload.title ?? "").trim();
        const messageBody = String(payload.body ?? "").trim();
        const targetType = payload.target_type === "device" ? "device" : "all";
        const targetDeviceId = targetType === "device" ? String(payload.target_device_id ?? "") : null;
        if (!title || title.length > 160 || !messageBody || messageBody.length > 5000) return fail("invalid_message_content");
        if (targetType === "device" && !targetDeviceId) return fail("target_device_required");
        const row = {
          title, body: messageBody,
          message_type: ["info","update","warning","success"].includes(String(payload.message_type)) ? payload.message_type : "info",
          target_type: targetType, target_device_id: targetDeviceId,
          is_published: payload.is_published !== false,
          publish_at: payload.publish_at ? new Date(String(payload.publish_at)).toISOString() : new Date().toISOString(),
          expires_at: payload.expires_at ? new Date(String(payload.expires_at)).toISOString() : null,
          created_by: user.id,
        };
        const { data, error } = await db.from("app_messages").insert(row).select().single();
        if (error) return fail("message_create_failed", 400, error.message);
        await audit("message_created", "app_messages", data.id, { target_type: targetType, target_device_id: targetDeviceId });
        return reply({ data }, 201);
      }
      case "messages.update": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("message_id_required");
        const patch: Record<string, unknown> = {};
        for (const key of ["title","body","message_type","target_type","target_device_id","is_published","publish_at","expires_at"]) {
          if (payload[key] !== undefined) patch[key] = payload[key];
        }
        const { data, error } = await db.from("app_messages").update(patch).eq("id", id).select().single();
        if (error) return fail("message_update_failed", 400, error.message);
        await audit("message_updated", "app_messages", id, { changed_fields: Object.keys(patch) });
        return reply({ data });
      }
      case "messages.delete": {
        const denied = requireWrite(); if (denied) return denied;
        const id = String(payload.id ?? "");
        if (!id) return fail("message_id_required");
        const { error } = await db.from("app_messages").delete().eq("id", id);
        if (error) return fail("message_delete_failed", 400, error.message);
        await audit("message_deleted", "app_messages", id);
        return reply({ success: true });
      }
      case "releases.list": {
        const { data, error } = await db.from("app_releases")
          .select("*,app_release_targets(device_id,devices(device_uid,device_name,model))")
          .order("created_at", { ascending: false }).limit(200);
        if (error) return fail("releases_query_failed", 500, error.message);
        return reply({ data: data ?? [] });
      }
      case "releases.create": {
        if (role !== "owner" && role !== "admin") return fail("release_admin_required", 403);
        const versionName = String(payload.version_name ?? "").trim();
        const versionCode = Number(payload.version_code);
        const channel = String(payload.channel ?? "stable");
        const apkUrl = String(payload.apk_url ?? "").trim();
        const releaseUrl = String(payload.release_url ?? "").trim();
        const sha256 = String(payload.sha256 ?? "").trim().toLowerCase();
        const targetPlatform = String(payload.target_platform ?? "all");
        const updatePolicy = String(payload.update_policy ?? "optional");
        const targetAbis = Array.isArray(payload.target_abis) ? payload.target_abis.map(String) : ["all"];
        const targetDeviceIds = Array.isArray(payload.target_device_ids)
          ? [...new Set(payload.target_device_ids.map(String))] : [];
        if (!versionName || versionName.length > 40 || !Number.isSafeInteger(versionCode) || versionCode <= 0) return fail("invalid_release_version");
        if (!["stable","beta"].includes(channel)) return fail("invalid_release_channel");
        if (!/^https:\/\//i.test(apkUrl) || apkUrl.length > 2048 || !/^https:\/\//i.test(releaseUrl) || releaseUrl.length > 2048) return fail("invalid_release_url");
        if (!/^[0-9a-f]{64}$/.test(sha256)) return fail("invalid_release_sha256");
        if (!["all","android","android_tv"].includes(targetPlatform)) return fail("invalid_target_platform");
        if (!["optional","mandatory"].includes(updatePolicy)) return fail("invalid_update_policy");
        const allowedAbis = ["all","armeabi-v7a","arm64-v8a","x86","x86_64"];
        if (!targetAbis.length || targetAbis.some(a => !allowedAbis.includes(a)) || (targetAbis.includes("all") && targetAbis.length !== 1)) return fail("invalid_target_abis");
        if (targetDeviceIds.length > 500) return fail("too_many_target_devices");
        const row = {
          version_name: versionName, version_code: versionCode, channel,
          apk_url: apkUrl, release_url: releaseUrl, sha256,
          apk_size_bytes: payload.apk_size_bytes == null ? null : Number(payload.apk_size_bytes),
          release_notes: String(payload.release_notes ?? "").slice(0,12000),
          update_policy: updatePolicy, target_platform: targetPlatform, target_abis: targetAbis,
          min_supported_version_code: Math.max(0, Number(payload.min_supported_version_code ?? 0) || 0),
          status: "draft", created_by: user.id,
        };
        if (row.apk_size_bytes !== null && (!Number.isSafeInteger(row.apk_size_bytes) || row.apk_size_bytes <= 0)) return fail("invalid_apk_size");
        const { data, error } = await db.from("app_releases").insert(row).select().single();
        if (error) return fail("release_create_failed", 400, error.message);
        if (targetDeviceIds.length) {
          const { error: targetError } = await db.from("app_release_targets")
            .insert(targetDeviceIds.map(device_id => ({ release_id: data.id, device_id })));
          if (targetError) {
            await db.from("app_releases").delete().eq("id", data.id);
            return fail("release_targets_create_failed", 400, targetError.message);
          }
        }
        await audit("app_release_created", "app_releases", data.id, {
          version_name: versionName, version_code: versionCode, channel,
          target_device_count: targetDeviceIds.length,
        });
        return reply({ data: { ...data, target_device_ids: targetDeviceIds } }, 201);
      }
      case "releases.update": {
        if (role !== "owner" && role !== "admin") return fail("release_admin_required", 403);
        const id = String(payload.id ?? "");
        if (!id) return fail("release_id_required");
        const { data: current, error: currentError } = await db.from("app_releases")
          .select("id,status").eq("id", id).maybeSingle();
        if (currentError) return fail("release_lookup_failed", 500, currentError.message);
        if (!current) return fail("release_not_found", 404);
        if (current.status !== "draft") return fail("only_draft_releases_editable", 409);
        const patch: Record<string, unknown> = {};
        if (payload.version_name !== undefined) patch.version_name = String(payload.version_name).trim();
        if (payload.version_code !== undefined) {
          const code = Number(payload.version_code);
          if (!Number.isSafeInteger(code) || code <= 0) return fail("invalid_release_version_code");
          patch.version_code = code;
        }
        for (const key of ["apk_url","release_url","release_notes","channel","update_policy","target_platform","target_abis","min_supported_version_code","apk_size_bytes"]) {
          if (payload[key] !== undefined) patch[key] = payload[key];
        }
        if (patch.apk_url !== undefined && !/^https:\/\//i.test(String(patch.apk_url))) return fail("invalid_apk_url");
        if (patch.release_url !== undefined && !/^https:\/\//i.test(String(patch.release_url))) return fail("invalid_release_url");
        if (patch.release_notes !== undefined) patch.release_notes = String(patch.release_notes).slice(0,12000);
        patch.updated_at = new Date().toISOString();
        const { data, error } = await db.from("app_releases").update(patch).eq("id", id).select().single();
        if (error) return fail("release_update_failed", 400, error.message);
        if (Array.isArray(payload.target_device_ids)) {
          const ids = [...new Set(payload.target_device_ids.map(String))];
          if (ids.length > 500) return fail("too_many_target_devices");
          const { error: clearError } = await db.from("app_release_targets").delete().eq("release_id", id);
          if (clearError) return fail("release_targets_clear_failed", 500, clearError.message);
          if (ids.length) {
            const { error: targetError } = await db.from("app_release_targets").insert(ids.map(device_id => ({ release_id: id, device_id })));
            if (targetError) return fail("release_targets_update_failed", 400, targetError.message);
          }
        }
        await audit("app_release_updated", "app_releases", id, { changed_fields: Object.keys(patch) });
        return reply({ data });
      }
      case "releases.publish": {
        if (role !== "owner" && role !== "admin") return fail("release_admin_required", 403);
        const id = String(payload.id ?? "");
        if (!id) return fail("release_id_required");
        const { data: current, error: currentError } = await db.from("app_releases")
          .select("id,status,version_name,version_code").eq("id", id).maybeSingle();
        if (currentError) return fail("release_lookup_failed", 500, currentError.message);
        if (!current) return fail("release_not_found", 404);
        if (current.status !== "draft") return fail("only_draft_releases_publishable", 409);
        const now = new Date().toISOString();
        const { data, error } = await db.from("app_releases")
          .update({ status: "published", published_at: now, updated_at: now })
          .eq("id", id).select().single();
        if (error) return fail("release_publish_failed", 400, error.message);
        await audit("app_release_published", "app_releases", id, {
          version_name: current.version_name, version_code: current.version_code,
        });
        return reply({ data });
      }
      case "releases.disable": {
        if (role !== "owner" && role !== "admin") return fail("release_admin_required", 403);
        const id = String(payload.id ?? "");
        if (!id) return fail("release_id_required");
        const { data, error } = await db.from("app_releases")
          .update({ status: "disabled", updated_at: new Date().toISOString() })
          .eq("id", id).neq("status", "disabled").select().maybeSingle();
        if (error) return fail("release_disable_failed", 400, error.message);
        if (!data) return fail("release_not_found_or_already_disabled", 404);
        await audit("app_release_disabled", "app_releases", id, {
          version_name: data.version_name, version_code: data.version_code,
        });
        return reply({ data });
      }
      case "activity.list": {
        const { data, error } = await db.from("audit_logs").select("*").order("created_at", { ascending: false }).limit(100);
        if (error) return fail("activity_query_failed", 500, error.message);
        return reply({ data });
      }
      default: return fail("unknown_action", 404);
    }
  } catch (error) {
    console.error("admin_api_error", error);
    return fail("internal_error", 500, error instanceof Error ? error.message : "unknown");
  }
});
