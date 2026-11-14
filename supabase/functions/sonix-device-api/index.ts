import { createClient } from "npm:@supabase/supabase-js@2.119.0";

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, x-client-info, content-type",
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
  try { body = await req.json(); } catch { return fail("invalid_json"); }

  const uid = String(body.device_uid ?? "").trim();
  if (uid.length < 8 || uid.length > 128) return fail("invalid_device_uid");
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return fail("server_configuration_error", 500);
  const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });

  try {
    const action = String(body.action ?? "sync");
    let { data: device, error: findError } = await db.from("devices").select("id,status,first_seen_at").eq("device_uid", uid).maybeSingle();
    if (findError) return fail("device_lookup_failed", 500, findError.message);

    if (!device) {
      const { data: created, error: createError } = await db.from("devices").insert({
        device_uid: uid,
        device_name: String(body.device_name ?? "").slice(0,120) || null,
        platform: body.platform === "android_tv" ? "android_tv" : "android",
        manufacturer: String(body.manufacturer ?? "").slice(0,120) || null,
        model: String(body.model ?? "").slice(0,120) || null,
        os_version: String(body.os_version ?? "").slice(0,80) || null,
        app_version: String(body.app_version ?? "").slice(0,80) || null,
        status: "active",
      }).select("id,status,first_seen_at").single();
      if (createError) {
        if (createError.code === "23505") {
          const retry = await db.from("devices").select("id,status,first_seen_at").eq("device_uid", uid).single();
          if (retry.error) return fail("device_register_failed", 500, retry.error.message);
          device = retry.data;
        } else return fail("device_register_failed", 500, createError.message);
      } else {
        device = created;
        const { data: cfg } = await db.from("app_config").select("config_value").eq("config_key", "trial_duration_days").maybeSingle();
        const days = Math.max(1, Math.min(365, Number(cfg?.config_value ?? 30) || 30));
        const now = new Date();
        const ends = new Date(now.getTime() + days * 86400000);
        const { error: trialError } = await db.from("device_trials").insert({
          device_id: device.id, status: "active", started_at: now.toISOString(), ends_at: ends.toISOString(),
        });
        if (trialError) console.error("device_trial_create_failed", trialError.message);
      }
    }

    await db.from("devices").update({
      last_seen_at: new Date().toISOString(),
      device_name: String(body.device_name ?? "").slice(0,120) || undefined,
      app_version: String(body.app_version ?? "").slice(0,80) || undefined,
      app_version_code: Number.isSafeInteger(Number(body.app_version_code)) && Number(body.app_version_code) > 0 ? Number(body.app_version_code) : undefined,
      app_abi: ["armeabi-v7a","arm64-v8a","x86","x86_64","unknown"].includes(String(body.app_abi)) ? String(body.app_abi) : undefined,
    }).eq("id", device.id);

    if (device.status !== "active") return reply({ status: device.status, messages: [], servers: [], themes: [] });

    if (action === "app.update.check") {
      const currentVersionCode = Number.isSafeInteger(Number(body.app_version_code))
        ? Math.max(0, Number(body.app_version_code)) : 0;
      const platform = body.platform === "android_tv" ? "android_tv" : "android";
      const abi = ["armeabi-v7a","arm64-v8a","x86","x86_64"].includes(String(body.app_abi))
        ? String(body.app_abi) : "unknown";
      const channel = body.channel === "beta" ? "beta" : "stable";
      const { data: candidates, error: releaseError } = await db.from("app_releases")
        .select("id,channel,version_name,version_code,apk_url,release_url,sha256,apk_size_bytes,release_notes,update_policy,target_platform,target_abis,min_supported_version_code,published_at,app_release_targets(device_id)")
        .eq("channel", channel).eq("status", "published")
        .gt("version_code", currentVersionCode)
        .order("version_code", { ascending: false }).limit(100);
      if (releaseError) return fail("update_check_failed", 500, releaseError.message);
      const compatible = (candidates ?? []).filter((release: {
        target_platform:string; target_abis:string[]; min_supported_version_code:number;
        app_release_targets:Array<{device_id:string}>;
      }) => {
        const platformMatches = release.target_platform === "all" || release.target_platform === platform;
        const abiMatches = release.target_abis.includes("all") || release.target_abis.includes(abi);
        const targets = release.app_release_targets ?? [];
        const deviceMatches = targets.length === 0 || targets.some((target) => target.device_id === device.id);
        return platformMatches && abiMatches && deviceMatches;
      });
      const release = compatible[0];
      if (!release) return reply({
        status: "active", update_available: false,
        current_version_code: currentVersionCode, channel,
      });
      const mandatory = release.update_policy === "mandatory"
        || currentVersionCode < Number(release.min_supported_version_code ?? 0);
      return reply({
        status: "active", update_available: true,
        current_version_code: currentVersionCode,
        update: {
          id: release.id, channel: release.channel,
          version_name: release.version_name, version_code: release.version_code,
          apk_url: release.apk_url, release_url: release.release_url,
          sha256: release.sha256, apk_size_bytes: release.apk_size_bytes,
          release_notes: release.release_notes,
          update_policy: mandatory ? "mandatory" : "optional",
          min_supported_version_code: release.min_supported_version_code,
          published_at: release.published_at,
        },
      });
    }

    if (action === "audio.sources") {
      const { data, error } = await db.from("device_audio_sources")
        .select("m3u_url,updated_at").eq("device_id", device.id).maybeSingle();
      if (error) return fail("audio_sources_fetch_failed", 500, error.message);
      return reply({
        status: "active",
        configured: Boolean(data?.m3u_url),
        m3u_url: data?.m3u_url ?? null,
        updated_at: data?.updated_at ?? null,
      });
    }

    if (action === "message.ack") {
      const messageId = String(body.message_id ?? "");
      if (!messageId) return fail("message_id_required");
      const { error } = await db.from("device_message_receipts").upsert({
        message_id: messageId, device_id: device.id, acknowledged_at: new Date().toISOString(),
      }, { onConflict: "message_id,device_id" });
      if (error) return fail("message_ack_failed", 500, error.message);
      return reply({ success: true });
    }

    if (action === "theme.set") {
      const themeId = String(body.theme_id ?? "");
      if (!themeId) return fail("theme_id_required");
      const { data: theme, error: themeError } = await db.from("app_themes").select("id").eq("id", themeId).eq("is_active", true).maybeSingle();
      if (themeError || !theme) return fail("theme_not_found", 404);
      const { error } = await db.from("device_theme_preferences").upsert({
        device_id: device.id, theme_id: themeId, updated_at: new Date().toISOString(),
      }, { onConflict: "device_id" });
      if (error) return fail("theme_preference_failed", 500, error.message);
      return reply({ success: true });
    }

    const [{ data: availableServers, error: serverError }, { data: themes, error: themeError }, { data: preference }, { data: receipts, error: receiptError }] = await Promise.all([
      db.from("servers").select("id,name,region,server_url,is_active").eq("is_active", true).order("priority"),
      db.from("app_themes").select("id,name,palette,is_default").eq("is_active", true).order("sort_order"),
      db.from("device_theme_preferences").select("theme_id").eq("device_id", device.id).maybeSingle(),
      db.from("device_message_receipts").select("message_id").eq("device_id", device.id).not("acknowledged_at", "is", null),
    ]);
    if (serverError || themeError || receiptError) return fail("device_sync_failed", 500, serverError?.message ?? themeError?.message ?? receiptError?.message);
    const acknowledged = new Set((receipts ?? []).map((r: {message_id:string}) => r.message_id));
    const { data: messages, error: messageError } = await db.from("app_messages")
      .select("id,title,body,message_type,publish_at")
      .eq("is_published", true).gt("created_at", device.first_seen_at).lte("publish_at", new Date().toISOString())
      .or("expires_at.is.null,expires_at.gt." + new Date().toISOString())
      .or("target_type.eq.all,and(target_type.eq.device,target_device_id.eq." + device.id + ")")
      .order("publish_at", { ascending: true }).limit(100);
    if (messageError) return fail("messages_fetch_failed", 500, messageError.message);
    const pendingMessages = (messages ?? []).filter((m: {id:string}) => !acknowledged.has(m.id));
    const theme = (themes ?? []).find((t: {id:string,is_default:boolean}) => t.id === preference?.theme_id)
      ?? (themes ?? []).find((t: {is_default:boolean}) => t.is_default)
      ?? (themes ?? [])[0] ?? null;
    return reply({
      status: "active",
      servers: availableServers ?? [],
      themes: themes ?? [],
      theme,
      messages: pendingMessages,
    });
  } catch (error) {
    console.error("sonix_device_api_error", error);
    return fail("internal_error", 500, error instanceof Error ? error.message : "unknown");
  }
});
