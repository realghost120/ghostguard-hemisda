import express from "express";
import crypto from "crypto";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";


const app = express();

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_EVIDENCE_BUCKET = process.env.SUPABASE_EVIDENCE_BUCKET || "ban-evidence";

const LICENSE_SECRET = process.env.LICENSE_SECRET || "change_me";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";


// (valfritt) sätt din Netlify-domän här för striktare CORS
// ex: https://ghostguard-panel.netlify.app
const DASHBOARD_ORIGIN = process.env.DASHBOARD_ORIGIN || null;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("⚠️ Missing SUPABASE env vars. API will fail on DB calls.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

/* ================= MIDDLEWARE ================= */
app.use(express.json({ limit: "2mb" }));

const corsOptions = {
  origin: DASHBOARD_ORIGIN ? [DASHBOARD_ORIGIN] : true,
  credentials: false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

/* ================= HELPERS ================= */
function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function requireAdmin(req, res) {
  const bearer = req.headers.authorization || "";
  const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : null;

  if (!ADMIN_SECRET || token !== ADMIN_SECRET) {
    res.status(401).json({ success: false, error: "UNAUTHORIZED" });
    return false;
  }
  return true;
}

function generateLicenseKey() {
  const part = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `GG-${part()}-${part()}`;
}

function computeExpiresAt(duration, explicitExpiresAt) {
  if (explicitExpiresAt) return new Date(explicitExpiresAt).toISOString();

  const raw = String(duration || "P").trim().toLowerCase();
  if (raw === "p" || raw === "perm" || raw === "permanent") return null;

  const match = raw.match(/^(\d+)([mhd])$/);
  if (!match) return null;

  const amount = Number(match[1]);
  const unit = match[2];
  const ms = unit === "m" ? amount * 60_000 : unit === "h" ? amount * 3_600_000 : amount * 86_400_000;
  return new Date(Date.now() + ms).toISOString();
}

function normalizeIdentifiers(value) {
  if (!Array.isArray(value)) return [];
  const cleaned = value
    .map((x) => String(x || "").trim())
    .filter(Boolean);
  return [...new Set(cleaned)];
}

function extractDataUriParts(imageData) {
  const m = String(imageData || "").match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
  if (!m) return null;
  return { mime: m[1], base64: m[2] };
}

/* ================= NEW: PANEL ADMINS HELPERS ================= */
// Generates a one-time invite token (we store only hash in DB)
function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

// Existing dashboard uses token in req.body (customers.id).
async function requireCustomer(req, res) {
  const token = req.body?.token || null;
  if (!token) {
    res.status(401).json({ success: false, error: "UNAUTHORIZED" });
    return null;
  }

  const { data: user, error } = await supabase
    .from("customers")
    .select("*")
    .eq("id", token)
    .single();

  if (error || !user) {
    res.status(401).json({ success: false, error: "UNAUTHORIZED" });
    return null;
  }

  return user;
}

// Allows both customers (token=customers.id) and panel admins (token=invite_token)
async function resolvePanelIdentity(token) {
  if (!token) return null;

  // 1) customer session token (customers.id)
  const { data: user } = await supabase.from("customers").select("*").eq("id", token).single();
  if (user) return { kind: "customer", license_key: user.license_key, user };

  // 2) panel admin invite token
  const token_hash = sha256(token);
  const { data: admin } = await supabase
    .from("panel_admins")
    .select("*")
    .eq("token_hash", token_hash)
    .eq("active", true)
    .single();

  if (admin) return { kind: "admin", license_key: admin.license_key, admin };

  return null;
}

/* ================= ROOT ================= */
app.get("/", (req, res) => res.send("GhostGuard Backend OK"));
app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

/* ================= LICENSE VERIFY ================= */
app.post("/api/license/verify", async (req, res) => {
  try {
    const { license_key, hwid } = req.body || {};
    if (!license_key) return res.status(400).json({ valid: false, reason: "MISSING_KEY" });

    const { data: lic, error } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (error || !lic) return res.json({ valid: false, reason: "NOT_FOUND" });
    if (lic.status !== "ACTIVE") return res.json({ valid: false, reason: lic.status });

    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      return res.json({ valid: false, reason: "EXPIRED" });
    }

    // HWID bind
    if (lic.hwid) {
      if (hwid && lic.hwid !== hwid) return res.json({ valid: false, reason: "HWID_MISMATCH" });
    } else if (hwid) {
      await supabase.from("licenses").update({ hwid }).eq("id", lic.id);
    }

    await supabase.from("licenses").update({ last_seen: new Date().toISOString() }).eq("id", lic.id);

    const payload = JSON.stringify({
      license_key,
      status: lic.status,
      expires_at: lic.expires_at,
      issued_at: Date.now(),
    });

    const signature = crypto.createHmac("sha256", LICENSE_SECRET).update(payload).digest("hex");

    return res.json({ valid: true, payload, signature });
  } catch (err) {
    console.error("verify error:", err);
    return res.status(500).json({ valid: false, reason: "SERVER_ERROR" });
  }
});



/* ================= BANS ================= */

app.post("/api/server/ban", async (req,res)=>{
  try{
    const {
      license_key,
      player,
      reason,
      duration,
      ban_id,
      evidence_url,
      banned_by,
      identifiers,
      created_at,
      expires_at
    } = req.body || {};

    if(!license_key || !player) {
      return res.status(400).json({success:false});
    }

    const finalBanId = ban_id || ("GG-" + Date.now());
    const finalDuration = duration || "P";
    const finalCreatedAt = created_at ? new Date(created_at).toISOString() : new Date().toISOString();
    const finalExpiresAt = computeExpiresAt(finalDuration, expires_at);
    const finalIdentifiers = normalizeIdentifiers(identifiers);

    await supabase.from("bans").insert([{
      license_key,
      player_id: player,
      reason: reason || "No reason",
      duration: finalDuration,
      ban_id: finalBanId,
      created_at: finalCreatedAt,
      expires_at: finalExpiresAt,
      banned_by: banned_by || "GhostGuard",
      evidence_url: evidence_url || null,
      identifiers: finalIdentifiers
    }]);

    res.json({success:true, ban_id: finalBanId});
  }catch(e){
    console.log(e);
    res.status(500).json({success:false});
  }
});




app.get("/api/server/bans/:license", async (req,res)=>{
  try{
    const { data } = await supabase
      .from("bans")
      .select("*")
      .eq("license_key", req.params.license)
      .order("created_at", {ascending:false});

    res.json({success:true, data});
  }catch(e){
    res.status(500).json({success:false});
  }
});

app.post("/api/server/ban/check", async (req, res) => {
  try {
    const { license_key, identifiers } = req.body || {};
    if (!license_key || !Array.isArray(identifiers)) {
      return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
    }

    const identifierArray = normalizeIdentifiers(identifiers);

    const { data, error } = await supabase.rpc("find_active_ban", {
      p_license_key: license_key,
      p_identifiers: identifierArray,
    });

    if (error) {
      console.error("ban/check rpc error:", error);
      return res.status(500).json({ success: false, error: "DB_ERROR" });
    }

    const ban = Array.isArray(data) ? data[0] : null;
    return res.json({ success: true, banned: !!ban, ban: ban || null });
  } catch (e) {
    console.error("ban/check error:", e);
    return res.status(500).json({ success: false });
  }
});

app.post("/api/server/ban/evidence", async (req, res) => {
  try {
    const { license_key, ban_id, image_data } = req.body || {};
    if (!license_key || !ban_id || !image_data) {
      return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
    }

    const parsed = extractDataUriParts(image_data);
    if (!parsed) {
      return res.status(400).json({ success: false, error: "INVALID_IMAGE_DATA" });
    }

    const ext = parsed.mime.includes("png") ? "png" : "jpg";
    const objectPath = `${license_key}/${ban_id}-${Date.now()}.${ext}`;
    const binary = Buffer.from(parsed.base64, "base64");

    const { error: uploadError } = await supabase.storage
      .from(SUPABASE_EVIDENCE_BUCKET)
      .upload(objectPath, binary, {
        contentType: parsed.mime,
        upsert: true,
      });

    if (uploadError) {
      console.error("evidence upload error:", uploadError);
      return res.status(500).json({ success: false, error: "UPLOAD_FAILED" });
    }

    const { data: urlData } = supabase.storage
      .from(SUPABASE_EVIDENCE_BUCKET)
      .getPublicUrl(objectPath);

    const publicUrl = urlData?.publicUrl || null;
    if (!publicUrl) {
      return res.status(500).json({ success: false, error: "PUBLIC_URL_FAILED" });
    }

    await supabase
      .from("bans")
      .update({ evidence_url: publicUrl })
      .eq("license_key", license_key)
      .eq("ban_id", ban_id);

    return res.json({ success: true, evidence_url: publicUrl });
  } catch (e) {
    console.error("ban/evidence error:", e);
    return res.status(500).json({ success: false });
  }
});

app.delete("/api/server/unban/:banId", async (req, res) => {
  try {
    const { banId } = req.params;
    const bearer = req.headers.authorization || "";
    const token = bearer.startsWith("Bearer ") ? bearer.slice(7) : null;
    const identity = await resolvePanelIdentity(token);

    if (!identity) {
      return res.status(401).json({ success: false, error: "UNAUTHORIZED" });
    }

    // 1️⃣ Hämta ban så vi vet license_key
    const { data: ban } = await supabase
      .from("bans")
      .select("*")
      .eq("ban_id", banId)
      .single();

    if (!ban) {
      return res.json({ success: false });
    }

    if (ban.license_key !== identity.license_key) {
      return res.status(403).json({ success: false, error: "FORBIDDEN" });
    }

    await supabase
      .from("bans")
      .update({ expires_at: new Date().toISOString() })
      .eq("ban_id", banId);

    // 3️⃣ SKICKA action till FiveM-servern
    pushAction(ban.license_key, {
      id: "ACT-" + Date.now(),
      type: "unban",
      payload: {
        ban_id: banId
      },
      created_at: new Date().toISOString()
    });

    return res.json({ success: true });

  } catch (e) {
    console.log("UNBAN ERROR:", e);
    return res.status(500).json({ success: false });
  }
});

app.delete("/api/server/ban/:banId", async (req, res) => {
  try {
    const { banId } = req.params;
    await supabase
      .from("bans")
      .update({ expires_at: new Date().toISOString() })
      .eq("ban_id", banId);

    return res.json({ success: true });
  } catch (e) {
    console.log("UNBAN LEGACY ERROR:", e);
    return res.status(500).json({ success: false });
  }
});




/* ================= LIVE MEMORY (status + players) ================= */
const serverState = {}; // { [license_key]: { last_seen, players, uptime, version } }
const livePlayersByLicense = {}; // { [license_key]: [{id,name,ping,identifiers?}] }

/* ===== HEARTBEAT ===== */
app.post("/api/server/heartbeat", async (req, res) => {
  try {
    const { license_key, players, version, uptime } = req.body || {};
    if (!license_key) return res.status(400).json({ success: false, error: "MISSING_LICENSE" });

    livePlayersByLicense[license_key] = Array.isArray(players) ? players : [];

    serverState[license_key] = {
      last_seen: Date.now(),
      players: livePlayersByLicense[license_key].length,
      uptime: Number(uptime || 0),
      version: version || null,
    };

    // Optional: persist status
    try {
      await supabase.from("server_status").upsert({
        license_key,
        online: true,
        players: livePlayersByLicense[license_key].length,
        version: version || null,
        uptime: Number(uptime || 0),
        last_seen: new Date().toISOString(),
      });
    } catch (dbErr) {
      // ignore if table missing
    }

    return res.json({ success: true });
  } catch (e) {
    console.error("heartbeat error:", e);
    return res.status(500).json({ success: false });
  }
});

app.get("/api/server/players/:license", (req, res) => {
  const license = req.params.license;
  return res.json({ success: true, players: livePlayersByLicense[license] || [] });
});

app.get("/api/server/status/:license", (req, res) => {
  const license = req.params.license;
  const data = serverState[license];

  if (!data) return res.json({ online: false, players: 0, uptime: 0, version: null });

  const online = Date.now() - data.last_seen < 30000;

  return res.json({
    online,
    players: data.players || 0,
    uptime: data.uptime || 0,
    version: data.version || null,
    last_seen: data.last_seen,
  });
});

/* ================= ACTION QUEUE (Dashboard -> FiveM poll) ================= */
const actionQueue = {}; // { [license_key]: [ {id, type, payload, created_at} ] }

function pushAction(license_key, action) {
  actionQueue[license_key] = actionQueue[license_key] || [];
  actionQueue[license_key].push(action);
  if (actionQueue[license_key].length > 200) actionQueue[license_key].splice(0, 50);
}

// Dashboard: create action (auth via token = customers.id OR panel admin invite token)
app.post("/api/dashboard/action", async (req, res) => {
  try {
    const { token, type, payload } = req.body || {};
    if (!token || !type) return res.status(400).json({ success: false, error: "MISSING_FIELDS" });

    // NEW: allow both customers and panel admins
    const identity = await resolvePanelIdentity(token);
    if (!identity) return res.status(401).json({ success: false, error: "UNAUTHORIZED" });

    const license_key = identity.license_key;
    const id = "ACT-" + Date.now() + "-" + Math.floor(Math.random() * 9999);

    pushAction(license_key, {
      id,
      type, // "kick" | "ban" | "dm" | "freeze"
      payload: payload || {},
      created_at: new Date().toISOString(),
    });

    return res.json({ success: true, id });
  } catch (e) {
    console.error("dashboard/action error:", e);
    return res.status(500).json({ success: false });
  }
});

// FiveM: get actions (poll)
// NOTE: clears queue after fetch
app.get("/api/server/actions/:license", (req, res) => {
  const license_key = req.params.license;
  const list = actionQueue[license_key] || [];
  actionQueue[license_key] = [];
  return res.json({ success: true, actions: list });
});

/* ================= LOGS (Live + Persist) ================= */
// In-memory logs for fast “live view”
const serverLogs = {}; // { [license_key]: [{id,time,level,type,title,message,meta}] }

function pushServerLog(license_key, item) {
  serverLogs[license_key] = serverLogs[license_key] || [];
  serverLogs[license_key].unshift(item);
  if (serverLogs[license_key].length > 300) serverLogs[license_key].length = 300;
}

// FiveM -> backend: send log
// body: { license_key, level?, type?, title?, message, meta? }
app.post("/api/server/log", async (req, res) => {
  try {
    const { license_key, level, type, title, message, meta } = req.body || {};
    if (!license_key || !message) {
      return res.status(400).json({ success: false, error: "MISSING_LICENSE_OR_MESSAGE" });
    }

    const item = {
      id: "LOG-" + Date.now() + "-" + Math.floor(Math.random() * 9999),
      time: new Date().toISOString(),
      level: level || "info",
      type: type || "log",
      title: title || "Server",
      message,
      meta: meta || null,
    };

    // 1) live memory
    pushServerLog(license_key, item);

    // 2) persist to Supabase if table exists (optional)
    // Table suggestion: server_logs(license_key text, level text, type text, title text, message text, meta jsonb, created_at timestamp default now())
    try {
      await supabase.from("server_logs").insert([
        {
          license_key,
          level: item.level,
          type: item.type,
          title: item.title,
          message: item.message,
          meta: item.meta,
        },
      ]);
    } catch (dbErr) {
      // ignore if missing table / RLS / etc.
    }

    return res.json({ success: true });
  } catch (e) {
    console.error("server/log error:", e);
    return res.status(500).json({ success: false });
  }
});

// Dashboard -> get logs
// returns BOTH "data" and "logs" to prevent UI mismatch
app.get("/api/server/logs/:license", async (req, res) => {
  const license_key = req.params.license;
  const limit = Math.min(parseInt(req.query.limit || "200", 10), 500);

  // Prefer DB logs if available, fallback to memory
  try {
    const { data, error } = await supabase
      .from("server_logs")
      .select("id, license_key, level, type, title, message, meta, created_at")
      .eq("license_key", license_key)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (!error && Array.isArray(data)) {
      const mapped = data.map((x) => ({
        id: x.id || ("DB-" + x.created_at),
        time: x.created_at,
        level: x.level || "info",
        type: x.type || "log",
        title: x.title || "Server",
        message: x.message,
        meta: x.meta ?? null,
      }));

      return res.json({ success: true, data: mapped, logs: mapped });
    }
  } catch (e) {
    // ignore, fallback below
  }

  const mem = (serverLogs[license_key] || []).slice(0, limit);
  return res.json({ success: true, data: mem, logs: mem });
});

/* ================= LOGIN ================= */
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.json({ success: false });

    const hash = sha256(password);

    const { data: user, error } = await supabase
      .from("customers")
      .select("*")
      .eq("username", username)
      .eq("password", hash)
      .single();

    if (error || !user) return res.json({ success: false });

    return res.json({ success: true, license_key: user.license_key, token: user.id });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ success: false });
  }
});

/* ================= NEW: PANEL ADMINS ROUTES ================= */
/**
 * Required Supabase table (run in SQL editor):
 *
 * create table if not exists public.panel_admins (
 *   id uuid primary key default gen_random_uuid(),
 *   license_key text not null,
 *   name text not null,
 *   steam text,
 *   discord text,
 *   role text not null default 'admin',
 *   active boolean not null default true,
 *   token_hash text not null,
 *   created_at timestamptz not null default now()
 * );
 * create index if not exists idx_panel_admins_license_key on public.panel_admins (license_key);
 * create unique index if not exists uq_panel_admins_token_hash on public.panel_admins (token_hash);
 */

// Owner (customer) lists admins for their license
app.post("/api/panel/admins/list", async (req, res) => {
  try {
    const user = await requireCustomer(req, res);
    if (!user) return;

    const { data, error } = await supabase
      .from("panel_admins")
      .select("id, name, steam, discord, role, active, created_at")
      .eq("license_key", user.license_key)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ success: false, error: "DB_ERROR" });
    return res.json({ success: true, data: data || [] });
  } catch (e) {
    console.error("panel/admins/list error:", e);
    return res.status(500).json({ success: false });
  }
});

// Owner (customer) adds an admin and receives invite_token ONCE
app.post("/api/panel/admins/add", async (req, res) => {
  try {
    const user = await requireCustomer(req, res);
    if (!user) return;

    const { name, steam, discord, role } = req.body || {};
    if (!name) return res.status(400).json({ success: false, error: "MISSING_NAME" });

    const invite_token = randomToken(24);
    const token_hash = sha256(invite_token);

    const { data, error } = await supabase
      .from("panel_admins")
      .insert([
        {
          license_key: user.license_key,
          name,
          steam: steam || null,
          discord: discord || null,
          role: role || "admin",
          active: true,
          token_hash,
        },
      ])
      .select("id, name, steam, discord, role, active, created_at")
      .single();

    if (error) return res.status(500).json({ success: false, error: "DB_ERROR" });

    return res.json({ success: true, admin: data, invite_token });
  } catch (e) {
    console.error("panel/admins/add error:", e);
    return res.status(500).json({ success: false });
  }
});

// Owner (customer) removes an admin
app.post("/api/panel/admins/remove", async (req, res) => {
  try {
    const user = await requireCustomer(req, res);
    if (!user) return;

    const { id } = req.body || {};
    if (!id) return res.status(400).json({ success: false, error: "MISSING_ID" });

    const { error } = await supabase
      .from("panel_admins")
      .delete()
      .eq("id", id)
      .eq("license_key", user.license_key);

    if (error) return res.status(500).json({ success: false, error: "DB_ERROR" });
    return res.json({ success: true });
  } catch (e) {
    console.error("panel/admins/remove error:", e);
    return res.status(500).json({ success: false });
  }
});

// Owner (customer) toggles active
app.post("/api/panel/admins/toggle", async (req, res) => {
  try {
    const user = await requireCustomer(req, res);
    if (!user) return;

    const { id, active } = req.body || {};
    if (!id || typeof active !== "boolean") {
      return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
    }

    const { error } = await supabase
      .from("panel_admins")
      .update({ active })
      .eq("id", id)
      .eq("license_key", user.license_key);

    if (error) return res.status(500).json({ success: false, error: "DB_ERROR" });
    return res.json({ success: true });
  } catch (e) {
    console.error("panel/admins/toggle error:", e);
    return res.status(500).json({ success: false });
  }
});

// Panel admin login using invite_token
app.post("/api/panel/admins/login", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ success: false });

    const identity = await resolvePanelIdentity(token);
    if (!identity || identity.kind !== "admin") return res.json({ success: false });

    return res.json({
      success: true,
      license_key: identity.license_key,
      admin: {
        id: identity.admin.id,
        name: identity.admin.name,
        role: identity.admin.role,
      },
      token, // client stores same token
    });
  } catch (e) {
    console.error("panel/admins/login error:", e);
    return res.status(500).json({ success: false });
  }
});

/* ================= CUSTOMER ================= */
app.post("/customer/dashboard", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(401).json({ success: false });

    const { data: user } = await supabase.from("customers").select("*").eq("id", token).single();
    if (!user) return res.status(401).json({ success: false });

    const { data: lic } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", user.license_key)
      .single();

    if (!lic) return res.status(404).json({ success: false });

    return res.json({
      success: true,
      data: { license_key: lic.license_key, status: lic.status, expires_at: lic.expires_at },
    });
  } catch (err) {
    console.error("customer/dashboard error:", err);
    return res.status(500).json({ success: false });
  }
});

app.post("/customer/toggle", async (req, res) => {
  try {
    const { token, status } = req.body || {};
    if (!token || !status) return res.status(400).json({ success: false });

    const { data: user } = await supabase.from("customers").select("*").eq("id", token).single();
    if (!user) return res.status(401).json({ success: false });

    await supabase.from("licenses").update({ status }).eq("license_key", user.license_key);
    return res.json({ success: true });
  } catch (err) {
    console.error("customer/toggle error:", err);
    return res.status(500).json({ success: false });
  }
});

/* ================= ADMIN ================= */
app.post("/admin/create-license", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const days = Number(req.body?.days_valid || 0);
    let expires_at = null;

    if (days > 0) {
      const d = new Date();
      d.setDate(d.getDate() + days);
      expires_at = d.toISOString();
    }

    const license_key = generateLicenseKey();
    await supabase.from("licenses").insert([{ license_key, status: "ACTIVE", expires_at, hwid: null }]);

    return res.json({ success: true, license_key });
  } catch (err) {
    console.error("admin/create-license error:", err);
    return res.status(500).json({ success: false });
  }
});

app.get("/admin/licenses", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { data } = await supabase.from("licenses").select("*").order("created_at", { ascending: false });
    return res.json({ success: true, data: data || [] });
  } catch (err) {
    console.error("admin/licenses error:", err);
    return res.status(500).json({ success: false });
  }
});

app.post("/admin/toggle-license", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { license_key, status } = req.body || {};
    if (!license_key || !status) return res.status(400).json({ success: false });

    await supabase.from("licenses").update({ status }).eq("license_key", license_key);
    return res.json({ success: true });
  } catch (err) {
    console.error("admin/toggle-license error:", err);
    return res.status(500).json({ success: false });
  }
});


app.post("/admin/create-customer", async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;

    const { username, password, license_key } = req.body || {};

    if (!username || !password || !license_key) {
      return res.status(400).json({ success: false, error: "MISSING_FIELDS" });
    }

    // kolla att license finns
    const { data: lic } = await supabase
      .from("licenses")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (!lic) {
      return res.status(404).json({ success: false, error: "LICENSE_NOT_FOUND" });
    }

    const password_hash = sha256(password);

    const { data, error } = await supabase
      .from("customers")
      .insert([
        {
          username,
          password: password_hash,
          license_key,
        },
      ])
      .select()
      .single();

    if (error) {
      console.error("create-customer error:", error);
      return res.status(500).json({ success: false, error: "DB_ERROR" });
    }

    return res.json({ success: true, customer: data });
  } catch (err) {
    console.error("admin/create-customer error:", err);
    return res.status(500).json({ success: false });
  }
});



/* ================= DETECTION SETTINGS ================= */

// Ensure row exists for license
async function ensureDetectionRow(license_key) {
  const { data } = await supabase
    .from("detection_settings")
    .select("license_key")
    .eq("license_key", license_key)
    .single();

  if (!data) {
    await supabase.from("detection_settings").insert([{ license_key }]);
  }
}

// GET detections (FiveM + Dashboard)
app.get("/api/server/detections/:license", async (req, res) => {
  try {
    const license_key = req.params.license;
    if (!license_key) return res.json({ success: false });

    await ensureDetectionRow(license_key);

    const { data, error } = await supabase
      .from("detection_settings")
      .select("*")
      .eq("license_key", license_key)
      .single();

    if (error || !data) return res.json({ success: false });

    return res.json({ success: true, settings: data });
  } catch (e) {
    console.error("detections GET error:", e);
    return res.status(500).json({ success: false });
  }
});

// UPDATE detection (Dashboard toggle)
app.post("/api/dashboard/detections", async (req, res) => {
  try {
    const { token, license_key, key, value } = req.body || {};
    if (!token || !license_key || !key) {
      return res.status(400).json({ success: false });
    }

    // allow both customers and panel admins
    const identity = await resolvePanelIdentity(token);
    if (!identity || identity.license_key !== license_key) {
      return res.status(401).json({ success: false });
    }

    const allowedKeys = [
      "noclip",
      "speed",
      "explosions",
      "vehicleSpam",
      "blacklistedVehicle",
      "godmode"
    ];

    if (!allowedKeys.includes(key)) {
      return res.status(400).json({ success: false });
    }

    await ensureDetectionRow(license_key);

    const { error } = await supabase
      .from("detection_settings")
      .update({
        [key]: Boolean(value),
        updated_at: new Date().toISOString()
      })
      .eq("license_key", license_key);

    if (error) return res.status(500).json({ success: false });

    return res.json({ success: true });
  } catch (e) {
    console.error("detections UPDATE error:", e);
    return res.status(500).json({ success: false });
  }
});


app.get("/version", (req, res) => {
  res.json({
    version: "3.1.0",
    download: "https://ghostguard.com/download",
    notes: "Stability improvements & detection optimizations"
  });
});



/* ================= START ================= */
app.listen(PORT, () => console.log("GhostGuard backend running on", PORT));
