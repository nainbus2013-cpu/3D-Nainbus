// api/state.js — sauvegarde en ligne pour 3D Nainbus (Vercel + Upstash Redis)
// Variables d'environnement attendues sur Vercel :
//   KV_REST_API_URL + KV_REST_API_TOKEN   (ou UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)
//   SESSION_SECRET                         (une longue phrase au hasard)
const crypto = require("crypto");

const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN_ = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SECRET = process.env.SESSION_SECRET || ("nb-" + (TOKEN_ || "dev"));

// Identifiant / mot de passe d'origine (mêmes empreintes que dans index.html)
const AUTH = {
  u: "6aeadee6393f09bcc86fc51cd989c5399e90b69a830de1c9fde4cc292f9467f5",
  p: "d15aa519613b2ba812c6be6091d4fe70e9dd37768dca1323603b15778f1162a3",
};
const ADMIN_KEYS = ["clients", "tickets", "stock", "logo", "reviews", "messages"];
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const uid = () => Date.now().toString(36) + crypto.randomBytes(3).toString("hex");

async function redis(...cmd) {
  const r = await fetch(URL_, {
    method: "POST",
    headers: { Authorization: "Bearer " + TOKEN_ },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
const getK = async (k, d = null) => { const v = await redis("GET", "nb3:" + k); return v == null ? d : JSON.parse(v); };
const setK = (k, v) => redis("SET", "nb3:" + k, JSON.stringify(v));

// --- Jeton de session signé (12 h) ---
function makeToken() {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600 * 1000 })).toString("base64url");
  return p + "." + crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
}
function checkToken(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [p, sig] = t.split(".");
  if (!p || !sig) return false;
  const good = crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return false;
  try { return JSON.parse(Buffer.from(p, "base64url").toString()).exp > Date.now(); } catch (e) { return false; }
}

// --- Limite de tentatives par adresse IP ---
async function limit(req, name, max, secs, msg) {
  const ip = String(req.headers["x-forwarded-for"] || "x").split(",")[0].trim();
  const k = `nb3:rl:${name}:${ip}`;
  const n = await redis("INCR", k);
  if (n === 1) await redis("EXPIRE", k, secs);
  if (n > max) { const e = new Error(msg); e.status = 429; throw e; }
}
const bad = (m, s = 400) => Object.assign(new Error(m), { status: s });
const clean = (v, n) => String(v == null ? "" : v).trim().slice(0, n);

async function passOk(p) {
  const st = await getK("pass");
  return st ? sha(st.salt + p) === st.hash : sha("nb-pw:" + p) === AUTH.p;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    if (!URL_ || !TOKEN_) throw bad("Base de données non configurée", 500);

    // Lecture publique : avis + logo (jamais les messages)
    if (req.method === "GET") {
      return res.status(200).json({ reviews: (await getK("reviews", [])) || [], logo: await getK("logo") });
    }
    if (req.method !== "POST") throw bad("Méthode non autorisée", 405);

    const b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const a = b.action;

    // ----- Actions publiques -----
    if (a === "login") {
      await limit(req, "login", 8, 600, "Trop de tentatives. Réessayez dans 10 minutes.");
      const okU = sha("nb-id:" + clean(b.user, 60).toLowerCase()) === AUTH.u;
      const okP = await passOk(String(b.pass || ""));
      if (!okU || !okP) throw bad("Identifiant ou mot de passe incorrect.", 401);
      return res.status(200).json({ token: makeToken() });
    }
    if (a === "review") {
      await limit(req, "review", 5, 3600, "Trop d'avis envoyés. Réessayez plus tard.");
      const name = clean(b.name, 30), text = clean(b.text, 600), rating = Math.round(Number(b.rating));
      if (!name || text.length < 5 || !(rating >= 1 && rating <= 5)) throw bad("Avis invalide.");
      const l = (await getK("reviews", [])) || [];
      l.unshift({ id: uid(), name, rating, text, date: Date.now() });
      await setK("reviews", l.slice(0, 500));
      return res.status(200).json({ reviews: l.slice(0, 500) });
    }
    if (a === "message") {
      await limit(req, "message", 6, 3600, "Trop de messages envoyés. Réessayez plus tard.");
      const name = clean(b.name, 30), text = clean(b.text, 1200), topic = clean(b.topic, 60);
      const via = ["site", "mail", "tel"].includes(b.replyVia) ? b.replyVia : "";
      if (!name || text.length < 10) throw bad("Message invalide.");
      const l = (await getK("messages", [])) || [];
      const m = { id: uid(), date: Date.now(), name, topic, text, replyVia: via, contact: via === "site" ? "" : clean(b.contact, 80), read: false };
      l.unshift(m);
      await setK("messages", l.slice(0, 500));
      return res.status(200).json({ id: m.id });
    }
    if (a === "replies") {
      const ids = Array.isArray(b.ids) ? b.ids.slice(0, 30) : [];
      const l = (await getK("messages", [])) || [];
      const out = {};
      l.forEach(m => { if (ids.includes(m.id) && m.reply) out[m.id] = m.reply; });
      return res.status(200).json({ replies: out });
    }

    // ----- Actions réservées au gérant -----
    if (!checkToken(req)) throw bad("Non autorisé", 401);

    if (a === "logout") return res.status(200).json({ ok: true });
    if (a === "verify") return res.status(200).json({ ok: await passOk(String(b.pass || "")) });
    if (a === "all") {
      const out = {};
      for (const k of ADMIN_KEYS) out[k] = await getK(k, ["clients", "tickets", "reviews", "messages"].includes(k) ? [] : null);
      return res.status(200).json(out);
    }
    if (a === "set") {
      if (!ADMIN_KEYS.includes(b.key)) throw bad("Clé inconnue");
      await setK(b.key, b.value);
      return res.status(200).json({ ok: true });
    }
    if (a === "changePass") {
      const p = String(b.pass || "");
      if (!/^\d{6,}$/.test(p)) throw bad("Chiffres uniquement, 6 minimum.");
      const salt = uid();
      await setK("pass", { salt, hash: sha(salt + p) });
      return res.status(200).json({ ok: true });
    }
    if (a === "delReview") {
      const l = ((await getK("reviews", [])) || []).filter(r => r.id !== b.id);
      await setK("reviews", l);
      return res.status(200).json({ reviews: l });
    }
    if (["markRead", "delMessage", "reply"].includes(a)) {
      let l = (await getK("messages", [])) || [];
      if (a === "delMessage") l = l.filter(m => m.id !== b.id);
      else {
        const m = l.find(x => x.id === b.id);
        if (!m) throw bad("Message introuvable.", 404);
        if (a === "markRead") m.read = !!b.read;
        if (a === "reply") { m.reply = { text: clean(b.text, 1500), date: Date.now() }; m.read = true; }
      }
      await setK("messages", l);
      return res.status(200).json({ messages: l });
    }
    throw bad("Action inconnue");
  } catch (e) {
    return res.status(e.status || 500).json({ error: e.status ? e.message : "Erreur serveur" });
  }
};
