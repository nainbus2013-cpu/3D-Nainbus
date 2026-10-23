// api/state.js — sauvegarde en ligne pour 3D Nainbus (Vercel + Upstash Redis)
// Variables Vercel : KV_REST_API_URL + KV_REST_API_TOKEN
// ou UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN
// ou REDIS_URL / KV_URL / STORAGE_URL ; SESSION_SECRET recommandé.

const crypto = require("crypto");

const REST_URL =
  process.env.KV_REST_API_URL ||
  process.env.UPSTASH_REDIS_REST_URL;

const REST_TOKEN =
  process.env.KV_REST_API_TOKEN ||
  process.env.UPSTASH_REDIS_REST_TOKEN;

const CONN =
  process.env.REDIS_URL ||
  process.env.KV_URL ||
  process.env.STORAGE_URL;

const SECRET =
  process.env.SESSION_SECRET ||
  ("nb-" + (REST_TOKEN || CONN || "dev"));

const AUTH = {
  u: "6aeadee6393f09bcc86fc51cd989c5399e90b69a830de1c9fde4cc292f9467f5",
  p: "d15aa519613b2ba8126cbe6091d4fe70e9dd37768dca1323603b15778f1162a3",
};

const ADMIN_KEYS = [
  "clients",
  "tickets",
  "stock",
  "logo",
  "reviews",
  "messages",
  "requests"
];

const sha = s =>
  crypto.createHash("sha256").update(s).digest("hex");

const uid = () =>
  Date.now().toString(36) + crypto.randomBytes(5).toString("hex");

const clean = (v, n) =>
  String(v == null ? "" : v).trim().slice(0, n);

const bad = (m, s = 400) =>
  Object.assign(new Error(m), { status: s });

let client = null;
let connecting = null;

async function getClient() {
  if (client && client.isReady) return client;

  if (!connecting) {
    const { createClient } = require("redis");

    const c = createClient({
      url: CONN,
      socket: { connectTimeout: 8000 }
    });

    c.on("error", () => {});

    c.on("end", () => {
      client = null;
      connecting = null;
    });

    connecting = c.connect()
      .then(() => {
        client = c;
        return c;
      })
      .catch(e => {
        connecting = null;
        throw e;
      });
  }

  return connecting;
}

async function redis(...cmd) {
  if (REST_URL && REST_TOKEN) {
    const r = await fetch(REST_URL, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + REST_TOKEN,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(cmd)
    });

    const j = await r.json();

    if (!r.ok || j.error) {
      throw new Error(j.error || "Erreur de base de données");
    }

    return j.result;
  }

  const c = await getClient();
  return c.sendCommand(cmd.map(String));
}

const getK = async (k, d = null) => {
  const v = await redis("GET", "nb3:" + k);
  return v == null ? d : JSON.parse(v);
};

const setK = (k, v) =>
  redis("SET", "nb3:" + k, JSON.stringify(v));

function makeToken(session) {
  const p = Buffer.from(
    JSON.stringify({
      ...session,
      exp: Date.now() + 12 * 3600 * 1000
    })
  ).toString("base64url");

  return p + "." + crypto
    .createHmac("sha256", SECRET)
    .update(p)
    .digest("base64url");
}

function checkToken(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";

  const [p, sig] = t.split(".");
  if (!p || !sig) return null;

  const good = crypto
    .createHmac("sha256", SECRET)
    .update(p)
    .digest("base64url");

  if (
    sig.length !== good.length ||
    !crypto.timingSafeEqual(
      Buffer.from(sig),
      Buffer.from(good)
    )
  ) {
    return null;
  }

  try {
    const session = JSON.parse(
      Buffer.from(p, "base64url").toString()
    );

    return (
      session.exp > Date.now() &&
      ["admin", "assistant"].includes(session.role)
    ) ? session : null;
  } catch (_) {
    return null;
  }
}

async function limit(req, name, max, secs, msg) {
  const ip = String(
    req.headers["x-forwarded-for"] || "x"
  ).split(",")[0].trim();

  const k = "nb3:rl:" + name + ":" + ip;
  const n = Number(await redis("INCR", k));

  if (n === 1) {
    await redis("EXPIRE", k, secs);
  }

  if (n > max) {
    throw bad(msg, 429);
  }
}

async function passOk(p) {
  const st = await getK("pass");

  return st
    ? sha(st.salt + p) === st.hash
    : sha("nb-pw:" + p) === AUTH.p;
}

function requireAdmin(session) {
  if (!session || session.role !== "admin") {
    throw bad("Accès réservé à un administrateur.", 403);
  }
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  try {
    if (!(REST_URL && REST_TOKEN) && !CONN) {
      throw bad("Base de données non configurée", 500);
    }

    if (req.method === "GET") {
      return res.status(200).json({
        reviews: (await getK("reviews", [])) || [],
        logo: await getK("logo")
      });
    }

    if (req.method !== "POST") {
      throw bad("Méthode non autorisée", 405);
    }

    const b = typeof req.body === "string"
      ? JSON.parse(req.body || "{}")
      : (req.body || {});

    const a = b.action;

    // Connexion
    if (a === "login") {
      await limit(
        req,
        "login",
        8,
        600,
        "Trop de tentatives. Réessayez dans 10 minutes."
      );

      const user = clean(b.user, 40).toLowerCase();
      const pass = String(b.pass || "");

      if (
        sha("nb-id:" + user) === AUTH.u &&
        await passOk(pass)
      ) {
        return res.status(200).json({
          token: makeToken({ role: "admin", user }),
          role: "admin",
          user
        });
      }

      const users = (await getK("users", [])) || [];

      const found = users.find(
        x =>
          x.user === user &&
          (x.role === "admin" || x.role === "assistant")
      );

      if (!found || sha(found.salt + pass) !== found.hash) {
        throw bad("Identifiant ou mot de passe incorrect.", 401);
      }

      return res.status(200).json({
        token: makeToken({
          role: found.role,
          user: found.user,
          uid: found.id
        }),
        role: found.role,
        user: found.user
      });
    }

    // Envoi public d'un avis
    if (a === "review") {
      await limit(
        req,
        "review",
        5,
        3600,
        "Trop d'avis envoyés. Réessayez plus tard."
      );

      const name = clean(b.name, 30);
      const text = clean(b.text, 600);
      const rating = Math.round(Number(b.rating));

      if (!name || text.length < 5 || !(rating >= 1 && rating <= 5)) {
        throw bad("Avis invalide.");
      }

      const l = (await getK("reviews", [])) || [];

      l.unshift({
        id: uid(),
        name,
        rating,
        text,
        date: Date.now()
      });

      await setK("reviews", l.slice(0, 500));

      return res.status(200).json({
        reviews: l.slice(0, 500)
      });
    }

    // Envoi public d'un message
    if (a === "message") {
      await limit(
        req,
        "message",
        6,
        3600,
        "Trop de messages envoyés. Réessayez plus tard."
      );

      const name = clean(b.name, 30);
      const text = clean(b.text, 1200);
      const topic = clean(b.topic, 60);

      const via = ["site", "mail", "tel"].includes(b.replyVia)
        ? b.replyVia
        : "";

      if (!name || text.length < 10) {
        throw bad("Message invalide.");
      }

      const l = (await getK("messages", [])) || [];

      const m = {
        id: uid(),
        date: Date.now(),
        name,
        topic,
        text,
        replyVia: via,
        contact: via === "site" ? "" : clean(b.contact, 80),
        read: false
      };

      l.unshift(m);
      await setK("messages", l.slice(0, 500));

      return res.status(200).json({ id: m.id });
    }

    // Lecture publique des réponses aux messages
    if (a === "replies") {
      const ids = Array.isArray(b.ids) ? b.ids.slice(0, 30) : [];
      const l = (await getK("messages", [])) || [];
      const out = {};

      l.forEach(m => {
        if (ids.includes(m.id) && m.reply) {
          out[m.id] = m.reply;
        }
      });

      return res.status(200).json({ replies: out });
    }

    const session = checkToken(req);

    if (!session) {
      throw bad(
        "Session expirée ou non autorisée. Reconnectez-vous.",
        401
      );
    }

    if (a === "logout") {
      return res.status(200).json({ ok: true });
    }

    // L'assistant peut uniquement consulter le stock
    if (a === "assistantData") {
      if (session.role !== "assistant") {
        throw bad(
          "Cette action est réservée à l’espace assistant.",
          403
        );
      }

      return res.status(200).json({
        stock: await getK("stock", null)
      });
    }

    // Créer une demande (assistant)
    if (a === "createRequest") {
      if (session.role !== "assistant" && session.role !== "admin") {
        throw bad("Accès refusé", 403);
      }

      const first = clean(b.first, 50);
      const last = clean(b.last, 60);
      const object = clean(b.object, 100);
      const color = clean(b.color, 40);
      const comment = clean(b.comment, 500);

      if (!first || !last || !object || !color) {
        throw bad("Prénom, nom, objet et couleur sont obligatoires.");
      }

      const stock = (await getK("stock", [])) || [];

      if (!stock.some(c => c.name === color && c.inStock)) {
        throw bad("Cette couleur n’est plus disponible dans le stock.", 409);
      }

      const requests = (await getK("requests", [])) || [];

      const request = {
        id: uid(),
        first,
        last,
        object,
        color,
        comment,
        by: session.user || "assistant",
        byUid: session.uid || session.user || "assistant",
        date: Date.now(),
        status: "pending",
        ticketPrepared: false
      };

      requests.push(request);
      await setK("requests", requests);

      return res.status(200).json({
        ok: true,
        id: request.id
      });
    }

    // Demandes de l'assistant : ne pas afficher les demandes supprimées
    if (a === "myRequests") {
      const requests = (await getK("requests", [])) || [];

      return res.status(200).json({
        requests: requests.filter(r =>
          r.status !== "deleted" &&
          (
            r.byUid === (session.uid || session.user || "assistant") ||
            r.by === (session.user || "assistant")
          )
        )
      });
    }

    requireAdmin(session);

    // Liste du gérant : ne pas afficher les demandes supprimées
    if (a === "listRequests") {
      const requests = (await getK("requests", [])) || [];

      return res.status(200).json({
        requests: requests.filter(r => r.status !== "deleted")
      });
    }

    // Lire une demande
    if (a === "getRequest") {
      const requests = (await getK("requests", [])) || [];
      const request = requests.find(
        r => r.id === b.id && r.status !== "deleted"
      );

      if (!request) {
        throw bad("Demande introuvable", 404);
      }

      return res.status(200).json({ request });
    }

    // Accepter ou refuser une demande
    if (a === "decideRequest") {
      if (!["accepted", "rejected"].includes(b.status)) {
        throw bad("Décision invalide");
      }

      const requests = (await getK("requests", [])) || [];
      const r = requests.find(x => x.id === b.id);

      if (!r || r.status === "deleted") {
        throw bad("Demande introuvable", 404);
      }

      if (r.status !== "pending") {
        throw bad("Cette demande a déjà été traitée", 409);
      }

      if (b.status === "accepted") {
        const stock = (await getK("stock", [])) || [];

        if (!stock.some(c => c.name === r.color && c.inStock)) {
          throw bad("Cette couleur n’est plus disponible dans le stock", 409);
        }
      }

      const reason = clean(b.reason, 500);

      if (b.status === "rejected" && !reason) {
        throw bad("Indiquez pourquoi vous refusez cette demande.");
      }

      r.status = b.status;
      r.reason = b.status === "rejected" ? reason : "";
      r.decidedAt = Date.now();
      r.decidedBy = session.user || "gerant";

      await setK("requests", requests);

      return res.status(200).json({ ok: true, request: r });
    }

    // Marquer une demande comme terminée après la création du ticket
    if (a === "completeRequest") {
      const requests = (await getK("requests", [])) || [];
      const r = requests.find(x => x.id === b.id);

      if (!r || r.status === "deleted") {
        throw bad("Demande introuvable", 404);
      }

      if (r.status !== "accepted") {
        throw bad("Cette demande n'est pas acceptée", 409);
      }

      r.status = "completed";
      r.ticketPrepared = true;
      r.ticketId = clean(b.ticketId, 100);
      r.completedAt = Date.now();

      await setK("requests", requests);

      return res.status(200).json({ ok: true, request: r });
    }

    // SUPPRESSION DÉFINITIVE d'une demande
    if (a === "deleteRequest") {
      const requests = (await getK("requests", [])) || [];
      const r = requests.find(x => x.id === b.id);

      if (!r) {
        throw bad("Demande introuvable", 404);
      }

      if (r.status === "completed") {
        throw bad("Cette demande est déjà terminée", 409);
      }

      // On retire entièrement la demande du tableau enregistré dans Redis.
      // Le motif de suppression n'est pas conservé.
      const remaining = requests.filter(x => x.id !== b.id);

      await setK("requests", remaining);

      return res.status(200).json({
        ok: true,
        id: b.id
      });
    }

    if (a === "verify") {
      return res.status(200).json({
        ok: await passOk(String(b.pass || ""))
      });
    }

    if (a === "all") {
      const out = {};

      for (const k of ADMIN_KEYS) {
        out[k] = await getK(
          k,
          ["clients", "tickets", "reviews", "messages", "requests"].includes(k)
            ? []
            : null
        );
      }

      return res.status(200).json(out);
    }

    if (a === "set") {
      if (!ADMIN_KEYS.includes(b.key)) {
        throw bad("Clé inconnue");
      }

      await setK(b.key, b.value);

      return res.status(200).json({ ok: true });
    }

    if (a === "changePass") {
      const p = String(b.pass || "");

      if (!/^\d{6,}$/.test(p)) {
        throw bad("Chiffres uniquement, 6 minimum.");
      }

      const salt = uid();

      await setK("pass", {
        salt,
        hash: sha(salt + p)
      });

      return res.status(200).json({ ok: true });
    }

    // Gestion des comptes
    if (a === "usersList") {
      const users = (await getK("users", [])) || [];

      return res.status(200).json({
        users: users.map(({ id, user, role }) => ({
          id,
          user,
          role
        }))
      });
    }

    if (a === "usersCreate") {
      const user = clean(b.user, 40).toLowerCase();
      const pass = String(b.pass || "");
      const role = b.role;

      if (!/^[a-z0-9._-]{3,40}$/.test(user)) {
        throw bad(
          "Identifiant invalide : 3 à 40 caractères, lettres/chiffres/._- uniquement."
        );
      }

      if (!/^\d{6,}$/.test(pass)) {
        throw bad(
          "Le mot de passe doit contenir au moins 6 chiffres."
        );
      }

      if (!["admin", "assistant"].includes(role)) {
        throw bad("Type de compte invalide.");
      }

      if (sha("nb-id:" + user) === AUTH.u) {
        throw bad("Cet identifiant est réservé au compte principal.");
      }

      const users = (await getK("users", [])) || [];

      if (users.some(x => x.user === user)) {
        throw bad("Cet identifiant existe déjà.");
      }

      const salt = uid();

      users.push({
        id: uid(),
        user,
        role,
        salt,
        hash: sha(salt + pass)
      });

      await setK("users", users);

      return res.status(200).json({ ok: true });
    }

    if (a === "usersDelete") {
      const users = (await getK("users", [])) || [];
      const target = users.find(x => x.id === b.id);

      if (!target) {
        throw bad("Compte introuvable.", 404);
      }

      if (target.id === session.uid) {
        throw bad(
          "Vous ne pouvez pas supprimer le compte actuellement utilisé."
        );
      }

      await setK(
        "users",
        users.filter(x => x.id !== b.id)
      );

      return res.status(200).json({ ok: true });
    }

    if (a === "delReview") {
      const l = ((await getK("reviews", [])) || [])
        .filter(r => r.id !== b.id);

      await setK("reviews", l);

      return res.status(200).json({ reviews: l });
    }

    if (["markRead", "delMessage", "reply"].includes(a)) {
      let l = (await getK("messages", [])) || [];

      if (a === "delMessage") {
        l = l.filter(m => m.id !== b.id);
      } else {
        const m = l.find(x => x.id === b.id);

        if (!m) {
          throw bad("Message introuvable.", 404);
        }

        if (a === "markRead") {
          m.read = !!b.read;
        }

        if (a === "reply") {
          m.reply = {
            text: clean(b.text, 1500),
            date: Date.now()
          };

          m.read = true;
        }
      }

      await setK("messages", l);

      return res.status(200).json({ messages: l });
    }

    throw bad("Action inconnue");

  } catch (e) {
    return res.status(e.status || 500).json(
      e.status
        ? { error: e.message }
        : {
            error: "Erreur serveur",
            detail: String(e && e.message || e).slice(0, 200)
          }
    );
  }
};
