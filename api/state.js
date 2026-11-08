// api/state.js — 3D Nainbus
// Stockage Vercel + Upstash Redis

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
  // Compte principal / plus haut niveau : administrateur.
  // Leroy est désormais un compte administrateur stocké dans la base.
  u: "dc2b5c6d76f7d132a4bc0228fee6903f5c236c99ef3222b6e2e72c67946b0343",
  p: "d15aa519613b2ba812c6be6091d4fe70e9dd37768dca1323603b15778f1162a3",
};

const MASTER_USER = "administrateur";
const SECONDARY_ADMIN_USER = "leroy";

const ADMIN_KEYS = [
  "clients",
  "tickets",
  "stock",
  "logo",
  "reviews",
  "messages",
  "requests",
  "tariffs"
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

function makeAccessToken(session) {
  const p = Buffer.from(JSON.stringify({
    role: session.role,
    user: session.user,
    uid: session.uid,
    master: !!session.master,
    accessControl: true,
    exp: Date.now() + 12 * 3600 * 1000
  })).toString("base64url");

  return p + "." + crypto
    .createHmac("sha256", SECRET)
    .update(p)
    .digest("base64url");
}

function requireAccessUnlock(req, b, session) {
  const token = checkToken({
    headers: {
      authorization: "Bearer " + String(b.accessToken || "")
    }
  });

  if (
    !token ||
    token.accessControl !== true ||
    token.user !== session.user ||
    token.uid !== session.uid
  ) {
    throw bad(
      "Saisis à nouveau le mot de passe pour gérer les accès.",
      403
    );
  }
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

const DEFAULT_ACCESS = {
  global: {
    enabled: false,
    message: "",
    reason: "maintenance",
    until: null,
    exemptIds: []
  },
  accounts: {},
  rules: []
};

async function getAccessControl() {
  const saved = await getK("accessControl", null);

  if (!saved || typeof saved !== "object") {
    return JSON.parse(JSON.stringify(DEFAULT_ACCESS));
  }

  return {
    global: {
      enabled: !!(saved.global && saved.global.enabled),
      message: clean(saved.global && saved.global.message, 500),
      reason: clean(saved.global && saved.global.reason, 40) || "maintenance",
      until: Number(saved.global && saved.global.until) || null,
      exemptIds: Array.isArray(saved.global && saved.global.exemptIds)
        ? saved.global.exemptIds.map(String)
        : []
    },
    accounts: saved.accounts && typeof saved.accounts === "object"
      ? saved.accounts
      : {},
    rules: Array.isArray(saved.rules) ? saved.rules : []
  };
}

function accessMessage(entry, fallback) {
  const reason = clean(entry && entry.reason, 40);
  const message = clean(entry && entry.message, 500);

  if (message) return message;

  const labels = {
    update: "Une mise à jour est en cours. Merci de réessayer ultérieurement.",
    maintenance: "Le service est momentanément en maintenance. Merci de réessayer plus tard.",
    security: "L’accès est temporairement suspendu pour des raisons de sécurité.",
    verification: "Une vérification est nécessaire avant de rétablir cet accès.",
    administrative: "L’accès à ce compte est temporairement désactivé.",
    suspension: "Ce compte a été suspendu. Contactez le responsable du service."
  };

  return labels[reason] || fallback;
}

async function checkAccountAccess(userRecord, control) {
  if (!userRecord) return;

  let changed = false;
  const legacy = control.accounts[userRecord.id];

  if (legacy && legacy.until && Number(legacy.until) <= Date.now()) {
    delete control.accounts[userRecord.id];
    changed = true;
  } else if (legacy && legacy.status && legacy.status !== "active") {
    throw bad(
      accessMessage(
        legacy,
        "L’accès à ce compte est temporairement indisponible."
      ),
      403
    );
  }

  const activeRules = [];

  for (const rule of control.rules || []) {
    if (rule.until && Number(rule.until) <= Date.now()) {
      changed = true;
      continue;
    }

    activeRules.push(rule);

    const applies = rule.targetAll === true ||
      (
        Array.isArray(rule.targetIds) &&
        rule.targetIds.map(String).includes(String(userRecord.id))
      );

    if (applies) {
      throw bad(
        accessMessage(
          rule,
          "L’accès à ce compte est temporairement indisponible."
        ),
        403
      );
    }
  }

  if (changed) {
    control.rules = activeRules;
    await setK("accessControl", control);
  }
}

async function checkGlobalAccess(control, isMaster, userId) {
  const g = control.global;

  if (isMaster || !g || !g.enabled) return;

  if (g.until && Number(g.until) <= Date.now()) {
    control.global.enabled = false;
    control.global.until = null;
    await setK("accessControl", control);
    return;
  }

  const exempt = Array.isArray(g.exemptIds) &&
    g.exemptIds.map(String).includes(String(userId || ""));

  if (!exempt) {
    throw bad(
      accessMessage(g, "Le service est momentanément indisponible."),
      503
    );
  }
}


async function migrateAdminRoles(pass) {
  const users = (await getK("users", [])) || [];
  let changed = false;

  // L'ancien compte principal « leroy » devient un vrai compte admin en base.
  const leroyIndex = users.findIndex(
    x => String(x.user || "").toLowerCase() === SECONDARY_ADMIN_USER
  );

  if (leroyIndex >= 0) {
    if (users[leroyIndex].role !== "admin") {
      users[leroyIndex].role = "admin";
      changed = true;
    }
  } else {
    const salt = uid();
    users.push({
      id: uid(),
      user: SECONDARY_ADMIN_USER,
      role: "admin",
      salt,
      hash: sha(salt + String(pass || ""))
    });
    changed = true;
  }

  // L'identifiant « administrateur » est réservé au compte principal
  // et ne doit donc pas apparaître comme compte secondaire en base.
  const filtered = users.filter(
    x => String(x.user || "").toLowerCase() !== MASTER_USER
  );

  if (filtered.length !== users.length) changed = true;

  if (changed) await setK("users", filtered);
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
        logo: await getK("logo"),
        tariffs: await getK("tariffs")
      });
    }

    if (req.method !== "POST") {
      throw bad("Méthode non autorisée", 405);
    }

    const b = typeof req.body === "string"
      ? JSON.parse(req.body || "{}")
      : (req.body || {});

    const a = b.action;

    // CONNEXION
    if (a === "login") {
      await limit(
        req,
        "login",
        12,
        600,
        "Trop de tentatives. Réessaie dans quelques minutes."
      );

      const user = clean(b.user, 40).toLowerCase();
      const entered = String(b.pass || "");
      const mode = b.mode === "assistant" ? "assistant" : "admin";

      const control = await getAccessControl();

      // COMPTE PRINCIPAL : administrateur
      if (user === MASTER_USER) {
        if (mode !== "admin") {
          throw bad("Le compte principal utilise l'espace administrateur.", 403);
        }

        const ok = await passOk(entered);

        if (!ok) {
          throw bad("Identifiant ou mot de passe incorrect.", 401);
        }

        await checkGlobalAccess(control, true, "master");

        const session = {
          uid: "master",
          user: MASTER_USER,
          role: "admin",
          master: true
        };

        return res.status(200).json({
          ok: true,
          token: makeToken(session),
          role: "admin",
          user: MASTER_USER,
          master: true
        });
      }

      const users = (await getK("users", [])) || [];

      const userRecord = users.find(
        x => String(x.user || "").toLowerCase() === user
      );

      if (!userRecord) {
        throw bad("Identifiant ou mot de passe incorrect.", 401);
      }

      if (mode === "assistant" && userRecord.role !== "assistant") {
        throw bad("Ce compte n'est pas un compte assistant.", 403);
      }

      if (mode === "admin" && userRecord.role !== "admin") {
        throw bad("Ce compte n'est pas un compte administrateur.", 403);
      }

      await checkAccountAccess(userRecord, control);

      await checkGlobalAccess(
        control,
        userRecord.role === "admin" && userRecord.user === SECONDARY_ADMIN_USER,
        userRecord.id
      );

      const ok = sha(userRecord.salt + entered) === userRecord.hash;

      if (!ok) {
        throw bad("Identifiant ou mot de passe incorrect.", 401);
      }

      const session = {
        uid: userRecord.id,
        user: userRecord.user,
        role: userRecord.role,
        master: false
      };

      return res.status(200).json({
        ok: true,
        token: makeToken(session),
        role: userRecord.role,
        user: userRecord.user,
        master: false
      });
    }

    // VÉRIFICATION DU TOKEN
    const session = checkToken(req);

    // Actions publiques
    if (a === "public") {
      return res.status(200).json({
        reviews: (await getK("reviews", [])) || [],
        logo: await getK("logo"),
        tariffs: await getK("tariffs")
      });
    }

    // LOGOUT
    if (a === "logout") {
      return res.status(200).json({ ok: true });
    }

    // Toutes les actions suivantes nécessitent une connexion.
    if (!session) {
      throw bad("Session expirée ou non autorisée.", 401);
    }

    // CRÉATION / MIGRATION DU COMPTE ADMINISTRATEUR PRINCIPAL
    if (a === "migrateAdminRoles") {
      requireAdmin(session);

      if (!session.master) {
        throw bad(
          "Seul le compte administrateur principal peut effectuer cette migration.",
          403
        );
      }

      const pass = String(b.pass || "");

      if (!pass) {
        throw bad("Mot de passe requis.");
      }

      if (!(await passOk(pass))) {
        throw bad("Mot de passe incorrect.", 401);
      }

      await migrateAdminRoles(pass);

      return res.status(200).json({
        ok: true
      });
    }

    // DONNÉES ASSISTANT
    if (a === "assistantData") {
      if (session.role !== "assistant") {
        throw bad("Accès réservé aux assistants.", 403);
      }

      return res.status(200).json({
        stock: (await getK("stock", [])) || [],
        tariffs: await getK("tariffs")
      });
    }

    // DÉVERROUILLAGE DU CONTRÔLE D'ACCÈS
    if (a === "accessUnlock") {
      requireAdmin(session);

      const entered = String(b.pass || "");

      let ok = false;

      if (session.master) {
        ok = await passOk(entered);
      } else {
        const users = (await getK("users", [])) || [];
        const userRecord = users.find(
          x => x.id === session.uid
        );

        if (userRecord) {
          ok = sha(userRecord.salt + entered) === userRecord.hash;
        }
      }

      if (!ok) {
        throw bad("Mot de passe incorrect.", 401);
      }

      return res.status(200).json({
        ok: true,
        accessToken: makeAccessToken(session)
      });
    }

    // OBTENIR LE CONTRÔLE D'ACCÈS
    if (a === "accessGet") {
      requireAdmin(session);
      requireAccessUnlock(req, b, session);

      const control = await getAccessControl();

      return res.status(200).json({
        control
      });
    }

    // ENREGISTRER LA MAINTENANCE GÉNÉRALE
    if (a === "accessSave") {
      requireAdmin(session);
      requireAccessUnlock(req, b, session);

      const reason = [
        "update",
        "maintenance",
        "security",
        "verification",
        "administrative",
        "suspension",
        "custom"
      ].includes(b.reason)
        ? b.reason
        : "maintenance";

      const message = clean(b.message, 500);

      if (reason === "custom" && !message) {
        throw bad("Écris le motif personnalisé.");
      }

      const until =
        b.until == null || b.until === ""
          ? null
          : Number(b.until);

      if (
        until !== null &&
        (!Number.isFinite(until) || until <= Date.now())
      ) {
        throw bad("La durée choisie est invalide.");
      }

      const control = await getAccessControl();

      control.global = {
        enabled: !!b.enabled,
        message,
        reason,
        until,
        exemptIds: Array.isArray(b.exemptIds)
          ? b.exemptIds.map(String).slice(0, 100)
          : []
      };

      await setK("accessControl", control);

      return res.status(200).json({
        ok: true,
        control
      });
    }

    // CRÉER UNE RÈGLE DE RESTRICTION
    if (a === "accessCreateRule") {
      requireAdmin(session);
      requireAccessUnlock(req, b, session);

      const users = (await getK("users", [])) || [];
      const targetAll = b.targetAll === true;

      const requested = Array.isArray(b.targetIds)
        ? [
            ...new Set(
              b.targetIds
                .map(x => clean(x, 100))
                .filter(Boolean)
            )
          ]
        : [];

      const validIds = new Set(users.map(u => String(u.id)));

      const targetIds = requested
        .filter(id => validIds.has(id))
        .slice(0, 100);

      if (!targetAll && !targetIds.length) {
        throw bad("Sélectionne au moins un compte.");
      }

      const kind = [
        "restriction",
        "maintenance",
        "custom"
      ].includes(b.kind)
        ? b.kind
        : "restriction";

      const reason = [
        "update",
        "maintenance",
        "security",
        "verification",
        "administrative",
        "suspension",
        "custom"
      ].includes(b.reason)
        ? b.reason
        : "administrative";

      const message = clean(b.message, 500);

      if (reason === "custom" && !message) {
        throw bad("Écris le motif personnalisé.");
      }

      const until =
        b.until == null || b.until === ""
          ? null
          : Number(b.until);

      if (
        until !== null &&
        (!Number.isFinite(until) || until <= Date.now())
      ) {
        throw bad("La durée choisie est invalide.");
      }

      const control = await getAccessControl();

      const rule = {
        id: uid(),
        kind,
        reason,
        message,
        targetAll,
        targetIds: targetAll ? [] : targetIds,
        until,
        createdAt: Date.now()
      };

      control.rules.push(rule);

      await setK("accessControl", control);

      return res.status(200).json({
        ok: true,
        rule
      });
    }

    // SUPPRIMER UNE RÈGLE
    if (a === "accessDeleteRule") {
      requireAdmin(session);
      requireAccessUnlock(req, b, session);

      const control = await getAccessControl();

      const before = control.rules.length;

      control.rules = control.rules.filter(
        rule => rule.id !== b.id
      );

      if (before === control.rules.length) {
        throw bad("Cette règle est introuvable.", 404);
      }

      await setK("accessControl", control);

      return res.status(200).json({
        ok: true
      });
    }

    // RESTRICTION D'UN COMPTE
    if (a === "usersAccessUpdate") {
      requireAdmin(session);
      requireAccessUnlock(req, b, session);

      const id = clean(b.id, 100);

      const status = [
        "active",
        "disabled",
        "maintenance",
        "suspended"
      ].includes(b.status)
        ? b.status
        : "";

      if (!id || !status) {
        throw bad("Paramètres de restriction invalides.");
      }

      if (session.uid && id === session.uid) {
        throw bad(
          "Vous ne pouvez pas désactiver le compte actuellement utilisé."
        );
      }

      const users = (await getK("users", [])) || [];

      const target = users.find(
        x => x.id === id
      );

      if (!target) {
        throw bad("Compte introuvable.", 404);
      }

      const until =
        b.until == null || b.until === ""
          ? null
          : Number(b.until);

      if (
        status !== "active" &&
        until !== null &&
        (!Number.isFinite(until) || until < Date.now() - 60000)
      ) {
        throw bad("Date de fin invalide.");
      }

      const control = await getAccessControl();

      if (status === "active") {
        delete control.accounts[id];
      } else {
        control.accounts[id] = {
          status,
          message: clean(b.message, 500),
          reason: [
            "update",
            "maintenance",
            "security",
            "verification",
            "administrative",
            "suspension",
            "custom"
          ].includes(b.reason)
            ? b.reason
            : "administrative",
          until
        };
      }

      await setK("accessControl", control);

      return res.status(200).json({
        ok: true
      });
    }

    // LISTE DES COMPTES
    if (a === "usersList") {
      requireAdmin(session);

      const users = (await getK("users", [])) || [];
      const control = await getAccessControl();

      let changed = false;

      const visibleUsers = users
        // Le compte principal administrateur n'est pas affiché
        // dans la liste des comptes secondaires.
        .filter(
          u =>
            String(u.user || "").toLowerCase() !== MASTER_USER
        )
        .map(({ id, user, role }) => {
          let access = control.accounts[id] || {
            status: "active"
          };

          if (
            access.until &&
            Number(access.until) <= Date.now()
          ) {
            delete control.accounts[id];
            access = {
              status: "active"
            };
            changed = true;
          }

          return {
            id,
            user,
            role,
            accessStatus: access.status || "active",
            accessMessage: access.message || "",
            accessReason: access.reason || "administrative",
            accessUntil: access.until || null
          };
        });

      if (changed) {
        await setK("accessControl", control);
      }

      return res.status(200).json({
        users: visibleUsers
      });
    }

    // CRÉER UN COMPTE
    if (a === "usersCreate") {
      requireAdmin(session);

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

      if (
        user === MASTER_USER ||
        sha("nb-id:" + user) === AUTH.u
      ) {
        throw bad(
          "Cet identifiant est réservé au compte principal."
        );
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

      return res.status(200).json({
        ok: true
      });
    }

    // SUPPRIMER UN COMPTE
    if (a === "usersDelete") {
      requireAdmin(session);

      const users = (await getK("users", [])) || [];

      const target = users.find(
        x => x.id === b.id
      );

      if (!target) {
        throw bad("Compte introuvable.", 404);
      }

      if (target.id === session.uid) {
        throw bad(
          "Vous ne pouvez pas supprimer le compte actuellement utilisé."
        );
      }

      if (
        String(target.user || "").toLowerCase() ===
        SECONDARY_ADMIN_USER
      ) {
        throw bad(
          "Le compte leroy est un compte administrateur protégé."
        );
      }

      await setK(
        "users",
        users.filter(
          x => x.id !== b.id
        )
      );

      return res.status(200).json({
        ok: true
      });
    }

    // LISTE DES DEMANDES
    if (a === "listRequests") {
      requireAdmin(session);

      return res.status(200).json({
        requests:
          (await getK("requests", [])) || []
      });
    }

    // CONSULTER UNE DEMANDE
    if (a === "getRequest") {
      requireAdmin(session);

      const requests =
        (await getK("requests", [])) || [];

      const request =
        requests.find(
          x => x.id === b.id
        );

      if (!request) {
        throw bad("Demande introuvable", 404);
      }

      return res.status(200).json({
        request
      });
    }

    // ACCEPTER OU REFUSER UNE DEMANDE
    if (a === "decideRequest") {
      requireAdmin(session);

      if (
        !["accepted", "rejected"].includes(b.status)
      ) {
        throw bad("Décision invalide");
      }

      const requests =
        (await getK("requests", [])) || [];

      const request =
        requests.find(
          x => x.id === b.id
        );

      if (!request) {
        throw bad("Demande introuvable", 404);
      }

      if (request.status !== "pending") {
        throw bad(
          "Cette demande a déjà été traitée",
          409
        );
      }

      const reason =
        clean(b.reason, 500);

      if (
        b.status === "rejected" &&
        !reason
      ) {
        throw bad(
          "Indiquez pourquoi vous refusez cette demande."
        );
      }

      if (b.status === "accepted") {
        const stock =
          (await getK("stock", [])) || [];

        if (
          !stock.some(
            c =>
              c.name === request.color &&
              c.inStock
          )
        ) {
          throw bad(
            "Cette couleur n’est plus disponible dans le stock.",
            409
          );
        }
      }

      request.status = b.status;
      request.reason =
        b.status === "rejected"
          ? reason
          : "";

      request.decidedAt =
        Date.now();

      request.decidedBy =
        session.user || "gerant";

      await setK(
        "requests",
        requests
      );

      return res.status(200).json({
        ok: true,
        request
      });
    }

    // MARQUER UNE DEMANDE COMME TERMINÉE
    if (a === "completeRequest") {
      requireAdmin(session);

      const requests =
        (await getK("requests", [])) || [];

      const request =
        requests.find(
          x => x.id === b.id
        );

      if (!request) {
        throw bad(
          "Demande introuvable",
          404
        );
      }

      if (request.status !== "accepted") {
        throw bad(
          "Cette demande n'est pas acceptée",
          409
        );
      }

      request.status = "completed";
      request.ticketPrepared = true;
      request.ticketId =
        clean(b.ticketId, 100);

      request.completedAt =
        Date.now();

      await setK(
        "requests",
        requests
      );

      return res.status(200).json({
        ok: true,
        request
      });
    }

    // RETIRER UNE DEMANDE AVEC MOTIF OBLIGATOIRE
    if (a === "deleteRequest") {
      requireAdmin(session);

      const reason =
        clean(b.reason, 500);

      if (!reason) {
        throw bad(
          "Indiquez pourquoi vous supprimez cette demande."
        );
      }

      const requests =
        (await getK("requests", [])) || [];

      const request =
        requests.find(
          x => x.id === b.id
        );

      if (!request) {
        throw bad(
          "Demande introuvable",
          404
        );
      }

      if (
        ["completed", "deleted"].includes(
          request.status
        )
      ) {
        throw bad(
          "Cette demande est déjà terminée ou retirée",
          409
        );
      }

      request.status = "deleted";
      request.reason = reason;
      request.deletedAt = Date.now();
      request.deletedBy =
        session.user || "gerant";

      await setK(
        "requests",
        requests
      );

      return res.status(200).json({
        ok: true,
        request
      });
    }

    // VÉRIFICATION DU MOT DE PASSE
    if (a === "verify") {
      return res.status(200).json({
        ok: await passOk(
          String(b.pass || "")
        )
      });
    }

    // CHARGEMENT DES DONNÉES DU GÉRANT
    if (a === "all") {
      requireAdmin(session);

      const out = {};

      for (const k of ADMIN_KEYS) {
        const value =
          await getK(
            k,
            [
              "clients",
              "tickets",
              "reviews",
              "messages",
              "requests"
            ].includes(k)
              ? []
              : null
          );

        // Ne pas écraser les tarifs locaux
        // s'il n'y a rien dans le cloud.
        if (
          k === "tariffs" &&
          value == null
        ) {
          continue;
        }

        out[k] = value;
      }

      return res.status(200).json(out);
    }

    // ENREGISTREMENT DES DONNÉES
    if (a === "set") {
      requireAdmin(session);

      if (!ADMIN_KEYS.includes(b.key)) {
        throw bad("Clé inconnue");
      }

      await setK(
        b.key,
        b.value
      );

      return res.status(200).json({
        ok: true
      });
    }

    // CHANGEMENT DU MOT DE PASSE
    if (a === "changePass") {
      requireAdmin(session);

      const p =
        String(b.pass || "");

      if (!/^\d{6,}$/.test(p)) {
        throw bad(
          "Chiffres uniquement, 6 minimum."
        );
      }

      const salt = uid();

      await setK("pass", {
        salt,
        hash: sha(salt + p)
      });

      return res.status(200).json({
        ok: true
      });
    }

    // SUPPRIMER UN AVIS
    if (a === "delReview") {
      requireAdmin(session);

      const l =
        ((await getK("reviews", [])) || [])
          .filter(
            r => r.id !== b.id
          );

      await setK(
        "reviews",
        l
      );

      return res.status(200).json({
        reviews: l
      });
    }

    // GESTION DES MESSAGES
    if (
      [
        "markRead",
        "delMessage",
        "reply"
      ].includes(a)
    ) {
      requireAdmin(session);

      let l =
        (await getK("messages", [])) || [];

      if (a === "delMessage") {
        l = l.filter(
          m => m.id !== b.id
        );
      } else {
        const m =
          l.find(
            x => x.id === b.id
          );

        if (!m) {
          throw bad(
            "Message introuvable.",
            404
          );
        }

        if (a === "markRead") {
          m.read = !!b.read;
        }

        if (a === "reply") {
          m.reply = {
            text: clean(
              b.text,
              1500
            ),
            date: Date.now()
          };

          m.read = true;
        }
      }

      await setK(
        "messages",
        l
      );

      return res.status(200).json({
        messages: l
      });
    }

    throw bad("Action inconnue");

  } catch (e) {
    return res.status(
      e.status || 500
    ).json(
      e.status
        ? {
            error: e.message
          }
        : {
            error: "Erreur serveur",
            detail: String(
              e && e.message || e
            ).slice(0, 200)
          }
    );
  }
};
