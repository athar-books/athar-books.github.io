/**
 * أثر — تبادل الكتب · backend
 * Cloudflare Worker + KV. Holds the listings so everyone sees the same shelf.
 *
 * Endpoints
 *   POST /data      { village, uid?, tok? }        -> shelf. Names and phones
 *                                                    only for identified users.
 *                                                    Completed exchanges are
 *                                                    hidden here for everyone
 *                                                    except the two people
 *                                                    who were part of one.
 *   POST /publish   { village, kind, uid, tok, records[], pics{} }
 *   POST /update    { village, kind, uid, tok, id, act }   act:"okOwner" now
 *                                                    marks a listing done
 *                                                    instead of deleting it,
 *                                                    so "my posts" has real
 *                                                    history. act:"hold"
 *                                                    emails the owner if
 *                                                    they've got an address
 *                                                    on file.
 *   POST /profile   { uid, tok, name, phone }       -> save or edit; edits
 *                                                    past the first log to
 *                                                    log:actions and, if the
 *                                                    phone changed, clear
 *                                                    "approved" until it's
 *                                                    reverified over WhatsApp
 *   GET  /pic?id=
 *   POST /track     { sid, events:[{t,label,ms?}] }  -> anonymous click and
 *                                                    page-time logging, see
 *                                                    queryAnalytics() and
 *                                                    the "stats" admin
 *                                                    action for how this
 *                                                    comes back out
 *   GET  /webhook   Meta handshake
 *   POST /webhook   incoming WhatsApp -> auto-approve
 *   GET  /auth/google/login      the only way to sign in
 *   GET  /auth/google/callback   Google redirects back here
 *   POST /admin     { uid, tok, act, ... }          -> founder-only, where
 *                                                    "founder" means your
 *                                                    Google account's email
 *                                                    is in ADMIN_EMAILS —
 *                                                    nothing to unlock,
 *                                                    nothing stored, just
 *                                                    checked fresh on every
 *                                                    call
 *
 * Identity: uid is "g:" + Google's stable subject id, not a phone number —
 * an account exists the moment someone signs in with Google, before a
 * phone is ever collected. Three rules that matter:
 *   1. The server decides who you are from your token. It never trusts a uid
 *      in the request body for authorization.
 *   2. Anonymous callers get books without names or numbers. Identity is
 *      exchanged for identity.
 *   3. Google can log someone in or create the account, but it never
 *      creates "approved" on its own. Only a phone number proven over
 *      WhatsApp does that — otherwise the whole point of verification
 *      (a real person from the village) is gone. See /profile and /webhook.
 *
 * Secrets: VERIFY_TOKEN, APP_SECRET, ADMIN_EMAILS,
 *          GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
 *          RESEND_API_KEY (email notifications; see sendEmail()),
 *          CF_ANALYTICS_TOKEN (reads back /track's data; see
 *            queryAnalytics() — an API token scoped to Account
 *            Analytics: Read, created once in the Cloudflare dashboard).
 * Vars: CF_ACCOUNT_ID (not secret — your 32-char Cloudflare account id).
 * Optional: EMAIL_FROM — a verified sender address once Resend has a real
 *          domain set up; falls back to Resend's shared test address.
 * Bindings: BOOKS (KV), ANALYTICS (Analytics Engine dataset "athar_events",
 *          write-only from the Worker — reading it back goes through
 *          queryAnalytics()'s HTTP call instead, see above).
 * (PEPPER and ADMIN_KEYS are no longer read anywhere — password auth and
 * the old key-based founder unlock are both gone. Safe to leave either
 * secret set in Cloudflare, or remove them, either way.)

/**
 * Which sites may call this Worker from a browser. Put your GitHub Pages URL
 * here. "null" covers any local HTML file opened straight off disk (e.g.
 * stats.html, if you still keep a copy around for something).
 * Leave the array empty to allow everyone (fine while testing, not after).
 *
 * This is a fence, not a lock: a script outside a browser ignores it entirely.
 * The token and key checks are what actually protect the data.
 *
 * admin.html and its own separate Worker deployment are retired — the
 * control panel now lives inside index.html itself (see /admin's doc
 * comment below), served from the one origin already listed here. Nothing
 * else needs a CORS entry.
 */
const ALLOWED = [
  "https://athar-books.github.io",
];

// Must be registered EXACTLY (including path, no trailing-slash mismatch)
// as an Authorised redirect URI on the "Athar" OAuth client in Google Cloud.
const GOOGLE_REDIRECT = "https://athar-books.athar-kutub.workers.dev/auth/google/callback";

function cors(request) {
  const origin = request.headers.get("Origin") || "";
  const allow = !ALLOWED.length ? "*"
    : (ALLOWED.includes(origin) || origin === "null") ? origin : ALLOWED[0];
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

let CORS = { "Access-Control-Allow-Origin": "*" };
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", ...CORS } });

const HOLD_MS = 48 * 3600 * 1000;
const MAX_BATCH = 15;

const kList = (v, kind) => `list:${kind}:${v}`;
const kPic = (id) => `pic:${id}`;
const kTok = (uid) => `tok:${uid}`;
const kUser = (uid) => `user:${uid}`;
// One phone, one account. This is the reverse index the WhatsApp webhook
// and the admin panel use to find which account a phone number belongs to
// — the uid itself no longer encodes the phone (see /auth/google/callback).
const kPhoneUid = (phone) => `phuid:${phone}`;
const kOState = (s) => `gstate:${s}`;

// Founder status is just "is this Google account's email on the list" —
// nothing stored, nothing to unlock, nothing that can drift out of sync.
// ADMIN_EMAILS is a JSON secret: {"mahmoud@gmail.com":"محمود","rana@gmail.com":"رنا"}.
// Add or remove a founder by editing the secret and redeploying:
//   npx wrangler secret put ADMIN_EMAILS
function founderName(env, email) {
  if (!email) return "";
  let map = {};
  try { map = JSON.parse(env.ADMIN_EMAILS || "{}"); } catch (e) {}
  return map[String(email).toLowerCase()] || "";
}

function vCode(uid) {
  let h = 0;
  for (let i = 0; i < uid.length; i++) h = (h * 31 + uid.charCodeAt(i)) >>> 0;
  return h.toString(36).toUpperCase().slice(-4).padStart(4, "0");
}
function normPhone(raw) {
  let d = String(raw || "").replace(/\D/g, "");
  if (!d) return "";
  if (d.startsWith("0")) d = "972" + d.slice(1);
  else if (!d.startsWith("972")) d = "972" + d;
  return d;
}
// Constant-time string comparison. Not password-specific despite living
// here originally — the admin panel uses this to compare founder keys
// without leaking timing information.
function sameHash(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function randomId(bytes = 20) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
/**
 * Reads the payload of Google's id_token WITHOUT checking its signature.
 * That's only safe here because this id_token comes back on a direct
 * server-to-server HTTPS call to Google, authenticated with our client
 * secret (see /auth/google/callback below) — a browser never touches it,
 * so there's nothing for anyone to forge. Never decode a token this way if
 * it arrived from the browser instead (e.g. Google One Tap / JS SDK).
 */
function decodeIdToken(idToken) {
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) return null;
  const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  try { return JSON.parse(atob(padded)); } catch { return null; }
}

async function readList(kv, key) {
  const v = await kv.get(key, "json");
  return Array.isArray(v) ? v : [];
}

/**
 * Anonymous funnel counters — never a per-person trail, only "how many of
 * this event happened, on this day, in this village." No uid, no name, no
 * phone touches these keys; see /admin's "stats" action for how a founder
 * reads them back.
 *
 * KV has no atomic increment, so this is read-then-write — under genuinely
 * concurrent requests to the exact same key in the exact same second, a
 * count can theoretically lose an increment. For a village-sized audience
 * this is a non-issue; stat:done already accepts the same tradeoff.
 * Always called via ctx.waitUntil(), so it never adds latency to the
 * response the person is actually waiting on.
 */
async function bump(env, event, village) {
  const day = new Date().toISOString().slice(0, 10);
  const keys = [`stat:day:${event}:${day}`, `stat:total:${event}`];
  if (village) keys.push(`stat:village:${event}:${village}`);
  await Promise.all(keys.map(async (k) => {
    const cur = Number((await env.BOOKS.get(k)) || 0);
    await env.BOOKS.put(k, String(cur + 1));
  }));
}

/**
 * Sends a transactional email via Resend (resend.com) — a single fetch
 * call, no SDK, which is what makes it workable inside a Worker. Requires
 * the RESEND_API_KEY secret; EMAIL_FROM is optional and falls back to
 * Resend's own shared test address, which is fine to start with but has
 * sending limits — verify a real domain in Resend once this needs to be
 * reliable for actual users.
 *
 * Always called via ctx.waitUntil() and always swallows its own errors —
 * a notification email failing must never break the action that triggered
 * it (a reservation has already succeeded by the time this runs).
 */
async function sendEmail(env, to, subject, text) {
  if (!env.RESEND_API_KEY || !to) return;
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM || "Athar <onboarding@resend.dev>",
        to: [to],
        subject,
        text,
      }),
    });
  } catch (e) {
    // Best-effort. See doc comment above.
  }
}

// Must match the `dataset` value in wrangler.toml's [[analytics_engine_datasets]]
// block exactly — this is the SQL table name, which is not the same thing
// as the binding name (env.ANALYTICS is the binding; this is the table).
const AE_DATASET = "athar_events";

/**
 * Runs a SQL query against the click/page-time data written by /track (see
 * that route below) and returns the rows, or null on any failure — this
 * whole feature is best-effort: the rest of the admin panel still works
 * fine with insights simply missing if these secrets aren't set yet or the
 * request fails for any reason.
 *
 * Needs two things env.ANALYTICS (the write binding) doesn't provide:
 * CF_ACCOUNT_ID (a plain var, not a secret — account IDs aren't sensitive)
 * and CF_ANALYTICS_TOKEN (a real secret — a Cloudflare API token scoped to
 * Account Analytics: Read, created once in the dashboard). Both are read
 * queries against Cloudflare's own API, nothing to do with env.ANALYTICS
 * itself, which is write-only from inside a Worker.
 */
async function queryAnalytics(env, sql) {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return null;
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`,
      { method: "POST", headers: { "Authorization": `Bearer ${env.CF_ANALYTICS_TOKEN}` }, body: sql }
    );
    if (!res.ok) return null;
    const j = await res.json().catch(() => null);
    return j && Array.isArray(j.data) ? j.data : null;
  } catch (e) {
    return null;
  }
}

/**
 * Audit trail for the admin panel. Every action a founder takes gets a row
 * here — who did it, what, to whom, when — so nothing happens invisibly.
 * Capped at the most recent 300 so it can't grow without bound.
 */
async function logAction(env, by, act, target, note) {
  const key = "log:actions";
  const list = await readList(env.BOOKS, key);
  list.push({ by, act, target: target || "", note: note || "", at: Date.now() });
  await env.BOOKS.put(key, JSON.stringify(list.slice(-300)));
}

/**
 * First device to claim an account keeps it. A second device with a different
 * token is refused until the account re-verifies over WhatsApp, which is what
 * stops someone signing in as you just by knowing your number.
 */
async function auth(env, uid, tok) {
  if (!uid || !tok || !uid.startsWith("g:")) return false;
  const held = await env.BOOKS.get(kTok(uid));
  if (!held) { await env.BOOKS.put(kTok(uid), tok); return true; }
  return held === tok;
}

function effStatus(r) {
  if (r.status === "done") return "done";
  if (r.status === "reserved" && Date.now() - (r.resAt || 0) > HOLD_MS) return "open";
  return r.status || "open";
}

/** Strip identity for anonymous callers; mark ownership for identified ones. */
function view(r, uid) {
  const mine = !!uid && r.uid === uid;
  const held = !!uid && r.holder === uid;
  const out = {
    id: r.id, village: r.village, grade: r.grade, subject: r.subject, kind: r.kind,
    title: r.title, cond: r.cond, desc: r.desc || "", school: r.school, handoff: r.handoff,
    pic: !!r.pic, at: r.at, status: effStatus(r), doneAt: r.doneAt || 0,
    confOwner: !!r.confOwner, confHolder: !!r.confHolder,
    ver: !!r.ver, mine, held,
  };
  if (uid) {
    out.name = r.name || "";
    out.holderName = r.holderName || "";
    if (r.handoff === "direct") out.phone = r.phone || "";
  }
  return out;
}

async function signatureValid(request, raw, appSecret) {
  const header = request.headers.get("x-hub-signature-256");
  if (!header || !header.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(appSecret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(raw));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const a = new TextEncoder().encode(header.slice(7));
  const b = new TextEncoder().encode(hex);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    CORS = cors(request);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    /* ---------------- Google sign-in ----------------
       The only way in. A full-page redirect flow — the browser navigates to
       Google and back, so these are 302s, never JSON responses.

       The callback always finishes by sending the browser back to the front
       end with one of these query strings, for the page's own JS to read on
       load (see handleGoogleReturn() there):
         ?glogin=ok&uid=&tok=&name=&phone=&verified=1|0
         ?glogin=error
       `phone` comes back empty on someone's first-ever sign-in — see
       /profile below, which is what fills it in, and only once the person
       actually tries to post. See the third rule at the top of this file:
       Google identifies someone, it never approves them.
       ------------------------------------------------------------------ */
    if (p === "/auth/google/login" && request.method === "GET") {
      const state = randomId(16);
      await env.BOOKS.put(kOState(state), "1", { expirationTtl: 600 });

      const auth = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      auth.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
      auth.searchParams.set("redirect_uri", GOOGLE_REDIRECT);
      auth.searchParams.set("response_type", "code");
      auth.searchParams.set("scope", "openid email profile");
      auth.searchParams.set("state", state);
      auth.searchParams.set("prompt", "select_account");
      return Response.redirect(auth.toString(), 302);
    }

    if (p === "/auth/google/callback" && request.method === "GET") {
      const FRONT = "https://athar-books.github.io/";
      const fail = () => Response.redirect(FRONT + "?glogin=error", 302);

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state") || "";
      const stateOk = state && await env.BOOKS.get(kOState(state));
      if (!code || !stateOk) return fail();
      await env.BOOKS.delete(kOState(state)); // one-time use, CSRF guard

      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: GOOGLE_REDIRECT, grant_type: "authorization_code",
        }),
      });
      if (!tokenRes.ok) return fail();
      const tokenData = await tokenRes.json().catch(() => ({}));
      const claims = tokenData.id_token && decodeIdToken(tokenData.id_token);
      if (!claims || claims.aud !== env.GOOGLE_CLIENT_ID || !claims.sub || !claims.email || !claims.email_verified) {
        return fail();
      }

      // Google's `sub` is the account key now — stable for life, known the
      // instant Google confirms who this is. That's what lets an account
      // exist before any phone number is ever collected.
      const uid = "g:" + claims.sub;
      const name = String(claims.name || "").slice(0, 80);

      let rec = await env.BOOKS.get(kUser(uid), "json");
      if (!rec) {
        rec = { name, email: String(claims.email).toLowerCase(), phone: "", at: Date.now() };
        await env.BOOKS.put(kUser(uid), JSON.stringify(rec));
        ctx.waitUntil(bump(env, "signup"));
      }

      const tok = randomId(20);
      await env.BOOKS.put(kTok(uid), tok);
      const approved = await readList(env.BOOKS, "approved");

      const u = new URL(FRONT);
      u.searchParams.set("glogin", "ok");
      u.searchParams.set("uid", uid);
      u.searchParams.set("tok", tok);
      u.searchParams.set("name", rec.name || name);
      u.searchParams.set("phone", rec.phone || "");
      u.searchParams.set("verified", approved.includes(uid) ? "1" : "0");
      return Response.redirect(u.toString(), 302);
    }

    /* ---------------- profile ----------------
       The one thing Google can't supply: a phone number, confirmed over
       WhatsApp like everyone else. Same endpoint for the first-time gate
       (front end shows it whenever S.user.phone is empty) and for later
       edits (a mistake typed once shouldn't be permanent) — see accountView
       in the front end.

       One phone, one account: if a number is already claimed by a
       different uid this is refused, not silently taken over.

       A name fix alone leaves verification untouched. A phone change resets
       it — the trust WhatsApp confirmed was tied to the OLD number, not
       whatever new one just got typed in — and every edit past the first is
       written to the same audit log founders already read in admin, so a
       genuine typo fix and someone quietly changing their contact number
       both leave a visible trail either way.
       ------------------------------------------------------------------ */
    if (p === "/profile" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!(await auth(env, b.uid, b.tok))) return json({ error: "auth" }, 401);

      const name = String(b.name || "").replace(/\s+/g, " ").trim();
      if (name.length < 5 || name.split(" ").filter(Boolean).length < 2) {
        return json({ ok: false, needName: true });
      }
      const phone = normPhone(b.phone);
      if (phone.length < 12) return json({ ok: false, badPhone: true });

      const holder = await env.BOOKS.get(kPhoneUid(phone));
      if (holder && holder !== b.uid) return json({ ok: false, phoneTaken: true });

      const rec = (await env.BOOKS.get(kUser(b.uid), "json")) || {};
      const firstTime = !rec.phone;
      const phoneChanged = !firstTime && rec.phone !== phone;
      const nameChanged = !firstTime && rec.name !== name;

      if (rec.phone && rec.phone !== phone) await env.BOOKS.delete(kPhoneUid(rec.phone));
      await env.BOOKS.put(kPhoneUid(phone), b.uid);
      await env.BOOKS.put(kUser(b.uid), JSON.stringify({ ...rec, name, phone, at: rec.at || Date.now() }));

      let reverify = false;
      if (phoneChanged) {
        const approved = await readList(env.BOOKS, "approved");
        if (approved.includes(b.uid)) {
          await env.BOOKS.put("approved", JSON.stringify(approved.filter((x) => x !== b.uid)));
          reverify = true;
        }
      }

      if (!firstTime && (phoneChanged || nameChanged)) {
        const parts = [];
        if (nameChanged) parts.push(`الاسم: ${rec.name} \u2192 ${name}`);
        if (phoneChanged) parts.push(`الرقم: ${rec.phone} \u2192 ${phone}`);
        await logAction(env, rec.name || "مستخدم", "editProfile", b.uid, parts.join(" | "));
      }
      return json({ ok: true, name: { name }, reverify });
    }

    /* ---------------- shelf ---------------- */
    if (p === "/data" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const village = String(b.village || "").slice(0, 24);
      if (!village) return json({ error: "village" }, 400);

      const ok = b.uid && b.tok ? await auth(env, b.uid, b.tok) : false;
      const uid = ok ? b.uid : null;
      ctx.waitUntil(bump(env, "shelfLoad", village));

      const [offers, wants, approved, blocked, doneRaw, myRec] = await Promise.all([
        readList(env.BOOKS, kList(village, "offers")),
        readList(env.BOOKS, kList(village, "wants")),
        readList(env.BOOKS, "approved"),
        readList(env.BOOKS, "blocked"),
        env.BOOKS.get("stat:done"),
        uid ? env.BOOKS.get(kUser(uid), "json") : null,
      ]);
      const live = (arr) => arr.filter((r) => !blocked.includes(r.uid))
        // Hidden from everyone but the owner until the account is verified —
        // the instant a founder approves it in admin, the same filter lets
        // every listing that account already posted through, with nothing
        // to republish.
        .filter((r) => approved.includes(r.uid) || r.uid === uid)
        // A completed exchange stays around as history for the two people
        // who were actually part of it (see "my posts" in the front end),
        // but drops off the public shelf for everyone else — nobody
        // browsing wants a marketplace cluttered with finished trades.
        .filter((r) => effStatus(r) !== "done" || r.uid === uid || r.holder === uid)
        .map((r) => view({ ...r, ver: approved.includes(r.uid) }, uid));

      return json({
        offers: live(offers), wants: live(wants),
        me: uid ? { verified: approved.includes(uid), blocked: false,
                     founder: founderName(env, myRec && myRec.email) || null } : null,
        authFailed: !!(b.uid && b.tok && !ok),
        // Total completed exchanges, across every village — this drives the
        // wreath mark on the public site. Deliberately not per-village: it
        // represents the initiative's overall reach, not a leaderboard.
        done: Number(doneRaw || 0),
      });
    }

    /* ---------------- publish a batch ---------------- */
    if (p === "/publish" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!(await auth(env, b.uid, b.tok))) return json({ error: "auth" }, 401);

      const blocked = await readList(env.BOOKS, "blocked");
      if (blocked.includes(b.uid)) return json({ error: "blocked" }, 403);

      // Name and phone live on the profile now (see /profile) — a Google
      // account can exist before either is set, so this is the one place
      // that actually needs them, and it refuses to guess.
      const rec = await env.BOOKS.get(kUser(b.uid), "json");
      if (!rec || !rec.phone || !rec.name) return json({ error: "noProfile" }, 400);

      // Anyone signed in can submit. Whether the post is public yet is
      // decided in /data, based on the account's current verified status —
      // not here, and not once per listing.

      const kind = b.kind === "wants" ? "wants" : "offers";
      const village = String(b.village || "").slice(0, 24);
      const recs = Array.isArray(b.records) ? b.records.slice(0, MAX_BATCH) : [];
      if (!village || !recs.length) return json({ error: "empty" }, 400);

      const now = Date.now();
      const clean = recs.map((r, i) => ({
        id: (now + i).toString(36) + Math.random().toString(36).slice(2, 7),
        village, uid: b.uid,                       // from the token, not the body
        grade: String(r.grade || "").slice(0, 2),
        subject: String(r.subject || "").slice(0, 40),
        kind: String(r.kind || "").slice(0, 20),
        title: String(r.title || "").slice(0, 90),
        cond: String(r.cond || "").slice(0, 20),
        desc: String(r.desc || "").slice(0, 300),
        school: String(r.school || "").slice(0, 60),
        handoff: r.handoff === "direct" ? "direct" : "point",
        name: rec.name,
        phone: r.handoff === "direct" ? rec.phone : "",
        pic: false, at: now + i, status: "open",
        holder: "", holderName: "", resAt: 0, confOwner: false, confHolder: false,
      }));

      const pics = b.pics && typeof b.pics === "object" ? b.pics : {};
      await Promise.all(clean.map(async (rec, i) => {
        const data = pics[String(i)];
        if (typeof data === "string" && data.length > 40 && data.length < 400000) {
          rec.pic = true;
          await env.BOOKS.put(kPic(rec.id), data);
        }
      }));

      const key = kList(village, kind);
      const latest = await readList(env.BOOKS, key);
      await env.BOOKS.put(key, JSON.stringify(clean.concat(latest).slice(0, 3000)));
      ctx.waitUntil(bump(env, "publish", village));
      return json({ ok: true, count: clean.length });
    }

    /* ---------------- reserve / confirm / delete ---------------- */
    if (p === "/update" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!(await auth(env, b.uid, b.tok))) return json({ error: "auth" }, 401);

      const kind = b.kind === "wants" ? "wants" : "offers";
      const key = kList(String(b.village || "").slice(0, 24), kind);
      const list = await readList(env.BOOKS, key);
      const i = list.findIndex((x) => x.id === b.id);
      if (i < 0) return json({ error: "gone" }, 404);

      const r = list[i];
      const owner = r.uid === b.uid;
      const holder = r.holder === b.uid;
      const st = effStatus(r);
      const act = b.act;

      if (act === "del") {
        if (!owner) return json({ error: "forbidden" }, 403);
        list.splice(i, 1);
        if (r.pic) await env.BOOKS.delete(kPic(r.id));
      } else if (act === "hold") {
        if (owner || st !== "open") return json({ error: "unavailable" }, 409);
        r.status = "reserved"; r.resAt = Date.now();
        r.holder = b.uid; r.holderName = String(b.name || "").slice(0, 80);
        r.confOwner = false; r.confHolder = false;
        // Let the owner know someone's interested, if there's an email on
        // file (Google always gives us one). Best-effort and non-blocking
        // — see sendEmail()'s doc comment.
        const ownerRec = await env.BOOKS.get(kUser(r.uid), "json");
        if (ownerRec && ownerRec.email) {
          ctx.waitUntil(sendEmail(env, ownerRec.email,
            `حدا مهتم بـ "${r.title || r.subject}" على أثر`,
            `مرحبا ${ownerRec.name || ""}،\n\n` +
            `${r.holderName || "حدا"} حجز "${r.title || r.subject}" اللي نشرتها على أثر.\n\n` +
            `شوف التفاصيل وتواصل من هون:\nhttps://athar-books.github.io/#l=${r.id}\n\n` +
            `— أثر · تبادل الكتب المدرسية`));
        }
        ctx.waitUntil(bump(env, "reservation", r.village));
      } else if (act === "release") {
        if (!owner && !holder) return json({ error: "forbidden" }, 403);
        r.status = "open"; r.holder = ""; r.holderName = "";
        r.resAt = 0; r.confOwner = false; r.confHolder = false;
      } else if (act === "okHolder") {
        if (!holder) return json({ error: "forbidden" }, 403);
        r.confHolder = true;
      } else if (act === "okOwner") {
        // Marked done, not deleted — kept around so both people can see it
        // as history under "my posts" (see /data's live() filter, which
        // hides done listings from everyone else but leaves these two
        // able to see it). The 3000-item cap at publish time is what keeps
        // this from growing forever, same as it always has.
        if (!owner) return json({ error: "forbidden" }, 403);
        r.status = "done"; r.doneAt = Date.now(); r.confOwner = true;
        const done = Number((await env.BOOKS.get("stat:done")) || 0) + 1;
        await env.BOOKS.put("stat:done", String(done));
        ctx.waitUntil(bump(env, "exchange", r.village));
      } else {
        return json({ error: "act" }, 400);
      }

      await env.BOOKS.put(key, JSON.stringify(list));
      return json({ ok: true });
    }

    /* ---------------- cover photo ---------------- */
    if (p === "/pic" && request.method === "GET") {
      const id = url.searchParams.get("id") || "";
      const v = await env.BOOKS.get(kPic(id));
      if (!v) return json({ error: "none" }, 404);
      return json({ id, value: v });
    }

    /* ---------------- click / page-time tracking ----------------
       Anonymous by design, same as bump() above — sid is a random id the
       front end throws away when the tab closes, never tied to a uid,
       name, phone, or even stored anywhere itself (it only rides along on
       individual events so a session's page-to-page time can eventually
       be told apart from another session's, nothing more).

       No auth on this route at all — it has to work for a browsing
       stranger, not just signed-in accounts. That means it's reachable by
       anyone with curl, not just the real site, so the caps below aren't
       optional: a small fixed batch size and short fixed string lengths,
       enforced before a single write happens. Analytics Engine itself has
       no per-key write budget the way KV does (see the file header), so
       the actual risk here is junk data, not a broken app — still worth
       keeping tight. ------------------------------------------------- */
    if (p === "/track" && request.method === "POST") {
      const b = await request.json().catch(() => null);
      if (!env.ANALYTICS || !b || !Array.isArray(b.events) || !b.events.length) {
        return new Response(null, { status: 204, headers: CORS });
      }
      const sid = String(b.sid || "").replace(/[^a-zA-Z0-9-]/g, "").slice(0, 40);
      for (const e of b.events.slice(0, 30)) {
        const kind = e && e.t === "view" ? "view" : e && e.t === "click" ? "click" : null;
        if (!kind) continue;
        const label = String((e && e.label) || "").slice(0, 40);
        if (!label) continue;
        // ms only means anything for a view (dwell time); clicks just count.
        // Capped at an hour so one stuck background tab can't submit a
        // dwell time that skews an average into meaninglessness.
        const value = kind === "view" ? Math.max(0, Math.min(3600000, Number(e.ms) || 0)) : 1;
        env.ANALYTICS.writeDataPoint({ blobs: [kind, label, sid], doubles: [value], indexes: [label] });
      }
      return new Response(null, { status: 204, headers: CORS });
    }

    /* ---------------- WhatsApp verification ---------------- */
    if (p === "/webhook" && request.method === "GET") {
      const ok = url.searchParams.get("hub.mode") === "subscribe" &&
                 url.searchParams.get("hub.verify_token") === env.VERIFY_TOKEN;
      return ok
        ? new Response(url.searchParams.get("hub.challenge"), { status: 200 })
        : new Response("forbidden", { status: 403 });
    }

    if (p === "/webhook" && request.method === "POST") {
      const raw = await request.text();
      if (!(await signatureValid(request, raw, env.APP_SECRET)))
        return new Response("bad signature", { status: 401 });

      let body; try { body = JSON.parse(raw); } catch { return new Response("ok"); }
      const messages = body?.entry?.[0]?.changes?.[0]?.value?.messages || [];

      for (const m of messages) {
        if (m.type !== "text") continue;
        const phone = normPhone(m.from);              // Meta fills this, not the sender
        if (!phone) continue;
        // The phone no longer IS the uid — look up who submitted it via
        // /profile. Nobody's claimed this number yet: nothing to verify.
        const uid = await env.BOOKS.get(kPhoneUid(phone));
        if (!uid) continue;

        const sent = String(m.text?.body || "").toUpperCase().match(/\b[0-9A-Z]{4}\b/g) || [];
        if (!sent.includes(vCode(uid))) {
          await env.BOOKS.put("fail:" + phone, JSON.stringify({ at: Date.now() }), { expirationTtl: 604800 });
          continue;
        }
        const blocked = await readList(env.BOOKS, "blocked");
        if (blocked.includes(uid)) continue;

        const approved = await readList(env.BOOKS, "approved");
        if (!approved.includes(uid)) {
          approved.push(uid);
          await env.BOOKS.put("approved", JSON.stringify(approved));
          ctx.waitUntil(bump(env, "verification"));
        }
      }
      return new Response("ok", { status: 200 });   // always 200 or Meta disables the hook
    }

    /* ---------------- admin ----------------
       Founder status lives on the same Google account everyone else signs
       in with — there's no separate site, no separate login, and no key to
       type in. Whoever's email is in the ADMIN_EMAILS secret is a founder,
       full stop; the check runs fresh on every request against the caller's
       own profile record (see /profile — email comes from Google at signup
       and never changes). Add or remove a founder by editing the secret
       and redeploying:
         npx wrangler secret put ADMIN_EMAILS
       ------------------------------------------------------------------ */
    if (p === "/admin" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!(await auth(env, b.uid, b.tok))) return json({ error: "auth" }, 401);
      const myRec = await env.BOOKS.get(kUser(b.uid), "json");
      const myName = founderName(env, myRec && myRec.email);
      if (!myName) return json({ error: "notFounder" }, 403);

      const village = String(b.village || "").slice(0, 24);
      const approved = await readList(env.BOOKS, "approved");
      const blocked = await readList(env.BOOKS, "blocked");
      const put = (k, v) => env.BOOKS.put(k, JSON.stringify(v));

      /* Aggregate counters only — see bump() above. Nothing here is
         per-person; there's no uid, name, or phone in any of these keys. */
      if (b.act === "stats") {
        const events = ["signup", "shelfLoad", "publish", "verification", "reservation", "exchange"];
        const villageEvents = ["shelfLoad", "publish", "reservation", "exchange"];
        const days = 30;
        const dayList = [];
        const today = new Date();
        for (let i = days - 1; i >= 0; i--) {
          const d = new Date(today);
          d.setUTCDate(d.getUTCDate() - i);
          dayList.push(d.toISOString().slice(0, 10));
        }

        const totals = {}, daily = {};
        await Promise.all(events.map(async (ev) => {
          totals[ev] = Number((await env.BOOKS.get(`stat:total:${ev}`)) || 0);
          daily[ev] = await Promise.all(
            dayList.map(async (day) => Number((await env.BOOKS.get(`stat:day:${ev}:${day}`)) || 0))
          );
        }));

        const byVillage = {};
        await Promise.all(villageEvents.map(async (ev) => {
          const prefix = `stat:village:${ev}:`;
          const list = await env.BOOKS.list({ prefix });
          byVillage[ev] = {};
          await Promise.all(list.keys.map(async (k) => {
            byVillage[ev][k.name.slice(prefix.length)] = Number((await env.BOOKS.get(k.name)) || 0);
          }));
        }));

        /* Clicks and page-time, from Analytics Engine (see /track above),
           not KV — this is the "how are people actually moving through the
           site" layer, one level deeper than the event counters above.
           `range` picks both how far back to look and how coarse the trend
           buckets are: a day view over the last month is one thing, a year
           view needs to bucket by year or the chart is unreadable. Bucket
           widths are fixed-length approximations (a "month" is 30 days, a
           "year" is 365) rather than calendar-aligned — deliberately, since
           it only needs INTERVAL and integer division, both confirmed to
           work against this API; calendar-aware bucketing functions were
           not worth gambling on for a Sunday-vs-Monday level of precision
           nobody's asking for here. */
        const RANGES = {
          day:   { rangeDays: 30,   bucketSeconds: 86400 },
          week:  { rangeDays: 91,   bucketSeconds: 604800 },
          month: { rangeDays: 366,  bucketSeconds: 2592000 },
          year:  { rangeDays: 1827, bucketSeconds: 31536000 },
        };
        const range = RANGES[b.range] ? b.range : "day";
        const cfg = RANGES[range];
        let insights = null;
        if (env.CF_ACCOUNT_ID && env.CF_ANALYTICS_TOKEN) {
          const [trend, topViews, topClicks] = await Promise.all([
            queryAnalytics(env, `
              SELECT intDiv(toUInt32(timestamp), ${cfg.bucketSeconds}) * ${cfg.bucketSeconds} AS bucket,
                     blob1 AS kind, SUM(_sample_interval) AS n, SUM(_sample_interval * double1) AS totalMs
              FROM ${AE_DATASET}
              WHERE timestamp > NOW() - INTERVAL '${cfg.rangeDays}' DAY
              GROUP BY bucket, kind ORDER BY bucket`),
            queryAnalytics(env, `
              SELECT blob2 AS label, SUM(_sample_interval) AS n,
                     SUM(_sample_interval * double1) / SUM(_sample_interval) AS avgMs
              FROM ${AE_DATASET}
              WHERE blob1 = 'view' AND timestamp > NOW() - INTERVAL '${cfg.rangeDays}' DAY
              GROUP BY label ORDER BY n DESC LIMIT 20`),
            queryAnalytics(env, `
              SELECT blob2 AS label, SUM(_sample_interval) AS n
              FROM ${AE_DATASET}
              WHERE blob1 = 'click' AND timestamp > NOW() - INTERVAL '${cfg.rangeDays}' DAY
              GROUP BY label ORDER BY n DESC LIMIT 20`),
          ]);
          // null (not []) signals "the query itself failed" to the front
          // end, which reads differently from "ran fine, nothing happened
          // yet" — worth keeping distinct while this is still new.
          insights = { range, trend, topViews, topClicks };
        }

        return json({
          days: dayList, totals, daily, byVillage, insights,
          doneAllTime: Number((await env.BOOKS.get("stat:done")) || 0),
        });
      }

      if (b.act === "dump") {
        const [offers, wants, userKeys, log] = await Promise.all([
          readList(env.BOOKS, kList(village, "offers")),
          readList(env.BOOKS, kList(village, "wants")),
          env.BOOKS.list({ prefix: "user:" }),
          readList(env.BOOKS, "log:actions"),
        ]);
        const users = await Promise.all(userKeys.keys.map(async (k) => {
          const u = (await env.BOOKS.get(k.name, "json")) || {};
          const uid = k.name.slice(5);
          return { uid, name: u.name || "", phone: u.phone || "", at: u.at || 0,
                   approved: approved.includes(uid), blocked: blocked.includes(uid),
                   claimedBy: u.claimedBy || "",
                   notes: Array.isArray(u.notes) ? u.notes
                        : (u.note ? [{ by: "", text: u.note, at: u.at || 0 }] : []) };
        }));
        // Most recent first — that is what a founder opening the panel wants to see.
        return json({ offers, wants, users, approved, blocked, me: myName,
                      log: log.slice(-100).reverse() });
      }

      if (b.act === "approve" || b.act === "unapprove") {
        const next = b.act === "approve"
          ? (approved.includes(b.target) ? approved : approved.concat([b.target]))
          : approved.filter((x) => x !== b.target);
        await put("approved", next);
        await logAction(env, myName, b.act, b.target);
        return json({ ok: true });
      }

      if (b.act === "block" || b.act === "unblock") {
        const next = b.act === "block"
          ? (blocked.includes(b.target) ? blocked : blocked.concat([b.target]))
          : blocked.filter((x) => x !== b.target);
        await put("blocked", next);
        await logAction(env, myName, b.act, b.target);
        return json({ ok: true });
      }

      // Clears the stored session token, signing the account out everywhere
      // until they sign in with Google again. Under Google auth this isn't
      // needed to switch devices — any device signs in fine — but it's kept
      // as a blunt "kick this account off" tool for the admin panel.
      if (b.act === "resetDevice") {
        await env.BOOKS.delete(kTok(b.target));
        await logAction(env, myName, "resetDevice", b.target);
        return json({ ok: true });
      }

      if (b.act === "delListing") {
        const kind = b.kind === "wants" ? "wants" : "offers";
        const key = kList(village, kind);
        const list = await readList(env.BOOKS, key);
        const gone = list.find((x) => x.id === b.id);
        if (gone && gone.pic) await env.BOOKS.delete(kPic(gone.id));
        await put(key, list.filter((x) => x.id !== b.id));
        await logAction(env, myName, "delListing", b.id, gone ? gone.title || gone.subject || "" : "");
        return json({ ok: true });
      }

      // Removes the person entirely: listings, photos, device claim, and the
      // stored contact record. Use when someone asks to be deleted.
      if (b.act === "purgeUser") {
        for (const kind of ["offers", "wants"]) {
          const key = kList(village, kind);
          const list = await readList(env.BOOKS, key);
          const keep = [];
          for (const r of list) {
            if (r.uid === b.target) { if (r.pic) await env.BOOKS.delete(kPic(r.id)); }
            else keep.push(r);
          }
          await put(key, keep);
        }
        // Grab the phone before the user record is gone, so the phone->uid
        // index (phuid:<phone>) can be cleaned up too. Without this, a
        // purged uid stays claiming the number forever and it can never be
        // submitted again as phoneTaken.
        const purgedRec = await env.BOOKS.get(kUser(b.target), "json");
        await env.BOOKS.delete(kTok(b.target));
        await env.BOOKS.delete(kUser(b.target));
        if (purgedRec && purgedRec.phone) {
          const holder = await env.BOOKS.get(kPhoneUid(purgedRec.phone));
          if (holder === b.target) await env.BOOKS.delete(kPhoneUid(purgedRec.phone));
        }
        await put("approved", approved.filter((x) => x !== b.target));
        await logAction(env, myName, "purgeUser", b.target);
        return json({ ok: true });
      }

      /* --- verification coordination: who's already calling whom, and what
             happened on the call. Prevents two founders phoning the same
             person and gives the team a shared record instead of memory. --- */
      if (b.act === "claim" || b.act === "release") {
        const rec = await env.BOOKS.get(kUser(b.target), "json");
        if (!rec) return json({ error: "gone" }, 404);
        rec.claimedBy = b.act === "claim" ? myName : "";
        await env.BOOKS.put(kUser(b.target), JSON.stringify(rec));
        await logAction(env, myName, b.act, b.target);
        return json({ ok: true });
      }

      if (b.act === "addNote") {
        const rec = await env.BOOKS.get(kUser(b.target), "json");
        if (!rec) return json({ error: "gone" }, 404);
        const text = String(b.text || "").slice(0, 300).trim();
        if (!text) return json({ error: "empty" }, 400);
        const notes = Array.isArray(rec.notes) ? rec.notes : [];
        notes.push({ by: myName, text, at: Date.now() });
        rec.notes = notes.slice(-50); // cap so one record can't grow without bound
        await env.BOOKS.put(kUser(b.target), JSON.stringify(rec));
        await logAction(env, myName, "addNote", b.target, text);
        return json({ ok: true });
      }

      return json({ error: "act" }, 400);
    }

    return new Response("not found", { status: 404, headers: CORS });
  },
};
