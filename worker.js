/**
 * أثر — تبادل الكتب · backend
 * Cloudflare Worker + KV. Holds the listings so everyone sees the same shelf.
 *
 * Endpoints
 *   POST /data      { village, uid?, tok? }        -> shelf. Names and phones
 *                                                    only for identified users.
 *   POST /publish   { village, kind, uid, tok, records[], pics{} }
 *   POST /update    { village, kind, uid, tok, id, act }
 *   GET  /pic?id=
 *   GET  /webhook   Meta handshake
 *   POST /webhook   incoming WhatsApp -> auto-approve
 *
 * Two rules that matter:
 *   1. The server decides who you are from your token. It never trusts a uid
 *      in the request body for authorization.
 *   2. Anonymous callers get books without names or numbers. Identity is
 *      exchanged for identity.
 *
 * Secrets: VERIFY_TOKEN, APP_SECRET, ADMIN_KEY, PEPPER.   KV binding: BOOKS
 */

/**
 * Which sites may call this Worker from a browser. Put your GitHub Pages URL
 * here. "null" covers admin.html opened as a local file on your laptop.
 * Leave the array empty to allow everyone (fine while testing, not after).
 *
 * This is a fence, not a lock: a script outside a browser ignores it entirely.
 * The token and key checks are what actually protect the data.
 */
const ALLOWED = [
  "https://athar-books.github.io",
  // The admin panel deployed for phone access. If you ever redeploy
  // admin.html under a different qz7m-panel... URL, update this too, or
  // every button in it will silently stop working.
  "https://qz7m-panel26bgfg-e.athar-kutub.workers.dev",
];

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
const kPend = (uid) => `pend:${uid}`;
// A phone number is a household, not a single account. kHouse lists every
// account registered on that number so a shared family phone can hold more
// than one person.
const kHouse = (phone) => `hh:${phone}`;

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
/**
 * Password hashing.
 *
 * Salt per user, plus a server-side pepper (PEPPER secret) that never touches
 * KV — so a leaked KV dump alone cannot be brute-forced offline.
 *
 * This is HMAC, not PBKDF2/bcrypt. Workers on the free plan get ~10ms CPU per
 * request and a proper slow hash blows through that. The pepper is what carries
 * the weight here. If this ever moves to a paid plan, switch to PBKDF2 with
 * 100k iterations and re-hash on next login.
 */
async function hashPass(pass, salt, pepper) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(pepper || "no-pepper-set"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(salt + "|" + pass));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function sameHash(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function newSalt() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function readList(kv, key) {
  const v = await kv.get(key, "json");
  return Array.isArray(v) ? v : [];
}

/**
 * First device to claim an account keeps it. A second device with a different
 * token is refused until the account re-verifies over WhatsApp, which is what
 * stops someone signing in as you just by knowing your number.
 */
async function auth(env, uid, tok) {
  if (!uid || !tok || !uid.startsWith("p:")) return false;
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
    title: r.title, cond: r.cond, school: r.school, handoff: r.handoff,
    pic: !!r.pic, at: r.at, status: effStatus(r),
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
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    CORS = cors(request);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    /* ---------------- sign up / sign in ----------------
       One number, one account. The first device to claim it keeps it. A second
       device is held pending until the account proves itself over WhatsApp,
       which is what stops someone signing in as you just by knowing your
       number.
       ------------------------------------------------------------------ */
    if (p === "/session" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const tok = String(b.tok || "");
      const pass = String(b.pass || "");
      // Older pages only ever sent a self-computed uid ("p:"+phone). Accept
      // that too, so nothing already deployed breaks while this rolls out.
      const rawUid = String(b.uid || "");
      const phone = normPhone(b.phone || (rawUid.startsWith("p:") ? rawUid.slice(2).split("#")[0] : ""));
      if (!tok || phone.length < 9) return json({ error: "bad" }, 400);

      const houseKey = kHouse(phone);
      let house = await readList(env.BOOKS, houseKey);

      // Self-heal: an account created before this feature existed has a user
      // record at the bare uid but was never indexed into a household list.
      if (!house.length) {
        const legacyUid = "p:" + phone;
        const legacyRec = await env.BOOKS.get(kUser(legacyUid), "json");
        if (legacyRec) house = [{ uid: legacyUid, name: legacyRec.name || "" }];
      }

      /* --- who is registered on this number, for the sign-in name picker --- */
      if (b.mode === "who") {
        return json({ accounts: house.map((h) => ({ uid: h.uid, name: h.name })) });
      }

      /* --- new account: always allowed, even if the number already has one.
             A shared family phone is normal here — identity is checked by a
             founder phoning the number, not by the number being untaken. --- */
      if (b.mode === "signup") {
        if (pass.length < 6) return json({ ok: false, weakPass: true });
        const name = String(b.name || "").replace(/\s+/g, " ").trim() ||
          [b.first, b.father, b.family].filter(Boolean).join(" ").trim();
        if (name.length < 5 || name.split(" ").filter(Boolean).length < 2) {
          return json({ ok: false, needName: true });
        }
        // No two accounts on the same phone may share a password — otherwise
        // the "pick your name" step at sign-in is cosmetic, since either
        // password would unlock either identity.
        for (const h of house) {
          const hrec = await env.BOOKS.get(kUser(h.uid), "json");
          if (hrec && sameHash(hrec.hash, await hashPass(pass, hrec.salt || "", env.PEPPER))) {
            return json({ ok: false, dupPass: true });
          }
        }

        const newUid = house.length ? `p:${phone}#${house.length + 1}` : `p:${phone}`;
        const salt = newSalt();
        await env.BOOKS.put(kUser(newUid), JSON.stringify({
          name, phone, salt, hash: await hashPass(pass, salt, env.PEPPER), at: Date.now(),
        }));
        house.push({ uid: newUid, name });
        await env.BOOKS.put(houseKey, JSON.stringify(house));
        await env.BOOKS.put(kTok(newUid), tok);
        return json({ ok: true, uid: newUid, name: { name } });
      }

      /* --- password sign in. One account on the number: transparent, same
             as before this change. Several: the client must say which uid,
             which it only knows after the person picks their name. --- */
      if (b.mode === "signin") {
        if (!house.length) return json({ ok: false, noAccount: true });

        let target;
        if (house.length === 1) {
          target = house[0];
        } else if (rawUid && house.some((h) => h.uid === rawUid)) {
          target = house.find((h) => h.uid === rawUid);
        } else {
          return json({ ok: false, pickAccount: true, accounts: house.map((h) => ({ uid: h.uid, name: h.name })) });
        }

        const rec = await env.BOOKS.get(kUser(target.uid), "json");
        if (!rec) return json({ ok: false, noAccount: true });
        const ok = sameHash(rec.hash, await hashPass(pass, rec.salt || "", env.PEPPER));
        if (!ok) return json({ ok: false, badPass: true });
        await env.BOOKS.put(kTok(target.uid), tok);
        const approved = await readList(env.BOOKS, "approved");
        return json({ ok: true, uid: target.uid, name: { name: rec.name }, verified: approved.includes(target.uid) });
      }

      /* --- set a new password. Requires a session already proven on this
             exact uid — recovery for a forgotten password is an admin reset,
             not self-service, per house rules (no outbound messages). --- */
      if (b.mode === "setpass") {
        if (!rawUid) return json({ error: "bad" }, 400);
        const rec = await env.BOOKS.get(kUser(rawUid), "json");
        if (!rec) return json({ ok: false, noAccount: true });
        const held = await env.BOOKS.get(kTok(rawUid));
        if (held !== tok) return json({ error: "auth" }, 401);
        if (pass.length < 6) return json({ ok: false, weakPass: true });

        const siblings = (await readList(env.BOOKS, kHouse(rec.phone))).filter((h) => h.uid !== rawUid);
        for (const h of siblings) {
          const hrec = await env.BOOKS.get(kUser(h.uid), "json");
          if (hrec && sameHash(hrec.hash, await hashPass(pass, hrec.salt || "", env.PEPPER))) {
            return json({ ok: false, dupPass: true });
          }
        }

        const salt = newSalt();
        await env.BOOKS.put(kUser(rawUid), JSON.stringify({ ...rec, salt, hash: await hashPass(pass, salt, env.PEPPER) }));
        return json({ ok: true, name: { name: rec.name } });
      }

      return json({ error: "mode" }, 400);
    }

    /* ---------------- shelf ---------------- */
    if (p === "/data" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const village = String(b.village || "").slice(0, 24);
      if (!village) return json({ error: "village" }, 400);

      const ok = b.uid && b.tok ? await auth(env, b.uid, b.tok) : false;
      const uid = ok ? b.uid : null;

      const [offers, wants, approved, blocked, doneRaw] = await Promise.all([
        readList(env.BOOKS, kList(village, "offers")),
        readList(env.BOOKS, kList(village, "wants")),
        readList(env.BOOKS, "approved"),
        readList(env.BOOKS, "blocked"),
        env.BOOKS.get("stat:done"),
      ]);
      const live = (arr) => arr.filter((r) => !blocked.includes(r.uid))
        // Hidden from everyone but the owner until the account is verified —
        // the instant a founder approves it in admin, the same filter lets
        // every listing that account already posted through, with nothing
        // to republish.
        .filter((r) => approved.includes(r.uid) || r.uid === uid)
        .map((r) => view({ ...r, ver: approved.includes(r.uid) }, uid));

      return json({
        offers: live(offers), wants: live(wants),
        me: uid ? { verified: approved.includes(uid), blocked: false } : null,
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
        school: String(r.school || "").slice(0, 60),
        handoff: r.handoff === "direct" ? "direct" : "point",
        name: String(b.name || "").slice(0, 80),
        phone: r.handoff === "direct" ? b.uid.slice(2) : "",
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

      await env.BOOKS.put(kUser(b.uid), JSON.stringify({
        name: String(b.name || "").slice(0, 80), phone: b.uid.slice(2),
        village, at: now,
      }));

      const key = kList(village, kind);
      const latest = await readList(env.BOOKS, key);
      await env.BOOKS.put(key, JSON.stringify(clean.concat(latest).slice(0, 3000)));
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
      } else if (act === "release") {
        if (!owner && !holder) return json({ error: "forbidden" }, 403);
        r.status = "open"; r.holder = ""; r.holderName = "";
        r.resAt = 0; r.confOwner = false; r.confHolder = false;
      } else if (act === "okHolder") {
        if (!holder) return json({ error: "forbidden" }, 403);
        r.confHolder = true;
      } else if (act === "okOwner") {
        // Done means gone: the record and its photo are removed, and the count
        // of completed exchanges is incremented so the number survives.
        if (!owner) return json({ error: "forbidden" }, 403);
        list.splice(i, 1);
        if (r.pic) await env.BOOKS.delete(kPic(r.id));
        const done = Number((await env.BOOKS.get("stat:done")) || 0) + 1;
        await env.BOOKS.put("stat:done", String(done));
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
        const uid = "p:" + phone;
        const sent = String(m.text?.body || "").toUpperCase().match(/\b[0-9A-Z]{4}\b/g) || [];
        if (!sent.includes(vCode(uid))) {
          await env.BOOKS.put("fail:" + phone, JSON.stringify({ at: Date.now() }), { expirationTtl: 604800 });
          continue;
        }
        const blocked = await readList(env.BOOKS, "blocked");
        if (blocked.includes(uid)) continue;

        // A device waiting on this number is now proven. Hand it the account.
        const pend = await env.BOOKS.get(kPend(uid));
        if (pend) {
          await env.BOOKS.put(kTok(uid), pend);
          await env.BOOKS.delete(kPend(uid));
        }

        const approved = await readList(env.BOOKS, "approved");
        if (!approved.includes(uid)) {
          approved.push(uid);
          await env.BOOKS.put("approved", JSON.stringify(approved));
        }
      }
      return new Response("ok", { status: 200 });   // always 200 or Meta disables the hook
    }

    /* ---------------- admin ----------------
       One shared key, checked in constant time. Everything destructive lives
       behind it. Rotate with: npx wrangler secret put ADMIN_KEY
       ------------------------------------------------------------------ */
    if (p === "/admin" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));

      // Each founder has their own key. The server resolves who they are
      // from it — a name typed into a box could be anyone; a personal key
      // can't be. ADMIN_KEYS is a JSON secret: {"key1":"محمود","key2":"رنا"}.
      let keyMap = {};
      try { keyMap = JSON.parse(env.ADMIN_KEYS || "{}"); } catch (e) {}
      const givenKey = String(b.key || "");
      let founderName = "";
      for (const k of Object.keys(keyMap)) {
        if (sameHash(k, givenKey)) { founderName = keyMap[k]; break; }
      }
      if (!founderName) return json({ error: "key" }, 401);

      const village = String(b.village || "").slice(0, 24);
      const approved = await readList(env.BOOKS, "approved");
      const blocked = await readList(env.BOOKS, "blocked");
      const put = (k, v) => env.BOOKS.put(k, JSON.stringify(v));

      if (b.act === "dump") {
        const [offers, wants, userKeys] = await Promise.all([
          readList(env.BOOKS, kList(village, "offers")),
          readList(env.BOOKS, kList(village, "wants")),
          env.BOOKS.list({ prefix: "user:" }),
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
        return json({ offers, wants, users, approved, blocked, me: founderName });
      }

      if (b.act === "approve" || b.act === "unapprove") {
        const next = b.act === "approve"
          ? (approved.includes(b.uid) ? approved : approved.concat([b.uid]))
          : approved.filter((x) => x !== b.uid);
        await put("approved", next);
        return json({ ok: true });
      }

      if (b.act === "block" || b.act === "unblock") {
        const next = b.act === "block"
          ? (blocked.includes(b.uid) ? blocked : blocked.concat([b.uid]))
          : blocked.filter((x) => x !== b.uid);
        await put("blocked", next);
        return json({ ok: true });
      }

      // Frees the account so the person can sign in again on a new phone.
      if (b.act === "resetDevice") {
        await env.BOOKS.delete(kTok(b.uid));
        return json({ ok: true });
      }

      if (b.act === "delListing") {
        const kind = b.kind === "wants" ? "wants" : "offers";
        const key = kList(village, kind);
        const list = await readList(env.BOOKS, key);
        const gone = list.find((x) => x.id === b.id);
        if (gone && gone.pic) await env.BOOKS.delete(kPic(gone.id));
        await put(key, list.filter((x) => x.id !== b.id));
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
            if (r.uid === b.uid) { if (r.pic) await env.BOOKS.delete(kPic(r.id)); }
            else keep.push(r);
          }
          await put(key, keep);
        }
        await env.BOOKS.delete(kTok(b.uid));
        await env.BOOKS.delete(kUser(b.uid));
        await put("approved", approved.filter((x) => x !== b.uid));
        return json({ ok: true });
      }

      /* --- verification coordination: who's already calling whom, and what
             happened on the call. Prevents two founders phoning the same
             person and gives the team a shared record instead of memory. --- */
      if (b.act === "claim" || b.act === "release") {
        const rec = await env.BOOKS.get(kUser(b.uid), "json");
        if (!rec) return json({ error: "gone" }, 404);
        rec.claimedBy = b.act === "claim" ? founderName : "";
        await env.BOOKS.put(kUser(b.uid), JSON.stringify(rec));
        return json({ ok: true });
      }

      if (b.act === "addNote") {
        const rec = await env.BOOKS.get(kUser(b.uid), "json");
        if (!rec) return json({ error: "gone" }, 404);
        const text = String(b.text || "").slice(0, 300).trim();
        if (!text) return json({ error: "empty" }, 400);
        const notes = Array.isArray(rec.notes) ? rec.notes : [];
        notes.push({ by: founderName, text, at: Date.now() });
        rec.notes = notes.slice(-50); // cap so one record can't grow without bound
        await env.BOOKS.put(kUser(b.uid), JSON.stringify(rec));
        return json({ ok: true });
      }

      return json({ error: "act" }, 400);
    }

    return new Response("not found", { status: 404, headers: CORS });
  },
};
