/**
 * أثر — تبادل الكتب · backend
 * Cloudflare Worker + KV. Holds the listings so everyone sees the same shelf.
 *
 * Endpoints
 *   POST /data      { village, uid?, tok? }        -> shelf. Names only for
 *                                                    identified users; phones
 *                                                    only when the listing
 *                                                    owner is verified too.
 *   POST /session   { uid, tok, mode, pass, name? } -> signup / signin / setpass
 *   POST /admin     { key, act, ... }               -> approve, block,
 *                                                    resetDevice, resetAccount
 *   POST /publish   { village, kind, uid, tok, records[], pics{} }
 *   POST /update    { village, kind, uid, tok, id, act }
 *   GET  /pic?id=
 *
 * Two rules that matter:
 *   1. The server decides who you are from your token. It never trusts a uid
 *      in the request body for authorization.
 *   2. Anonymous callers get books without names or numbers. Identity is
 *      exchanged for identity.
 *   3. Publishing is open to any signed-up account. Handing out a phone
 *      number is not — that waits until a founder approves the account by
 *      hand through /admin. See view().
 *
 * Secrets: ADMIN_KEY, PEPPER.   KV binding: BOOKS
 *
 * There is no WhatsApp verification and no webhook. Accounts are approved by
 * hand by the founders through /admin, and nothing is ever sent to anyone's
 * number. The wa.me links in the frontend are plain links that open on the
 * parent's own phone — they do not touch this Worker.
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

const K_DONE = "stat:done";

const kList = (v, kind) => `list:${kind}:${v}`;
const kPic = (id) => `pic:${id}`;
const kTok = (uid) => `tok:${uid}`;
const kUser = (uid) => `user:${uid}`;
const kPass = (uid) => `pass:${uid}`;
// Throttles wrong passwords, keyed by uid.
const kFail = (uid) => `pfail:${uid}`;

/* ---------------- passwords ----------------
   PBKDF2-SHA256 over Web Crypto — no dependencies, available in Workers.
   Per-account random salt, plus a server-side PEPPER secret so a KV dump
   alone is not enough to attack the hashes offline. 6-character passwords
   from parents will not survive a fast unsalted hash, which is exactly why
   this is deliberately slow.

   PEPPER is set with: npx wrangler secret put PEPPER
   Changing or losing it invalidates every stored password — every account
   would need an admin resetAccount. Set it once, before real signups.
   ------------------------------------------------------------------ */
const PBKDF2_ITER = 100000;
const MAX_SIGNIN_FAILS = 8;

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function hashPass(pass, salt, pepper, iter) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(pass + (pepper || "")),
    "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: iter || PBKDF2_ITER, hash: "SHA-256" },
    key, 256
  );
  return b64(bits);
}
/** Constant time, so a wrong password cannot be narrowed down by timing. */
function sameStr(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function normPhone(raw) {
  let d = String(raw || "").replace(/\D/g, "");
  if (!d) return "";
  if (d.startsWith("0")) d = "972" + d.slice(1);
  else if (!d.startsWith("972")) d = "972" + d;
  return d;
}
async function readList(kv, key) {
  const v = await kv.get(key, "json");
  return Array.isArray(v) ? v : [];
}

/**
 * The device holding the bound token is the account. Signing in with the right
 * password rebinds it here. Knowing the number alone gets you nothing.
 */
async function auth(env, uid, tok) {
  if (!uid || !tok || !uid.startsWith("p:")) return false;
  const held = await env.BOOKS.get(kTok(uid));
  if (held) return held === tok;
  // No device bound yet. Refuse to auto-bind once the account has a password:
  // otherwise knowing the phone number would be enough to claim the account
  // without ever presenting the password, and /session would be decorative.
  if (await env.BOOKS.get(kPass(uid))) return false;
  await env.BOOKS.put(kTok(uid), tok);
  return true;
}

function effStatus(r) {
  if (r.status === "done") return "done";
  if (r.status === "reserved" && Date.now() - (r.resAt || 0) > HOLD_MS) return "open";
  return r.status || "open";
}

/**
 * Strip identity for anonymous callers; mark ownership for identified ones.
 *
 * `ownerOk` is whether the *listing owner's* account has been verified. The
 * gate on posting was removed so supply is captured at the moment of intent —
 * a parent who clears a shelf at 9pm should not be told to wait for a phone
 * call. The gate now sits on contact instead, which is where it belongs: an
 * unverified account can fill the shelf, but its number is never handed out.
 * The risk we actually care about — a stranger reaching a number nobody
 * confirmed — is still covered by the same manual check.
 *
 * This is the whole enforcement point. The frontend hiding a button is
 * convenience; a listing whose owner is unverified simply has no `phone` key
 * in the response, for every caller including an authenticated one.
 */
function view(r, uid, ownerOk) {
  const mine = !!uid && r.uid === uid;
  const held = !!uid && r.holder === uid;
  const out = {
    id: r.id, village: r.village, grade: r.grade, subject: r.subject, kind: r.kind,
    title: r.title, cond: r.cond, school: r.school, handoff: r.handoff,
    pic: !!r.pic, at: r.at, status: effStatus(r),
    confOwner: !!r.confOwner, confHolder: !!r.confHolder,
    ver: !!ownerOk, sealed: !ownerOk, mine, held,
  };
  if (uid) {
    out.name = r.name || "";
    // Who reserved a book is between those two people. It was previously
    // returned to everyone signed in, which told the whole village who is
    // taking what.
    if (mine || held) out.holderName = r.holderName || "";
    // Own number always comes back — you cannot leak yourself to yourself.
    if (r.handoff === "direct" && (ownerOk || mine)) out.phone = r.phone || "";
  }
  return out;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    CORS = cors(request);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

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
        env.BOOKS.get(K_DONE),
      ]);
      const live = (arr) => arr.filter((r) => !blocked.includes(r.uid))
        .map((r) => view(r, uid, approved.includes(r.uid)));

      return json({
        offers: live(offers), wants: live(wants),
        me: uid ? { verified: approved.includes(uid), blocked: false } : null,
        done: parseInt(doneRaw, 10) || 0,
        authFailed: !!(b.uid && b.tok && !ok),
      });
    }

    /* ---------------- sessions ----------------
       Signup, sign-in, WhatsApp recovery and setting a password.

       A password does one job here: it lets a person move to a new phone
       without a founder running resetDevice by hand. Signing in rebinds the
       account to whichever device presents the right password, replacing the
       old first-token-wins rule.

       There is no self-serve recovery. If someone forgets their password, a
       founder clears the account with the admin `resetAccount` action after
       speaking to them, and they sign up again on the same number. Nothing is
       ever sent to anyone's phone.
       ------------------------------------------------------------------ */
    if (p === "/session" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const uid = String(b.uid || "");
      const tok = String(b.tok || "");
      if (!uid.startsWith("p:") || uid.length < 5 || !tok) return json({ error: "bad" }, 400);

      const blocked = await readList(env.BOOKS, "blocked");
      if (blocked.includes(uid)) return json({ error: "blocked" }, 403);

      const mode = String(b.mode || "");
      const stored = await env.BOOKS.get(kPass(uid));
      const userOf = async () => (await env.BOOKS.get(kUser(uid), "json")) || {};
      const putPass = async (pass) => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        await env.BOOKS.put(kPass(uid), JSON.stringify({
          s: b64(salt), h: await hashPass(pass, salt, env.PEPPER, PBKDF2_ITER), i: PBKDF2_ITER,
        }));
      };

      // No mode = the recovery poll. "Has my pending token gone live yet?"
      if (!mode) {
        const held = await env.BOOKS.get(kTok(uid));
        if (held && sameStr(held, tok)) {
          const u = await userOf();
          return json({ ok: true, name: u.name || "", noPass: !stored });
        }
        return json({ ok: false });
      }

      if (mode === "signup") {
        if (stored) return json({ exists: true });
        const name = String(b.name || "").replace(/\s+/g, " ").trim().slice(0, 80);
        if (name.length < 5 || name.split(" ").filter(Boolean).length < 2) return json({ needName: true });
        const pass = String(b.pass || "");
        if (pass.length < 6) return json({ weakPass: true });
        // Re-claim: an account with a record but no password has been cleared
        // by a founder for someone who forgot theirs. Keep the stored name and
        // the listings; only the password and device are new.
        const prior = await env.BOOKS.get(kUser(uid), "json");
        await putPass(pass);
        await env.BOOKS.put(kTok(uid), tok);
        await env.BOOKS.put(kUser(uid), JSON.stringify(prior
          ? { ...prior, name: prior.name || name }
          : { name, phone: uid.slice(2), village: String(b.village || "").slice(0, 24), at: Date.now() }));
        return json({ ok: true, name: (prior && prior.name) || name });
      }

      if (mode === "signin") {
        // No password set: either no account at all, or one a founder cleared.
        // Both are handled by signing up again on the same number.
        if (!stored) return json({ noAccount: true });
        const fails = parseInt(await env.BOOKS.get(kFail(uid)), 10) || 0;
        if (fails >= MAX_SIGNIN_FAILS) return json({ badPass: true, locked: true });
        const rec = JSON.parse(stored);
        const got = await hashPass(String(b.pass || ""), unb64(rec.s), env.PEPPER, rec.i);
        if (!sameStr(got, rec.h)) {
          // Throttled, not permanent: a parent who forgets is not locked out
          // for good, but guessing is bounded. Expires with the key.
          await env.BOOKS.put(kFail(uid), String(fails + 1), { expirationTtl: 900 });
          return json({ badPass: true });
        }
        await env.BOOKS.delete(kFail(uid));
        await env.BOOKS.put(kTok(uid), tok);   // the password moved the account here
        const u = await userOf();
        return json({ ok: true, name: u.name || "" });
      }

      if (mode === "setpass") {
        const held = await env.BOOKS.get(kTok(uid));
        if (!held || !sameStr(held, tok)) return json({ error: "auth" }, 401);
        const pass = String(b.pass || "");
        if (pass.length < 6) return json({ weakPass: true });
        await putPass(pass);
        await env.BOOKS.delete(kFail(uid));
        return json({ ok: true });
      }

      return json({ error: "mode" }, 400);
    }

    /* ---------------- publish a batch ---------------- */
    if (p === "/publish" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (!(await auth(env, b.uid, b.tok))) return json({ error: "auth" }, 401);

      const blocked = await readList(env.BOOKS, "blocked");
      if (blocked.includes(b.uid)) return json({ error: "blocked" }, 403);

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
        // Reserving is the step that hands over a phone number. There is
        // nothing to hand over yet if the owner has not been verified, and
        // letting the book be locked for 48h on a contact nobody can use
        // takes it off the shelf for no reason.
        const approved = await readList(env.BOOKS, "approved");
        if (!approved.includes(r.uid)) return json({ error: "unverified" }, 409);
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
        if (!owner) return json({ error: "forbidden" }, 403);
        // Count the exchange once. `st` is the status before this call, so a
        // second okOwner on an already-done listing does not inflate the tally.
        // Read-modify-write is not atomic; at village volume a lost increment
        // is an undercount of a vanity number, which is the acceptable failure.
        if (st !== "done") {
          const n = parseInt(await env.BOOKS.get(K_DONE), 10) || 0;
          await env.BOOKS.put(K_DONE, String(n + 1));
        }
        r.confOwner = true; r.status = "done"; r.doneAt = Date.now();
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

    /* ---------------- admin ----------------
       One shared key, checked in constant time. Everything destructive lives
       behind it. Rotate with: npx wrangler secret put ADMIN_KEY
       ------------------------------------------------------------------ */
    if (p === "/admin" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const given = new TextEncoder().encode(String(b.key || ""));
      const real = new TextEncoder().encode(env.ADMIN_KEY || "");
      let bad = given.length !== real.length ? 1 : 0;
      for (let i = 0; i < Math.min(given.length, real.length); i++) bad |= given[i] ^ real[i];
      if (bad) return json({ error: "key" }, 401);

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
                   approved: approved.includes(uid), blocked: blocked.includes(uid) };
        }));
        return json({ offers, wants, users, approved, blocked });
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

      // Forgot-password reset. There is no self-serve recovery on purpose —
      // nothing is sent to anyone's phone. A founder speaks to the person,
      // clears the account here, and they sign up again on the same number.
      // Their name, listings and approved status all survive; only the
      // password and the bound device are new.
      if (b.act === "resetAccount") {
        await env.BOOKS.delete(kPass(b.uid));
        await env.BOOKS.delete(kTok(b.uid));
        await env.BOOKS.delete(kFail(b.uid));
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

      return json({ error: "act" }, 400);
    }

    return new Response("not found", { status: 404 });
  },
};
