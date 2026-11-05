// =====================================================================
// Athar — exchange-confirmation reminders
// The email only reminds and links to the site. It changes nothing;
// the owner updates the book status himself on the website.
// Paste this whole block into worker.js (top level, outside handlers).
// Lines marked  ADAPT  must match your actual KV schema.
// =====================================================================

const REMIND = {
  PREFIX: 'remind:',                 // KV index: one key per pending reservation
  STEPS_H: [48, 120],                // owner reminder emails: 48h and 5 days after reservation
  ESCALATE_H: 168,                   // 7 days: email OWNER_EMAIL (you) for manual follow-up, then stop
  SEND_HOURS: [9, 21],               // only send 09:00–21:00 Israel time
  SITE: 'https://athar-books.github.io',
  FROM: 'Athar <noreply@YOUR-DOMAIN>',            // ADAPT: the same verified "from" you already use with Resend
};

// ADAPT: where the button sends the owner. If the frontend can open a
// specific post or a "my posts" view from a URL parameter, point it there.
const rmPostUrl = postId => `${REMIND.SITE}/?post=${encodeURIComponent(postId)}`;

// Arabic copy — placeholders, rewrite in your voice.
const REMIND_COPY = {
  subject: t => `هل تم تسليم كتاب "${t}"؟`,
  hello: n => (n ? `مرحبا ${n}،` : 'مرحبا،'),
  body: t => `تم حجز كتابك "${t}" ولم يتم تأكيد التبادل بعد. إذا تم التسليم، ادخل إلى أثر وأكّد التبادل. إذا لم يتم، يمكنك إلغاء الحجز من الموقع حتى يعود الكتاب للعرض.`,
  btn: 'افتح أثر',
};

// ---------------------------------------------------------------------
// ADAPT — the only functions that touch your existing data model
// ---------------------------------------------------------------------
const rmKV = env => env.KV;                                   // ADAPT: your KV binding name

async function rmGetPost(env, postId) {                      // ADAPT: your post key format
  return rmKV(env).get('post:' + postId, 'json');
}

function rmIsPending(post, reservedAt) {                     // ADAPT: your status fields
  // Still reserved, not yet confirmed, and the same reservation the reminder was created for.
  return !!post && post.status === 'reserved' && Number(post.reservedAt) === Number(reservedAt);
}

// ---------------------------------------------------------------------
// Hooks — call these from your existing handlers
// ---------------------------------------------------------------------

// Call right after a reservation succeeds.
// reservedAt must be the same number (ms) you store on the post.
async function rmTrack(env, { postId, reservedAt, ownerEmail, ownerName, title }) {
  if (!ownerEmail) return;
  await rmKV(env).put(REMIND.PREFIX + postId, '', {
    metadata: {
      r: Number(reservedAt),
      e: ownerEmail,
      nm: String(ownerName || '').slice(0, 40),
      t: String(title || '').slice(0, 80),   // KV metadata cap is 1024 bytes
      n: 0,                                  // reminders sent so far
    },
  });
}

// Call after confirm, after reservation cancel, and after post delete.
async function rmClear(env, postId) {
  await rmKV(env).delete(REMIND.PREFIX + postId);
}

// ---------------------------------------------------------------------
// Scheduled job (hourly cron)
// ---------------------------------------------------------------------
function rmInWindow(date = new Date()) {
  const h = Number(new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Asia/Jerusalem', hour: '2-digit', hourCycle: 'h23',
  }).format(date));
  return h >= REMIND.SEND_HOURS[0] && h < REMIND.SEND_HOURS[1];
}

async function rmRun(env, now = Date.now(), force = false) {
  if (!force && !rmInWindow(new Date(now))) return { skipped: 'outside window' };
  const kv = rmKV(env);
  const stats = { checked: 0, reminded: 0, escalated: 0, cleared: 0, failed: 0 };
  let cursor;
  do {
    const page = await kv.list({ prefix: REMIND.PREFIX, cursor });
    for (const k of page.keys) {
      stats.checked++;
      try {
        const res = await rmProcess(env, k, now);
        if (res) stats[res]++;
      } catch (e) {
        stats.failed++;
        console.log('remind fail', k.name, e && e.message);   // retried next hour
      }
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  return stats;
}

async function rmProcess(env, k, now) {
  const kv = rmKV(env);
  const m = k.metadata;
  const postId = k.name.slice(REMIND.PREFIX.length);
  if (!m || !m.r) { await kv.delete(k.name); return 'cleared'; }

  const ageH = (now - m.r) / 3600000;
  const isEscalation = m.n >= REMIND.STEPS_H.length;
  const dueAt = isEscalation ? REMIND.ESCALATE_H : REMIND.STEPS_H[m.n];
  if (ageH < dueAt) return null;

  // Re-check the real post: never email about something already confirmed/cancelled.
  const post = await rmGetPost(env, postId);
  if (!rmIsPending(post, m.r)) { await kv.delete(k.name); return 'cleared'; }

  if (!isEscalation) {
    await rmSend(env, m.e, REMIND_COPY.subject(m.t), rmEmailHtml(postId, m));
    m.n++;
    await kv.put(k.name, '', { metadata: m });
    return 'reminded';
  }

  if (env.OWNER_EMAIL) {
    await rmSend(env, env.OWNER_EMAIL, `[Athar] Unconfirmed exchange after 7 days: ${m.t}`,
      `<p>Post <b>${rmEsc(postId)}</b> ("${rmEsc(m.t)}") reserved ${new Date(m.r).toISOString()} — ` +
      `owner ${rmEsc(m.nm)} &lt;${rmEsc(m.e)}&gt; did not respond to ${REMIND.STEPS_H.length} reminders. ` +
      `Follow up manually.</p>`);
  }
  await kv.delete(k.name);
  return 'escalated';
}

// ---------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------
async function rmSend(env, to, subject, html) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: REMIND.FROM, to: [to], subject, html }),
  });
  if (!res.ok) throw new Error(`resend ${res.status} ${await res.text()}`);
}

function rmEmailHtml(postId, m) {
  return `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;font-size:16px;line-height:1.7;color:#222;max-width:520px">
<p>${rmEsc(REMIND_COPY.hello(m.nm))}</p>
<p>${rmEsc(REMIND_COPY.body(m.t))}</p>
<p><a href="${rmEsc(rmPostUrl(postId))}" style="display:inline-block;margin:6px 0;padding:12px 24px;border-radius:10px;background:#2e7d32;color:#fff;text-decoration:none;font-weight:bold">${REMIND_COPY.btn}</a></p>
</div>`;
}

function rmEsc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------------------------------------------------------------------
// One-time backfill for reservations made before this was deployed.
// Call once:  GET /rm-backfill?token=<VERIFY_TOKEN>   then remove the route.
// ---------------------------------------------------------------------
async function rmBackfill(env) {
  const kv = rmKV(env);
  let cursor, added = 0;
  do {
    const page = await kv.list({ prefix: 'post:', cursor });                // ADAPT: post prefix
    for (const k of page.keys) {
      const post = await kv.get(k.name, 'json');
      if (!post || post.status !== 'reserved' || !post.reservedAt) continue; // ADAPT
      await rmTrack(env, {
        postId: k.name.slice('post:'.length),
        reservedAt: post.reservedAt,
        ownerEmail: post.ownerEmail,                                        // ADAPT
        ownerName: post.ownerName,                                          // ADAPT
        title: post.title,                                                  // ADAPT
      });
      added++;
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  return added;
}

// =====================================================================
// WIRING (module syntax):
//
// export default {
//   async fetch(request, env, ctx) {
//     const url = new URL(request.url);
//     if (url.pathname === '/rm-backfill' && url.searchParams.get('token') === env.VERIFY_TOKEN)
//       return Response.json({ added: await rmBackfill(env) });
//     ... existing routes ...
//   },
//   async scheduled(event, env, ctx) {
//     ctx.waitUntil(rmRun(env));
//   },
// };
//
// Reserve handler, after success:
//   await rmTrack(env, { postId, reservedAt: post.reservedAt, ownerEmail: post.ownerEmail,
//                        ownerName: post.ownerName, title: post.title });
// Confirm handler, cancel-reservation handler, delete-post handler, after success:
//   await rmClear(env, postId);
// =====================================================================

if (typeof module !== 'undefined') {
  module.exports = { REMIND, rmTrack, rmClear, rmRun, rmInWindow, rmBackfill };
}
