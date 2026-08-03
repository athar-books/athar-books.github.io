# أثر — تبادل الكتب المدرسية

A used-textbook exchange for Arab villages in northern Israel. Starting with
Bu'eine Nujeidat. Someone lists the books their family has finished with; a
family that needs them finds one by grade and contacts them on WhatsApp.

Arabic (RTL) interface. Built to be opened from a WhatsApp link on a phone —
no app store, no install.

## Stack

Deliberately small. No framework, no build step, no dependencies.

| | |
|---|---|
| `index.html` | The whole app. Vanilla JS, inline CSS, single file. |
| `worker.js` | Cloudflare Worker + KV. Listings, ownership, admin, WhatsApp webhook. |
| `wrangler.toml` | Worker config. |

`admin.html` is the private moderation console. It is **not** in this repo and
must never be deployed — it is opened as a local file on the maintainer's
machine.

## How it works

**Listing.** Contact details are entered once, then books are added one at a
time and published as a batch. Ten books take about as long as two.

**Identity.** Triple name plus phone number, no SMS. The account id is derived
from the normalised number, so the same phone gives the same account on any
device. Names and numbers are returned by the API only to callers who have
identified themselves; anonymous visitors see books without people.

**Verification.** The user sends a short code to the initiative's WhatsApp
number. The proof is not the code — it is that the message arrives from the
number the account claims, which cannot be forged. A webhook derives the
expected code from the sender's number, so no lookup table is needed.

**Handoff.** Reserve, then the supplier confirms. Reservations expire after 48
hours so a silent requester cannot lock a book indefinitely.

**Authorization.** The Worker derives identity from a per-account token and
overwrites any uid supplied in a request body. Hidden buttons are convenience;
the server check is the security.

## Setup

```bash
npm i -g wrangler
npx wrangler login
npx wrangler kv namespace create BOOKS      # paste the id into wrangler.toml
npx wrangler secret put ADMIN_KEY           # long random string
npx wrangler deploy
```

Then set `API` at the top of the script in `index.html` to the Worker URL, and
add your Pages origin to `ALLOWED` in `worker.js`.

Optional, for automatic verification:

```bash
npx wrangler secret put VERIFY_TOKEN        # any string, also given to Meta
npx wrangler secret put APP_SECRET          # Meta app secret
```

## Placeholders to fill before launch

- `SCHOOLS` — real school names
- `VERIFY_WA` — the WhatsApp number that receives verification codes
- `VILLAGES` — each `code` becomes a permanent storage key; do not rename after
  listings exist

## Known limits

Listings for a village live in one KV value, so two simultaneous publishes can
overwrite each other. KV is eventually consistent — a new book may take a few
seconds to appear elsewhere. Both are acceptable at village scale and would
need a real database beyond it.
