# Cloudflare deployment and storage

The public `hot-deal-kr.pages.dev` Pages Function proxies requests through an
`APP` service binding to the private `dubuzzang-hotdeal-app` Worker. The Worker
binds the dedicated `dubuzzang-hotdeal-data` R2 bucket. This deployment remains
fully separate from the `du-bu.pages.dev` application and its data.

The bucket contains:

- `data/links.json`
- `data/clicks.json`
- `data/users.json`
- `data/activity.json`
- `data/invites.json`
- `previews/goldbox-archive.json` (Goldbox products seen in the last 7 days)

`data/priceCollectionState.json` may still exist from the removed price
collector. Nothing reads it any more: Coupang answers every server-side product
page request with 403, so the collector never stored a price.

Write requests pass through one `RequestCoordinator` Durable Object, preventing
concurrent JSON read-modify-write operations from overwriting each other.
Read-only requests bypass it and load only the documents they need (a short-link
preview reads `links.json` only).

Short-link redirects (`GET /r/:code/go`) are answered by the Worker itself from
a per-isolate copy of `links.json` (reused for 5 seconds, re-read at most once a
second when a code is missing, so new links work immediately). The visitor is
redirected without waiting; the click is sent to the coordinator's
`recordClick` RPC, stored in its SQLite table `pending_clicks`, and an alarm
applies the queued clicks to `links.json` and `clicks.json` about 2 seconds
later in one read and one write, inside the same serial lane as other writes.
A click counts once per link, visitor IP and KST day; the IP comes only from
`CF-Connecting-IP`, which visitors cannot spoof. HEAD requests are not counted.
`cloudflare/click-counter.js` holds the shared counting rules.

Expired-link cleanup, the Goldbox archive refresh, and removal of unpinned
links older than each owner's auto-delete setting (plus past-day entries in
`clicks.json`) run from the Worker's Cron Trigger. The setting is stored per
user in `users.json` as `autoDelete: { enabled, days }` and changed above the
link list; users who never set it keep the original rule (on, 3 days). Pinned
links are never auto-deleted.

Preview deployments are disabled because they would otherwise write to the same
production bucket. Runtime secrets are configured on the private Worker and are
never stored in this repository. The former `dubuzzang-hotdeal.pages.dev`
address is retained only as a path-preserving redirect to this site.
