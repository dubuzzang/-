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
- `data/priceCollectionState.json`

Write requests and click-count redirects pass through one `RequestCoordinator`
Durable Object, preventing concurrent JSON read-modify-write operations from
overwriting each other. Read-only requests bypass it. Price collection and
expired-link cleanup run in batches from the Worker's Cron Trigger.

Preview deployments are disabled because they would otherwise write to the same
production bucket. Runtime secrets are configured on the private Worker and are
never stored in this repository. The former `dubuzzang-hotdeal.pages.dev`
address is retained only as a path-preserving redirect to this site.
