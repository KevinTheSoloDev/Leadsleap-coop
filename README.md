# LeadsLeap Instant Cloudflare Worker Filter

This is a standalone Cloudflare Worker version. It is slightly simpler than Pages if you only need an instant redirect/filter.

## Flow

`ZerAds -> Worker URL -> instant filter -> LeadsLeap or fallback`

Clean Tier-1 visitors only:

`https://lltrco.com/?r=sologotemm`

Suspicious visitors and non-Tier-1 countries:

`https://liquidsatoshis.duckdns.org/`

## Deploy

```bash
cd leadsleap-instant-filter-worker
npx wrangler deploy
```

Cloudflare will give you a URL like:

`https://leadsleap-instant-filter.YOUR-SUBDOMAIN.workers.dev`

Advertise that Worker URL in ZerAds.

## Add ProxyCheck API key

Recommended:

```bash
npx wrangler secret put PROXYCHECK_KEY
```

Paste your ProxyCheck.io key when asked.

Or add it in Cloudflare Dashboard:

**Workers & Pages -> your Worker -> Settings -> Variables -> Secrets**

Name:

`PROXYCHECK_KEY`

## Why Worker may be better than Pages here

For your current goal, Worker is ideal because there is no landing page and no static hosting. It only receives the request, filters it, and immediately returns a 302 redirect.


## Tier 1 country filter

This Worker currently sends only these countries to LeadsLeap:

- `US` - United States
- `GB` - United Kingdom
- `CA` - Canada
- `AU` - Australia
- `NZ` - New Zealand

All other countries are redirected to the fallback URL.

This is the conservative LeadsLeap-aligned Tier 1 / top English-speaking list based on LeadsLeap's own co-op traffic discussion highlighting US plus Australia, Canada, New Zealand, and UK as key English-speaking co-op traffic.

To edit the list, change this line in `src/worker.js`:

```js
const ALLOWED_COUNTRIES = ["US", "GB", "CA", "AU", "NZ"];
```
