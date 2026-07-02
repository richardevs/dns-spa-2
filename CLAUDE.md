# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pnpm install
pnpm dev            # Vite dev server on localhost:5173
pnpm build          # production build → dist/
pnpm preview        # serve the built dist/
pnpm run deploy     # build + push dist/ to gh-pages (deploys dns.holywhite.com)
```

- Package manager is **pnpm** (see `packageManager` in package.json); do not use npm/yarn.
- There is **no test runner and no linter** configured. "Verifying" a change means running `pnpm dev`/`pnpm build` and exercising it in the browser.
- `vite.config.js` sets `base: '/'` because the site is served from a custom domain (`public/CNAME` → dns.holywhite.com), not a `/repo/` GitHub Pages path.

## Architecture

A single-page **Svelte 5 (runes)** app. No backend — everything runs client-side, querying public DNS-over-HTTPS resolvers directly from the browser. `src/main.js` mounts `App.svelte`; there is no router.

### Data flow

`App.svelte` (search UI + URL state) → `lib/dns.js performLookup()` (the orchestrator) → `results` object → `components/ReportView.svelte` (report) and `lib/analysis.js analyzeResults()` (health summary).

`performLookup(domain, provider, dkimSelectors)` is the heart of the app. It:
1. Queries the "usual" records (SOA/A/AAAA/TXT/MX/NS/CAA) against the chosen DoH provider.
2. Derives SPF from the TXT answers, and queries email-security names (`_dmarc`, `mta-sts`, `_smtp._tls`, plus each `<selector>._domainkey`).
3. Enriches results with best-effort async lookups (see below).
4. Returns `{ domain, provider, usual, emailSecurity, soaCrossCheck, isSubdomain, parentZone }`.

### Subdomain detection (PSL-free)

`performLookup` distinguishes a zone apex from an in-zone subdomain **without a public-suffix list**: an SOA query returns the record in the `Answer` section only at a zone apex; for a subdomain the `Answer` is empty and the enclosing zone's SOA comes back in `Authority` (whose name becomes `parentZone`). Both DoH providers behave identically here. The **SOA query runs first and alone** — its verdict decides which later requests to skip, so it's the one deliberate serialization point; everything after it (the remaining usual records, email-security records, and DKIM selectors) fans out concurrently via `Promise.all`. When `isSubdomain`, `performLookup` skips the bare NS query and the `orgScoped` email records (MTA-STS, TLS-RPT) — which can't exist below the apex — while still querying SPF/DMARC/DKIM (a subdomain can legitimately have those). `analyzeResults` then reports NS/SOA as `N/A — subdomain of <zone>` (info) instead of a red `fail`. On any SOA *error* the code stays in the apex path so a failed lookup never hides data. Note a CNAME'd subdomain resolves (transparently) to its target's SOA and is treated as apex — consistent with the app's CNAME-transparent behavior.

Because the Email Security section renders in insertion order, `emailSecurityResults` is assembled in a fixed order *after* the parallel batch resolves (SPF first, then the queried records in defined order, then DKIM) rather than by whichever request returns first.

### DoH provider abstraction

`PROVIDERS` maps `google` → dns.google and `cloudflare` → 1.1.1.1. All queries go through `queryDNS(name, type, providerUrl)` using the `application/dns-json` format. Because both resolvers return the JSON-DNS shape, providers are interchangeable — but **Cloudflare returns CAA as raw hex** (`parseCAA` decodes it) while Google returns it pre-parsed, so CAA has provider-specific handling in `performLookup`.

`filterAnswers()` drops CNAME passthrough records by matching the numeric DNS type — this is why record resolution is "CNAME-transparent."

### Team Cymru ASN enrichment (lib/dns.js)

NS records are enriched with network/ASN data via **Team Cymru's DNS-based whois** (not an HTTP API — plain TXT queries through the same DoH provider):
- `resolveNSNetwork()` resolves each NS host to its IPs, then `cymruQueryName()` builds the `<reversed-ip>.origin[6].asn.cymru.com` query to get ASN+prefix per IP. A single NS host can span **multiple ASNs** (some providers return one IP per ISP backbone) — the code tracks the full distinct-ASN set per host, not one representative IP, so network-diversity counts are accurate.
- `resolveAsnNames()` does a second-stage `AS<n>.asn.cymru.com` lookup for the org/AS-name.
- Both are cached in **localStorage** via `createPersistentCache(name, ttlMs)` (IP→ASN 7-day TTL, ASN→name 30-day TTL). The cache is fully best-effort: it never throws and falls back to in-memory if localStorage is unavailable.

### DKIM key classification & SOA cross-check

- `classifyDkimKey()` decodes the `p=` tag and uses **Web Crypto (`crypto.subtle.importKey`)** to read the RSA modulus bit length, flagging keys below RFC 8301's 2048-bit recommendation (Ed25519 is handled directly).
- `checkSoaCrossResolver()` re-queries SOA against the *other* DoH provider as a weak proxy for authoritative-NS serial agreement.

### Rendering pipeline (components/)

Rendering is driven by record label, not hard-coded per section:
- `lib/parsers.js detectRenderType(label)` maps a record label → a render mode (ipv4/ipv6/mx/ns/soa/caa/dkim/dmarc/mta-sts/tls-rpt/spf/txt).
- `RecordRow.svelte` switches on that mode to render IP chips, MX priority chips, KV tables, SPF token coloring, collapsible DKIM keys, etc. The various `parse*` helpers in parsers.js turn raw record data into structured display data.
- `ReportView.svelte` holds a section config (NS/SOA/MX/Email Security/WWW), renders each as a `CategorySection.svelte`, and uses an `IntersectionObserver` to drive the active-section sidebar nav. `HealthSummary.svelte` renders the 4-card dashboard from `analyzeResults()`.

`analyzeResults()` (lib/analysis.js) is pure/synchronous and produces the pass/warn/fail/info verdicts (NS count, SOA serial format, SPF cardinality, DMARC policy, private-IP detection). Keep it decoupled from the report-rendering components.

### Styling

Global design tokens (colors, section colors, IP/priority/domain chip colors) live as CSS custom properties in `src/app.css`. Fonts: **Syne** for UI, **IBM Plex Mono** for values/code, loaded via Google Fonts in `index.html`. Components use scoped `<style>` blocks referencing the tokens.

## Conventions

- **Svelte 5 runes**: `$state`, `$derived`, `$derived.by(() => …)`, `$props`, `$bindable`. Event handlers are `onclick={}` (not `on:click`).
- **URL state**: search state is serialized to `?domain=…&provider=google|cloudflare&dkim=…` via `pushState`, and restored on mount and `popstate`.
- All network enrichment (ASN, DKIM key, SOA cross-check) is **best-effort**: failures are logged and omitted, never surfaced as errors to the user.
