# dns-spa-2

DNS record analyzer — queries DNS via DNS-over-HTTPS and presents results in a structured report.

Live: [dns.holywhite.com](https://dns.holywhite.com)

Successor of [dns-spa](https://github.com/richardevs/dns-spa)

## Features

- Standard records: SOA, A, AAAA, MX, NS, TXT, CAA
- Email security: SPF, DMARC, DKIM (configurable selectors), MTA-STS, SMTP-TLS
- Parsed display: DMARC key-value, SPF token coloring, IP type chips, DKIM key collapse
- Health summary: at-a-glance pass/warn/fail for NS count, SPF, DMARC policy
- Two DNS providers: dns.google and 1.1.1.1
- URL state persistence — shareable links via query params
- CNAME-transparent record resolution

## Stack

- [Svelte 5](https://svelte.dev) (runes)
- [Vite](https://vitejs.dev)
- pnpm
- Deployed on GitHub Pages

## Development

```bash
pnpm install
pnpm dev      # localhost:5173
pnpm build
pnpm run deploy   # build + push to gh-pages
```

---

Made with [Claude Code](https://claude.ai/claude-code) · Use at your own risk
