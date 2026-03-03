<script>
  import { parseSOA } from '../lib/dns.js';
  import {
    detectRenderType,
    parseDMARC, parseMTASTS, parseTLSRPT, parseDKIM,
    parseSPF, parseMX, parseCAAsimple
  } from '../lib/parsers.js';

  let { record, type, onCopy } = $props();

  const renderType = $derived(detectRenderType(type));

  // SOA expand
  let soaExpanded  = $state(false);
  const soa        = $derived(renderType === 'soa' ? parseSOA(record.data) : null);

  // DKIM key expand
  let dkimExpanded = $state(false);
  const dkimPairs  = $derived(renderType === 'dkim' ? parseDKIM(record.data) : null);
  const dkimKey    = $derived(dkimPairs?.find(p => p.k === 'p')?.v ?? '');

  // Parsed structures
  const mxParsed   = $derived(renderType === 'mx'      ? parseMX(record.data)       : null);
  const caaParsed  = $derived(renderType === 'caa'     ? parseCAAsimple(record.data) : null);
  const dmarcPairs = $derived(renderType === 'dmarc'   ? parseDMARC(record.data)     : null);
  const mtasPairs  = $derived(renderType === 'mta-sts' ? parseMTASTS(record.data)    : null);
  const tlsPairs   = $derived(renderType === 'tls-rpt' ? parseTLSRPT(record.data)    : null);
  const spfTokens  = $derived(renderType === 'spf'     ? parseSPF(record.data)       : null);

  function formatDuration(seconds) {
    const s = Number(seconds);
    if (s >= 86400) return `${(s / 86400).toFixed(1)}d`;
    if (s >= 3600)  return `${(s / 3600).toFixed(1)}h`;
    if (s >= 60)    return `${(s / 60).toFixed(1)}m`;
    return `${s}s`;
  }

  // DMARC p= status color
  function dmarcPColor(val) {
    if (val === 'reject')     return 'var(--pass)';
    if (val === 'quarantine') return 'var(--warn)';
    return 'var(--text-2)';
  }

  // SPF token color
  function spfTokenColor(kind) {
    if (kind === 'version')   return 'var(--text-2)';
    if (kind === 'all')       return 'var(--warn)';
    if (kind === 'mechanism') return 'var(--color-ip)';
    return 'var(--text-1)';
  }
</script>

<!-- ─── Wrapper ───────────────────────────────────────── -->
<div class="record-wrap">
  <div class="record-row">
    <span class="ttl-badge">{record.TTL}s</span>

    <!-- ── IP chip (A/AAAA) ── -->
    {#if renderType === 'ipv4' || renderType === 'ipv6'}
      <span class="ip-chip {renderType}">
        <span class="ip-label">{renderType === 'ipv4' ? 'IPv4' : 'IPv6'}</span>
        {record.data}
      </span>

    <!-- ── MX ── -->
    {:else if renderType === 'mx' && mxParsed}
      <span class="mx-priority">{mxParsed.priority}</span>
      <span class="mono domain-val">{mxParsed.hostname}</span>

    <!-- ── NS ── -->
    {:else if renderType === 'ns'}
      <span class="mono domain-val">{record.data}</span>

    <!-- ── CAA ── -->
    {:else if renderType === 'caa' && caaParsed}
      <span class="caa-flag">{caaParsed.flags}</span>
      <span class="caa-tag">{caaParsed.tag}</span>
      <span class="mono domain-val">"{caaParsed.value}"</span>

    <!-- ── SOA toggle ── -->
    {:else if renderType === 'soa'}
      <span class="mono raw-val">{record.data}</span>

    <!-- ── DKIM ── -->
    {:else if renderType === 'dkim' && dkimPairs}
      <div class="kv-table">
        {#each dkimPairs as pair}
          {#if pair.k === 'p'}
            <div class="kv-row">
              <span class="kv-key">p</span>
              <span class="kv-val mono">
                {dkimExpanded ? pair.v : (pair.v.slice(0, 48) + (pair.v.length > 48 ? '…' : ''))}
                {#if pair.v.length > 48}
                  <button class="inline-toggle" onclick={() => dkimExpanded = !dkimExpanded}>
                    {dkimExpanded ? 'collapse' : 'expand key'}
                  </button>
                {/if}
              </span>
            </div>
          {:else}
            <div class="kv-row">
              <span class="kv-key">{pair.k}</span>
              <span class="kv-val mono">{pair.v}</span>
            </div>
          {/if}
        {/each}
      </div>

    <!-- ── DMARC ── -->
    {:else if renderType === 'dmarc' && dmarcPairs}
      <div class="kv-table">
        {#each dmarcPairs as pair}
          <div class="kv-row">
            <span class="kv-key">{pair.k}</span>
            <span class="kv-val mono"
              style={pair.k === 'p' ? `color:${dmarcPColor(pair.v)}` : ''}>
              {pair.v}
            </span>
          </div>
        {/each}
      </div>

    <!-- ── MTA-STS / TLS-RPT ── -->
    {:else if (renderType === 'mta-sts' && mtasPairs) || (renderType === 'tls-rpt' && tlsPairs)}
      {@const pairs = renderType === 'mta-sts' ? mtasPairs : tlsPairs}
      <div class="kv-table">
        {#each pairs as pair}
          <div class="kv-row">
            <span class="kv-key">{pair.k}</span>
            <span class="kv-val mono">{pair.v}</span>
          </div>
        {/each}
      </div>

    <!-- ── SPF ── -->
    {:else if renderType === 'spf' && spfTokens}
      <div class="spf-tokens">
        {#each spfTokens as t}
          <span class="spf-token" style="color:{spfTokenColor(t.kind)}">{t.token}</span>
        {/each}
      </div>

    <!-- ── fallback raw text ── -->
    {:else}
      <span class="mono raw-val">{record.data}</span>
    {/if}

    <!-- ── actions ── -->
    <div class="actions">
      {#if renderType === 'soa'}
        <button class="icon-btn" onclick={() => soaExpanded = !soaExpanded} title="SOA details">
          {soaExpanded ? '▲' : '▼'}
        </button>
      {/if}
      <button class="icon-btn copy" onclick={() => onCopy(record.data)} title="Copy">⧉</button>
    </div>
  </div>

  <!-- ── SOA expanded ── -->
  {#if soaExpanded && soa}
    <div class="soa-detail">
      <div class="soa-grid">
        <div class="soa-field"><span class="kv-key">Primary NS</span>  <span class="mono soa-val">{soa.mname}</span></div>
        <div class="soa-field"><span class="kv-key">Responsible</span> <span class="mono soa-val">{soa.rname}</span></div>
        <div class="soa-field"><span class="kv-key">Serial</span>      <span class="mono soa-val">{soa.serial}</span></div>
        <div class="soa-field"><span class="kv-key">Refresh</span>     <span class="mono soa-val">{formatDuration(soa.refresh)}</span></div>
        <div class="soa-field"><span class="kv-key">Retry</span>       <span class="mono soa-val">{formatDuration(soa.retry)}</span></div>
        <div class="soa-field"><span class="kv-key">Expire</span>      <span class="mono soa-val">{formatDuration(soa.expire)}</span></div>
        <div class="soa-field"><span class="kv-key">Min TTL</span>     <span class="mono soa-val">{formatDuration(soa.minimum)}</span></div>
      </div>
    </div>
  {/if}
</div>

<style>
  /* ── Layout ────────────────────────────────────────── */
  .record-wrap {
    display: flex;
    flex-direction: column;
  }

  .record-row {
    display: flex;
    align-items: flex-start;
    gap: 0.55rem;
    padding: 0.45rem 0.65rem;
    background: var(--bg-raised);
    border-radius: 5px;
    font-size: 0.875rem;
  }

  /* ── TTL badge ─────────────────────────────────────── */
  .ttl-badge {
    flex-shrink: 0;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    color: var(--text-2);
    font-size: 0.7rem;
    padding: 0.1rem 0.35rem;
    border-radius: 3px;
    font-family: 'IBM Plex Mono', monospace;
    margin-top: 3px;
    white-space: nowrap;
  }

  /* ── Shared value styles ───────────────────────────── */
  .mono       { font-family: 'IBM Plex Mono', 'Courier New', monospace; }
  .raw-val    { flex: 1; color: var(--text-1); word-break: break-all; line-height: 1.5; }
  .domain-val { flex: 1; color: var(--color-domain); word-break: break-all; }

  /* ── IP chip ───────────────────────────────────────── */
  .ip-chip {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.875rem;
    color: var(--color-ip);
    flex: 1;
    flex-wrap: wrap;
  }

  .ip-label {
    font-size: 0.69rem;
    font-weight: 700;
    letter-spacing: 0.4px;
    background: rgba(88, 166, 255, 0.12);
    color: var(--color-ip);
    padding: 0.1rem 0.38rem;
    border-radius: 3px;
    border: 1px solid rgba(88, 166, 255, 0.25);
    flex-shrink: 0;
  }

  /* ── MX ────────────────────────────────────────────── */
  .mx-priority {
    flex-shrink: 0;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--color-priority);
    background: rgba(227, 179, 65, 0.1);
    border: 1px solid rgba(227, 179, 65, 0.25);
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    margin-top: 1px;
  }

  /* ── CAA ───────────────────────────────────────────── */
  .caa-flag {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
    color: var(--text-2);
    flex-shrink: 0;
  }

  .caa-tag {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    color: var(--color-priority);
    background: rgba(227, 179, 65, 0.08);
    padding: 0.08rem 0.35rem;
    border-radius: 3px;
    flex-shrink: 0;
  }

  /* ── Key-value table (DMARC/SPF/DKIM/MTA-STS/TLS-RPT) */
  .kv-table {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .kv-row {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
  }

  .kv-key {
    flex-shrink: 0;
    width: 6rem;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: none;
    color: var(--color-key);
    font-family: 'IBM Plex Mono', monospace;
    opacity: 0.85;
  }

  .kv-val {
    flex: 1;
    font-size: 0.875rem;
    color: var(--text-1);
    word-break: break-all;
    line-height: 1.5;
  }

  /* ── DKIM inline toggle ─────────────────────────────── */
  .inline-toggle {
    display: inline;
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.75rem;
    cursor: pointer;
    padding: 0 0.3rem;
    font-family: 'IBM Plex Mono', monospace;
    text-decoration: underline;
    text-decoration-style: dotted;
  }

  /* ── SPF tokens ─────────────────────────────────────── */
  .spf-tokens {
    flex: 1;
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    align-items: center;
  }

  .spf-token {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem;
    word-break: break-all;
  }

  /* ── SOA expanded ───────────────────────────────────── */
  .soa-detail {
    margin-top: 0.3rem;
    padding: 0.7rem 0.85rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-top: none;
    border-radius: 0 0 5px 5px;
  }

  .soa-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
    gap: 0.6rem;
  }

  .soa-field {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .soa-val {
    font-size: 0.84rem;
    color: var(--text-1);
    word-break: break-all;
  }

  /* ── Actions ────────────────────────────────────────── */
  .actions {
    display: flex;
    gap: 0.2rem;
    flex-shrink: 0;
    margin-top: 1px;
  }

  .icon-btn {
    background: transparent;
    border: none;
    color: var(--text-2);
    cursor: pointer;
    padding: 0.18rem 0.38rem;
    border-radius: 3px;
    font-size: 0.8rem;
    transition: color 0.15s, background 0.15s;
    line-height: 1;
  }

  .icon-btn:hover {
    color: var(--text-1);
    background: var(--bg-surface);
  }

  .icon-btn.copy:hover {
    color: var(--accent);
  }
</style>
