<script>
  let { domain, analysis } = $props();

  const cards = $derived([
    {
      label: 'Nameservers',
      value: analysis?.ns?.message ?? '—',
      status: analysis?.ns?.status ?? 'info'
    },
    {
      label: 'SPF',
      value: analysis?.spf?.message ?? '—',
      status: analysis?.spf?.status ?? 'info'
    },
    {
      label: 'DMARC',
      value: analysis?.dmarc?.policy ? `p=${analysis.dmarc.policy}` : (analysis?.dmarc?.message ?? '—'),
      status: analysis?.dmarc?.status ?? 'info'
    },
    {
      label: 'Security records',
      value: analysis?.securityCount != null ? `${analysis.securityCount} found` : '—',
      status: analysis?.securityCount > 0 ? 'pass' : 'warn'
    }
  ]);
</script>

<div class="health-summary">
  <div class="summary-title">
    <span class="prompt-glyph">┌─</span>
    <span class="domain-text">{domain}</span>
    <span class="summary-label">health overview</span>
  </div>
  <div class="status-strip">
    {#each cards as card, i}
      <div class="strip-item">
        <span class="block-indicator {card.status}"></span>
        <span class="strip-label">{card.label}</span>
        <span class="strip-value">{card.value}</span>
      </div>
      {#if i < cards.length - 1}<span class="strip-sep">·</span>{/if}
    {/each}
  </div>
</div>

<style>
  .health-summary {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.9rem 1.2rem;
    margin-bottom: 1.5rem;
  }

  .summary-title {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
  }

  .prompt-glyph {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    color: var(--text-2);
    user-select: none;
  }

  .domain-text {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.05rem;
    font-weight: 500;
    color: var(--accent);
  }

  .summary-label {
    font-size: 0.78rem;
    color: var(--text-2);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
  }

  .status-strip {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem;
    font-family: 'IBM Plex Mono', monospace;
  }

  .strip-item {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .block-indicator {
    width: 0.6rem;
    height: 0.6rem;
    flex-shrink: 0;
  }

  .block-indicator.pass { background: var(--pass); }
  .block-indicator.warn { background: var(--warn); }
  .block-indicator.fail { background: var(--fail); }
  .block-indicator.info { background: var(--info); }

  .strip-label {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-2);
  }

  .strip-value {
    font-size: 0.82rem;
    color: var(--text-1);
  }

  .strip-sep {
    color: var(--border-bright);
    font-size: 0.9rem;
  }
</style>
