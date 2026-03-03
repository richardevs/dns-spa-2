<script>
  let { domain, analysis } = $props();

  const statusIcon = { pass: '✓', warn: '⚠', fail: '✕', info: 'ℹ' };

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
    <span class="domain-text">{domain}</span>
    <span class="summary-label">Health overview</span>
  </div>
  <div class="cards">
    {#each cards as card}
      <div class="card {card.status}">
        <div class="card-icon">{statusIcon[card.status]}</div>
        <div class="card-body">
          <div class="card-label">{card.label}</div>
          <div class="card-value">{card.value}</div>
        </div>
      </div>
    {/each}
  </div>
</div>

<style>
  .health-summary {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 1.5rem;
  }

  .summary-title {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
    margin-bottom: 0.9rem;
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

  .cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.7rem;
  }

  .card {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 0.7rem 0.85rem;
    border-left-width: 3px;
  }

  .card.pass { border-left-color: var(--pass); }
  .card.warn { border-left-color: var(--warn); }
  .card.fail { border-left-color: var(--fail); }
  .card.info { border-left-color: var(--info); }

  .card-icon {
    font-size: 0.9rem;
    margin-top: 1px;
    flex-shrink: 0;
  }

  .card.pass .card-icon { color: var(--pass); }
  .card.warn .card-icon { color: var(--warn); }
  .card.fail .card-icon { color: var(--fail); }
  .card.info .card-icon { color: var(--info); }

  .card-body {
    min-width: 0;
  }

  .card-label {
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-2);
    margin-bottom: 0.2rem;
  }

  .card-value {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text-1);
    font-family: 'IBM Plex Mono', monospace;
    word-break: break-word;
  }

  @media (max-width: 700px) {
    .cards {
      grid-template-columns: repeat(2, 1fr);
    }
  }

  @media (max-width: 400px) {
    .cards {
      grid-template-columns: 1fr;
    }
  }
</style>
