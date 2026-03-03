<script>
  import StatusBadge from './StatusBadge.svelte';
  import RecordRow from './RecordRow.svelte';

  let {
    id,
    title,
    records   = {},
    analysis  = null,
    warnings  = [],
    color     = 'var(--accent)',
    gridCols  = 1,
    onCopy
  } = $props();

  let open = $state(true);

  const recordCount = $derived(Object.values(records).flat().length);
</script>

<section class="category-section" {id} style="--section-color: {color}">
  <button class="section-header" onclick={() => open = !open}>
    <div class="header-left">
      <span class="section-title">{title}</span>
      {#if analysis}
        <StatusBadge status={analysis.status} label={analysis.message} />
      {/if}
    </div>
    <div class="header-right">
      <span class="record-count">{recordCount} record{recordCount !== 1 ? 's' : ''}</span>
      <span class="chevron">{open ? '▲' : '▼'}</span>
    </div>
  </button>

  {#if open}
    <div class="section-body">
      {#each warnings as warning}
        <div class="warning-banner">{warning}</div>
      {/each}

      {#if Object.keys(records).length > 0}
        {#each Object.entries(records) as [label, recs]}
          <div class="record-group">
            <div class="group-label">{label}</div>
            <div class="record-list" class:grid-2={gridCols === 2 && recs.length > 1}>
              {#each recs as record}
                <RecordRow {record} type={label} {onCopy} />
              {/each}
            </div>
          </div>
        {/each}
      {:else}
        <div class="empty-state">No records found</div>
      {/if}
    </div>
  {/if}
</section>

<style>
  .category-section {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--section-color);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 0.875rem;
  }

  .section-header {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.8rem 1.1rem;
    background: transparent;
    border: none;
    cursor: pointer;
    color: var(--text-1);
    transition: background 0.15s;
    text-align: left;
  }

  .section-header:hover {
    background: var(--bg-raised);
  }

  .header-left {
    display: flex;
    align-items: center;
    gap: 0.65rem;
    flex-wrap: wrap;
  }

  .section-title {
    font-weight: 700;
    font-size: 0.92rem;
    letter-spacing: 0.2px;
    color: var(--section-color);
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    color: var(--text-2);
    font-size: 0.78rem;
    flex-shrink: 0;
  }

  .chevron {
    font-size: 0.6rem;
  }

  .section-body {
    padding: 0.6rem 1.1rem 1.05rem;
    border-top: 1px solid var(--border);
  }

  .warning-banner {
    background: rgba(210, 153, 34, 0.08);
    border: 1px solid rgba(210, 153, 34, 0.3);
    border-radius: 5px;
    color: var(--warn);
    padding: 0.5rem 0.75rem;
    font-size: 0.835rem;
    line-height: 1.5;
    margin-bottom: 0.7rem;
  }

  .record-group {
    margin-bottom: 0.85rem;
  }

  .record-group:last-child {
    margin-bottom: 0;
  }

  .group-label {
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--section-color);
    opacity: 0.8;
    margin-bottom: 0.35rem;
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
  }

  .record-list {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  /* Two-column grid for compact uniform records */
  .record-list.grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.3rem;
  }

  @media (max-width: 560px) {
    .record-list.grid-2 {
      grid-template-columns: 1fr;
    }
  }

  .empty-state {
    color: var(--text-2);
    font-style: italic;
    font-size: 0.875rem;
    padding: 0.25rem 0;
  }
</style>
