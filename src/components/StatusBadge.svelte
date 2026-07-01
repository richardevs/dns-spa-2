<script>
  let { status, label } = $props();

  const icons = { pass: '✓', warn: '⚠', fail: '✕', info: 'ℹ' };
</script>

<span class="badge {status}">
  {icons[status] ?? 'ℹ'} {label ?? status}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.14rem 0.5rem;
    border: 1px solid currentColor;
    border-radius: 2px;
    background: color-mix(in srgb, currentColor 10%, transparent);
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
    font-size: 0.74rem;
    font-weight: 600;
    letter-spacing: 0.2px;
    white-space: nowrap;
  }
  .pass { color: var(--pass); }
  .warn { color: var(--warn); }
  .fail { color: var(--fail); }
  .info { color: var(--info); }
</style>
