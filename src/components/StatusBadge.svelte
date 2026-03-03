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
    gap: 0.25rem;
    padding: 0.18rem 0.55rem;
    border-radius: 12px;
    font-size: 0.76rem;
    font-weight: 600;
    letter-spacing: 0.2px;
    white-space: nowrap;
  }
  .pass { background: rgba(63, 185, 80, 0.15);  color: var(--pass); }
  .warn { background: rgba(210, 153, 34, 0.15); color: var(--warn); }
  .fail { background: rgba(248, 81, 73, 0.15);  color: var(--fail); }
  .info { background: rgba(88, 166, 255, 0.15); color: var(--info); }
</style>
