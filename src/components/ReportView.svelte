<script>
  import { onMount } from 'svelte';
  import CategorySection from './CategorySection.svelte';
  import HealthSummary from './HealthSummary.svelte';
  import { analyzeResults } from '../lib/analysis.js';

  let { results, onCopy } = $props();

  const analysis = $derived(analyzeResults(results));

  // Section definitions with identity color + optional 2-column grid
  const sections = $derived.by(() => {
    if (!results) return [];
    const { usual, emailSecurity } = results;

    const spfCount = (emailSecurity['SPF (TXT)'] || []).length;
    const emailWarnings = spfCount > 1
      ? [`Multiple SPF records detected (${spfCount}). RFC 7208 requires exactly one — having more causes SPF checks to fail for all senders.`]
      : [];

    const wwwRecords = {};
    if (usual.A)    wwwRecords.A    = usual.A;
    if (usual.AAAA) wwwRecords.AAAA = usual.AAAA;
    if (usual.TXT)  wwwRecords.TXT  = usual.TXT;
    if (usual.CAA)  wwwRecords.CAA  = usual.CAA;

    return [
      {
        id: 'sec-ns', title: 'NS — Nameservers',
        records: usual.NS ? { NS: usual.NS } : {},
        analysis: analysis?.ns,
        color: 'var(--ns-color)',
        gridCols: 2
      },
      {
        id: 'sec-soa', title: 'SOA — Start of Authority',
        records: usual.SOA ? { SOA: usual.SOA } : {},
        analysis: analysis?.soa,
        color: 'var(--soa-color)'
      },
      {
        id: 'sec-mx', title: 'MX — Mail Exchange',
        records: usual.MX ? { MX: usual.MX } : {},
        analysis: analysis?.mx,
        color: 'var(--mx-color)',
        gridCols: 2
      },
      {
        id: 'sec-email', title: 'Email Security',
        records: emailSecurity,
        analysis: analysis?.spf,
        color: 'var(--email-color)',
        warnings: emailWarnings
      },
      {
        id: 'sec-www', title: 'WWW — Web Records',
        records: wwwRecords,
        analysis: analysis?.www,
        color: 'var(--www-color)',
        gridCols: 2
      }
    ];
  });

  const navItems = [
    { id: 'sec-ns',    label: 'NS',         color: 'var(--ns-color)'    },
    { id: 'sec-soa',   label: 'SOA',        color: 'var(--soa-color)'   },
    { id: 'sec-mx',    label: 'MX',         color: 'var(--mx-color)'    },
    { id: 'sec-email', label: 'Email Sec',  color: 'var(--email-color)' },
    { id: 'sec-www',   label: 'WWW',        color: 'var(--www-color)'   }
  ];

  let activeSection = $state('sec-ns');

  function scrollTo(id) {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  onMount(() => {
    // Delay slightly so sections are rendered before observing
    const raf = requestAnimationFrame(() => {
      const els = document.querySelectorAll('.category-section');
      if (!els.length) return;

      const observer = new IntersectionObserver(entries => {
        // Pick the entry closest to viewport top that is intersecting
        const visible = entries
          .filter(e => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length) activeSection = visible[0].target.id;
      }, {
        rootMargin: '-10% 0px -60% 0px',
        threshold: 0
      });

      els.forEach(el => observer.observe(el));
      return () => observer.disconnect();
    });

    return () => cancelAnimationFrame(raf);
  });
</script>

<div class="report-layout">
  <!-- ── Main content ── -->
  <div class="report-main">
    <HealthSummary domain={results.domain} {analysis} />

    {#each sections as section}
      <CategorySection
        id={section.id}
        title={section.title}
        records={section.records}
        analysis={section.analysis}
        warnings={section.warnings ?? []}
        color={section.color}
        gridCols={section.gridCols ?? 1}
        {onCopy}
      />
    {/each}
  </div>

  <!-- ── Sticky sidebar ── -->
  <aside class="sticky-nav">
    <div class="nav-label">Sections</div>
    {#each navItems as item}
      <button
        class="nav-item"
        class:active={activeSection === item.id}
        style="--item-color: {item.color}"
        onclick={() => scrollTo(item.id)}
      >
        {item.label}
      </button>
    {/each}
  </aside>
</div>

<style>
  .report-layout {
    display: grid;
    grid-template-columns: 1fr 200px;
    gap: 1.5rem;
    align-items: start;
  }

  .report-main {
    min-width: 0;
  }

  /* ── Sticky sidebar ── */
  .sticky-nav {
    position: sticky;
    top: 4.5rem;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 0.6rem;
  }

  .nav-label {
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-2);
    margin-bottom: 0.45rem;
    padding: 0 0.4rem;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    width: 100%;
    text-align: left;
    padding: 0.38rem 0.5rem;
    background: transparent;
    border: none;
    color: var(--text-2);
    font-size: 0.82rem;
    font-weight: 500;
    cursor: pointer;
    border-radius: 5px;
    transition: background 0.15s, color 0.15s;
    font-family: 'IBM Plex Mono', 'Courier New', monospace;
    position: relative;
  }

  .nav-item::before {
    content: '';
    width: 3px;
    height: 14px;
    border-radius: 2px;
    background: transparent;
    flex-shrink: 0;
    transition: background 0.2s;
  }

  .nav-item:hover {
    background: var(--bg-raised);
    color: var(--text-1);
  }

  .nav-item.active {
    color: var(--item-color);
    background: color-mix(in srgb, var(--item-color) 8%, transparent);
  }

  .nav-item.active::before {
    background: var(--item-color);
  }

  @media (max-width: 768px) {
    .report-layout {
      grid-template-columns: 1fr;
    }

    .sticky-nav {
      display: none;
    }
  }
</style>
