<script>
  import { onMount } from 'svelte';
  import CategorySection from './CategorySection.svelte';
  import HealthSummary from './HealthSummary.svelte';
  import { analyzeResults } from '../lib/analysis.js';
  import { parseSOA } from '../lib/dns.js';

  const ASN_PALETTE = ['var(--color-ip)', 'var(--color-priority)', 'var(--color-domain)', 'var(--pass)'];

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

    // DKIM key strength — flag weak/deprecated RSA keys and revoked keys.
    for (const [label, records] of Object.entries(emailSecurity)) {
      if (!label.includes('_domainkey')) continue;
      for (const r of records) {
        if (r.keyStatus === 'warn') {
          emailWarnings.push(`${label} uses a ${r.keyBits}-bit RSA key — RFC 8301 recommends 2048-bit minimum. Consider rotating.`);
        } else if (r.keyStatus === 'fail') {
          emailWarnings.push(r.keyBits
            ? `${label} uses a ${r.keyBits}-bit RSA key — below the deprecated 1024-bit floor. Rotate immediately.`
            : `${label} key appears to be revoked (empty p= tag).`);
        }
      }
    }

    const wwwRecords = {};
    if (usual.A)    wwwRecords.A    = usual.A;
    if (usual.AAAA) wwwRecords.AAAA = usual.AAAA;
    if (usual.TXT) {
      // Exclude SPF records — already shown under Email Security, using the
      // same v=spf1 match performLookup uses to classify them there.
      const nonSpfTxt = usual.TXT.filter(r =>
        !(r.data && r.data.toLowerCase().includes('v=spf1'))
      );
      if (nonSpfTxt.length) wwwRecords.TXT = nonSpfTxt;
    }
    if (usual.CAA)  wwwRecords.CAA  = usual.CAA;

    // NS network diversity — group by ASN (attached during lookup) to flag
    // a single-network "3+1" failure and to color-code shared-network chips.
    const nsRecords = usual.NS || [];
    const distinctAsns = [...new Set(nsRecords.map(r => r.asn).filter(Boolean))];
    const nsRecordsWithColor = nsRecords.map(r => ({
      ...r,
      asnColor: r.asn ? ASN_PALETTE[distinctAsns.indexOf(r.asn) % ASN_PALETTE.length] : null
    }));
    const nsWarnings = (nsRecords.length >= 2 && distinctAsns.length === 1)
      ? [`All ${nsRecords.length} nameservers are on the same network (ASN ${distinctAsns[0]}) — a single provider-side incident (BGP issue, bad rollout, DDoS) could take every nameserver down at once. No independent '+1'.`]
      : [];
    const nsDiversityBadge = distinctAsns.length >= 2
      ? { status: 'pass', message: `${distinctAsns.length} networks` }
      : (nsRecords.length >= 2 && distinctAsns.length === 1)
        ? { status: 'warn', message: 'single network' }
        : null;

    // Cross-resolver SOA serial check — a weaker proxy for per-NS serial
    // agreement, since public DoH can't be pinned to a specific authoritative NS.
    const soaRecords = usual.SOA || [];
    const soaWarnings = [];
    if (results.soaCrossCheck && soaRecords.length) {
      const primarySoa = parseSOA(soaRecords[0].data);
      if (primarySoa && primarySoa.serial !== results.soaCrossCheck.serial) {
        soaWarnings.push(
          `${results.soaCrossCheck.provider}'s resolver reports a different SOA serial (${results.soaCrossCheck.serial}) than ${results.provider}'s (${primarySoa.serial}) — likely propagation lag or a stale secondary. (Public resolvers only — not a substitute for querying each authoritative nameserver directly.)`
        );
      }
    }

    return [
      {
        id: 'sec-ns', title: 'NS — Nameservers',
        records: nsRecords.length ? { NS: nsRecordsWithColor } : {},
        analysis: analysis?.ns,
        extraBadges: nsDiversityBadge ? [nsDiversityBadge] : [],
        color: 'var(--ns-color)',
        gridCols: 2,
        warnings: nsWarnings
      },
      {
        id: 'sec-soa', title: 'SOA — Start of Authority',
        records: usual.SOA ? { SOA: usual.SOA } : {},
        analysis: analysis?.soa,
        color: 'var(--soa-color)',
        warnings: soaWarnings
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
        extraBadges={section.extraBadges ?? []}
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
    border-radius: 4px;
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
    border-radius: 2px;
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
