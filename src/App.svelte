<script>
  import { onMount } from 'svelte';
  import ReportView from './components/ReportView.svelte';
  import { performLookup, PROVIDERS } from './lib/dns.js';

  let domain        = $state('');
  let provider      = $state('google');
  let dkimSelectors = $state('google, default, selector1, selector2');
  let loading       = $state(false);
  let error         = $state('');
  let results       = $state(null);
  let showToast     = $state(false);
  let showDkim      = $state(false);

  let toastTimer = null;

  async function handleSearch() {
    if (!domain.trim()) {
      error = 'Please enter a domain name';
      return;
    }
    loading = true;
    error   = '';
    results = null;

    try {
      results = await performLookup(domain, provider, dkimSelectors);
      const state = { domain: results.domain, provider, dkimSelectors };
      const url   = `?domain=${encodeURIComponent(results.domain)}&provider=${provider}&dkim=${encodeURIComponent(dkimSelectors)}`;
      window.history.pushState(state, '', url);
    } catch (err) {
      error = `Error: ${err.message}`;
    } finally {
      loading = false;
    }
  }

  function handleKey(e) {
    if (e.key === 'Enter') handleSearch();
  }

  function handlePopState(event) {
    if (event.state?.domain) {
      domain        = event.state.domain;
      provider      = event.state.provider      || 'google';
      dkimSelectors = event.state.dkimSelectors || 'google, default, selector1, selector2';
      handleSearch();
    } else {
      results = null;
      domain  = '';
      provider = 'google';
      dkimSelectors = 'google, default, selector1, selector2';
    }
  }

  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      if (toastTimer) clearTimeout(toastTimer);
      showToast  = true;
      toastTimer = setTimeout(() => { showToast = false; toastTimer = null; }, 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  }

  onMount(() => {
    window.addEventListener('popstate', handlePopState);

    const params      = new URLSearchParams(window.location.search);
    const urlDomain   = params.get('domain');
    const urlProvider = params.get('provider');
    const urlDkim     = params.get('dkim');

    if (urlDomain) {
      domain = urlDomain;
      if (urlProvider && PROVIDERS[urlProvider]) provider = urlProvider;
      if (urlDkim) dkimSelectors = urlDkim;
      handleSearch();
    }

    return () => window.removeEventListener('popstate', handlePopState);
  });
</script>

<div class="app-shell">
  <!-- ── Sticky header with inline search ── -->
  <header class="site-header">
    <div class="header-inner">
      <button class="site-title" onclick={() => {
          results = null; domain = ''; error = '';
          window.history.pushState({}, '', window.location.pathname);
        }}>dns.holywhite.com</button>

      <div class="search-inline">
        <select bind:value={provider} disabled={loading} class="provider-select">
          <option value="google">dns.google</option>
          <option value="cloudflare">1.1.1.1</option>
        </select>
        <div class="input-wrap">
          <input
            type="text"
            bind:value={domain}
            onkeypress={handleKey}
            placeholder="example.com"
            disabled={loading}
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
          />
          <button class="dkim-btn" onclick={() => showDkim = !showDkim} title="DKIM selectors" class:active={showDkim}>
            ⚙
          </button>
        </div>
        <button class="analyze-btn" onclick={handleSearch} disabled={loading}>
          {loading ? '…' : 'Analyze'}
        </button>
      </div>

      <a class="github-link" href="https://github.com/richardevs/dns-spa-2" target="_blank" rel="noopener">
        GitHub
      </a>
    </div>

    <!-- DKIM panel: always visible in initial state, toggle-controlled after search -->
    {#if showDkim || !results}
      <div class="dkim-panel">
        <label class="dkim-label" for="dkim-input">DKIM selectors (comma-separated)</label>
        <input
          id="dkim-input"
          class="dkim-input"
          type="text"
          bind:value={dkimSelectors}
          placeholder="google, default, selector1, selector2"
          disabled={loading}
        />
      </div>
    {/if}
  </header>

  <!-- ── Main content ── -->
  <main class="main-content">
    {#if !results && !loading && !error}
      <div class="welcome">
        <h1 class="welcome-title">DNS Analyzer</h1>
        <p class="welcome-sub">Query DNS records via DNS-over-HTTPS. Enter a domain above to get started.</p>
      </div>
    {/if}

    {#if loading}
      <div class="loading-state">
        <div class="spinner"></div>
        <p>Querying DNS records…</p>
      </div>
    {/if}

    {#if error}
      <div class="error-state">{error}</div>
    {/if}

    {#if results}
      <ReportView {results} onCopy={copyToClipboard} />
    {/if}
  </main>

  <footer class="site-footer">
    <p>
      <a href="https://github.com/richardevs/dns-spa-2" target="_blank" rel="noopener">GitHub</a>
      &middot; DNS-over-HTTPS &middot; Educational use
    </p>
  </footer>
</div>

{#if showToast}
  <div class="toast">✓ Copied</div>
{/if}

<style>
  .app-shell {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  /* ── Header ── */
  .site-header {
    position: sticky;
    top: 0;
    z-index: 100;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    backdrop-filter: blur(8px);
  }

  .header-inner {
    max-width: 1100px;
    margin: 0 auto;
    padding: 0.6rem 1.25rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .site-title {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem;
    font-weight: 500;
    color: var(--accent);
    flex-shrink: 0;
    white-space: nowrap;
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
    opacity: 1;
    transition: opacity 0.15s;
  }

  .site-title:hover { opacity: 0.7; }

  /* ── Inline search ── */
  .search-inline {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 0;
    max-width: 560px;
    border: 1px solid var(--border);
    border-radius: 7px;
    overflow: hidden;
    background: var(--bg-raised);
    transition: border-color 0.15s;
  }

  .search-inline:focus-within {
    border-color: var(--accent);
  }

  .provider-select {
    padding: 0.5rem 1.6rem 0.5rem 0.7rem;
    background: var(--bg-surface);
    border: none;
    border-right: 1px solid var(--border);
    color: var(--text-1);
    font-size: 0.8rem;
    cursor: pointer;
    outline: none;
    flex-shrink: 0;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='9' height='9' viewBox='0 0 9 9'%3E%3Cpath fill='%238b949e' d='M4.5 6.5L1 2.5h7z'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 0.4rem center;
    font-family: 'IBM Plex Mono', monospace;
  }

  .provider-select:disabled { opacity: 0.5; cursor: not-allowed; }

  .input-wrap {
    flex: 1;
    display: flex;
    align-items: center;
    min-width: 0;
  }

  .input-wrap input {
    flex: 1;
    padding: 0.5rem 0.6rem;
    background: transparent;
    border: none;
    color: var(--text-1);
    font-size: 0.9rem;
    outline: none;
    min-width: 0;
    font-family: 'IBM Plex Mono', monospace;
  }

  .input-wrap input::placeholder { color: var(--text-2); }
  .input-wrap input:disabled { opacity: 0.5; cursor: not-allowed; }

  .dkim-btn {
    flex-shrink: 0;
    background: transparent;
    border: none;
    border-left: 1px solid var(--border);
    color: var(--text-2);
    cursor: pointer;
    padding: 0.35rem 0.6rem;
    font-size: 1rem;
    transition: color 0.15s, background 0.15s;
    line-height: 1;
  }

  .dkim-btn:hover, .dkim-btn.active { color: var(--accent); background: var(--bg-surface); }

  .analyze-btn {
    flex-shrink: 0;
    padding: 0.5rem 1rem;
    background: var(--accent);
    color: #0d1117;
    border: none;
    font-size: 0.85rem;
    font-weight: 700;
    cursor: pointer;
    transition: opacity 0.15s;
    font-family: 'Syne', sans-serif;
    white-space: nowrap;
  }

  .analyze-btn:hover:not(:disabled) { opacity: 0.85; }
  .analyze-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  /* ── DKIM panel ── */
  .dkim-panel {
    max-width: 1100px;
    margin: 0 auto;
    padding: 0.5rem 1.25rem 0.65rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    border-top: 1px solid var(--border);
  }

  .dkim-label {
    font-size: 0.75rem;
    color: var(--text-2);
    white-space: nowrap;
    font-weight: 600;
    flex-shrink: 0;
  }

  .dkim-input {
    flex: 1;
    max-width: 480px;
    padding: 0.38rem 0.65rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 5px;
    color: var(--text-1);
    font-size: 0.83rem;
    outline: none;
    font-family: 'IBM Plex Mono', monospace;
    transition: border-color 0.15s;
  }

  .dkim-input:focus { border-color: var(--accent); }

  .github-link {
    font-size: 0.78rem;
    color: var(--text-2);
    text-decoration: none;
    transition: color 0.15s;
    flex-shrink: 0;
    white-space: nowrap;
  }

  .github-link:hover { color: var(--text-1); }

  /* ── Main ── */
  .main-content {
    max-width: 1100px;
    margin: 0 auto;
    padding: 1.75rem 1.25rem;
    width: 100%;
    flex: 1;
  }

  /* ── Welcome state ── */
  .welcome {
    text-align: center;
    padding: 5rem 1rem;
  }

  .welcome-title {
    margin: 0 0 0.75rem;
    font-size: 2.2rem;
    font-weight: 700;
    color: var(--text-1);
    letter-spacing: -0.5px;
  }

  .welcome-sub {
    margin: 0;
    font-size: 1rem;
    color: var(--text-2);
    max-width: 460px;
    margin: 0 auto;
    line-height: 1.6;
  }

  /* ── Loading ── */
  .loading-state {
    text-align: center;
    padding: 4rem;
    color: var(--text-2);
  }

  .spinner {
    width: 36px;
    height: 36px;
    margin: 0 auto 1rem;
    border: 3px solid var(--bg-raised);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.75s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Error ── */
  .error-state {
    background: rgba(248, 81, 73, 0.07);
    border: 1px solid var(--fail);
    border-left-width: 4px;
    color: var(--fail);
    padding: 0.75rem 1rem;
    border-radius: 6px;
    margin-bottom: 1.5rem;
    font-size: 0.875rem;
  }

  /* ── Footer ── */
  .site-footer {
    border-top: 1px solid var(--border);
    padding: 1.1rem 1.25rem;
    text-align: center;
    color: var(--text-2);
    font-size: 0.78rem;
  }

  .site-footer p { margin: 0; }

  .site-footer a {
    color: var(--accent);
    text-decoration: none;
  }

  .site-footer a:hover { text-decoration: underline; }

  /* ── Toast ── */
  .toast {
    position: fixed;
    bottom: 1.75rem;
    left: 50%;
    transform: translateX(-50%);
    background: var(--pass);
    color: #0d1117;
    padding: 0.5rem 1.1rem;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.82rem;
    box-shadow: 0 4px 14px rgba(63, 185, 80, 0.3);
    animation: slideUp 0.22s ease-out;
    z-index: 1000;
  }

  @keyframes slideUp {
    from { opacity: 0; transform: translateX(-50%) translateY(0.5rem); }
    to   { opacity: 1; transform: translateX(-50%) translateY(0); }
  }

  /* ── Responsive ── */
  @media (max-width: 768px) {
    .header-inner {
      flex-wrap: wrap;
      gap: 0.5rem;
    }

    .site-title { order: 1; }
    .github-link { order: 2; margin-left: auto; }
    .search-inline { order: 3; flex: 1 1 100%; max-width: none; }

    .main-content {
      padding: 1.25rem 1rem;
    }
  }

  @media (max-width: 480px) {
    .analyze-btn {
      padding: 0.5rem 0.7rem;
    }
  }
</style>
