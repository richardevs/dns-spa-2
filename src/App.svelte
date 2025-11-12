<script>
  import { onMount } from 'svelte';

  // Record types to query
  const RECORD_TYPES = {
    usual: ['SOA', 'A', 'AAAA', 'TXT', 'MX', 'NS', 'CAA'],
    emailSecurity: [
      { type: 'TXT', name: '_dmarc', label: '_dmarc (TXT)' },
      { type: 'A', name: 'mta-sts', label: 'mta-sts (A)' },
      { type: 'AAAA', name: 'mta-sts', label: 'mta-sts (AAAA)' },
      { type: 'TXT', name: '_mta-sts', label: '_mta-sts (TXT)' },
      { type: 'TXT', name: '_smtp._tls', label: '_smtp._tls (TXT)' },
      { type: 'TXT', name: 'google._domainkey', label: 'google._domainkey (TXT)' }
    ]
  };

  // DNS providers
  const PROVIDERS = {
    google: 'https://dns.google/resolve',
    cloudflare: 'https://cloudflare-dns.com/dns-query'
  };

  let domain = '';
  let provider = 'google';
  let loading = false;
  let error = '';
  let results = null;
  let showToast = false;

  // Parse CAA record from Cloudflare's hex format
  function parseCAA(hexData) {
    // Format: \# <length> <hex bytes>
    // Hex bytes: <flags> <tag_length> <tag> <value>
    
    const match = hexData.match(/\\#\s+\d+\s+([\da-fA-F\s]+)/);
    if (!match) return hexData;

    const hexBytes = match[1].replace(/\s+/g, '');
    
    try {
      // Parse flags (1 byte)
      const flags = parseInt(hexBytes.substr(0, 2), 16);
      
      // Parse tag length (1 byte)
      const tagLength = parseInt(hexBytes.substr(2, 2), 16);
      
      // Parse tag (tagLength bytes)
      const tagHex = hexBytes.substr(4, tagLength * 2);
      const tag = tagHex.match(/.{2}/g)
        .map(byte => String.fromCharCode(parseInt(byte, 16)))
        .join('');
      
      // Parse value (remaining bytes)
      const valueHex = hexBytes.substr(4 + tagLength * 2);
      const value = valueHex.match(/.{2}/g)
        .map(byte => String.fromCharCode(parseInt(byte, 16)))
        .join('');
      
      return `${flags} ${tag} "${value}"`;
    } catch (err) {
      console.error('Error parsing CAA record:', err);
      return hexData;
    }
  }

  // Query DNS records
  async function queryDNS(recordDomain, recordType, providerUrl) {
    const url = new URL(providerUrl);
    url.searchParams.set('name', recordDomain);
    url.searchParams.set('type', recordType);

    const response = await fetch(url.toString(), {
      headers: { 'Accept': 'application/dns-json' }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  }

  // Perform lookup
  async function handleLookup() {
    if (!domain.trim()) {
      error = 'Please enter a domain name';
      return;
    }

    // Clean domain
    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
    
    loading = true;
    error = '';
    results = null;

    try {
      const providerUrl = PROVIDERS[provider];
      const usualResults = {};
      const emailSecurityResults = {};

      // Query usual records
      for (const type of RECORD_TYPES.usual) {
        try {
          const result = await queryDNS(cleanDomain, type, providerUrl);
          if (result.Answer && result.Answer.length > 0) {
            // Parse CAA records from Cloudflare's hex format
            if (type === 'CAA' && provider === 'cloudflare') {
              result.Answer = result.Answer.map(record => ({
                ...record,
                data: parseCAA(record.data)
              }));
            }
            usualResults[type] = result.Answer;
          }
        } catch (err) {
          console.error(`Error querying ${type}:`, err);
        }
      }

      // Extract SPF records from root TXT records
      if (usualResults.TXT) {
        const spfRecords = usualResults.TXT.filter(record => 
          record.data && record.data.toLowerCase().includes('v=spf1')
        );
        if (spfRecords.length > 0) {
          emailSecurityResults['SPF (TXT)'] = spfRecords;
        }
      }

      // Query email security records
      for (const record of RECORD_TYPES.emailSecurity) {
        const queryDomain = `${record.name}.${cleanDomain}`;
        
        try {
          const result = await queryDNS(queryDomain, record.type, providerUrl);
          if (result.Answer && result.Answer.length > 0) {
            emailSecurityResults[record.label] = result.Answer;
          }
        } catch (err) {
          console.error(`Error querying ${record.label}:`, err);
        }
      }

      results = {
        domain: cleanDomain,
        provider: provider === 'google' ? 'dns.google' : '1.1.1.1',
        usual: usualResults,
        emailSecurity: emailSecurityResults
      };

      // Update browser history
      const state = { domain: cleanDomain, provider };
      const url = `?domain=${encodeURIComponent(cleanDomain)}&provider=${provider}`;
      window.history.pushState(state, '', url);

    } catch (err) {
      error = `Error: ${err.message}`;
    } finally {
      loading = false;
    }
  }

  // Handle browser back/forward navigation
  function handlePopState(event) {
    if (event.state && event.state.domain) {
      domain = event.state.domain;
      provider = event.state.provider || 'google';
      handleLookup();
    } else {
      // Clear results when going back to initial state
      results = null;
      domain = '';
      provider = 'google';
    }
  }

  // Check URL params on mount
  onMount(() => {
    window.addEventListener('popstate', handlePopState);

    const params = new URLSearchParams(window.location.search);
    const urlDomain = params.get('domain');
    const urlProvider = params.get('provider');

    if (urlDomain) {
      domain = urlDomain;
      if (urlProvider && PROVIDERS[urlProvider]) {
        provider = urlProvider;
      } else {
        provider = 'google';
      }
      handleLookup();
    }

    return () => {
      window.removeEventListener('popstate', handlePopState);
    };
  });

  // Handle Enter key
  function handleKeyPress(event) {
    if (event.key === 'Enter') {
      handleLookup();
    }
  }

  // Clear all results and reset
  function handleClear() {
    domain = '';
    results = null;
    error = '';
    // Reset URL to clean state
    window.history.pushState({}, '', window.location.pathname);
  }

  // Scroll to section
  function scrollToSection(sectionId) {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  // Get all available record types from results
  function getAvailableRecords() {
    if (!results) return { usual: [], emailSecurity: [] };
    
    return {
      usual: Object.keys(results.usual),
      emailSecurity: Object.keys(results.emailSecurity)
    };
  }

  // Copy record data to clipboard
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      showToast = true;
      setTimeout(() => {
        showToast = false;
      }, 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  }
</script>

<main>
  <header>
    <h1>🔍 dns.holywhite.com</h1>
    <p>Query DNS records using DNS-over-HTTPS</p>
    <p>Use at your own risk. This tool is a playground project.</p>
  </header>

  <div class="search-section">
    <div class="input-group">
      <select bind:value={provider} disabled={loading}>
        <option value="google">dns.google</option>
        <option value="cloudflare">1.1.1.1</option>
      </select>
      <input
        type="text"
        bind:value={domain}
        on:keypress={handleKeyPress}
        placeholder="Enter domain (e.g., example.com)"
        disabled={loading}
      />
      <button on:click={handleLookup} disabled={loading}>
        {loading ? 'Querying...' : 'Query'}
      </button>
      <button on:click={handleClear} disabled={loading} class="clear-btn">
        Clear
      </button>
    </div>
  </div>

  {#if loading}
    <div class="loading">
      <div class="spinner"></div>
      <p>Querying DNS records...</p>
    </div>
  {/if}

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if results}
    <div class="results-container">
      <div class="results">
        <div class="results-header">
          <h2>Results for: <span class="domain">{results.domain}</span></h2>
          <p class="provider">Provider: {results.provider}</p>
  </div>

        <!-- Usual Records Section -->
        <section class="records-section">
          <h3>📋 Standard DNS Records</h3>
          {#if Object.keys(results.usual).length > 0}
            {#each Object.entries(results.usual) as [type, records]}
              <div class="record-group" id="record-{type}">
                <h4>{type}</h4>
                <div class="record-list">
                  {#each records as record}
                    <div class="record-item">
                      <div class="record-content">
                        <span class="record-ttl">TTL: {record.TTL}s</span>
                        <span class="record-data">{record.data}</span>
                      </div>
                      <button class="copy-btn" on:click={() => copyToClipboard(record.data)} title="Copy to clipboard">
                        📋
                      </button>
                    </div>
                  {/each}
                </div>
              </div>
            {/each}
          {:else}
            <p class="no-records">No standard records found</p>
          {/if}
        </section>

        <!-- Email Security Section -->
        <section class="records-section">
          <h3>🔒 Email Security Records</h3>
          {#if Object.keys(results.emailSecurity).length > 0}
            {#each Object.entries(results.emailSecurity) as [label, records]}
              <div class="record-group" id="record-{label}">
                <h4>{label}</h4>
                <div class="record-list">
                  {#each records as record}
                    <div class="record-item">
                      <div class="record-content">
                        <span class="record-ttl">TTL: {record.TTL}s</span>
                        <span class="record-data">{record.data}</span>
                      </div>
                      <button class="copy-btn" on:click={() => copyToClipboard(record.data)} title="Copy to clipboard">
                        📋
                      </button>
                    </div>
                  {/each}
                </div>
              </div>
            {/each}
          {:else}
            <p class="no-records">No email security records found</p>
          {/if}
        </section>
      </div>
    </div>

    <!-- Floating Navigation -->
    <aside class="floating-index">
        <h4>Navigation</h4>
        <div class="index-section">
          <p class="index-category">Standard</p>
          {#each getAvailableRecords().usual as type}
            <button class="index-link" on:click={() => scrollToSection(`record-${type}`)}>
              {type}
            </button>
          {/each}
        </div>
        {#if getAvailableRecords().emailSecurity.length > 0}
          <div class="index-section">
            <p class="index-category">Security</p>
            {#each getAvailableRecords().emailSecurity as type}
              <button class="index-link" on:click={() => scrollToSection(`record-${type}`)}>
                {type}
              </button>
            {/each}
          </div>
        {/if}
      </aside>
  {/if}
</main>

<footer>
  <p>Source: <a href="https://github.com/richardevs/dns-spa-2">GitHub</a></p>
</footer>

<!-- Toast Notification -->
{#if showToast}
  <div class="toast">
    ✓ Copied to clipboard
  </div>
{/if}

<style>
  :global(body) {
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: #1a1a1a;
    min-height: 100vh;
  }

  main {
    max-width: 1100px;
    margin: 0 auto;
    padding: 2rem 1rem;
    min-height: calc(100vh - 100px);
  }

  header {
    text-align: center;
    color: #e0e0e0;
    margin-bottom: 2rem;
  }

  header h1 {
    font-size: 2.5rem;
    margin: 0 0 0.5rem 0;
    font-weight: 700;
  }

  header p {
    font-size: 1.1rem;
    margin: 0;
    opacity: 0.7;
  }

  .search-section {
    background: #2a2a2a;
    padding: 2rem;
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
    margin-bottom: 2rem;
  }

  .input-group {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  select {
    min-width: 160px;
    padding: 0.75rem 1rem;
    border: 2px solid #3a3a3a;
    border-radius: 8px;
    font-size: 1rem;
    background: #1a1a1a;
    color: #e0e0e0;
    cursor: pointer;
    transition: border-color 0.3s;
    height: 48px;
  }

  select:focus {
    outline: none;
    border-color: #667eea;
  }

  select:disabled {
    background: #333;
    cursor: not-allowed;
  }

  input {
    flex: 1;
    min-width: 200px;
    padding: 0.75rem 1rem;
    border: 2px solid #3a3a3a;
    border-radius: 8px;
    font-size: 1rem;
    background: #1a1a1a;
    color: #e0e0e0;
    transition: border-color 0.3s;
    height: 48px;
  }

  input:focus {
    outline: none;
    border-color: #667eea;
  }

  input:disabled {
    background: #333;
    cursor: not-allowed;
  }

  button {
    padding: 0.75rem 2rem;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
    height: 48px;
  }

  button:active:not(:disabled) {
    transform: scale(0.98);
  }

  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  button.clear-btn {
    background: #3a3a3a;
    color: #b0b0b0;
    border: 2px solid #4a4a4a;
  }

  button.clear-btn:active:not(:disabled) {
    background: #4a4a4a;
    color: #e0e0e0;
  }

  .loading {
    background: #2a2a2a;
    padding: 3rem;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
    color: #e0e0e0;
  }

  .spinner {
    width: 50px;
    height: 50px;
    margin: 0 auto 1rem;
    border: 4px solid #3a3a3a;
    border-top: 4px solid #667eea;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  .error {
    background: #3a1f1f;
    color: #ff6b6b;
    padding: 1rem;
    border-radius: 8px;
    border-left: 4px solid #ff6b6b;
    margin-bottom: 1rem;
  }

  .results-container {
    max-width: 1100px;
    margin: 0 auto;
    position: relative;
  }

  .floating-index {
    position: fixed;
    right: max(1rem, calc((100vw - 1100px) / 2 - 140px - 2rem));
    bottom: 4rem;
    width: 140px;
    max-height: 80vh;
    overflow-y: auto;
    background: rgba(42, 42, 42, 0.95);
    backdrop-filter: blur(10px);
    padding: 1rem 0.75rem;
    border-radius: 8px;
    border: 1px solid rgba(102, 126, 234, 0.3);
    scrollbar-width: thin;
    scrollbar-color: #667eea rgba(42, 42, 42, 0.5);
  }

  .floating-index::-webkit-scrollbar {
    width: 4px;
  }

  .floating-index::-webkit-scrollbar-track {
    background: transparent;
  }

  .floating-index::-webkit-scrollbar-thumb {
    background: #667eea;
    border-radius: 2px;
  }

  .floating-index h4 {
    margin: 0 0 0.75rem 0;
    font-size: 0.85rem;
    color: #667eea;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    opacity: 0.9;
  }

  .index-section {
    margin-bottom: 1rem;
  }

  .index-section:last-child {
    margin-bottom: 0;
  }

  .index-category {
    font-size: 0.7rem;
    color: #888;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.8px;
    margin: 0 0 0.4rem 0;
    opacity: 0.6;
  }

  .index-link {
    display: block;
    width: 100%;
    text-align: left;
    padding: 0.4rem 0.5rem;
    margin-bottom: 0.15rem;
    background: transparent;
    border: none;
    color: #8b9cff;
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    border-radius: 4px;
    transition: all 0.2s;
    font-family: 'Courier New', monospace;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .index-link:active {
    background: rgba(102, 126, 234, 0.3);
    color: #fff;
  }

  .results {
    background: #2a2a2a;
    padding: 2.5rem;
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
  }

  .results-header {
    margin-bottom: 2.5rem;
    padding-bottom: 1.25rem;
    border-bottom: 3px solid #3a3a3a;
  }

  .results-header h2 {
    margin: 0 0 0.75rem 0;
    font-size: 1.75rem;
    color: #e0e0e0;
    font-weight: 700;
  }

  .domain {
    color: #8b9cff;
    font-family: 'Courier New', monospace;
    font-weight: 600;
  }

  .provider {
    margin: 0;
    color: #999;
    font-size: 1rem;
    font-weight: 500;
  }

  .records-section {
    margin-bottom: 3rem;
  }

  .records-section:last-child {
    margin-bottom: 0;
  }

  .records-section h3 {
    color: #e0e0e0;
    margin: 0 0 1.5rem 0;
    font-size: 1.5rem;
    font-weight: 700;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #3a3a3a;
  }

  .record-group {
    margin-bottom: 2rem;
  }

  .record-group h4 {
    margin: 0 0 0.75rem 0;
    color: #8b9cff;
    font-size: 1.2rem;
    font-weight: 700;
    letter-spacing: 0.5px;
  }

  .record-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .record-item {
    background: #1a1a1a;
    padding: 1rem 1.25rem;
    border-radius: 8px;
    border-left: 4px solid #667eea;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
  }

  .record-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .record-ttl {
    font-size: 0.9rem;
    color: #888;
    font-weight: 500;
  }

  .record-data {
    font-family: 'Courier New', monospace;
    color: #b0b0b0;
    font-size: 1rem;
    font-weight: bold;
    word-break: break-all;
    line-height: 1.6;
    padding: 0.5rem;
    background: #0f0f0f;
    border-radius: 4px;
  }

  .copy-btn {
    flex-shrink: 0;
    padding: 0.25rem 0.5rem;
    background: transparent;
    border: none;
    font-size: 1rem;
    color: #888;
    cursor: pointer;
    transition: all 0.2s;
    opacity: 0.5;
  }

  .copy-btn:active {
    opacity: 1;
    transform: scale(0.9);
  }

  .no-records {
    color: #888;
    font-style: italic;
    margin: 1rem 0;
    font-size: 1rem;
    padding: 1rem;
    background: #1a1a1a;
    border-radius: 8px;
    text-align: center;
  }

  footer {
    text-align: center;
    color: #888;
    padding: 2rem 1rem;
    font-size: 0.9rem;
  }

  footer p {
    margin: 0;
  }

  footer a {
    color: #8b9cff;
    text-decoration: none;
  }

  .toast {
    position: fixed;
    bottom: 2rem;
    left: 50%;
    transform: translateX(-50%);
    background: #4ade80;
    color: #1a1a1a;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.95rem;
    box-shadow: 0 4px 12px rgba(74, 222, 128, 0.3);
    animation: slideUp 0.3s ease-out;
    z-index: 1000;
  }

  @keyframes slideUp {
    from {
      opacity: 0;
      transform: translateX(-50%) translateY(1rem);
    }
    to {
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }
  }

  @media (max-width: 1400px) {
    .floating-index {
      display: none;
    }
  }

  @media (max-width: 768px) {
    header h1 {
      font-size: 2rem;
    }

    .input-group {
      flex-direction: column;
    }

    input, select, button {
      width: 100%;
      height: 48px;
    }

    .floating-index {
      padding: 1rem;
    }

    .floating-index h4 {
      font-size: 1rem;
    }

    .index-link {
      font-size: 0.85rem;
      padding: 0.4rem 0.6rem;
    }

    .results {
      padding: 1.5rem;
    }

    .results-header h2 {
      font-size: 1.4rem;
    }

    .records-section h3 {
      font-size: 1.3rem;
    }

    .record-group h4 {
      font-size: 1.1rem;
    }

    .record-item {
      padding: 1rem;
      flex-direction: column;
      align-items: flex-start;
    }

    .copy-btn {
      align-self: flex-end;
    }

    .record-data {
      font-size: 0.95rem;
    }
  }
</style>
