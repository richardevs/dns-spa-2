export const PROVIDERS = {
  google: 'https://dns.google/resolve',
  cloudflare: 'https://cloudflare-dns.com/dns-query'
};

export const RECORD_TYPES = {
  usual: ['SOA', 'A', 'AAAA', 'TXT', 'MX', 'NS', 'CAA'],
  emailSecurity: [
    { type: 'TXT', name: '_dmarc', label: '_dmarc (TXT)' },
    { type: 'A', name: 'mta-sts', label: 'mta-sts (A)' },
    { type: 'AAAA', name: 'mta-sts', label: 'mta-sts (AAAA)' },
    { type: 'TXT', name: '_mta-sts', label: '_mta-sts (TXT)' },
    { type: 'TXT', name: '_smtp._tls', label: '_smtp._tls (TXT)' }
  ]
};

export function parseCAA(hexData) {
  const match = hexData.match(/\\#\s+\d+\s+([\da-fA-F\s]+)/);
  if (!match) return hexData;

  const hexBytes = match[1].replace(/\s+/g, '');
  try {
    const flags = parseInt(hexBytes.substr(0, 2), 16);
    const tagLength = parseInt(hexBytes.substr(2, 2), 16);
    const tagHex = hexBytes.substr(4, tagLength * 2);
    const tag = tagHex.match(/.{2}/g)
      .map(byte => String.fromCharCode(parseInt(byte, 16)))
      .join('');
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

export function parseSOA(soaData) {
  const parts = soaData.trim().split(/\s+/);
  if (parts.length < 7) return null;
  return {
    mname:   parts[0],
    rname:   parts[1],
    serial:  parts[2],
    refresh: parts[3],
    retry:   parts[4],
    expire:  parts[5],
    minimum: parts[6]
  };
}

export async function queryDNS(recordDomain, recordType, providerUrl) {
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

// DNS type numbers — used to filter CNAME passthrough records from answers
const DNS_TYPE = { A: 1, NS: 2, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };

function filterAnswers(answers, type) {
  const typeNum = DNS_TYPE[type];
  return typeNum ? answers.filter(r => r.type === typeNum) : answers;
}

export async function performLookup(domain, provider, dkimSelectors) {
  const cleanDomain = domain.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '');

  const providerUrl = PROVIDERS[provider];
  const usualResults = {};
  const emailSecurityResults = {};

  for (const type of RECORD_TYPES.usual) {
    try {
      const result = await queryDNS(cleanDomain, type, providerUrl);
      const answers = filterAnswers(result.Answer ?? [], type);
      if (answers.length > 0) {
        if (type === 'CAA' && provider === 'cloudflare') {
          usualResults[type] = answers.map(record => ({ ...record, data: parseCAA(record.data) }));
        } else {
          usualResults[type] = answers;
        }
      }
    } catch (err) {
      console.error(`Error querying ${type}:`, err);
    }
  }

  if (usualResults.TXT) {
    const spfRecords = usualResults.TXT.filter(record =>
      record.data && record.data.toLowerCase().includes('v=spf1')
    );
    if (spfRecords.length > 0) {
      emailSecurityResults['SPF (TXT)'] = spfRecords;
    }
  }

  for (const record of RECORD_TYPES.emailSecurity) {
    const queryDomain = `${record.name}.${cleanDomain}`;
    try {
      const result = await queryDNS(queryDomain, record.type, providerUrl);
      const answers = filterAnswers(result.Answer ?? [], record.type);
      if (answers.length > 0) {
        emailSecurityResults[record.label] = answers;
      }
    } catch (err) {
      console.error(`Error querying ${record.label}:`, err);
    }
  }

  if (dkimSelectors && dkimSelectors.trim()) {
    const selectors = dkimSelectors.split(',').map(s => s.trim()).filter(s => s);
    for (const selector of selectors) {
      const queryDomain = `${selector}._domainkey.${cleanDomain}`;
      const label = `${selector}._domainkey (TXT)`;
      try {
        const result = await queryDNS(queryDomain, 'TXT', providerUrl);
        const answers = filterAnswers(result.Answer ?? [], 'TXT');
        if (answers.length > 0) {
          emailSecurityResults[label] = answers;
        }
      } catch (err) {
        console.error(`Error querying ${label}:`, err);
      }
    }
  }

  return {
    domain: cleanDomain,
    provider: provider === 'google' ? 'dns.google' : '1.1.1.1',
    usual: usualResults,
    emailSecurity: emailSecurityResults
  };
}
