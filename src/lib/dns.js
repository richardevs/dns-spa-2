import { parseDKIM } from './parsers.js';

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

/** Build the Team Cymru DNS-based ASN whois query name for an IP (v4 or v6). */
export function cymruQueryName(ip) {
  if (ip.includes(':')) {
    // IPv6: reverse the full exploded nibble list, e.g. 2001:db8::1 -> ...origin6.asn.cymru.com
    const parts = ip.split('::');
    const head = parts[0] ? parts[0].split(':') : [];
    const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    const groups = [...head, ...Array(Math.max(missing, 0)).fill('0'), ...tail];
    const exploded = groups.map(g => g.padStart(4, '0')).join('');
    const nibbles = exploded.split('').reverse().join('.');
    return `${nibbles}.origin6.asn.cymru.com`;
  }
  const octets = ip.split('.').reverse().join('.');
  return `${octets}.origin.asn.cymru.com`;
}

/** Parse a Team Cymru origin TXT answer: "ASN | prefix | CC | registry | date" */
export function parseCymruTxt(txt) {
  if (!txt) return null;
  const cleaned = txt.replace(/^"|"$/g, '');
  const parts = cleaned.split('|').map(p => p.trim());
  if (parts.length < 2 || !/^\d+/.test(parts[0])) return null;
  return { asn: parts[0].split(' ')[0], prefix: parts[1] };
}

/**
 * Look up the registered org/AS-name for each ASN via Team Cymru's
 * second-stage DNS whois (AS{asn}.asn.cymru.com, format:
 * "ASN | CC | registry | date | AS Name"). Best-effort, per-ASN failures
 * are silently omitted.
 *
 * The AS Name field is conventionally "HANDLE - free-text description, CC"
 * (e.g. "TENCENT-NET-AP - Shenzhen Tencent Computer Systems..., CN") — we
 * split that into a short handle for compact display and the full string
 * for a hover tooltip.
 */
export async function resolveAsnNames(asns, providerUrl) {
  const uniqueAsns = [...new Set(asns)];
  const names = {};
  await Promise.all(uniqueAsns.map(async asn => {
    try {
      const result = await queryDNS(`AS${asn}.asn.cymru.com`, 'TXT', providerUrl);
      const answer = (result.Answer ?? [])[0];
      if (!answer) return;
      const parts = answer.data.replace(/^"|"$/g, '').split('|').map(p => p.trim());
      const full = parts.length >= 5 ? parts[4] : '';
      if (!full) return;
      const dashIdx = full.indexOf(' - ');
      names[asn] = { short: dashIdx === -1 ? full : full.slice(0, dashIdx), full };
    } catch (err) {
      console.error(`Error looking up name for AS${asn}:`, err);
    }
  }));
  return names;
}

/**
 * Resolve each NS hostname to its IP(s) and look up ASN + org name via Team
 * Cymru's DNS-based whois (plain TXT queries through the same DoH provider).
 * Best-effort: any failed lookup is silently omitted, never thrown.
 *
 * A single NS hostname can resolve to many IPs on *different* networks
 * (e.g. providers like DNSPod return 8-10+ IPs per NS, one per major ISP
 * backbone) — so we track the full set of distinct ASNs per host rather
 * than picking one representative IP, which would misrepresent both the
 * per-host display and the overall network-diversity count.
 *
 * Returns { [hostname]: {
 *   ips: string[],
 *   asns: string[],                                   // distinct ASNs across all of this host's IPs
 *   ipDetails: { ip, asn: string|null, prefix: string|null }[],
 *   asnGroups: { asn: string|null, name: string|null, nameShort: string|null, ips: string[] }[]  // IPs grouped by network, for display
 * } }
 */
export async function resolveNSNetwork(nsHosts, providerUrl) {
  const uniqueHosts = [...new Set(nsHosts)];

  const hostIPs = await Promise.all(uniqueHosts.map(async host => {
    const [aResult, aaaaResult] = await Promise.allSettled([
      queryDNS(host, 'A', providerUrl),
      queryDNS(host, 'AAAA', providerUrl)
    ]);
    const ips = [];
    if (aResult.status === 'fulfilled') {
      ips.push(...filterAnswers(aResult.value.Answer ?? [], 'A').map(r => r.data));
    }
    if (aaaaResult.status === 'fulfilled') {
      ips.push(...filterAnswers(aaaaResult.value.Answer ?? [], 'AAAA').map(r => r.data));
    }
    return { host, ips };
  }));

  const uniqueIPs = [...new Set(hostIPs.flatMap(h => h.ips))];
  const asnByIP = {};
  await Promise.all(uniqueIPs.map(async ip => {
    try {
      const result = await queryDNS(cymruQueryName(ip), 'TXT', providerUrl);
      const answer = (result.Answer ?? [])[0];
      const parsed = answer ? parseCymruTxt(answer.data) : null;
      if (parsed) asnByIP[ip] = parsed;
    } catch (err) {
      console.error(`Error looking up ASN for ${ip}:`, err);
    }
  }));

  const allAsns = [...new Set(Object.values(asnByIP).map(v => v.asn))];
  const asnNames = await resolveAsnNames(allAsns, providerUrl);

  const network = {};
  for (const { host, ips } of hostIPs) {
    const ipDetails = ips.map(ip => ({
      ip,
      asn: asnByIP[ip]?.asn ?? null,
      prefix: asnByIP[ip]?.prefix ?? null
    }));
    const asnKeys = [...new Set(ipDetails.map(d => d.asn))];
    network[host] = {
      ips,
      asns: asnKeys.filter(Boolean),
      ipDetails,
      asnGroups: asnKeys.map(asn => ({
        asn,
        name: asn ? (asnNames[asn]?.full ?? null) : null,
        nameShort: asn ? (asnNames[asn]?.short ?? null) : null,
        ips: ipDetails.filter(d => d.asn === asn).map(d => d.ip)
      }))
    };
  }
  return network;
}

/**
 * Classify a DKIM TXT record's public key: type (RSA/Ed25519), and for RSA
 * the exact modulus bit length (via Web Crypto SPKI import of the p= tag) —
 * flags keys below RFC 8301's 2048-bit recommendation. Best-effort: returns
 * null if the key can't be parsed (malformed, unsupported k= type, etc).
 */
export async function classifyDkimKey(txt) {
  const pairs = parseDKIM(txt);
  const kTag = pairs.find(p => p.k === 'k')?.v?.toLowerCase() || 'rsa';
  const pTag = pairs.find(p => p.k === 'p')?.v || '';

  if (!pTag) {
    return { keyType: kTag, keyBits: null, keyStatus: 'fail', keyLabel: 'Revoked (empty p=)' };
  }

  let bytes;
  try {
    bytes = Uint8Array.from(atob(pTag), c => c.charCodeAt(0));
  } catch (err) {
    console.error('Error decoding DKIM key:', err);
    return null;
  }

  if (kTag === 'ed25519') {
    return { keyType: 'ed25519', keyBits: 256, keyStatus: 'pass', keyLabel: 'Ed25519' };
  }

  try {
    const cryptoKey = await crypto.subtle.importKey(
      'spki', bytes.buffer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']
    );
    const bits = cryptoKey.algorithm.modulusLength;
    const status = bits < 1024 ? 'fail' : bits < 2048 ? 'warn' : 'pass';
    return { keyType: 'rsa', keyBits: bits, keyStatus: status, keyLabel: `RSA ${bits}-bit` };
  } catch (err) {
    console.error('Error classifying DKIM key:', err);
    return null;
  }
}

/**
 * Query SOA for domain against the DoH provider other than primaryProvider,
 * as a weak cross-resolver proxy for per-authoritative-NS serial agreement.
 */
export async function checkSoaCrossResolver(domain, primaryProvider) {
  const otherProvider = primaryProvider === 'google' ? 'cloudflare' : 'google';
  try {
    const result = await queryDNS(domain, 'SOA', PROVIDERS[otherProvider]);
    const answers = filterAnswers(result.Answer ?? [], 'SOA');
    if (!answers.length) return null;
    const soa = parseSOA(answers[0].data);
    if (!soa) return null;
    return { provider: otherProvider === 'google' ? 'dns.google' : '1.1.1.1', serial: soa.serial };
  } catch (err) {
    console.error('Error cross-checking SOA:', err);
    return null;
  }
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
          emailSecurityResults[label] = await Promise.all(
            answers.map(async record => ({ ...record, ...(await classifyDkimKey(record.data)) }))
          );
        }
      } catch (err) {
        console.error(`Error querying ${label}:`, err);
      }
    }
  }

  const [nsNetwork, soaCrossCheck] = await Promise.all([
    usualResults.NS ? resolveNSNetwork(usualResults.NS.map(r => r.data), providerUrl) : Promise.resolve(null),
    usualResults.SOA ? checkSoaCrossResolver(cleanDomain, provider) : Promise.resolve(null)
  ]);

  if (nsNetwork && usualResults.NS) {
    usualResults.NS = usualResults.NS.map(record => ({ ...record, ...nsNetwork[record.data] }));
  }

  return {
    domain: cleanDomain,
    provider: provider === 'google' ? 'dns.google' : '1.1.1.1',
    usual: usualResults,
    emailSecurity: emailSecurityResults,
    soaCrossCheck
  };
}
