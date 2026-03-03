/**
 * Detect how a record should be rendered based on its label and data.
 * Returns one of: 'ipv4' | 'ipv6' | 'mx' | 'ns' | 'soa' | 'caa' |
 *                 'spf' | 'dmarc' | 'mta-sts' | 'tls-rpt' | 'dkim' | 'txt'
 */
export function detectRenderType(label) {
  if (label === 'A')                         return 'ipv4';
  if (label === 'AAAA')                      return 'ipv6';
  if (label === 'MX')                        return 'mx';
  if (label === 'NS')                        return 'ns';
  if (label === 'SOA')                       return 'soa';
  if (label === 'CAA')                       return 'caa';
  if (label === 'SPF (TXT)')                 return 'spf';
  if (label === '_dmarc (TXT)')              return 'dmarc';
  if (label === '_mta-sts (TXT)')            return 'mta-sts';
  if (label === '_smtp._tls (TXT)')          return 'tls-rpt';
  if (label.includes('_domainkey'))          return 'dkim';
  return 'txt';
}

/** Parse semicolon-delimited key=value pairs (DMARC, MTA-STS, TLS-RPT, DKIM) */
function parseSemicolonKV(txt) {
  const pairs = [];
  txt.split(/;\s*/).forEach(part => {
    const eq = part.indexOf('=');
    if (eq === -1) return;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) pairs.push({ k, v });
  });
  return pairs;
}

export function parseDMARC(txt) {
  return parseSemicolonKV(txt);
}

export function parseMTASTS(txt) {
  return parseSemicolonKV(txt);
}

export function parseTLSRPT(txt) {
  return parseSemicolonKV(txt);
}

export function parseDKIM(txt) {
  return parseSemicolonKV(txt);
}

/**
 * Parse SPF record into annotated tokens.
 * Returns array of { token, kind }
 * kind: 'version' | 'mechanism' | 'modifier' | 'qualifier'
 */
export function parseSPF(txt) {
  const tokens = txt.trim().split(/\s+/);
  return tokens.map(token => {
    if (/^v=spf1$/i.test(token))         return { token, kind: 'version' };
    if (/^[+\-~?]?all$/.test(token))     return { token, kind: 'all' };
    if (/^[+\-~?]?(include|ip4|ip6|a|mx|ptr|exists|redirect|exp)[:\/=]/.test(token))
                                          return { token, kind: 'mechanism' };
    if (/^[+\-~?](a|mx)$/.test(token))  return { token, kind: 'mechanism' };
    return { token, kind: 'other' };
  });
}

/**
 * Parse MX record data "priority hostname" into { priority, hostname }
 */
export function parseMX(data) {
  const m = data.match(/^(\d+)\s+(.+)$/);
  if (m) return { priority: m[1], hostname: m[2] };
  return { priority: null, hostname: data };
}

/**
 * Parse CAA record already decoded to "flags tag value"
 * e.g. "0 issue \"letsencrypt.org\""
 */
export function parseCAAsimple(data) {
  const m = data.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?$/);
  if (m) return { flags: m[1], tag: m[2], value: m[3] };
  return null;
}
