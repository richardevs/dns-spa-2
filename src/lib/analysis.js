import { parseSOA } from './dns.js';

function isPrivateIP(ip) {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fc00:|fd[0-9a-f]{2}:)/.test(ip);
}

export function analyzeResults(results) {
  if (!results) return null;

  const { usual, emailSecurity } = results;
  const analysis = {};

  // NS: 2+ = pass, 1 = warn, 0 = fail
  const nsRecords = usual.NS || [];
  const nsCount = nsRecords.length;
  if (nsCount >= 2) {
    analysis.ns = { status: 'pass', message: `${nsCount} nameservers` };
  } else if (nsCount === 1) {
    analysis.ns = { status: 'warn', message: '1 nameserver (2+ recommended)' };
  } else {
    analysis.ns = { status: 'fail', message: 'No NS records' };
  }

  // SOA: serial format check
  const soaRecords = usual.SOA || [];
  if (soaRecords.length > 0) {
    const soa = parseSOA(soaRecords[0].data);
    if (soa) {
      const isDateSerial = /^\d{10}$/.test(String(soa.serial));
      analysis.soa = {
        status: isDateSerial ? 'pass' : 'info',
        message: isDateSerial
          ? 'Serial uses date format (YYYYMMDDnn)'
          : 'Serial does not use date format'
      };
    } else {
      analysis.soa = { status: 'info', message: 'SOA record present' };
    }
  } else {
    analysis.soa = { status: 'fail', message: 'No SOA record' };
  }

  // MX
  const mxRecords = usual.MX || [];
  if (mxRecords.length > 0) {
    analysis.mx = { status: 'pass', message: `${mxRecords.length} MX record(s)` };
  } else {
    analysis.mx = { status: 'info', message: 'No MX records' };
  }

  // SPF: exactly 1 = pass, >1 = fail, 0 = warn
  const spfRecords = emailSecurity['SPF (TXT)'] || [];
  if (spfRecords.length === 1) {
    analysis.spf = { status: 'pass', message: 'SPF record found' };
  } else if (spfRecords.length > 1) {
    analysis.spf = { status: 'fail', message: `${spfRecords.length} SPF records (must be 1)` };
  } else {
    analysis.spf = { status: 'warn', message: 'No SPF record' };
  }

  // DMARC — extract policy for dashboard display
  const dmarcRecords = emailSecurity['_dmarc (TXT)'] || [];
  if (dmarcRecords.length > 0) {
    const dmarcData = dmarcRecords[0].data;
    const pMatch = dmarcData.match(/\bp=([a-z]+)/i);
    const policy = pMatch ? pMatch[1].toLowerCase() : 'none';
    const status = policy === 'reject' ? 'pass' : policy === 'quarantine' ? 'info' : 'warn';
    analysis.dmarc = { status, message: `p=${policy}`, policy };
  } else {
    analysis.dmarc = { status: 'warn', message: 'No DMARC record', policy: null };
  }

  // WWW: A/AAAA IP analysis
  const aRecords = usual.A || [];
  const aaaaRecords = usual.AAAA || [];
  const allIPs = [...aRecords.map(r => r.data), ...aaaaRecords.map(r => r.data)];
  if (allIPs.length > 0) {
    const hasPrivate = allIPs.some(ip => isPrivateIP(ip));
    analysis.www = {
      status: hasPrivate ? 'warn' : 'pass',
      message: hasPrivate ? 'Private IP detected' : `${allIPs.length} IP(s) found`
    };
  } else {
    analysis.www = { status: 'info', message: 'No A/AAAA records' };
  }

  // Total email security records for dashboard
  analysis.securityCount = Object.keys(emailSecurity).length;

  return analysis;
}
