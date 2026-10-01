/* codec_mgmt.js — SNMP (BER v1/v2c) et syslog : encodage / décodage / arbre pour l'analyseur */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS; const { N, hex, u16, u32, hex2str, Writer } = Codec._h;

/* ------------------------------------------------------------------ BER */
const BER = {};
BER.len = n => n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255];
BER.tlv = (tag, c) => { const l = BER.len(c.length); const u = new Uint8Array(1 + l.length + c.length); u[0] = tag; u.set(l, 1); u.set(c, 1 + l.length); return u; };
BER.cat = arr => { let n = 0; arr.forEach(a => n += a.length); const u = new Uint8Array(n); let o = 0; arr.forEach(a => { u.set(a, o); o += a.length; }); return u; };
BER.int = v => { const b = []; let x = v; do { b.unshift(((x % 256) + 256) % 256); x = Math.floor(x / 256); } while (!((x === 0 && !(b[0] & 0x80)) || (x === -1 && (b[0] & 0x80)))); return Uint8Array.from(b); };
BER.uint = v => { const b = []; let x = v; do { b.unshift(x % 256); x = Math.floor(x / 256); } while (x > 0); if (b[0] & 0x80) b.unshift(0); return Uint8Array.from(b); };
BER.oid = s => { const p = String(s).replace(/^\./, '').split('.').map(Number); const b = [40 * p[0] + p[1]]; for (let i = 2; i < p.length; i++) { let x = p[i]; const t = [x & 127]; x = Math.floor(x / 128); while (x > 0) { t.unshift((x & 127) | 128); x = Math.floor(x / 128); } b.push(...t); } return Uint8Array.from(b); };
BER.oidStr = (u, o, l) => { const p = [Math.floor(u[o] / 40), u[o] % 40]; let x = 0; for (let i = o + 1; i < o + l; i++) { x = x * 128 + (u[i] & 127); if (!(u[i] & 128)) { p.push(x); x = 0; } } return p.join('.'); };
BER.str = v => typeof v === 'string' ? Uint8Array.from(Array.from(unescape(encodeURIComponent(v))).map(c => c.charCodeAt(0))) : v;
const TAGS = { get: 0xA0, getnext: 0xA1, response: 0xA2, set: 0xA3, trap1: 0xA4, getbulk: 0xA5, inform: 0xA6, trap2: 0xA7, report: 0xA8 };
const PDU_NAMES = { 0xA0: 'get-request', 0xA1: 'get-next-request', 0xA2: 'get-response', 0xA3: 'set-request', 0xA4: 'trap', 0xA5: 'getBulkRequest', 0xA6: 'informRequest', 0xA7: 'snmpV2-trap', 0xA8: 'report' };
const ERRS = ['noError', 'tooBig', 'noSuchName', 'badValue', 'readOnly', 'genErr', 'noAccess', 'wrongType', 'wrongLength', 'wrongEncoding', 'wrongValue', 'noCreation', 'inconsistentValue', 'resourceUnavailable', 'commitFailed', 'undoFailed', 'authorizationError', 'notWritable', 'inconsistentName'];
BER.value = vb => {
  switch (vb.t) {
    case 'int': return BER.tlv(2, BER.int(vb.v)); case 'oct': return BER.tlv(4, BER.str(vb.v)); case 'null': return BER.tlv(5, []); case 'oid': return BER.tlv(6, BER.oid(vb.v));
    case 'ip': return BER.tlv(0x40, Uint8Array.from([(vb.v >>> 24) & 255, (vb.v >>> 16) & 255, (vb.v >>> 8) & 255, vb.v & 255])); case 'c32': return BER.tlv(0x41, BER.uint(vb.v >>> 0)); case 'g32': return BER.tlv(0x42, BER.uint(vb.v >>> 0)); case 'tt': return BER.tlv(0x43, BER.uint(vb.v >>> 0));
    case 'opaque': return BER.tlv(0x44, BER.str(vb.v)); case 'c64': return BER.tlv(0x46, BER.uint(vb.v)); case 'nso': return BER.tlv(0x80, []); case 'nsi': return BER.tlv(0x81, []); case 'eom': return BER.tlv(0x82, []);
  } return BER.tlv(5, []);
};
Codec.snmp = function (m) {
  const pdu = m.pdu; const vbs = BER.tlv(0x30, BER.cat((pdu.varbinds || []).map(vb => BER.tlv(0x30, BER.cat([BER.tlv(6, BER.oid(vb.oid)), BER.value(vb)])))));
  let body;
  if (pdu.type === 'trap1') body = BER.cat([BER.tlv(6, BER.oid(pdu.enterprise)), BER.value({ t: 'ip', v: pdu.agent }), BER.tlv(2, BER.int(pdu.generic)), BER.tlv(2, BER.int(pdu.specific || 0)), BER.tlv(0x43, BER.uint(pdu.time || 0)), vbs]);
  else body = BER.cat([BER.tlv(2, BER.int(pdu.reqId)), BER.tlv(2, BER.int(pdu.errStatus || 0)), BER.tlv(2, BER.int(pdu.errIdx || 0)), vbs]);
  return BER.tlv(0x30, BER.cat([BER.tlv(2, BER.int(m.ver)), BER.tlv(4, BER.str(m.community)), BER.tlv(TAGS[pdu.type], body)]));
};
function tlv(u, o, end) {
  if (o + 2 > end) return null; const tag = u[o]; let l = u[o + 1], h = 2; if (l & 0x80) { const n = l & 0x7f; if (n < 1 || n > 2 || o + 2 + n > end) return null; l = 0; for (let i = 0; i < n; i++) l = l * 256 + u[o + 2 + i]; h = 2 + n; }
  if (o + h + l > end) return null; return { tag, o, h, l, v: o + h, next: o + h + l };
}
function rdInt(u, t) { let x = (u[t.v] & 0x80) ? -1 : 0; for (let i = 0; i < t.l; i++) x = x * 256 + u[t.v + i]; return x; }
function rdUint(u, t) { let x = 0; for (let i = 0; i < t.l; i++) x = x * 256 + u[t.v + i]; return x; }
function rdVal(u, t) {
  switch (t.tag) {
    case 2: return { t: 'int', v: rdInt(u, t) }; case 4: return { t: 'oct', v: u.slice(t.v, t.v + t.l) }; case 5: return { t: 'null', v: null }; case 6: return { t: 'oid', v: BER.oidStr(u, t.v, t.l) };
    case 0x40: return { t: 'ip', v: ((u[t.v] << 24) | (u[t.v + 1] << 16) | (u[t.v + 2] << 8) | u[t.v + 3]) >>> 0 }; case 0x41: return { t: 'c32', v: rdUint(u, t) }; case 0x42: return { t: 'g32', v: rdUint(u, t) }; case 0x43: return { t: 'tt', v: rdUint(u, t) };
    case 0x44: return { t: 'opaque', v: u.slice(t.v, t.v + t.l) }; case 0x46: return { t: 'c64', v: rdUint(u, t) }; case 0x80: return { t: 'nso', v: null }; case 0x81: return { t: 'nsi', v: null }; case 0x82: return { t: 'eom', v: null };
  } return { t: 'null', v: null };
}
const TNAME = { int: 'Integer32', oct: 'OctetString', null: 'Null', oid: 'OID', ip: 'IpAddress', c32: 'Counter32', g32: 'Gauge32', tt: 'Timeticks', opaque: 'Opaque', c64: 'Counter64', nso: 'noSuchObject', nsi: 'noSuchInstance', eom: 'endOfMibView' };
function valStr(v) {
  if (v.t === 'oct') { let s = ''; let printable = true; for (const b of v.v) { if (b < 32 || b > 126) printable = false; s += String.fromCharCode(b); } return printable ? s : hex2str(v.v, 0, v.v.length); }
  if (v.t === 'ip') return IP.str(v.v); if (v.t === 'null') return ''; if (v.t === 'nso' || v.t === 'nsi' || v.t === 'eom') return ''; return String(v.v);
}
function parseSnmp(u, o, end, detail, nodes) {
  const top = tlv(u, o, end); if (!top || top.tag !== 0x30) return null;
  const tv = tlv(u, top.v, top.next), tc = tv && tlv(u, tv.next, top.next); if (!tv || tv.tag !== 2 || !tc || tc.tag !== 4) return null;
  const tp = tlv(u, tc.next, top.next); if (!tp || !PDU_NAMES[tp.tag]) return null;
  const m = { ver: rdInt(u, tv), community: String.fromCharCode.apply(null, Array.from(u.subarray(tc.v, tc.v + tc.l))), pdu: { tag: tp.tag, type: PDU_NAMES[tp.tag], varbinds: [] } };
  const P = m.pdu; let vbT;
  if (tp.tag === 0xA4) {
    const e = tlv(u, tp.v, tp.next), a = e && tlv(u, e.next, tp.next), gt = a && tlv(u, a.next, tp.next), st = gt && tlv(u, gt.next, tp.next), tt = st && tlv(u, st.next, tp.next); vbT = tt && tlv(u, tt.next, tp.next); if (!vbT) return null;
    P.enterprise = BER.oidStr(u, e.v, e.l); P.agent = rdVal(u, a).v; P.generic = rdInt(u, gt); P.specific = rdInt(u, st); P.time = rdUint(u, tt);
  } else {
    const r = tlv(u, tp.v, tp.next), es = r && tlv(u, r.next, tp.next), ei = es && tlv(u, es.next, tp.next); vbT = ei && tlv(u, ei.next, tp.next); if (!vbT) return null;
    P.reqId = rdInt(u, r); P.errStatus = rdInt(u, es); P.errIdx = rdInt(u, ei); var offs = { r, es, ei };
  }
  const vbo = [];
  for (let q = vbT.v; q < vbT.next;) { const vb = tlv(u, q, vbT.next); if (!vb) break; const on = tlv(u, vb.v, vb.next), vv = on && tlv(u, on.next, vb.next); if (!on || !vv) break; const val = rdVal(u, vv); P.varbinds.push({ oid: BER.oidStr(u, on.v, on.l), t: val.t, v: val.v }); vbo.push({ vb, on, vv }); q = vb.next; }
  if (detail) {
    const VN = ['v1', 'v2c'][m.ver] || 'v' + m.ver;
    const vbn = P.varbinds.map((x, i) => { const w = vbo[i]; return N(x.oid + ': Value (' + TNAME[x.t] + (x.t === 'null' || x.t === 'nso' || x.t === 'nsi' || x.t === 'eom' ? '' : ': ' + valStr(x)) + ')', w.vb.o, w.vb.next - w.vb.o, [N('Object Name: ' + x.oid + ' (iso.' + x.oid.replace(/^1\./, '') + ')', w.on.o, w.on.next - w.on.o), N('Value (' + TNAME[x.t] + ')' + (valStr(x) ? ': ' + valStr(x) : ''), w.vv.o, w.vv.next - w.vv.o)]); });
    const pch = [];
    if (tp.tag === 0xA4) pch.push(N('enterprise: ' + P.enterprise, tp.v, 0), N('generic-trap: ' + P.generic, tp.v, 0));
    else { const nm = tp.tag === 0xA5 ? ['non-repeaters', 'max-repetitions'] : ['error-status', 'error-index'];
      pch.push(N('request-id: ' + P.reqId, offs.r.o, offs.r.next - offs.r.o), N(nm[0] + ': ' + (tp.tag === 0xA5 ? P.errStatus : (ERRS[P.errStatus] || P.errStatus) + ' (' + P.errStatus + ')'), offs.es.o, offs.es.next - offs.es.o), N(nm[1] + ': ' + P.errIdx, offs.ei.o, offs.ei.next - offs.ei.o)); }
    pch.push(N('variable-bindings: ' + P.varbinds.length + ' item' + (P.varbinds.length > 1 ? 's' : ''), vbT.o, vbT.next - vbT.o, vbn));
    nodes.push(N('version: ' + VN + ' (' + m.ver + ')', tv.o, tv.next - tv.o), N('community: ' + m.community, tc.o, tc.next - tc.o), N('data: ' + P.type + ' (' + (tp.tag & 15) + ')', tp.o, tp.next - tp.o, [N(P.type, tp.v, tp.next - tp.v, pch)]));
  }
  return m;
}
Codec.snmpTypeName = TNAME; Codec.snmpValStr = valStr; Codec.SNMP_ERRS = ERRS; Codec.BER = BER;
Codec.snmpSummary = function (s) {
  const P = s.pdu; const oids = P.varbinds.slice(0, 3).map(v => v.oid).join(' '); return P.type + ' ' + (P.type === 'get-response' && P.errStatus ? '(' + ERRS[P.errStatus] + ') ' : '') + oids + (P.varbinds.length > 3 ? ' …' : '');
};

/* ------------------------------------------------------------------ syslog (RFC 3164) */
const FAC = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
const SEV = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug'];
Codec.SYSLOG_FAC = FAC; Codec.SYSLOG_SEV = SEV;
Codec.syslog = function (pri, text) { return Uint8Array.from(Array.from('<' + pri + '>' + text).map(c => c.charCodeAt(0) & 255)); };
function parseSyslog(u, o, end) {
  let s = ''; for (let i = o; i < Math.min(end, o + 1200); i++) s += String.fromCharCode(u[i]); const m = /^<(\d{1,3})>([\s\S]*)$/.exec(s); if (!m) return null; const pri = +m[1];
  return { pri, facility: pri >> 3, severity: pri & 7, msg: m[2].replace(/\0+$/, '') };
}
Codec.udpApps.push((p, u, o, end, detail) => {
  const { sport, dport } = p.udp;
  if (sport === 161 || dport === 161 || sport === 162 || dport === 162) {
    const nodes = []; const s = parseSnmp(u, o, end, detail, nodes); if (!s) return false; p.snmp = s;
    if (detail) { const n = N('Simple Network Management Protocol', o, end - o, nodes); n.layer = 'snmp'; p.tree.push(n); } return true;
  }
  if (dport === 514 || sport === 514) {
    const s = parseSyslog(u, o, end); if (!s) return false; p.syslog = s;
    if (detail) { const n = N('Syslog message: ' + FAC[s.facility].toUpperCase() + '.' + SEV[s.severity].toUpperCase() + ': ' + s.msg.slice(0, 80), o, end - o, [N((s.facility * 8 + s.severity < 10 ? '' : '') + '.... ' + (s.facility).toString(2).padStart(5, '0') + ' ' + (s.severity).toString(2).padStart(3, '0') + ' = Facility: ' + FAC[s.facility].toUpperCase() + ' - ' + s.facility, o, 5), N('Level: ' + SEV[s.severity].toUpperCase() + ' - ' + SEV[s.severity] + ' (' + s.severity + ')', o, 5), N('Message: ' + s.msg, o + 1 + String(s.pri).length + 1, end - o - String(s.pri).length - 2)]); n.layer = 'syslog'; p.tree.push(n); }
    return true;
  }
  return false;
});
})(typeof window !== 'undefined' ? window : globalThis);
