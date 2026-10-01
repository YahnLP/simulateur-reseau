/* codec_aaa.js — MD5/HMAC-MD5, RADIUS (RFC 2865/2866/3579), EAP, EAPOL (802.1X) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS; const { N, hex, u16, u32, hex2str } = Codec._h;
const cat = (...a) => { let n = 0; a.forEach(x => n += x.length); const r = new Uint8Array(n); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };
const be32 = v => Uint8Array.of((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255), be16 = v => Uint8Array.of((v >> 8) & 255, v & 255);
const sb = s => Uint8Array.from(Array.from(String(s)).map(c => c.charCodeAt(0) & 255)), bs = u => Array.from(u).map(c => String.fromCharCode(c)).join('');
const hx = u => Array.from(u).map(b => b.toString(16).padStart(2, '0')).join('');

/* ---------------------------------------------------------------- MD5 */
const K = new Uint32Array(64); for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
function md5(data) {
  const len = data.length; const nb = ((len + 8) >> 6) + 1; const m = new Uint8Array(nb * 64); m.set(data); m[len] = 0x80;
  const dv = new DataView(m.buffer); dv.setUint32(nb * 64 - 8, (len << 3) >>> 0, true); dv.setUint32(nb * 64 - 4, Math.floor(len / 536870912), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let o = 0; o < nb * 64; o += 64) {
    const M = new Uint32Array(16); for (let i = 0; i < 16; i++) M[i] = dv.getUint32(o + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, gi; const r = i >> 4;
      if (r === 0) { F = (B & C) | (~B & D); gi = i; } else if (r === 1) { F = (D & B) | (~D & C); gi = (5 * i + 1) & 15; } else if (r === 2) { F = B ^ C ^ D; gi = (3 * i + 5) & 15; } else { F = C ^ (B | ~D); gi = (7 * i) & 15; }
      F = (F + A + K[i] + M[gi]) >>> 0; A = D; D = C; C = B; const s = S[r * 4 + (i & 3)]; B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer); ov.setUint32(0, a0, true); ov.setUint32(4, b0, true); ov.setUint32(8, c0, true); ov.setUint32(12, d0, true); return out;
}
function hmacMd5(key, data) {
  if (key.length > 64) key = md5(key); const k = new Uint8Array(64); k.set(key); const ip = k.map(x => x ^ 0x36), op = k.map(x => x ^ 0x5c);
  return md5(cat(op, md5(cat(ip, data))));
}
Codec.md5 = md5; Codec.hmacMd5 = hmacMd5; Codec.md5hex = s => hx(md5(typeof s === 'string' ? sb(s) : s));

/* ---------------------------------------------------------------- RADIUS */
const RCODES = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 4: 'Accounting-Request', 5: 'Accounting-Response', 11: 'Access-Challenge', 12: 'Status-Server', 13: 'Status-Client' };
const RATTR = { 1: 'User-Name', 2: 'User-Password', 3: 'CHAP-Password', 4: 'NAS-IP-Address', 5: 'NAS-Port', 6: 'Service-Type', 7: 'Framed-Protocol', 8: 'Framed-IP-Address', 11: 'Filter-Id', 18: 'Reply-Message', 24: 'State', 25: 'Class', 26: 'Vendor-Specific', 27: 'Session-Timeout', 30: 'Called-Station-Id', 31: 'Calling-Station-Id', 32: 'NAS-Identifier', 40: 'Acct-Status-Type', 41: 'Acct-Delay-Time', 42: 'Acct-Input-Octets', 43: 'Acct-Output-Octets', 44: 'Acct-Session-Id', 45: 'Acct-Authentic', 46: 'Acct-Session-Time', 61: 'NAS-Port-Type', 64: 'Tunnel-Type', 65: 'Tunnel-Medium-Type', 79: 'EAP-Message', 80: 'Message-Authenticator', 81: 'Tunnel-Private-Group-Id' };
const RTYPE = { text: [1, 18, 30, 31, 32, 44, 11, 81], int: [5, 6, 7, 27, 40, 41, 42, 43, 45, 46, 61, 64, 65], ip: [4, 8] };
const SVC = { 1: 'Login', 2: 'Framed', 8: 'Authenticate Only', 10: 'Call Check' }, ACCT = { 1: 'Start', 2: 'Stop', 3: 'Interim-Update' }, NASPT = { 15: 'Ethernet', 19: 'Wireless - IEEE 802.11' };
Object.assign(Codec, { RADIUS_CODES: RCODES, RADIUS_ATTRS: RATTR });
/* attrs : [{t, v:Uint8Array|string|number}] */
function attrBytes(a) {
  let v = a.v; if (typeof v === 'string') v = sb(v); else if (typeof v === 'number') v = be32(v >>> 0); else if (v && v.ip !== undefined) v = be32(v.ip);
  const max = 253; if (v.length > max) throw new Error('attr too long'); return cat(Uint8Array.of(a.t, v.length + 2), v);
}
/* construit un paquet. req : {code, id, auth (16 o.), attrs, secret, reqAuth (pour les réponses)} */
Codec.radius = function (o) {
  let attrs = (o.attrs || []).slice();
  // EAP-Message fragmentés + Message-Authenticator
  const eapIdx = attrs.findIndex(a => a.t === 79);
  if (eapIdx >= 0) {
    const a = attrs[eapIdx]; const frag = []; for (let i = 0; i < a.v.length; i += 253) frag.push({ t: 79, v: a.v.slice(i, i + 253) }); attrs.splice(eapIdx, 1, ...frag);
    if (!attrs.some(x => x.t === 80)) attrs.push({ t: 80, v: new Uint8Array(16) });
  }
  const body0 = cat(...attrs.map(attrBytes)); const len = 20 + body0.length; const isResp = o.code === 2 || o.code === 3 || o.code === 11 || o.code === 5;
  const hdr = (auth) => cat(Uint8Array.of(o.code, o.id), be16(len), auth);
  let auth = o.auth || new Uint8Array(16);
  const macIdx = attrs.findIndex(x => x.t === 80);
  if (macIdx >= 0) { // HMAC-MD5 sur le paquet (Message-Authenticator à zéro) ; pour une réponse, on utilise l'authenticator de la requête
    const zero = cat(...attrs.map(x => attrBytes(x.t === 80 ? { t: 80, v: new Uint8Array(16) } : x))); const pk = cat(hdr(isResp ? o.reqAuth : auth), zero); attrs[macIdx] = { t: 80, v: hmacMd5(sb(o.secret), pk) };
  }
  const body = cat(...attrs.map(attrBytes));
  if (isResp) auth = md5(cat(Uint8Array.of(o.code, o.id), be16(len), o.reqAuth, body, sb(o.secret)));
  else if (o.code === 4) auth = md5(cat(Uint8Array.of(o.code, o.id), be16(len), new Uint8Array(16), body, sb(o.secret)));
  return cat(hdr(auth), body);
};
/* User-Password (PAP) : chiffrement RFC 2865 §5.2 */
Codec.radiusPap = function (pass, secret, auth) {
  const p = sb(pass); const n = Math.max(16, Math.ceil(p.length / 16) * 16); const pp = new Uint8Array(n); pp.set(p); const out = new Uint8Array(n); let prev = auth;
  for (let i = 0; i < n; i += 16) { const h = md5(cat(sb(secret), prev)); for (let j = 0; j < 16; j++) out[i + j] = pp[i + j] ^ h[j]; prev = out.slice(i, i + 16); }
  return out;
};
Codec.radiusPapDecode = function (enc, secret, auth) {
  const out = new Uint8Array(enc.length); let prev = auth;
  for (let i = 0; i < enc.length; i += 16) { const h = md5(cat(sb(secret), prev)); for (let j = 0; j < 16; j++) out[i + j] = enc[i + j] ^ h[j]; prev = enc.slice(i, i + 16); }
  let e = out.length; while (e > 0 && out[e - 1] === 0) e--; return bs(out.slice(0, e));
};
/* vérifie authenticator de réponse (et Message-Authenticator) */
Codec.radiusVerifyResp = function (bytes, reqAuth, secret) {
  const len = u16(bytes, 2); const t = bytes.slice(0, len); t.set(reqAuth, 4); const want = md5(cat(t, sb(secret)));
  return want.every((x, i) => x === bytes[4 + i]);
};
Codec.radiusVerifyMac = function (bytes, reqAuth, secret, isResp) {
  const len = u16(bytes, 2); let o = 20, mo = -1; while (o + 2 <= len) { if (bytes[o] === 80) { mo = o; } if (bytes[o + 1] < 2) break; o += bytes[o + 1]; }
  if (mo < 0) return true; const t = bytes.slice(0, len); if (isResp) t.set(reqAuth, 4); t.fill(0, mo + 2, mo + 18); const want = hmacMd5(sb(secret), t);
  return want.every((x, i) => x === bytes[mo + 2 + i]);
};
Codec.parseRadiusAttrs = function (u, o, end) {
  const r = []; while (o + 2 <= end) { const t = u[o], l = u[o + 1]; if (l < 2 || o + l > end) break; r.push({ t, name: RATTR[t] || 'Attribute ' + t, v: u.slice(o + 2, o + l), off: o, len: l }); o += l; } return r;
};
function attrText(a) {
  const v = a.v; if (RTYPE.int.includes(a.t) && v.length === 4) { const n = u32(v, 0); const nm = a.t === 6 ? SVC[n] : a.t === 40 ? ACCT[n] : a.t === 61 ? NASPT[n] : a.t === 64 ? ({ 13: 'VLAN' })[n] : a.t === 65 ? ({ 6: 'IEEE-802' })[n] : null; return nm ? nm + ' (' + n + ')' : String(n); }
  if (RTYPE.ip.includes(a.t) && v.length === 4) return IP.str(u32(v, 0));
  if (a.t === 2) return 'Encrypted (' + v.length + ' bytes)'; if (a.t === 80) return hx(v); if (a.t === 79) return 'Last Segment[1]'; if (a.t === 24 || a.t === 25) return hx(v);
  if (a.t === 81) return v[0] < 32 ? bs(v.slice(1)) : bs(v);
  return bs(v).replace(/[^\x20-\x7e]/g, '.');
}
Codec.radiusAttrText = attrText;
/* attributs → valeur texte */
Codec.radiusGet = (attrs, t) => { const a = attrs.find(x => x.t === t); return a ? a.v : null; };
Codec.radiusGetStr = (attrs, t) => { const a = attrs.find(x => x.t === t); return a ? bs(a.v) : null; };

function parseRadius(p, u, o, end, detail) {
  if (end - o < 20) return false; const code = u[o], id = u[o + 1], len = u16(u, o + 2); if (!RCODES[code] || len < 20 || len > end - o + 0) return false;
  const attrs = Codec.parseRadiusAttrs(u, o + 20, o + len); const auth = u.slice(o + 4, o + 20);
  const eapParts = attrs.filter(a => a.t === 79); let eap = null; if (eapParts.length) { const all = cat(...eapParts.map(a => a.v)); eap = Codec.parseEapBytes(all); }
  const r = p.radius = { code, id, len, auth, attrs, eap, user: Codec.radiusGetStr(attrs, 1) };
  if (eap) p.eap = eap;
  if (detail) {
    const ch = [N('Code: ' + RCODES[code] + ' (' + code + ')', o, 1), N('Packet identifier: 0x' + hex(id, 2) + ' (' + id + ')', o + 1, 1), N('Length: ' + len, o + 2, 2), N('Authenticator: ' + hx(auth), o + 4, 16)];
    const an = attrs.map(a => { const c = [N('Type: ' + a.t, a.off, 1), N('Length: ' + a.len, a.off + 1, 1), N(a.name + ': ' + attrText(a), a.off + 2, a.len - 2)]; return N('AVP: t=' + a.name + '(' + a.t + ') l=' + a.len + ' val=' + attrText(a), a.off, a.len, c); });
    if (an.length) ch.push(N('Attribute Value Pairs', o + 20, len - 20, an));
    const n = N('RADIUS Protocol', o, len, ch); n.layer = 'radius'; p.tree.push(n);
    if (eap) { const first = eapParts[0]; const en = Codec.eapNode(eap, first.off + 2, eapParts.reduce((s, a) => s + a.len - 2, 0)); p.tree.push(en); }
  }
  return true;
}
Codec.udpApps.push((p, u, o, end, detail) => { const { sport, dport } = p.udp; if (![1812, 1813, 1645, 1646].includes(sport) && ![1812, 1813, 1645, 1646].includes(dport)) return false; return parseRadius(p, u, o, end, detail); });
Codec.radiusSummary = function (r) {
  const nm = RCODES[r.code]; let s = nm + ' id=' + r.id; if (r.user) s += ', user=' + r.user;
  if (r.eap) s += ' [' + Codec.eapSummary(r.eap) + ']'; const rm = Codec.radiusGetStr(r.attrs, 18); if (rm) s += ' "' + rm + '"'; return s;
};

/* ---------------------------------------------------------------- EAP / EAPOL */
const EAPC = { 1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure' }, EAPT = { 1: 'Identity', 2: 'Notification', 3: 'Legacy Nak', 4: 'MD5-Challenge', 13: 'EAP-TLS', 25: 'Protected EAP (EAP-PEAP)', 26: 'EAP-MSCHAPv2' };
Object.assign(Codec, { EAP_CODES: EAPC, EAP_TYPES: EAPT });
Codec.eap = function (o) { // {code, id, type, data}
  if (o.code === 3 || o.code === 4) return cat(Uint8Array.of(o.code, o.id), be16(4));
  const d = o.data || new Uint8Array(0); return cat(Uint8Array.of(o.code, o.id), be16(5 + d.length), Uint8Array.of(o.type), d);
};
Codec.parseEapBytes = function (b) {
  if (b.length < 4) return null; const code = b[0], id = b[1], len = u16(b, 2); if (!EAPC[code] || len < 4 || len > b.length) return null; const e = { code, id, len, type: null, data: new Uint8Array(0) };
  if (len > 4 && (code === 1 || code === 2)) { e.type = b[4]; e.data = b.slice(5, len); } return e;
};
/* PEAP : indicateurs + charge TLS */
function tlsLabel(d) {
  if (!d.length) return 'empty'; const t = d[0]; if (t === 22 && d.length > 5) return ({ 1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 14: 'Server Hello Done', 16: 'Client Key Exchange', 20: 'Finished' })[d[5]] || 'Handshake';
  return ({ 20: 'Change Cipher Spec', 21: 'Alert', 23: 'Application Data' })[t] || 'TLS data';
}
Codec.peapInfo = function (data) { // data = octets après le type
  if (!data.length) return { flags: 0, tls: new Uint8Array(0) }; const fl = data[0]; let o = 1; if (fl & 0x80) o += 4; return { flags: fl, start: !!(fl & 0x20), more: !!(fl & 0x40), tls: data.slice(o), ver: fl & 7 };
};
Codec.eapSummary = function (e) {
  let s = 'EAP ' + EAPC[e.code]; if (e.type !== null) { s += ', ' + (EAPT[e.type] || 'type ' + e.type); if (e.type === 25 || e.type === 13) { const pi = Codec.peapInfo(e.data); s += pi.start ? ' (Start)' : ' (' + tlsLabel(pi.tls) + ')'; } if (e.type === 1 && e.data.length) s += ': ' + bs(e.data); } return s;
};
Codec.eapNode = function (e, off, len) {
  const ch = [N('Code: ' + EAPC[e.code] + ' (' + e.code + ')', off, 1), N('Id: ' + e.id, off + 1, 1), N('Length: ' + e.len, off + 2, 2)];
  if (e.type !== null) {
    ch.push(N('Type: ' + (EAPT[e.type] || e.type) + ' (' + e.type + ')', off + 4, 1));
    if (e.type === 1) ch.push(N('Identity: ' + bs(e.data), off + 5, e.data.length));
    else if (e.type === 4) { ch.push(N('EAP-MD5 Value-Size: ' + e.data[0], off + 5, 1), N('EAP-MD5 Value: ' + hx(e.data.slice(1, 1 + e.data[0])), off + 6, e.data[0])); }
    else if (e.type === 25 || e.type === 13) { const pi = Codec.peapInfo(e.data); ch.push(N('EAP-TLS Flags: 0x' + hex(pi.flags, 2) + (pi.start ? ' (Start)' : '') + (pi.more ? ' (More fragments)' : ''), off + 5, 1)); if (pi.tls.length) ch.push(N('TLS payload: ' + tlsLabel(pi.tls) + ' (' + pi.tls.length + ' bytes)', off + 6, pi.tls.length)); }
    else if (e.type === 3) ch.push(N('Desired Auth Type: ' + (EAPT[e.data[0]] || e.data[0]), off + 5, 1));
  }
  const n = N('Extensible Authentication Protocol', off, len, ch); n.layer = 'eap'; return n;
};
const EAPOLT = { 0: 'EAP Packet', 1: 'Start', 2: 'Logoff', 3: 'Key', 4: 'Encapsulated-ASF-Alert' };
Codec.EAPOL_MAC = '01:80:c2:00:00:03'; Codec.EAPOL_TYPES = EAPOLT;
Codec.eapol = function (type, body) { body = body || new Uint8Array(0); return cat(Uint8Array.of(2, type), be16(body.length), body); };
Codec.ethApps[0x888e] = function (p, u, off, end, detail) {
  if (end - off < 4) { p.bad = 'Trame EAPOL tronquée'; return; } const ver = u[off], type = u[off + 1], len = u16(u, off + 2); const eapol = p.eapol = { ver, type, len, eap: null };
  if (type === 0 && len >= 4 && off + 4 + len <= end + 0) { const e = Codec.parseEapBytes(u.slice(off + 4, off + 4 + len)); if (e) { eapol.eap = e; p.eap = e; } }
  if (detail) {
    const ch = [N('Version: 802.1X-' + (ver === 2 ? '2004' : ver === 1 ? '2001' : ver) + ' (' + ver + ')', off, 1), N('Type: ' + (EAPOLT[type] || type) + ' (' + type + ')', off + 1, 1), N('Length: ' + len, off + 2, 2)];
    const n = N('802.1X Authentication', off, Math.min(end - off, 4 + len), ch); n.layer = 'eapol'; p.tree.push(n); if (eapol.eap) p.tree.push(Codec.eapNode(eapol.eap, off + 4, len));
  }
};
Codec.eapolSummary = function (e) { return e.type === 0 && e.eap ? Codec.eapSummary(e.eap) : 'Start' === EAPOLT[e.type] ? 'Start' : (EAPOLT[e.type] || 'type ' + e.type); };
})(typeof window !== 'undefined' ? window : globalThis);
