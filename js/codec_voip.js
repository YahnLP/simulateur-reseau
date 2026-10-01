/* codec_voip.js — SIP (texte), SDP, RTP, CDP (VLAN voix) : construction, décodage et arbre pour l'analyseur */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS; const { N, hex, u16, u32 } = Codec._h;
const sb = s => Uint8Array.from(Array.from(unescape(encodeURIComponent(String(s)))).map(c => c.charCodeAt(0) & 255));
const bs = u => { let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); try { return decodeURIComponent(escape(s)); } catch (e) { return s; } };

/* ---------------------------------------------------------------- SIP */
const REASON = { 100: 'Trying', 180: 'Ringing', 183: 'Session Progress', 200: 'OK', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 407: 'Proxy Authentication Required', 408: 'Request Timeout', 480: 'Temporarily Unavailable', 486: 'Busy Here', 487: 'Request Terminated', 488: 'Not Acceptable Here', 500: 'Server Internal Error', 503: 'Service Unavailable', 603: 'Decline' };
Codec.SIP_REASON = REASON;
const COMPACT = { i: 'Call-ID', f: 'From', t: 'To', v: 'Via', m: 'Contact', c: 'Content-Type', l: 'Content-Length' };
/* m : {method, uri} ou {status, reason} ; headers : [[nom, valeur]] ; body : texte */
Codec.sip = function (m) {
  let o = m.method ? m.method + ' ' + m.uri + ' SIP/2.0\r\n' : 'SIP/2.0 ' + m.status + ' ' + (m.reason || REASON[m.status] || '') + '\r\n';
  const body = m.body || ''; const hs = (m.headers || []).filter(h => h[0] !== 'Content-Length');
  hs.forEach(h => { o += h[0] + ': ' + h[1] + '\r\n'; }); o += 'Content-Length: ' + sb(body).length + '\r\n\r\n' + body; return sb(o);
};
Codec.parseSipText = function (txt) {
  const i = txt.indexOf('\r\n\r\n'); const head = i < 0 ? txt : txt.slice(0, i), body = i < 0 ? '' : txt.slice(i + 4);
  const lines = head.split('\r\n'); const first = lines.shift();
  let m = /^SIP\/2\.0 (\d{3}) ?(.*)$/.exec(first), r;
  if (m) r = { isReq: false, status: +m[1], reason: m[2] }; else { m = /^([A-Z]+) (\S+) SIP\/2\.0$/.exec(first); if (!m) return null; r = { isReq: true, method: m[1], uri: m[2] }; }
  r.first = first; r.headers = []; lines.forEach(l => { const k = l.indexOf(':'); if (k > 0) { let n = l.slice(0, k).trim(); n = COMPACT[n] || n; r.headers.push([n, l.slice(k + 1).trim()]); } });
  r.body = body; r.h = n => { const x = r.headers.find(h => h[0].toLowerCase() === n.toLowerCase()); return x ? x[1] : null; };
  r.callId = r.h('Call-ID'); const cs = /^(\d+)\s+(\w+)/.exec(r.h('CSeq') || ''); r.cseq = cs ? +cs[1] : 0; r.cmethod = cs ? cs[2] : (r.method || '');
  const user = (v) => { const q = /sip:([^@;>]+)@/.exec(v || ''); return q ? q[1] : ''; }; r.from = user(r.h('From')); r.to = user(r.h('To'));
  r.sdp = /application\/sdp/i.test(r.h('Content-Type') || '') ? Codec.parseSdp(body) : null;
  return r;
};
/* ---------------------------------------------------------------- SDP */
const PTN = { 0: 'PCMU/8000', 8: 'PCMA/8000', 9: 'G722/8000', 18: 'G729/8000', 101: 'telephone-event/8000' };
Codec.SDP_PT = PTN;
Codec.sdp = function (o) { // {user, sid, ip, port, pts:[0,8,101]}
  let s = 'v=0\r\no=' + o.user + ' ' + o.sid + ' ' + o.sid + ' IN IP4 ' + IP.str(o.ip) + '\r\ns=Session SIP\r\nc=IN IP4 ' + IP.str(o.ip) + '\r\nt=0 0\r\nm=audio ' + o.port + ' RTP/AVP ' + o.pts.join(' ') + '\r\n';
  o.pts.forEach(pt => { s += 'a=rtpmap:' + pt + ' ' + PTN[pt] + '\r\n'; if (pt === 101) s += 'a=fmtp:101 0-16\r\n'; }); s += 'a=ptime:20\r\na=sendrecv\r\n'; return s;
};
Codec.parseSdp = function (t) {
  const r = { ip: null, port: 0, pts: [], lines: t.split(/\r?\n/).filter(Boolean) };
  r.lines.forEach(l => { let m; if ((m = /^c=IN IP4 (\S+)/.exec(l))) r.ip = IP.parse(m[1]); else if ((m = /^m=audio (\d+) \S+ (.*)$/.exec(l))) { r.port = +m[1]; r.pts = m[2].split(' ').map(Number); } });
  return r;
};
Codec.sipSummary = function (s) { return s.isReq ? s.method + ' ' + s.uri + (s.sdp ? ' (SDP)' : '') : 'Status: ' + s.status + ' ' + s.reason + ' (' + s.cmethod + ')' + (s.sdp ? ' (SDP)' : ''); };
function sipNode(u, o, end, s) {
  const txt = bs(u.slice(o, end)); const lines = txt.split('\r\n'); let p = o; const kids = [];
  const first = N(s.isReq ? 'Request-Line: ' + s.first : 'Status-Line: ' + s.first, p, lines[0].length + 2, s.isReq ? [N('Method: ' + s.method, p, s.method.length), N('Request-URI: ' + s.uri, p + s.method.length + 1, s.uri.length)] : [N('Status-Code: ' + s.status, p + 8, 3), N('Reason Phrase: ' + s.reason, p + 12, s.reason.length)]);
  kids.push(first); p += lines[0].length + 2; const hk = [];
  for (let i = 1; i < lines.length && lines[i] !== ''; i++) { hk.push(N(lines[i], p, lines[i].length + 2)); p += lines[i].length + 2; }
  kids.push(N('Message Header', o + lines[0].length + 2, p - o - lines[0].length - 2, hk)); p += 2;
  if (s.body) { const bk = s.body.split(/\r?\n/).filter(Boolean).map(l => N(l, p, l.length)); kids.push(N('Message Body', p, end - p, s.sdp ? [N('Session Description Protocol', p, end - p, bk)] : bk)); }
  const n = N('Session Initiation Protocol (' + (s.isReq ? s.method : s.status) + ')', o, end - o, kids); n.layer = 'sip'; return n;
}
/* ---------------------------------------------------------------- RTP */
Codec.rtp = function (o) { // {pt, seq, ts, ssrc, mark, payload}
  const h = new Uint8Array(12 + o.payload.length); h[0] = 0x80; h[1] = (o.mark ? 0x80 : 0) | (o.pt & 127); h[2] = (o.seq >> 8) & 255; h[3] = o.seq & 255;
  h[4] = (o.ts >>> 24) & 255; h[5] = (o.ts >>> 16) & 255; h[6] = (o.ts >>> 8) & 255; h[7] = o.ts & 255; h[8] = (o.ssrc >>> 24) & 255; h[9] = (o.ssrc >>> 16) & 255; h[10] = (o.ssrc >>> 8) & 255; h[11] = o.ssrc & 255; h.set(o.payload, 12); return h;
};
Codec.RTP_PT = { 0: 'ITU-T G.711 PCMU', 8: 'ITU-T G.711 PCMA', 9: 'ITU-T G.722', 18: 'ITU-T G.729', 101: 'telephone-event' };
function parseRtp(u, o, end) {
  if (end - o < 12 || (u[o] >> 6) !== 2) return null; const pt = u[o + 1] & 127; if (!(pt in Codec.RTP_PT) && pt < 96) return null;
  return { pt, mark: !!(u[o + 1] & 128), seq: u16(u, o + 2), ts: u32(u, o + 4), ssrc: u32(u, o + 8), len: end - o - 12 };
}
/* ---------------------------------------------------------------- CDP */
Codec.CDP_MAC = '01:00:0c:cc:cc:cc';
Codec.cdp = function (o) { // {device, port, platform, caps, voiceVlan (réponse), query}
  const tlv = (t, v) => { const b = new Uint8Array(4 + v.length); b[0] = t >> 8; b[1] = t & 255; b[2] = (4 + v.length) >> 8; b[3] = (4 + v.length) & 255; b.set(v, 4); return b; };
  const parts = [tlv(1, sb(o.device || '')), tlv(3, sb(o.port || '')), tlv(4, Uint8Array.of(0, 0, 0, o.caps === undefined ? 8 : o.caps)), tlv(6, sb(o.platform || ''))];
  if (o.voiceVlan) parts.push(tlv(0x0e, Uint8Array.of(0x20, o.voiceVlan >> 8, o.voiceVlan & 255)));
  if (o.query) parts.push(tlv(0x0f, Uint8Array.of(0x20, 0, 0)));
  let n = 4; parts.forEach(x => n += x.length); const b = new Uint8Array(n); b[0] = 2; b[1] = o.ttl || 180; let k = 4; parts.forEach(x => { b.set(x, k); k += x.length; });
  let sum = 0; for (let i = 0; i < n; i += 2) sum += (b[i] << 8) | (i + 1 < n ? b[i + 1] : 0); while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16); sum = (~sum) & 0xffff; b[2] = sum >> 8; b[3] = sum & 255; return b;
};
Codec.parseCdp = function (p, u, o, end, detail) {
  if (end - o < 4) return; const c = p.cdp = { ver: u[o], ttl: u[o + 1], device: '', port: '', platform: '', voiceVlan: 0, query: false, caps: 0 }; const kids = [N('Version: ' + u[o], o, 1), N('TTL: ' + u[o + 1] + ' seconds', o + 1, 1), N('Checksum: 0x' + hex(u16(u, o + 2), 4), o + 2, 2)];
  let q = o + 4; while (q + 4 <= end) {
    const t = u16(u, q), l = u16(u, q + 2); if (l < 4 || q + l > end) break; const v = u.slice(q + 4, q + l); let lab;
    if (t === 1) { c.device = bs(v); lab = 'Device ID: ' + c.device; } else if (t === 3) { c.port = bs(v); lab = 'Port ID: ' + c.port; } else if (t === 6) { c.platform = bs(v); lab = 'Platform: ' + c.platform; } else if (t === 4) { c.caps = v[3]; lab = 'Capabilities: 0x' + hex(v[3], 8); }
    else if (t === 0x0e) { c.voiceVlan = (v[1] << 8) | v[2]; lab = 'VoIP VLAN Reply: VLAN ' + c.voiceVlan; } else if (t === 0x0f) { c.query = true; lab = 'VoIP VLAN Query'; } else lab = 'Type ' + t + ' (' + v.length + ' octets)';
    kids.push(N(lab, q, l)); q += l;
  }
  if (detail) { const n = N('Cisco Discovery Protocol', o, end - o, kids); n.layer = 'cdp'; p.tree.push(n); }
};
Codec.cdpSummary = c => 'Device ID: ' + c.device + '  Port ID: ' + c.port + (c.voiceVlan ? '  VoIP VLAN Reply: ' + c.voiceVlan : '') + (c.query ? '  VoIP VLAN Query' : '');
/* ---------------------------------------------------------------- crochets UDP */
Codec.udpApps.push((p, u, o, end, detail) => {
  const { sport, dport } = p.udp;
  if (sport === 5060 || dport === 5060) {
    const s = Codec.parseSipText(bs(u.slice(o, end))); if (!s) return false; p.sip = s; if (detail) p.tree.push(sipNode(u, o, end, s)); return true;
  }
  if (sport >= 10000 && dport >= 10000 && sport < 40000 && dport < 40000) {
    const r = parseRtp(u, o, end); if (!r) return false; p.rtp = r;
    if (detail) { const n = N('Real-Time Transport Protocol', o, end - o, [N('Version: RFC 1889 Version 2 (2)', o, 1), N('Marker: ' + (r.mark ? 'True' : 'False'), o + 1, 1), N('Payload type: ' + (Codec.RTP_PT[r.pt] || r.pt) + ' (' + r.pt + ')', o + 1, 1), N('Sequence number: ' + r.seq, o + 2, 2), N('Timestamp: ' + r.ts, o + 4, 4), N('Synchronization Source identifier: 0x' + hex(r.ssrc, 8), o + 8, 4), N('Payload: ' + r.len + ' octets', o + 12, r.len)]); n.layer = 'rtp'; p.tree.push(n); }
    return true;
  }
  return false;
});
})(typeof window !== 'undefined' ? window : globalThis);
