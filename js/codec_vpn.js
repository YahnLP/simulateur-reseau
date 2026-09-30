/* codec_vpn.js — GRE, ESP et ISAKMP/IKEv1 (encodage / décodage / arbre analyseur) */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS; const { N, hex, u16, u32, hex2str } = Codec._h;
const cat = (...a) => { let n = 0; a.forEach(x => n += x.length); const r = new Uint8Array(n); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };
const be32 = v => Uint8Array.of((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255), be16 = v => Uint8Array.of((v >> 8) & 255, v & 255);
Codec.IPPROTOS = Codec.IPPROTOS || {}; Codec.IPPROTOS[47] = 'GRE'; Codec.IPPROTOS[50] = 'ESP'; Codec.IPPROTOS[51] = 'AH';

/* ------------------------------------------------------------------ helpers de décodage d'un paquet IPv4 encapsulé */
function shift(n, d) { n.off += d; (n.ch || []).forEach(c => shift(c, d)); return n; }
/* décode l'IPv4 situé à u[off..end) ; retourne le paquet décodé (sans couche Ethernet) et ses nœuds d'arbre recalés */
Codec.parseIpAt = function (u, off, end, detail) {
  const f = new Uint8Array(14 + end - off); f[12] = 8; f.set(u.subarray(off, end), 14);
  const p = Codec.parse(f, detail); p.inner = true; if (detail) p.tree = p.tree.slice(1).map(n => shift(n, off - 14)); return p;
};

/* ------------------------------------------------------------------ GRE */
Codec.gre = function (o) {
  const key = o.key !== undefined && o.key !== null; const h = cat(be16(key ? 0x2000 : 0), be16(o.proto || 0x0800), key ? be32(o.key) : new Uint8Array(0)); return cat(h, o.payload);
};
Codec.ipApps[47] = function (p, u, po, end, detail) {
  if (end - po < 4) return; const fl = u16(u, po), pr = u16(u, po + 2); let o = po + 4; const hasK = !!(fl & 0x2000), hasC = !!(fl & 0x8000), hasS = !!(fl & 0x1000);
  if (hasC) o += 4; let key = null; if (hasK) { key = u32(u, o); o += 4; } if (hasS) o += 4;
  const gre = p.gre = { flags: fl, proto: pr, key, hdr: o - po };
  if (pr === 0x0800 && end - o >= 20) gre.inner = Codec.parseIpAt(u, o, end, detail);
  if (detail) {
    const ch = [N('Flags and Version: 0x' + hex(fl, 4), po, 2, [N((hasC ? '1' : '0') + '... .... .... .... = Checksum Bit: ' + (hasC ? 'Yes' : 'No'), po, 2), N('..' + (hasK ? '1' : '0') + '. .... .... .... = Key Bit: ' + (hasK ? 'Yes' : 'No'), po, 2), N('.... .... .... .000 = Version: GRE (0)', po, 2)]), N('Protocol Type: ' + (pr === 0x0800 ? 'IP (0x0800)' : pr === 0x86dd ? 'IPv6 (0x86dd)' : '0x' + hex(pr, 4)), po + 2, 2)];
    if (hasK) ch.push(N('Key: 0x' + hex(key, 8), po + 4 + (hasC ? 4 : 0), 4));
    const n = N('Generic Routing Encapsulation (' + (pr === 0x0800 ? 'IP' : '0x' + hex(pr, 4)) + ')', po, o - po, ch); n.layer = 'gre'; p.tree.push(n);
    if (gre.inner) gre.inner.tree.forEach(t => p.tree.push(t));
  }
};

/* ------------------------------------------------------------------ ESP */
Codec.esp = function (spi, seq, body) { return cat(be32(spi), be32(seq), body); };
Codec.ipApps[50] = function (p, u, po, end, detail) {
  if (end - po < 8) return; const spi = u32(u, po), seq = u32(u, po + 4); p.esp = { spi, seq, len: end - po - 8 };
  if (detail) { const n = N('Encapsulating Security Payload', po, end - po, [N('ESP SPI: 0x' + hex(spi, 8) + ' (' + spi + ')', po, 4), N('ESP Sequence: ' + seq, po + 4, 4), N('Encrypted data (' + (end - po - 8) + ' bytes)', po + 8, end - po - 8)]); n.layer = 'esp'; p.tree.push(n); }
};

/* ------------------------------------------------------------------ ISAKMP (IKEv1) */
const EXCH = { 0: 'None', 1: 'Base', 2: 'Identity Protection (Main Mode)', 3: 'Authentication Only', 4: 'Aggressive', 5: 'Informational', 32: 'Quick Mode', 33: 'New Group Mode' };
const PLT = { 0: 'NONE', 1: 'Security Association', 2: 'Proposal', 3: 'Transform', 4: 'Key Exchange', 5: 'Identification', 6: 'Certificate', 7: 'Certificate Request', 8: 'Hash', 9: 'Signature', 10: 'Nonce', 11: 'Notification', 12: 'Delete', 13: 'Vendor ID', 20: 'NAT-D', 21: 'NAT-D (draft)' };
const NOTIF = { 1: 'INVALID-PAYLOAD-TYPE', 2: 'DOI-NOT-SUPPORTED', 3: 'SITUATION-NOT-SUPPORTED', 4: 'INVALID-COOKIE', 5: 'INVALID-MAJOR-VERSION', 7: 'INVALID-EXCHANGE-TYPE', 8: 'INVALID-FLAGS', 9: 'INVALID-MESSAGE-ID', 10: 'INVALID-PROTOCOL-ID', 11: 'INVALID-SPI', 12: 'INVALID-TRANSFORM-ID', 13: 'ATTRIBUTES-NOT-SUPPORTED', 14: 'NO-PROPOSAL-CHOSEN', 15: 'BAD-PROPOSAL-SYNTAX', 16: 'PAYLOAD-MALFORMED', 17: 'INVALID-KEY-INFORMATION', 18: 'INVALID-ID-INFORMATION', 23: 'INVALID-HASH-INFORMATION', 24: 'AUTHENTICATION-FAILED' };
Codec.IKE_EXCH = EXCH; Codec.IKE_NOTIF = NOTIF; Codec.IKE_PAYLOADS = PLT;
const IKE_ATTR = { 1: 'Encryption-Algorithm', 2: 'Hash-Algorithm', 3: 'Authentication-Method', 4: 'Group-Description', 11: 'Life-Type', 12: 'Life-Duration', 14: 'Key-Length' };
const IKE_ENC = { 1: 'DES-CBC', 5: '3DES-CBC', 7: 'AES-CBC' }, IKE_HASH = { 1: 'MD5', 2: 'SHA', 4: 'SHA2-256' }, IKE_AUTH = { 1: 'Pre-shared key', 3: 'RSA signatures' }, IKE_GRP = { 1: 'Default 768-bit MODP group', 2: '1024-bit MODP group', 5: '1536-bit MODP group', 14: '2048-bit MODP group' };
const IPSEC_ATTR = { 1: 'SA-Life-Type', 2: 'SA-Life-Duration', 3: 'Group-Description', 4: 'Encapsulation-Mode', 5: 'Authentication-Algorithm', 6: 'Key-Length' };
const ESP_ID = { 1: 'ESP_DES', 3: 'ESP_3DES', 11: 'ESP_NULL', 12: 'ESP_AES' }, AUTH_ID = { 1: 'HMAC-MD5', 2: 'HMAC-SHA', 5: 'HMAC-SHA2-256' };
Object.assign(Codec, { IKE_ENC, IKE_HASH, ESP_ID, AUTH_ID });
function attrBytes(t, v) { if (v < 65536) return cat(be16(0x8000 | t), be16(v)); return cat(be16(t), be16(4), be32(v)); }
/* transform : {num, id, attrs:[[type,val]…]} ; proposal : {num, proto, spi:Uint8Array, transforms:[]} */
Codec.ikeSA = function (props) {
  const pp = props.map((pr, i) => {
    const tt = pr.transforms.map((t, k) => { const at = cat(...t.attrs.map(a => attrBytes(a[0], a[1]))); const len = 8 + at.length; return cat(Uint8Array.of(k < pr.transforms.length - 1 ? 3 : 0, 0), be16(len), Uint8Array.of(t.num, t.id, 0, 0), at); });
    const spi = pr.spi || new Uint8Array(0); const body = cat(Uint8Array.of(pr.num, pr.proto, spi.length, pr.transforms.length), spi, ...tt);
    return cat(Uint8Array.of(i < props.length - 1 ? 2 : 0, 0), be16(4 + body.length), body);
  });
  return cat(be32(1), be32(1), ...pp);
};
Codec.ikeId = function (type, data) { return cat(Uint8Array.of(type, 0, 0, 0), data); };
Codec.ikeNotify = function (type, spi, data) { return cat(be32(1), Uint8Array.of(1, spi ? spi.length : 0), be16(type), spi || new Uint8Array(0), data || new Uint8Array(0)); };
Codec.isakmp = function (o) {
  const pls = o.payloads || []; const parts = pls.map((pl, i) => cat(Uint8Array.of(i < pls.length - 1 ? pls[i + 1].t : 0, 0), be16(4 + pl.body.length), pl.body));
  const body = cat(...parts); const len = 28 + body.length;
  return cat(o.ic, o.rc, Uint8Array.of(pls.length ? pls[0].t : 0, 0x10, o.exch, o.flags || 0), be32(o.mid || 0), be32(len), body);
};
function parseAttrs(u, o, end, names, valNames) {
  const r = [];
  while (o + 4 <= end) {
    const t = u16(u, o), tv = !!(t & 0x8000), ty = t & 0x7fff; let val, len;
    if (tv) { val = u16(u, o + 2); len = 4; } else { const l = u16(u, o + 2); val = l === 4 ? u32(u, o + 4) : l === 2 ? u16(u, o + 4) : 0; len = 4 + l; }
    r.push({ type: ty, val, tv, off: o, len, name: names[ty] || 'Attribute ' + ty }); o += len;
  }
  return r;
}
function attrNode(a, phase1) {
  let vn = ''; if (phase1) { if (a.type === 1) vn = IKE_ENC[a.val]; else if (a.type === 2) vn = IKE_HASH[a.val]; else if (a.type === 3) vn = IKE_AUTH[a.val]; else if (a.type === 4) vn = IKE_GRP[a.val]; else if (a.type === 11) vn = a.val === 1 ? 'Seconds' : 'Kilobytes'; }
  else { if (a.type === 1) vn = a.val === 1 ? 'Seconds' : 'Kilobytes'; else if (a.type === 4) vn = ({ 1: 'Tunnel', 2: 'Transport' })[a.val]; else if (a.type === 5) vn = AUTH_ID[a.val]; else if (a.type === 3) vn = IKE_GRP[a.val]; }
  return N((a.tv ? 'Attribute Type: (t=' + a.type + ',l=2) ' : 'Attribute Type: (t=' + a.type + ',l=' + (a.len - 4) + ') ') + a.name + ': ' + (vn ? vn + ' (' + a.val + ')' : a.val), a.off, a.len);
}
function parseIsakmp(u, o, end, detail, nodes) {
  if (end - o < 28) return null; const h = { ic: hex2str(u, o, 8).replace(/:/g, ''), rc: hex2str(u, o + 8, 8).replace(/:/g, ''), next: u[o + 16], ver: u[o + 17], exch: u[o + 18], flags: u[o + 19], mid: u32(u, o + 20), len: u32(u, o + 24), payloads: [] };
  if ((h.ver >> 4) !== 1) return null; const enc = !!(h.flags & 1); const fend = Math.min(end, o + h.len);
  let t = h.next, q = o + 28; const pnodes = [];
  if (!enc) {
    while (t !== 0 && q + 4 <= fend) {
      const nx = u[q], pl = u16(u, q + 2); if (pl < 4 || q + pl > fend) break; const pd = { type: t, len: pl, off: q }; const ch = [N('Next payload: ' + (PLT[nx] || nx) + ' (' + nx + ')', q, 1), N('Payload length: ' + pl, q + 2, 2)];
      if (t === 1 && pl >= 12) {
        pd.doi = u32(u, q + 4); pd.props = []; ch.push(N('Domain of interpretation: ' + (pd.doi === 1 ? 'IPSEC' : pd.doi) + ' (' + pd.doi + ')', q + 4, 4), N('Situation: 0x' + hex(u32(u, q + 8), 8) + ' (Identity Only)', q + 8, 4));
        let pq = q + 12; const pend = q + pl;
        while (pq + 8 <= pend) {
          const pnx = u[pq], ppl = u16(u, pq + 2); if (ppl < 8 || pq + ppl > pend) break; const num = u[pq + 4], proto = u[pq + 5], sl = u[pq + 6], nt = u[pq + 7]; const spi = u.slice(pq + 8, pq + 8 + sl); const pr = { num, proto, spi, transforms: [] };
          const tch = []; let tq = pq + 8 + sl;
          for (let k = 0; k < nt && tq + 8 <= pq + ppl; k++) {
            const tnx = u[tq], tl = u16(u, tq + 2); if (tl < 8) break; const tr = { num: u[tq + 4], id: u[tq + 5], attrs: parseAttrs(u, tq + 8, tq + tl, proto === 1 ? IKE_ATTR : IPSEC_ATTR) }; pr.transforms.push(tr);
            tch.push(N('Payload: Transform (3) # ' + tr.num, tq, tl, [N('Next payload: ' + (tnx ? 'Transform (3)' : 'NONE') + ' (' + tnx + ')', tq, 1), N('Payload length: ' + tl, tq + 2, 2), N('Transform number: ' + tr.num, tq + 4, 1), N('Transform ID: ' + (proto === 1 ? 'KEY_IKE' : (ESP_ID[tr.id] || tr.id)) + ' (' + tr.id + ')', tq + 5, 1)].concat(tr.attrs.map(a => attrNode(a, proto === 1)))));
            tq += tl;
          }
          pd.props.push(pr);
          ch.push(N('Payload: Proposal (2) # ' + num, pq, ppl, [N('Next payload: ' + (pnx ? 'Proposal (2)' : 'NONE') + ' (' + pnx + ')', pq, 1), N('Payload length: ' + ppl, pq + 2, 2), N('Proposal number: ' + num, pq + 4, 1), N('Protocol ID: ' + (proto === 1 ? 'ISAKMP' : proto === 3 ? 'IPSEC_ESP' : proto) + ' (' + proto + ')', pq + 5, 1), N('SPI Size: ' + sl, pq + 6, 1), N('Proposal transforms: ' + nt, pq + 7, 1)].concat(sl ? [N('SPI: ' + hex2str(u, pq + 8, sl).replace(/:/g, ''), pq + 8, sl)] : [], tch)));
          pq += ppl;
        }
      } else if (t === 4) { pd.ke = u.slice(q + 4, q + pl); ch.push(N('Key Exchange Data (' + (pl - 4) + ' bytes)', q + 4, pl - 4)); }
      else if (t === 10) { pd.nonce = u.slice(q + 4, q + pl); ch.push(N('Nonce DATA (' + (pl - 4) + ' bytes)', q + 4, pl - 4)); }
      else if (t === 5 && pl >= 8) { pd.idType = u[q + 4]; pd.idData = u.slice(q + 8, q + pl); const nm = { 1: 'IPV4_ADDR', 4: 'IPV4_ADDR_SUBNET', 11: 'KEY_ID' }[pd.idType] || pd.idType; let idv = ''; if (pd.idType === 1 && pl >= 12) idv = IP.str(u32(u, q + 8)); else if (pd.idType === 4 && pl >= 16) idv = IP.str(u32(u, q + 8)) + '/' + IP.str(u32(u, q + 12)); ch.push(N('ID type: ' + nm + ' (' + pd.idType + ')', q + 4, 1), N('ID data: ' + idv, q + 8, pl - 8)); pd.idStr = idv; }
      else if (t === 8) { pd.hash = u.slice(q + 4, q + pl); ch.push(N('Hash DATA (' + (pl - 4) + ' bytes)', q + 4, pl - 4)); }
      else if (t === 11 && pl >= 12) { pd.notify = u16(u, q + 10); const sl = u[q + 9]; ch.push(N('Domain of interpretation: IPSEC (1)', q + 4, 4), N('Protocol ID: ' + u[q + 8], q + 8, 1), N('SPI Size: ' + sl, q + 9, 1), N('Notify Message Type: ' + (NOTIF[pd.notify] || pd.notify) + ' (' + pd.notify + ')', q + 10, 2)); }
      else if (t === 13) { pd.vid = u.slice(q + 4, q + pl); ch.push(N('Vendor ID: ' + hex2str(u, q + 4, Math.min(pl - 4, 20)).replace(/:/g, ''), q + 4, pl - 4)); }
      h.payloads.push(pd);
      pnodes.push(N('Payload: ' + (PLT[t] || t) + ' (' + t + ')' + (t === 1 ? '' : ''), q, pl, ch));
      t = nx; q += pl;
    }
  } else if (fend - q > 0) pnodes.push(N('Encrypted Data (' + (fend - q) + ' bytes)', q, fend - q));
  if (detail) {
    const ch = [N('Initiator SPI: ' + h.ic, o, 8), N('Responder SPI: ' + h.rc, o + 8, 8), N('Next payload: ' + (PLT[h.next] || h.next) + ' (' + h.next + ')', o + 16, 1), N('Version: ' + (h.ver >> 4) + '.' + (h.ver & 15), o + 17, 1), N('Exchange type: ' + (EXCH[h.exch] || h.exch) + ' (' + h.exch + ')', o + 18, 1),
      N('Flags: 0x' + hex(h.flags, 2), o + 19, 1, [N('.... ...' + (h.flags & 1) + ' = Encryption: ' + (enc ? 'Encrypted' : 'Not encrypted'), o + 19, 1), N('.... ..' + ((h.flags >> 1) & 1) + '. = Commit: ' + ((h.flags >> 1) & 1 ? 'Commit' : 'No commit'), o + 19, 1), N('.... .' + ((h.flags >> 2) & 1) + '.. = Authentication: ' + ((h.flags >> 2) & 1 ? 'Authentication only' : 'Not authentication'), o + 19, 1)]), N('Message ID: 0x' + hex(h.mid, 8), o + 20, 4), N('Length: ' + h.len, o + 24, 4)].concat(pnodes);
    const n = N('Internet Security Association and Key Management Protocol', o, fend - o, ch); n.layer = 'isakmp'; nodes.push(n);
  }
  return h;
}
Codec.ikeSummary = function (h) {
  const pl = h.payloads.map(p => ({ 1: 'SA', 4: 'KE', 5: 'ID', 8: 'HASH', 10: 'NONCE', 11: 'NOTIFY', 13: 'VID', 12: 'DELETE' }[p.type] || p.type));
  return (EXCH[h.exch] || 'ISAKMP') + (h.flags & 1 ? '' : '') + (pl.length ? ' : ' + pl.join(', ') : ' (encrypted)') + (h.payloads.find(p => p.notify) ? ' — ' + (NOTIF[h.payloads.find(p => p.notify).notify] || '') : '');
};
Codec.udpApps.push((p, u, o, end, detail) => {
  const { sport, dport } = p.udp; if (sport !== 500 && dport !== 500) return false;
  const nodes = []; const h = parseIsakmp(u, o, end, detail, nodes); if (!h) return false; p.isakmp = h; if (detail) nodes.forEach(n => p.tree.push(n)); return true;
});
})(typeof window !== 'undefined' ? window : globalThis);
