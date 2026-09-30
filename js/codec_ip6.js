/* codec_ip6.js — IPv6 : adresses (BigInt), en-tête, ICMPv6 et NDP (encodage / décodage / arbre analyseur) */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { MAC, Codec } = NS; const { N, hex, u16, u32, hex2str } = Codec._h;

/* ------------------------------------------------------------------ adresses */
const IP6 = {};
const B0 = 0n, ONE = 1n, ALL = (1n << 128n) - 1n;
IP6.parse = function (s) {
  s = String(s).trim().replace(/%.*$/, ''); if (!s || /[^0-9a-fA-F:.]/.test(s)) return null;
  let v4 = null; const m4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s); if (m4) { const o = m4[2].split('.').map(Number); if (o.some(x => x > 255)) return null; v4 = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]]; s = m4[1] + '0:0'; }
  const dc = s.indexOf('::'); if (dc !== s.lastIndexOf('::')) return null;
  let head, tail;
  if (dc >= 0) { head = s.slice(0, dc) ? s.slice(0, dc).split(':') : []; tail = s.slice(dc + 2) ? s.slice(dc + 2).split(':') : []; } else { head = s.split(':'); tail = []; }
  if (head.concat(tail).some(x => !/^[0-9a-fA-F]{1,4}$/.test(x))) return null;
  let groups;
  if (dc >= 0) { const fill = 8 - head.length - tail.length; if (fill < 1) return null; groups = head.concat(new Array(fill).fill('0'), tail); } else { if (head.length !== 8) return null; groups = head; }
  if (v4) { groups[6] = v4[0].toString(16); groups[7] = v4[1].toString(16); }
  let x = B0; groups.forEach(gp => { x = (x << 16n) | BigInt(parseInt(gp, 16)); }); return x;
};
IP6.groups = x => { const r = []; for (let i = 7; i >= 0; i--) r.push(Number((x >> BigInt(i * 16)) & 0xffffn)); return r; };
IP6.str = function (x) {
  const gr = IP6.groups(x); let bs = -1, bl = 0;
  for (let i = 0; i < 8;) { if (gr[i] === 0) { let j = i; while (j < 8 && gr[j] === 0) j++; if (j - i > bl && j - i >= 2) { bs = i; bl = j - i; } i = j; } else i++; }
  const h = gr.map(v => v.toString(16));
  if (bs < 0) return h.join(':');
  return h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
};
IP6.strUp = x => IP6.str(x).toUpperCase();
IP6.full = x => IP6.groups(x).map(v => v.toString(16).padStart(4, '0')).join(':');
IP6.toBytes = x => { const u = new Uint8Array(16); for (let i = 15; i >= 0; i--) { u[i] = Number(x & 0xffn); x >>= 8n; } return u; };
IP6.fromBytes = (u, o) => { let x = B0; for (let i = 0; i < 16; i++) x = (x << 8n) | BigInt(u[o + i]); return x; };
IP6.mask = plen => plen <= 0 ? B0 : (ALL << BigInt(128 - plen)) & ALL;
IP6.net = (x, plen) => x & IP6.mask(plen);
IP6.inNet = (x, net, plen) => (x & IP6.mask(plen)) === (net & IP6.mask(plen));
IP6.parseCidr = s => { const m = /^([^\/]+)\/(\d{1,3})$/.exec(String(s).trim()); if (!m) return null; const a = IP6.parse(m[1]); const p = +m[2]; if (a === null || p > 128) return null; return { addr: a, plen: p }; };
IP6.isMulticast = x => (x >> 120n) === 0xffn;
IP6.isLinkLocal = x => (x >> 118n) === 0x3fan;
IP6.isLoopback = x => x === ONE;
IP6.isUnspecified = x => x === B0;
IP6.isUla = x => (x >> 121n) === 0x7en;
IP6.isGlobal = x => (x >> 125n) === 1n;
IP6.mcScope = x => Number((x >> 112n) & 0xfn);
IP6.kind = x => IP6.isUnspecified(x) ? 'unspecified' : IP6.isLoopback(x) ? 'loopback' : IP6.isMulticast(x) ? 'multicast' : IP6.isLinkLocal(x) ? 'link-local' : IP6.isUla(x) ? 'ULA' : IP6.isGlobal(x) ? 'global' : 'autre';
IP6.eui64 = mac => { const b = mac.split(':').map(h => parseInt(h, 16)); b[0] ^= 2; const e = [b[0], b[1], b[2], 0xff, 0xfe, b[3], b[4], b[5]]; let x = B0; e.forEach(v => { x = (x << 8n) | BigInt(v); }); return x; };
IP6.linkLocal = mac => (0xfe80n << 112n) | IP6.eui64(mac);
IP6.withIid = (prefix, mac) => (prefix & IP6.mask(64)) | IP6.eui64(mac);
IP6.ALL_NODES = IP6.parse('ff02::1'); IP6.ALL_ROUTERS = IP6.parse('ff02::2');
IP6.solicited = x => (0xff02n << 112n) | (1n << 32n) | (0xffn << 24n) | (x & 0xffffffn);
IP6.multicastMac = x => { const u = IP6.toBytes(x); return '33:33:' + [12, 13, 14, 15].map(i => hex(u[i], 2)).join(':'); };
IP6.isSolicitedNode = x => (x >> 24n) === ((0xff02n << 88n) | (1n << 8n) | 0xffn);
IP6.expandName = { 'ff02::1': 'All nodes', 'ff02::2': 'All routers' };
IP6.scopeName = x => ({ 'link-local': 'Link-local', ULA: 'Unique local (ULA)', global: 'Global unicast', loopback: 'Loopback', multicast: 'Multicast', unspecified: 'Non spécifiée' }[IP6.kind(x)] || '');
NS.IP6 = IP6;
Codec.ETHERTYPES[0x86dd] = 'IPv6';

/* ------------------------------------------------------------------ encodage */
const Wr = Codec._h.Writer;
function sum16(u, o, len, init) { let s = init || 0; for (let i = 0; i + 1 < len; i += 2) s += (u[o + i] << 8) | u[o + i + 1]; if (len & 1) s += u[o + len - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16); return s; }
function pseudo6(src, dst, next, len) { const b = new Uint8Array(40); b.set(IP6.toBytes(src), 0); b.set(IP6.toBytes(dst), 16); b[32] = (len >>> 24) & 255; b[33] = (len >>> 16) & 255; b[34] = (len >>> 8) & 255; b[35] = len & 255; b[39] = next; return sum16(b, 0, 40, 0); }
Codec.ip6Packet = function (h, payload) {
  const u = new Uint8Array(40 + payload.length);
  u[0] = 0x60 | ((h.tc || 0) >> 4); u[1] = (((h.tc || 0) & 15) << 4) | (((h.flow || 0) >> 16) & 15); u[2] = ((h.flow || 0) >> 8) & 255; u[3] = (h.flow || 0) & 255;
  u[4] = payload.length >> 8; u[5] = payload.length & 255; u[6] = h.next; u[7] = h.hop === undefined ? 64 : h.hop;
  u.set(IP6.toBytes(h.src), 8); u.set(IP6.toBytes(h.dst), 24); u.set(payload, 40); return u;
};
/* ICMPv6 : type, code, corps (après les 4 octets type/code/checksum) */
Codec.icmp6 = function (src, dst, type, code, body) {
  const u = new Uint8Array(4 + body.length); u[0] = type; u[1] = code || 0; u.set(body, 4);
  let c = sum16(u, 0, u.length, pseudo6(src, dst, 58, u.length)); c = (~c) & 0xffff; u[2] = c >> 8; u[3] = c & 255; return u;
};
Codec.ndOpts = function (opts) {
  const parts = [];
  (opts || []).forEach(o => {
    let b;
    if (o.t === 1 || o.t === 2) { b = new Uint8Array(8); b[0] = o.t; b[1] = 1; MAC.toBytes ? b.set(MAC.toBytes(o.mac), 2) : b.set(o.mac.split(':').map(h => parseInt(h, 16)), 2); }
    else if (o.t === 3) { b = new Uint8Array(32); b[0] = 3; b[1] = 4; b[2] = o.plen; b[3] = (o.l ? 0x80 : 0) | (o.a ? 0x40 : 0); b[4] = (o.vl >>> 24) & 255; b[5] = (o.vl >>> 16) & 255; b[6] = (o.vl >>> 8) & 255; b[7] = o.vl & 255; b[8] = (o.pl >>> 24) & 255; b[9] = (o.pl >>> 16) & 255; b[10] = (o.pl >>> 8) & 255; b[11] = o.pl & 255; b.set(IP6.toBytes(o.prefix), 16); }
    else if (o.t === 5) { b = new Uint8Array(8); b[0] = 5; b[1] = 1; b[4] = (o.mtu >>> 24) & 255; b[5] = (o.mtu >>> 16) & 255; b[6] = (o.mtu >>> 8) & 255; b[7] = o.mtu & 255; }
    else if (o.t === 25) { const n = o.addrs.length; b = new Uint8Array(8 + 16 * n); b[0] = 25; b[1] = 1 + 2 * n; b[4] = (o.life >>> 24) & 255; b[5] = (o.life >>> 16) & 255; b[6] = (o.life >>> 8) & 255; b[7] = o.life & 255; o.addrs.forEach((a, i) => b.set(IP6.toBytes(a), 8 + 16 * i)); }
    if (b) parts.push(b);
  });
  return Codec._h.concat ? parts.reduce((a, b) => { const r = new Uint8Array(a.length + b.length); r.set(a, 0); r.set(b, a.length); return r; }, new Uint8Array(0)) : parts;
};
const cat = (...a) => { let n = 0; a.forEach(x => n += x.length); const r = new Uint8Array(n); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };
Codec.nsBody = (target, opts) => cat(new Uint8Array(4), IP6.toBytes(target), Codec.ndOpts(opts));
Codec.naBody = (flags, target, opts) => { const h = new Uint8Array(4); h[0] = (flags.r ? 0x80 : 0) | (flags.s ? 0x40 : 0) | (flags.o ? 0x20 : 0); return cat(h, IP6.toBytes(target), Codec.ndOpts(opts)); };
Codec.rsBody = opts => cat(new Uint8Array(4), Codec.ndOpts(opts));
Codec.raBody = r => { const h = new Uint8Array(12); h[0] = r.hop || 0; h[1] = (r.m ? 0x80 : 0) | (r.o ? 0x40 : 0); h[2] = (r.life >> 8) & 255; h[3] = r.life & 255; const rt = r.reach || 0, tr = r.retrans || 0; h[4] = (rt >>> 24) & 255; h[5] = (rt >>> 16) & 255; h[6] = (rt >>> 8) & 255; h[7] = rt & 255; h[8] = (tr >>> 24) & 255; h[9] = (tr >>> 16) & 255; h[10] = (tr >>> 8) & 255; h[11] = tr & 255; return cat(h, Codec.ndOpts(r.opts)); };
Codec.echo6Body = (id, seq, payload) => { const h = new Uint8Array(4); h[0] = id >> 8; h[1] = id & 255; h[2] = seq >> 8; h[3] = seq & 255; return cat(h, payload || new Uint8Array(0)); };
/* erreurs : Destination unreachable / Time exceeded / Packet too big : 4 octets + début du paquet fautif */
Codec.err6Body = (invoking, mtu) => { const h = new Uint8Array(4); if (mtu) { h[0] = (mtu >>> 24) & 255; h[1] = (mtu >>> 16) & 255; h[2] = (mtu >>> 8) & 255; h[3] = mtu & 255; } return cat(h, invoking.subarray(0, Math.min(invoking.length, 1232))); };

/* ------------------------------------------------------------------ décodage */
const ICMP6 = { 1: 'Destination Unreachable', 2: 'Packet Too Big', 3: 'Time Exceeded', 4: 'Parameter Problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router Solicitation', 134: 'Router Advertisement', 135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement', 137: 'Redirect Message' };
const UNREACH6 = { 0: 'No route to destination', 1: 'Communication with destination administratively prohibited', 3: 'Address unreachable', 4: 'Port unreachable' };
Codec.ICMP6_NAMES = ICMP6; Codec.UNREACH6 = UNREACH6;
const NH = { 0: 'IPv6 Hop-by-Hop Option', 6: 'TCP', 17: 'UDP', 43: 'Routing Header for IPv6', 44: 'Fragment Header for IPv6', 50: 'Encapsulating Security Payload', 51: 'Authentication Header', 58: 'ICMPv6', 59: 'No Next Header', 60: 'Destination Options for IPv6', 89: 'OSPF IGP' };
function parseOpts(u, o, end) {
  const r = [];
  while (o + 2 <= end) {
    const t = u[o], l = u[o + 1] * 8; if (l === 0 || o + l > end) break; const op = { t, len: l, off: o };
    if (t === 1 || t === 2) op.mac = MAC.fromBytes(u, o + 2);
    else if (t === 3 && l >= 32) { op.plen = u[o + 2]; op.l = !!(u[o + 3] & 0x80); op.a = !!(u[o + 3] & 0x40); op.vl = u32(u, o + 4); op.pl = u32(u, o + 8); op.prefix = IP6.fromBytes(u, o + 16); }
    else if (t === 5 && l >= 8) op.mtu = u32(u, o + 4);
    else if (t === 25 && l >= 24) { op.life = u32(u, o + 4); op.addrs = []; for (let k = o + 8; k + 16 <= o + l; k += 16) op.addrs.push(IP6.fromBytes(u, k)); }
    r.push(op); o += l;
  }
  return r;
}
const OPTN = { 1: 'ICMPv6 Option (Source link-layer address', 2: 'ICMPv6 Option (Target link-layer address', 3: 'ICMPv6 Option (Prefix information', 5: 'ICMPv6 Option (MTU', 25: 'ICMPv6 Option (Recursive DNS Server' };
function optNode(op) {
  const nm = OPTN[op.t] || 'ICMPv6 Option (Type ' + op.t;
  const ch = [N('Type: ' + ({ 1: 'Source link-layer address', 2: 'Target link-layer address', 3: 'Prefix information', 5: 'MTU', 25: 'Recursive DNS Server' }[op.t] || op.t) + ' (' + op.t + ')', op.off, 1), N('Length: ' + op.len / 8 + ' (' + op.len + ' bytes)', op.off + 1, 1)];
  let sfx = ')';
  if (op.t === 1 || op.t === 2) { ch.push(N('Link-layer address: ' + Codec.macLabel(op.mac) + ' (' + op.mac + ')', op.off + 2, 6)); sfx = ' : ' + op.mac + ')'; }
  else if (op.t === 3) { ch.push(N('Prefix Length: ' + op.plen, op.off + 2, 1), N('Flag: 0x' + hex((op.l ? 0x80 : 0) | (op.a ? 0x40 : 0), 2) + (op.l ? ', On-link flag(L)' : '') + (op.a ? ', Autonomous address-configuration flag(A)' : ''), op.off + 3, 1), N('Valid Lifetime: ' + op.vl + ' (' + Math.round(op.vl / 3600) + ' hours)', op.off + 4, 4), N('Preferred Lifetime: ' + op.pl, op.off + 8, 4), N('Prefix: ' + IP6.str(op.prefix), op.off + 16, 16)); sfx = ' : ' + IP6.str(op.prefix) + '/' + op.plen + ')'; }
  else if (op.t === 5) { ch.push(N('MTU: ' + op.mtu, op.off + 4, 4)); sfx = ' : ' + op.mtu + ')'; }
  else if (op.t === 25) { ch.push(N('Lifetime: ' + op.life, op.off + 4, 4)); op.addrs.forEach((a, i) => ch.push(N('Recursive DNS Server: ' + IP6.str(a), op.off + 8 + 16 * i, 16))); sfx = ' : ' + op.addrs.map(IP6.str).join(', ') + ')'; }
  return N(nm + sfx, op.off, op.len, ch);
}
Codec.ethApps[0x86dd] = function (p, u, off, end, detail) {
  if (end - off < 40) { p.bad = 'Paquet IPv6 tronqué'; return; }
  const ver = u[off] >> 4; if (ver !== 6) { p.bad = 'Version IPv6 invalide (' + ver + ')'; return; }
  const plen = u16(u, off + 4); const send = Math.min(end, off + 40 + plen);
  const h = { ver, tc: ((u[off] & 15) << 4) | (u[off + 1] >> 4), flow: ((u[off + 1] & 15) << 16) | u16(u, off + 2), plen, next: u[off + 6], hop: u[off + 7], src: IP6.fromBytes(u, off + 8), dst: IP6.fromBytes(u, off + 24), off, total: 40 + plen };
  p.ip6 = h; const po = off + 40;
  let n6 = null;
  if (detail) {
    n6 = N('Internet Protocol Version 6, Src: ' + IP6.str(h.src) + ', Dst: ' + IP6.str(h.dst), off, 40, [
      N('0110 .... = Version: 6', off, 1), N('.... ' + (h.tc >> 4).toString(2).padStart(4, '0') + ' ' + (h.tc & 15).toString(2).padStart(4, '0') + ' .... .... .... .... .... = Traffic Class: 0x' + hex(h.tc, 2) + ' (DSCP: ' + (h.tc >> 2) + ', ECN: ' + (h.tc & 3) + ')', off, 2),
      N('.... .... .... ' + h.flow.toString(2).padStart(20, '0').replace(/(.{4})(?!$)/g, '$1 ') + ' = Flow Label: 0x' + hex(h.flow, 5), off + 1, 3), N('Payload Length: ' + plen, off + 4, 2), N('Next Header: ' + (NH[h.next] || h.next) + ' (' + h.next + ')', off + 6, 1), N('Hop Limit: ' + h.hop, off + 7, 1),
      N('Source Address: ' + IP6.str(h.src), off + 8, 16), N('Destination Address: ' + IP6.str(h.dst), off + 24, 16)]);
    n6.layer = 'ip6'; p.tree.push(n6);
  }
  if (h.next !== 58) return;
  if (send - po < 4) return;
  const ty = u[po], code = u[po + 1]; const cs = u16(u, po + 2);
  const chk = sum16(u, po, send - po, pseudo6(h.src, h.dst, 58, send - po)); const c = { type: ty, code, csum: cs, csumOk: chk === 0xffff, len: send - po };
  p.icmp6 = c; const bo = po + 4; const ch = [];
  if (ty === 128 || ty === 129) { c.id = u16(u, bo); c.seq = u16(u, bo + 2); c.payload = u.slice(bo + 4, send); ch.push(N('Identifier: 0x' + hex(c.id, 4), bo, 2), N('Sequence: ' + c.seq, bo + 2, 2), N('Data (' + c.payload.length + ' bytes)', bo + 4, c.payload.length)); }
  else if (ty === 135 || ty === 136) {
    if (send - bo < 20) return; c.target = IP6.fromBytes(u, bo + 4); c.opts = parseOpts(u, bo + 20, send);
    if (ty === 136) { const f = u[bo]; c.r = !!(f & 0x80); c.s = !!(f & 0x40); c.o = !!(f & 0x20); ch.push(N('Flags: 0x' + hex(f, 2) + '000000' + (c.r ? ', Router' : '') + (c.s ? ', Solicited' : '') + (c.o ? ', Override' : ''), bo, 4, [N((c.r ? '1' : '0') + '... .... .... .... .... .... .... .... = Router: ' + (c.r ? 'Set' : 'Not set'), bo, 4), N('.' + (c.s ? '1' : '0') + '.. .... .... .... .... .... .... .... = Solicited: ' + (c.s ? 'Set' : 'Not set'), bo, 4), N('..' + (c.o ? '1' : '0') + '. .... .... .... .... .... .... .... = Override: ' + (c.o ? 'Set' : 'Not set'), bo, 4)])); }
    else ch.push(N('Reserved: 00000000', bo, 4));
    ch.push(N('Target Address: ' + IP6.str(c.target), bo + 4, 16)); c.opts.forEach(op => ch.push(optNode(op)));
  } else if (ty === 133) { c.opts = parseOpts(u, bo + 4, send); ch.push(N('Reserved: 00000000', bo, 4)); c.opts.forEach(op => ch.push(optNode(op))); }
  else if (ty === 134) {
    if (send - bo < 12) return; const f = u[bo + 1]; Object.assign(c, { hop: u[bo], m: !!(f & 0x80), o: !!(f & 0x40), life: u16(u, bo + 2), reach: u32(u, bo + 4), retrans: u32(u, bo + 8), opts: parseOpts(u, bo + 12, send) });
    ch.push(N('Cur hop limit: ' + c.hop, bo, 1), N('Flags: 0x' + hex(f, 2) + (c.m ? ', Managed address configuration' : ', Managed: No') + (c.o ? ', Other configuration' : ', Other: No'), bo + 1, 1, [N((c.m ? '1' : '0') + '... .... = Managed address configuration: ' + (c.m ? 'Set' : 'Not set'), bo + 1, 1), N('.' + (c.o ? '1' : '0') + '.. .... = Other configuration: ' + (c.o ? 'Set' : 'Not set'), bo + 1, 1)]), N('Router lifetime (s): ' + c.life, bo + 2, 2), N('Reachable time (ms): ' + c.reach, bo + 4, 4), N('Retrans timer (ms): ' + c.retrans, bo + 8, 4)); c.opts.forEach(op => ch.push(optNode(op)));
  } else if (ty === 1 || ty === 3 || ty === 2 || ty === 4) {
    const qo = bo + 4; c.rest = u32(u, bo); if (ty === 2) c.mtu = c.rest; if (send - qo >= 40 && (u[qo] >> 4) === 6) { c.quote = { src: IP6.fromBytes(u, qo + 8), dst: IP6.fromBytes(u, qo + 24), next: u[qo + 6] }; if (c.quote.next === 58 && send - qo >= 48 && u[qo + 40] === 128) { c.quote.icmpType = 128; c.quote.id = u16(u, qo + 44); c.quote.seq = u16(u, qo + 46); } }
    ch.push(ty === 2 ? N('MTU: ' + c.mtu, bo, 4) : N('Unused: 00000000', bo, 4)); if (c.quote) ch.push(N('Internet Protocol Version 6, Src: ' + IP6.str(c.quote.src) + ', Dst: ' + IP6.str(c.quote.dst), qo, 40));
  }
  if (detail) {
    const tn = ICMP6[ty] || 'type ' + ty; const cn = ty === 1 ? (UNREACH6[code] || 'code ' + code) : (code + '');
    const n = N('Internet Control Message Protocol v6', po, send - po, [N('Type: ' + tn + ' (' + ty + ')', po, 1), N('Code: ' + (ty === 1 ? cn + ' (' + code + ')' : code), po + 1, 1), N('Checksum: 0x' + hex(cs, 4) + ' [' + (c.csumOk ? 'correct' : 'incorrect') + ']', po + 2, 2)].concat(ch));
    n.layer = 'icmp6'; p.tree.push(n);
  }
};
})(typeof window !== 'undefined' ? window : globalThis);
