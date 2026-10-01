/* codec.js — encodage/décodage de VRAIES trames (octets) : Ethernet, 802.1Q, ARP, IPv4, ICMP, TCP, UDP,
   DHCP, DNS, HTTP, STP, RIPv2, OSPFv2, TLS (enregistrements), SSH (bannière), Telnet.
   parse(u8, true) produit aussi l'arbre de champs (avec décalages) pour l'analyseur de trames. */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Writer, B } = NS;
const { u16, u32, checksum, concat, bytesStr, strBytes, hex } = B;

const Codec = {};
const ETHERTYPES = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x8100: '802.1Q Virtual LAN', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x8809: 'Slow Protocols', 0x888e: '802.1X Authentication' };
const IPPROTOS = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 89: 'OSPF', 50: 'ESP', 47: 'GRE' };
const PORTNAMES = { 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 67: 'bootps', 68: 'bootpc', 80: 'http', 110: 'pop3',
  123: 'ntp', 143: 'imap', 161: 'snmp', 162: 'snmp-trap', 443: 'https', 445: 'microsoft-ds', 514: 'syslog', 520: 'rip', 993: 'imaps', 3306: 'mysql', 3389: 'ms-wbt-server', 8080: 'http-alt', 5060: 'sip', 1194: 'openvpn', 500: 'isakmp', 4500: 'ipsec-nat-t' };
Codec.udpApps = []; Codec.ipApps = {}; Codec.ethApps = {};
Codec.ETHERTYPES = ETHERTYPES; Codec.IPPROTOS = IPPROTOS; Codec.PORTNAMES = PORTNAMES;
Codec.portName = p => PORTNAMES[p] ? PORTNAMES[p] + ' (' + p + ')' : String(p);
Codec.macLabel = function (m) {
  if (m === 'ff:ff:ff:ff:ff:ff') return 'Broadcast';
  const oui = m.slice(0, 8);
  const v = NS.OUI_NAMES && NS.OUI_NAMES[oui];
  if (v) return v + '_' + m.slice(9);
  if (m.startsWith('01:00:5e')) return 'IPv4mcast_' + m.slice(9);
  if (m === '01:80:c2:00:00:00') return 'Spanning-tree-(for-bridges)_00';
  return m;
};

/* ------------------------------------------------------------------ ENCODEURS */
Codec.frame = function ({ dst, src, vlan, type, payload }) {
  const w = new Writer();
  w.mac(dst).mac(src);
  if (vlan !== undefined && vlan !== null) { w.u16(0x8100).u16((((vlan.pcp || 0) & 7) << 13) | (vlan.vid & 0xfff)); }
  w.u16(type).bytes(payload);
  while (w.length < 60) w.u8(0);
  return w.toU8();
};
/* Trame 802.3 + LLC (STP) */
Codec.frame8023 = function ({ dst, src, payload, dsap, ssap }) {
  const w = new Writer();
  w.mac(dst).mac(src).u16(payload.length + 3).u8(dsap || 0x42).u8(ssap || 0x42).u8(3).bytes(payload);
  while (w.length < 60) w.u8(0);
  return w.toU8();
};
Codec.arp = function (a) {
  return new Writer().u16(1).u16(0x0800).u8(6).u8(4).u16(a.op).mac(a.sha).ip(a.spa).mac(a.tha).ip(a.tpa).toU8();
};
Codec.ipPacket = function (ip, l4) {
  const w = new Writer();
  w.u8(0x45).u8(ip.tos || 0).u16(20 + l4.length).u16(ip.id || 0).u16((ip.df ? 0x4000 : 0)).u8(ip.ttl).u8(ip.proto).u16(0).ip(ip.src).ip(ip.dst);
  const h = w.toU8();
  const c = checksum(h, 0, 20); h[10] = c >> 8; h[11] = c & 255;
  return concat(h, l4);
};
Codec.icmp = function (i) {
  const w = new Writer();
  w.u8(i.type).u8(i.code || 0).u16(0);
  if (i.type === 8 || i.type === 0) w.u16(i.id || 0).u16(i.seq || 0); else w.u32(i.rest || 0);
  w.bytes(i.payload || []);
  const u = w.toU8(); const c = checksum(u, 0, u.length); u[2] = c >> 8; u[3] = c & 255; return u;
};
function pseudo(src, dst, proto, len) { return ((src >>> 16) + (src & 0xffff) + (dst >>> 16) + (dst & 0xffff) + proto + len); }
Codec.udp = function (src, dst, sport, dport, payload) {
  const len = 8 + payload.length;
  const w = new Writer().u16(sport).u16(dport).u16(len).u16(0).bytes(payload);
  const u = w.toU8(); let c = checksum(u, 0, u.length, pseudo(src, dst, 17, len)); if (c === 0) c = 0xffff;
  u[6] = c >> 8; u[7] = c & 255; return u;
};
Codec.tcp = function (src, dst, t) {
  const opt = t.mss ? [2, 4, t.mss >> 8, t.mss & 255] : [];
  const hl = 20 + opt.length;
  const w = new Writer().u16(t.sport).u16(t.dport).u32(t.seq >>> 0).u32(t.ack >>> 0).u8((hl / 4) << 4).u8(t.flags & 0x3f).u16(t.win === undefined ? 64240 : t.win).u16(0).u16(0).bytes(opt).bytes(t.payload || []);
  const u = w.toU8(); const c = checksum(u, 0, u.length, pseudo(src, dst, 6, u.length)); u[16] = c >> 8; u[17] = c & 255; return u;
};
/* Réencode la couche 4 d'un paquet analysé avec de nouvelles adresses (NAT, TTL…) -> octets IP complets */
Codec.rebuildIp = function (p, ch) {
  const ip = Object.assign({}, p.ip, ch.ip || {});
  let l4;
  if (p.tcp) { const t = Object.assign({}, p.tcp, ch.l4 || {}); l4 = Codec.tcp(ip.src, ip.dst, t); }
  else if (p.udp) { const t = Object.assign({}, p.udp, ch.l4 || {}); l4 = Codec.udp(ip.src, ip.dst, t.sport, t.dport, t.payload); }
  else if (p.icmp) { const t = Object.assign({}, p.icmp, ch.l4 || {}); l4 = Codec.icmp(t); }
  else l4 = p.ipPayload;
  return Codec.ipPacket(ip, l4);
};

/* --- DHCP --- */
const DHCP_TYPES = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
Codec.DHCP_TYPES = DHCP_TYPES;
Codec.dhcp = function (d) {
  const w = new Writer();
  w.u8(d.op).u8(1).u8(6).u8(d.hops || 0).u32(d.xid).u16(d.secs || 0).u16(d.flags || 0).ip(d.ciaddr || 0).ip(d.yiaddr || 0).ip(d.siaddr || 0).ip(d.giaddr || 0);
  w.mac(d.chaddr).zeros(10).zeros(64).zeros(128).u8(0x63).u8(0x82).u8(0x53).u8(0x63);
  const o = d.opts || {};
  const opt = (c, b) => { w.u8(c).u8(b.length).bytes(b); };
  const ipb = v => new Writer().ip(v).toU8();
  if (o.msgType) opt(53, [o.msgType]);
  if (o.clientId) opt(61, [1].concat(MAC.toBytes(o.clientId)));
  if (o.requested !== undefined) opt(50, ipb(o.requested));
  if (o.serverId !== undefined) opt(54, ipb(o.serverId));
  if (o.hostname) opt(12, strBytes(o.hostname));
  if (o.lease !== undefined) opt(51, new Writer().u32(o.lease).toU8());
  if (o.renewal !== undefined) opt(58, new Writer().u32(o.renewal).toU8());
  if (o.rebinding !== undefined) opt(59, new Writer().u32(o.rebinding).toU8());
  if (o.mask !== undefined) opt(1, ipb(o.mask));
  if (o.routers && o.routers.length) opt(3, o.routers.reduce((a, r) => a.concat(Array.from(ipb(r))), []));
  if (o.dns && o.dns.length) opt(6, o.dns.reduce((a, r) => a.concat(Array.from(ipb(r))), []));
  if (o.domain) opt(15, strBytes(o.domain));
  if (o.paramList) opt(55, o.paramList);
  w.u8(255);
  while (w.length < 300) w.u8(0);
  return w.toU8();
};
function parseDhcp(u, off, end) {
  if (end - off < 240) return null;
  const d = { op: u[off], xid: u32(u, off + 4), secs: u16(u, off + 8), flags: u16(u, off + 10), ciaddr: u32(u, off + 12), yiaddr: u32(u, off + 16), siaddr: u32(u, off + 20), giaddr: u32(u, off + 24), chaddr: MAC.fromBytes(u, off + 28), opts: {}, optList: [] };
  if (u32(u, off + 236) !== 0x63825363) return null;
  let o = off + 240;
  while (o < end && u[o] !== 255) {
    if (u[o] === 0) { o++; continue; }
    const c = u[o], l = u[o + 1]; const v = u.subarray(o + 2, o + 2 + l);
    d.optList.push({ code: c, off: o, len: l + 2, val: v });
    if (c === 53) d.opts.msgType = v[0];
    else if (c === 1) d.opts.mask = u32(v, 0);
    else if (c === 3) { d.opts.routers = []; for (let i = 0; i + 3 < l; i += 4) d.opts.routers.push(u32(v, i)); }
    else if (c === 6) { d.opts.dns = []; for (let i = 0; i + 3 < l; i += 4) d.opts.dns.push(u32(v, i)); }
    else if (c === 50) d.opts.requested = u32(v, 0);
    else if (c === 51) d.opts.lease = u32(v, 0);
    else if (c === 54) d.opts.serverId = u32(v, 0);
    else if (c === 58) d.opts.renewal = u32(v, 0);
    else if (c === 59) d.opts.rebinding = u32(v, 0);
    else if (c === 12) d.opts.hostname = bytesStr(v, 0, l);
    else if (c === 15) d.opts.domain = bytesStr(v, 0, l);
    else if (c === 55) d.opts.paramList = Array.from(v);
    o += 2 + l;
  }
  d.msgType = d.opts.msgType;
  return d;
}

/* --- DNS --- */
const DNS_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA' };
const DNS_TYPE_NUM = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };
Codec.DNS_TYPES = DNS_TYPES; Codec.DNS_TYPE_NUM = DNS_TYPE_NUM;
function dnsName(name) {
  const w = new Writer();
  if (name && name !== '.') name.replace(/\.$/, '').split('.').forEach(l => { w.u8(l.length).str(l); });
  w.u8(0); return w.toU8();
}
Codec.dns = function (d) {
  const w = new Writer();
  const flags = ((d.qr ? 1 : 0) << 15) | ((d.opcode || 0) << 11) | ((d.aa ? 1 : 0) << 10) | ((d.rd ? 1 : 0) << 8) | ((d.ra ? 1 : 0) << 7) | (d.rcode || 0);
  const qs = d.questions || [], an = d.answers || [];
  w.u16(d.id).u16(flags).u16(qs.length).u16(an.length).u16(0).u16(0);
  const qOff = 12;
  qs.forEach(q => { w.bytes(dnsName(q.name)).u16(DNS_TYPE_NUM[q.type] || q.type).u16(1); });
  an.forEach(a => {
    if (qs.length && a.name.toLowerCase() === qs[0].name.toLowerCase()) w.u16(0xC000 | qOff); else w.bytes(dnsName(a.name));
    const t = DNS_TYPE_NUM[a.type] || a.type;
    w.u16(t).u16(1).u32(a.ttl === undefined ? 3600 : a.ttl);
    let rd;
    if (t === 1) rd = new Writer().ip(IP.parse(a.data)).toU8();
    else if (t === 2 || t === 5 || t === 12) rd = dnsName(a.data);
    else if (t === 15) rd = new Writer().u16(a.pref || 10).bytes(dnsName(a.data)).toU8();
    else if (t === 16) rd = new Writer().u8(String(a.data).length).str(String(a.data)).toU8();
    else rd = new Uint8Array(0);
    w.u16(rd.length).bytes(rd);
  });
  return w.toU8();
};
function readName(u, o, base) {
  let name = [], jumped = false, next = o, guard = 0;
  while (guard++ < 64) {
    const l = u[o];
    if (l === undefined) return null;
    if (l === 0) { if (!jumped) next = o + 1; break; }
    if ((l & 0xC0) === 0xC0) { const ptr = ((l & 0x3f) << 8) | u[o + 1]; if (!jumped) next = o + 2; jumped = true; o = base + ptr; continue; }
    name.push(bytesStr(u, o + 1, l)); o += 1 + l;
  }
  return { name: name.join('.') || '<Root>', next };
}
function parseDns(u, off, end, detail, nodes) {
  if (end - off < 12) return null;
  const fl = u16(u, off + 2);
  const d = { id: u16(u, off), qr: fl >> 15, opcode: (fl >> 11) & 15, aa: (fl >> 10) & 1, tc: (fl >> 9) & 1, rd: (fl >> 8) & 1, ra: (fl >> 7) & 1, rcode: fl & 15, questions: [], answers: [], flags: fl };
  const qd = u16(u, off + 4), an = u16(u, off + 6);
  let o = off + 12; const qNodes = [], aNodes = [];
  for (let i = 0; i < qd; i++) {
    const r = readName(u, o, off); if (!r) return d; const t = u16(u, r.next), c = u16(u, r.next + 2);
    d.questions.push({ name: r.name, type: DNS_TYPES[t] || String(t) });
    if (detail) qNodes.push({ t: r.name + ': type ' + (DNS_TYPES[t] || t) + ', class IN', off: o, len: r.next + 4 - o, ch: [{ t: 'Name: ' + r.name, off: o, len: r.next - o }, { t: 'Type: ' + (DNS_TYPES[t] || t) + ' (' + t + ')', off: r.next, len: 2 }, { t: 'Class: IN (0x0001)', off: r.next + 2, len: 2 }] });
    o = r.next + 4;
  }
  for (let i = 0; i < an; i++) {
    const r = readName(u, o, off); if (!r) return d; const t = u16(u, r.next), ttl = u32(u, r.next + 4), rl = u16(u, r.next + 8), ro = r.next + 10;
    let data = '', extra = {};
    if (t === 1) data = IP.str(u32(u, ro));
    else if (t === 2 || t === 5 || t === 12) { const n = readName(u, ro, off); data = n ? n.name : ''; }
    else if (t === 15) { const n = readName(u, ro + 2, off); extra.pref = u16(u, ro); data = n ? n.name : ''; }
    else if (t === 16) data = bytesStr(u, ro + 1, u[ro]);
    d.answers.push({ name: r.name, type: DNS_TYPES[t] || String(t), ttl, data, pref: extra.pref });
    if (detail) {
      const tn = DNS_TYPES[t] || t;
      const lab = t === 1 ? 'addr ' + data : t === 15 ? 'preference ' + extra.pref + ', mx ' + data : (t === 5 ? 'cname ' : t === 2 ? 'ns ' : t === 12 ? 'domain name ' : '') + data;
      aNodes.push({ t: r.name + ': type ' + tn + ', class IN, ' + lab, off: o, len: ro + rl - o, ch: [
        { t: 'Name: ' + r.name, off: o, len: r.next - o }, { t: 'Type: ' + tn + ' (' + t + ')', off: r.next, len: 2 }, { t: 'Class: IN (0x0001)', off: r.next + 2, len: 2 },
        { t: 'Time to live: ' + ttl + ' (' + (ttl >= 60 ? Math.round(ttl / 60) + ' minutes' : ttl + ' seconds') + ')', off: r.next + 4, len: 4 }, { t: 'Data length: ' + rl, off: r.next + 8, len: 2 },
        { t: (t === 1 ? 'Address: ' : t === 5 ? 'CNAME: ' : t === 15 ? 'Mail Exchange: ' : t === 12 ? 'Domain Name: ' : 'Data: ') + data, off: ro, len: rl }] });
    }
    o = ro + rl;
  }
  if (detail) {
    const RC = ['No error (0)', 'Format error (1)', 'Server failure (2)', 'Name Error (3)', 'Not Implemented (4)', 'Refused (5)'];
    nodes.push({ t: 'Transaction ID: 0x' + hex(d.id, 4), off: off, len: 2 });
    nodes.push({ t: 'Flags: 0x' + hex(fl, 4) + (d.qr ? ' Standard query response, ' + RC[d.rcode] : ' Standard query'), off: off + 2, len: 2, ch: [
      { t: (d.qr ? '1' : '0') + '... .... .... .... = Response: Message is a ' + (d.qr ? 'response' : 'query'), off: off + 2, len: 2 },
      { t: '.... ' + d.opcode + '... .... .... = Opcode: Standard query (0)', off: off + 2, len: 2 },
      ...(d.qr ? [{ t: '.... .' + d.aa + '.. .... .... = Authoritative: Server is ' + (d.aa ? '' : 'not ') + 'an authority for domain', off: off + 2, len: 2 }] : []),
      { t: '.... ...' + d.rd + ' .... .... = Recursion desired: ' + (d.rd ? 'Do' : "Don't do") + ' query recursively', off: off + 2, len: 2 },
      ...(d.qr ? [{ t: '.... .... ' + d.ra + '... .... = Recursion available: Server ' + (d.ra ? 'can' : 'cannot') + ' do recursive queries', off: off + 2, len: 2 }, { t: '.... .... .... ' + hex(d.rcode, 1) + ' = Reply code: ' + RC[d.rcode], off: off + 2, len: 2 }] : [])] });
    nodes.push({ t: 'Questions: ' + qd, off: off + 4, len: 2 }); nodes.push({ t: 'Answer RRs: ' + an, off: off + 6, len: 2 });
    nodes.push({ t: 'Authority RRs: 0', off: off + 8, len: 2 }); nodes.push({ t: 'Additional RRs: 0', off: off + 10, len: 2 });
    if (qNodes.length) nodes.push({ t: 'Queries', off: off + 12, len: qNodes.reduce((a, n) => a + n.len, 0), ch: qNodes });
    if (aNodes.length) nodes.push({ t: 'Answers', off: aNodes[0].off, len: aNodes.reduce((a, n) => a + n.len, 0), ch: aNodes });
  }
  return d;
}

/* --- STP (BPDU de configuration) --- */
Codec.bpdu = function (b) {
  const rstp = !!b.rstp;
  const w = new Writer();
  w.u16(0).u8(rstp ? 2 : 0).u8(rstp ? 2 : 0).u8(b.flags || 0).u16(b.rootPri).mac(b.rootMac).u32(b.cost).u16(b.brPri).mac(b.brMac).u16(b.portId)
    .u16(Math.round((b.age || 0) * 256)).u16((b.maxAge || 20) * 256).u16(2 * 256).u16((b.fwd || 15) * 256);
  if (rstp) w.u8(0);
  return w.toU8();
};
/* drapeaux RSTP : bit1 proposition, bits2-3 rôle (1 alt/backup, 2 racine, 3 désigné), bit4 learning, bit5 forwarding, bit6 accord */
Codec.rstpFlags = function (f) { return (f.tc ? 1 : 0) | (f.proposal ? 2 : 0) | ((f.role || 0) << 2) | (f.learning ? 16 : 0) | (f.forwarding ? 32 : 0) | (f.agreement ? 64 : 0) | (f.tcAck ? 128 : 0); };
/* trame SNAP (PVST+, PAgP) : LLC AA AA 03 + OUI + PID, VLAN optionnel (802.1Q) */
Codec.frameSnap = function ({ dst, src, vlan, oui, pid, payload }) {
  const w = new Writer(); w.mac(dst).mac(src);
  if (vlan) w.u16(0x8100).u16(vlan & 0xfff);
  w.u16(payload.length + 8).u8(0xaa).u8(0xaa).u8(3).u8(oui[0]).u8(oui[1]).u8(oui[2]).u16(pid).bytes(payload);
  while (w.length < 60) w.u8(0);
  return w.toU8();
};
Codec.pvstBpdu = function (b, vlan) { const u = Codec.bpdu(b); const w = new Writer().bytes(u).u16(0).u16(2).u16(vlan); return w.toU8(); };
/* LACPDU (802.1AX) */
Codec.lacp = function (l) {
  const w = new Writer().u8(1).u8(1);
  [[1, l.actor], [2, l.partner]].forEach(([t, x]) => { x = x || { sysPri: 0, sysMac: '00:00:00:00:00:00', key: 0, portPri: 0, port: 0, state: 0 }; w.u8(t).u8(20).u16(x.sysPri).mac(x.sysMac).u16(x.key).u16(x.portPri).u16(x.port).u8(x.state).u8(0).u8(0).u8(0); });
  w.u8(3).u8(16).u16(l.maxDelay || 0).zeros(12).u8(0).u8(0).zeros(50);
  return w.toU8();
};
Codec.lacpFrame = function (src, l) { return Codec.frame({ dst: '01:80:c2:00:00:02', src, type: 0x8809, payload: Codec.lacp(l) }); };
function parseLacp(u, o, end) {
  if (end - o < 110 && end - o < 70) return null;
  const rd = p => ({ sysPri: u16(u, p + 2), sysMac: MAC.fromBytes(u, p + 4), key: u16(u, p + 10), portPri: u16(u, p + 12), port: u16(u, p + 14), state: u[p + 16] });
  if (u[o] !== 1) return null;
  return { subtype: 1, version: u[o + 1], actor: rd(o + 2), partner: rd(o + 22) };
}
/* PAgP (Cisco) simplifié : version, drapeaux, id équipement, port, capacité de groupe, + partenaire */
Codec.pagp = function (p) {
  const w = new Writer().u8(1).u8(p.flags || 0).mac(p.devId).u32(p.group || 0).u32(p.ifIndex || 0).mac(p.pDevId || '00:00:00:00:00:00').u32(p.pGroup || 0).u32(p.pIf || 0).u16(p.hello || 30);
  return w.toU8();
};
function parsePagp(u, o, end) {
  if (end - o < 30) return null;
  return { version: u[o], flags: u[o + 1], devId: MAC.fromBytes(u, o + 2), group: u32(u, o + 8), ifIndex: u32(u, o + 12), pDevId: MAC.fromBytes(u, o + 16), pGroup: u32(u, o + 22), pIf: u32(u, o + 26), hello: u16(u, o + 30) };
}
function parseBpdu(u, o, end) {
  if (end - o < 35) return null;
  const b = { proto: u16(u, o), ver: u[o + 2], type: u[o + 3], flags: u[o + 4], rootPri: u16(u, o + 5), rootMac: MAC.fromBytes(u, o + 7), cost: u32(u, o + 13), brPri: u16(u, o + 17), brMac: MAC.fromBytes(u, o + 19), portId: u16(u, o + 25), age: u16(u, o + 27) / 256, maxAge: u16(u, o + 29) / 256, hello: u16(u, o + 31) / 256, fwd: u16(u, o + 33) / 256 };
  if (b.type === 2 || b.ver >= 2) { b.rstp = true; b.role = (b.flags >> 2) & 3; b.proposal = !!(b.flags & 2); b.agreement = !!(b.flags & 64); b.learning = !!(b.flags & 16); b.forwarding = !!(b.flags & 32); }
  return b;
}

/* --- RIPv2 --- */
Codec.rip = function (cmd, entries) {
  const w = new Writer().u8(cmd).u8(2).u16(0);
  entries.forEach(e => { w.u16(2).u16(0).ip(e.net).ip(e.mask).ip(e.nh || 0).u32(e.metric); });
  return w.toU8();
};
function parseRip(u, o, end) {
  if (end - o < 4) return null;
  const r = { cmd: u[o], ver: u[o + 1], entries: [] };
  for (let i = o + 4; i + 20 <= end; i += 20) r.entries.push({ fam: u16(u, i), net: u32(u, i + 4), mask: u32(u, i + 8), nh: u32(u, i + 12), metric: u32(u, i + 16), off: i });
  return r;
}

/* --- OSPFv2 (Hello, DBD simplifié, LSU) — en-tête réel, corps simplifié --- */
Codec.ospf = function (o) {
  const w = new Writer();
  w.u8(2).u8(o.type).u16(0).ip(o.rid).ip(o.area || 0).u16(0).u16(0).zeros(8); // 24 octets
  w.bytes(o.body || []);
  const u = w.toU8(); u[2] = u.length >> 8; u[3] = u.length & 255;
  const c = checksum(u, 0, u.length); u[12] = c >> 8; u[13] = c & 255; return u;
};
Codec.ospfHello = function (h) {
  const w = new Writer().ip(h.mask).u16(h.hello || 10).u8(0x02).u8(h.pri === undefined ? 1 : h.pri).u32(h.dead || 40).ip(h.dr || 0).ip(h.bdr || 0);
  (h.neighbors || []).forEach(n => w.ip(n));
  return w.toU8();
};
const OSPF_TYPES = { 1: 'Hello Packet', 2: 'DB Description', 3: 'LS Request', 4: 'LS Update', 5: 'LS Acknowledge' };
const LSA_TYPES = { 1: 'Router-LSA', 2: 'Network-LSA', 3: 'Summary-LSA (IP network)', 4: 'Summary-LSA (ASBR)', 5: 'AS-External-LSA' };
Codec.LSA_TYPES = LSA_TYPES;
function fletcher(d, ck) { d[ck] = 0; d[ck + 1] = 0; let c0 = 0, c1 = 0; for (let i = 0; i < d.length; i++) { c0 = (c0 + d[i]) % 255; c1 = (c1 + c0) % 255; } let x = ((d.length - ck - 1) * c0 - c1) % 255; if (x <= 0) x += 255; let y = 510 - c0 - x; if (y > 255) y -= 255; d[ck] = x; d[ck + 1] = y; }
/* LSA -> octets (en-tête 20 octets + corps). lsa = {type,id,adv,seq,age,opts,router:{flags,links},network:{mask,routers},summary:{mask,metric},ext:{mask,metric,fwd,tag}} */
Codec.lsaBytes = function (l) {
  const w = new Writer();
  if (l.type === 1) { w.u8(l.router.flags || 0).u8(0).u16(l.router.links.length); l.router.links.forEach(k => w.ip(k.id).ip(k.data).u8(k.type).u8(0).u16(k.metric)); }
  else if (l.type === 2) { w.ip(l.network.mask); l.network.routers.forEach(r => w.ip(r)); }
  else if (l.type === 3 || l.type === 4) { w.ip(l.summary.mask).u8(0).u8((l.summary.metric >> 16) & 255).u16(l.summary.metric & 0xffff); }
  else if (l.type === 5) { const e = l.ext; w.ip(e.mask).u8(0x80).u8((e.metric >> 16) & 255).u16(e.metric & 0xffff).ip(e.fwd || 0).u32(e.tag || 0); }
  const body = w.toU8(); const h = new Writer().u16(l.age || 0).u8(l.opts === undefined ? 0x02 : l.opts).u8(l.type).ip(l.id).ip(l.adv).u32(l.seq >>> 0).u16(0).u16(20 + body.length).toU8();
  const u = new Uint8Array(20 + body.length); u.set(h, 0); u.set(body, 20);
  const cov = u.subarray(2); fletcher(cov, 14); return u;
};
Codec.lsaHeader = function (l) { return Codec.lsaBytes(Object.assign({}, l, l.type === 1 ? { router: { links: [] } } : {})).subarray(0, 20); };
function parseLsaHdr(u, o) { return { age: u16(u, o), opts: u[o + 2], type: u[o + 3], id: u32(u, o + 4), adv: u32(u, o + 8), seq: u32(u, o + 12) | 0, chk: u16(u, o + 16), len: u16(u, o + 18), off: o }; }
function parseLsa(u, o, end) {
  if (end - o < 20) return null; const l = parseLsaHdr(u, o); if (l.len < 20 || o + l.len > end) return null; const b = o + 20;
  if (l.type === 1 && l.len >= 24) { l.router = { flags: u[b], links: [] }; const n = u16(u, b + 2); for (let i = 0; i < n && b + 4 + i * 12 + 12 <= o + l.len; i++) { const q = b + 4 + i * 12; l.router.links.push({ id: u32(u, q), data: u32(u, q + 4), type: u[q + 8], metric: u16(u, q + 10) }); } }
  else if (l.type === 2 && l.len >= 24) { l.network = { mask: u32(u, b), routers: [] }; for (let q = b + 4; q + 4 <= o + l.len; q += 4) l.network.routers.push(u32(u, q)); }
  else if ((l.type === 3 || l.type === 4) && l.len >= 28) l.summary = { mask: u32(u, b), metric: (u[b + 5] << 16) | u16(u, b + 6) };
  else if (l.type === 5 && l.len >= 36) l.ext = { mask: u32(u, b), e2: !!(u[b + 4] & 0x80), metric: (u[b + 5] << 16) | u16(u, b + 6), fwd: u32(u, b + 8), tag: u32(u, b + 12) };
  return l;
}
Codec.ospfDbd = function (d) { const w = new Writer().u16(d.mtu || 1500).u8(d.opts === undefined ? 0x02 : d.opts).u8((d.init ? 4 : 0) | (d.more ? 2 : 0) | (d.master ? 1 : 0)).u32(d.seq >>> 0); (d.headers || []).forEach(h => w.bytes(h)); return w.toU8(); };
Codec.ospfLsr = function (reqs) { const w = new Writer(); reqs.forEach(r => w.u32(r.type).ip(r.id).ip(r.adv)); return w.toU8(); };
Codec.ospfLsu = function (lsas) { const w = new Writer().u32(lsas.length); lsas.forEach(b => w.bytes(b)); return w.toU8(); };
Codec.ospfAck = function (headers) { const w = new Writer(); headers.forEach(h => w.bytes(h)); return w.toU8(); };
Codec.ospfIp = function (o) { return Codec.ospf(o); };
function lsaNode(l, b) {
  const n = { t: 'LS Type: ' + (LSA_TYPES[l.type] || l.type) + ', LSID ' + IP.str(l.id) + ', Adv Rtr ' + IP.str(l.adv), off: l.off, len: l.len, ch: [
    { t: 'LS Age: ' + l.age + ' seconds' + (l.age >= 3600 ? ' (MaxAge)' : ''), off: l.off, len: 2 }, { t: 'Options: 0x' + hex(l.opts, 2) + ' (E)', off: l.off + 2, len: 1 },
    { t: 'LS Type: ' + (LSA_TYPES[l.type] || l.type) + ' (' + l.type + ')', off: l.off + 3, len: 1 }, { t: 'Link State ID: ' + IP.str(l.id), off: l.off + 4, len: 4 }, { t: 'Advertising Router: ' + IP.str(l.adv), off: l.off + 8, len: 4 },
    { t: 'Sequence Number: 0x' + hex(l.seq >>> 0, 8), off: l.off + 12, len: 4 }, { t: 'Checksum: 0x' + hex(l.chk, 4), off: l.off + 16, len: 2 }, { t: 'Length: ' + l.len, off: l.off + 18, len: 2 }] };
  if (b === false) return n; const o = l.off + 20;
  if (l.router) { n.ch.push({ t: 'Flags: 0x' + hex(l.router.flags, 2) + (l.router.flags & 1 ? ' (B)' : '') + (l.router.flags & 2 ? ' (E)' : ''), off: o, len: 1 }, { t: 'Number of Links: ' + l.router.links.length, off: o + 2, len: 2 });
    l.router.links.forEach((k, i) => { const q = o + 4 + i * 12; const T = { 1: 'PTP', 2: 'Transit', 3: 'Stub' }[k.type] || k.type; n.ch.push({ t: 'Type: ' + T + '   ID: ' + IP.str(k.id) + '   Data: ' + IP.str(k.data) + '   Metric: ' + k.metric, off: q, len: 12, ch: [{ t: (k.type === 3 ? 'Link ID: ' + IP.str(k.id) + ' (network)' : k.type === 2 ? 'Link ID: ' + IP.str(k.id) + ' (DR interface address)' : 'Link ID: ' + IP.str(k.id) + ' (neighbor Router ID)'), off: q, len: 4 }, { t: (k.type === 3 ? 'Link Data: ' + IP.str(k.data) + ' (mask)' : 'Link Data: ' + IP.str(k.data) + ' (interface address)'), off: q + 4, len: 4 }, { t: 'Link Type: ' + T + ' (' + k.type + ')', off: q + 8, len: 1 }, { t: 'Metric: ' + k.metric, off: q + 10, len: 2 }] }); }); }
  else if (l.network) { n.ch.push({ t: 'Netmask: ' + IP.str(l.network.mask), off: o, len: 4 }); l.network.routers.forEach((r, i) => n.ch.push({ t: 'Attached Router: ' + IP.str(r), off: o + 4 + 4 * i, len: 4 })); }
  else if (l.summary) n.ch.push({ t: 'Netmask: ' + IP.str(l.summary.mask), off: o, len: 4 }, { t: 'Metric: ' + l.summary.metric, off: o + 5, len: 3 });
  else if (l.ext) n.ch.push({ t: 'Netmask: ' + IP.str(l.ext.mask), off: o, len: 4 }, { t: 'E-bit: ' + (l.ext.e2 ? 'External Type 2 (Larger than any link state path)' : 'Type 1'), off: o + 4, len: 1 }, { t: 'Metric: ' + l.ext.metric, off: o + 5, len: 3 }, { t: 'Forwarding Address: ' + IP.str(l.ext.fwd), off: o + 8, len: 4 }, { t: 'External Route Tag: ' + l.ext.tag, off: o + 12, len: 4 });
  return n;
}
function parseOspf(u, o, end, detail, nodes) {
  if (end - o < 24) return null;
  const r = { ver: u[o], type: u[o + 1], len: u16(u, o + 2), rid: u32(u, o + 4), area: u32(u, o + 8), body: u.subarray(o + 24, end) };
  const b = o + 24;
  if (r.type === 1 && r.body.length >= 20) { r.mask = u32(r.body, 0); r.hello = u16(r.body, 4); r.pri = r.body[7]; r.dead = u32(r.body, 8); r.dr = u32(r.body, 12); r.bdr = u32(r.body, 16); r.neighbors = []; for (let i = 20; i + 3 < r.body.length; i += 4) r.neighbors.push(u32(r.body, i)); }
  else if (r.type === 2 && r.body.length >= 8) { const f = r.body[3]; r.dbd = { mtu: u16(r.body, 0), opts: r.body[2], init: !!(f & 4), more: !!(f & 2), master: !!(f & 1), seq: u32(r.body, 4), headers: [] }; for (let q = 8; q + 20 <= r.body.length; q += 20) r.dbd.headers.push(parseLsaHdr(u, b + q)); }
  else if (r.type === 3) { r.lsr = []; for (let q = 0; q + 12 <= r.body.length; q += 12) r.lsr.push({ type: u32(r.body, q), id: u32(r.body, q + 4), adv: u32(r.body, q + 8), off: b + q }); }
  else if (r.type === 4 && r.body.length >= 4) { r.lsu = []; let q = b + 4; const n = u32(r.body, 0); for (let i = 0; i < n; i++) { const l = parseLsa(u, q, end); if (!l) break; r.lsu.push(l); q += l.len; } }
  else if (r.type === 5) { r.acks = []; for (let q = 0; q + 20 <= r.body.length; q += 20) r.acks.push(parseLsaHdr(u, b + q)); }
  if (detail) {
    nodes.push({ t: 'Version: ' + r.ver, off: o, len: 1 }); nodes.push({ t: 'Message Type: ' + (OSPF_TYPES[r.type] || r.type) + ' (' + r.type + ')', off: o + 1, len: 1 });
    nodes.push({ t: 'Packet Length: ' + r.len, off: o + 2, len: 2 }); nodes.push({ t: 'Source OSPF Router: ' + IP.str(r.rid), off: o + 4, len: 4 });
    nodes.push({ t: 'Area ID: ' + IP.str(r.area) + (r.area === 0 ? ' (Backbone)' : ''), off: o + 8, len: 4 }); nodes.push({ t: 'Checksum: 0x' + hex(u16(u, o + 12), 4), off: o + 12, len: 2 });
    nodes.push({ t: 'Auth Type: Null (0)', off: o + 14, len: 2 });
    if (r.type === 1 && r.mask !== undefined) {
      nodes.push({ t: 'OSPF Hello Packet', off: b, len: r.body.length, ch: [{ t: 'Network Mask: ' + IP.str(r.mask), off: b, len: 4 }, { t: 'Hello Interval [sec]: ' + r.hello, off: b + 4, len: 2 }, { t: 'Options: 0x02, (E) External Routing', off: b + 6, len: 1 }, { t: 'Router Priority: ' + r.pri, off: b + 7, len: 1 }, { t: 'Router Dead Interval [sec]: ' + r.dead, off: b + 8, len: 4 }, { t: 'Designated Router: ' + IP.str(r.dr), off: b + 12, len: 4 }, { t: 'Backup Designated Router: ' + IP.str(r.bdr), off: b + 16, len: 4 }].concat(r.neighbors.map((n, i) => ({ t: 'Active Neighbor: ' + IP.str(n), off: b + 20 + 4 * i, len: 4 }))) });
    } else if (r.dbd) {
      const d = r.dbd; nodes.push({ t: 'OSPF DB Description', off: b, len: r.body.length, ch: [{ t: 'Interface MTU: ' + d.mtu, off: b, len: 2 }, { t: 'Options: 0x' + hex(d.opts, 2), off: b + 2, len: 1 }, { t: 'DB Description: 0x' + hex(r.body[3], 2) + (d.init ? ' (I)' : '') + (d.more ? ' (M)' : '') + (d.master ? ' (MS)' : ''), off: b + 3, len: 1 }, { t: 'DD Sequence: ' + d.seq, off: b + 4, len: 4 }].concat(d.headers.map(h => lsaNode(h, false))) });
    } else if (r.lsr) nodes.push({ t: 'Link State Request', off: b, len: r.body.length, ch: r.lsr.map(x => ({ t: 'LS Type: ' + (LSA_TYPES[x.type] || x.type) + ', LS ID: ' + IP.str(x.id) + ', Adv Rtr: ' + IP.str(x.adv), off: x.off, len: 12 })) });
    else if (r.lsu) nodes.push({ t: 'LS Update Packet', off: b, len: r.body.length, ch: [{ t: 'Number of LSAs: ' + r.lsu.length, off: b, len: 4 }].concat(r.lsu.map(l => lsaNode(l, true))) });
    else if (r.acks) nodes.push({ t: 'LSA-type ' + 'Acknowledge (' + r.acks.length + ' LSA header' + (r.acks.length > 1 ? 's' : '') + ')', off: b, len: r.body.length, ch: r.acks.map(l => lsaNode(l, false)) });
    else if (r.body.length) nodes.push({ t: 'Données OSPF (' + r.body.length + ' octets)', off: o + 24, len: r.body.length });
  }
  return r;
}
Codec.OSPF_TYPES = OSPF_TYPES;

/* --- TLS (enregistrements simplifiés), SSH (bannière) --- */
Codec.tlsRecord = function (type, ver, body) { return new Writer().u8(type).u16(ver || 0x0303).u16(body.length).bytes(body).toU8(); };
Codec.tlsClientHello = function (sni, rng) {
  const sn = strBytes(sni || '');
  const ext = new Writer().u16(0).u16(sn.length + 5).u16(sn.length + 3).u8(0).u16(sn.length).bytes(sn).toU8();
  const w = new Writer().u16(0x0303).bytes(rng.bytes(32)).u8(0).u16(4).u16(0x1301).u16(0x1302).u8(1).u8(0).u16(ext.length).bytes(ext);
  const b = w.toU8();
  return Codec.tlsRecord(22, 0x0301, concat(Uint8Array.of(1, 0, b.length >> 8, b.length & 255), b));
};
Codec.tlsServerHello = function (rng) {
  const w = new Writer().u16(0x0303).bytes(rng.bytes(32)).u8(0).u16(0x1301).u8(0).u16(0);
  const b = w.toU8();
  return Codec.tlsRecord(22, 0x0303, concat(Uint8Array.of(2, 0, b.length >> 8, b.length & 255), b));
};
function parseTls(u, o, end, detail, nodes) {
  const recs = []; let p = o;
  while (p + 5 <= end) {
    const type = u[p], ver = u16(u, p + 1), len = u16(u, p + 3);
    if (type < 20 || type > 24) break;
    const rec = { type, ver, len };
    if (type === 22 && p + 9 <= end) { rec.hsType = u[p + 5]; if (rec.hsType === 1) { const q = p + 9 + 2 + 32; const sl = u[q]; const cl = u16(u, q + 1 + sl); let e = q + 1 + sl + 2 + cl; e += 1 + u[e]; const el = u16(u, e); let x = e + 2; const xe = x + el; while (x + 4 <= xe) { const et = u16(u, x), ell = u16(u, x + 2); if (et === 0) { rec.sni = bytesStr(u, x + 9, u16(u, x + 7)); } x += 4 + ell; } } }
    recs.push(rec);
    if (detail) {
      const TN = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data' };
      const HN = { 1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 14: 'Server Hello Done', 16: 'Client Key Exchange', 20: 'Finished' };
      const vn = ver === 0x0303 ? 'TLS 1.2' : ver === 0x0301 ? 'TLS 1.0' : '0x' + hex(ver, 4);
      const ch = [{ t: 'Content Type: ' + TN[type] + ' (' + type + ')', off: p, len: 1 }, { t: 'Version: ' + vn + ' (0x' + hex(ver, 4) + ')', off: p + 1, len: 2 }, { t: 'Length: ' + len, off: p + 3, len: 2 }];
      if (type === 22) { const c2 = [{ t: 'Handshake Type: ' + (HN[rec.hsType] || rec.hsType) + ' (' + rec.hsType + ')', off: p + 5, len: 1 }]; if (rec.sni) c2.push({ t: 'Extension: server_name (len=' + (rec.sni.length + 5) + ') Server Name: ' + rec.sni, off: p + 5, len: len }); ch.push({ t: 'Handshake Protocol: ' + (HN[rec.hsType] || 'Encrypted Handshake Message'), off: p + 5, len: len, ch: c2 }); }
      else if (type === 23) ch.push({ t: 'Encrypted Application Data: ' + hex(u[p + 5] || 0, 2) + hex(u[p + 6] || 0, 2) + '…', off: p + 5, len: Math.min(len, end - p - 5) });
      nodes.push({ t: (vn) + ' Record Layer: ' + TN[type] + (type === 22 ? ' Protocol: ' + (HN[rec.hsType] || 'Encrypted Handshake Message') : '') , off: p, len: 5 + Math.min(len, end - p - 5), ch });
    }
    p += 5 + len;
  }
  return recs.length ? { records: recs } : null;
}

/* --- HTTP --- */
function parseHttp(u, o, end, detail, nodes) {
  const txt = bytesStr(u, o, end - o);
  const idx = txt.indexOf('\r\n\r\n');
  const head = idx >= 0 ? txt.slice(0, idx) : txt;
  const lines = head.split('\r\n');
  const first = lines[0];
  let h = { headers: {}, body: idx >= 0 ? u.subarray(o + idx + 4, end) : new Uint8Array(0), first, complete: idx >= 0 };
  let m;
  if ((m = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS) (\S+) HTTP\/(\d\.\d)$/.exec(first))) { h.isReq = true; h.method = m[1]; h.uri = m[2]; h.version = m[3]; }
  else if ((m = /^HTTP\/(\d\.\d) (\d{3}) ?(.*)$/.exec(first))) { h.isReq = false; h.version = m[1]; h.status = +m[2]; h.reason = m[3]; }
  else return null;
  lines.slice(1).forEach(l => { const k = l.indexOf(':'); if (k > 0) h.headers[l.slice(0, k).trim().toLowerCase()] = l.slice(k + 1).trim(); });
  if (detail) {
    let p = o; const ch = [];
    lines.forEach((l, i) => { ch.push({ t: l + '\\r\\n', off: p, len: l.length + 2 }); p += l.length + 2; });
    ch.push({ t: '\\r\\n', off: p, len: 2 });
    nodes.push({ t: 'Hypertext Transfer Protocol', off: o, len: (idx >= 0 ? idx + 4 : end - o), ch: ch.map((c, i) => i === 0 ? { t: c.t, off: c.off, len: c.len, ch: h.isReq ? [{ t: 'Request Method: ' + h.method, off: c.off, len: h.method.length }, { t: 'Request URI: ' + h.uri, off: c.off + h.method.length + 1, len: h.uri.length }, { t: 'Request Version: HTTP/' + h.version, off: c.off + h.method.length + h.uri.length + 2, len: 8 }] : [{ t: 'Response Version: HTTP/' + h.version, off: c.off, len: 8 }, { t: 'Status Code: ' + h.status, off: c.off + 9, len: 3 }, { t: 'Response Phrase: ' + h.reason, off: c.off + 13, len: h.reason.length }] } : c) });
    if (h.body.length) nodes.push({ t: 'Line-based text data / File Data: ' + h.body.length + ' bytes', off: o + idx + 4, len: h.body.length });
  }
  return h;
}
Codec.httpRequest = function (method, host, uri, extra) {
  let s = method + ' ' + uri + ' HTTP/1.1\r\nHost: ' + host + '\r\nUser-Agent: SimuReseau/1.0\r\nAccept: text/html\r\nConnection: close\r\n';
  const body = (extra && extra.body) || '';
  if (body) s += 'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ' + NS.B.utf8Bytes(body).length + '\r\n';
  return NS.B.utf8Bytes(s + '\r\n' + body);
};
Codec.httpResponse = function (status, reason, body, type) {
  const b = NS.B.utf8Bytes(body);
  return concat(NS.B.utf8Bytes('HTTP/1.1 ' + status + ' ' + reason + '\r\nServer: SimuServeur/1.0\r\nContent-Type: ' + (type || 'text/html; charset=utf-8') + '\r\nContent-Length: ' + b.length + '\r\nConnection: close\r\n\r\n'), b);
};

/* ------------------------------------------------------------------ DECODEUR */
function N(t, off, len, ch) { return { t, off, len, ch: ch || null }; }
const ICMP_NAMES = { 0: 'Echo (ping) reply', 3: 'Destination unreachable', 5: 'Redirect', 8: 'Echo (ping) request', 11: 'Time-to-live exceeded' };
const UNREACH = { 0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable', 3: 'Port unreachable', 13: 'Communication administratively filtered' };
Codec.ICMP_NAMES = ICMP_NAMES; Codec.UNREACH = UNREACH;

Codec.parse = function (u, detail) {
  const p = { bytes: u, len: u.length, tree: [] };
  const T = p.tree;
  if (u.length < 14) { p.bad = 'Trame trop courte'; return p; }
  const dst = MAC.fromBytes(u, 0), src = MAC.fromBytes(u, 6);
  let type = u16(u, 12), off = 14, end = u.length;
  const eth = p.eth = { dst, src, type, vlan: null, hdr: 14 };
  let ethNode = null;
  if (detail) {
    ethNode = N((type <= 1500 ? 'IEEE 802.3 Ethernet' : 'Ethernet II') + ', Src: ' + Codec.macLabel(src) + ' (' + src + '), Dst: ' + Codec.macLabel(dst) + ' (' + dst + ')', 0, 14, [
      N('Destination: ' + Codec.macLabel(dst) + ' (' + dst + ')', 0, 6), N('Source: ' + Codec.macLabel(src) + ' (' + src + ')', 6, 6)]);
    ethNode.layer = 'eth'; T.push(ethNode);
  }
  if (type === 0x8100 && u.length >= 18) {
    const tci = u16(u, 14); eth.vlan = { pcp: tci >> 13, dei: (tci >> 12) & 1, vid: tci & 0xfff };
    const inner = u16(u, 16);
    if (detail) {
      ethNode.ch.push(N('Type: 802.1Q Virtual LAN (0x8100)', 12, 2));
      const vn = N('802.1Q Virtual LAN, PRI: ' + eth.vlan.pcp + ', DEI: ' + eth.vlan.dei + ', ID: ' + eth.vlan.vid, 14, 4, [
        N(bitStr(tci >> 13, 3, 0, 16) + ' = Priority: ' + (eth.vlan.pcp === 0 ? 'Best Effort (default)' : eth.vlan.pcp) + ' (' + eth.vlan.pcp + ')', 14, 2),
        N('...' + eth.vlan.dei + ' .... .... .... = DEI: ' + (eth.vlan.dei ? 'Eligible' : 'Ineligible'), 14, 2),
        N('.... ' + vlanBits(eth.vlan.vid) + ' = ID: ' + eth.vlan.vid, 14, 2),
        N('Type: ' + (ETHERTYPES[inner] || 'Unknown') + ' (0x' + hex(inner, 4) + ')', 16, 2)]);
      vn.layer = 'vlan'; T.push(vn);
    }
    type = inner; eth.type = inner; off = 18; eth.hdr = 18;
  } else if (detail && type > 1500) ethNode.ch.push(N('Type: ' + (ETHERTYPES[type] || 'Unknown') + ' (0x' + hex(type, 4) + ')', 12, 2));

  if (type <= 1500) { // 802.3 + LLC
    end = Math.min(u.length, off + type);
    if (detail) ethNode.ch.push(N('Length: ' + type, 12, 2));
    if (end - off >= 3) {
      const dsap = u[off], ssap = u[off + 1];
      p.llc = { dsap, ssap };
      if (detail) { const l = N('Logical-Link Control', off, 3, [N('DSAP: ' + (dsap === 0x42 ? 'Spanning Tree BPDU' : '0x' + hex(dsap, 2)) + ' (0x' + hex(dsap, 2) + ')', off, 1), N('SSAP: ' + (ssap === 0x42 ? 'Spanning Tree BPDU' : '0x' + hex(ssap, 2)) + ' (0x' + hex(ssap, 2) + ')', off + 1, 1), N('Control field: U, func=UI (0x03)', off + 2, 1)]); l.layer = 'llc'; T.push(l); }
      let bo = -1, pvst = false;
      if (dsap === 0x42) bo = off + 3;
      else if (dsap === 0xaa && end - off >= 8) {
        const oui = hex(u[off + 3], 2) + ':' + hex(u[off + 4], 2) + ':' + hex(u[off + 5], 2), pid = u16(u, off + 6);
        if (detail) T[T.length - 1].ch.push(N('Organization Code: ' + (oui === '00:00:0c' ? 'Cisco (00:00:0c)' : oui), off + 3, 3), N('PID: ' + (pid === 0x010b ? 'PVSTP+ (0x010b)' : pid === 0x0104 ? 'PAgP (0x0104)' : '0x' + hex(pid, 4)), off + 6, 2));
        if (oui === '00:00:0c' && pid === 0x010b) { bo = off + 8; pvst = true; }
        else if (oui === '00:00:0c' && pid === 0x2000 && Codec.parseCdp) { Codec.parseCdp(p, u, off + 8, end, detail); }
        else if (oui === '00:00:0c' && pid === 0x0104) {
          const g = parsePagp(u, off + 8, end);
          if (g) { p.pagp = g; if (detail) { const n = N('Port Aggregation Protocol', off + 8, 32, [N('Version: ' + g.version, off + 8, 1), N('Flags: 0x' + hex(g.flags, 2) + (g.flags & 1 ? ' (Slow hello)' : '') + (g.flags & 2 ? ' (Auto mode)' : ' (Desirable mode)'), off + 9, 1), N('Local Device ID: ' + g.devId, off + 10, 6), N('Local Group Capability: 0x' + hex(g.group, 8), off + 16, 4), N('Local Interface Index: ' + g.ifIndex, off + 20, 4), N('Partner Device ID: ' + g.pDevId, off + 24, 6), N('Partner Group Capability: 0x' + hex(g.pGroup, 8), off + 30, 4), N('Partner Port Index: ' + g.pIf, off + 34, 4), N('Partner Hello Time: ' + g.hello + ' s', off + 38, 2)]); n.layer = 'pagp'; T.push(n); } }
        }
      }
      if (bo >= 0) {
        const b = parseBpdu(u, bo, end);
        if (b) {
          p.stp = b; b.pvst = pvst;
          if (pvst) { const t = bo + (b.rstp ? 36 : 35); if (end - t >= 6 && u16(u, t) === 0 && u16(u, t + 2) === 2) b.vlan = u16(u, t + 4); else b.vlan = eth.vlan ? eth.vlan.vid : 1; }
          if (detail) {
            const o = bo, ROLE = ['Unknown', 'Alternate/Backup', 'Root', 'Designated'];
            const fl = [];
            if (b.rstp) fl.push(N((b.flags & 128 ? '1' : '0') + '... .... = Topology Change Acknowledgment: ' + (b.flags & 128 ? 'Yes' : 'No'), o + 4, 1), N('.' + (b.agreement ? 1 : 0) + '.. .... = Agreement: ' + (b.agreement ? 'Yes' : 'No'), o + 4, 1), N('..' + (b.forwarding ? 1 : 0) + '. .... = Forwarding: ' + (b.forwarding ? 'Yes' : 'No'), o + 4, 1), N('...' + (b.learning ? 1 : 0) + ' .... = Learning: ' + (b.learning ? 'Yes' : 'No'), o + 4, 1), N('.... ' + ((b.role >> 1) & 1) + (b.role & 1) + '.. = Port Role: ' + ROLE[b.role] + ' (' + b.role + ')', o + 4, 1), N('.... ..' + (b.proposal ? 1 : 0) + '. = Proposal: ' + (b.proposal ? 'Yes' : 'No'), o + 4, 1));
            fl.push(N('.... ...' + (b.flags & 1) + ' = Topology Change: ' + (b.flags & 1 ? 'Yes' : 'No'), o + 4, 1));
            const n = N((b.rstp ? 'Rapid ' : '') + 'Spanning Tree Protocol', o, b.rstp ? 36 : 35, [N('Protocol Identifier: Spanning Tree Protocol (0x0000)', o, 2), N('Protocol Version Identifier: ' + (b.rstp ? 'Rapid Spanning Tree (2)' : 'Spanning Tree (0)'), o + 2, 1), N('BPDU Type: ' + (b.rstp ? 'Rapid/Multiple Spanning Tree (0x02)' : 'Configuration (0x00)'), o + 3, 1), N('BPDU flags: 0x' + hex(b.flags, 2), o + 4, 1, fl),
              N('Root Identifier: ' + b.rootPri + ' / ' + b.rootMac, o + 5, 8, [N('Root Bridge Priority: ' + (b.rootPri & 0xf000), o + 5, 2), N('Root Bridge System ID Extension: ' + (b.rootPri & 0xfff), o + 5, 2), N('Root Bridge System ID: ' + Codec.macLabel(b.rootMac) + ' (' + b.rootMac + ')', o + 7, 6)]),
              N('Root Path Cost: ' + b.cost, o + 13, 4),
              N('Bridge Identifier: ' + b.brPri + ' / ' + b.brMac, o + 17, 8, [N('Bridge Priority: ' + (b.brPri & 0xf000), o + 17, 2), N('Bridge System ID Extension: ' + (b.brPri & 0xfff), o + 17, 2), N('Bridge System ID: ' + Codec.macLabel(b.brMac) + ' (' + b.brMac + ')', o + 19, 6)]),
              N('Port identifier: 0x' + hex(b.portId, 4), o + 25, 2), N('Message Age: ' + b.age, o + 27, 2), N('Max Age: ' + b.maxAge, o + 29, 2), N('Hello Time: ' + b.hello, o + 31, 2), N('Forward Delay: ' + b.fwd, o + 33, 2)]);
            if (b.rstp) n.ch.push(N('Version 1 Length: 0', o + 35, 1));
            if (pvst) n.ch.push(N('Originating VLAN (PVID): ' + b.vlan, bo + (b.rstp ? 36 : 35) + 4, 2));
            n.layer = 'stp'; T.push(n);
          }
        }
      }
    }
    return p;
  }
  if (Codec.ethApps[type]) { Codec.ethApps[type](p, u, off, end, detail); return p; }
  if (type === 0x8809) {
    const l = parseLacp(u, off, end);
    if (l) {
      p.lacp = l;
      if (detail) {
        const fl = st => ['Activity', 'Timeout', 'Aggregation', 'Synchronization', 'Collecting', 'Distributing', 'Defaulted', 'Expired'].map((n, i) => (st >> i) & 1 ? n : null).filter(Boolean).join(', ');
        const tl = (nm, x, o) => N(nm + ' Information', o, 20, [N('TLV Type: ' + nm + ' Information', o, 1), N('TLV Length: 0x14', o + 1, 1), N(nm + ' System Priority: ' + x.sysPri, o + 2, 2), N(nm + ' System ID: ' + x.sysMac, o + 4, 6), N(nm + ' Key: ' + x.key, o + 10, 2), N(nm + ' Port Priority: ' + x.portPri, o + 12, 2), N(nm + ' Port: ' + x.port, o + 14, 2), N(nm + ' State: 0x' + hex(x.state, 2) + ' (' + fl(x.state) + ')', o + 16, 1)]);
        const n = N('Link Aggregation Control Protocol', off, 110, [N('LACP Version: 0x01', off + 1, 1), tl('Actor', l.actor, off + 2), tl('Partner', l.partner, off + 22), N('Collector Information', off + 42, 16)]); n.layer = 'lacp'; T.push(n);
      }
    }
    return p;
  }
  if (type === 0x0806) { parseArp(p, u, off, detail); return p; }
  if (type === 0x0800) { parseIp(p, u, off, detail); return p; }
  if (detail) { const n = N(ETHERTYPES[type] ? ETHERTYPES[type] + ' (non décodé)' : 'Données (' + (u.length - off) + ' octets)', off, u.length - off); n.layer = 'data'; T.push(n); }
  return p;
};
function bitStr(v, nbits, shift, total) {
  // représentation "xxx. .... .... ...." pour un champ de nbits en tête
  let s = ''; for (let i = 0; i < total; i++) { const inField = i < nbits; s += inField ? ((v >> (nbits - 1 - i)) & 1) : '.'; if (i % 4 === 3 && i < total - 1) s += ' '; } return s;
}
function vlanBits(v) { let s = ''; for (let i = 11; i >= 0; i--) { s += (v >> i) & 1; if (i % 4 === 0 && i) s += ' '; } return s; }

function parseArp(p, u, off, detail) {
  if (u.length - off < 28) return;
  const op = u16(u, off + 6);
  const a = p.arp = { op, sha: MAC.fromBytes(u, off + 8), spa: u32(u, off + 14), tha: MAC.fromBytes(u, off + 18), tpa: u32(u, off + 24) };
  if (detail) {
    const n = N('Address Resolution Protocol (' + (op === 1 ? 'request' : op === 2 ? 'reply' : 'op ' + op) + ')', off, 28, [
      N('Hardware type: Ethernet (1)', off, 2), N('Protocol type: IPv4 (0x0800)', off + 2, 2), N('Hardware size: 6', off + 4, 1), N('Protocol size: 4', off + 5, 1),
      N('Opcode: ' + (op === 1 ? 'request (1)' : op === 2 ? 'reply (2)' : op), off + 6, 2),
      N('Sender MAC address: ' + Codec.macLabel(a.sha) + ' (' + a.sha + ')', off + 8, 6), N('Sender IP address: ' + IP.str(a.spa), off + 14, 4),
      N('Target MAC address: ' + Codec.macLabel(a.tha) + ' (' + a.tha + ')', off + 18, 6), N('Target IP address: ' + IP.str(a.tpa), off + 24, 4)]);
    n.layer = 'arp'; p.tree.push(n);
    if (u.length > off + 28) { const pad = N('Padding (' + (u.length - off - 28) + ' octets)', off + 28, u.length - off - 28); pad.layer = 'pad'; p.tree.push(pad); }
  }
}

const DSCP = { 0: 'CS0', 8: 'CS1', 16: 'CS2', 24: 'CS3', 32: 'CS4', 40: 'CS5', 46: 'EF', 48: 'CS6', 56: 'CS7' };
function parseIp(p, u, off, detail) {
  if (u.length - off < 20) return;
  const vhl = u[off]; if ((vhl >> 4) !== 4) return;
  const ihl = (vhl & 15) * 4; if (ihl < 20) return;
  const total = u16(u, off + 2), ff = u16(u, off + 6);
  const ip = p.ip = { tos: u[off + 1], total, id: u16(u, off + 4), df: (ff >> 14) & 1, mf: (ff >> 13) & 1, frag: ff & 0x1fff, ttl: u[off + 8], proto: u[off + 9], src: u32(u, off + 12), dst: u32(u, off + 16), ihl, off };
  const end = Math.min(u.length, off + total);
  const po = off + ihl;
  if (detail) {
    const csOk = checksum(u, off, ihl) === 0; const cs = u16(u, off + 10);
    ip.csumOk = csOk;
    const n = N('Internet Protocol Version 4, Src: ' + IP.str(ip.src) + ', Dst: ' + IP.str(ip.dst), off, ihl, [
      N('0100 .... = Version: 4', off, 1), N('.... ' + ((ihl / 4) >> 3 & 1) + ((ihl / 4) >> 2 & 1) + ((ihl / 4) >> 1 & 1) + ((ihl / 4) & 1) + ' = Header Length: ' + ihl + ' bytes (' + ihl / 4 + ')', off, 1),
      N('Differentiated Services Field: 0x' + hex(ip.tos, 2) + ' (DSCP: ' + (DSCP[ip.tos >> 2] || (ip.tos >> 2)) + ', ECN: Not-ECT)', off + 1, 1),
      N('Total Length: ' + total, off + 2, 2), N('Identification: 0x' + hex(ip.id, 4) + ' (' + ip.id + ')', off + 4, 2),
      N('Flags: 0x' + (ip.df ? '2' : '0') + (ip.df ? ", Don't fragment" : ''), off + 6, 2, [N('0... .... = Reserved bit: Not set', off + 6, 1), N('.' + ip.df + '.. .... = Don\'t fragment: ' + (ip.df ? 'Set' : 'Not set'), off + 6, 1), N('..' + ip.mf + '. .... = More fragments: ' + (ip.mf ? 'Set' : 'Not set'), off + 6, 1)]),
      N('Fragment Offset: ' + ip.frag, off + 6, 2), N('Time to Live: ' + ip.ttl, off + 8, 1), N('Protocol: ' + (IPPROTOS[ip.proto] || 'Unknown') + ' (' + ip.proto + ')', off + 9, 1),
      N('Header Checksum: 0x' + hex(cs, 4) + (csOk ? ' [correct]' : ' [incorrect]'), off + 10, 2), N('Source Address: ' + IP.str(ip.src), off + 12, 4), N('Destination Address: ' + IP.str(ip.dst), off + 16, 4)]);
    n.layer = 'ip'; p.tree.push(n);
  }
  p.ipPayload = u.subarray(po, end);
  if (ip.frag || ip.mf) return;
  if (ip.proto === 1) parseIcmp(p, u, po, end, detail);
  else if (ip.proto === 6) parseTcp(p, u, po, end, detail);
  else if (ip.proto === 17) parseUdp(p, u, po, end, detail);
  else if (ip.proto === 89) {
    const nodes = []; const r = parseOspf(u, po, end, detail, nodes);
    if (r) { p.ospf = r; if (detail) { const n = N('OSPF Header', po, end - po, nodes); n.layer = 'ospf'; p.tree.push(n); } }
  }
  else if (Codec.ipApps[ip.proto]) Codec.ipApps[ip.proto](p, u, po, end, detail);
  else if (detail && end > po) { const n = N('Données IP, protocole ' + ip.proto + ' (' + (end - po) + ' octets)', po, end - po); n.layer = 'data'; p.tree.push(n); }
}

function parseIcmp(p, u, o, end, detail) {
  if (end - o < 8) return;
  const type = u[o], code = u[o + 1];
  const ic = p.icmp = { type, code, id: 0, seq: 0, payload: u.subarray(o + 8, end), rest: u32(u, o + 4) };
  if (type === 0 || type === 8) { ic.id = u16(u, o + 4); ic.seq = u16(u, o + 6); }
  else if (type === 3 || type === 11 || type === 5) {
    const q = o + 8;
    if (end - q >= 20) {
      const qih = (u[q] & 15) * 4;
      const qi = { src: u32(u, q + 12), dst: u32(u, q + 16), proto: u[q + 9], ttl: u[q + 8] };
      if (end - q >= qih + 8) {
        if (qi.proto === 6 || qi.proto === 17) { qi.sport = u16(u, q + qih); qi.dport = u16(u, q + qih + 2); }
        else if (qi.proto === 1) { qi.id = u16(u, q + qih + 4); qi.seq = u16(u, q + qih + 6); qi.icmpType = u[q + qih]; }
      }
      ic.quote = qi;
    }
  }
  if (detail) {
    const csOk = checksum(u, o, end - o) === 0;
    const ch = [N('Type: ' + type + ' (' + (ICMP_NAMES[type] || '?') + ')', o, 1), N('Code: ' + code + (type === 3 ? ' (' + (UNREACH[code] || '?') + ')' : ''), o + 1, 1), N('Checksum: 0x' + hex(u16(u, o + 2), 4) + (csOk ? ' [correct]' : ' [incorrect]'), o + 2, 2)];
    if (type === 0 || type === 8) {
      ch.push(N('Identifier (BE): ' + ic.id + ' (0x' + hex(ic.id, 4) + ')', o + 4, 2), N('Identifier (LE): ' + (((ic.id & 255) << 8) | (ic.id >> 8)), o + 4, 2), N('Sequence Number (BE): ' + ic.seq, o + 6, 2), N('Sequence Number (LE): ' + (((ic.seq & 255) << 8) | (ic.seq >> 8)), o + 6, 2));
      if (end - o > 8) ch.push(N('Data (' + (end - o - 8) + ' bytes)', o + 8, end - o - 8, [N('Data: ' + hex2str(u, o + 8, Math.min(16, end - o - 8)) + '…', o + 8, end - o - 8)]));
    } else if (ic.quote) {
      const q = ic.quote;
      ch.push(N('Unused: 00000000', o + 4, 4));
      ch.push(N('Internet Protocol Version 4, Src: ' + IP.str(q.src) + ', Dst: ' + IP.str(q.dst), o + 8, end - o - 8, [N('Protocol: ' + (IPPROTOS[q.proto] || q.proto) + ' (' + q.proto + ')', o + 17, 1), N('Source Address: ' + IP.str(q.src), o + 20, 4), N('Destination Address: ' + IP.str(q.dst), o + 24, 4)]));
    }
    const n = N('Internet Control Message Protocol', o, end - o, ch); n.layer = 'icmp'; p.tree.push(n);
  }
}
function hex2str(u, o, l) { let s = ''; for (let i = 0; i < l; i++) s += hex(u[o + i], 2); return s; }

const TCPF = [[0x01, 'FIN'], [0x02, 'SYN'], [0x04, 'RST'], [0x08, 'PSH'], [0x10, 'ACK'], [0x20, 'URG']];
Codec.tcpFlagsStr = f => TCPF.filter(x => f & x[0]).map(x => x[1]).join(', ') || '<None>';
function parseTcp(p, u, o, end, detail) {
  if (end - o < 20) return;
  const hl = (u[o + 12] >> 4) * 4; if (hl < 20 || o + hl > end) return;
  const t = p.tcp = { sport: u16(u, o), dport: u16(u, o + 2), seq: u32(u, o + 4), ack: u32(u, o + 8), hl, flags: u[o + 13] & 0x3f, win: u16(u, o + 14), payload: u.subarray(o + hl, end), mss: 0 };
  for (let i = o + 20; i < o + hl;) { const k = u[i]; if (k === 0) break; if (k === 1) { i++; continue; } const l = u[i + 1]; if (k === 2 && l === 4) t.mss = u16(u, i + 2); i += l; }
  const pl = t.payload.length; t.len = pl;
  const nodes = [];
  if (detail) {
    const ip = p.ip;
    const cs = u16(u, o + 16);
    const csOk = checksum(u, o, end - o, pseudo(ip.src, ip.dst, 6, end - o)) === 0;
    const fl = t.flags;
    const fch = [['1', 'Reserved'], ['', '']].slice(0, 0);
    const fbit = (m, nm) => N(bitLine(fl, m) + ' = ' + nm + ': ' + ((fl & m) ? 'Set' : 'Not set'), o + 12, 2);
    const n = N('Transmission Control Protocol, Src Port: ' + t.sport + ', Dst Port: ' + t.dport + ', Seq: ' + t.seq + ', Len: ' + pl, o, hl, [
      N('Source Port: ' + t.sport, o, 2), N('Destination Port: ' + t.dport, o + 2, 2), N('[TCP Segment Len: ' + pl + ']', o + 12, 1),
      N('Sequence Number (raw): ' + t.seq, o + 4, 4), N('Acknowledgment Number (raw): ' + t.ack, o + 8, 4),
      N((hl / 4).toString(2).padStart(4, '0') + ' .... = Header Length: ' + hl + ' bytes (' + hl / 4 + ')', o + 12, 1),
      N('Flags: 0x' + hex(fl, 3) + ' (' + Codec.tcpFlagsStr(fl) + ')', o + 12, 2, [fbit(0x20, 'Urgent'), fbit(0x10, 'Acknowledgment'), fbit(0x08, 'Push'), fbit(0x04, 'Reset'), fbit(0x02, 'Syn'), fbit(0x01, 'Fin')]),
      N('Window: ' + t.win, o + 14, 2), N('Checksum: 0x' + hex(cs, 4) + (csOk ? ' [correct]' : ' [incorrect]'), o + 16, 2), N('Urgent Pointer: 0', o + 18, 2)]);
    if (hl > 20) n.ch.push(N('Options: (' + (hl - 20) + ' bytes)' + (t.mss ? ', Maximum segment size' : ''), o + 20, hl - 20, t.mss ? [N('TCP Option - Maximum segment size: ' + t.mss + ' bytes', o + 20, 4)] : null));
    n.layer = 'tcp'; p.tree.push(n);
  }
  if (pl) appTcp(p, u, o + hl, end, detail);
}
function bitLine(fl, m) { // ...x .... : position textuelle du bit dans les 12 bits de flags
  let s = ''; for (let b = 11; b >= 0; b--) { s += (1 << b) === m ? ((fl & m) ? '1' : '0') : '.'; if (b % 4 === 0 && b) s += ' '; } return s;
}
function parseUdp(p, u, o, end, detail) {
  if (end - o < 8) return;
  const t = p.udp = { sport: u16(u, o), dport: u16(u, o + 2), len: u16(u, o + 4), payload: u.subarray(o + 8, end) };
  if (detail) {
    const ip = p.ip; const cs = u16(u, o + 6);
    const csOk = cs === 0 || checksum(u, o, end - o, pseudo(ip.src, ip.dst, 17, end - o)) === 0;
    const n = N('User Datagram Protocol, Src Port: ' + t.sport + ', Dst Port: ' + t.dport, o, 8, [N('Source Port: ' + t.sport, o, 2), N('Destination Port: ' + t.dport, o + 2, 2), N('Length: ' + t.len, o + 4, 2), N('Checksum: 0x' + hex(cs, 4) + (csOk ? ' [correct]' : ' [incorrect]'), o + 6, 2), N('[UDP payload: ' + t.payload.length + ' bytes]', o + 8, 0)]);
    n.layer = 'udp'; p.tree.push(n);
  }
  if (t.payload.length) appUdp(p, u, o + 8, end, detail);
}
function appUdp(p, u, o, end, detail) {
  const { sport, dport } = p.udp; const nodes = [];
  if (sport === 67 || sport === 68 || dport === 67 || dport === 68) {
    const d = parseDhcp(u, o, end); if (!d) return;
    p.dhcp = d;
    if (detail) {
      const OP = d.op === 1 ? 'Boot Request (1)' : 'Boot Reply (2)';
      const ch = [N('Message type: ' + OP, o, 1), N('Hardware type: Ethernet (0x01)', o + 1, 1), N('Hardware address length: 6', o + 2, 1), N('Hops: ' + u[o + 3], o + 3, 1), N('Transaction ID: 0x' + hex(d.xid, 8), o + 4, 4), N('Seconds elapsed: ' + d.secs, o + 8, 2),
        N('Bootp flags: 0x' + hex(d.flags, 4) + (d.flags & 0x8000 ? ' (Broadcast)' : ' (Unicast)'), o + 10, 2),
        N('Client IP address: ' + IP.str(d.ciaddr), o + 12, 4), N('Your (client) IP address: ' + IP.str(d.yiaddr), o + 16, 4), N('Next server IP address: ' + IP.str(d.siaddr), o + 20, 4), N('Relay agent IP address: ' + IP.str(d.giaddr), o + 24, 4),
        N('Client MAC address: ' + Codec.macLabel(d.chaddr) + ' (' + d.chaddr + ')', o + 28, 6), N('Client hardware address padding: 00000000000000000000', o + 34, 10),
        N('Server host name not given', o + 44, 64), N('Boot file name not given', o + 108, 128), N('Magic cookie: DHCP', o + 236, 4)];
      const ON = { 1: 'Subnet Mask', 3: 'Router', 6: 'Domain Name Server', 12: 'Host Name', 15: 'Domain Name', 50: 'Requested IP Address', 51: 'IP Address Lease Time', 53: 'DHCP Message Type', 54: 'DHCP Server Identifier', 55: 'Parameter Request List', 58: 'Renewal Time Value', 59: 'Rebinding Time Value', 61: 'Client identifier' };
      d.optList.forEach(x => {
        const v = x.val; let vs;
        if (x.code === 53) vs = '(' + DHCP_TYPES[v[0]] + ')'; else if ([1, 50, 54].includes(x.code)) vs = IP.str(u32(v, 0));
        else if (x.code === 3 || x.code === 6) { vs = ''; for (let i = 0; i < v.length; i += 4) vs += (i ? ', ' : '') + IP.str(u32(v, i)); }
        else if ([51, 58, 59].includes(x.code)) vs = u32(v, 0) + ' (' + u32(v, 0) + 's)'; else if (x.code === 12 || x.code === 15) vs = bytesStr(v, 0, v.length);
        else if (x.code === 61) vs = 'Hardware type: Ethernet (0x01), ' + MAC.fromBytes(v, 1); else if (x.code === 55) vs = v.length + ' options';
        else vs = hex2str(v, 0, v.length);
        ch.push(N('Option: (' + x.code + ') ' + (ON[x.code] || 'Option ' + x.code) + ': ' + vs, x.off, x.len, [N('Length: ' + (x.len - 2), x.off + 1, 1), N('Value: ' + vs, x.off + 2, x.len - 2)]));
      });
      ch.push(N('Option: (255) End', end > o ? (d.optList.length ? d.optList[d.optList.length - 1].off + d.optList[d.optList.length - 1].len : o + 240) : o, 1));
      const n = N('Dynamic Host Configuration Protocol (' + DHCP_TYPES[d.msgType] + ')', o, end - o, ch); n.layer = 'dhcp'; p.tree.push(n);
    }
    return;
  }
  if (sport === 53 || dport === 53) {
    const d = parseDns(u, o, end, detail, nodes); if (!d) return; p.dns = d;
    if (detail) { const n = N('Domain Name System (' + (d.qr ? 'response' : 'query') + ')', o, end - o, nodes); n.layer = 'dns'; p.tree.push(n); }
    return;
  }
  if (dport === 520 && sport === 520) {
    const r = parseRip(u, o, end); if (!r) return; p.rip = r;
    if (detail) {
      const ch = [N('Command: ' + (r.cmd === 1 ? 'Request (1)' : 'Response (2)'), o, 1), N('Version: RIPv' + r.ver + ' (' + r.ver + ')', o + 1, 1)];
      r.entries.forEach(e => ch.push(N('IP Address: ' + IP.str(e.net) + ', Metric: ' + e.metric, e.off, 20, [N('Address Family: IP (2)', e.off, 2), N('IP Address: ' + IP.str(e.net), e.off + 4, 4), N('Netmask: ' + IP.str(e.mask), e.off + 8, 4), N('Next Hop: ' + IP.str(e.nh), e.off + 12, 4), N('Metric: ' + e.metric, e.off + 16, 4)])));
      const n = N('Routing Information Protocol', o, end - o, ch); n.layer = 'rip'; p.tree.push(n);
    }
    return;
  }
  for (const f of Codec.udpApps) { if (f(p, u, o, end, detail)) return; }
  if (detail) { const n = N('Data (' + (end - o) + ' bytes)', o, end - o, [N('Data: ' + hex2str(u, o, Math.min(end - o, 24)) + (end - o > 24 ? '…' : ''), o, end - o)]); n.layer = 'data'; p.tree.push(n); }
}
function appTcp(p, u, o, end, detail) {
  const { sport, dport } = p.tcp; const nodes = [];
  if (sport === 80 || dport === 80 || sport === 8080 || dport === 8080) {
    const h = parseHttp(u, o, end, detail, nodes);
    if (h) { p.http = h; if (detail) { nodes.forEach(n => { n.layer = 'http'; p.tree.push(n); }); } return; }
  }
  if (sport === 443 || dport === 443) {
    const t = parseTls(u, o, end, detail, nodes);
    if (t) { p.tls = t; if (detail) nodes.forEach(n => { n.layer = 'tls'; p.tree.push(n); }); return; }
  }
  const txt = bytesStr(u, o, Math.min(end - o, 64));
  if ((sport === 22 || dport === 22) && /^SSH-/.test(txt)) {
    p.ssh = { banner: txt.split('\r')[0].split('\n')[0] };
    if (detail) { const n = N('SSH Protocol', o, end - o, [N('Protocol: ' + p.ssh.banner, o, end - o)]); n.layer = 'ssh'; p.tree.push(n); } return;
  }
  if (sport === 22 || dport === 22) {
    p.ssh = { encrypted: true };
    if (detail) { const n = N('SSH Protocol', o, end - o, [N('Encrypted packet (len=' + (end - o) + ')', o, end - o)]); n.layer = 'ssh'; p.tree.push(n); } return;
  }
  if (sport === 23 || dport === 23) {
    p.telnet = { data: bytesStr(u, o, end - o) };
    if (detail) { const n = N('Telnet', o, end - o, [N('Data: ' + p.telnet.data.replace(/\r/g, '\\r').replace(/\n/g, '\\n'), o, end - o)]); n.layer = 'telnet'; p.tree.push(n); } return;
  }
  if (detail) { const n = N('Data (' + (end - o) + ' bytes)', o, end - o, [N('Data: ' + hex2str(u, o, Math.min(end - o, 24)) + (end - o > 24 ? '…' : ''), o, end - o), N('[Length: ' + (end - o) + ']', o, 0)]); n.layer = 'data'; p.tree.push(n); }
}

Codec._h = { N, hex, u16, u32, hex2str, bytesStr, Writer, checksum, concat, strBytes };
NS.Codec = Codec;
})(typeof window !== 'undefined' ? window : globalThis);
