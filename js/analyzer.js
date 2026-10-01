/* analyzer.js — moteur d'analyse de trames (sans DOM) : résumé, filtres d'affichage, flux TCP, statistiques, pcap */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { Codec, IP, MAC, B } = NS;
const A = {};

/* ------------------------------------------------------------------ résumé d'une trame */
const COLORS = {
  tcp: ['#e7e6ff', '#12272e'], udp: ['#daeeff', '#12272e'], icmp: ['#fce0ff', '#12272e'], arp: ['#faf0d7', '#12272e'],
  http: ['#e4ffc7', '#12272e'], dns: ['#daeeff', '#12272e'], dhcp: ['#daeeff', '#12272e'], tls: ['#e7e6ff', '#12272e'], ssh: ['#e7e6ff', '#12272e'],
  telnet: ['#e7e6ff', '#12272e'], stp: ['#d6e8ff', '#12272e'], rip: ['#daeeff', '#12272e'], ospf: ['#daeeff', '#12272e'], other: ['#ffffff', '#12272e'],
  vpn: ['#e8dcff', '#12272e'], aaa: ['#ffe9c2', '#12272e'], voip: ['#d7f5d0', '#12272e'], rst: ['#a40000', '#fffc9c'], syn: ['#a0a0a0', '#12272e'], bad: ['#12272e', '#ff5f5f'], err: ['#ffd0d0', '#12272e'],
};
A.COLORS = COLORS;
const ipS = IP.str;
const tcpKey = (ip) => null;

function tcpStreamInfo(ctx, p) {
  const t = p.tcp, ip = p.ip;
  const a = ip.src + ':' + t.sport, b = ip.dst + ':' + t.dport;
  const key = a < b ? a + '|' + b : b + '|' + a;
  let st = ctx.streams.get(key);
  if (!st) { st = { id: ctx.streams.size, key, isn: {}, first: a, n: 0 }; ctx.streams.set(key, st); }
  const dir = a === st.first ? 0 : 1;
  if (st.isn[dir] === undefined) st.isn[dir] = t.seq;
  const rel = ((t.seq - st.isn[dir]) >>> 0);
  let relAck = null; if ((t.flags & 0x10) && st.isn[1 - dir] !== undefined) relAck = ((t.ack - st.isn[1 - dir]) >>> 0);
  st.n++;
  return { id: st.id, dir, rel, relAck };
}
function newCtx() { return { streams: new Map(), cache: new Map() }; }
A.newCtx = newCtx;

function info(p, s) {
  if (p.bad) return p.bad;
  if (p.lacp) { const a = p.lacp.actor; return 'Actor Port = ' + a.port + ' Partner Port = ' + p.lacp.partner.port + ' [' + (a.state & 1 ? 'Active' : 'Passive') + (a.state & 4 ? ', Aggregation' : '') + (a.state & 8 ? ', Sync' : '') + (a.state & 16 ? ', Collecting' : '') + (a.state & 32 ? ', Distributing' : '') + ']'; }
  if (p.pagp) return 'Port Aggregation Protocol  Device ' + p.pagp.devId + '  ' + (p.pagp.flags & 2 ? 'Auto' : 'Desirable');
  if (p.stp && p.stp.pvst) return (p.stp.rstp ? 'RST. Root = ' : 'Conf. Root = ') + p.stp.rootPri + '/' + p.stp.vlan + '/' + p.stp.rootMac + '  Cost = ' + p.stp.cost + '  Port = 0x' + p.stp.portId.toString(16).padStart(4, '0');
  if (p.stp && p.stp.rstp) return 'RST. Root = ' + p.stp.rootPri + '/' + (p.stp.rootPri & 0xfff) + '/' + p.stp.rootMac + '  Cost = ' + p.stp.cost + '  Port = 0x' + p.stp.portId.toString(16).padStart(4, '0') + (p.stp.proposal ? ' [Proposal]' : '') + (p.stp.agreement ? ' [Agreement]' : '');
  if (p.stp) return 'Conf. Root = ' + p.stp.rootPri + '/' + (p.stp.rootPri & 0xfff) + '/' + p.stp.rootMac + '  Cost = ' + p.stp.cost + '  Port = 0x' + p.stp.portId.toString(16).padStart(4, '0');
  if (p.llc) return 'IEEE 802.3, LLC DSAP 0x' + p.llc.dsap.toString(16);
  if (p.arp) {
    const a = p.arp;
    if (a.op === 1) return (a.spa === a.tpa ? 'ARP Announcement for ' + ipS(a.tpa) : 'Who has ' + ipS(a.tpa) + '? Tell ' + ipS(a.spa));
    if (a.op === 2) return ipS(a.spa) + ' is at ' + a.sha;
    return 'ARP opcode ' + a.op;
  }
  if (p.icmp6) {
    const c = p.icmp6, I6 = NS.IP6.str, nm = Codec.ICMP6_NAMES[c.type] || 'type ' + c.type;
    if (c.type === 128 || c.type === 129) return nm.padEnd(22) + ' id=0x' + c.id.toString(16).padStart(4, '0') + ', seq=' + c.seq + ', hop limit=' + p.ip6.hop;
    if (c.type === 135) return 'Neighbor Solicitation for ' + I6(c.target) + (c.opts && c.opts.find(o => o.t === 1) ? ' from ' + c.opts.find(o => o.t === 1).mac : '');
    if (c.type === 136) return 'Neighbor Advertisement ' + I6(c.target) + ' (' + [c.r ? 'rtr' : '', c.s ? 'sol' : '', c.o ? 'ovr' : ''].filter(Boolean).join(', ') + ')' + (c.opts && c.opts.find(o => o.t === 2) ? ' is at ' + c.opts.find(o => o.t === 2).mac : '');
    if (c.type === 133) return 'Router Solicitation' + (c.opts && c.opts.find(o => o.t === 1) ? ' from ' + c.opts.find(o => o.t === 1).mac : '');
    if (c.type === 134) return 'Router Advertisement' + (c.opts && c.opts.find(o => o.t === 1) ? ' from ' + c.opts.find(o => o.t === 1).mac : '');
    if (c.type === 1) return nm + ' (' + (Codec.UNREACH6[c.code] || 'code ' + c.code) + ')';
    return nm + (c.type === 3 ? ' (hop limit exceeded in transit)' : c.type === 2 ? ' (MTU ' + c.mtu + ')' : '');
  }
  if (p.icmp) {
    const c = p.icmp, nm = Codec.ICMP_NAMES[c.type] || 'type ' + c.type;
    if (c.type === 0 || c.type === 8) return nm.padEnd(22) + ' id=0x' + c.id.toString(16).padStart(4, '0') + ', seq=' + c.seq + '/' + (((c.seq & 255) << 8) | (c.seq >> 8)) + ', ttl=' + p.ip.ttl;
    if (c.type === 3) return nm + ' (' + (Codec.UNREACH[c.code] || 'code ' + c.code) + ')';
    return nm + (c.code ? ' (code ' + c.code + ')' : ' (' + (c.type === 11 ? 'Time to live exceeded in transit' : '') + ')').replace(' ()', '');
  }
  if (p.dhcp) {
    const T = { 1: 'DHCP Discover', 2: 'DHCP Offer', 3: 'DHCP Request', 4: 'DHCP Decline', 5: 'DHCP ACK', 6: 'DHCP NAK', 7: 'DHCP Release', 8: 'DHCP Inform' };
    return (T[p.dhcp.opts.msgType] || 'DHCP') + ' '.repeat(3) + '- Transaction ID 0x' + p.dhcp.xid.toString(16);
  }
  if (p.dns) {
    const d = p.dns, q = d.questions[0];
    const rc = ['', '', ' Server failure', ' No such name', ' Not implemented', ' Refused'][d.rcode] || '';
    if (!d.qr) return 'Standard query 0x' + d.id.toString(16).padStart(4, '0') + ' ' + (q ? q.type + ' ' + q.name : '');
    return 'Standard query response 0x' + d.id.toString(16).padStart(4, '0') + rc + ' ' + (q ? q.type + ' ' + q.name : '') + d.answers.map(a => ' ' + a.type + ' ' + a.data).join('');
  }
  if (p.sip) return Codec.sipSummary(p.sip);
  if (p.rtp) return 'PT=' + (Codec.RTP_PT[p.rtp.pt] || p.rtp.pt) + ', SSRC=0x' + p.rtp.ssrc.toString(16).padStart(8, '0') + ', Seq=' + p.rtp.seq + ', Time=' + p.rtp.ts + (p.rtp.mark ? ', Mark' : '');
  if (p.cdp) return Codec.cdpSummary(p.cdp);
  if (p.radius) return Codec.radiusSummary(p.radius);
  if (p.eapol) return Codec.eapolSummary(p.eapol);
  if (p.isakmp) return Codec.ikeSummary(p.isakmp);
  if (p.esp) return 'ESP (SPI=0x' + p.esp.spi.toString(16).padStart(8, '0') + ')';
  if (p.gre) return 'Encapsulated ' + (p.gre.proto === 0x0800 ? 'IP' : '0x' + p.gre.proto.toString(16)) + (p.gre.key !== null ? ' (key 0x' + p.gre.key.toString(16) + ')' : '');
  if (p.snmp) return Codec.snmpSummary(p.snmp);
  if (p.syslog) return Codec.SYSLOG_FAC[p.syslog.facility].toUpperCase() + '.' + Codec.SYSLOG_SEV[p.syslog.severity].toUpperCase() + ': ' + p.syslog.msg;
  if (p.rip) return p.rip.cmd === 1 ? 'Request' : 'Response';
  if (p.ospf) return Codec.OSPF_TYPES[p.ospf.type] || 'OSPF';
  if (p.tcp) {
    const t = p.tcp, pre = t.sport + ' → ' + t.dport + ' [' + Codec.tcpFlagsStr(t.flags) + '] ';
    if (p.http) { const h = p.http; return h.isReq ? h.method + ' ' + h.uri + ' HTTP/' + h.version : 'HTTP/' + h.version + ' ' + h.status + ' ' + h.reason + (h.headers['content-type'] ? '  (' + h.headers['content-type'].split(';')[0] + ')' : ''); }
    if (p.tls) return p.tls.records.map(r => r.type === 22 ? (r.hsType === 1 ? 'Client Hello' + (r.sni ? ' (SNI=' + r.sni + ')' : '') : r.hsType === 2 ? 'Server Hello' : r.hsType === 11 ? 'Certificate' : r.hsType === 14 ? 'Server Hello Done' : r.hsType === 16 ? 'Client Key Exchange' : 'Handshake') : r.type === 20 ? 'Change Cipher Spec' : r.type === 21 ? 'Alert' : 'Application Data').join(', ');
    if (p.ssh) return (t.dport === 22 ? 'Client: ' : 'Server: ') + (p.ssh.banner ? 'Protocol (' + p.ssh.banner + ')' : 'Encrypted packet (len=' + t.len + ')');
    if (p.telnet) return 'Telnet Data ...';
    const sn = s.tcp;
    return pre + 'Seq=' + sn.rel + (sn.relAck !== null ? ' Ack=' + sn.relAck : '') + ' Win=' + t.win + ' Len=' + t.len + (t.mss ? ' MSS=' + t.mss : '');
  }
  if (p.udp) return p.udp.sport + ' → ' + p.udp.dport + ' Len=' + p.udp.payload.length;
  if (p.ip) return 'Protocole IP ' + p.ip.proto;
  if (p.ip6) return 'IPv6 next header ' + p.ip6.next;
  return 'Ethernet type 0x' + (p.eth ? p.eth.type.toString(16) : '?');
}

function protoOf(p) {
  if (p.bad) return 'Malformed';
  if (p.lacp) return 'LACP'; if (p.pagp) return 'PAgP';
  if (p.stp) return p.stp.pvst ? 'PVST+' : p.stp.rstp ? 'RSTP' : 'STP';
  if (p.llc) return 'LLC';
  if (p.arp) return 'ARP';
  if (p.icmp6) return 'ICMPv6';
  if (p.icmp) return 'ICMP';
  if (p.dhcp) return 'DHCP';
  if (p.dns) return 'DNS';
  if (p.sip) return 'SIP'; if (p.rtp) return 'RTP'; if (p.cdp) return 'CDP';
  if (p.eapol) return 'EAPOL'; if (p.radius) return 'RADIUS';
  if (p.isakmp) return 'ISAKMP'; if (p.esp) return 'ESP'; if (p.gre) return 'GRE';
  if (p.snmp) return 'SNMP'; if (p.syslog) return 'SYSLOG';
  if (p.rip) return 'RIPv' + p.rip.ver;
  if (p.ospf) return 'OSPF';
  if (p.http) return 'HTTP';
  if (p.tls) return 'TLSv1.2';
  if (p.ssh) return 'SSHv2';
  if (p.telnet) return 'TELNET';
  if (p.tcp) return 'TCP';
  if (p.udp) return 'UDP';
  if (p.ip) return 'IPv4';
  if (p.ip6) return 'IPv6';
  return 'Ethernet';
}
function protoList(p) {
  const l = ['frame', 'eth']; if (p.eth && p.eth.vlan) l.push('vlan'); if (p.llc) l.push('llc');
  if (p.ip) l.push('ip'); if (p.ip6) l.push('ipv6'); if (p.icmp6) l.push('icmpv6'); if (p.arp) l.push('arp'); if (p.icmp) l.push('icmp'); if (p.tcp) l.push('tcp'); if (p.udp) l.push('udp');
  if (p.dhcp) l.push('dhcp', 'bootp'); if (p.dns) l.push('dns'); if (p.http) l.push('http'); if (p.tls) l.push('tls', 'ssl'); if (p.ssh) l.push('ssh');
  if (p.telnet) l.push('telnet'); if (p.stp) l.push('stp'); if (p.lacp) l.push('lacp'); if (p.pagp) l.push('pagp'); if (p.stp && p.stp.rstp) l.push('rstp'); if (p.rip) l.push('rip'); if (p.ospf) l.push('ospf'); if (p.snmp) l.push('snmp'); if (p.syslog) l.push('syslog'); if (p.isakmp) l.push('isakmp'); if (p.esp) l.push('esp');
  if (p.sip) l.push('sip'); if (p.rtp) l.push('rtp'); if (p.cdp) l.push('cdp');
  if (p.eapol) l.push('eapol'); if (p.eap) l.push('eap'); if (p.radius) l.push('radius');
  if (p.gre) { l.push('gre'); if (p.gre.inner) protoList(p.gre.inner).filter(x => x !== 'frame' && x !== 'eth').forEach(x => l.push(x)); }
  return l;
}
function colorOf(p) {
  if (p.bad) return COLORS.bad;
  if (p.tcp && (p.tcp.flags & 4)) return COLORS.rst;
  if (p.tcp && (p.tcp.flags & 3) && !p.http) return COLORS.syn;
  if (p.icmp && (p.icmp.type === 3 || p.icmp.type === 11)) return COLORS.err;
  if (p.icmp6 && p.icmp6.type < 128) return COLORS.err;
  if (p.icmp6) return COLORS.icmp;
  if (p.radius || p.eapol || p.eap) return COLORS.aaa;
  if (p.sip || p.rtp || p.cdp) return COLORS.voip;
  if (p.http) return COLORS.http; if (p.dns || p.snmp || p.syslog) return COLORS.dns; if (p.dhcp) return COLORS.dhcp; if (p.tls) return COLORS.tls; if (p.ssh) return COLORS.ssh; if (p.telnet) return COLORS.telnet;
  if (p.stp || p.lacp || p.pagp) return COLORS.stp; if (p.rip) return COLORS.rip; if (p.ospf) return COLORS.ospf; if (p.arp) return COLORS.arp; if (p.icmp) return COLORS.icmp;
  if (p.tcp) return COLORS.tcp; if (p.udp) return COLORS.udp; return COLORS.other;
}

/* rec = {no,t,link,from,bytes} -> résumé (mis en cache dans ctx) */
A.summarize = function (ctx, rec) {
  let s = ctx.cache.get(rec.no); if (s) return s;
  const p = Codec.parse(rec.bytes, false);
  s = { no: rec.no, t: rec.t, rec, p, len: rec.bytes.length, protos: protoList(p) };
  const e = (p.gre && p.gre.inner) || p;
  if (e.tcp) s.tcp = tcpStreamInfo(ctx, e);
  s.proto = protoOf(e); s.color = colorOf(e);
  s.src = p.ip6 ? NS.IP6.str(p.ip6.src) : p.ip ? ipS(p.ip.src) : p.arp ? p.arp.sha : p.eth ? p.eth.src : '';
  s.dst = p.ip6 ? NS.IP6.str(p.ip6.dst) : p.ip ? ipS(p.ip.dst) : p.arp ? (p.arp.op === 1 ? 'Broadcast' : p.arp.tha) : p.eth ? p.eth.dst : '';
  if (p.eth && !p.ip && !p.ip6 && !p.arp) { s.src = Codec.macLabel(p.eth.src); s.dst = Codec.macLabel(p.eth.dst); }
  if (p.arp) { s.src = Codec.macLabel(p.eth.src); s.dst = Codec.macLabel(p.eth.dst); }
  s.info = info(e, s);
  ctx.cache.set(rec.no, s);
  return s;
};
/* arbre détaillé complet : trame + nœuds TCP enrichis (numéros relatifs) */
A.detail = function (ctx, rec) {
  const s = A.summarize(ctx, rec); const p = Codec.parse(rec.bytes, true);
  const tree = p.tree.slice();
  const pr = [];
  let l = s.proto; const nm = { TCP: 'Transmission Control Protocol' };
  const names = tree.map(n => n.layer).filter(x => x !== 'pad' && x !== 'data');
  const fr = { t: 'Frame ' + rec.no + ': ' + rec.bytes.length + ' bytes on wire (' + rec.bytes.length * 8 + ' bits), ' + rec.bytes.length + ' bytes captured (' + rec.bytes.length * 8 + ' bits) on interface ' + rec.from.dev.name + ' ' + rec.from.short, off: 0, len: 0, layer: 'frame', ch: [
    { t: 'Interface name: ' + rec.from.dev.name + ' ' + rec.from.name, off: 0, len: 0 },
    { t: 'Arrival Time: ' + new Date(NS.T0 + rec.t).toISOString().replace('T', ' ').replace('Z', ''), off: 0, len: 0 },
    { t: '[Time since first capture: ' + (rec.t / 1000).toFixed(6) + ' seconds]', off: 0, len: 0 },
    { t: 'Frame Number: ' + rec.no, off: 0, len: 0 }, { t: 'Frame Length: ' + rec.bytes.length + ' bytes (' + rec.bytes.length * 8 + ' bits)', off: 0, len: 0 },
    { t: '[Protocols in frame: ' + s.protos.filter(x => x !== 'frame' && x !== 'bootp' && x !== 'ssl').join(':') + ']', off: 0, len: 0 }, { t: '[Coloring Rule Name: ' + s.proto + ']', off: 0, len: 0 }] };
  if (p.tcp && s.tcp) {
    const tn = tree.find(n => n.layer === 'tcp');
    if (tn) {
      const o = tn.off;
      tn.ch.splice(1, 0, { t: '[Stream index: ' + s.tcp.id + ']', off: o, len: 0 });
      const i = tn.ch.findIndex(c => /^Sequence Number \(raw\)/.test(c.t));
      tn.ch.splice(i, 0, { t: 'Sequence Number: ' + s.tcp.rel + '    (relative sequence number)', off: o + 4, len: 4 });
      const j = tn.ch.findIndex(c => /^Acknowledgment Number \(raw\)/.test(c.t));
      if (s.tcp.relAck !== null) tn.ch.splice(j, 0, { t: 'Acknowledgment Number: ' + s.tcp.relAck + '    (relative ack number)', off: o + 8, len: 4 });
    }
  }
  return [fr].concat(tree);
};

/* ------------------------------------------------------------------ filtres d'affichage */
const macNorm = m => String(m).toLowerCase().replace(/-/g, ':');
function ipNum(x) { return typeof x === 'number' ? x : IP.parse(x); }
const FIELDS = {
  'frame.number': s => [s.no], 'frame.len': s => [s.len], 'frame.time_relative': s => [s.t / 1000],
  'eth.src': s => s.p.eth ? [s.p.eth.src] : null, 'eth.dst': s => s.p.eth ? [s.p.eth.dst] : null, 'eth.addr': s => s.p.eth ? [s.p.eth.src, s.p.eth.dst] : null,
  'eth.type': s => s.p.eth ? [s.p.eth.type] : null,
  'vlan.id': s => s.p.eth && s.p.eth.vlan ? [s.p.eth.vlan.vid] : null, 'vlan.priority': s => s.p.eth && s.p.eth.vlan ? [s.p.eth.vlan.pcp] : null,
  'arp.opcode': s => s.p.arp ? [s.p.arp.op] : null, 'arp.src.proto_ipv4': s => s.p.arp ? [s.p.arp.spa] : null, 'arp.dst.proto_ipv4': s => s.p.arp ? [s.p.arp.tpa] : null,
  'arp.src.hw_mac': s => s.p.arp ? [s.p.arp.sha] : null, 'arp.dst.hw_mac': s => s.p.arp ? [s.p.arp.tha] : null,
  'ip.src': s => s.p.ip ? [s.p.ip.src] : null, 'ip.dst': s => s.p.ip ? [s.p.ip.dst] : null, 'ip.addr': s => s.p.ip ? [s.p.ip.src, s.p.ip.dst] : null,
  'ip.ttl': s => s.p.ip ? [s.p.ip.ttl] : null, 'ip.proto': s => s.p.ip ? [s.p.ip.proto] : null, 'ip.len': s => s.p.ip ? [s.p.ip.total] : null, 'ip.id': s => s.p.ip ? [s.p.ip.id] : null,
  'ip.flags.df': s => s.p.ip ? [s.p.ip.df] : null, 'ip.flags.mf': s => s.p.ip ? [s.p.ip.mf] : null, 'ip.frag_offset': s => s.p.ip ? [s.p.ip.frag] : null,
  'icmp.type': s => s.p.icmp ? [s.p.icmp.type] : null, 'icmp.code': s => s.p.icmp ? [s.p.icmp.code] : null, 'icmp.ident': s => s.p.icmp ? [s.p.icmp.id] : null, 'icmp.seq': s => s.p.icmp ? [s.p.icmp.seq] : null,
  'tcp.srcport': s => s.p.tcp ? [s.p.tcp.sport] : null, 'tcp.dstport': s => s.p.tcp ? [s.p.tcp.dport] : null, 'tcp.port': s => s.p.tcp ? [s.p.tcp.sport, s.p.tcp.dport] : null,
  'tcp.len': s => s.p.tcp ? [s.p.tcp.len] : null, 'tcp.seq': s => s.p.tcp ? [s.tcp.rel] : null, 'tcp.ack': s => s.p.tcp && s.tcp.relAck !== null ? [s.tcp.relAck] : null,
  'tcp.window_size': s => s.p.tcp ? [s.p.tcp.win] : null, 'tcp.stream': s => s.p.tcp ? [s.tcp.id] : null, 'tcp.flags': s => s.p.tcp ? [s.p.tcp.flags] : null,
  'tcp.flags.syn': s => s.p.tcp ? [(s.p.tcp.flags >> 1) & 1] : null, 'tcp.flags.ack': s => s.p.tcp ? [(s.p.tcp.flags >> 4) & 1] : null, 'tcp.flags.fin': s => s.p.tcp ? [s.p.tcp.flags & 1] : null,
  'tcp.flags.reset': s => s.p.tcp ? [(s.p.tcp.flags >> 2) & 1] : null, 'tcp.flags.rst': s => s.p.tcp ? [(s.p.tcp.flags >> 2) & 1] : null, 'tcp.flags.push': s => s.p.tcp ? [(s.p.tcp.flags >> 3) & 1] : null,
  'udp.srcport': s => s.p.udp ? [s.p.udp.sport] : null, 'udp.dstport': s => s.p.udp ? [s.p.udp.dport] : null, 'udp.port': s => s.p.udp ? [s.p.udp.sport, s.p.udp.dport] : null, 'udp.length': s => s.p.udp ? [s.p.udp.len] : null,
  'dns.qry.name': s => s.p.dns ? s.p.dns.questions.map(q => q.name) : null, 'dns.qry.type': s => s.p.dns ? s.p.dns.questions.map(q => q.type) : null, 'dns.id': s => s.p.dns ? [s.p.dns.id] : null,
  'dns.flags.response': s => s.p.dns ? [s.p.dns.qr] : null, 'dns.flags.rcode': s => s.p.dns ? [s.p.dns.rcode] : null, 'dns.a': s => s.p.dns ? s.p.dns.answers.filter(a => a.type === 'A').map(a => a.data) : null, 'dns.resp.name': s => s.p.dns ? s.p.dns.answers.map(a => a.name) : null,
  'dhcp.option.dhcp': s => s.p.dhcp ? [s.p.dhcp.opts.msgType] : null, 'dhcp.id': s => s.p.dhcp ? [s.p.dhcp.xid] : null, 'dhcp.hw.mac_addr': s => s.p.dhcp ? [s.p.dhcp.chaddr] : null, 'dhcp.ip.your': s => s.p.dhcp ? [s.p.dhcp.yiaddr] : null,
  'http.request.method': s => s.p.http && s.p.http.isReq ? [s.p.http.method] : null, 'http.request.uri': s => s.p.http && s.p.http.isReq ? [s.p.http.uri] : null,
  'http.host': s => s.p.http && s.p.http.headers.host ? [s.p.http.headers.host] : null, 'http.response.code': s => s.p.http && !s.p.http.isReq ? [s.p.http.status] : null,
  'http.request': s => s.p.http && s.p.http.isReq ? [1] : null, 'http.response': s => s.p.http && !s.p.http.isReq ? [1] : null,
  'http.content_type': s => s.p.http && s.p.http.headers['content-type'] ? [s.p.http.headers['content-type']] : null,
  'tls.handshake.type': s => s.p.tls ? s.p.tls.records.filter(r => r.type === 22).map(r => r.hsType) : null, 'tls.record.content_type': s => s.p.tls ? s.p.tls.records.map(r => r.type) : null,
  'tls.handshake.extensions_server_name': s => s.p.tls ? s.p.tls.records.filter(r => r.sni).map(r => r.sni) : null,
  'telnet.data': s => s.p.telnet ? [s.p.telnet.data] : null,
  'stp.root.hw': s => s.p.stp ? [s.p.stp.rootMac] : null, 'stp.bridge.hw': s => s.p.stp ? [s.p.stp.brMac] : null, 'stp.root.cost': s => s.p.stp ? [s.p.stp.cost] : null,
  'rip.command': s => s.p.rip ? [s.p.rip.cmd] : null, 'rip.ip': s => s.p.rip ? s.p.rip.entries.map(e => e.net) : null,
  'ipv6.src': s => s.p.ip6 ? [s.p.ip6.src] : null, 'ipv6.dst': s => s.p.ip6 ? [s.p.ip6.dst] : null, 'ipv6.addr': s => s.p.ip6 ? [s.p.ip6.src, s.p.ip6.dst] : null, 'ipv6.hlim': s => s.p.ip6 ? [s.p.ip6.hop] : null, 'ipv6.nxt': s => s.p.ip6 ? [s.p.ip6.next] : null,
  'icmpv6.type': s => s.p.icmp6 ? [s.p.icmp6.type] : null, 'icmpv6.code': s => s.p.icmp6 ? [s.p.icmp6.code] : null, 'icmpv6.nd.ns.target_address': s => s.p.icmp6 && s.p.icmp6.type === 135 ? [s.p.icmp6.target] : null, 'icmpv6.nd.na.target_address': s => s.p.icmp6 && s.p.icmp6.type === 136 ? [s.p.icmp6.target] : null,
  'snmp.version': s => s.p.snmp ? [s.p.snmp.ver] : null, 'snmp.community': s => s.p.snmp ? [s.p.snmp.community] : null, 'snmp.name': s => s.p.snmp ? s.p.snmp.pdu.varbinds.map(v => v.oid) : null, 'snmp.request_id': s => s.p.snmp && s.p.snmp.pdu.reqId !== undefined ? [s.p.snmp.pdu.reqId] : null, 'snmp.error_status': s => s.p.snmp && s.p.snmp.pdu.errStatus !== undefined ? [s.p.snmp.pdu.errStatus] : null,
  'syslog.msg': s => s.p.syslog ? [s.p.syslog.msg] : null, 'syslog.facility': s => s.p.syslog ? [s.p.syslog.facility] : null, 'syslog.level': s => s.p.syslog ? [s.p.syslog.severity] : null,
  'gre.key': s => s.p.gre && s.p.gre.key !== null ? [s.p.gre.key] : null, 'gre.proto': s => s.p.gre ? [s.p.gre.proto] : null, 'esp.spi': s => s.p.esp ? [s.p.esp.spi] : null, 'esp.sequence': s => s.p.esp ? [s.p.esp.seq] : null,
  'sip.method': s => s.p.sip && s.p.sip.isReq ? [s.p.sip.method] : null, 'sip.status_code': s => s.p.sip && !s.p.sip.isReq ? [s.p.sip.status] : null, 'sip.call_id': s => s.p.sip ? [s.p.sip.callId] : null, 'sip.from.user': s => s.p.sip ? [s.p.sip.from] : null, 'sip.to.user': s => s.p.sip ? [s.p.sip.to] : null, 'sip.cseq': s => s.p.sip ? [s.p.sip.cseq] : null,
  'rtp.ssrc': s => s.p.rtp ? [s.p.rtp.ssrc] : null, 'rtp.p_type': s => s.p.rtp ? [s.p.rtp.pt] : null, 'rtp.seq': s => s.p.rtp ? [s.p.rtp.seq] : null, 'cdp.deviceid': s => s.p.cdp ? [s.p.cdp.device] : null, 'vlan.priority': s => s.p.eth && s.p.eth.vlan ? [s.p.eth.vlan.pcp] : null, 'ip.dsfield.dscp': s => s.p.ip ? [s.p.ip.tos >> 2] : null,
  'eapol.type': s => s.p.eapol ? [s.p.eapol.type] : null, 'eapol.version': s => s.p.eapol ? [s.p.eapol.ver] : null, 'eap.code': s => s.p.eap ? [s.p.eap.code] : null, 'eap.id': s => s.p.eap ? [s.p.eap.id] : null, 'eap.type': s => s.p.eap && s.p.eap.type !== null ? [s.p.eap.type] : null,
  'radius.code': s => s.p.radius ? [s.p.radius.code] : null, 'radius.id': s => s.p.radius ? [s.p.radius.id] : null, 'radius.User_Name': s => s.p.radius && s.p.radius.user ? [s.p.radius.user] : null,
  'isakmp.exchtype': s => s.p.isakmp ? [s.p.isakmp.exch] : null, 'isakmp.ispi': s => s.p.isakmp ? [s.p.isakmp.ic] : null, 'isakmp.rspi': s => s.p.isakmp ? [s.p.isakmp.rc] : null, 'isakmp.mid': s => s.p.isakmp ? [s.p.isakmp.mid] : null,
  'ospf.msg': s => s.p.ospf ? [s.p.ospf.type] : null, 'ospf.srcrouter': s => s.p.ospf ? [s.p.ospf.rid] : null, 'ospf.area_id': s => s.p.ospf ? [s.p.ospf.area] : null,
};
['ip.src', 'ip.dst', 'ip.addr', 'ip.ttl', 'ip.proto', 'icmp.type', 'icmp.code', 'tcp.port', 'tcp.srcport', 'tcp.dstport', 'udp.port', 'udp.srcport', 'udp.dstport'].forEach(n => { const f = FIELDS[n]; FIELDS[n] = s => { const a = f(s); const g = s.p.gre && s.p.gre.inner; if (!g) return a; const b = f(Object.assign({}, s, { p: g })); return a && b ? a.concat(b) : (a || b); }; });
const IPFIELD = /^(ip\.(src|dst|addr)|arp\.(src|dst)\.proto_ipv4|dns\.a|dhcp\.ip\.your|rip\.ip|ospf\.srcrouter|ospf\.area_id)$/;
const IP6FIELD = /^(ipv6\.(src|dst|addr)|icmpv6\.nd\.n[sa]\.target_address)$/;
const MACFIELD = /^(eth\.(src|dst|addr)|arp\.(src|dst)\.hw_mac|dhcp\.hw\.mac_addr|stp\.(root|bridge)\.hw)$/;
A.FIELD_NAMES = Object.keys(FIELDS);
const PROTO_ALIAS = { dot1x: 'eapol', ipv4: 'ip', bootp: 'dhcp', ssl: 'tls', ike: 'isakmp', ipsec: 'esp' };

function tokenize(src) {
  const t = []; let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"') { let j = i + 1, v = ''; while (j < src.length && src[j] !== '"') { if (src[j] === '\\' && j + 1 < src.length) { v += src[j + 1]; j += 2; } else v += src[j++]; } if (j >= src.length) throw new Error('Chaîne non terminée'); t.push({ k: 'str', v }); i = j + 1; continue; }
    const two = src.substr(i, 2);
    if (['==', '!=', '>=', '<=', '&&', '||'].includes(two)) { t.push({ k: 'op', v: two }); i += 2; continue; }
    if ('()<>!{}'.includes(c)) { t.push({ k: c === '(' || c === ')' || c === '{' || c === '}' ? c : 'op', v: c }); i++; continue; }
    const m = /^[A-Za-z0-9_.:\/\-]+/.exec(src.slice(i));
    if (!m) throw new Error("Caractère inattendu '" + c + "'");
    t.push({ k: 'word', v: m[0] }); i += m[0].length;
  }
  return t;
}
const OPW = { eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=', and: '&&', or: '||', not: '!' };

function parseValue(field, tok) {
  if (tok.k === 'str') return { s: tok.v };
  const w = tok.v;
  if (IP6FIELD.test(field)) {
    const c = w.includes('/') ? NS.IP6.parseCidr(w) : (NS.IP6.parse(w) === null ? null : { addr: NS.IP6.parse(w), plen: 128 }); if (!c) throw new Error('Adresse IPv6 invalide : ' + w);
    return { ip6: c.addr, plen: c.plen };
  }
  if (IPFIELD.test(field)) {
    const m = /^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?$/.exec(w); if (!m) throw new Error("Adresse IP invalide : " + w);
    const ip = IP.parse(m[1]); const bits = m[2] === undefined ? 32 : +m[2]; const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { ip: ip >>> 0, mask };
  }
  if (MACFIELD.test(field)) return { s: macNorm(w) };
  if (/^0x[0-9a-f]+$/i.test(w)) return { n: parseInt(w, 16) };
  if (/^-?\d+(\.\d+)?$/.test(w)) return { n: +w };
  if (/^(true|false)$/i.test(w)) return { n: /^true$/i.test(w) ? 1 : 0 };
  return { s: w };
}
function cmpVals(field, vals, op, rhs) {
  const test = v => {
    if (rhs.ip6 !== undefined) { const eq = typeof v === 'bigint' && NS.IP6.inNet(v, rhs.ip6, rhs.plen); return op === '==' ? eq : op === '!=' ? !eq : false; }
    if (rhs.ip !== undefined) { const x = ipNum(v) >>> 0; const eq = ((x & rhs.mask) >>> 0) === ((rhs.ip & rhs.mask) >>> 0); return op === '==' ? eq : op === '!=' ? !eq : false; }
    if (rhs.n !== undefined) { const x = typeof v === 'number' ? v : Number(v); switch (op) { case '==': return x === rhs.n; case '!=': return x !== rhs.n; case '>': return x > rhs.n; case '<': return x < rhs.n; case '>=': return x >= rhs.n; case '<=': return x <= rhs.n; } }
    let x = String(v), y = rhs.s;
    if (MACFIELD.test(field)) x = macNorm(x);
    switch (op) { case '==': return x === y; case '!=': return x !== y; case 'contains': return x.toLowerCase().indexOf(String(y).toLowerCase()) >= 0; case 'matches': return new RegExp(y, 'i').test(x); case '>': return x > y; case '<': return x < y; case '>=': return x >= y; case '<=': return x <= y; }
    return false;
  };
  if (op === '!=') return vals.every(test);           // Wireshark ≥ 3.6 : "tous différents"
  return vals.some(test);
}
/* compile("ip.addr == 10.0.0.1 && tcp.port == 80") -> fonction (résumé) -> bool ; lève Error si syntaxe invalide */
A.compile = function (src) {
  src = String(src || '').trim();
  if (!src) return null;
  const toks = tokenize(src).map(t => (t.k === 'word' && OPW[t.v] ? { k: 'op', v: OPW[t.v] } : t));
  let pos = 0;
  const peek = () => toks[pos], next = () => toks[pos++];
  function orE() { let l = andE(); while (peek() && peek().k === 'op' && peek().v === '||') { next(); const r = andE(); const a = l; l = s => a(s) || r(s); } return l; }
  function andE() { let l = notE(); while (peek() && peek().k === 'op' && peek().v === '&&') { next(); const r = notE(); const a = l; l = s => a(s) && r(s); } return l; }
  function notE() { if (peek() && peek().k === 'op' && peek().v === '!') { next(); const e = notE(); return s => !e(s); } return atom(); }
  function atom() {
    const t = next(); if (!t) throw new Error('Expression incomplète');
    if (t.k === '(') { const e = orE(); const c = next(); if (!c || c.k !== ')') throw new Error("Parenthèse ')' attendue"); return e; }
    if (t.k !== 'word') throw new Error('Terme inattendu : ' + (t.v || t.k));
    const name = t.v.toLowerCase();
    const n = peek();
    const isOp = n && (n.k === 'op' && ['==', '!=', '>', '<', '>=', '<='].includes(n.v) || n.k === 'word' && ['contains', 'matches', 'in'].includes(n.v.toLowerCase()));
    if (!isOp) {
      if (FIELDS[name] && name.indexOf('.') >= 0) return s => { const v = FIELDS[name](s); return !!(v && v.length && v.some(x => x !== 0 && x !== '' || typeof x === 'number' && (name.indexOf('flags.') >= 0))); };
      const pn = PROTO_ALIAS[name] || name;
      if (['frame', 'eth', 'vlan', 'llc', 'ip', 'arp', 'icmp', 'tcp', 'udp', 'dhcp', 'dns', 'http', 'tls', 'ssh', 'telnet', 'stp', 'rip', 'ospf', 'lacp', 'pagp', 'rstp', 'snmp', 'syslog', 'ipv6', 'icmpv6', 'gre', 'esp', 'isakmp', 'eapol', 'eap', 'radius', 'sip', 'rtp', 'cdp'].includes(pn)) return s => s.protos.includes(pn);
      throw new Error("Champ ou protocole inconnu : « " + t.v + " »");
    }
    const PN = PROTO_ALIAS[name] || name;
    if (!FIELDS[name] && ['frame', 'eth', 'ip', 'arp', 'icmp', 'tcp', 'udp', 'dhcp', 'dns', 'http', 'tls', 'ssh', 'telnet', 'stp', 'rip', 'ospf', 'lacp', 'pagp', 'rstp', 'snmp', 'syslog', 'ipv6', 'icmpv6', 'gre', 'esp', 'isakmp', 'eapol', 'eap', 'radius', 'sip', 'rtp', 'cdp'].includes(PN)) {
      const opx = next().v.toLowerCase(); if (opx !== 'contains' && opx !== 'matches') throw new Error("Opérateur « " + opx + " » invalide pour un protocole");
      const vt2 = next(); if (!vt2) throw new Error('Valeur attendue'); const pat = vt2.v;
      let re; try { re = opx === 'matches' ? new RegExp(pat, 'i') : null; } catch (e) { throw new Error('Expression régulière invalide'); }
      return s => s.protos.includes(PN) && (() => { const txt = B.bytesStr(s.rec.bytes, 0, s.rec.bytes.length); return re ? re.test(txt) : txt.toLowerCase().indexOf(String(pat).toLowerCase()) >= 0; })();
    }
    if (!FIELDS[name]) throw new Error("Champ inconnu : « " + t.v + " »");
    const f = FIELDS[name]; const opT = next(); let op = opT.v.toLowerCase();
    if (op === 'in') {
      const o = next(); if (!o || o.k !== '{') throw new Error("'{' attendu après in");
      const items = []; while (peek() && peek().k !== '}') items.push(parseValue(name, next())); if (!next()) throw new Error("'}' attendu");
      return s => { const v = f(s); return !!v && items.some(r => cmpVals(name, v, '==', r)); };
    }
    const vt = next(); if (!vt) throw new Error("Valeur attendue après l'opérateur");
    const rhs = parseValue(name, vt);
    if (op === 'matches') { try { new RegExp(rhs.s); } catch (e) { throw new Error('Expression régulière invalide'); } }
    return s => { const v = f(s); return !!v && v.length > 0 && cmpVals(name, v, op, rhs); };
  }
  const e = orE();
  if (pos < toks.length) throw new Error('Terme inattendu : ' + toks[pos].v);
  return e;
};

/* ------------------------------------------------------------------ suivi de flux TCP */
A.followTcp = function (ctx, recs, streamId) {
  const segs = []; const seen = new Set(); let st = null;
  recs.forEach(r => {
    const s = A.summarize(ctx, r); if (!s.tcp || s.tcp.id !== streamId) return;
    const t = s.p.tcp; if (!t.len) return;
    const k = s.tcp.dir + ':' + t.seq; if (seen.has(k)) return; seen.add(k);
    segs.push({ dir: s.tcp.dir, data: t.payload, no: s.no, src: ipS(s.p.ip.src) + ':' + t.sport, dst: ipS(s.p.ip.dst) + ':' + t.dport });
  });
  return segs;
};
A.streamText = function (segs, ssh) {
  return segs.map(sg => ({ dir: sg.dir, text: sg.data && /^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(B.bytesStr(sg.data, 0, sg.data.length)) ? B.utf8Str ? B.utf8Str(sg.data) : B.bytesStr(sg.data, 0, sg.data.length) : '[' + sg.data.length + ' octets binaires]', n: sg.data.length }));
};

/* ------------------------------------------------------------------ statistiques */
A.stats = function (ctx, recs) {
  const proto = new Map(), conv = new Map(); let bytes = 0;
  recs.forEach(r => {
    const s = A.summarize(ctx, r); bytes += s.len;
    const pv = proto.get(s.proto) || { n: 0, b: 0 }; pv.n++; pv.b += s.len; proto.set(s.proto, pv);
    let a = s.src, b = s.dst; if (s.p.ip) { a = ipS(s.p.ip.src); b = ipS(s.p.ip.dst); }
    const k = a < b ? a + ' ↔ ' + b : b + ' ↔ ' + a; const c = conv.get(k) || { n: 0, b: 0 }; c.n++; c.b += s.len; conv.set(k, c);
  });
  return { total: recs.length, bytes, proto: Array.from(proto, ([k, v]) => ({ proto: k, n: v.n, b: v.b })).sort((x, y) => y.n - x.n), conv: Array.from(conv, ([k, v]) => ({ conv: k, n: v.n, b: v.b })).sort((x, y) => y.n - x.n) };
};

/* ------------------------------------------------------------------ export pcap (libpcap, Ethernet) */
A.toPcap = function (recs) {
  let size = 24; recs.forEach(r => size += 16 + r.bytes.length);
  const out = new Uint8Array(size), dv = new DataView(out.buffer);
  dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
  let o = 24;
  recs.forEach(r => {
    const ms = NS.T0 + r.t; const sec = Math.floor(ms / 1000); const us = Math.floor((ms - sec * 1000) * 1000);
    dv.setUint32(o, sec, true); dv.setUint32(o + 4, us, true); dv.setUint32(o + 8, r.bytes.length, true); dv.setUint32(o + 12, r.bytes.length, true);
    out.set(r.bytes, o + 16); o += 16 + r.bytes.length;
  });
  return out;
};
/* hexdump façon Wireshark : lignes de 16 */
A.hexRows = function (u) {
  const rows = [];
  for (let i = 0; i < u.length; i += 16) { const r = { off: i, bytes: [] }; for (let j = 0; j < 16 && i + j < u.length; j++) r.bytes.push(u[i + j]); rows.push(r); }
  return rows;
};

NS.Analyzer = A;
})(typeof window !== 'undefined' ? window : globalThis);
