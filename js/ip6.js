/* ip6.js — pile IPv6 : adresses (LL/GUA/ULA/SLAAC), DAD, NDP (NS/NA/RS/RA), voisins, routes, ICMPv6, ping/traceroute, transfert */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { MAC, Codec, IP6, IPNode } = NS;

const REACH_MS = 30000, DELAY_MS = 5000, RETRANS_MS = 1000;
const ip6s = IP6.str;

class Ip6 {
  constructor(node) {
    this.node = node; this.sim = node.sim;
    this.routing = false; this.hopLimit = 64;
    this.statics = []; this.raDefaults = []; this.nc = new Map(); this.dns = [];
    this.counters = { in: 0, out: 0, fwd: 0, icmpIn: 0, icmpOut: 0 };
    node.ifHooks.push(i => this.ifaceChanged(i));
  }
  reset() { Array.from(this.node.ifaces.values()).forEach(i => { if (i.v6) this.disable(i); }); this.routing = false; this.statics = []; this.raDefaults = []; this.hopLimit = 64; this.nc.clear(); }
  get isHost() { return this.node.type === 'pc' || this.node.type === 'server' || this.node.type === 'peripheral'; }
  get dadMs() { return this.sim.opts && this.sim.opts.stpFast ? 200 : 1000; }
  /* ---------------- état par interface ---------------- */
  st(iface) { return iface.v6 || null; }
  enable(iface, o) {
    o = o || {};
    if (!iface.v6) iface.v6 = { addrs: [], autoconf: this.isHost || !!o.autoconf, raSuppress: this.isHost, raInterval: 200, raLife: 1800, m: false, o: false, dad: true, timers: [], raTimer: null, prefixes: null, dnsRa: [], noLl: false, mtu: 1500 };
    const s = iface.v6;
    s.up = iface.isUp();
    if (!s.addrs.some(a => a.kind === 'll')) this.addAddr(iface, IP6.linkLocal(iface.mac), 64, 'll');
    return s;
  }
  disable(iface) { const s = iface.v6; if (!s) return; s.timers.forEach(t => this.sim.cancel(t)); this.sim.cancel(s.raTimer); iface.v6 = null; this.flushIface(iface); }
  addrsOf(iface) { return iface.v6 ? iface.v6.addrs : []; }
  ownAddr(a, iface) { for (const i of this.node.ifaces.values()) { if (iface && i !== iface) continue; const s = i.v6; if (s && s.addrs.some(x => x.addr === a && x.state !== 'duplicate')) return i; } return null; }
  addAddr(iface, addr, plen, kind, o) {
    o = o || {}; const s = iface.v6 || this.enable(iface); if (s.addrs.some(x => x.addr === addr)) return s.addrs.find(x => x.addr === addr);
    const a = { addr, plen, kind, state: 'tentative', vl: o.vl === undefined ? null : o.vl, pl: o.pl === undefined ? null : o.pl, t: this.sim.now, eui: !!o.eui, from: o.from || null };
    s.addrs.push(a); if (iface.isUp()) this.startDad(iface, a); return a;
  }
  removeAddr(iface, addr) { const s = iface.v6; if (!s) return; s.addrs = s.addrs.filter(x => x.addr !== addr); }
  startDad(iface, a) {
    const s = iface.v6; a.state = 'tentative'; a.dadT = null;
    if (!s.dad) return this.dadDone(iface, a);
    this.sendNS(iface, a.addr, IP6.solicited(a.addr), 0n, true);
    a.dadT = this.sim.at(this.dadMs, () => { if (a.state === 'tentative') this.dadDone(iface, a); });
  }
  dadDone(iface, a) {
    a.state = 'preferred'; a.t = this.sim.now;
    const s = iface.v6; s.timers = s.timers.filter(t => t !== a.dadT);
    if (a.kind === 'll') { if (s.autoconf && !this.routing) this.sendRS(iface); }
    this.raSoon(iface);
  }
  dup(iface, a) { a.state = 'duplicate'; this.sim.cancel(a.dadT); this.node.log('%IPV6_ND-4-DUPLICATE: Duplicate address ' + IP6.strUp(a.addr) + ' on ' + iface.name, 'warn'); }
  ifaceChanged(iface) {
    if (!iface.v6) { if (this.isHost && iface.isUp()) this.enable(iface); return; }
    const s = iface.v6;
    if (iface.isUp()) { if (!s.up) { s.up = true; s.addrs.forEach(a => this.startDad(iface, a)); } }
    else if (s.up) { s.up = false; s.gotRa = false; s.addrs.forEach(a => this.sim.cancel(a.dadT)); this.sim.cancel(s.raTimer); s.raTimer = null; this.flushIface(iface); this.raDefaults = this.raDefaults.filter(r => r.iface !== iface); }
  }
  flushIface(iface) { for (const [k, e] of Array.from(this.nc)) if (e.iface === iface) { this.sim.cancel(e.timer); this.nc.delete(k); } }
  /* ---------------- adresses : sélection ---------------- */
  usable(a) { return a.state === 'preferred'; }
  pickSrc(iface, dst) {
    const s = iface.v6; if (!s) return null; const ok = s.addrs.filter(a => this.usable(a));
    if (!ok.length) return null;
    if (IP6.isLinkLocal(dst) || (IP6.isMulticast(dst) && IP6.mcScope(dst) <= 2)) { const l = ok.find(a => a.kind === 'll'); return l ? l.addr : ok[0].addr; }
    const gua = ok.filter(a => a.kind !== 'll'); if (!gua.length) return ok[0].addr;
    let best = gua[0], bl = -1; gua.forEach(a => { let l = 0; const x = a.addr ^ dst; for (let i = 127; i >= 0 && ((x >> BigInt(i)) & 1n) === 0n; i--) l++; if (l > bl) { bl = l; best = a; } });
    return best.addr;
  }
  /* ---------------- routes ---------------- */
  connected() {
    const r = [];
    this.node.ifaces.forEach(i => { const s = i.v6; if (!s || !i.isUp()) return; s.addrs.forEach(a => { if (a.kind === 'll' || a.state !== 'preferred') return; r.push({ net: IP6.net(a.addr, a.plen), plen: a.plen, nh: null, iface: i, proto: 'C', ad: 0, metric: 0 }); }); });
    return r;
  }
  locals() { const r = []; this.node.ifaces.forEach(i => { const s = i.v6; if (!s || !i.isUp()) return; s.addrs.forEach(a => { if (a.state === 'preferred') r.push({ net: a.addr, plen: 128, iface: i, proto: 'L', ad: 0, metric: 0 }); }); }); return r; }
  allRoutes() {
    const conn = this.connected(); const r = conn.slice(); const now = this.sim.now;
    this.statics.forEach(s => {
      let iface = null;
      if (s.iface) { iface = this.node.ifaceByName(s.iface); if (!iface || !iface.isUp() || !iface.v6) return; }
      else { const c = conn.filter(c => IP6.inNet(s.nh, c.net, c.plen)).sort((a, b) => b.plen - a.plen)[0]; if (!c) return; iface = c.iface; }
      r.push({ net: s.net, plen: s.plen, nh: s.nh, iface, proto: 'S', ad: s.ad || 1, metric: 0 });
    });
    this.raDefaults = this.raDefaults.filter(d => d.exp > now);
    this.raDefaults.forEach(d => { if (d.iface.isUp()) r.push({ net: 0n, plen: 0, nh: d.nh, iface: d.iface, proto: 'ND', ad: 2, metric: 0 }); });
    return r;
  }
  lookup(dst, zone) {
    if (IP6.isMulticast(dst) || IP6.isLinkLocal(dst)) {
      let i = zone || null; if (!i) { const c = Array.from(this.node.ifaces.values()).filter(x => x.v6 && x.isUp()); i = c.length === 1 ? c[0] : (c.find(x => x.v6.addrs.some(a => a.kind !== 'll')) || c[0] || null); }
      return i ? { iface: i, nh: null, proto: 'LL' } : null;
    }
    let best = null; for (const r of this.allRoutes()) { if (!IP6.inNet(dst, r.net, r.plen)) continue; if (!best || r.plen > best.plen || (r.plen === best.plen && (r.ad < best.ad))) best = r; }
    return best;
  }
  /* ---------------- émission ---------------- */
  txFrame(iface, mac, pkt) { return this.node.sendFrame(iface, mac, 0x86dd, pkt); }
  send(iface, src, dst, next, body, o) {
    o = o || {}; this.counters.out++;
    const pkt = Codec.ip6Packet({ next, hop: o.hop === undefined ? this.hopLimit : o.hop, src, dst, tc: o.tc || 0 }, body);
    this.out(iface, o.nh || dst, pkt, o.onFail); return pkt;
  }
  out(iface, nh, pkt, onFail) {
    if (!iface.isUp()) { if (onFail) onFail('down'); return; }
    if (IP6.isMulticast(nh)) { this.txFrame(iface, IP6.multicastMac(nh), pkt); return; }
    this.resolve(iface, nh, mac => { if (!mac) { if (onFail) onFail('arp'); } else this.txFrame(iface, mac, pkt); });
  }
  /* envoi d'un message ICMPv6 depuis ce nœud ; retourne {ok,iface,src} */
  sendIcmp(dst, type, code, body, o) {
    o = o || {}; let iface = o.iface || null, nh = null;
    if (!iface) { const r = this.lookup(dst, o.zone); if (!r) { if (o.onFail) o.onFail('noroute'); return { ok: false, err: 'noroute' }; } iface = r.iface; nh = r.nh; }
    if (!iface.isUp() || !iface.v6) { if (o.onFail) o.onFail('down'); return { ok: false, err: 'down' }; }
    const src = o.src !== undefined ? o.src : this.pickSrc(iface, dst); if (src === null || src === undefined) { if (o.onFail) o.onFail('noroute'); return { ok: false, err: 'nosrc' }; }
    this.counters.icmpOut++;
    this.send(iface, src, dst, 58, Codec.icmp6(src, dst, type, code, body), { hop: o.hop, nh: o.nh || nh || dst, onFail: o.onFail }); return { ok: true, iface, src };
  }
  /* ---------------- voisins ---------------- */
  key(iface, a) { return iface.name + '|' + a; }
  nstate(e) { if (e.state === 'REACHABLE' && this.sim.now - e.t > REACH_MS) e.state = 'STALE'; return e.state; }
  getNbr(iface, a) { return this.nc.get(this.key(iface, a)) || null; }
  setNbr(iface, a, mac, state, isRouter) {
    const k = this.key(iface, a); let e = this.nc.get(k);
    if (!e) { e = { iface, addr: a, mac, state, t: this.sim.now, router: !!isRouter, timer: null, cbs: [], tries: 0 }; this.nc.set(k, e); }
    else { const changed = e.mac !== mac; e.mac = mac; if (changed || state === 'REACHABLE') { e.state = state; e.t = this.sim.now; } if (isRouter !== undefined) e.router = !!isRouter; }
    return e;
  }
  resolve(iface, nh, cb) {
    let e = this.getNbr(iface, nh);
    if (e && e.mac) { const st = this.nstate(e); if (st === 'STALE') { e.state = 'DELAY'; e.t2 = this.sim.now; e.timer = this.sim.at(DELAY_MS, () => this.probe(e)); } cb(e.mac); return; }
    if (!e) { e = { iface, addr: nh, mac: null, state: 'INCOMPLETE', t: this.sim.now, router: false, timer: null, cbs: [], tries: 0 }; this.nc.set(this.key(iface, nh), e); }
    e.cbs.push(cb);
    if (e.cbs.length > 1) return;
    const attempt = () => {
      if (!iface.isUp()) { this.failNbr(e); return; }
      if (e.tries >= 3) { this.failNbr(e); return; }
      e.tries++; this.sendNS(iface, nh, IP6.solicited(nh), null, false); e.timer = this.sim.at(RETRANS_MS, attempt);
    };
    attempt();
  }
  failNbr(e) { this.nc.delete(this.key(e.iface, e.addr)); const c = e.cbs; e.cbs = []; c.forEach(f => f(null)); }
  probe(e) {
    if (e.state !== 'DELAY') return; e.state = 'PROBE'; e.tries = 0;
    const attempt = () => { if (e.state !== 'PROBE') return; if (e.tries >= 3) { this.nc.delete(this.key(e.iface, e.addr)); return; } e.tries++; this.sendNS(e.iface, e.addr, e.addr, null, false, e.mac); e.timer = this.sim.at(RETRANS_MS, attempt); };
    attempt();
  }
  /* NS : dst = adresse IP de destination (multicast sollicité ou unicast) */
  sendNS(iface, target, dst, srcOverride, dad, unicastMac) {
    let src; if (dad) src = 0n; else { src = this.pickSrc(iface, target); if (src === null) return; if (IP6.isLinkLocal(target) === false) { const same = iface.v6.addrs.find(a => this.usable(a) && a.kind !== 'll' && IP6.inNet(target, a.addr, a.plen)); if (same) src = same.addr; } }
    const opts = dad ? [] : [{ t: 1, mac: iface.mac }];
    const body = Codec.icmp6(src, dst, 135, 0, Codec.nsBody(target, opts)); this.counters.icmpOut++;
    const pkt = Codec.ip6Packet({ next: 58, hop: 255, src, dst }, body);
    this.txFrame(iface, unicastMac || IP6.multicastMac(dst), pkt);
  }
  sendNA(iface, src, dst, target, flags, dstMac) {
    const body = Codec.icmp6(src, dst, 136, 0, Codec.naBody(flags, target, [{ t: 2, mac: iface.mac }])); this.counters.icmpOut++;
    const pkt = Codec.ip6Packet({ next: 58, hop: 255, src, dst }, body); this.txFrame(iface, dstMac || (IP6.isMulticast(dst) ? IP6.multicastMac(dst) : null), pkt);
  }
  sendRS(iface) {
    const s = iface.v6; if (!s) return; const ll = s.addrs.find(a => a.kind === 'll' && this.usable(a)); if (!ll) return;
    let n = 0; const go = () => {
      if (!iface.isUp() || !s.autoconf || this.hasRa(iface) || n >= 3) return; n++;
      const dst = IP6.ALL_ROUTERS; const body = Codec.icmp6(ll.addr, dst, 133, 0, Codec.rsBody([{ t: 1, mac: iface.mac }])); this.counters.icmpOut++;
      this.txFrame(iface, IP6.multicastMac(dst), Codec.ip6Packet({ next: 58, hop: 255, src: ll.addr, dst }, body)); s.timers.push(this.sim.at(4000, go));
    };
    s.timers.push(this.sim.at(this.sim.rng.int(500) + 10, go));
  }
  hasRa(iface) { return this.raDefaults.some(r => r.iface === iface && r.exp > this.sim.now) || (iface.v6 && iface.v6.gotRa); }
  /* ---------------- RA (routeur) ---------------- */
  raOn(iface) { const s = iface.v6; return !!(this.routing && s && !s.raSuppress && iface.isUp() && s.addrs.some(a => a.kind !== 'll' && a.state === 'preferred' || (s.prefixes && s.prefixes.length))); }
  raPrefixes(iface) {
    const s = iface.v6; if (s.prefixes) return s.prefixes;
    return s.addrs.filter(a => a.kind !== 'll' && a.state === 'preferred' && a.plen === 64).map(a => ({ prefix: IP6.net(a.addr, 64), plen: 64, l: true, a: true, vl: 2592000, pl: 604800 }));
  }
  raSoon(iface) {
    const s = iface.v6; if (!s || !this.routing || s.raSuppress) return; this.sim.cancel(s.raTimer);
    s.raTimer = this.sim.at(30 + this.sim.rng.int(200), () => this.sendRA(iface, null, null));
  }
  sendRA(iface, dst, dstMac) {
    const s = iface.v6; if (!s) return; const rep = !!dst; if (!this.raOn(iface)) return;
    const ll = s.addrs.find(a => a.kind === 'll' && this.usable(a)); if (!ll) return;
    const opts = [{ t: 1, mac: iface.mac }, { t: 5, mtu: s.mtu }].concat(this.raPrefixes(iface).map(p => Object.assign({ t: 3 }, p)));
    if (s.dnsRa.length) opts.push({ t: 25, life: 1800, addrs: s.dnsRa });
    const d = dst || IP6.ALL_NODES; const body = Codec.icmp6(ll.addr, d, 134, 0, Codec.raBody({ hop: this.hopLimit, m: s.m, o: s.o, life: s.raLife, reach: 0, retrans: 0, opts })); this.counters.icmpOut++;
    this.txFrame(iface, dstMac || IP6.multicastMac(d), Codec.ip6Packet({ next: 58, hop: 255, src: ll.addr, dst: d }, body));
    if (!rep) { this.sim.cancel(s.raTimer); const iv = s.raInterval * 1000; s.raTimer = this.sim.at(iv * (0.66 + this.sim.rng.next() * 0.34), () => this.sendRA(iface, null, null)); }
  }
  /* ---------------- réception ---------------- */
  acceptsMac(iface, mac) {
    if (!/^33:33:/.test(mac) || !iface.v6) return false;
    if (mac === '33:33:00:00:00:01') return true; if (mac === '33:33:00:00:00:02') return this.routing;
    if (/^33:33:ff:/.test(mac)) return iface.v6.addrs.some(a => IP6.multicastMac(IP6.solicited(a.addr)) === mac);
    return false;
  }
  accepts(iface, dst) {
    if (IP6.isMulticast(dst)) {
      if (dst === IP6.ALL_NODES) return true; if (dst === IP6.ALL_ROUTERS) return this.routing;
      if (IP6.isSolicitedNode(dst)) return !!(iface.v6 && iface.v6.addrs.some(a => IP6.solicited(a.addr) === dst)); return false;
    }
    if (dst === 1n) return true;
    return !!(iface.v6 && iface.v6.addrs.some(a => a.addr === dst && a.state !== 'duplicate' && (a.state !== 'tentative')));
  }
  input(iface, p) {
    const h = p.ip6; if (!iface.v6) return; this.counters.in++;
    const dst = h.dst;
    if (this.accepts(iface, dst)) return this.deliver(iface, p);
    if (IP6.isMulticast(dst)) return;
    // tentative : NS/NA de DAD reçus pour cette adresse
    if (iface.v6.addrs.some(a => a.addr === dst && a.state === 'tentative')) return;
    if (this.routing) return this.forward(iface, p);
  }
  deliver(iface, p) {
    const h = p.ip6; if (h.next === 58 && p.icmp6) { this.counters.icmpIn++; return this.icmpInput(iface, p); }
    if (this.node.ip6Proto && this.node.ip6Proto[h.next]) return this.node.ip6Proto[h.next](iface, p);
  }
  icmpInput(iface, p) {
    const h = p.ip6, c = p.icmp6; if (!c.csumOk) return; const n = this.node;
    if (c.type === 128) {
      if (!n.allowIcmpEcho) return; if (n.icmp6Filter && !n.icmp6Filter(iface, p)) return;
      const dst = IP6.isMulticast(h.dst) ? this.pickSrc(iface, h.src) : h.dst; if (dst === null) return;
      this.reply(iface, dst, h.src, 129, 0, Codec.echo6Body(c.id, c.seq, c.payload)); return;
    }
    if (c.type === 128 + 1) { const w = n.pingW.get(c.id + ':' + c.seq); if (w) w({ type: 'reply', from: h.src, ttl: h.hop, bytes: c.payload.length }); return; }
    if ((c.type === 1 || c.type === 3 || c.type === 2) && c.quote && c.quote.icmpType === 128) { const w = n.pingW.get(c.quote.id + ':' + c.quote.seq); if (w) w({ type: c.type === 3 ? 'ttl' : c.type === 2 ? 'ptb' : 'unreach', from: h.src, code: c.code, mtu: c.mtu }); return; }
    if (h.hop !== 255) return; // NDP : hop limit 255 obligatoire
    if (c.type === 135) return this.onNS(iface, p);
    if (c.type === 136) return this.onNA(iface, p);
    if (c.type === 133) return this.onRS(iface, p);
    if (c.type === 134) return this.onRA(iface, p);
  }
  reply(iface, src, dst, type, code, body) {
    const r = this.lookup(dst, iface); if (!r) return; const oi = r.iface; if (!oi.v6 || !oi.isUp()) return;
    const sa = src === undefined || src === null ? this.pickSrc(oi, dst) : src; if (sa === null) return; this.counters.icmpOut++;
    this.send(oi, sa, dst, 58, Codec.icmp6(sa, dst, type, code, body), { nh: r.nh || dst });
  }
  setRouting(on) { this.routing = !!on; this.node.ifaces.forEach(i => { if (i.v6) { if (on) this.raSoon(i); else { this.sim.cancel(i.v6.raTimer); i.v6.raTimer = null; } } }); }
  slla(c) { const o = (c.opts || []).find(x => x.t === 1); return o ? o.mac : null; }
  onNS(iface, p) {
    const h = p.ip6, c = p.icmp6, s = iface.v6; const tgt = c.target; const mine = s.addrs.find(a => a.addr === tgt);
    if (!mine) return;
    if (h.src === 0n) { if (mine.state === 'tentative') this.dup(iface, mine); else if (mine.state === 'preferred') this.sendNA(iface, mine.addr, IP6.ALL_NODES, tgt, { r: this.routing, s: false, o: true }); return; }
    if (mine.state === 'tentative') return;
    const mac = this.slla(c); if (mac) { const e = this.getNbr(iface, h.src); if (!e || !e.mac) { const ne = this.setNbr(iface, h.src, mac, 'STALE'); this.flush(ne); } else if (e.mac !== mac) { e.mac = mac; e.state = 'STALE'; e.t = this.sim.now; } }
    this.sim.at(0.05, () => this.sendNA(iface, tgt, h.src, tgt, { r: this.routing, s: true, o: true }, mac || (this.getNbr(iface, h.src) || {}).mac));
  }
  flush(e) { const c = e.cbs; e.cbs = []; this.sim.cancel(e.timer); c.forEach(f => f(e.mac)); }
  onNA(iface, p) {
    const h = p.ip6, c = p.icmp6, s = iface.v6; const tgt = c.target;
    const mine = s.addrs.find(a => a.addr === tgt); if (mine && mine.state === 'tentative') { this.dup(iface, mine); return; }
    const tl = (c.opts || []).find(x => x.t === 2); const mac = tl ? tl.mac : null;
    const e = this.getNbr(iface, tgt); if (!e) return;
    if (e.state === 'INCOMPLETE') { if (!mac) return; e.mac = mac; e.state = c.s ? 'REACHABLE' : 'STALE'; e.t = this.sim.now; e.router = c.r; this.flush(e); return; }
    if (mac && mac !== e.mac) { if (c.o) { e.mac = mac; e.state = c.s ? 'REACHABLE' : 'STALE'; e.t = this.sim.now; } else if (e.state === 'REACHABLE') e.state = 'STALE'; }
    else if (c.s && (c.o || mac === e.mac || !mac)) { e.state = 'REACHABLE'; e.t = this.sim.now; this.sim.cancel(e.timer); }
    e.router = c.r;
  }
  onRS(iface, p) {
    const h = p.ip6, c = p.icmp6; if (!this.routing || !this.raOn(iface)) return; const mac = this.slla(c);
    if (mac && h.src !== 0n) this.setNbr(iface, h.src, mac, 'STALE');
    this.sim.at(20 + this.sim.rng.int(100), () => this.sendRA(iface, h.src === 0n ? null : h.src, mac));
  }
  onRA(iface, p) {
    const h = p.ip6, c = p.icmp6, s = iface.v6; if (this.routing && !s.autoconf) return; if (!IP6.isLinkLocal(h.src)) return; if (!s.autoconf) return;
    s.gotRa = true; const mac = this.slla(c); if (mac) { const e = this.setNbr(iface, h.src, mac, 'STALE', true); e.router = true; }
    const now = this.sim.now; this.raDefaults = this.raDefaults.filter(d => !(d.iface === iface && d.nh === h.src));
    if (c.life > 0) this.raDefaults.push({ iface, nh: h.src, exp: now + c.life * 1000, life: c.life });
    (c.opts || []).forEach(o => {
      if (o.t === 3 && o.a && o.plen === 64 && o.vl >= o.pl && !IP6.isLinkLocal(o.prefix)) {
        const addr = IP6.withIid(o.prefix, iface.mac); const ex = s.addrs.find(a => a.addr === addr);
        if (ex) { ex.vl = o.vl; ex.pl = o.pl; ex.t = now; } else if (o.vl > 0) this.addAddr(iface, addr, 64, 'slaac', { vl: o.vl, pl: o.pl, from: h.src });
      }
      if (o.t === 25) o.addrs.forEach(a => { if (!this.dns.includes(a)) this.dns.push(a); });
      if (o.t === 5 && o.mtu >= 1280 && o.mtu <= 1500) s.mtu = o.mtu;
    });
    if (c.hop) this.hopLimit = c.hop;
  }
  /* ---------------- transfert ---------------- */
  forward(iface, p) {
    const h = p.ip6; const n = this.node;
    if (IP6.isLinkLocal(h.dst) || IP6.isMulticast(h.dst) || h.src === 0n) return;
    if (n.forwardFilter6 && !n.forwardFilter6(iface, null, p)) return;
    if (h.hop <= 1) { this.icmpErr(iface, p, 3, 0); return; }
    const r = this.lookup(h.dst); if (!r) { this.icmpErr(iface, p, 1, 0); return; }
    const out = r.iface; const size = h.total;
    if (size > (out.v6 ? out.v6.mtu : 1500)) { this.icmpErr(iface, p, 2, 0, out.v6.mtu); return; }
    this.counters.fwd++;
    const pkt = p.bytes.slice(h.off, h.off + h.total); pkt[7] = h.hop - 1;
    this.out(out, r.nh || h.dst, pkt, () => this.icmpErr(iface, p, 1, 3));
  }
  icmpErr(iface, p, type, code, mtu) {
    const h = p.ip6; if (IP6.isMulticast(h.src) || h.src === 0n) return; if (p.icmp6 && p.icmp6.type < 128) return;
    const inv = p.bytes.slice(h.off, h.off + h.total);
    this.reply(iface, this.pickSrc(iface, h.src), h.src, type, code, Codec.err6Body(inv, mtu));
  }
  /* ---------------- ping ---------------- */
  pingOnce(dst, o, cb) {
    o = o || {}; const n = this.node; const id = o.id || 1, seq = o.seq || 1, key = id + ':' + seq; const t0 = this.sim.now; let done = false;
    const fin = r => { if (done) return; done = true; this.sim.cancel(tm); n.pingW.delete(key); r.rtt = this.sim.now - t0; cb(r); };
    const tm = this.sim.at(o.timeout || 2000, () => fin({ type: 'timeout' })); n.pingW.set(key, fin);
    const payload = new Uint8Array(o.size === undefined ? 32 : o.size); for (let i = 0; i < payload.length; i++) payload[i] = 0x61 + (i % 23);
    if (this.ownAddr(dst) || dst === 1n) { const i = Array.from(n.ifaces.values()).find(x => x.v6 && x.isUp()) || Array.from(n.ifaces.values())[0]; this.sim.at(0.05, () => fin({ type: 'reply', from: dst, ttl: this.hopLimit, bytes: payload.length })); return; }
    const zone = o.zone || null; const r = this.sendIcmp(dst, 128, 0, Codec.echo6Body(id, seq, payload), { hop: o.ttl, src: o.src, zone, onFail: why => fin({ type: why === 'arp' ? 'arpfail' : 'noroute' }) });
    if (!r.ok) fin({ type: 'noroute' });
  }
}

/* ---- intégration IPNode ---- */
const P = IPNode.prototype;
const origInput = P.input; P.input = function (iface, p) { if (p.ip6) { if (this.ip6) this.ip6.input(iface, p); return; } return origInput.call(this, iface, p); };
const origRecv = P.recv;
P.recv = function (port, bytes) {
  const p = Codec.parse(bytes, false); if (!p.eth) return;
  if (p.ip6 && this.ip6) {
    const vid = p.eth.vlan ? p.eth.vlan.vid : null; const iface = this.ifaceFor(port, vid); if (!iface || !iface.isUp() || !iface.v6) return;
    const dst = p.eth.dst; if (dst !== iface.mac && !(MAC.isMulticast(dst) && this.ip6.acceptsMac(iface, dst))) return; this.ip6.input(iface, p); return;
  }
  return origRecv.call(this, port, bytes);
};
const origPing = P.pingOnce; P.pingOnce = function (dst, o, cb) { if (typeof dst === 'bigint') return this.ip6.pingOnce(dst, o, cb); return origPing.call(this, dst, o, cb); };
NS.Ip6 = Ip6; NS.fmtIp = x => typeof x === 'bigint' ? IP6.strUp(x) : NS.IP.str(x);
})(typeof window !== 'undefined' ? window : globalThis);
