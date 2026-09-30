/* stack.js — équipement de base, interfaces L3, pile IP (ARP, IPv4, ICMP, UDP, TCP), routage, ACL, NAT */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, Port, B } = NS;
const { checksum } = B;
const SYN = 1 << 1, ACK = 1 << 4, FIN = 1, RST = 1 << 2, PSH = 1 << 3;
const MSS = 1460;

/* ================================================================== Device */
class Device {
  constructor(sim, o) {
    this.sim = sim; this.id = o.id || sim.uid('D'); this.type = o.type; this.model = o.model; this.name = o.name || this.id;
    this.x = o.x || 0; this.y = o.y || 0; this.ports = []; this.powered = true; this.oui = o.oui || NS.OUI.generic; this.mdi = 'MDI';
    this.baseMac = MAC.make(this.oui);
  }
  addPort(name, o) { o = Object.assign({}, o); o.idx = this.ports.length; const p = new Port(this, name, o); this.ports.push(p); return p; }
  findPort(str) {
    if (!str) return null; str = String(str).toLowerCase().replace(/\s+/g, '');
    let p = this.ports.find(x => x.name.toLowerCase() === str || x.short.toLowerCase() === str); if (p) return p;
    const m = /^([a-z\-]+)([\d\/\.]+)$/.exec(str); if (!m) return null;
    return this.ports.find(x => { const n = x.name.toLowerCase(); const mm = /^([a-z\-]+)([\d\/\.]+)$/.exec(n); return mm && mm[2] === m[2] && mm[1].startsWith(m[1]); }) || null;
  }
  freePorts() { return this.ports.filter(p => !p.link); }
  send(port, bytes) { return this.sim.transmit(port, bytes); }
  recv() {}
  portStateChanged() {}
  log(m, l) { this.sim.log(this, m, l); }
  destroy() {}
  serialize() { return { id: this.id, type: this.type, model: this.model, name: this.name, x: Math.round(this.x), y: Math.round(this.y), powered: this.powered }; }
}

/* ================================================================== Interface L3 */
class Iface {
  constructor(node, name, o) {
    o = o || {};
    this.node = node; this.name = name; this.port = o.port || null; this.vid = o.vid || null; this.svi = o.svi === undefined ? null : o.svi;
    this.ip = 0; this.mask = 0; this.adminUp = true; this.dhcp = false; this.helper = []; this.aclIn = null; this.aclOut = null; this.nat = null; this.desc = '';
    this.zone = null; this.ripPassive = false; this.ospfCost = 1; this.ospfArea = null; this.ospfCostFix = 0; this.ospfHello = 0; this.ospfDead = 0; this.ospfPri = null; this.ospfNet = null; this.dhcpInfo = null; this.mtu = 1500; this.sec = [];
  }
  get mac() { return this.port ? this.port.mac : this.node.baseMac; }
  get configured() { return this.ip !== 0; }
  get network() { return IP.net(this.ip, this.mask); }
  isUp() {
    if (!this.adminUp) return false;
    if (this.loop) return true;
    if (this.tun) return this.node.vpn ? this.node.vpn.tunUp(this) : false;
    if (this.sub) { if (!this.port || !this.port.up) return false; const par = this.node.ifaces.get(this.parentName); if (par && !par.adminUp) return false; return this.vid !== null; }
    if (this.svi !== null) return this.node.sviUp ? this.node.sviUp(this.svi) : false;
    return !!(this.port && this.port.up);
  }
}

/* ================================================================== Connexion TCP */
class TcpConn {
  constructor(node, lip, lport, rip, rport) {
    this.node = node; this.lip = lip; this.lport = lport; this.rip = rip; this.rport = rport;
    this.state = 'CLOSED'; this.iss = 0; this.snd_nxt = 0; this.snd_una = 0; this.rcv_nxt = 0; this.mss = MSS; this.finSent = false; this.finAcked = false;
    this.key = lip + ':' + lport + '-' + rip + ':' + rport; this.ackTimer = null; this.timer = null; this.user = {};
    this.onOpen = null; this.onData = null; this.onClose = null; this.onError = null;
  }
  get remote() { return IP.str(this.rip) + ':' + this.rport; }
  seg(flags, payload, o) {
    o = o || {};
    if (this.ackTimer) { this.node.sim.cancel(this.ackTimer); this.ackTimer = null; }
    const seq = o.seq !== undefined ? o.seq : this.snd_nxt;
    const ack = (flags & ACK) ? this.rcv_nxt : 0;
    this.node.sendIp(this.rip, 6, src => Codec.tcp(src, this.rip, { sport: this.lport, dport: this.rport, seq, ack, flags, payload, mss: o.mss }), { src: this.lip, onFail: () => { } });
  }
  sendAck() { this.seg(ACK, []); }
  scheduleAck() { if (this.ackTimer) return; this.ackTimer = this.node.sim.at(0.2, () => { this.ackTimer = null; this.sendAck(); }); }
  send(data) {
    if (typeof data === 'string') data = B.utf8Bytes(data);
    if (this.state !== 'ESTABLISHED' && this.state !== 'CLOSE_WAIT') return false;
    for (let i = 0; i < data.length; i += this.mss) {
      const chunk = data.subarray(i, Math.min(data.length, i + this.mss));
      this.seg(PSH | ACK, chunk); this.snd_nxt = (this.snd_nxt + chunk.length) >>> 0;
    }
    return true;
  }
  close() {
    if (this.state === 'ESTABLISHED') { this.seg(FIN | ACK, []); this.snd_nxt = (this.snd_nxt + 1) >>> 0; this.finSent = true; this.state = 'FIN_WAIT_1'; }
    else if (this.state === 'CLOSE_WAIT') { this.seg(FIN | ACK, []); this.snd_nxt = (this.snd_nxt + 1) >>> 0; this.finSent = true; this.state = 'LAST_ACK'; }
    else if (this.state === 'SYN_SENT' || this.state === 'SYN_RCVD') this.terminate('closed');
  }
  abort() { if (this.state !== 'CLOSED') { this.seg(RST | ACK, []); } this.terminate('reset'); }
  terminate(why) {
    if (this.state === 'CLOSED' && !this.node.tcpC.has(this.key)) return;
    const was = this.state; this.state = 'CLOSED';
    if (this.timer) this.node.sim.cancel(this.timer); if (this.ackTimer) this.node.sim.cancel(this.ackTimer);
    this.node.tcpC.delete(this.key);
    if (why === 'timeout' || why === 'refused' || why === 'unreachable') { if (this.onError) this.onError(why); }
    else if (this.onClose) this.onClose(why, was);
  }
  input(p) {
    const t = p.tcp, f = t.flags;
    if (f & RST) { this.terminate(this.state === 'SYN_SENT' ? 'refused' : 'reset'); return; }
    if (this.state === 'SYN_SENT') {
      if ((f & SYN) && (f & ACK) && t.ack === this.snd_nxt) {
        this.rcv_nxt = (t.seq + 1) >>> 0; this.snd_una = t.ack; this.mss = Math.min(MSS, t.mss || MSS); this.state = 'ESTABLISHED';
        if (this.timer) { this.node.sim.cancel(this.timer); this.timer = null; }
        this.sendAck(); if (this.onOpen) this.onOpen(this);
      }
      return;
    }
    if (this.state === 'SYN_RCVD') {
      if ((f & ACK) && t.ack === this.snd_nxt) {
        this.snd_una = t.ack; this.state = 'ESTABLISHED';
        if (this.timer) { this.node.sim.cancel(this.timer); this.timer = null; }
        if (this.listener && this.listener.onAccept) this.listener.onAccept(this);
      } else if (f & SYN) { this.retxSynAck(); return; } else return;
    }
    if (f & ACK) {
      this.snd_una = t.ack;
      if (this.finSent && t.ack === this.snd_nxt) {
        this.finAcked = true;
        if (this.state === 'FIN_WAIT_1') this.state = 'FIN_WAIT_2';
        else if (this.state === 'LAST_ACK' || this.state === 'CLOSING') { this.terminate('closed'); return; }
      }
    }
    if (t.len > 0) {
      if (t.seq === this.rcv_nxt && (this.state === 'ESTABLISHED' || this.state === 'FIN_WAIT_1' || this.state === 'FIN_WAIT_2')) {
        this.rcv_nxt = (this.rcv_nxt + t.len) >>> 0;
        this.scheduleAck();
        if (this.onData) this.onData(t.payload, this);
        if (this.state === 'CLOSED') return;
      } else this.sendAck();
    }
    if ((f & FIN) && ((t.seq + t.len) >>> 0) === this.rcv_nxt) {
      this.rcv_nxt = (this.rcv_nxt + 1) >>> 0; this.sendAck();
      if (this.state === 'ESTABLISHED') { this.state = 'CLOSE_WAIT'; if (this.onClose) this.onClose('fin', 'ESTABLISHED'); }
      else if (this.state === 'FIN_WAIT_2' || (this.state === 'FIN_WAIT_1' && this.finAcked)) { this.state = 'TIME_WAIT'; this.timer = this.node.sim.at(2000, () => this.terminate('closed')); }
      else if (this.state === 'FIN_WAIT_1') this.state = 'CLOSING';
    }
  }
  retxSynAck() { this.seg(SYN | ACK, [], { seq: this.iss, mss: MSS }); }
}

/* ================================================================== Nœud IP */
class IPNode extends Device {
  constructor(sim, o) {
    super(sim, o);
    this.ifaces = new Map(); this.statics = []; this.dynRoutes = []; this.arpTable = new Map(); this.arpPending = new Map(); this.arpTtl = 300000;
    this.forwarding = false; this.ttl = 64; this.ipId = 1 + sim.rng.int(60000); this.udp = new Map(); this.tcpL = new Map(); this.tcpC = new Map();
    this.pingW = new Map(); this.acls = new Map(); this.joined = new Set(); this.ephemeral = 49152 + sim.rng.int(2000);
    this.nat = { dyn: [], statics: [], table: [] }; this.allowIcmpEcho = true; this.sendUnreach = true; this.services = {}; this.pingId = 1;
    this.counters = { icmpIn: 0, icmpOut: 0, ipIn: 0, ipFwd: 0, aclDeny: 0 };
    this.protoHandlers = new Map(); this.ifHooks = []; this.mgmt = NS.Mgmt ? new NS.Mgmt(this) : null; this.ip6 = NS.Ip6 ? new NS.Ip6(this) : null; this.vpn = NS.Vpn ? new NS.Vpn(this) : null; this.radius = NS.Radius ? new NS.Radius(this) : null; this.voip = NS.Sip ? new NS.Sip(this) : null; this.pbx = NS.Pbx ? new NS.Pbx(this) : null; this.dot1x = NS.Dot1x ? new NS.Dot1x(this) : null;
    this.joinedIp = new Set(); this.dhcpClients = new Map(); this.dnsServers = []; this.hosts = {};
    this.udpBind(68, (p, i) => { const c = this.dhcpClients.get(i.name); if (c) c.input(p); });
  }
  enableDhcp(iface, on) {
    let c = this.dhcpClients.get(iface.name);
    iface.dhcp = !!on;
    if (on) { if (!c) { c = new NS.svc.DhcpClient(this, iface); this.dhcpClients.set(iface.name, c); } if (iface.isUp()) c.start(); else c.state = 'INIT'; }
    else if (c) { c.stop(); c.unconfigure(); this.dhcpClients.delete(iface.name); }
  }
  ifaceStateChanged(i) {
    this.ifHooks.forEach(f => f(i));
    const c = this.dhcpClients.get(i.name);
    if (i.dhcp && c) { if (i.isUp()) { if (c.state !== 'BOUND' && c.state !== 'APIPA') c.start(); } else { c.stop(); c.unconfigure(); c.state = 'INIT'; } }
  }
  /* ARP gratuit (annonce) */
  arpAnnounce(iface) { if (iface.ip && iface.isUp() && !iface.loop) this.sendArp(iface, 1, null, iface.ip, MAC.BCAST, iface.ip); }
  /* ---- interfaces ---- */
  addIface(name, o) { const i = new Iface(this, name, o); this.ifaces.set(name, i); return i; }
  ifaceList() { return Array.from(this.ifaces.values()); }
  ifaceFor(port, vid) {
    for (const i of this.ifaces.values()) if (i.port === port && i.svi === null && (i.vid || null) === (vid || null) && (vid || !i.sub)) return i;
    return null;
  }
  ifaceByName(str) {
    if (!str) return null; const s = String(str).toLowerCase().replace(/\s+/g, '');
    if (this.ifaces.has(str)) return this.ifaces.get(str);
    for (const i of this.ifaces.values()) if (i.name.toLowerCase() === s) return i;
    const m = /^([a-z\-]+)([\d\/\.]+)$/.exec(s); if (!m) return null;
    for (const i of this.ifaces.values()) { const mm = /^([a-z\-]+)([\d\/\.]+)$/.exec(i.name.toLowerCase()); if (mm && mm[2] === m[2] && mm[1].startsWith(m[1])) return i; }
    return null;
  }
  localIps() { const r = []; this.ifaces.forEach(i => { if (i.ip && i.isUp()) r.push(i.ip); }); return r; }
  isLocalIp(ip) { for (const i of this.ifaces.values()) if (i.ip && i.ip === ip && i.isUp()) return true; return (ip >>> 24) === 127; }
  portStateChanged(port) {
    this.ifaces.forEach(i => { if (i.port === port || (i.port === null && i.svi !== null)) this.ifaceStateChanged(i); });
  }
  get primaryIface() { for (const i of this.ifaces.values()) if (i.ip) return i; return this.ifaces.values().next().value; }

  /* ---- routage ---- */
  connectedRoutes() {
    const r = [];
    this.ifaces.forEach(i => { if (i.ip && i.mask && i.isUp()) r.push({ net: IP.net(i.ip, i.mask), mask: i.mask, nh: 0, iface: i, proto: 'C', ad: 0, metric: 0 }); });
    return r;
  }
  allRoutes() {
    const r = this.connectedRoutes(); const conn = r.slice();
    this.statics.forEach(s => {
      let iface = null;
      if (s.iface) { iface = this.ifaceByName(s.iface); if (!iface || !iface.isUp()) return; }
      else { const c = conn.filter(c => IP.inNet(s.nh, c.net, c.mask)).sort((a, b) => b.mask - a.mask)[0]; if (!c) return; iface = c.iface; }
      r.push({ net: s.net, mask: s.mask, nh: s.nh, iface, proto: 'S', ad: s.ad || 1, metric: 0, gw: s.gw });
    });
    this.dynRoutes.forEach(d => { if (d.iface && d.iface.isUp()) r.push(d); });
    return r;
  }
  lookup(dst) {
    let best = null;
    for (const r of this.allRoutes()) {
      if (!IP.inNet(dst, r.net, r.mask)) continue;
      if (!best || r.mask > best.mask || (r.mask === best.mask && (r.ad < best.ad || (r.ad === best.ad && r.metric < best.metric)))) best = r;
    }
    return best;
  }
  addStatic(net, mask, nh, iface, ad) {
    net = IP.net(net, mask);
    this.statics = this.statics.filter(s => !(s.net === net && s.mask === mask && s.nh === nh && (s.iface || '') === (iface || '')));
    this.statics.push({ net, mask, nh: nh || 0, iface: iface || null, ad: ad || 1 });
  }

  /* ---- ARP ---- */
  arpGet(ip) { const e = this.arpTable.get(ip); if (!e) return null; if (!e.static && this.sim.now - e.t > this.arpTtl) { this.arpTable.delete(ip); return null; } return e; }
  arpSet(ip, mac, iface, st) { this.arpTable.set(ip, { mac, iface, t: this.sim.now, static: !!st }); }
  sendArp(iface, op, tha, tpa, dstMac, spa) {
    const pl = Codec.arp({ op, sha: iface.mac, spa: spa === undefined ? iface.ip : spa, tha: tha || '00:00:00:00:00:00', tpa });
    this.sendFrame(iface, dstMac, 0x0806, pl);
  }
  arpResolve(iface, ip, cb) {
    const e = this.arpGet(ip); if (e) { cb(e.mac); return; }
    const key = iface.name + '|' + ip; let pd = this.arpPending.get(key);
    if (pd) { pd.cbs.push(cb); return; }
    pd = { cbs: [cb], tries: 0, timer: null }; this.arpPending.set(key, pd);
    const attempt = () => {
      if (!iface.isUp()) { this.arpPending.delete(key); pd.cbs.forEach(f => f(null)); return; }
      if (pd.tries >= 3) { this.arpPending.delete(key); pd.cbs.forEach(f => f(null)); return; }
      pd.tries++; this.sendArp(iface, 1, null, ip, MAC.BCAST); pd.timer = this.sim.at(1000, attempt);
    };
    attempt();
  }
  arpInput(iface, a) {
    if (!iface.ip) return;
    if (a.spa && a.sha !== MAC.BCAST) {
      const had = this.arpTable.get(a.spa);
      if (a.tpa === iface.ip || had || a.op === 2) {
        if (IP.inNet(a.spa, iface.ip, iface.mask) || had) this.arpSet(a.spa, a.sha, iface);
      }
    }
    if (a.op === 1 && a.tpa === iface.ip && a.spa !== iface.ip) this.sendArp(iface, 2, a.sha, a.spa, a.sha);
    else if (a.op === 1 && this.proxyArp && this.proxyArp(iface, a)) { /* proxy */ }
    if (a.op === 2 || a.op === 1) {
      const key = iface.name + '|' + a.spa; const pd = this.arpPending.get(key);
      if (pd && a.op === 2) { this.sim.cancel(pd.timer); this.arpPending.delete(key); pd.cbs.forEach(f => f(a.sha)); }
    }
  }
  /* ---- émission trame / paquet ---- */
  sendFrame(iface, dstMac, type, payload) {
    const vlan = iface.vid ? { vid: iface.vid } : null;
    const f = Codec.frame({ dst: dstMac, src: iface.mac, vlan, type, payload });
    return this.txIface(iface, f);
  }
  txIface(iface, frame) {
    if (!iface.isUp()) return false;
    if (iface.svi !== null) return this.sviTx ? this.sviTx(iface.svi, frame) : false;
    return this.send(iface.port, frame);
  }
  ipOut(iface, nh, ipBytes, onFail) {
    if (IP.isBroadcast(nh) || (iface.ip && nh === IP.bcast(iface.ip, iface.mask))) { this.sendFrame(iface, MAC.BCAST, 0x0800, ipBytes); return; }
    if (IP.isMulticast(nh)) { this.sendFrame(iface, IP.multicastMac(nh), 0x0800, ipBytes); return; }
    this.arpResolve(iface, nh, mac => { if (!mac) { if (onFail) onFail('arp'); } else this.sendFrame(iface, mac, 0x0800, ipBytes); });
  }
  nextId() { this.ipId = (this.ipId + 1) & 0xffff; return this.ipId; }
  /* mkL4(srcIp) -> octets de la couche 4. Retourne {ok,iface,src,err} */
  sendIp(dst, proto, mkL4, o) {
    o = o || {};
    let route;
    if (o.iface) route = { iface: o.iface, nh: 0 };
    else route = this.lookup(dst);
    if (this.isLocalIp(dst) && !o.iface) { // bouclage
      const ifc = this.primaryIface; const src = dst;
      const ip = Codec.ipPacket({ ttl: this.ttl, proto, src, dst, id: this.nextId(), df: 1 }, mkL4(src));
      const fr = Codec.frame({ dst: ifc.mac, src: ifc.mac, type: 0x0800, payload: ip });
      this.sim.at(0.02, () => this.ipInput(ifc, Codec.parse(fr)));
      return { ok: true, iface: ifc, src };
    }
    if (!route) { if (o.onFail) o.onFail('noroute'); return { ok: false, err: 'noroute' }; }
    const iface = route.iface; if (!iface.isUp()) { if (o.onFail) o.onFail('down'); return { ok: false, err: 'down' }; }
    const src = o.src !== undefined ? o.src : iface.ip;
    const l4 = mkL4(src);
    const ip = Codec.ipPacket({ tos: o.tos || 0, id: this.nextId(), ttl: o.ttl === undefined ? this.ttl : o.ttl, proto, src, dst, df: o.df === undefined ? 1 : o.df }, l4);
    this.ipOut(iface, route.nh || dst, ip, o.onFail);
    return { ok: true, iface, src };
  }
  /* ---- réception ---- */
  recv(port, bytes) {
    const p = Codec.parse(bytes, false); if (!p.eth) return;
    const vid = p.eth.vlan ? p.eth.vlan.vid : null;
    const iface = this.ifaceFor(port, vid);
    if (!iface || !iface.isUp()) return;
    const dst = p.eth.dst;
    if (dst !== iface.mac && dst !== MAC.BCAST && !(MAC.isMulticast(dst) && this.joined.has(dst))) return;
    this.input(iface, p);
  }
  input(iface, p) {
    if (p.arp) return this.arpInput(iface, p.arp);
    if (p.ip) return this.ipInput(iface, p);
    if (this.otherInput) this.otherInput(iface, p);
  }
  isLocalDst(iface, dst) {
    if (dst === 0xFFFFFFFF || (dst >>> 24) === 127) return true;
    if (IP.isMulticast(dst)) return this.joinedIp && this.joinedIp.has(dst);
    for (const i of this.ifaces.values()) { if (i.ip && i.ip === dst) return true; if (i.ip && i.mask && i.mask !== 0xFFFFFFFF && dst === IP.bcast(i.ip, i.mask) && i === iface) return true; }
    return false;
  }
  ipInput(iface, p) {
    this.counters.ipIn++;
    if (iface.aclIn && !this.aclPermit(iface.aclIn, p)) { this.aclDenied(iface, p); return; }
    if (iface.nat === 'outside' && this.natInbound) { const q = this.natInbound(iface, p); if (q) p = q; }
    if (this.inFilter && !this.inFilter(iface, p)) return;
    const dst = p.ip.dst;
    if (this.isLocalDst(iface, dst)) return this.deliver(iface, p);
    if (this.forwarding) return this.forward(iface, p);
  }
  deliver(iface, p) {
    const ip = p.ip;
    if (ip.proto === 1 && p.icmp) return this.icmpInput(iface, p);
    if (ip.proto === 17 && p.udp) return this.udpInput(iface, p);
    if (ip.proto === 6 && p.tcp) return this.tcpInput(iface, p);
    const ph = this.protoHandlers.get(ip.proto); if (ph) return ph(iface, p);
    if (this.protoInput && ip.proto !== 1 && ip.proto !== 6 && ip.proto !== 17) return this.protoInput(iface, p);
  }
  /* ---- transfert ---- */
  forward(iface, p) {
    const ip = p.ip;
    if (IP.isBroadcast(ip.dst) || IP.isMulticast(ip.dst)) return;
    if (ip.ttl <= 1) { this.icmpError(p, iface, 11, 0); return; }
    const r = this.lookup(ip.dst);
    if (!r) { this.icmpError(p, iface, 3, 0); return; }
    const out = r.iface;
    if (this.forwardFilter && !this.forwardFilter(iface, out, p)) return;
    if (out.aclOut && !this.aclPermit(out.aclOut, p)) { this.aclDenied(iface, p); return; }
    this.counters.ipFwd++;
    let ipb;
    const nat = (iface.nat === 'inside' && out.nat === 'outside' && this.natOutbound) ? this.natOutbound(iface, out, p) : null;
    if (nat) { nat.ip = Object.assign({ ttl: ip.ttl - 1 }, nat.ip); ipb = Codec.rebuildIp(p, nat); }
    else {
      ipb = p.bytes.slice(ip.off, ip.off + ip.total); ipb[8] = ip.ttl - 1; ipb[10] = 0; ipb[11] = 0;
      const c = checksum(ipb, 0, ip.ihl); ipb[10] = c >> 8; ipb[11] = c & 255;
    }
    this.ipOut(out, r.nh || ip.dst, ipb, () => this.icmpError(p, iface, 3, 1));
  }
  /* ---- ICMP ---- */
  icmpError(p, iface, type, code) {
    const ip = p.ip;
    if (!this.sendUnreach && type === 3) return;
    if (IP.isBroadcast(ip.dst) || IP.isMulticast(ip.dst) || ip.frag || !ip.src || IP.isBroadcast(ip.src)) return;
    if (p.icmp && (p.icmp.type === 3 || p.icmp.type === 11 || p.icmp.type === 5)) return;
    const q = p.bytes.slice(ip.off, ip.off + Math.min(ip.total, ip.ihl + 8));
    const src = iface && iface.ip ? iface.ip : (this.primaryIface ? this.primaryIface.ip : 0);
    this.counters.icmpOut++;
    this.sendIp(ip.src, 1, () => Codec.icmp({ type, code, rest: 0, payload: q }), { src, ttl: this.type === 'router' ? 255 : this.ttl });
  }
  icmpInput(iface, p) {
    const ic = p.icmp, ip = p.ip; this.counters.icmpIn++;
    if (ic.type === 8) {
      if (!this.allowIcmpEcho || IP.isBroadcast(ip.dst) || (ip.dst !== iface.ip && !this.isLocalIp(ip.dst) && ip.dst !== IP.bcast(iface.ip, iface.mask))) return;
      if (this.icmpFilter && !this.icmpFilter(iface, p)) return;
      this.counters.icmpOut++;
      this.sendIp(ip.src, 1, () => Codec.icmp({ type: 0, code: 0, id: ic.id, seq: ic.seq, payload: ic.payload }), { src: ip.dst, iface: undefined });
    } else if (ic.type === 0) {
      const w = this.pingW.get(ic.id + ':' + ic.seq); if (w) w({ type: 'reply', from: ip.src, ttl: ip.ttl, bytes: ic.payload.length });
    } else if ((ic.type === 3 || ic.type === 11) && ic.quote) {
      const q = ic.quote;
      if (q.proto === 1 && q.icmpType === 8) { const w = this.pingW.get(q.id + ':' + q.seq); if (w) w({ type: ic.type === 11 ? 'ttl' : 'unreach', from: ip.src, code: ic.code }); }
      else if (q.proto === 6) { const c = this.tcpC.get(q.src + ':' + q.sport + '-' + q.dst + ':' + q.dport); if (c && c.state === 'SYN_SENT') c.terminate('unreachable'); }
      else if (q.proto === 17 && this.udpErr) this.udpErr(q, ic, ip);
    }
  }
  /* Envoie une requête d'écho ; cb(res) appelé une seule fois. */
  pingOnce(dst, o, cb) {
    o = o || {}; const id = o.id || 1, seq = o.seq || 1, key = id + ':' + seq; const t0 = this.sim.now; let done = false;
    const fin = r => { if (done) return; done = true; this.sim.cancel(tm); this.pingW.delete(key); r.rtt = this.sim.now - t0; cb(r); };
    const tm = this.sim.at(o.timeout || 2000, () => fin({ type: 'timeout' }));
    this.pingW.set(key, fin);
    const payload = new Uint8Array(o.size === undefined ? 32 : o.size); for (let i = 0; i < payload.length; i++) payload[i] = 0x61 + (i % 23);
    this.counters.icmpOut++;
    const r = this.sendIp(dst, 1, () => Codec.icmp({ type: 8, code: 0, id, seq, payload }), { ttl: o.ttl, src: o.src, onFail: why => { fin({ type: why === 'arp' ? 'arpfail' : 'noroute' }); } });
    if (!r.ok) fin({ type: r.err === 'down' ? 'noroute' : 'noroute' });
  }
  /* ---- UDP ---- */
  udpBind(port, fn) { this.udp.set(port, fn); }
  udpUnbind(port) { this.udp.delete(port); }
  udpInput(iface, p) {
    const h = this.udp.get(p.udp.dport);
    if (h) { h(p, iface); return; }
    if (!IP.isBroadcast(p.ip.dst) && !IP.isMulticast(p.ip.dst) && p.ip.dst !== IP.bcast(iface.ip || 0, iface.mask || 0)) this.icmpError(p, iface, 3, 3);
  }
  udpSend(dst, dport, sport, payload, o) {
    o = o || {};
    return this.sendIp(dst, 17, src => Codec.udp(src, dst, sport, dport, payload), o);
  }
  /* diffusion sur une interface précise (client DHCP, RIP…) */
  udpSendOn(iface, srcIp, dst, dport, sport, payload, o) {
    o = o || {};
    const l4 = Codec.udp(srcIp, dst, sport, dport, payload);
    const ip = Codec.ipPacket({ id: this.nextId(), ttl: o.ttl || this.ttl, proto: 17, src: srcIp, dst, df: 0 }, l4);
    if (o.dstMac) this.sendFrame(iface, o.dstMac, 0x0800, ip); else this.ipOut(iface, dst, ip, null);
  }
  /* ---- TCP ---- */
  tcpListen(port, onAccept) { this.tcpL.set(port, { port, onAccept }); }
  tcpUnlisten(port) { this.tcpL.delete(port); }
  nextPort() { this.ephemeral++; if (this.ephemeral > 65000) this.ephemeral = 49152; return this.ephemeral; }
  tcpConnect(dst, dport, cbs) {
    const r = this.lookup(dst);
    if (!r && !this.isLocalIp(dst)) { if (cbs.onError) this.sim.at(0, () => cbs.onError('noroute')); return null; }
    const src = r ? r.iface.ip : dst;
    const c = new TcpConn(this, src, this.nextPort(), dst, dport);
    Object.assign(c, { onOpen: cbs.onOpen, onData: cbs.onData, onClose: cbs.onClose, onError: cbs.onError });
    c.iss = (this.sim.rng.next() * 4294967295) >>> 0; c.snd_una = c.iss; c.snd_nxt = (c.iss + 1) >>> 0; c.state = 'SYN_SENT';
    this.tcpC.set(c.key, c);
    let tries = 0;
    const send = () => {
      if (c.state !== 'SYN_SENT') return;
      if (tries >= 3) { c.terminate('timeout'); return; }
      tries++; c.seg(SYN, [], { seq: c.iss, mss: MSS }); c.timer = this.sim.at(tries === 1 ? 1000 : 2000, send);
    };
    send();
    return c;
  }
  tcpInput(iface, p) {
    const ip = p.ip, t = p.tcp;
    const key = ip.dst + ':' + t.dport + '-' + ip.src + ':' + t.sport;
    let c = this.tcpC.get(key);
    if (!c) {
      if ((t.flags & SYN) && !(t.flags & ACK)) {
        const lis = this.tcpL.get(t.dport);
        if (lis && (!this.tcpFilter || this.tcpFilter(iface, p))) {
          c = new TcpConn(this, ip.dst, t.dport, ip.src, t.sport);
          c.state = 'SYN_RCVD'; c.rcv_nxt = (t.seq + 1) >>> 0; c.iss = (this.sim.rng.next() * 4294967295) >>> 0; c.snd_una = c.iss; c.snd_nxt = (c.iss + 1) >>> 0;
          c.mss = Math.min(MSS, t.mss || MSS); c.listener = lis; this.tcpC.set(key, c);
          c.seg(SYN | ACK, [], { seq: c.iss, mss: MSS });
          c.timer = this.sim.at(1000, () => { if (c.state === 'SYN_RCVD') { c.terminate('timeout'); } });
          return;
        }
      }
      if (!(t.flags & RST) && !IP.isBroadcast(ip.dst) && !IP.isMulticast(ip.dst)) {
        // port fermé : RST
        const seq = (t.flags & ACK) ? t.ack : 0, ack = (t.seq + t.len + ((t.flags & SYN) ? 1 : 0) + ((t.flags & FIN) ? 1 : 0)) >>> 0;
        this.sendIp(ip.src, 6, src => Codec.tcp(src, ip.src, { sport: t.dport, dport: t.sport, seq, ack, flags: (t.flags & ACK) ? RST : (RST | ACK), payload: [] }), { src: ip.dst });
      }
      return;
    }
    c.input(p);
  }

  /* ---- ACL ---- */
  aclMatchAddr(a, ip) { return (((ip ^ a.ip) & (~a.wc)) >>> 0) === 0; }
  aclPortMatch(pm, port) {
    if (!pm) return true;
    switch (pm.op) { case 'eq': return port === pm.a; case 'neq': return port !== pm.a; case 'gt': return port > pm.a; case 'lt': return port < pm.a; case 'range': return port >= pm.a && port <= pm.b; }
    return true;
  }
  aclEntryMatch(acl, e, p) {
    const ip = p.ip;
    if (!this.aclMatchAddr(e.src, ip.src)) return false;
    if (acl.type === 'standard') return true;
    if (e.proto !== 'ip') {
      const pn = { icmp: 1, tcp: 6, udp: 17, ospf: 89, gre: 47, esp: 50, ahp: 51, eigrp: 88 }[e.proto] || e.proto;
      if (ip.proto !== pn) return false;
    }
    if (!this.aclMatchAddr(e.dst, ip.dst)) return false;
    if (e.proto === 'tcp' && p.tcp) {
      if (!this.aclPortMatch(e.sport, p.tcp.sport) || !this.aclPortMatch(e.dport, p.tcp.dport)) return false;
      if (e.established && !(p.tcp.flags & (ACK | RST))) return false;
    } else if (e.proto === 'udp' && p.udp) {
      if (!this.aclPortMatch(e.sport, p.udp.sport) || !this.aclPortMatch(e.dport, p.udp.dport)) return false;
    } else if ((e.proto === 'tcp' || e.proto === 'udp') && (e.sport || e.dport)) return false;
    if (e.proto === 'icmp' && e.icmpType !== undefined && e.icmpType !== null && (!p.icmp || p.icmp.type !== e.icmpType)) return false;
    return true;
  }
  aclPermit(name, p) {
    const acl = this.acls.get(name); if (!acl) return true;
    for (const e of acl.entries) if (this.aclEntryMatch(acl, e, p)) { e.hits = (e.hits || 0) + 1; return e.action === 'permit'; }
    return false;
  }
  aclDenied(iface, p) {
    this.counters.aclDeny++;
    this.log('ACL : paquet refusé ' + IP.str(p.ip.src) + ' → ' + IP.str(p.ip.dst) + ' sur ' + iface.name, 'warn');
    this.icmpError(p, iface, 3, 13);
  }

  /* ---- NAT ---- */
  natFindOut(proto, ilIp, ilPort, ogIp, ogPort) { return this.nat.table.find(e => e.proto === proto && e.ilIp === ilIp && e.ilPort === ilPort && (e.static || (e.ogIp === ogIp && e.ogPort === ogPort))); }
  natPortOf(p) {
    if (p.tcp) return { proto: 'tcp', sp: p.tcp.sport, dp: p.tcp.dport };
    if (p.udp) return { proto: 'udp', sp: p.udp.sport, dp: p.udp.dport };
    if (p.icmp && (p.icmp.type === 8 || p.icmp.type === 0)) return { proto: 'icmp', sp: p.icmp.id, dp: p.icmp.id };
    return null;
  }
  natOutbound(inIf, outIf, p) {
    const pp = this.natPortOf(p); if (!pp) return null;
    const ip = p.ip;
    // statique
    const st = this.nat.statics.find(s => s.lip === ip.src && (!s.proto || (s.proto === pp.proto && s.lport === pp.sp)));
    if (st) {
      const gip = st.gip || outIf.ip; const gport = st.proto ? st.gport : pp.sp;
      this.natTouch(pp.proto, st.lip, pp.sp, gip, gport, ip.dst, pp.dp, true);
      return this.natChange(pp, gip, gport, 'src');
    }
    let e = this.natFindOut(pp.proto, ip.src, pp.sp, ip.dst, pp.dp);
    if (!e) {
      const rule = this.nat.dyn.find(r => (!r.acl || this.aclPermit(r.acl, p)) && (r.iface ? this.ifaceByName(r.iface) === outIf : true));
      if (!rule) return null;
      let gip = rule.iface ? outIf.ip : rule.pool ? rule.pool.start : outIf.ip;
      let port = pp.sp;
      if (rule.iface || rule.overload) {
        const used = q => this.nat.table.some(x => x.proto === pp.proto && x.igIp === gip && x.igPort === q);
        if (used(port) || port < 1024) { port = 1024; while (used(port)) port++; }
      }
      e = this.natTouch(pp.proto, ip.src, pp.sp, gip, port, ip.dst, pp.dp, false);
    } else e.t = this.sim.now;
    return this.natChange(pp, e.igIp, e.igPort, 'src');
  }
  natTouch(proto, ilIp, ilPort, igIp, igPort, ogIp, ogPort, isStatic) {
    let e = this.nat.table.find(x => x.proto === proto && x.ilIp === ilIp && x.ilPort === ilPort && x.ogIp === ogIp && x.ogPort === ogPort);
    if (!e) { e = { proto, ilIp, ilPort, igIp, igPort, ogIp, ogPort, t: this.sim.now, static: isStatic }; this.nat.table.push(e); if (this.nat.table.length > 4000) this.nat.table.shift(); }
    e.t = this.sim.now; return e;
  }
  natChange(pp, ip, port, dir) {
    if (dir === 'src') return pp.proto === 'icmp' ? { ip: { src: ip }, l4: { id: port } } : { ip: { src: ip }, l4: { sport: port } };
    return pp.proto === 'icmp' ? { ip: { dst: ip }, l4: { id: port } } : { ip: { dst: ip }, l4: { dport: port } };
  }
  natInbound(iface, p) {
    const pp = this.natPortOf(p); if (!pp) return null; const ip = p.ip;
    if (pp.proto === 'icmp' && p.icmp.type !== 0) {
      // requêtes d'écho depuis l'extérieur : seulement si NAT statique 1:1
      const s1 = this.nat.statics.find(s => !s.proto && (s.gip || iface.ip) === ip.dst);
      if (s1) { return this.natReparse(p, { ip: { dst: s1.lip } }); }
      return null;
    }
    // traduction dynamique (retour)
    const e = this.nat.table.find(x => !x.static && x.proto === pp.proto && x.igIp === ip.dst && x.igPort === pp.dp && x.ogIp === ip.src && (pp.proto === 'icmp' || x.ogPort === pp.sp));
    if (e) { e.t = this.sim.now; return this.natReparse(p, this.natChange(pp, e.ilIp, e.ilPort, 'dst')); }
    // statique
    const s = this.nat.statics.find(s => (s.gip || iface.ip) === ip.dst && (!s.proto || (s.proto === pp.proto && s.gport === pp.dp)));
    if (s) {
      const lport = s.proto ? s.lport : pp.dp;
      this.natTouch(pp.proto, s.lip, lport, ip.dst, s.proto ? s.gport : pp.dp, ip.src, pp.sp, true);
      return this.natReparse(p, this.natChange(pp, s.lip, lport, 'dst'));
    }
    return null;
  }
  natReparse(p, ch) {
    const ipb = Codec.rebuildIp(p, ch);
    const f = Codec.frame({ dst: p.eth.dst, src: p.eth.src, vlan: p.eth.vlan, type: 0x0800, payload: ipb });
    return Codec.parse(f);
  }
  natClear() { this.nat.table = this.nat.table.filter(e => e.static); }
}

NS.Device = Device; NS.Iface = Iface; NS.IPNode = IPNode; NS.TcpConn = TcpConn;
})(typeof window !== 'undefined' ? window : globalThis);
