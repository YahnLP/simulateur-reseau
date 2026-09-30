/* devices.js — Hôtes, hub, switch (VLAN/trunk/STP/port-security/SVI), routeur, pare-feu, borne Wi-Fi, box */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, B, Device, IPNode, Iface, svc } = NS;
const BCAST = MAC.BCAST;

/* ---------- utilitaires ports ---------- */
function buildPorts(dev, m) {
  if (m.ports) m.ports.forEach(p => dev.addPort(p.name, { short: p.short, speed: p.speed, media: p.media, kind: p.kind }));
  if (m.portGroups) m.portGroups.forEach(gp => {
    for (let i = 0; i < gp.n; i++) { const idx = (gp.start || 0) + i; dev.addPort(gp.nonum ? gp.prefix : gp.prefix + idx, { short: gp.nonum ? gp.short : gp.short + idx, speed: gp.speed, media: gp.media || 'cu' }); }
  });
}
function ipOrNull(s) { return s ? IP.parse(s) : 0; }

/* ================================================================== Hôte (PC, serveur, imprimante…) */
class Host extends IPNode {
  constructor(sim, o) {
    const m = NS.CATALOG[o.model]; o.oui = NS.OUI[m.oui] || NS.OUI.generic; o.type = m.server ? 'server' : (m.peripheral ? 'peripheral' : 'pc');
    super(sim, o);
    this.os = m.os; this.ttl = m.os === 'windows' ? 128 : 64; this.forwarding = false; this.kindModel = m;
    buildPorts(this, m);
    this.ports.forEach(p => { this.addIface(p.name, { port: p }); });
    this.domain = '';
    this.dhcpd = new svc.DhcpServer(this); this.dnsd = new svc.DnsServer(this); this.httpd = new svc.HttpServer(this);
    this.udpBind(67, (p, i) => this.dhcpd.handle(p, i));
    this.wifi = { ssid: '', key: '' };
    this.shell = null;
    if (m.phone && NS.initPhone) NS.initPhone(this);
  }
  get mainIface() { return this.ifaceList()[0]; }
  /* applique une configuration IP (formulaire) à une interface */
  applyIp(ifaceName, cfg) {
    const i = this.ifaceByName(ifaceName) || this.mainIface;
    if (cfg.dhcp) { this.enableDhcp(i, true); return i; }
    this.enableDhcp(i, false);
    i.ip = cfg.ip ? (IP.parse(cfg.ip) || 0) : 0; i.mask = cfg.mask ? (IP.parseMask(cfg.mask) || 0) : 0; i.dhcpLeased = false;
    if (i.ip) this.sim.at(0.1, () => this.arpAnnounce(i));
    return i;
  }
  setGateway(gw) {
    this.statics = this.statics.filter(s => !(s.net === 0 && s.mask === 0));
    const ip = gw ? IP.parse(gw) : null; if (ip) this.statics.push({ net: 0, mask: 0, nh: ip, iface: null, ad: 1 });
  }
  get gateway() { const s = this.statics.find(s => s.net === 0 && s.mask === 0); return s ? s.nh : 0; }
  startServices() { if (this.dnsd.enabled) this.dnsd.start(); if (this.httpd.enabled) this.httpd.start(); }
  serialize() {
    const b = super.serialize();
    b.ifaces = this.ifaceList().map(i => ({ name: i.name, ip: i.ip && !i.dhcpLeased ? IP.str(i.ip) : '', mask: i.mask && !i.dhcpLeased ? IP.str(i.mask) : '', dhcp: !!i.dhcp }));
    const gs = this.statics.find(s => s.net === 0 && s.mask === 0 && !s.dhcp); b.gw = gs ? IP.str(gs.nh) : '';
    b.dns = this.dhcpDns ? [] : (this.dnsServers || []).map(IP.str); b.domain = this.domain; b.allowIcmpEcho = this.allowIcmpEcho; b.wifi = this.wifi; b.hosts = this.hosts;
    b.dhcpd = { enabled: this.dhcpd.enabled, excluded: this.dhcpd.excluded, pools: this.dhcpd.pools };
    b.dnsd = { enabled: this.dnsd.enabled, records: this.dnsd.records, forwarders: this.dnsd.forwarders.map(IP.str) };
    b.httpd = { enabled: this.httpd.enabled, https: this.httpd.https, pages: this.httpd.pages };
    return b;
  }
  restore(b) {
    (b.ifaces || []).forEach(c => { const i = this.ifaceByName(c.name); if (i) this.applyIp(i.name, c); });
    this.setGateway(b.gw); this.dnsServers = (b.dns || []).map(IP.parse).filter(x => x !== null); this.domain = b.domain || '';
    if (b.allowIcmpEcho !== undefined) this.allowIcmpEcho = b.allowIcmpEcho; if (b.wifi) this.wifi = b.wifi; this.hosts = b.hosts || {};
    if (b.dhcpd) { this.dhcpd.enabled = b.dhcpd.enabled; this.dhcpd.excluded = b.dhcpd.excluded || []; this.dhcpd.pools = b.dhcpd.pools || []; }
    if (b.dnsd) { this.dnsd.records = b.dnsd.records || []; this.dnsd.forwarders = (b.dnsd.forwarders || []).map(IP.parse); this.dnsd.enabled = false; if (b.dnsd.enabled) this.dnsd.start(); }
    if (b.httpd) { this.httpd.pages = b.httpd.pages || this.httpd.pages; this.httpd.https = !!b.httpd.https; this.httpd.enabled = false; if (b.httpd.enabled) this.httpd.start(); }
  }
}

/* ================================================================== Hub */
class Hub extends Device {
  constructor(sim, o) { const m = NS.CATALOG[o.model]; o.oui = NS.OUI[m.oui]; o.type = 'hub'; super(sim, o); this.mdi = 'MDIX'; buildPorts(this, m); this.ports.forEach(p => p.mdi = 'MDIX'); }
  recv(port, bytes) { this.ports.forEach(p => { if (p !== port && p.up) this.send(p, bytes); }); }
}

const Stp = NS.Stp;
const STP_MAC = '01:80:c2:00:00:00', PVST_MAC = '01:00:0c:cc:cc:cd';

/* ================================================================== Switch / commutateur (L2, L3, box) */
class Switch extends IPNode {
  constructor(sim, o) {
    const m = NS.CATALOG[o.model]; o.oui = NS.OUI[m.oui]; o.type = m.kind === 'box' ? 'box' : 'switch';
    super(sim, o);
    this.mdi = 'MDIX'; this.managed = m.managed !== false; this.model_ = m; this.forwarding = !!m.l3 && m.kind === 'box';
    this.ttl = 255; this.macTable = new Map(); this.vlans = new Map([[1, { name: 'default' }]]); this.stp = new Stp(this); this.initLag();
    this.macAging = 300000; this.l3capable = !!m.l3;
    buildPorts(this, m);
    this.ports.forEach(p => {
      p.mdi = 'MDIX'; p.mode = 'access'; p.vlan = 1; p.native = 1; p.allowed = null; p.portfast = false; p.routed = null; p.desc = '';
      p.stp = { state: 'forwarding', role: 'disabled', best: null, timer: null, v: new Map() }; p.sec = { enabled: false, max: 1, violation: 'shutdown', macs: new Set(), sticky: false }; p.errdis = false; p.lag = null;
    });
    if (this.managed) this.stp.enable();
    this.dhcpd = new svc.DhcpServer(this); this.relay = new svc.DhcpRelay(this);
    this.udpBind(67, (p, i) => this.relay.handle(p, i) || this.dhcpd.handle(p, i));
    this.rip = new svc.Rip(this); if (m.l3) this.ospf = new NS.Ospf(this); this.vty = { password: '', login: false }; this.enableSecret = ''; this.banner = '';
    if (m.kind === 'box') this.initBox();
    else if (this.managed) this.ports.forEach(p => { p.adminUp = true; });
  }
  destroy() { this.stp.dead = true; this.dead = true; }
  sviIface(v) { for (const i of this.ifaces.values()) if (i.svi === v) return i; return null; }
  sviUp(v) {
    if (!this.vlans.has(v)) return false;
    return this.l2ports().some(p => p.up && !p.routed && this.carries(p, v) && (!this.stp.enabled || (st => st !== 'blocking' && st !== 'disabled')(this.stp.stateFor(p, v))));
  }
  carries(p, v) { return p.mode === 'access' ? ((p.dynVlan || p.vlan) === v || (!!p.voiceVlan && p.voiceVlan === v)) : (p.allowed === null || p.allowed.has(v)); }
  /* --- Box : LAN (SVI 1) + WAN routé --- */
  initBox() {
    const wan = this.ports.find(p => p.name === 'WAN'); wan.routed = true;
    const lan = this.addIface('Vlan1', { svi: 1 }); lan.ip = IP.parse('192.168.1.1'); lan.mask = IP.parseMask('24'); lan.nat = 'inside';
    const w = this.addIface('WAN', { port: wan }); wan.routed = w; w.nat = 'outside'; this.enableDhcp(w, true);
    this.nat.dyn.push({ overload: true, iface: 'WAN', acl: null });
    this.dhcpd.enabled = true; this.dhcpd.addPool({ name: 'LAN', net: IP.parse('192.168.1.0'), mask: IP.parseMask('24'), router: lan.ip, dns: [lan.ip], start: IP.parse('192.168.1.10'), end: IP.parse('192.168.1.100'), lease: 86400 });
    this.udp.set(53, (p, i) => this.boxDns(p, i));
    this.dnsServers = [];
  }
  boxDns(p) { /* relais DNS : transmet la requête au DNS obtenu en DHCP WAN */
    const d = p.dns; if (!d || d.qr || !d.questions.length) return; const q = d.questions[0];
    const up = this.dnsServers && this.dnsServers[0]; if (!up) return;
    this.dnsQuery(up, q.name, q.type, (err, res) => {
      if (err) return;
      const out = Codec.dns({ id: d.id, qr: 1, rd: 1, ra: 1, rcode: res.rcode, questions: [{ name: q.name, type: q.type }], answers: res.answers });
      this.udpSend(p.ip.src, p.udp.sport, 53, out, { src: p.ip.dst });
    });
  }
  /* --- table MAC --- */
  macGet(v, m) { const k = v + '|' + m; const e = this.macTable.get(k); if (!e) return null; if (this.sim.now - e.t > this.macAging) { this.macTable.delete(k); return null; } return e; }
  /* apprentissage avec capacité de la table CAM (bande passante pédagogique : une attaque de saturation
     ("MAC flooding") remplit la table de fausses adresses ; une fois pleine, le commutateur n'apprend
     plus de nouvelles adresses et inonde (comme un hub) le trafic dont l'adresse n'est plus apprise). */
  learnMac(v, m, port) {
    const k = v + '|' + m; const cap = this.model_ && this.model_.macTableSize;
    if (!this.macTable.has(k) && cap && this.macTable.size >= cap) {
      if (!this._macTableFullAt) { this._macTableFullAt = this.sim.now; this.log('Table d\'adresses MAC saturée (' + cap + ' entrées) : plus d\'apprentissage, le trafic non appris est inondé sur tous les ports', 'warn'); }
      return;
    }
    this.macTable.set(k, { port, t: this.sim.now });
  }
  secCheck(port, mac, v) {
    const s = port.sec; if (!s.enabled) return true;
    if (s.macs.has(mac)) return true;
    if (s.macs.size < s.max) { s.macs.add(mac); return true; }
    this.log('Port-security : violation sur ' + port.name + ' (' + mac + ')', 'warn');
    if (s.violation === 'shutdown') { port.errdis = true; this.sim.portChanged(port); if (port.peer) this.sim.portChanged(port.peer); if (this.stp.enabled) this.stp.portChanged(port); }
    s.violations = (s.violations || 0) + 1;
    return false;
  }
  portStateChanged(port) {
    super.portStateChanged(port);
    if (port.lag) this.lagMemberChanged(port);
    if (this.stp.enabled) this.stp.portChanged(port);
    if (!port.up) { for (const [k, e] of this.macTable) if (e.port === port) this.macTable.delete(k); }
    if (this.dot1x && this.dot1x.enabled) this.dot1x.portChanged(port);
    if (port.up && port.voiceVlan && this.managed) this.sim.at(50, () => this.sendCdp(port));
  }
  /* CDP : annonce le VLAN voix (VoIP VLAN Reply) au téléphone connecté ; renouvelé toutes les 60 s */
  sendCdp(port) {
    if (!port.up || !port.voiceVlan || !this.managed) return;
    const pl = Codec.cdp({ device: this.name, port: port.name, platform: 'cisco ' + (this.kindModel && this.kindModel.label || 'WS-C2960'), caps: 40, voiceVlan: port.voiceVlan });
    this.send(port, Codec.frameSnap({ dst: Codec.CDP_MAC, src: port.mac, oui: [0, 0, 12], pid: 0x2000, payload: pl }));
    if (!port._cdpT || port._cdpT.dead) port._cdpT = this.sim.at(60000, () => { port._cdpT = null; this.sendCdp(port); });
  }
  /* --- réception --- */
  recv(port, bytes) {
    if (!port.up) return;
    if (port.routed) { IPNode.prototype.recv.call(this, port, bytes); return; }
    const p = Codec.parse(bytes, false); if (!p.eth) return;
    const dst = p.eth.dst, src = p.eth.src;
    const lp = port.lag && port.lag.bundled ? port.lag.ch.lp : port;
    if (this.managed) {
      if (p.cdp) { if (p.cdp.query && port.voiceVlan) this.sendCdp(port); return; }
      if (dst === NS.LACP_MAC || dst === NS.PAGP_MAC) { if (port.lag) this.lagInput(port, p); return; }
      if (dst === STP_MAC || dst === PVST_MAC) { if (this.stp.enabled) this.stp.input(lp, p); return; }
    }
    port = lp;
    if (this.dot1x && this.dot1x.enabled) {
      if (p.eapol || dst === '01:80:c2:00:00:03') { if (p.eapol && this.dot1x.active(port)) this.dot1x.authInput(port, p); return; }
      if (this.dot1x.active(port) && !this.dot1x.allows(port, src, p)) { this.dot1x.noteDrop(port, src); return; }
    }
    const tag = p.eth.vlan; let vlan;
    if (port.mode === 'access') { if (tag && tag.vid !== 0) { if (port.voiceVlan && tag.vid === port.voiceVlan) vlan = tag.vid; else return; } else vlan = port.dynVlan || port.vlan; }
    else { vlan = (tag && tag.vid !== 0) ? tag.vid : port.native; if (!(port.allowed === null || port.allowed.has(vlan))) return; }
    const st = this.stp.enabled ? this.stp.stateFor(port, vlan) : 'forwarding';
    if (st === 'blocking' || st === 'listening' || st === 'disabled') return;
    if (!this.vlans.has(vlan)) return;
    if (this.managed && !this.secCheck(port, src, vlan)) return;
    if (!MAC.isMulticast(src)) this.learnMac(vlan, src, port);
    if (st === 'learning') return;
    const bc = dst === BCAST || MAC.isMulticast(dst);
    const svi = this.sviIface(vlan);
    if (svi && svi.isUp() && (dst === this.baseMac || bc && (dst === BCAST || this.joined.has(dst) || (this.ip6 && this.ip6.acceptsMac(svi, dst))))) this.input(svi, p);
    if (dst === this.baseMac) return;
    const tagged = !!tag;
    if (bc) { this.flood(port, vlan, bytes, tagged); return; }
    const e = this.macGet(vlan, dst);
    if (e) { if (e.port !== port) this.egress(e.port, vlan, bytes, tagged); }
    else this.flood(port, vlan, bytes, tagged);
  }
  flood(from, vlan, bytes, tagged) { this.l2ports().forEach(p => { if (p !== from && p.up && !p.routed) this.egress(p, vlan, bytes, tagged); }); }
  egress(out, vlan, bytes, wasTagged) {
    if (!out.up) return;
    if (this.stp.enabled && this.stp.stateFor(out, vlan) !== 'forwarding') return;
    let want;
    if (this.dot1x && this.dot1x.enabled && this.dot1x.active(out) && !this.dot1x.egressAllows(out, MAC.fromBytes(bytes, 0))) return;
    if (out.mode === 'access') { if (out.voiceVlan && vlan === out.voiceVlan && out.voiceVlan !== (out.dynVlan || out.vlan)) want = true; else { if ((out.dynVlan || out.vlan) !== vlan) return; want = false; } }
    else { if (!(out.allowed === null || out.allowed.has(vlan))) return; want = vlan !== out.native; }
    let f = bytes;
    if (want && !wasTagged) { f = new Uint8Array(bytes.length + 4); f.set(bytes.subarray(0, 12), 0); f[12] = 0x81; f[13] = 0x00; f[14] = (vlan >> 8) & 15; f[15] = vlan & 255; f.set(bytes.subarray(12), 16); }
    else if (want && wasTagged) { /* déjà étiqueté avec le bon VLAN */ }
    else if (!want && wasTagged) { f = new Uint8Array(bytes.length - 4); f.set(bytes.subarray(0, 12), 0); f.set(bytes.subarray(16), 12); }
    this.sendL(out, f);
  }
  sviTx(vlan, frame) {
    const dst = MAC.fromBytes(frame, 0);
    if (dst === BCAST || MAC.isMulticast(dst)) { this.flood(null, vlan, frame, false); return true; }
    const e = this.macGet(vlan, dst);
    if (e) this.egress(e.port, vlan, frame, false); else this.flood(null, vlan, frame, false);
    return true;
  }
  /* pings vers le switch lui-même passent par les SVI ; le routage L3 exige `ip routing` */
  serialize() { const b = super.serialize(); if (this.cliText) b.cli = this.cliText(); b.startup = this.startup; return b; }
}

/* ================================================================== Routeur (Cisco IOS) */
class Router extends IPNode {
  constructor(sim, o) {
    const m = NS.CATALOG[o.model]; o.oui = NS.OUI[m.oui]; o.type = 'router';
    super(sim, o);
    this.forwarding = true; this.ttl = 255; this.model_ = m;
    buildPorts(this, m);
    this.ports.forEach(p => { const i = this.addIface(p.name, { port: p }); i.adminUp = false; p.adminUp = false; });
    this.dhcpd = new svc.DhcpServer(this); this.dhcpd.enabled = true; this.relay = new svc.DhcpRelay(this);
    this.udpBind(67, (p, i) => this.relay.handle(p, i) || this.dhcpd.handle(p, i));
    this.rip = new svc.Rip(this); this.ospf = new NS.Ospf(this); this.vty = { password: '', login: false }; this.enableSecret = ''; this.banner = ''; this.domain = '';
    this.natInterval = 0;
  }
  serialize() { const b = super.serialize(); if (this.cliText) b.cli = this.cliText(); b.startup = this.startup; return b; }
}

/* ================================================================== Pare-feu (Stormshield / Fortinet / pfSense) */
function parsePorts(s) {
  if (!s || s === 'any') return null;
  const r = [];
  String(s).split(',').forEach(t => { t = t.trim(); const m = /^(\d+)(?:-(\d+))?$/.exec(t); if (m) r.push([+m[1], +(m[2] || m[1])]); });
  return r.length ? r : null;
}
class Firewall extends IPNode {
  constructor(sim, o) {
    const m = NS.CATALOG[o.model]; o.oui = NS.OUI[m.oui]; o.type = 'firewall';
    super(sim, o);
    this.forwarding = true; this.ttl = 64; this.model_ = m; this.style = m.fwStyle;
    buildPorts(this, m);
    this.ports.forEach(p => { const i = this.addIface(p.name, { port: p }); const mp = m.ports.find(x => x.name === p.name); i.zone = mp.zone; });
    Object.keys(m.defaults || {}).forEach(n => { const i = this.ifaceByName(n), d = m.defaults[n]; if (d.dhcp) this.enableDhcp(i, true); else { i.ip = IP.parse(d.ip); i.mask = IP.parseMask(d.mask); } });
    this.rules = []; this.sessions = new Map(); this.fwlog = []; this.natMasq = []; this.forwards = []; this.wanPing = false; this.policyLog = true;
    this.dhcpd = new svc.DhcpServer(this); this.rip = new svc.Rip(this);
    this.udpBind(67, (p, i) => this.dhcpd.handle(p, i));
    this.defaultPolicy();
  }
  zones() { const z = new Set(); this.ifaceList().forEach(i => z.add(i.zone)); return Array.from(z); }
  defaultPolicy() {
    this.rules = [
      { on: true, action: 'pass', from: 'LAN', to: 'WAN', proto: 'any', src: 'any', dst: 'any', dport: 'any', comment: 'Accès Internet du LAN' },
      { on: true, action: 'pass', from: 'LAN', to: 'DMZ', proto: 'any', src: 'any', dst: 'any', dport: 'any', comment: 'Le LAN accède à la DMZ' },
      { on: true, action: 'pass', from: 'DMZ', to: 'WAN', proto: 'any', src: 'any', dst: 'any', dport: 'any', comment: 'La DMZ accède à Internet' },
    ];
    this.natMasq = [{ from: 'LAN', to: 'WAN' }, { from: 'DMZ', to: 'WAN' }];
    this.rebuildNat();
  }
  rebuildNat() {
    this.nat.dyn = []; this.nat.statics = [];
    this.ifaceList().forEach(i => { i.nat = null; });
    this.natMasq.forEach(r => {
      this.ifaceList().forEach(i => { if (i.zone === r.from) i.nat = 'inside'; });
      this.ifaceList().forEach(i => { if (i.zone === r.to) { i.nat = 'outside'; if (!this.nat.dyn.some(d => d.iface === i.name)) this.nat.dyn.push({ overload: true, iface: i.name, acl: null }); } });
    });
    this.forwards.forEach(f => { const lip = IP.parse(f.toIp); if (lip !== null) this.nat.statics.push({ proto: f.proto, gport: f.port, lip, lport: f.toPort || f.port, gip: 0 }); });
    if (this.forwards.length) this.ifaceList().forEach(i => { if (i.zone === 'WAN' && !i.nat) i.nat = 'outside'; });
  }
  ruleMatch(r, zin, zout, p) {
    if (!r.on) return false;
    if (r.from !== 'any' && r.from !== zin) return false; if (r.to !== 'any' && r.to !== zout) return false;
    const ip = p.ip;
    if (r.proto !== 'any') { const pn = { tcp: 6, udp: 17, icmp: 1 }[r.proto]; if (ip.proto !== pn) return false; }
    const netOk = (spec, a) => { if (!spec || spec === 'any') return true; const c = IP.parseCidr(spec.indexOf('/') < 0 ? spec + '/32' : spec); return c ? IP.inNet(a, c.ip, c.mask) : false; };
    if (!netOk(r.src, ip.src) || !netOk(r.dst, ip.dst)) return false;
    const ports = parsePorts(r.dport);
    if (ports) { const dp = p.tcp ? p.tcp.dport : p.udp ? p.udp.dport : -1; if (!ports.some(x => dp >= x[0] && dp <= x[1])) return false; }
    return true;
  }
  flowKey(p) {
    const ip = p.ip; let pr, sp = 0, dp = 0;
    if (p.tcp) { pr = 'tcp'; sp = p.tcp.sport; dp = p.tcp.dport; } else if (p.udp) { pr = 'udp'; sp = p.udp.sport; dp = p.udp.dport; } else if (p.icmp) { pr = 'icmp'; sp = dp = p.icmp.id; } else pr = 'ip' + ip.proto;
    return { fwd: pr + '|' + ip.src + '|' + sp + '|' + ip.dst + '|' + dp, rev: pr + '|' + ip.dst + '|' + dp + '|' + ip.src + '|' + sp, pr };
  }
  logFw(action, p, why, zin, zout) {
    const ip = p.ip; const e = { t: this.sim.now, action, src: IP.str(ip.src), dst: IP.str(ip.dst), proto: p.tcp ? 'tcp' : p.udp ? 'udp' : p.icmp ? 'icmp' : String(ip.proto), sport: p.tcp ? p.tcp.sport : p.udp ? p.udp.sport : '', dport: p.tcp ? p.tcp.dport : p.udp ? p.udp.dport : '', why, zin, zout };
    this.fwlog.push(e); if (this.fwlog.length > 400) this.fwlog.shift();
    if (action !== 'pass') this.log('Pare-feu : ' + action + ' ' + e.proto + ' ' + e.src + (e.sport !== '' ? ':' + e.sport : '') + ' → ' + e.dst + (e.dport !== '' ? ':' + e.dport : '') + ' (' + why + ')', 'warn');
  }
  forwardFilter(inIf, outIf, p) {
    const k = this.flowKey(p); const now = this.sim.now;
    let s = this.sessions.get(k.fwd), viaRev = false; if (!s) { s = this.sessions.get(k.rev); viaRev = !!s; }
    if (s && viaRev && p.icmp && p.icmp.type === 8) s = null; // une requête d'écho inverse n'est jamais « établie »
    if (s && s.exp > now) { s.exp = now + (k.pr === 'tcp' ? 3600000 : 60000); return true; }
    if (s) { this.sessions.delete(k.fwd); this.sessions.delete(k.rev); }
    if (p.tcp && !(p.tcp.flags & 2)) { this.logFw('block', p, 'TCP hors session (pas de SYN)', inIf.zone, outIf.zone); return false; }
    for (let n = 0; n < this.rules.length; n++) {
      const r = this.rules[n];
      if (this.ruleMatch(r, inIf.zone, outIf.zone, p)) {
        r.hits = (r.hits || 0) + 1;
        if (r.action === 'pass') { this.sessions.set(k.fwd, { exp: now + (k.pr === 'tcp' ? 3600000 : 60000), t: now, zin: inIf.zone, zout: outIf.zone, pr: k.pr, rule: n + 1 }); this.logFw('pass', p, 'règle ' + (n + 1), inIf.zone, outIf.zone); return true; }
        this.logFw(r.action, p, 'règle ' + (n + 1), inIf.zone, outIf.zone);
        if (r.action === 'reject') this.icmpError(p, inIf, 3, 13);
        return false;
      }
    }
    this.logFw('block', p, 'politique par défaut', inIf.zone, outIf.zone);
    return false;
  }
  inFilter(iface, p) {
    if (!this.isLocalDst(iface, p.ip.dst)) return true;
    if (iface.zone === 'WAN') {
      if (p.udp && (p.udp.dport === 68 || p.udp.dport === 67)) return true;
      if (p.icmp && p.icmp.type === 8) { if (!this.wanPing) { this.logFw('block', p, 'ping refusé sur WAN', 'WAN', 'FW'); return false; } }
      if (p.tcp && (p.tcp.flags & 2) && !(p.tcp.flags & 16)) { this.logFw('block', p, 'connexion vers le pare-feu refusée (WAN)', 'WAN', 'FW'); return false; }
    }
    return true;
  }
  serialize() {
    const b = super.serialize();
    b.fw = { ifaces: this.ifaceList().map(i => ({ name: i.name, ip: i.ip && !i.dhcpLeased ? IP.str(i.ip) : '', mask: i.mask && !i.dhcpLeased ? IP.str(i.mask) : '', dhcp: !!i.dhcp, zone: i.zone, up: i.adminUp })), rules: this.rules, natMasq: this.natMasq, forwards: this.forwards, wanPing: this.wanPing, dhcpd: { enabled: this.dhcpd.enabled, pools: this.dhcpd.pools, excluded: this.dhcpd.excluded } };
    return b;
  }
  restore(b) {
    const f = b.fw; if (!f) return;
    f.ifaces.forEach(c => { const i = this.ifaceByName(c.name); if (!i) return; i.zone = c.zone; i.adminUp = c.up !== false; if (c.dhcp) this.enableDhcp(i, true); else { this.enableDhcp(i, false); i.ip = c.ip ? IP.parse(c.ip) : 0; i.mask = c.mask ? IP.parseMask(c.mask) : 0; } });
    this.rules = f.rules || []; this.natMasq = f.natMasq || []; this.forwards = f.forwards || []; this.wanPing = !!f.wanPing;
    if (f.dhcpd) { this.dhcpd.enabled = f.dhcpd.enabled; this.dhcpd.pools = f.dhcpd.pools || []; this.dhcpd.excluded = f.dhcpd.excluded || []; }
    this.rebuildNat();
  }
}

/* ================================================================== Borne Wi-Fi (pont L2 + association dynamique) */
class AP extends Switch {
  constructor(sim, o) {
    const m = NS.CATALOG[o.model]; o.model_ = m;
    // AP = switch non manageable avec un port filaire ; les ports radio sont créés à l'association
    const saved = m.ports; super(sim, Object.assign(o, { _ap: true }));
    this.type = 'ap'; this.ssid = 'LYCEE-WIFI'; this.key = 'ciel2026'; this.security = 'WPA2'; this.radioN = 0;
    this.managed = false; this.stp.enabled = false; this.stp.dead = true;
    // supprime le port radio "modèle" (on crée des liaisons virtuelles par client)
    const radio = this.ports.find(p => p.name === 'Radio'); if (radio) { this.ports.splice(this.ports.indexOf(radio), 1); }
    this.ports.forEach(p => { p.stp.state = 'forwarding'; });
  }
  associate(cport) {
    const p = this.addPort('wlan' + (++this.radioN), { speed: 300, media: 'wifi', kind: 'radio' });
    p.mdi = 'MDIX'; p.mode = 'access'; p.vlan = 1; p.native = 1; p.allowed = null; p.portfast = true; p.routed = null; p.desc = '';
    p.stp = { state: 'forwarding', role: 'disabled', best: null, timer: null, v: new Map() }; p.sec = { enabled: false, max: 1, violation: 'shutdown', macs: new Set() }; p.errdis = false; p.lag = null;
    p.virtual = true;
    return this.sim.connect(p, cport, 'wifi');
  }
}
/* Association Wi-Fi : relie les portables (SSID/clé identiques) aux bornes */
function wifiRefresh(sim) {
  const aps = Array.from(sim.devices.values()).filter(d => d instanceof AP);
  sim.devices.forEach(d => {
    if (!(d instanceof Host) || !d.kindModel.wifi) return;
    const wp = d.ports.find(p => p.media === 'wifi'); if (!wp) return;
    const want = d.wifi && d.wifi.ssid ? aps.find(a => a.ssid === d.wifi.ssid && a.key === d.wifi.key && a.powered) : null;
    const cur = wp.link ? wp.link.other(wp).dev : null;
    if (cur === want) return;
    if (wp.link) { const ap = cur; const rp = wp.link.other(wp); sim.disconnect(wp.link); ap.ports.splice(ap.ports.indexOf(rp), 1); }
    if (want) want.associate(wp);
  });
}

/* ================================================================== Fabrique */
const KIND = { host: Host, switch: Switch, box: Switch, hub: Hub, router: Router, firewall: Firewall, ap: AP };
function createDevice(sim, modelKey, o) {
  const m = NS.CATALOG[modelKey]; if (!m) throw new Error('modèle inconnu ' + modelKey);
  o = Object.assign({}, o); o.model = modelKey;
  if (!o.name) { let n = 1; const pre = m.prefix || 'D'; const names = new Set(Array.from(sim.devices.values()).map(d => d.name)); while (names.has(pre + n)) n++; o.name = pre + n; }
  const D = KIND[m.kind]; const d = new D(sim, o);
  d.kind = m.kind; sim.addDevice(d);
  if (m.aos && NS.aosAttach) NS.aosAttach(d);
  else if ((d instanceof Router || (d instanceof Switch && d.managed)) && NS.attachRemote) NS.attachRemote(d);
  if (d.httpd && !d.httpd.pages['/']._custom) d.httpd.pages['/'].body = '<html><head><title>' + d.name + '</title></head><body><h1>Bienvenue sur ' + d.name + '</h1><p>Serveur web du simulateur.</p></body></html>';
  return d;
}

NS.installLag(Switch);
NS.Host = Host; NS.Hub = Hub; NS.Switch = Switch; NS.Router = Router; NS.Firewall = Firewall; NS.AP = AP;
NS.createDevice = createDevice; NS.wifiRefresh = wifiRefresh; NS.buildPorts = buildPorts;
})(typeof window !== 'undefined' ? window : globalThis);
