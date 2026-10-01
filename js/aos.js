/* aos.js — Alcatel-Lucent OmniSwitch 6400-P48 : CLI AOS 6.4 (pas de mode enable/configure, invite « -> »),
   VLAN (default/802.1q), interfaces IP, routes statiques, spantree, linkagg LACP, PoE (lanpower), 802.1X/RADIUS, port-security.
   La sortie des commandes reprend la présentation d'AOS ; elle est reconstituée (pas de capture sur matériel réel). */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {}; const { IP, Codec } = NS; const U = () => NS.iosUtil;
const pad = (s, n) => String(s).padEnd(n), padL = (s, n) => String(s).padStart(n);
const cm = m => m.replace(/:/g, ':');
const tokz = l => { const t = []; const re = /"([^"]*)"|(\S+)/g; let m; while ((m = re.exec(l))) t.push(m[1] !== undefined ? m[1] : m[2]); return t; };
const fmtUp = ms => { let s = Math.floor(ms / 1000); const d = Math.floor(s / 86400); s -= d * 86400; const h = Math.floor(s / 3600); s -= h * 3600; const m = Math.floor(s / 60); s -= m * 60; return d + ' days ' + h + ' hours ' + m + ' minutes and ' + s + ' seconds'; };
const hhmmss = ms => { const s = Math.floor(ms / 1000); return String(Math.floor(s / 3600)).padStart(2, '0') + ':' + String(Math.floor(s / 60) % 60).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
const POE_ALLOC = 15400;  // mW alloués par port (802.3af)
const PD_W = { ipphone: 4000, 'ap-u6': 9000 }; // consommation typique simulée (mW) — non issue de la fiche

/* ---- désignation des ports : 1/1, 1/1-4, 1/1-4 1/10, linkagg 3 ---- */
function parsePorts(d, toks) {
  const out = []; let bad = false;
  toks.join(' ').split(/[\s,]+/).filter(Boolean).forEach(seg => {
    let m;
    if ((m = /^(\d+)\/(\d+)-(\d+)$/.exec(seg))) { for (let n = +m[2]; n <= +m[3]; n++) { const p = d.findPort(m[1] + '/' + n); if (p) out.push(p); else bad = true; } }
    else if ((m = /^(\d+)\/(\d+)$/.exec(seg))) { const p = d.findPort(seg); if (p) out.push(p); else bad = true; }
    else if ((m = /^(?:linkagg)?(\d+)$/.exec(seg)) && d.chans.has(+m[1])) out.push(d.chans.get(+m[1]).lp);
    else bad = true;
  });
  return bad ? null : out;
}
const pname = p => p.chan ? 'linkagg ' + p.chan : p.name;
function chanIdOf(d, lp) { for (const [k, c] of d.chans) if (c.lp === lp) return k; return 0; }
const portLabel = (d, p) => { const id = chanIdOf(d, p); return id ? String(id) : p.name; };

/* ---- membership VLAN -> paramètres du switch ---- */
function applyMembership(d, p) {
  p.aosDef = p.aosDef || 1; const tags = Array.from(p.aosTag || []).filter(v => v !== p.aosDef);
  if (!tags.length) { p.mode = 'access'; p.vlan = p.aosDef; p.allowed = null; p.native = 1; }
  else { p.mode = 'trunk'; p.native = p.aosDef; p.allowed = new Set([p.aosDef].concat(tags)); }
  p.explicitAccess = false; d.syncChans && d.syncChans(); d.macTable.clear();
}
function memberVlansOf(p) { const r = new Set([p.aosDef || 1]); (p.aosTag || new Set()).forEach(v => r.add(v)); return r; }

class AosSession {
  constructor(dev) { this.dev = dev; this.history = []; this.mode = 'priv'; this.ctx = null; this.closed = false; this.pending = null; this.isRouter = false; this.isSwitch = true; this.remote = null; this.hostVersion = '6.4.x'; }
  get name() { return this.dev.name; }
  abort() { this.aborted = true; }
  prompt() { return '-> '; }
  get masking() { return false; }
  exec(line, io) {
    this.aborted = false; const l = line.trim(); if (l) this.history.push(l); if (!l) { io.done(); return; }
    const d = this.dev; let r;
    try { r = this.run(l, tokz(l), io); } catch (e) { io.print('ERROR: ' + e.message + '\n'); console.error(e); }
    if (r !== 'async') io.done();
  }
  complete(l) { const all = AOS_WORDS.filter(w => w.startsWith(l.trim().toLowerCase())); if (all.length === 1) return all[0] + ' '; return all.length ? all : ''; }
  help(l) { const t = l.trim().toLowerCase(); return AOS_WORDS.filter(w => w.startsWith(t)).slice(0, 40).map(w => [w, '']); }
  err(io, msg) { io.print('ERROR: ' + msg + '\n'); }
  run(l, T, io) {
    const d = this.dev; const t = T.map(x => x.toLowerCase()); const c0 = t[0];
    const ok = () => { };
    const invalid = () => io.print('ERROR: Invalid entry: "' + (T[1] !== undefined ? T[1] : T[0]) + '"\n');
    // ------------------------------------------------ VLAN
    if (c0 === 'vlan') {
      if (t[1] === 'port' || t[1] === 'mobile' ) { return invalid(); }
      const list = t[1] === undefined ? null : (U().parseVlanList ? U().parseVlanList(t[1]) : null); const ids = list ? Array.from(list) : []; if (!ids.length || ids.some(v => v < 1 || v > 4094)) { this.err(io, 'VLAN Id must be between 1 and 4094'); return; }
      const sub = t[2];
      if (sub === undefined || sub === 'enable' || sub === 'disable') { ids.forEach(v => { if (!d.vlans.has(v)) d.vlans.set(v, { name: 'VLAN ' + v }); if (sub === 'disable') { d.vlans.get(v).off = true; } else d.vlans.get(v).off = false; }); d.stp.syncVlans && d.stp.syncVlans(); return; }
      if (sub === 'name') { const nm = T[3]; if (nm === undefined) return invalid(); ids.forEach(v => { const e = d.vlans.get(v) || {}; e.name = nm; d.vlans.set(v, e); }); d.stp.syncVlans && d.stp.syncVlans(); return; }
      if (sub === 'port' && (t[3] === 'default')) { const ps = parsePorts(d, T.slice(4)); if (!ps || !ps.length) { this.err(io, 'Invalid port'); return; } if (ids.length !== 1) return invalid(); const v = ids[0]; if (!d.vlans.has(v)) { this.err(io, 'VLAN ' + v + ' does not exist'); return; } ps.forEach(p => { p.aosDef = v; applyMembership(d, p); }); d.stp.syncVlans && d.stp.syncVlans(); return; }
      if (sub === '802.1q') { const ps = parsePorts(d, T.slice(3).filter(x => !/^[a-z]/i.test(x) || /^linkagg$/i.test(x) ? true : false).filter(x => /^[\d\/,-]+$/.test(x) || /^linkagg$/i.test(x))); if (!ps || !ps.length) { this.err(io, 'Invalid port'); return; } if (ids.length !== 1) return invalid(); const v = ids[0]; if (!d.vlans.has(v)) { this.err(io, 'VLAN ' + v + ' does not exist'); return; } ps.forEach(p => { p.aosTag = p.aosTag || new Set(); p.aosTag.add(v); applyMembership(d, p); }); d.stp.syncVlans && d.stp.syncVlans(); return; }
      if (sub === 'stp') { if (t[3] === 'enable') d.stp.enableVlan(ids[0]); else d.stp.disableVlan(ids[0]); return; }
      if (sub === 'mtu-ip' || sub === 'router' || sub === 'source-learning') return ok();
      return invalid();
    }
    if (c0 === 'no' && t[1] === 'vlan') {
      const v = +t[2]; if (!d.vlans.has(v)) { this.err(io, 'VLAN ' + v + ' does not exist'); return; }
      if (t[3] === '802.1q') { const ps = parsePorts(d, T.slice(4)); if (!ps) return invalid(); ps.forEach(p => { if (p.aosTag) p.aosTag.delete(v); applyMembership(d, p); }); return; }
      if (v === 1) { this.err(io, 'Cannot delete VLAN 1 (default VLAN)'); return; }
      d.ports.concat(Array.from(d.chans.values()).map(c => c.lp)).forEach(p => { if (p.aosDef === v) p.aosDef = 1; if (p.aosTag) p.aosTag.delete(v); applyMembership(d, p); }); d.vlans.delete(v); d.stp.syncVlans && d.stp.syncVlans(); return;
    }
    if (c0 === 'show' && t[1] === 'vlan') { return this.showVlan(io, t); }
    if (c0 === 'show' && t[1] === '802.1q') { const ps = parsePorts(d, T.slice(2)); if (!ps || !ps.length) return invalid(); let o = ''; ps.forEach(p => { const tg = Array.from(p.aosTag || []).sort((a, b) => a - b); o += 'Acceptable Frame Type  :  ' + (tg.length ? 'Any' : 'Any') + '\n  Force Tag Internal  :  NONE\n\n  VLAN    Tagging\n-------+-----------\n'; tg.forEach(v => { o += padL(v, 6) + '  tagged\n'; }); o += padL(p.aosDef || 1, 6) + '  untagged\n'; }); io.print(o); return; }
    // ------------------------------------------------ interfaces
    if (c0 === 'interfaces') {
      const ps = parsePorts(d, [T[1] || '']); if (!ps || !ps.length) { this.err(io, 'Invalid port'); return; } const k = t[2];
      if (k === 'admin') { ps.forEach(p => { p.adminUp = t[3] === 'up'; d.sim.portChanged && d.sim.portChanged(p); }); return; }
      if (k === 'alias') { ps.forEach(p => { p.desc = T[3] || ''; }); return; }
      if (k === 'speed' || k === 'duplex' || k === 'autoneg' || k === 'flow' || k === 'ifg' || k === 'hybrid-mode' || k === 'clear-violation-all') return ok();
      if (k === 'no') return ok();
      return invalid();
    }
    if (c0 === 'show' && t[1] === 'interfaces') { return this.showInterfaces(io, T, t); }
    // ------------------------------------------------ IP
    if (c0 === 'ip' && t[1] === 'interface') { return this.ipInterface(io, T, t); }
    if (c0 === 'no' && t[1] === 'ip' && t[2] === 'interface') { const nm = T[3]; const i = d.ifaceList().find(x => x.aosName === nm); if (!i) { this.err(io, 'Interface ' + nm + ' does not exist'); return; } d.ifaces.delete(i.name); return; }
    if (c0 === 'show' && t[1] === 'ip' && t[2] === 'interface') { return this.showIpIf(io, T[3]); }
    if (c0 === 'ip' && t[1] === 'static-route') {
      const net = t[2] === 'default' ? 0 : IP.parse(t[2]); const mi = t.indexOf('mask'), gi = t.indexOf('gateway'); const mask = t[2] === 'default' ? 0 : IP.parseMask(t[mi + 1] || '255.255.255.255'); const gw = IP.parse(t[gi + 1] || t[3] || '');
      if (net === null || mask === null || gw === null) return invalid(); const metric = t.indexOf('metric'); d.addStatic(net, mask, gw, null, metric >= 0 ? +t[metric + 1] : 1); return;
    }
    if (c0 === 'no' && t[1] === 'ip' && t[2] === 'static-route') { const net = t[3] === 'default' ? 0 : IP.parse(t[3]); const mi = t.indexOf('mask'); const mask = t[3] === 'default' ? 0 : IP.parseMask(t[mi + 1] || '255.255.255.255'); d.statics = d.statics.filter(x => !(x.net === IP.net(net, mask) && x.mask === mask)); return; }
    if (c0 === 'show' && t[1] === 'ip' && (t[2] === 'routes' || t[2] === 'route')) { return this.showRoutes(io); }
    if (c0 === 'show' && t[1] === 'arp') { let o = 'Total 0 arp entries\n'; const rows = []; d.arpTable.forEach((e, ip) => rows.push([ip, e])); o = 'Total ' + rows.length + ' arp entries\n Flags (P=Proxy, A=Authentication, V=VRRP, B=BFD, H=HAVLAN Address)\n\n  IP Addr           Hardware Addr       Type       Flags   Port      Interface  Name\n-----------------+-------------------+----------+-------+---------+-----------+--------------------\n'; rows.forEach(([ip, e]) => { o += ' ' + pad(IP.str(ip), 17) + ' ' + pad(e.mac, 19) + ' ' + pad('DYNAMIC', 10) + ' ' + pad('', 7) + ' ' + pad('', 9) + ' ' + (e.iface ? e.iface.aosName || e.iface.name : '') + '\n'; }); io.print(o); return; }
    if (c0 === 'ip' && t[1] === 'helper') { return this.ipHelper(io, T, t); }
    if (c0 === 'no' && t[1] === 'ip' && t[2] === 'helper') { d.ifaceList().forEach(i => { if (i.svi !== null) i.helper = []; }); return; }
    if (c0 === 'show' && t[1] === 'ip' && t[2] === 'helper') { let o = 'Forward Delay(seconds) = 3 ,\nMax number of hops  = 4 ,\nRelay Agent Information = Disabled,\nPXE support = Disabled,\nForwarding option = standard mode\nIP helper addresses (all VLANs):\n'; d.ifaceList().forEach(i => { i.helper.forEach(h => { o += '  ' + IP.str(h) + '\n'; }); }); io.print(o); return; }
    if (c0 === 'ping' || c0 === 'traceroute') return this.netTool(io, T, t);
    // ------------------------------------------------ MAC / STP / linkagg
    if (c0 === 'show' && t[1] === 'mac-learning') { return this.showMac(io, T, t); }
    if (c0 === 'mac-learning') { if (t[1] === 'aging-time') { d.macAging = (+t[2] || 300) * 1000; } return; }
    if (c0 === 'no' && t[1] === 'mac-learning') { d.macTable.clear(); return; }
    if (c0 === 'spantree' || (c0 === 'no' && t[1] === 'spantree') || (c0 === 'bridge')) return this.spantree(io, T, t);
    if (c0 === 'show' && t[1] === 'spantree') return this.showSpantree(io, T, t);
    if (c0 === 'lacp' || c0 === 'static' || c0 === 'no' && (t[1] === 'lacp' || t[1] === 'static')) return this.linkagg(io, T, t);
    if (c0 === 'show' && t[1] === 'linkagg') return this.showLinkagg(io, T, t);
    // ------------------------------------------------ PoE
    if (c0 === 'lanpower') return this.lanpower(io, T, t);
    if (c0 === 'show' && t[1] === 'lanpower') return this.showLanpower(io, T, t);
    // ------------------------------------------------ sécurité
    if (c0 === 'port-security') { return this.portSec(io, T, t); }
    if (c0 === 'show' && t[1] === 'port-security') { return this.showPortSec(io, T, t); }
    if (c0 === 'aaa') return this.aaa(io, T, t);
    if (c0 === '802.1x') return this.dot1x(io, T, t);
    if (c0 === 'show' && t[1] === '802.1x') return this.showDot1x(io, T, t);
    if (c0 === 'show' && t[1] === 'aaa') { const R = d.radius; let o = 'Server name   Address        Port  Status\n'; R.servers.forEach(sv => { o += pad(sv.name || IP.str(sv.ip), 14) + pad(IP.str(sv.ip), 15) + pad(sv.authPort, 6) + 'UP\n'; }); io.print(o); return; }
    if (c0 === 'user') { if (t[1]) d.aosUsers = d.aosUsers || {}, d.aosUsers[T[1]] = T[T.indexOf('password') + 1] || ''; return; }
    // ------------------------------------------------ système
    if (c0 === 'show') return this.showSys(io, T, t);
    if (c0 === 'system') { if (t[1] === 'name') d.name = T[2]; else if (t[1] === 'contact') d.aosContact = T[2]; else if (t[1] === 'location') d.aosLocation = T[2]; else if (t[1] === 'date' || t[1] === 'time' || t[1] === 'timezone') return ok(); return; }
    if (c0 === 'write' && t[1] === 'memory') { d.startup = this.dev.cliText(true); io.print('Working configuration saved.\n'); return; }
    if (c0 === 'copy') { if (t[1] === 'running-config' && t[2] === 'working') { d.startup = d.cliText(true); return; } if (t[1] === 'working' && t[2] === 'certified') { d.certified = d.startup; return; } return invalid(); }
    if (c0 === 'reload') { io.print('Reloading...\n'); d.cliReset(); const cfgText = d.startup || ''; if (cfgText) d.cliRestore(cfgText, true); return; }
    if (c0 === 'swlog' || c0 === 'snmp' || c0 === 'session' || c0 === 'telnet' && false || c0 === 'ntp' || c0 === 'qos' || c0 === 'policy' || c0 === 'amap' || c0 === 'lldp' || c0 === 'ip-service' || c0 === 'ip' && t[1] === 'service') return ok();
    if (c0 === 'clear' || c0 === 'history' || c0 === 'whoami' || c0 === 'clear screen') { if (c0 === 'whoami') io.print('User: admin\n'); return; }
    if (c0 === 'exit' || c0 === 'logout') { this.closed = true; return; }
    return invalid();
  }
  /* ---------------------------------------------------------------- VLAN */
  showVlan(io, t) {
    const d = this.dev;
    if (t[2] && /^\d+$/.test(t[2]) && t[3] === 'port') { const v = +t[2]; if (!d.vlans.has(v)) { this.err(io, 'VLAN ' + v + ' does not exist'); return; } let o = '  port      type       status\n--------+-----------+--------------\n'; d.ports.concat(Array.from(d.chans.values()).map(c => c.lp)).forEach(p => { const df = (p.aosDef || 1) === v, tg = p.aosTag && p.aosTag.has(v); if (!df && !tg) return; o += ' ' + pad(portLabel(d, p), 8) + pad(df ? 'default' : 'qtagged', 11) + '  ' + (p.up || (p.chan) ? 'forwarding' : 'inactive') + '\n'; }); io.print(o); return; }
    if (t[2] === 'port') { let o = '  vlan    port     type      status\n--------+--------+----------+------------\n'; d.vlans.forEach((e, v) => { d.ports.forEach(p => { const df = (p.aosDef || 1) === v, tg = p.aosTag && p.aosTag.has(v); if (df || tg) o += ' ' + pad(v, 7) + pad(p.name, 8) + pad(df ? 'default' : 'qtagged', 11) + (p.up ? 'forwarding' : 'inactive') + '\n'; }); }); io.print(o); return; }
    const only = t[2] && /^\d+$/.test(t[2]) ? +t[2] : 0; if (only && !d.vlans.has(only)) { this.err(io, 'VLAN ' + only + ' does not exist'); return; }
    let o = ' vlan    type   admin   oper    ip    mtu          name\n------+-------+-------+------+------+------+------------------\n';
    Array.from(d.vlans.keys()).sort((a, b) => a - b).forEach(v => { if (only && v !== only) return; const e = d.vlans.get(v); const adm = e.off ? 'Dis' : 'Ena'; const oper = !e.off && d.sviUp !== undefined && d.ports.some(p => p.up && !p.routed && memberVlansOf(p).has(v)) ? 'Ena' : 'Dis'; const si = d.sviIface(v); o += ' ' + pad(v, 6) + ' ' + pad('std', 6) + ' ' + pad(adm, 7) + ' ' + pad(oper, 5) + ' ' + pad(si && si.ip ? 'Ena' : 'Dis', 5) + ' ' + pad(1500, 5) + '  ' + e.name + '\n'; });
    io.print(o);
  }
  /* ---------------------------------------------------------------- interfaces physiques */
  showInterfaces(io, T, t) {
    const d = this.dev; const st = t.indexOf('status'); const cnt = t.indexOf('counters'); const target = T[2] && /^\d+\/\d+$/.test(T[2]) ? [d.findPort(T[2])] : null;
    if (t[2] === 'status' || (target && st > 0)) { let o = ' Port    Admin   Auto  Detected  Detected   Alias\n         Status  Nego  Speed     Duplex\n-------+-------+-----+---------+----------+----------------\n'; (target || d.ports).forEach(p => { if (!p) return; const up = p.up; o += ' ' + pad(p.name, 7) + ' ' + pad(p.adminUp === false ? 'dis' : 'en', 7) + ' ' + pad('en', 5) + ' ' + pad(up ? (p.link ? p.link.speed : 1000) : '-', 9) + ' ' + pad(up ? 'Full' : '-', 10) + ' ' + (p.desc || '') + '\n'; }); io.print(o); return; }
    if (t[2] === 'capability') { io.print('Port  Capability\n  Ethernet 10/100/1000 auto-negotiation, PoE (802.3af)\n'); return; }
    if (target && target[0]) { const p = target[0]; io.print('Slot/Port  : ' + p.name + ',\n  Operational Status : ' + (p.up ? 'up' : 'down') + ',\n  Last Time Link Changed : ' + hhmmss(d.sim.now) + ',\n  Number of Status Change : 1,\n  Type : Gigabit Ethernet,\n  SFP/XFP : N/A,\n  MAC address : ' + p.mac + ',\n  BandWidth (Megabits) : 1000, Duplex : ' + (p.up ? 'Full' : '---') + ',\n  Autonegotiation : 1 [ 100 M/F 1000 M/F ],\n  Long Frame Size(Bytes) : 9216,\n  Rx :\n  Bytes Received : ' + (p.rxB || 0) + ', Unicast Frames : ' + (p.rxPk || 0) + ',\n  Tx :\n  Bytes Xmitted : ' + (p.txB || 0) + ', Unicast Frames : ' + (p.txPk || 0) + '\n'); return; }
    io.print('Type "show interfaces status" ou "show interfaces <slot/port>"\n');
  }
  /* ---------------------------------------------------------------- IP */
  ipInterface(io, T, t) {
    const d = this.dev; const nm = T[2]; if (!nm) return io.print('ERROR: Invalid entry: "interface"\n');
    const ai = t.indexOf('address'), mi = t.indexOf('mask'), vi = t.indexOf('vlan');
    if (ai < 0 && vi < 0) { const i = d.ifaceList().find(x => x.aosName === nm); if (!i) { this.err(io, 'Interface ' + nm + ' does not exist'); return; } if (t.includes('admin')) i.adminUp = t[t.indexOf('admin') + 1] === 'enable'; return; }
    const ip = IP.parse(T[ai + 1] || ''), v = +T[vi + 1];
    if (ip === null || !(v >= 1)) { this.err(io, 'Invalid IP address or VLAN'); return; }
    let mask = mi >= 0 ? IP.parseMask(T[mi + 1]) : IP.classMask(ip); if (mask === null) { this.err(io, 'Invalid mask'); return; }
    if (!d.vlans.has(v)) { this.err(io, 'VLAN ' + v + ' does not exist'); return; }
    let i = d.sviIface(v); if (!i) i = d.addIface('Vlan' + v, { svi: v }); i.aosName = nm; i.ip = ip; i.mask = mask; i.adminUp = true; d.forwarding = true; d.sim.at(0.1, () => d.arpAnnounce && d.arpAnnounce(i));
  }
  showIpIf(io, nm) {
    const d = this.dev; const l = d.ifaceList().filter(i => i.svi !== null && (!nm || i.aosName === nm)); if (nm && !l.length) { this.err(io, 'Interface ' + nm + ' does not exist'); return; }
    let o = 'Total ' + l.length + ' interfaces\n  Name                 IP Address      Subnet Mask     Status Forward  Device\n--------------------+---------------+---------------+------+-------+--------\n';
    l.forEach(i => { const up = i.isUp(); o += pad(i.aosName || i.name, 20) + ' ' + pad(IP.str(i.ip), 15) + ' ' + pad(IP.str(i.mask), 15) + ' ' + pad(up ? 'UP' : 'DOWN', 6) + ' ' + pad(up ? 'YES' : 'NO', 7) + ' vlan ' + i.svi + '\n'; }); io.print(o);
  }
  showRoutes(io) {
    const d = this.dev; const rs = d.allRoutes ? d.allRoutes() : []; const now = d.sim.now;
    let o = '+ = Equal cost multipath routes\n\nTotal ' + rs.length + ' routes\n\n  Dest Address     Subnet Mask      Gateway Addr     Age        Protocol\n------------------+---------------+-----------------+----------+-----------\n';
    rs.slice().sort((a, b) => (a.net - b.net) || (a.mask - b.mask)).forEach(r => { const proto = r.proto === 'C' ? 'LOCAL' : r.proto === 'S' ? 'STATIC' : r.proto === 'R' ? 'RIP' : r.proto === 'O' ? 'OSPF' : r.proto; const gw = r.nh ? IP.str(r.nh) : (r.iface && r.iface.ip ? IP.str(r.iface.ip) : '0.0.0.0'); o += '  ' + pad(IP.str(r.net), 16) + ' ' + pad(IP.str(r.mask), 16) + ' ' + pad(gw, 16) + ' ' + pad(hhmmss(now - (r.t || 0)), 10) + ' ' + proto + '\n'; });
    io.print(o);
  }
  ipHelper(io, T, t) {
    const d = this.dev; if (t[2] === 'address') { const ip = IP.parse(T[3] || ''); if (ip === null) return; d.ifaceList().forEach(i => { if (i.svi !== null && !i.helper.includes(ip)) i.helper.push(ip); }); return; }
    if (t[2] === 'vlan') { const v = +T[3], ip = IP.parse(T[T.indexOf('address') + 1] || ''); const i = d.sviIface(v); if (i && ip !== null) i.helper.push(ip); return; }
    return;
  }
  netTool(io, T, t) {
    const d = this.dev; const dst = IP.parse(T[1] || ''); if (dst === null) { this.err(io, 'Invalid destination'); return; }
    if (t[0] === 'ping') { const cnt = t.includes('count') ? +T[t.indexOf('count') + 1] : 5; let ok = 0; io.print('PING ' + IP.str(dst) + ': 56 data bytes\n'); NS.tools.pingSeries(d, dst, { count: cnt, size: 56, interval: 1000 }, r => { if (r.type === 'reply') { ok++; io.print('64 bytes from ' + IP.str(dst) + ': icmp_seq=' + r.seq + ' ttl=' + (r.ttl || 64) + ' time=' + Math.max(1, Math.round(r.rtt)) + ' ms\n'); } else io.print('Request timed out or destination unreachable (' + r.type + ')\n'); }, () => { io.print('\n----' + IP.str(dst) + ' PING Statistics----\n' + cnt + ' packets transmitted, ' + ok + ' packets received, ' + Math.round(100 - ok * 100 / cnt) + '% packet loss\n'); io.done(); }); return 'async'; }
    io.print('traceroute to ' + IP.str(dst) + ', 30 hops max, 40 byte packets\n'); NS.tools.trace(d, dst, { maxHops: 30, probes: 3 }, (ttl, rs) => { const first = rs.find(r => r.from !== undefined); io.print(padL(ttl, 2) + '  ' + (first ? IP.str(first.from) : '*') + '\n'); }, () => io.done()); return 'async';
  }
  /* ---------------------------------------------------------------- MAC */
  showMac(io, T, t) {
    const d = this.dev; const vi = t.indexOf('vlan'); const fv = vi >= 0 ? +t[vi + 1] : 0; const rows = [];
    d.macTable.forEach((e, k) => { const [v, m] = k.split('|'); if (fv && +v !== fv) return; rows.push([+v, m, e.port]); }); rows.sort((a, b) => a[0] - b[0] || a[1].localeCompare(b[1]));
    let o = ' Legend: Mac Address: * = address not valid,\n\n  Mac Address        Vlan    Type          Operation     Interface\n-------------------+-------+-------------+-------------+-------------\n'; rows.forEach(([v, m, p]) => { o += ' ' + pad(m, 18) + ' ' + pad(v, 7) + ' ' + pad('learned', 13) + ' ' + pad('bridging', 13) + ' ' + portLabel(d, p) + '\n'; });
    io.print(o + '\n Total number of Valid MAC addresses above = ' + rows.length + '\n');
  }
  /* ---------------------------------------------------------------- spantree */
  spantree(io, T, t) {
    const d = this.dev, st = d.stp; let i = t[0] === 'no' ? 1 : 0; const A = t.slice(i + 1); const c = t[i];
    if (c === 'bridge') return;
    if (A[0] === 'mode') { d.aosStpMode = A[1]; return; }
    if (A[0] === 'protocol') { const p = A[1]; if (p === 'rstp' || p === '8021w') st.setMode('rapid-pvst'); else if (p === 'stp' || p === '8021d') st.setMode('pvst'); else if (p === 'mstp' || p === '8021s') { io.print('ERROR: MSTP n\'est pas simulé (utilisez stp ou rstp)\n'); return; } return; }
    if (A[0] === 'vlan') {
      const v = +A[1]; if (!d.vlans.has(v)) { this.err(io, 'VLAN ' + v + ' does not exist'); return; } const k = A[2];
      if (k === 'priority') { st.vpri.set(v, +A[3]); st.recompute && st.recompute(); return; }
      if (k === 'enable') { st.enableVlan(v); return; } if (k === 'disable') { st.disableVlan(v); return; }
      if (k === 'port') { const ps = parsePorts(d, [T[i + 4] || '']); if (!ps) return; const w = A[3]; ps.forEach(p => { if (w === 'path-cost') p.stpCost = +A[4]; else if (w === 'priority') p.stpPri = +A[4]; else if (w === 'connection') p.portfast = A[4] === 'edge' || A[4] === 'auto' && false; }); return; }
      return;
    }
    if (A[0] === 'cist') { if (A[1] === 'priority') st.priority = +A[2]; return; }
    if (A[0] === 'auto-vlan-containment' || A[0] === 'path-cost-mode') return;
    io.print('ERROR: Invalid entry: "' + (T[i + 1] || '') + '"\n');
  }
  showSpantree(io, T, t) {
    const d = this.dev, st = d.stp;
    if (t[2] === 'ports') { let o = ' Vlan  Port   Oper Status  Path Cost  Role   Loop Guard  Note\n------+------+-----------+-----------+------+-----------+------\n'; const ST = { forwarding: 'FORW', blocking: 'BLK', learning: 'LRN', listening: 'LIS', disabled: 'DIS' }, RL = { root: 'ROOT', designated: 'DESG', alternate: 'ALTN', backup: 'BKUP', disabled: 'DIS' }; Array.from(st.insts.keys()).sort((a, b) => a - b).forEach(v => { const inf = st.info(v); if (!inf) return; inf.ports.forEach(x => { if (x.role === 'disabled' || !x.role) return; o += ' ' + pad(v, 5) + ' ' + pad(portLabel(d, x.port), 6) + ' ' + pad(ST[x.state] || x.state, 11) + ' ' + pad(st.cost(x.port), 10) + ' ' + pad(RL[x.role] || x.role, 6) + ' ' + pad('DIS', 11) + '\n'; }); }); io.print(o); return; }
    const one = t[2] && /^\d+$/.test(t[2]) ? +t[2] : 0;
    if (one) { const inf = st.info(one); if (!inf) { this.err(io, 'STP instance for VLAN ' + one + ' not found'); return; } io.print('Spanning Tree Parameters for Vlan ' + one + '\n  Spanning Tree Status     :  ON,\n  Protocol                 :  ' + (st.rapid ? 'IEEE 802.1w (RSTP)' : 'IEEE 802.1D (STP)') + ',\n  mode                     :  1X1 (Per VLAN),\n  Priority                 :  ' + st.pri(one) + ' (0x' + st.pri(one).toString(16) + '),\n  Bridge ID                :  ' + (st.pri(one).toString(16).padStart(4, '0')) + '-' + d.baseMac + ',\n  Designated Root          :  ' + inf.rootPri.toString(16).padStart(4, '0') + '-' + inf.rootMac + ',\n  Cost to Root Bridge      :  ' + inf.rootCost + ',\n  Root Port                :  ' + (inf.isRoot ? 'NONE' : portLabel(d, inf.rootPort)) + ',\n  Next Best Root Cost      :  0,\n  Tx Hold Count            :  3,\n  Topology Changes         :  0,\n  Max Age/Fwd Delay/Hello  :  20/' + st.fwd / 1000 + '/2\n'); return; }
    let o = ' Spanning Tree Path Cost Mode : AUTO\n Vlan STP Status Protocol Priority\n-----+----------+--------+--------------\n'; Array.from(st.insts.keys()).sort((a, b) => a - b).forEach(v => { o += ' ' + pad(v, 4) + ' ON         ' + pad(st.rapid ? 'RSTP' : 'STP', 8) + ' ' + st.pri(v) + ' (0x' + st.pri(v).toString(16) + ')\n'; }); io.print(o);
  }
  /* ---------------------------------------------------------------- linkagg */
  linkagg(io, T, t) {
    const d = this.dev; const neg = t[0] === 'no'; const c = neg ? t.slice(1) : t; const kind = c[0]; const cT = neg ? T.slice(1) : T;
    if (c[1] === 'linkagg') {
      const id = +c[2]; if (!(id >= 0 && id <= 31)) { this.err(io, 'Invalid linkagg number'); return; } d.aosLag = d.aosLag || new Map();
      if (neg) { const ch = d.chans.get(id); if (ch) ch.members.slice().forEach(m => d.removeFromChan(m)); d.aosLag.delete(id); return; }
      const e = d.aosLag.get(id) || { id, kind, size: 2, admin: 'disable', key: id, name: '' }; d.aosLag.set(id, e); e.kind = kind;
      for (let i = 3; i < c.length; i++) { if (c[i] === 'size') e.size = +c[++i]; else if (c[i] === 'admin' && c[i + 1] === 'state') { e.admin = c[i + 2]; i += 2; } else if (c[i] === 'name') e.name = cT[++i]; else if (c[i] === 'actor' && c[i + 1] === 'admin' && c[i + 2] === 'key') { e.key = +c[i + 3]; i += 3; } }
      this.syncLag(); return;
    }
    if (c[1] === 'agg') {
      const p = d.findPort(cT[2] || ''); if (!p) { this.err(io, 'Invalid port'); return; } d.aosLagMem = d.aosLagMem || new Map();
      if (neg) { d.aosLagMem.delete(p); d.removeFromChan(p); return; }
      if (kind === 'lacp') { const k = c.indexOf('key'); d.aosLagMem.set(p, { kind: 'lacp', key: +c[k + 1] }); }
      else { const n = c.indexOf('num'); d.aosLagMem.set(p, { kind: 'static', id: +c[n + 1] }); }
      this.syncLag(); return;
    }
    io.print('ERROR: Invalid entry: "' + (T[1] || '') + '"\n');
  }
  syncLag() {
    const d = this.dev; if (!d.aosLag) return; d.aosLagMem = d.aosLagMem || new Map();
    d.aosLagMem.forEach((m, p) => {
      let id = 0; if (m.kind === 'static') { const e = d.aosLag.get(m.id); if (e && e.admin === 'enable') id = m.id; } else { d.aosLag.forEach(e => { if (e.kind === 'lacp' && e.key === m.key && e.admin === 'enable') id = e.id; }); }
      if (id && (!p.lag || p.lag.id !== id)) { p.aosDef = p.aosDef || 1; d.addToChan(p, id, m.kind === 'lacp' ? 'active' : 'on'); } else if (!id && p.lag) d.removeFromChan(p);
    });
  }
  showLinkagg(io, T, t) {
    const d = this.dev; d.aosLag = d.aosLag || new Map();
    if (t[2] === 'port') { let o = ' Slot/Port  Aggregate  SNMP Id  Status    Agg   Oper  Link  Prim  Actor Sys ID\n-----------+---------+--------+---------+-----+-----+-----+-----+--------------\n'; d.ports.forEach(p => { if (!p.lag) return; o += ' ' + pad(p.name, 10) + ' ' + pad(p.lag.id === undefined ? '-' : 'Dynamic', 9) + ' ' + pad(p.idx + 1, 8) + ' ' + pad(p.lag.bundled ? 'ATTACHED' : 'CONFIGURED', 9) + ' ' + pad(p.lag.id, 5) + ' ' + pad(p.up ? 'UP' : 'DOWN', 5) + '\n'; }); io.print(o); return; }
    let o = ' Number  Aggregate     SNMP Id  Size  Admin State  Oper State  Att/Sel Ports\n-------+-------------+--------+-----+------------+-----------+--------------\n';
    d.aosLag.forEach((e, id) => { const c = d.chans.get(id); const up = c && c.lp.up; const att = c ? c.bundled().length : 0; o += ' ' + pad(id, 7) + ' ' + pad(e.kind === 'lacp' ? 'Dynamic' : 'Static', 13) + ' ' + pad(40000000 + id, 8) + ' ' + pad(e.size, 5) + ' ' + pad(e.admin === 'enable' ? 'ENABLED' : 'DISABLED', 12) + ' ' + pad(up ? 'UP' : 'DOWN', 11) + ' ' + att + '/' + (c ? c.members.length : 0) + '\n'; }); io.print(o);
  }
  /* ---------------------------------------------------------------- PoE */
  poeWatts(d, p) { const peer = p.link && p.link.other(p); const dev = peer && peer.dev; const key = dev && dev.model; return dev && p.up && PD_W[key] ? PD_W[key] : 0; }
  lanpower(io, T, t) {
    const d = this.dev; d.aosPoe = d.aosPoe || { off: new Set(), max: new Map() };
    const slot = /^\d+$/.test(t[1] || ''); if (t[1] === 'start' || t[1] === 'stop') { const ps = /\//.test(T[2] || '') ? parsePorts(d, [T[2]]) : d.ports.slice(0, 44); if (!ps) return; ps.forEach(p => { if (t[1] === 'stop') d.aosPoe.off.add(p); else d.aosPoe.off.delete(p); }); this.poeRefresh(); return; }
    if (/\//.test(t[1] || '') && t[2] === 'maxpower') { const ps = parsePorts(d, [T[1]]); if (ps) ps.forEach(p => d.aosPoe.max.set(p, +T[3])); return; }
    if (slot && (t[2] === 'maxpower' || t[2] === 'power-budget' || t[2] === 'priority-disconnect')) { if (t[2] === 'maxpower') d.aosPoeBudget = +T[3]; return; }
    if (t[1] === 'priority' || /\//.test(t[1] || '')) return; io.print('ERROR: Invalid entry: "' + (T[1] || '') + '"\n');
  }
  poeRefresh() { const d = this.dev; d.ports.forEach(p => { if (!p.link || p.idx >= 44) return; const peer = p.link.other(p); const dev = peer && peer.dev; if (dev && dev.phone) { const on = !(d.aosPoe && d.aosPoe.off.has(p)); if ((peer.adminUp !== false) !== on) { peer.adminUp = on; d.sim.portChanged && d.sim.portChanged(peer); d.sim.portChanged && d.sim.portChanged(p); } } }); }
  showLanpower(io, T, t) {
    const d = this.dev; d.aosPoe = d.aosPoe || { off: new Set(), max: new Map() }; const budget = d.aosPoeBudget || 390; let used = 0;
    let o = 'Port  Maximum(mW) Actual Used(mW)  Status      Priority  On/Off  Class  Type\n-----+-----------+---------------+-----------+---------+-------+------+-------\n';
    d.ports.slice(0, 44).forEach(p => { const off = d.aosPoe.off.has(p); const w = off ? 0 : this.poeWatts(d, p); used += w; o += pad(p.name.replace(/^1\//, ''), 5) + padL(d.aosPoe.max.get(p) || POE_ALLOC, 11) + padL(w, 15) + '   ' + pad(off ? 'Off' : w ? 'Powered On' : p.up ? 'Searching' : 'Searching', 11) + ' ' + pad('Low', 9) + ' ' + pad(off ? 'OFF' : 'ON', 7) + ' ' + pad(w ? '2' : '-', 6) + ' ' + (w ? '802.3af' : '') + '\n'; });
    io.print(o + '\nSlot 1 Max Watts ' + budget + '\n' + '1 Power Supply Available\nTotal Power Budget Remaining ' + Math.round(budget * 1000 - used) / 1000 + ' W\nTotal Power Used ' + Math.round(used) / 1000 + ' W\n');
  }
  /* ---------------------------------------------------------------- sécurité */
  portSec(io, T, t) {
    const d = this.dev; const ps = parsePorts(d, [(T[1] === 'port' ? T[2] : T[1]) || '']); if (!ps || !ps.length) { this.err(io, 'Invalid port'); return; } const rest = t.slice(T[1] === 'port' ? 3 : 2);
    ps.forEach(p => { if (rest[0] === 'admin-status') p.sec.enabled = rest[1] === 'enable' || rest[1] === 'locked'; else if (rest[0] === 'maximum') p.sec.max = +rest[1]; else if (rest[0] === 'violation') p.sec.violation = rest[1] === 'restrict' ? 'restrict' : rest[1] === 'discard' ? 'protect' : 'shutdown'; });
  }
  showPortSec(io, T, t) {
    const d = this.dev; let o = 'Port: 1/x  Operation Mode  Max MAC  Violation\n'; d.ports.forEach(p => { if (p.sec.enabled) o += ' ' + pad(p.name, 8) + ' ' + pad(p.errdis ? 'SHUTDOWN' : 'ENABLED', 15) + ' ' + pad(p.sec.max, 8) + ' ' + p.sec.violation + '\n'; }); io.print(o);
  }
  aaa(io, T, t) {
    const d = this.dev, R = d.radius;
    if (t[1] === 'radius-server') { const nm = T[2]; const hi = t.indexOf('host'), ki = t.indexOf('key'); if (hi < 0 || ki < 0) { this.err(io, 'Missing host or key'); return; } const ip = IP.parse(T[hi + 1]); if (ip === null) return; const ex = R.servers.find(s => s.name === nm); if (ex) R.delServer(ex); R.addServer({ ip, key: T[ki + 1], name: nm, authPort: t.indexOf('auth-port') >= 0 ? +T[t.indexOf('auth-port') + 1] : 1812, acctPort: 1813 }); d.aosRad = d.aosRad || new Map(); d.aosRad.set(nm, { ip, key: T[ki + 1] }); return; }
    if (t[1] === 'authentication' && t[2] === '802.1x') { const nm = T[3]; if (!R.servers.find(s => s.name === nm)) { this.err(io, 'Server ' + nm + ' does not exist'); return; } R.aaa.newModel = true; R.groups.set('AOS8021X', [nm]); R.aaa.dot1x.set('default', ['group AOS8021X']); d.aosDot1xSrv = nm; return; }
    if (t[1] === 'authentication' || t[1] === 'accounting') return;
    io.print('ERROR: Invalid entry: "' + (T[1] || '') + '"\n');
  }
  dot1x(io, T, t) {
    const d = this.dev; const ps = parsePorts(d, [T[1] || '']); if (!ps || !ps.length) { this.err(io, 'Invalid port'); return; } d.dot1x.enabled = true;
    ps.forEach(p => { p.dx = p.dx || {}; if (t[2] === 'direction') { p.dx.mode = 'auto'; p.dx.pae = 'authenticator'; } else if (t[2] === 'port-control') { p.dx.mode = t[3] === 'force-authorized' ? 'force-authorized' : t[3] === 'force-unauthorized' ? 'force-unauthorized' : 'auto'; } else if (t[2] === 'tx-period') p.dx.txPeriod = +t[3]; else if (t[2] === 'supp-timeout') p.dx.suppTimeout = +t[3]; });
    d.dot1x.applyAll && d.dot1x.applyAll();
  }
  showDot1x(io, T, t) { const d = this.dev; let o = 'Slot  Port  Control  Status\n'; d.ports.forEach(p => { if (p.dx && p.dx.mode) o += ' 1/' + pad(p.name.replace(/^1\//, ''), 5) + pad(p.dx.mode, 9) + (p.dxs ? (p.dxs.state || '') : '') + '\n'; }); io.print(o); }
  /* ---------------------------------------------------------------- système */
  showSys(io, T, t) {
    const d = this.dev, w = t[1];
    if (w === 'system') { io.print('System:\n  Description:  Alcatel-Lucent Enterprise OS6400-P48 AOS 6.4.x (simulé),\n  Object ID:    1.3.6.1.4.1.6486.800.1.1.2.1.6.1.2,\n  Up Time:      ' + fmtUp(d.sim.now) + ',\n  Contact:      ' + (d.aosContact || 'Alcatel-Lucent, http://alcatel-lucent.com/wps/portal/enterprise') + ',\n  Name:         ' + d.name + ',\n  Location:     ' + (d.aosLocation || 'Unknown') + ',\n  Services:     78,\n  Date & Time:  ' + new Date(1780000000000 + d.sim.now).toString().slice(0, 24) + '\n'); return; }
    if (w === 'chassis' || w === 'hardware' || w === 'module') { io.print('Chassis 1\n  Model Name:                   OS6400-P48,\n  Description:                  48 10/100/1000 PoE + 4 combo + 2 10G stacking,\n  Part Number:                  902xxx-xx (simulé),\n  Hardware Revision:            01,\n  Serial Number:                SIM' + d.baseMac.replace(/:/g, '').slice(-6).toUpperCase() + ',\n  Manufacture Date:             simulé,\n  Admin Status:                 POWER ON,\n  Operational Status:           UP,\n  Number Of Resets:             0\n'); return; }
    if (w === 'microcode') { io.print('/flash/working\n   Package         Release       Size     Description\n-----------------+---------+--------+-----------------------------------\n   Jbase.img      6.4.x    simulé   Alcatel-Lucent Base Software\n'); return; }
    if (w === 'running-directory') { io.print('CONFIGURATION STATUS\n   Running CMM                     : MASTER-PRIMARY,\n   CMM Mode                        : MONO CMM,\n   Current CMM Slot                : 1,\n   Running configuration           : WORKING,\n   Certify/Restore Status          : ' + (d.certified === d.startup && d.startup ? 'CERTIFIED' : 'CERTIFY NEEDED') + '\nSYNCHRONIZATION STATUS\n   Flash Between CMMs              : NOT SYNCHRONIZED,\n   Running Configuration           : NOT AVAILABLE\n'); return; }
    if (w === 'temperature') { io.print('Chassis/Device   Current   Range      Threshold   Status\n---------------+---------+----------+-----------+---------\n   1/ 1           40       0 to 100     75        UNDER THRESHOLD\n'); return; }
    if (w === 'fan') { io.print('Chassis/Fan   Status\n-------------+----------\n   1/ 1       Running\n   1/ 2       Running\n'); return; }
    if (w === 'health') { io.print('CPU  Current 1 Min 1 Hr  1 Day\n-----+-------+-----+-----+------\n  1     3     3     3     3\n'); return; }
    if (w === 'configuration' && t[2] === 'snapshot') { io.print('! Chassis :\n! VLAN :\n' + d.cliText(false) + '\n'); return; }
    if (w === 'stack' || w === 'ntp' || w === 'amap' || w === 'lldp' || w === 'snmp' || w === 'swlog' || w === 'qos') { io.print('(Fonction non simulée sur ce modèle)\n'); return; }
    if (w === 'session') { io.print('Session Type Active User  IP\n  console      admin\n'); return; }
    io.print('ERROR: Invalid entry: "' + (T[1] || '') + '"\n');
  }
}
const AOS_WORDS = ['vlan ', 'no vlan ', 'show vlan', 'show vlan port', 'show 802.1q ', 'interfaces ', 'show interfaces status', 'show interfaces capability', 'ip interface ', 'no ip interface ', 'show ip interface', 'ip static-route ', 'no ip static-route ', 'show ip routes', 'show arp', 'ip helper address ', 'show ip helper', 'ping ', 'traceroute ', 'show mac-learning', 'mac-learning aging-time ', 'spantree protocol rstp', 'spantree protocol stp', 'spantree vlan ', 'show spantree', 'show spantree ports', 'lacp linkagg ', 'lacp agg ', 'static linkagg ', 'static agg ', 'show linkagg', 'show linkagg port', 'lanpower start ', 'lanpower stop ', 'show lanpower ', 'port-security ', 'show port-security', 'aaa radius-server ', 'aaa authentication 802.1x ', '802.1x ', 'show 802.1x', 'show aaa', 'user ', 'show system', 'system name ', 'system contact ', 'system location ', 'show chassis', 'show microcode', 'show running-directory', 'show temperature', 'show fan', 'show health', 'show configuration snapshot', 'write memory', 'copy running-config working', 'copy working certified', 'reload', 'whoami', 'exit'];

/* ---- sauvegarde / restauration en syntaxe AOS ---- */
function aosText(d) {
  const L = []; const q = s => /\s/.test(s) ? '"' + s + '"' : s;
  L.push('! Chassis :', 'system name ' + q(d.name)); if (d.aosContact) L.push('system contact ' + q(d.aosContact)); if (d.aosLocation) L.push('system location ' + q(d.aosLocation));
  L.push('', '! VLAN :'); d.vlans.forEach((e, v) => { if (v === 1 && e.name === 'default') { } else L.push('vlan ' + v + ' name ' + q(e.name || 'VLAN ' + v)); if (e.off) L.push('vlan ' + v + ' disable'); });
  const P = d.ports.concat(Array.from(d.chans.values()).map(c => c.lp));
  P.forEach(p => { const lab = portLabel(d, p); if (p.aosDef && p.aosDef !== 1) L.push('vlan ' + p.aosDef + ' port default ' + lab); (p.aosTag ? Array.from(p.aosTag) : []).sort((a, b) => a - b).forEach(v => L.push('vlan ' + v + ' 802.1q ' + lab)); });
  const iface = []; d.ports.forEach(p => { if (p.adminUp === false) iface.push('interfaces ' + p.name + ' admin down'); if (p.desc) iface.push('interfaces ' + p.name + ' alias ' + q(p.desc)); }); if (iface.length) L.push('', '! Interface :', ...iface);
  const ips = d.ifaceList().filter(i => i.svi !== null && i.ip); if (ips.length) { L.push('', '! IP :'); ips.forEach(i => L.push('ip interface ' + q(i.aosName || 'vlan-' + i.svi) + ' address ' + IP.str(i.ip) + ' mask ' + IP.str(i.mask) + ' vlan ' + i.svi)); d.statics.forEach(s => L.push('ip static-route ' + IP.str(s.net) + ' mask ' + IP.str(s.mask) + ' gateway ' + IP.str(s.nh) + (s.ad !== 1 ? ' metric ' + s.ad : ''))); d.ifaceList().forEach(i => i.helper && i.helper.forEach(h => L.push('ip helper vlan ' + i.svi + ' address ' + IP.str(h)))); }
  L.push('', '! Spanning Tree :', 'spantree protocol ' + (d.stp.rapid ? 'rstp' : 'stp')); Array.from(d.stp.vpri.entries()).forEach(([v, pr]) => L.push('spantree vlan ' + v + ' priority ' + pr));
  if (d.aosLag && d.aosLag.size) { L.push('', '! Link Aggregate :'); d.aosLag.forEach((e, id) => { L.push(e.kind + ' linkagg ' + id + ' size ' + e.size + ' admin state ' + e.admin + (e.name ? ' name ' + q(e.name) : '') + (e.kind === 'lacp' ? '\nlacp linkagg ' + id + ' actor admin key ' + e.key : '')); }); (d.aosLagMem || new Map()).forEach((m, p) => L.push(m.kind === 'lacp' ? 'lacp agg ' + p.name + ' actor admin key ' + m.key : 'static agg ' + p.name + ' agg num ' + m.id)); }
  const poe = d.aosPoe && d.aosPoe.off.size ? Array.from(d.aosPoe.off).map(p => 'lanpower stop ' + p.name) : []; if (poe.length) L.push('', '! PoE :', ...poe);
  const sec = d.ports.filter(p => p.sec.enabled); if (sec.length) { L.push('', '! Port Security :'); sec.forEach(p => { L.push('port-security ' + p.name + ' admin-status enable'); if (p.sec.max !== 1) L.push('port-security ' + p.name + ' maximum ' + p.sec.max); }); }
  if (d.aosRad && d.aosRad.size) { L.push('', '! AAA :'); d.aosRad.forEach((v, nm) => L.push('aaa radius-server ' + q(nm) + ' host ' + IP.str(v.ip) + ' key ' + v.key)); if (d.aosDot1xSrv) L.push('aaa authentication 802.1x ' + q(d.aosDot1xSrv)); const dx = d.ports.filter(p => p.dx && p.dx.mode); dx.forEach(p => L.push('802.1x ' + p.name + ' direction both')); }
  return L.join('\n');
}
function aosReset(d) {
  if (d.radius) d.radius.reset(); if (d.dot1x) d.dot1x.reset(); if (d.mgmt) d.mgmt.reset && d.mgmt.reset();
  d.statics = []; d.dynRoutes = []; d.aosLag = new Map(); d.aosLagMem = new Map(); d.aosPoe = { off: new Set(), max: new Map() }; d.aosRad = new Map(); d.aosDot1xSrv = null; d.aosContact = ''; d.aosLocation = '';
  Array.from(d.chans.values()).forEach(c => c.members.slice().forEach(m => d.removeFromChan(m)));
  Array.from(d.ifaces.keys()).forEach(k => { const i = d.ifaces.get(k); if (i.svi !== null) d.ifaces.delete(k); });
  d.vlans = new Map([[1, { name: 'default' }]]); d.stp.vpri.clear(); d.stp.defPri = 32768; d.stp.setMode('pvst');
  d.ports.forEach(p => { Object.assign(p, { mode: 'access', vlan: 1, native: 1, allowed: null, aosDef: 1, aosTag: new Set(), portfast: false, desc: '', adminUp: true, errdis: false, dx: null }); p.sec = { enabled: false, max: 1, violation: 'shutdown', macs: new Set(), sticky: false }; });
  d.macTable.clear(); d.forwarding = true;
}
function aosRestore(d, text) {
  aosReset(d); const s = new AosSession(d); const io = { print() { }, done() { }, clear() { } };
  text.split('\n').forEach(l => { l = l.trim(); if (!l || l[0] === '!') return; if (/^system name /.test(l)) { const n = tokz(l)[2]; if (n) d.name = n; return; } s.exec(l, io); });
}
NS.aosAttach = function (d) {
  d.forwarding = true; d.aosLag = new Map(); d.aosLagMem = new Map(); d.aosPoe = { off: new Set(), max: new Map() }; d.aosRad = new Map(); d.ports.forEach(p => { p.aosDef = 1; p.aosTag = new Set(); });
  d.newSession = () => new AosSession(d); d.cliText = () => aosText(d); d.cliReset = () => aosReset(d); d.cliRestore = (t) => aosRestore(d, t);
  d.sim.at(1000, function tick() { if (d.dead) return; new AosSession(d).poeRefresh(); d.sim.at(5000, tick); });
  const serve = d.tcpListen && d.tcpListen(23, conn => {
    const st = { buf: '', stage: 0, user: '', s: new AosSession(d) }; const out = t => conn.send(t.replace(/\n/g, '\r\n'));
    out('\nlogin : '); conn.onClose = () => { if (conn.state === 'CLOSE_WAIT') conn.close(); };
    conn.onData = buf => { st.buf += String.fromCharCode.apply(null, buf); let i; while ((i = st.buf.search(/\r\n|\n|\r/)) >= 0) { const l = st.buf.slice(0, i); st.buf = st.buf.slice(st.buf.slice(i).match(/^(\r\n|\n|\r)/)[0].length + i); if (st.stage === 0) { st.user = l.trim(); st.stage = 1; out('password : '); } else if (st.stage === 1) { const users = Object.assign({ admin: 'switch' }, d.aosUsers || {}); if (users[st.user] !== undefined && users[st.user] === l.trim()) { st.stage = 2; out('\nWelcome to the Alcatel-Lucent OmniSwitch 6400\n\n-> '); } else { out('\nlogin incorrect\nlogin : '); st.stage = 0; } } else { const io = { print: t => out(t), done: () => out('-> '), clear() { } }; if (/^(exit|logout)$/i.test(l.trim())) { conn.close(); return; } st.s.exec(l, io); } } };
  });
};
NS.AosSession = AosSession;
})(typeof window !== 'undefined' ? window : globalThis);
