/* ioscli.js — interpréteur de commandes de type Cisco IOS pour routeurs et commutateurs
   (modes user/priv/config/interface/line/router/dhcp/acl/vlan, abréviations, ?, show, write, telnet/ssh serveur) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, tools, B } = NS;

const PORTNUM = { www: 80, http: 80, ftp: 21, 'ftp-data': 20, telnet: 23, smtp: 25, domain: 53, https: 443, ssh: 22, pop3: 110, imap: 143, snmp: 161, ntp: 123, bootps: 67, bootpc: 68, tftp: 69, echo: 7, syslog: 514 };
const PORTNAME = { 80: 'www', 21: 'ftp', 20: 'ftp-data', 23: 'telnet', 25: 'smtp', 53: 'domain', 110: 'pop3', 143: 'imap', 161: 'snmp', 123: 'ntp', 67: 'bootps', 68: 'bootpc', 69: 'tftp', 7: 'echo', 514: 'syslog' };
const pad = (s, n) => { s = String(s); return s.length >= n ? s + ' ' : s + ' '.repeat(n - s.length); };
const padL = (s, n) => { s = String(s); return s.length >= n ? s : ' '.repeat(n - s.length) + s; };
const cm = m => MAC.cisco(m);

/* ------------------------------------------------------------- registre de commandes */
const CMDS = [];
const MODESETS = { exec: ['user', 'priv'], cfg: ['config', 'if', 'line', 'rip', 'dhcp', 'nacl', 'vlan', 'ospf', 'isakmp', 'tset', 'cmap', 'ipsecprof', 'radsrv', 'aaagrp'], all: ['user', 'priv', 'config', 'if', 'line', 'rip', 'dhcp', 'nacl', 'vlan', 'ospf', 'isakmp', 'tset', 'cmap', 'ipsecprof', 'radsrv', 'aaagrp'] };
function cmd(modes, pattern, fn, o) {
  o = o || {};
  const ms = [].concat(modes).reduce((a, m) => a.concat(MODESETS[m] || [m]), []);
  const toks = pattern.split(/\s+/).map(t => {
    let m;
    if ((m = /^\[<(\w+)(\.\.\.)?>\]$/.exec(t))) return { param: m[1], rest: !!m[2], opt: true };
    if ((m = /^<(\w+)(\.\.\.)?>$/.exec(t))) return { param: m[1], rest: !!m[2] };
    return { lit: t.toLowerCase() };
  });
  CMDS.push({ modes: ms, toks, fn, pattern, only: o.only, help: o.help, priv: o.priv });
}
function matchCmd(c, toks) {
  const a = {}; let score = 0, k = 0; const pt = c.toks;
  for (let i = 0; i < pt.length; i++) {
    const p = pt[i];
    if (i >= toks.length) { if (p.opt) { k = i; break; } return { fail: k, need: true }; }
    const t = toks[i];
    if (p.lit) {
      if (!p.lit.startsWith(t.toLowerCase())) return { fail: k };
      score += t.toLowerCase() === p.lit ? 1.01 : 1;
    } else if (p.rest) { a[p.param] = toks.slice(i).join(' '); a._rest = toks.slice(i); k = toks.length; return { a, score }; }
    else a[p.param] = t;
    k = i + 1;
  }
  if (toks.length > pt.length) return { fail: pt.length };
  return { a, score };
}

/* ------------------------------------------------------------- session */
class Session {
  constructor(dev) {
    this.dev = dev; this.mode = 'user'; this.ctx = null; this.history = []; this.pending = null; this.closed = false; this.exitRequested = false;
    this.isRouter = dev instanceof NS.Router; this.isSwitch = dev instanceof NS.Switch;
  }
  get name() { return this.dev.name; }
  abort() { this.aborted = true; }
  prompt() {
    if (this.remote) return '';
    if (this.pending) return this.pending.prompt;
    const n = this.name, m = this.mode;
    const M = { user: '>', priv: '#', config: '(config)#', if: '(config-if)#', line: '(config-line)#', rip: '(config-router)#', ospf: '(config-router)#', dhcp: '(dhcp-config)#', vlan: '(config-vlan)#', isakmp: '(config-isakmp)#', tset: '(cfg-crypto-trans)#', cmap: '(config-crypto-map)#', ipsecprof: '(ipsec-profile)#', radsrv: '(config-radius-server)#', cmapq: '(config-cmap)#', pmapq: '(config-pmap)#', pmapc: '(config-pmap-c)#', aaagrp: '(config-sg-radius)#' };
    if (m === 'if') return n + (this.ctx && this.ctx.items[0] && this.ctx.items[0].iface && this.ctx.items[0].iface.sub ? '(config-subif)#' : this.ctx && this.ctx.items.length > 1 ? '(config-if-range)#' : '(config-if)#');
    if (m === 'nacl') return n + '(config-' + (this.ctx.acl.type === 'standard' ? 'std' : 'ext') + '-nacl)#';
    return n + M[m];
  }
  get masking() { return !!(this.pending && this.pending.mask); }
  /* exécute une ligne ; io = {print(str), done()} */
  exec(line, io) {
    this.aborted = false;
    if (this.remote) { this.remoteIo = io; this.remote.send(line); io.done(); return; }
    if (this.pending) { const p = this.pending; this.pending = null; p.fn(line, io); if (!p.async) io.done(); return; }
    let l = line.trim();
    if (l) { this.history.push(l); if (this.history.length > 200) this.history.shift(); }
    if (!l || l.startsWith('!')) { io.done(); return; }
    let asyncFlag = false;
    const finish = () => { io.done(); };
    try {
      const cfgBefore = this.mode !== 'user' && this.mode !== 'priv';
      const r = this.run(l, io, line);
      if (cfgBefore && (this.mode === 'priv' || this.mode === 'user') && !this.dev.restoring && this.dev.mgmt) this.dev.log('%SYS-5-CONFIG_I: Configured from console by console');
      if (r === 'async') asyncFlag = true;
      if (this.isSwitch && this.mode !== 'user' && this.mode !== 'priv' && this.dev.syncChans) { this.dev.syncChans(); if (this.dev.stp.enabled) this.dev.stp.recompute(); }
    } catch (e) { io.print('% Erreur interne : ' + e.message + '\n'); console.error(e); }
    if (!asyncFlag) finish();
  }
  run(l, io, raw) {
    const toks = l.split(/\s+/);
    // "do" en mode config
    if (toks[0].toLowerCase() === 'do' && this.mode !== 'user' && this.mode !== 'priv') {
      const save = { mode: this.mode, ctx: this.ctx }; this.mode = 'priv';
      const r = this.run(toks.slice(1).join(' '), io, raw);
      if (r !== 'async') { this.mode = save.mode; this.ctx = save.ctx; } else { const oldDone = io.done; io.done = () => { this.mode = save.mode; this.ctx = save.ctx; io.done = oldDone; oldDone(); }; }
      return r;
    }
    const sub = !['user', 'priv', 'config'].includes(this.mode);
    let m = this.resolve(l, toks, this.mode, io, raw, sub);
    if (m === 'error') return;
    if (!m && sub) {
      m = this.resolve(l, toks, 'config', io, raw, true);
      if (m && m !== 'error') { this.mode = 'config'; this.ctx = null; }
      else { this.resolve(l, toks, this.mode, io, raw, false); return; }
    }
    if (!m) return;
    return m.c.fn(this, m.a, io, toks);
  }
  resolve(l, toks, mode, io, raw, quiet) {
    let best = [], bestScore = -1, bestFail = 0, need = false;
    CMDS.forEach(c => {
      if (!c.modes.includes(mode)) return;
      if (c.priv && this.mode === 'user') return;
      const r = matchCmd(c, toks);
      if (r.a) { if (r.score > bestScore) { bestScore = r.score; best = [{ c, a: r.a }]; } else if (r.score === bestScore) best.push({ c, a: r.a }); }
      else if (r.fail !== undefined) { if (r.fail > bestFail || (r.fail === bestFail && r.need)) { bestFail = r.fail; need = !!r.need; } if (r.fail === bestFail && r.need) need = true; }
    });
    if (best.length === 1) return best[0];
    if (best.length > 1) {
      const uniq = new Set(best.map(b => b.c.fn));
      if (uniq.size === 1) return best[0];
      // priorité aux motifs sans paramètres libres supplémentaires
      const lits = best.filter(b => b.c.toks.every(t => t.lit));
      if (lits.length === 1) return lits[0];
      if (quiet) return null;
      io.print('% Ambiguous command:  "' + l + '"\n');
      return 'error';
    }
    if (quiet) return null;
    if (need && bestFail >= toks.length) io.print('% Incomplete command.\n');
    else {
      // position du caret
      let pos = 0; for (let i = 0; i < bestFail && i < toks.length; i++) { pos = raw.indexOf(toks[i], pos) + toks[i].length; }
      const next = raw.indexOf(toks[Math.min(bestFail, toks.length - 1)] || '', pos);
      io.print(' '.repeat(this.prompt().length + Math.max(0, next)) + '^\n% Invalid input detected at \'^\' marker.\n');
    }
    return 'error';
  }
  /* complétion (Tab) : renvoie la ligne complétée ou null */
  complete(line) {
    const toks = line.split(/\s+/); const last = toks[toks.length - 1]; if (!last) return null;
    const idx = toks.length - 1; const cands = new Set();
    CMDS.forEach(c => {
      if (!c.modes.includes(this.mode)) return; if (c.priv && this.mode === 'user') return;
      let ok = true;
      for (let i = 0; i < idx; i++) { const p = c.toks[i]; if (!p) { ok = false; break; } if (p.lit && !p.lit.startsWith(toks[i].toLowerCase())) { ok = false; break; } }
      const p = c.toks[idx]; if (ok && p && p.lit && p.lit.startsWith(last.toLowerCase())) cands.add(p.lit);
    });
    if (cands.size === 1) { const w = Array.from(cands)[0]; toks[idx] = w; return toks.join(' ') + ' '; }
    return cands.size ? Array.from(cands) : null;
  }
  help(line) {
    const toks = line.split(/\s+/); if (toks[toks.length - 1] === '') toks.pop();
    const partial = line.endsWith(' ') || !line.trim();
    const idx = partial ? toks.length : toks.length - 1; const out = new Map();
    CMDS.forEach(c => {
      if (!c.modes.includes(this.mode)) return; if (c.priv && this.mode === 'user') return;
      let ok = true;
      for (let i = 0; i < idx; i++) { const p = c.toks[i]; if (!p) { ok = false; break; } if (p.lit && !p.lit.startsWith(toks[i].toLowerCase())) { ok = false; break; } }
      if (!ok) return;
      const p = c.toks[idx];
      if (!p) { out.set('<cr>', ''); return; }
      if (p.lit) { if (!partial && !p.lit.startsWith(toks[idx].toLowerCase())) return; out.set(p.lit, c.help || ''); }
      else out.set('WORD', '');
    });
    return Array.from(out.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }
  /* ---- outils ---- */
  notice(io, msg) { io.print('\n*Sep 30 08:00:' + String(Math.floor(this.dev.sim.now / 1000) % 60).padStart(2, '0') + '.000: ' + msg + '\n'); }
  items() { return (this.ctx && this.ctx.items) || []; }
}

/* ------------------------------------------------------------- utilitaires */
function ifaceName(dev, i) { return i.name; }
function ospfLines(i, ln) {
  if (i.ospfCostFix) ln.push('ip ospf cost ' + i.ospfCostFix); if (i.ospfHello) ln.push('ip ospf hello-interval ' + i.ospfHello); if (i.ospfDead) ln.push('ip ospf dead-interval ' + i.ospfDead);
  if (i.ospfPri !== undefined && i.ospfPri !== null) ln.push('ip ospf priority ' + i.ospfPri); if (i.ospfNet && !(i.tun && i.ospfNet === 'p2p')) ln.push('ip ospf network ' + (i.ospfNet === 'p2p' ? 'point-to-point' : i.ospfNet));
  if (i.ospfArea !== null && i.ospfArea !== undefined) ln.push('ip ospf ' + (i.node.ospf ? i.node.ospf.pid : 1) + ' area ' + i.ospfArea);
}
function findIfaceForShow(dev, str) {
  let i = dev.ifaceByName(str); if (i) return i;
  if (dev.findPort) { const p = dev.findPort(str); if (p) { const ii = dev.ifaceList().find(x => x.port === p && !x.sub); return { port: p, name: p.name, ip: 0, mask: 0, isUp: () => p.up, portOnly: true }; } }
  return null;
}
function ipMask(s) { const m = IP.parseMask(s); return m; }
function wcFromMask(m) { return (~m) >>> 0; }
function fmtDur(ms) { const s = Math.floor(ms / 1000); return String(Math.floor(s / 3600)).padStart(2, '0') + ':' + String(Math.floor(s / 60) % 60).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); }
function statusOf(dev, i) {
  if (i.svi !== undefined && i.svi !== null) return i.adminUp ? (i.isUp() ? ['up', 'up'] : ['up', 'down']) : ['administratively down', 'down'];
  if (!i.adminUp) return ['administratively down', 'down'];
  if (i.tun) return i.isUp() ? ['up', 'up'] : ['up', 'down'];
  return i.isUp() ? ['up', 'up'] : ['down', 'down'];
}
function shortName(n) { return n.replace('GigabitEthernet', 'Gi').replace('FastEthernet', 'Fa').replace('Ethernet', 'Eth'); }
function fmtPorts(list) {
  // regroupe les ports Fa0/1, Fa0/2… en chaînes
  return list.map(p => shortName(p.name)).join(', ');
}
function vlanListStr(set) { // ensemble -> "1,10,20-30"
  const a = Array.from(set).sort((x, y) => x - y); const r = []; let i = 0;
  while (i < a.length) { let j = i; while (j + 1 < a.length && a[j + 1] === a[j] + 1) j++; r.push(j > i ? a[i] + '-' + a[j] : String(a[i])); i = j + 1; }
  return r.join(',');
}
function parseVlanList(s) {
  const r = new Set();
  s.split(',').forEach(t => { const m = /^(\d+)(?:-(\d+))?$/.exec(t.trim()); if (m) { for (let v = +m[1]; v <= +(m[2] || m[1]); v++) r.add(v); } });
  return r;
}
function expandRange(dev, str) {
  const out = [];
  str.replace(/\s*-\s*/g, '-').split(',').forEach(seg => {
    seg = seg.trim().replace(/\s+/g, '');
    const m = /^([a-z\-]+)((?:\d+\/)*)(\d+)-(?:[a-z\-]*(?:\d+\/)*)?(\d+)$/i.exec(seg);
    if (m) { for (let n = +m[3]; n <= +m[4]; n++) { const p = dev.findPort(m[1] + m[2] + n); if (p) out.push(p); } }
    else { const p = dev.findPort(seg); if (p) out.push(p); }
  });
  return out;
}

/* ------------------------------------------------------------- ACL */
function addrStr(a) { if (a.wc === 0xFFFFFFFF) return 'any'; if (a.wc === 0) return 'host ' + IP.str(a.ip); return IP.str(a.ip) + ' ' + IP.str(a.wc); }
function portOpStr(p) { if (!p) return ''; const nm = n => PORTNAME[n] || n; return p.op === 'range' ? ' range ' + nm(p.a) + ' ' + nm(p.b) : ' ' + p.op + ' ' + nm(p.a); }
function entryText(acl, e, forShow) {
  if (e.remark !== undefined) return 'remark ' + e.remark;
  if (acl.type === 'standard') return e.action + ' ' + (forShow ? (e.src.wc === 0xFFFFFFFF ? 'any' : e.src.wc === 0 ? IP.str(e.src.ip) : IP.str(e.src.ip) + ', wildcard bits ' + IP.str(e.src.wc)) : addrStr(e.src));
  let s = e.action + ' ' + e.proto + ' ' + addrStr(e.src) + portOpStr(e.sport) + ' ' + addrStr(e.dst) + portOpStr(e.dport);
  if (e.icmpType !== undefined && e.icmpType !== null) s += ' ' + ({ 8: 'echo', 0: 'echo-reply', 3: 'unreachable', 11: 'time-exceeded' }[e.icmpType] || e.icmpType);
  if (e.established) s += ' established'; if (e.log) s += ' log';
  return s;
}
function parseAddr(toks, pos) { // renvoie {a, n} (n = nb tokens consommés)
  const t = toks[pos]; if (t === undefined) return null;
  if (t === 'any') return { a: { ip: 0, wc: 0xFFFFFFFF }, n: 1 };
  if (t === 'host') { const ip = IP.parse(toks[pos + 1]); return ip === null ? null : { a: { ip, wc: 0 }, n: 2 }; }
  const ip = IP.parse(t); if (ip === null) return null;
  const wc = IP.parse(toks[pos + 1]);
  if (wc !== null && toks[pos + 1] !== undefined && /^\d+\.\d+\.\d+\.\d+$/.test(toks[pos + 1])) return { a: { ip: (ip & ~wc) >>> 0, wc }, n: 2 };
  return { a: { ip, wc: 0 }, n: 1 };
}
function parsePortSpec(toks, pos) {
  const op = toks[pos]; if (!['eq', 'neq', 'gt', 'lt', 'range'].includes(op)) return null;
  const num = t => PORTNUM[t] !== undefined ? PORTNUM[t] : (/^\d+$/.test(t) ? +t : null);
  const a = num(toks[pos + 1]); if (a === null) return null;
  if (op === 'range') { const b = num(toks[pos + 2]); if (b === null) return null; return { p: { op, a, b }, n: 3 }; }
  return { p: { op, a }, n: 2 };
}
function parseAclEntry(type, toks) {
  const action = toks[0]; if (action !== 'permit' && action !== 'deny') return 'bad';
  if (type === 'standard') { const r = parseAddr(toks, 1); if (!r) return 'bad'; return { action, src: r.a }; }
  let proto = toks[1]; if (!['ip', 'icmp', 'tcp', 'udp', 'ospf', 'gre', 'esp', 'ahp', 'eigrp'].includes(proto)) { if (/^\d+$/.test(proto)) proto = +proto; else return 'bad'; }
  let pos = 2; const e = { action, proto };
  const s = parseAddr(toks, pos); if (!s) return 'bad'; e.src = s.a; pos += s.n;
  if (proto === 'tcp' || proto === 'udp') { const sp = parsePortSpec(toks, pos); if (sp) { e.sport = sp.p; pos += sp.n; } }
  const d = parseAddr(toks, pos); if (!d) return 'bad'; e.dst = d.a; pos += d.n;
  if (proto === 'tcp' || proto === 'udp') { const dp = parsePortSpec(toks, pos); if (dp) { e.dport = dp.p; pos += dp.n; } }
  while (pos < toks.length) {
    const t = toks[pos++];
    if (t === 'established') e.established = true; else if (t === 'log') e.log = true;
    else if (proto === 'icmp' && ({ echo: 8, 'echo-reply': 0, unreachable: 3, 'time-exceeded': 11 }[t] !== undefined)) e.icmpType = { echo: 8, 'echo-reply': 0, unreachable: 3, 'time-exceeded': 11 }[t];
    else return 'bad';
  }
  return e;
}
function getAcl(dev, name, type, numbered) {
  let a = dev.acls.get(name);
  if (!a) { a = { name, type, numbered: !!numbered, entries: [] }; dev.acls.set(name, a); }
  return a;
}
function addAclEntry(acl, e, seq) {
  if (seq) e.seq = seq; else e.seq = (acl.entries.length ? acl.entries[acl.entries.length - 1].seq : 0) + 10;
  const i = acl.entries.findIndex(x => x.seq > e.seq); if (i < 0) acl.entries.push(e); else acl.entries.splice(i, 0, e);
}

/* ------------------------------------------------------------- génération de la configuration */
function genConfig(dev, save) {
  const L = []; const isSw = dev instanceof NS.Switch; const p = t => L.push(t);
  p('!'); if (!save) { p('version 15.1'); p('service timestamps debug datetime msec'); p('service timestamps log datetime msec'); p('no service password-encryption'); p('!'); }
  p('hostname ' + dev.name); p('!');
  if (dev.enableSecret) p('enable secret ' + (save ? dev.enableSecret : '5 $1$mERr$' + B.hex((dev.enableSecret.length * 7919) >>> 0, 8) + '.FvWbxCzs'));
  if (dev.enableSecret) p('!');
  if (NS.ip6Global) NS.ip6Global(dev, p, 'pre');
  if (dev.noDomainLookup) p('no ip domain-lookup'); if (dev.domain) p('ip domain-name ' + dev.domain);
  if (isSw && dev.forwarding && dev.l3capable) p('ip routing');
  Object.keys(dev.hosts || {}).forEach(h => p('ip host ' + h + ' ' + dev.hosts[h]));
  if (dev.dnsServers && dev.dnsServers.length && !dev.dhcpDns) p('ip name-server ' + dev.dnsServers.map(IP.str).join(' '));
  if (dev.users) dev.users.forEach(u => p('username ' + u.name + ' privilege ' + (u.priv || 1) + ' secret ' + u.secret));
  if (dev.dhcpd && dev.dhcpd.excluded.length) { dev.dhcpd.excluded.forEach(r => p('ip dhcp excluded-address ' + IP.str(r[0]) + (r[1] !== r[0] ? ' ' + IP.str(r[1]) : ''))); }
  if (dev.dhcpd) dev.dhcpd.pools.forEach(pl => {
    p('ip dhcp pool ' + pl.name);
    if (pl.net) p(' network ' + IP.str(pl.net) + ' ' + IP.str(pl.mask));
    if (pl.router) p(' default-router ' + IP.str(pl.router));
    if (pl.dns && pl.dns.length) p(' dns-server ' + pl.dns.map(IP.str).join(' '));
    if (pl.domain) p(' domain-name ' + pl.domain);
    if (pl.lease !== 86400) p(' lease ' + Math.floor(pl.lease / 86400) + ' ' + Math.floor(pl.lease % 86400 / 3600) + ' ' + Math.floor(pl.lease % 3600 / 60));
    p('!');
  });
  if (isSw) {
    if (dev.managed) {
      if (dev.lacpPri !== 32768) p('lacp system-priority ' + dev.lacpPri);
      if (dev.lbMethod !== 'src-mac') p('port-channel load-balance ' + dev.lbMethod);
      p('spanning-tree mode ' + dev.stp.mode);
      if (dev.stp.gPortfast) p('spanning-tree portfast default');
      if (dev.stp.gBpduGuard) p('spanning-tree portfast bpduguard default');
      dev.stp.off.forEach(v => p('no spanning-tree vlan ' + v));
      if (dev.stp.defPri !== 32768) p('spanning-tree vlan 1-4094 priority ' + dev.stp.defPri);
      Array.from(dev.stp.vpri.entries()).sort((x, y) => x[0] - y[0]).forEach(([v, pr]) => p('spanning-tree vlan ' + v + ' priority ' + pr));
    }
    dev.vlans.forEach((v, id) => { if (id !== 1) { p('vlan ' + id); p(' name ' + v.name); p('!'); } });
  }
  if (NS.aaaGlobal) NS.aaaGlobal(dev, p);
  if (NS.vpnGlobal) NS.vpnGlobal(dev, p);
  if (NS.qosGlobal) NS.qosGlobal(dev, p);
  const ifaceBlock = (name, lines, def) => { if (save && !lines.length) return; p('interface ' + name); lines.forEach(x => p(' ' + x)); p('!'); };
  if (isSw) {
    Array.from(dev.chans.values()).map(c => c.lp).concat(dev.ports).forEach(pt => {
      if (pt.virtual) return;
      const ln = [];
      if (pt.desc) ln.push('description ' + pt.desc);
      if (pt.routed) { ln.push('no switchport'); const ii = pt.routed && pt.routed.ip !== undefined ? pt.routed : null; if (ii) { ii.ip ? ln.push('ip address ' + IP.str(ii.ip) + ' ' + IP.str(ii.mask)) : (ii.dhcp ? ln.push('ip address dhcp') : ln.push('no ip address')); if (ii.aclIn) ln.push('ip access-group ' + ii.aclIn + ' in'); if (ii.aclOut) ln.push('ip access-group ' + ii.aclOut + ' out'); if (ii.nat) ln.push('ip nat ' + ii.nat); if (ii.helper) ii.helper.forEach(h => ln.push('ip helper-address ' + IP.str(h))); } }
      else {
        if (pt.lag) { ln.push('channel-group ' + pt.lag.id + ' mode ' + pt.lag.mode); if (pt.lacpFast) ln.push('lacp rate fast'); }
        else if (pt.mode === 'trunk') { ln.push('switchport mode trunk'); if (pt.native !== 1) ln.push('switchport trunk native vlan ' + pt.native); if (pt.allowed !== null) ln.push('switchport trunk allowed vlan ' + vlanListStr(pt.allowed)); }
        else if (pt.vlan !== 1) { ln.push('switchport access vlan ' + pt.vlan); ln.push('switchport mode access'); }
        else if (dev.managed && !save) { }
        if (pt.mode === 'access' && pt.vlan === 1 && pt.explicitAccess) ln.push('switchport mode access');
        if (pt.sec.enabled) { ln.push('switchport port-security'); if (pt.sec.max !== 1) ln.push('switchport port-security maximum ' + pt.sec.max); if (pt.sec.violation !== 'shutdown') ln.push('switchport port-security violation ' + pt.sec.violation); pt.sec.macs.forEach(m => { if (pt.sec.sticky) ln.push('switchport port-security mac-address sticky ' + cm(m)); }); if (pt.sec.sticky) ln.push('switchport port-security mac-address sticky'); }
        if (pt.voiceVlan) ln.push('switchport voice vlan ' + pt.voiceVlan);
        if (pt.portfast && !pt.lag) ln.push('spanning-tree portfast');
        if (pt.bpduGuard === true) ln.push('spanning-tree bpduguard enable'); else if (pt.bpduGuard === false) ln.push('spanning-tree bpduguard disable');
        if (pt.rootGuard) ln.push('spanning-tree guard root');
        if (pt.stpCost) ln.push('spanning-tree cost ' + pt.stpCost);
        if (pt.stpPri !== undefined && pt.stpPri !== 128) ln.push('spanning-tree port-priority ' + pt.stpPri);
        if (NS.dotIfLines) NS.dotIfLines(pt, ln);
        if (NS.qosIfLines) NS.qosIfLines(pt, ln, dev);
      }
      if (!pt.adminUp && !pt.errdis) ln.push('shutdown');
      ifaceBlock(pt.name, ln);
    });
    dev.ifaceList().filter(i => i.svi !== null).forEach(i => {
      const ln = []; if (i.desc) ln.push('description ' + i.desc);
      if (i.ip) ln.push('ip address ' + IP.str(i.ip) + ' ' + IP.str(i.mask)); else if (i.dhcp) ln.push('ip address dhcp'); else ln.push('no ip address');
      if (i.aclIn) ln.push('ip access-group ' + i.aclIn + ' in'); if (i.aclOut) ln.push('ip access-group ' + i.aclOut + ' out');
      i.helper.forEach(h => ln.push('ip helper-address ' + IP.str(h)));
      if (i.nat) ln.push('ip nat ' + i.nat);
      if (NS.ip6Lines) NS.ip6Lines(i, ln);
      ospfLines(i, ln);
      if (!i.adminUp) ln.push('shutdown');
      p('interface Vlan' + i.svi); ln.forEach(x => p(' ' + x)); p('!');
    });
  } else {
    dev.ifaceList().forEach(i => {
      const ln = []; if (i.desc) ln.push('description ' + i.desc);
      if (i.sub) ln.push('encapsulation dot1Q ' + (i.vid || 1));
      if (i.ip) ln.push('ip address ' + IP.str(i.ip) + ' ' + IP.str(i.mask)); else if (i.dhcp) ln.push('ip address dhcp'); else ln.push('no ip address');
      if (i.aclIn) ln.push('ip access-group ' + i.aclIn + ' in'); if (i.aclOut) ln.push('ip access-group ' + i.aclOut + ' out');
      i.helper.forEach(h => ln.push('ip helper-address ' + IP.str(h)));
      if (i.nat) ln.push('ip nat ' + i.nat);
      if (NS.ip6Lines) NS.ip6Lines(i, ln);
      if (NS.vpnIfLines) NS.vpnIfLines(i, ln);
      if (NS.qosIfLines && i.port && !i.sub) NS.qosIfLines(i.port, ln, dev);
      ospfLines(i, ln);
      if (!i.loop && !i.adminUp) ln.push('shutdown');
      p('interface ' + i.name); ln.forEach(x => p(' ' + x)); p('!');
    });
  }
  if (dev.rip && dev.rip.enabled) {
    p('router rip'); p(' version 2');
    dev.rip.passive.forEach(x => p(' passive-interface ' + x)); dev.rip.networks.forEach(n => p(' network ' + IP.str(n)));
    if (dev.rip.redistStatic) p(' redistribute static'); if (dev.rip.defaultOrig) p(' default-information originate'); p(' no auto-summary'); p('!');
  }
  if (dev.ospf && dev.ospf.enabled) {
    const o = dev.ospf; p('router ospf ' + o.pid); if (o.rid) p(' router-id ' + IP.str(o.rid));
    if (o.refBw !== 100) p(' auto-cost reference-bandwidth ' + o.refBw);
    if (o.passiveDefault) { p(' passive-interface default'); o.nonPassive.forEach(x => p(' no passive-interface ' + x)); } else o.passive.forEach(x => p(' passive-interface ' + x));
    o.networks.forEach(n => p(' network ' + IP.str(n.net) + ' ' + IP.str(n.wc) + ' area ' + n.area));
    if (o.defaultOrig) p(' default-information originate' + (o.defaultOrig.always ? ' always' : '') + (o.defaultOrig.metric && o.defaultOrig.metric !== 1 ? ' metric ' + o.defaultOrig.metric : ''));
    ['static', 'connected', 'rip'].forEach(k => { if (o.redist[k]) p(' redistribute ' + k + (k !== 'rip' ? ' subnets' : '') + (o.redist[k].metric ? ' metric ' + o.redist[k].metric : '')); });
    p('!');
  }
  dev.statics.forEach(s => { if (s.dhcp) return; if (s.net === 0 && s.mask === 0 && isSw && !dev.forwarding) p('ip default-gateway ' + IP.str(s.nh)); else p('ip route ' + IP.str(s.net) + ' ' + IP.str(s.mask) + ' ' + (s.nh ? IP.str(s.nh) : s.iface) + (s.ad && s.ad !== 1 ? ' ' + s.ad : '')); });
  if (dev.statics.length) p('!');
  // NAT
  dev.nat.dyn.forEach(r => { if (r.iface) p('ip nat inside source list ' + r.acl + ' interface ' + r.iface + ' overload'); else if (r.pool) p('ip nat inside source list ' + r.acl + ' pool ' + r.poolName + (r.overload ? ' overload' : '')); });
  if (dev.nat.pools) dev.nat.pools.forEach(pl => p('ip nat pool ' + pl.name + ' ' + IP.str(pl.start) + ' ' + IP.str(pl.end) + ' netmask ' + IP.str(pl.mask)));
  dev.nat.statics.forEach(s => p('ip nat inside source static ' + (s.proto ? s.proto + ' ' : '') + IP.str(s.lip) + ' ' + (s.proto ? s.lport + ' ' : '') + (s.gip ? IP.str(s.gip) : 'interface') + (s.proto ? ' ' + s.gport : '')));
  if (dev.nat.dyn.length || dev.nat.statics.length) p('!');
  dev.acls.forEach(a => {
    if (a.numbered) a.entries.forEach(e => p('access-list ' + a.name + ' ' + (e.remark !== undefined ? 'remark ' + e.remark : entryText(a, e))));
    else { p('ip access-list ' + a.type + ' ' + a.name); a.entries.forEach(e => p(' ' + entryText(a, e))); }
  });
  if (dev.acls.size) p('!');
  if (NS.ip6Global) NS.ip6Global(dev, p, 'post');
  if (NS.mgmtConfig) NS.mgmtConfig(dev, p);
  if (dev.banner) { p('banner motd ^C' + dev.banner + '^C'); p('!'); }
  p('line con 0'); p(' logging synchronous'); p('line vty 0 4');
  if (dev.vty.password) p(' password ' + dev.vty.password); if (dev.vty.login) p(' login'); if (dev.vty.local) p(' login local');
  if (dev.vty.loginList) p(' login authentication ' + dev.vty.loginList);
  if (dev.vty.transport) p(' transport input ' + dev.vty.transport);
  p('!'); if (!save) p('end');
  return L;
}

/* ------------------------------------------------------------- commandes EXEC */
const T = NS.tools;
cmd('exec', 'enable', (s, a, io) => {
  if (s.mode === 'priv') return;
  if (s.dev.enableSecret) { s.pending = { prompt: 'Password: ', mask: true, fn: (pw, io2) => { if (pw === s.dev.enableSecret) s.mode = 'priv'; else io2.print('% Access denied\n'); } }; return; }
  s.mode = 'priv';
});
cmd('priv', 'disable', s => { s.mode = 'user'; });
cmd('exec', 'exit', s => { if (s.mode === 'priv' || s.mode === 'user') { s.exitRequested = true; s.closed = true; } });
cmd('exec', 'logout', s => { s.exitRequested = true; s.closed = true; });
cmd('priv', 'configure terminal', (s, a, io) => { s.mode = 'config'; s.ctx = null; io.print('Enter configuration commands, one per line.  End with CNTL/Z.\n'); });
cmd('priv', 'configure', (s, a, io) => { s.mode = 'config'; s.ctx = null; io.print('Enter configuration commands, one per line.  End with CNTL/Z.\n'); });
cmd('exec', 'terminal <x...>', () => { });
cmd('exec', 'clock <x...>', () => { });

cmd('exec', 'show running-config [<x...>]', (s, a, io) => {
  const L = genConfig(s.dev, false); io.print('Building configuration...\n\nCurrent configuration : ' + L.join('\n').length + ' bytes\n' + L.join('\n') + '\n');
}, { priv: true });
cmd('exec', 'show startup-config', (s, a, io) => { if (!s.dev.startup) io.print('startup-config is not present\n'); else io.print('Using ' + s.dev.startup.length + ' bytes\n!\n' + s.dev.startup + '\n'); }, { priv: true });
cmd('exec', 'show version', (s, a, io) => {
  const d = s.dev, m = d.model_ || {}; io.print('Cisco IOS Software, ' + (s.isSwitch ? 'C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4' : m.label && /4321/.test(m.label) ? 'ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.5(3)S' : 'C1900 Software (C1900-UNIVERSALK9-M), Version 15.1(4)M4') + ', RELEASE SOFTWARE (fc2)\n' +
    'Technical Support: http://www.cisco.com/techsupport\n\nROM: Bootstrap program\n\n' + d.name + ' uptime is ' + Math.floor(d.sim.now / 60000) + ' minutes\nSystem image file is "flash:/ios.bin"\n\n' +
    'cisco ' + (m.label || d.model) + ' (simulé) processor with 524288K/65536K bytes of memory.\nProcessor board ID FTX0000SIM0\n' + d.ports.length + ' interfaces\n\nBase ethernet MAC Address       : ' + cm(d.baseMac) + '\n');
});
cmd('exec', 'show clock', (s, a, io) => { io.print('*08:00:' + String(Math.floor(s.dev.sim.now / 1000) % 60).padStart(2, '0') + '.000 UTC Wed Sep 30 2026\n'); });
cmd('exec', 'show history', (s, a, io) => { io.print('  ' + s.history.slice(-10).join('\n  ') + '\n'); });

cmd('exec', 'show ip interface brief', (s, a, io) => {
  const d = s.dev; let out = pad('Interface', 23) + pad('IP-Address', 16) + 'OK? Method Status                Protocol\n';
  const row = (name, ip, method, st) => { out += pad(name, 23) + pad(ip, 16) + 'YES ' + pad(method, 7) + pad(st[0], 22) + st[1] + '\n'; };
  if (s.isSwitch) {
    d.ports.forEach(p => { if (p.virtual) return; if (p.routed) { const i = p.routed; row(p.name, i.ip ? IP.str(i.ip) : 'unassigned', i.ip ? (i.dhcp ? 'DHCP' : 'manual') : 'unset', statusOf(d, i)); } else row(p.name, 'unassigned', 'unset', p.errdis ? ['err-disabled', 'down'] : !p.adminUp ? ['administratively down', 'down'] : p.up ? ['up', 'up'] : ['down', 'down']); });
    d.ifaceList().filter(i => i.svi !== null).forEach(i => row('Vlan' + i.svi, i.ip ? IP.str(i.ip) : 'unassigned', i.ip ? 'manual' : 'unset', statusOf(d, i)));
  } else d.ifaceList().forEach(i => row(i.name, i.ip ? IP.str(i.ip) : 'unassigned', i.ip ? (i.dhcp ? 'DHCP' : 'manual') : 'unset', statusOf(d, i)));
  io.print(out);
});
cmd('exec', 'show ip interface [<x>]', (s, a, io) => {
  const d = s.dev; const list = a.x ? [d.ifaceByName(a.x)].filter(Boolean) : d.ifaceList();
  list.forEach(i => { const st = statusOf(d, i); io.print(i.name + ' is ' + st[0] + ', line protocol is ' + st[1] + '\n' + (i.ip ? '  Internet address is ' + IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask) + '\n' : '  Internet protocol processing disabled\n') + '  Inbound  access list is ' + (i.aclIn || 'not set') + '\n  Outgoing access list is ' + (i.aclOut || 'not set') + '\n' + (i.helper.length ? '  Helper address is ' + i.helper.map(IP.str).join(', ') + '\n' : '  Helper address is not set\n') + '  NAT: ' + (i.nat || 'not configured') + '\n'); });
});
cmd('exec', 'show interfaces trunk', (s, a, io) => {
  const d = s.dev; const tr = d.l2ports().filter(p => p.mode === 'trunk' && !p.routed);
  if (!tr.length) { io.print(''); return; }
  let o = 'Port        Mode             Encapsulation  Status        Native vlan\n';
  tr.forEach(p => { o += pad(shortName(p.name), 11) + ' ' + pad('on', 16) + ' ' + pad('802.1q', 14) + ' ' + pad(p.up ? 'trunking' : 'not-trunking', 13) + ' ' + p.native + '\n'; });
  o += '\nPort        Vlans allowed on trunk\n'; tr.forEach(p => { o += pad(shortName(p.name), 11) + ' ' + (p.allowed === null ? '1-4094' : vlanListStr(p.allowed)) + '\n'; });
  o += '\nPort        Vlans in spanning tree forwarding state and not pruned\n'; tr.forEach(p => { o += pad(shortName(p.name), 11) + ' ' + (vlanListStr(new Set(Array.from(d.vlans.keys()).filter(v => (p.allowed === null || p.allowed.has(v)) && d.stp.stateFor(p, v) === 'forwarding'))) || 'none') + '\n'; });
  io.print(o);
});
cmd('exec', 'show interfaces status', (s, a, io) => {
  const d = s.dev; let o = 'Port      Name               Status       Vlan       Duplex  Speed Type\n';
  d.allPorts().forEach(p => { if (p.virtual) return; const st = p.errdis ? 'err-disabled' : !p.adminUp ? 'disabled' : p.up ? 'connected' : 'notconnect'; o += pad(shortName(p.name), 9) + ' ' + pad((p.desc || '').slice(0, 18), 18) + ' ' + pad(st, 12) + ' ' + pad(p.routed ? 'routed' : p.mode === 'trunk' ? 'trunk' : p.vlan, 10) + ' a-full  a-' + (p.isChannel ? p.speedSum() : p.speed) + ' ' + (p.isChannel ? 'N/A' : p.speed >= 1000 ? '10/100/1000BaseTX' : '10/100BaseTX') + '\n'; });
  io.print(o);
});
cmd('exec', 'show interfaces [<x>] [<y>]', (s, a, io) => {
  const d = s.dev; let list;
  if (NS.vpnShowIf && NS.vpnShowIf(s, a, io)) return;
  if (a.x && a.x.toLowerCase().startsWith('tr')) return;
  if (a.x) { const i = findIfaceForShow(d, a.x); if (!i) { io.print('% Invalid input detected at \'^\' marker.\n'); return; } list = [i]; }
  else list = s.isSwitch ? d.ports.filter(p => !p.virtual).map(p => findIfaceForShow(d, p.name)) : d.ifaceList();
  list.forEach(i => {
    const p = i.port || (i.portOnly && i.port) || null; const port = i.portOnly ? i.port : i.port; const pt = i.portOnly ? d.findPort(i.name) : i.port;
    const up = i.portOnly ? (pt.adminUp ? (pt.up ? 'up' : 'down') : 'administratively down') : statusOf(d, i)[0];
    const lp = i.portOnly ? (pt.up ? 'up' : 'down') : statusOf(d, i)[1];
    if (a.y && a.y.toLowerCase().startsWith('sw') && pt) { io.print('Name: ' + shortName(pt.name) + '\nSwitchport: Enabled\nAdministrative Mode: ' + (pt.mode === 'trunk' ? 'trunk' : 'static access') + '\nOperational Mode: ' + (pt.up ? (pt.mode === 'trunk' ? 'trunk' : 'static access') : 'down') + '\nAdministrative Trunking Encapsulation: dot1q\nAccess Mode VLAN: ' + pt.vlan + ' (' + ((d.vlans.get(pt.vlan) || {}).name || 'inactive') + ')\nTrunking Native Mode VLAN: ' + pt.native + '\nTrunking VLANs Enabled: ' + (pt.allowed === null ? 'ALL' : vlanListStr(pt.allowed)) + '\n'); return; }
    const mac = i.portOnly ? pt.mac : i.mac; const ip = !i.portOnly && i.ip ? '  Internet address is ' + IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask) + '\n' : '';
    const q = pt || {};
    io.print(i.name + ' is ' + up + ', line protocol is ' + lp + (lp === 'up' ? ' (connected)' : '') + '\n  Hardware is ' + (s.isSwitch ? 'Fast Ethernet' : 'CN Gigabit Ethernet') + ', address is ' + cm(mac) + ' (bia ' + cm(mac) + ')\n' + (i.desc ? '  Description: ' + i.desc + '\n' : '') + ip +
      '  MTU 1500 bytes, BW ' + (q.speed ? q.speed * 1000 : 1000000) + ' Kbit/sec, DLY 10 usec,\n     reliability 255/255, txload 1/255, rxload 1/255\n  Encapsulation ARPA, loopback not set\n  Full-duplex, ' + (q.speed || 1000) + 'Mb/s\n  ARP type: ARPA, ARP Timeout 04:00:00\n' +
      '     ' + (q.rxPk || 0) + ' packets input, ' + (q.rxB || 0) + ' bytes\n     ' + (q.txPk || 0) + ' packets output, ' + (q.txB || 0) + ' bytes\n');
  });
});
function routeLines(d, filter) {
  const routes = d.allRoutes(); const out = [];
  d.ifaceList().forEach(i => { if (i.ip && i.isUp() && i.mask !== 0xFFFFFFFF) routes.push({ net: i.ip, mask: 0xFFFFFFFF, iface: i, proto: 'L', nh: 0, ad: 0, metric: 0 }); });
  const now = d.sim.now;
  const sorted = routes.filter(r => !filter || r.proto === filter).sort((a, b) => (a.net - b.net) || (a.mask - b.mask));
  return { sorted, now };
}
cmd('exec', 'show ip route [<x>]', (s, a, io) => {
  const d = s.dev; const f = a.x ? ({ connected: 'C', static: 'S', rip: 'R', ospf: 'O' }[a.x.toLowerCase()] || (a.x.length === 1 ? a.x.toUpperCase() : null)) : null;
  let out = 'Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\n       * - candidate default, U - per-user static route, o - ODR\n       P - periodic downloaded static route\n\n';
  const def = d.allRoutes().filter(r => r.net === 0 && r.mask === 0).sort((x, y) => x.ad - y.ad)[0];
  out += 'Gateway of last resort is ' + (def ? (def.nh ? IP.str(def.nh) + ' to network 0.0.0.0' : 'not set') : 'not set') + '\n\n';
  const { sorted, now } = routeLines(d, f);
  // regroupement par réseau classful
  const groups = new Map(); sorted.forEach(r => { const k = r.net === 0 && r.mask === 0 ? 'def' : ((r.net & IP.classMask(r.net)) >>> 0); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); });
  groups.forEach((rs, k) => {
    let indent = 0;
    if (k !== 'def') { const masks = new Set(rs.map(r => r.mask)); const cmk = IP.classMask(rs[0].net); if (masks.size > 1) { out += '      ' + IP.str(k) + '/' + IP.prefixFromMask(cmk) + ' is variably subnetted, ' + rs.length + ' subnets, ' + masks.size + ' masks\n'; indent = 1; } else if (rs[0].mask !== cmk) { out += '      ' + IP.str(k) + '/' + IP.prefixFromMask(cmk) + ' is subnetted, ' + rs.length + ' subnets\n'; indent = 1; } }
    rs.forEach(r => {
      const code = r.proto === 'S' && r.net === 0 && r.mask === 0 ? 'S*' : (r.proto === 'O' && r.sub ? 'O ' + r.sub : r.proto);
      const cc = pad(code, indent ? 9 : 5); const rs_ = r;
      const dest = IP.str(r.net) + '/' + IP.prefixFromMask(r.mask);
      if (r.proto === 'C' || r.proto === 'L') out += cc + dest + ' is directly connected, ' + r.iface.name + '\n';
      else if (r.proto === 'R') out += cc + dest + ' [120/' + r.metric + '] via ' + IP.str(r.nh) + ', ' + fmtDur(now - r.t) + ', ' + r.iface.name + '\n';
      else if (r.proto === 'O') out += cc + dest + ' [110/' + r.metric + '] via ' + IP.str(r.nh) + ', ' + fmtDur(now - r.t) + ', ' + r.iface.name + '\n';
      else out += cc + dest + ' [' + r.ad + '/0] via ' + IP.str(r.nh || 0) + (r.nh ? '' : ', ' + r.iface.name) + '\n';
    });
  });
  io.print(out);
});
cmd('exec', 'show arp', (s, a, io) => showArp(s, io));
cmd('exec', 'show ip arp', (s, a, io) => showArp(s, io));
function showArp(s, io) {
  const d = s.dev; let o = 'Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n';
  d.ifaceList().forEach(i => { if (i.ip && i.isUp()) o += pad('Internet', 9) + ' ' + pad(IP.str(i.ip), 16) + padL('-', 9) + '   ' + cm(i.mac) + '  ARPA   ' + i.name + '\n'; });
  d.arpTable.forEach((e, ip) => { o += pad('Internet', 9) + ' ' + pad(IP.str(ip), 16) + padL(Math.floor((d.sim.now - e.t) / 60000), 9) + '   ' + cm(e.mac) + '  ARPA   ' + (e.iface ? e.iface.name : '') + '\n'; });
  io.print(o);
}
function macTable(s, io, filterVlan) {
  const d = s.dev; let o = '          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n'; let n = 0;
  Array.from(d.macTable.entries()).sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true })).forEach(([k, e]) => { const [v, m] = k.split('|'); if (filterVlan && +v !== filterVlan) return; if (d.sim.now - e.t > d.macAging) return; o += padL(v, 4) + '    ' + cm(m) + '    DYNAMIC     ' + shortName(e.port.name) + '\n'; n++; });
  io.print(o + 'Total Mac Addresses for this criterion: ' + n + '\n');
}
cmd('exec', 'show mac address-table [<x...>]', (s, a, io) => { const m = /vlan\s+(\d+)/i.exec(a.x || ''); macTable(s, io, m ? +m[1] : 0); });
cmd('exec', 'show mac-address-table [<x...>]', (s, a, io) => { const m = /vlan\s+(\d+)/i.exec(a.x || ''); macTable(s, io, m ? +m[1] : 0); });
cmd('exec', 'show vlan [<x...>]', (s, a, io) => {
  const d = s.dev; let o = 'VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n';
  Array.from(d.vlans.keys()).sort((x, y) => x - y).forEach(id => {
    const pts = d.ports.filter(p => !p.virtual && !p.routed && p.mode === 'access' && p.vlan === id).map(p => shortName(p.name));
    const lines = []; let cur = '';
    pts.forEach(x => { if ((cur + x).length > 30) { lines.push(cur.replace(/, $/, '')); cur = ''; } cur += x + ', '; }); if (cur) lines.push(cur.replace(/, $/, ''));
    o += pad(id, 5) + pad(d.vlans.get(id).name, 33) + pad('active', 10) + (lines[0] || '') + '\n'; for (let i = 1; i < lines.length; i++) o += ' '.repeat(48) + lines[i] + '\n';
  });
  io.print(o);
});
cmd('exec', 'show port-security [<x...>]', (s, a, io) => {
  const d = s.dev; let o = 'Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action\n                (Count)       (Count)          (Count)\n--------------------------------------------------------------------\n';
  d.ports.forEach(p => { if (p.sec && p.sec.enabled) o += padL(shortName(p.name), 11) + padL(p.sec.max, 15) + padL(p.sec.macs.size, 13) + padL(p.sec.violations || 0, 19) + '         ' + p.sec.violation[0].toUpperCase() + p.sec.violation.slice(1) + '\n'; });
  io.print(o);
});
cmd('exec', 'show ip dhcp binding', (s, a, io) => {
  const d = s.dev; let o = 'Bindings from all pools not associated with VRF:\nIP address          Client-ID/              Lease expiration        Type\n                    Hardware address/\n                    User name\n';
  d.dhcpd.leases.forEach((l, m) => { if (l.offered) return; o += pad(IP.str(l.ip), 19) + ' 01' + cm(m).replace(/\./g, '').replace(/(..)(..)(..)(..)(..)(..)/, '$1$2.$3$4.$5$6') + '     ' + pad('Sep 30 2026 08:00 AM', 23) + ' Automatic\n'; });
  io.print(o);
});
cmd('exec', 'show ip dhcp pool [<x>]', (s, a, io) => {
  s.dev.dhcpd.pools.forEach(p => { const n = Array.from(s.dev.dhcpd.leases.values()).filter(l => l.pool === p.name && !l.offered).length; io.print('Pool ' + p.name + ' :\n Utilization mark (high/low)    : 100 / 0\n Subnet size (first/next)       : 0 / 0\n Total addresses                : ' + (IP.bcast(p.net, p.mask) - p.net - 1) + '\n Leased addresses               : ' + n + '\n Pending event                  : none\n 1 subnet is currently in the pool :\n Current index        IP address range                    Leased addresses\n ' + pad(IP.str(p.net + 1), 20) + pad(IP.str(p.net + 1) + ' - ' + IP.str(IP.bcast(p.net, p.mask) - 1), 36) + n + '\n'); });
});
cmd('exec', 'show ip dhcp server statistics', () => { });
cmd('exec', 'show ip nat translations', (s, a, io) => {
  const d = s.dev; let o = 'Pro Inside global      Inside local       Outside local      Outside global\n';
  d.nat.table.forEach(e => { const f = (ip, po) => pad(IP.str(ip) + (e.proto === 'icmp' ? ':' + po : ':' + po), 18); o += pad(e.proto, 4) + f(e.igIp, e.igPort) + ' ' + f(e.ilIp, e.ilPort) + ' ' + f(e.ogIp, e.ogPort) + ' ' + f(e.ogIp, e.ogPort) + '\n'; });
  io.print(o);
});
cmd('exec', 'show ip nat statistics', (s, a, io) => { const d = s.dev; io.print('Total active translations: ' + d.nat.table.length + ' (' + d.nat.table.filter(e => e.static).length + ' static, ' + d.nat.table.filter(e => !e.static).length + ' dynamic; ' + d.nat.table.filter(e => !e.static).length + ' extended)\nOutside interfaces:\n  ' + d.ifaceList().filter(i => i.nat === 'outside').map(i => i.name).join(', ') + '\nInside interfaces:\n  ' + d.ifaceList().filter(i => i.nat === 'inside').map(i => i.name).join(', ') + '\n'); });
function showAcl(s, io, name) {
  s.dev.acls.forEach(a => { if (name && a.name !== name) return; io.print((a.type === 'standard' ? 'Standard' : 'Extended') + ' IP access list ' + a.name + '\n'); a.entries.forEach(e => { io.print('    ' + e.seq + ' ' + entryText(a, e, true) + (e.hits ? ' (' + e.hits + ' match' + (e.hits > 1 ? 'es' : '') + ')' : '') + '\n'); }); });
}
cmd('exec', 'show access-lists [<x>]', (s, a, io) => showAcl(s, io, a.x));
cmd('exec', 'show ip access-lists [<x>]', (s, a, io) => showAcl(s, io, a.x));
cmd('exec', 'show cdp neighbors', (s, a, io) => {
  const d = s.dev; let o = 'Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge\n                  S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone\n\nDevice ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n';
  d.ports.forEach(p => { const pe = p.peer; if (!pe || !p.up) return; const pd = pe.dev; if (!(pd instanceof NS.Router || (pd instanceof NS.Switch && pd.managed))) return; o += pad(pd.name, 16) + ' ' + pad(shortName(p.name), 17) + ' 150        ' + pad(pd instanceof NS.Router ? 'R' : 'S', 11) + pad('Cisco', 9) + ' ' + shortName(pe.name) + '\n'; });
  io.print(o);
});
cmd('exec', 'show users', (s, a, io) => { io.print('    Line       User       Host(s)              Idle       Location\n*  0 con 0                idle                 00:00:00\n'); });
cmd('exec', 'show ssh', () => { });
cmd('exec', 'show ip ssh', (s, a, io) => io.print('SSH Enabled - version 2.0\n'));
cmd('exec', 'show flash:', (s, a, io) => io.print('-#- --length-- -----date/time------ path\n1     33591768 Mar 01 2013 00:00:00 ios.bin\n'));
cmd('exec', 'show sessions', (s, a, io) => io.print('% No connections open\n'));

/* --- ping / traceroute --- */
function resolveTarget(s, host, io, cb) {
  const d = s.dev; const ip = IP.parse(host);
  if (ip !== null) return cb(ip);
  const v6 = NS.IP6.parse(host); if (v6 !== null) return cb(v6);
  if (d.noDomainLookup && !(d.hosts && d.hosts[host.toLowerCase()])) { io.print('% Unrecognized host or address, or protocol not running.\n'); return io.done(); }
  io.print('Translating "' + host + '"...domain server (' + ((d.dnsServers || []).map(IP.str).join(', ') || '255.255.255.255') + ')\n');
  d.resolve(host, (err, r) => { if (err) { io.print('% Unrecognized host or address, or protocol not running.\n'); return io.done(); } cb(r.ip); });
}
cmd('exec', 'ping <host> [<opts...>]', (s, a, io) => {
  const d = s.dev; let toks = (a._rest || []); let count = 5, size = 100, src;
  if (a.host.toLowerCase() === 'ipv6') { a = Object.assign({}, a, { host: toks[0] || '' }); toks = toks.slice(1); }
  for (let i = 0; i < toks.length; i++) { const t = toks[i].toLowerCase(); if (t === 'repeat') count = +toks[++i] || 5; else if (t === 'size') size = +toks[++i] || 100; else if (t === 'source') { const v = toks[++i]; const ifc = d.ifaceByName(v); src = ifc ? ifc.ip : IP.parse(v); } }
  resolveTarget(s, a.host, io, dst => {
    if (src === 0 || src === undefined) src = undefined;
    io.print('Type escape sequence to abort.\nSending ' + count + ', ' + size + '-byte ICMP Echos to ' + NS.fmtIp(dst) + ', timeout is 2 seconds:\n');
    let ok = 0; const rtts = [];
    T.pingSeries(d, dst, { count, size: Math.max(0, size - (typeof dst === 'bigint' ? 48 : 28)), interval: 0, src: typeof dst === 'bigint' ? undefined : src, abort: () => s.aborted }, (r) => {
      const ch = r.type === 'reply' ? '!' : r.type === 'unreach' ? 'U' : r.type === 'ttl' ? '&' : '.';
      if (r.type === 'reply') { ok++; rtts.push(r.rtt); } io.print(ch);
    }, st => {
      const rt = T.fmtStats(rtts);
      io.print('\nSuccess rate is ' + Math.round(ok * 100 / count) + ' percent (' + ok + '/' + count + ')' + (rt ? ', round-trip min/avg/max = ' + Math.max(1, Math.round(rt.mn)) + '/' + Math.max(1, Math.round(rt.av)) + '/' + Math.max(1, Math.round(rt.mx)) + ' ms' : '') + '\n'); io.done();
    });
  });
  return 'async';
});
cmd('exec', 'traceroute <host> [<x...>]', (s, a, io) => {
  const d = s.dev; if (a.host.toLowerCase() === 'ipv6') a = Object.assign({}, a, { host: (a._rest || [])[0] || '' });
  resolveTarget(s, a.host, io, dst => {
    io.print('Type escape sequence to abort.\nTracing the route to ' + NS.fmtIp(dst) + '\nVRF info: (vrf in name/id, vrf out name/id)\n');
    T.trace(d, dst, { maxHops: 30, probes: 3 }, (ttl, rs) => {
      let line = padL(ttl, 3) + ' ';
      const first = rs.find(r => r.from !== undefined);
      line += first ? NS.fmtIp(first.from) : '*';
      rs.forEach(r => { line += r.type === 'timeout' || r.type === 'noroute' || r.type === 'arpfail' ? ' *' : ' ' + Math.max(1, Math.round(r.rtt)) + ' msec'; });
      io.print(line + '\n');
    }, () => { io.done(); });
  });
  return 'async';
});
cmd('exec', 'tracert <host>', (s, a, io) => io.print('% Invalid input detected. Utilisez "traceroute".\n'));

/* --- telnet / ssh client --- */
function remoteSession(s, io, hostArg, mode) {
  const d = s.dev;
  resolveTarget(s, hostArg, io, dst => {
    io.print('Trying ' + IP.str(dst) + ' ... ');
    NS.tools.openRemote(d, dst, mode, {
      onOpen: send => { io.print('Open\n'); s.remote = { send }; s.remoteIo = io; io.done(); },
      onText: t => { (s.remoteIo || io).print(t.replace(/\r\n/g, '\n').replace(/\r/g, '')); },
      onClose: () => { const r = s.remote; s.remote = null; (s.remoteIo || io).print('\n[Connection to ' + hostArg + ' closed by foreign host]\n'); if (r) (s.remoteIo || io).done(); },
      onError: e => { io.print(e === 'refused' ? '% Connection refused by remote host\n' : '% Destination unreachable; gateway or host down\n'); io.done(); },
    });
  });
  return 'async';
}
cmd('exec', 'telnet <host>', (s, a, io) => remoteSession(s, io, a.host, 'telnet'));
cmd('exec', 'ssh <x...>', (s, a, io) => { const t = a._rest; const h = t.filter(x => !x.startsWith('-') && x !== 'l' && x !== t[t.indexOf('-l') + 1]).pop() || t[t.length - 1]; return remoteSession(s, io, h, 'ssh'); });

/* --- fichiers de config --- */
function writeMem(s, a, io) { s.dev.startup = genConfig(s.dev, true).join('\n'); io.print('Building configuration...\n[OK]\n'); }
cmd('priv', 'write memory', writeMem); cmd('priv', 'write', writeMem); cmd('priv', 'copy running-config startup-config', (s, a, io) => { io.print('Destination filename [startup-config]?\n'); writeMem(s, a, io); });
cmd('priv', 'erase startup-config', (s, a, io) => { s.dev.startup = null; io.print('Erasing the nvram filesystem will remove all configuration files! Continue? [confirm]\n[OK]\nErase of nvram: complete\n'); });
cmd('priv', 'reload', (s, a, io) => {
  const d = s.dev; io.print('Proceed with reload? [confirm]\nSystem Bootstrap, Version 15.0(1r)M15\nRestarting system...\n');
  d.cliReset(); if (d.startup) d.cliRestore(d.startup, true); s.mode = 'user'; s.ctx = null;
});
cmd('priv', 'clear ip nat translation <x...>', (s) => s.dev.natClear());
cmd('priv', 'clear arp-cache', (s) => s.dev.arpTable.clear());
cmd('priv', 'clear arp', (s) => s.dev.arpTable.clear());
cmd('priv', 'clear mac address-table <x...>', (s) => s.dev.macTable && s.dev.macTable.clear());
cmd('priv', 'clear counters <x...>', () => { });
cmd('priv', 'clear access-list counters [<x>]', (s) => s.dev.acls.forEach(a => a.entries.forEach(e => e.hits = 0)));
cmd('priv', 'debug <x...>', (s, a, io) => io.print('(debug non simulé — utilisez l\'analyseur de trames)\n'));
cmd('priv', 'undebug <x...>', () => { });
cmd('priv', 'no debug <x...>', () => { });

/* ------------------------------------------------------------- commandes de configuration globale */
cmd('cfg', 'end', s => { s.mode = 'priv'; s.ctx = null; });
cmd('cfg', 'exit', s => { if (s.mode === 'config') s.mode = 'priv'; else s.mode = 'config'; s.ctx = null; });
cmd('config', 'hostname <x>', (s, a) => { s.dev.name = a.x; s.dev.sim.emit('rename', s.dev); });
cmd('config', 'enable secret <x...>', (s, a) => { s.dev.enableSecret = a._rest[a._rest.length - 1]; });
cmd('config', 'enable password <x>', (s, a) => { if (!s.dev.enableSecret) s.dev.enableSecret = a.x; });
cmd('config', 'no enable secret [<x...>]', s => { s.dev.enableSecret = ''; });
cmd('config', 'service <x...>', () => { }); cmd('config', 'no service <x...>', () => { });
cmd('config', 'banner motd <x...>', (s, a) => { s.dev.banner = a.x.replace(/^(\S)(.*)\1$/, '$2').replace(/^\^C|\^C$/g, ''); });
cmd('config', 'no ip domain-lookup', s => { s.dev.noDomainLookup = true; });
cmd('config', 'ip domain-lookup', s => { s.dev.noDomainLookup = false; });
cmd('config', 'no ip domain lookup', s => { s.dev.noDomainLookup = true; });
cmd('config', 'ip domain-name <x>', (s, a) => { s.dev.domain = a.x; });
cmd('config', 'ip name-server <x...>', (s, a) => { s.dev.dnsServers = a._rest.map(IP.parse).filter(x => x !== null); s.dev.dhcpDns = false; });
cmd('config', 'ip host <n> <ip>', (s, a) => { s.dev.hosts = s.dev.hosts || {}; s.dev.hosts[a.n.toLowerCase()] = a.ip; });
cmd('config', 'no ip host <n>', (s, a) => { delete s.dev.hosts[a.n.toLowerCase()]; });
cmd('config', 'clock <x...>', () => { }); 
cmd('config', 'cdp <x...>', () => { }); cmd('config', 'no cdp <x...>', () => { }); cmd('config', 'lldp <x...>', () => { });
cmd('config', 'ipv6 <x...>', () => { }); cmd('config', 'ip classless', () => { }); cmd('config', 'ip cef', () => { }); cmd('config', 'no ip cef', () => { });
cmd('config', 'ip ssh <x...>', () => { }); cmd('config', 'crypto key generate <x...>', (s, a, io) => io.print('The name for the keys will be: ' + s.dev.name + '.' + (s.dev.domain || 'local') + '\n% The key modulus size is 1024 bits\n% Generating 1024 bit RSA keys, keys will be non-exportable...[OK]\n'));
cmd('config', 'username <u> <x...>', (s, a) => { const t = a._rest; const secret = t[t.length - 1]; const pi = t.indexOf('privilege'); s.dev.users = (s.dev.users || []).filter(u => u.name !== a.u); s.dev.users.push({ name: a.u, secret, priv: pi >= 0 ? +t[pi + 1] : 1 }); });
cmd('config', 'ip routing', s => { if (!s.dev.l3capable && s.isSwitch) return; s.dev.forwarding = true; });
cmd('config', 'no ip routing', s => { if (s.isSwitch) s.dev.forwarding = false; });
cmd('config', 'ip default-gateway <ip>', (s, a) => { const ip = IP.parse(a.ip); s.dev.statics = s.dev.statics.filter(x => !(x.net === 0 && x.mask === 0)); if (ip) s.dev.statics.push({ net: 0, mask: 0, nh: ip, iface: null, ad: 1 }); });
cmd('config', 'ip route <net> <mask> <nh> [<ad>]', (s, a, io) => {
  const net = IP.parse(a.net), mask = IP.parseMask(a.mask);
  if (net === null || mask === null) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  const nh = IP.parse(a.nh); let ifc = null; if (nh === null) { ifc = s.dev.ifaceByName(a.nh); if (!ifc) { io.print('% Invalid next hop: ' + a.nh + '\n'); return; } }
  s.dev.addStatic(net, mask, nh || 0, ifc ? ifc.name : null, a.ad ? +a.ad : 1); s.dev.rip && s.dev.rip.enabled && s.dev.rip.triggered();
});
cmd('config', 'no ip route <net> <mask> [<nh>] [<ad>]', (s, a) => { const net = IP.parse(a.net), mask = IP.parseMask(a.mask); const nh = a.nh ? IP.parse(a.nh) : null; s.dev.statics = s.dev.statics.filter(x => !(x.net === IP.net(net, mask) && x.mask === mask && (nh === null || x.nh === nh))); });
cmd('config', 'vlan <ids>', (s, a, io) => {
  if (!s.isSwitch) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  const ids = parseVlanList(a.ids); ids.forEach(id => { if (id < 1 || id > 4094) return; if (!s.dev.vlans.has(id)) s.dev.vlans.set(id, { name: 'VLAN' + String(id).padStart(4, '0') }); });
  s.dev.stp && s.dev.stp.syncVlans(); s.mode = 'vlan'; s.ctx = { vlan: Array.from(ids)[0], ids: Array.from(ids) };
  s.dev.ifaceList().forEach(i => s.dev.ifaceStateChanged && 0);
});
cmd('config', 'no vlan <ids>', (s, a) => { parseVlanList(a.ids).forEach(id => { if (id !== 1) s.dev.vlans.delete(id); }); });
cmd('vlan', 'name <x>', (s, a) => { s.ctx.ids.forEach(id => s.dev.vlans.get(id).name = a.x); });
cmd('vlan', 'state <x>', () => { }); cmd('vlan', 'no <x...>', () => { });
cmd('config', 'mac address-table <x...>', () => { }); cmd('config', 'no mac address-table <x...>', () => { });
cmd('config', 'errdisable <x...>', () => { });

/* ---- interfaces ---- */
function makeItem(s, str, io) {
  const d = s.dev; const low = str.toLowerCase().replace(/\s+/g, '');
  let m;
  if ((m = /^vlan(\d+)$/.exec(low)) && s.isSwitch) { const v = +m[1]; let i = d.sviIface(v); if (!i) { i = d.addIface('Vlan' + v, { svi: v }); } return { iface: i, name: 'Vlan' + v }; }
  if ((m = /^loopback(\d+)$/.exec(low)) || (m = /^lo(\d+)$/.exec(low))) { const nm = 'Loopback' + m[1]; let i = d.ifaces.get(nm); if (!i) { i = d.addIface(nm, {}); i.loop = true; } return { iface: i, name: nm }; }
  if (s.isRouter && ((m = /^tunnel(\d+)$/.exec(low)) || (m = /^tu(\d+)$/.exec(low)))) { const nm = 'Tunnel' + m[1]; let i = d.ifaces.get(nm); if (!i) { d.vpn.ensure(); i = d.addIface(nm, {}); i.tun = { srcIf: null, srcIp: 0, dst: 0, key: null, mode: 'gre', prot: null }; i.mtu = 1476; i.ospfNet = 'p2p'; } return { iface: i, name: nm }; }
  if (s.isRouter && (m = /^(.+?)\.(\d+)$/.exec(low))) {
    const par = d.ifaceByName(m[1]); if (!par) return null; const nm = par.name + '.' + m[2];
    let i = d.ifaces.get(nm); if (!i) { i = d.addIface(nm, { port: par.port }); i.sub = true; i.parentName = par.name; i.vid = null; i.adminUp = true; }
    return { iface: i, name: nm };
  }
  if (s.isSwitch && (m = /^(?:po|port-?channel)(\d+)$/.exec(low))) { const c = d.chanOf(+m[1], true); return { port: c.lp, iface: null, name: c.lp.name }; }
  if (s.isSwitch) { const p = d.findPort(str); if (!p || p.virtual) return null; return { port: p, iface: p.routed && p.routed !== true ? p.routed : null, name: p.name }; }
  const i = d.ifaceByName(str); if (!i) return null; return { iface: i, port: i.port, name: i.name };
}
cmd('config', 'interface range <x...>', (s, a, io) => {
  if (!s.isSwitch) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  const ports = expandRange(s.dev, a.x); if (!ports.length) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  s.mode = 'if'; s.ctx = { items: ports.map(p => ({ port: p, iface: p.routed && p.routed !== true ? p.routed : null, name: p.name })) };
});
cmd('config', 'interface <x...>', (s, a, io) => {
  const it = makeItem(s, a.x, io); if (!it) { io.print('% Invalid interface specified\n'); return; }
  s.mode = 'if'; s.ctx = { items: [it] };
});
cmd('if', 'description <x...>', (s, a) => s.items().forEach(it => { if (it.port) it.port.desc = a.x; if (it.iface) it.iface.desc = a.x; }));
cmd('if', 'no description', s => s.items().forEach(it => { if (it.port) it.port.desc = ''; if (it.iface) it.iface.desc = ''; }));
function setAdmin(s, io, up) {
  const d = s.dev;
  s.items().forEach(it => {
    const ifc = it.iface; const pt = it.port || (ifc && ifc.port && !ifc.sub ? ifc.port : null);
    if (ifc) ifc.adminUp = up;
    if (pt && !(ifc && ifc.sub)) { pt.adminUp = up; if (up) pt.errdis = false; d.sim.portChanged(pt); if (pt.peer) d.sim.portChanged(pt.peer); }
    if (ifc) d.ifaceStateChanged(ifc);
    const nm = ifc ? ifc.name : pt.name; const isUp = ifc ? ifc.isUp() : pt.up;
    if (!up) s.notice(io, '%LINK-5-CHANGED: Interface ' + nm + ', changed state to administratively down');
    else if (isUp) { s.notice(io, '%LINK-3-UPDOWN: Interface ' + nm + ', changed state to up'); io.print('*Sep 30 08:00:00.000: %LINEPROTO-5-UPDOWN: Line protocol on Interface ' + nm + ', changed state to up\n'); }
  });
}
cmd('if', 'shutdown', (s, a, io) => setAdmin(s, io, false));
cmd('if', 'no shutdown', (s, a, io) => setAdmin(s, io, true));
cmd('if', 'ip address dhcp', (s, a, io) => s.items().forEach(it => { if (!it.iface) { io.print('% Invalid input detected at \'^\' marker.\n'); return; } s.dev.enableDhcp(it.iface, true); }));
cmd('if', 'ip address <ip> <mask> [<x...>]', (s, a, io) => {
  const ip = IP.parse(a.ip), mask = IP.parseMask(a.mask);
  if (ip === null || mask === null) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  s.items().forEach(it => {
    if (!it.iface) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
    s.dev.enableDhcp(it.iface, false); it.iface.ip = ip; it.iface.mask = mask;
    s.dev.sim.at(0.1, () => s.dev.arpAnnounce(it.iface));
    if (s.dev.rip && s.dev.rip.enabled) s.dev.rip.triggered();
  });
});
cmd('if', 'no ip address [<x...>]', s => s.items().forEach(it => { if (it.iface) { s.dev.enableDhcp(it.iface, false); it.iface.ip = 0; it.iface.mask = 0; } }));
cmd('if', 'ip access-group <n> <dir>', (s, a) => s.items().forEach(it => { if (it.iface) { if (a.dir.toLowerCase().startsWith('i')) it.iface.aclIn = a.n; else it.iface.aclOut = a.n; } }));
cmd('if', 'no ip access-group <n> <dir>', (s, a) => s.items().forEach(it => { if (it.iface) { if (a.dir.toLowerCase().startsWith('i')) it.iface.aclIn = null; else it.iface.aclOut = null; } }));
cmd('if', 'ip nat <x>', (s, a) => s.items().forEach(it => { if (it.iface) it.iface.nat = a.x.toLowerCase().startsWith('i') ? 'inside' : 'outside'; }));
cmd('if', 'no ip nat <x>', (s, a) => s.items().forEach(it => { if (it.iface) it.iface.nat = null; }));
cmd('if', 'ip helper-address <ip>', (s, a) => s.items().forEach(it => { const ip = IP.parse(a.ip); if (it.iface && ip !== null && !it.iface.helper.includes(ip)) it.iface.helper.push(ip); }));
cmd('if', 'no ip helper-address <ip>', (s, a) => s.items().forEach(it => { if (it.iface) it.iface.helper = it.iface.helper.filter(x => x !== IP.parse(a.ip)); }));
cmd('if', 'encapsulation dot1q <v> [<x>]', (s, a, io) => s.items().forEach(it => { if (it.iface && it.iface.sub) { it.iface.vid = +a.v; s.dev.ifaceStateChanged(it.iface); } else io.print('% Invalid input detected at \'^\' marker.\n'); }));
cmd('if', 'encapsulation <x...>', () => { });
cmd('if', 'no ip proxy-arp', () => { }); cmd('if', 'ip <x...>', () => { }); cmd('if', 'no ip <x...>', () => { });
cmd('if', 'duplex <x>', () => { }); cmd('if', 'speed <x>', () => { }); cmd('if', 'bandwidth <x>', () => { }); cmd('if', 'mdix <x...>', () => { }); cmd('if', 'cdp <x...>', () => { }); cmd('if', 'no cdp <x...>', () => { });
cmd('if', 'no keepalive', () => { }); cmd('if', 'clock rate <x>', () => { }); cmd('if', 'mls <x...>', () => { }); cmd('if', 'storm-control <x...>', () => { }); cmd('if', 'lldp <x...>', () => { });
cmd('if', 'no switchport', (s, a, io) => s.items().forEach(it => {
  if (!s.isSwitch || !it.port) { return; } const d = s.dev; const pt = it.port; if (!d.l3capable && d.model_.kind !== 'box') { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  if (!pt.routed || pt.routed === true) { const i = d.addIface(pt.name, { port: pt }); pt.routed = i; it.iface = i; } else it.iface = pt.routed;
}));
cmd('if', 'switchport', (s) => s.items().forEach(it => { if (s.isSwitch && it.port && it.port.routed) { const d = s.dev; d.ifaces.delete(it.port.name); it.port.routed = null; it.iface = null; } }));
function needSw(s, io) { if (!s.isSwitch) { io.print('% Invalid input detected at \'^\' marker.\n'); return false; } return true; }
cmd('if', 'switchport mode <x>', (s, a, io) => { if (!needSw(s, io)) return; const m = a.x.toLowerCase(); s.items().forEach(it => { if (!it.port) return; if (m.startsWith('t')) it.port.mode = 'trunk'; else if (m.startsWith('a')) { it.port.mode = 'access'; it.port.explicitAccess = true; } else if (m.startsWith('d')) { /* dynamic : reste access */ } s.dev.stp.enabled && s.dev.stp.recompute(); }); });
cmd('if', 'switchport access vlan <v>', (s, a, io) => {
  if (!needSw(s, io)) return; const v = +a.v; if (!(v >= 1 && v <= 4094)) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  if (!s.dev.vlans.has(v)) { s.dev.vlans.set(v, { name: 'VLAN' + String(v).padStart(4, '0') }); io.print('% Access VLAN does not exist. Creating vlan ' + v + '\n'); }
  s.items().forEach(it => { if (it.port) { it.port.vlan = v; it.port.mode = 'access'; } });
});
cmd('if', 'switchport trunk encapsulation <x>', () => { });
cmd('if', 'switchport trunk native vlan <v>', (s, a, io) => { if (needSw(s, io)) s.items().forEach(it => { if (it.port) it.port.native = +a.v; }); });
cmd('if', 'switchport trunk allowed vlan <op> [<ids>]', (s, a, io) => {
  if (!needSw(s, io)) return;
  s.items().forEach(it => {
    const p = it.port; if (!p) return; const op = a.op.toLowerCase();
    if (op === 'all') p.allowed = null;
    else if (op === 'none') p.allowed = new Set();
    else if (op === 'add') { if (p.allowed) parseVlanList(a.ids).forEach(v => p.allowed.add(v)); }
    else if (op === 'remove') { if (p.allowed === null) p.allowed = new Set(Array.from({ length: 4094 }, (_, i) => i + 1)); parseVlanList(a.ids).forEach(v => p.allowed.delete(v)); }
    else if (op === 'except') { p.allowed = new Set(Array.from({ length: 4094 }, (_, i) => i + 1)); parseVlanList(a.ids || '').forEach(v => p.allowed.delete(v)); }
    else p.allowed = parseVlanList(a.op);
  });
});
cmd('if', 'no switchport trunk allowed vlan', s => s.items().forEach(it => { if (it.port) it.port.allowed = null; }));
cmd('if', 'no switchport access vlan', s => s.items().forEach(it => { if (it.port) it.port.vlan = 1; }));
cmd('if', 'no switchport mode', s => s.items().forEach(it => { if (it.port) it.port.mode = 'access'; }));
cmd('if', 'switchport nonegotiate', () => { }); cmd('if', 'switchport voice vlan <v>', (s, a, io) => { if (!needSw(s, io)) return; const v = +a.v; if (!(v >= 1 && v <= 4094)) { s.dev.vlans; if (/^(dot1p|untagged|none)$/i.test(a.v)) { s.items().forEach(it => { if (it.port) it.port.voiceVlan = 0; }); return; } io.print('% Invalid input detected at \'^\' marker.\n'); return; } s.items().forEach(it => { if (it.port) { it.port.voiceVlan = v; if (it.port.up) s.dev.sendCdp(it.port); } }); });
cmd('if', 'no switchport voice vlan', s => s.items().forEach(it => { if (it.port) it.port.voiceVlan = 0; }));
cmd('if', 'switchport port-security', (s, a, io) => { if (needSw(s, io)) s.items().forEach(it => { if (it.port) { if (it.port.mode !== 'access' && it.port.mode !== 'trunk') { } it.port.sec.enabled = true; } }); });
cmd('if', 'no switchport port-security', s => s.items().forEach(it => { if (it.port) { it.port.sec.enabled = false; it.port.sec.macs.clear(); it.port.errdis = false; } }));
cmd('if', 'switchport port-security maximum <n>', (s, a) => s.items().forEach(it => { if (it.port) it.port.sec.max = +a.n; }));
cmd('if', 'switchport port-security violation <x>', (s, a) => s.items().forEach(it => { if (it.port) it.port.sec.violation = a.x.toLowerCase(); }));
cmd('if', 'switchport port-security mac-address sticky [<m>]', (s, a) => s.items().forEach(it => { if (it.port) { it.port.sec.sticky = true; if (a.m) { const m = MAC.parseAny(a.m); if (m) it.port.sec.macs.add(m); } } }));
cmd('if', 'switchport port-security mac-address <m>', (s, a) => s.items().forEach(it => { const m = MAC.parseAny(a.m); if (it.port && m) it.port.sec.macs.add(m); }));
cmd('if', 'switchport <x...>', () => { });
cmd('if', 'spanning-tree portfast <x...>', (s, a) => s.items().forEach(it => { if (it.port) { it.port.portfast = true; s.dev.stp.enabled && s.dev.stp.recompute(); } }));
cmd('if', 'spanning-tree portfast', (s, a) => s.items().forEach(it => { if (it.port) { it.port.portfast = true; s.dev.stp.enabled && s.dev.stp.recompute(); } }));
cmd('if', 'no spanning-tree portfast', s => s.items().forEach(it => { if (it.port) it.port.portfast = false; }));
cmd('if', 'spanning-tree <x...>', () => { });

/* ---- ACL ---- */
cmd('config', 'access-list <n> remark <x...>', (s, a) => { const acl = getAcl(s.dev, a.n, +a.n < 100 || (+a.n >= 1300 && +a.n < 2000) ? 'standard' : 'extended', true); addAclEntry(acl, { remark: a.x }); });
cmd('config', 'access-list <n> <x...>', (s, a, io) => {
  const n = +a.n; const type = (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999) ? 'standard' : (n >= 100 && n <= 199) || (n >= 2000 && n <= 2699) ? 'extended' : null;
  if (!type) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  const e = parseAclEntry(type, a._rest); if (e === 'bad') { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  addAclEntry(getAcl(s.dev, a.n, type, true), e);
});
cmd('config', 'no access-list <n>', (s, a) => s.dev.acls.delete(a.n));
cmd('config', 'ip access-list <t> <name>', (s, a, io) => {
  const t = a.t.toLowerCase(); const type = t.startsWith('s') ? 'standard' : t.startsWith('e') ? 'extended' : null; if (!type) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  const acl = getAcl(s.dev, a.name, type, false); s.mode = 'nacl'; s.ctx = { acl };
});
cmd('config', 'no ip access-list <t> <name>', (s, a) => s.dev.acls.delete(a.name));
cmd('nacl', 'permit <x...>', (s, a, io, toks) => nacl(s, io, toks)); cmd('nacl', 'deny <x...>', (s, a, io, toks) => nacl(s, io, toks));
cmd('nacl', 'remark <x...>', (s, a) => addAclEntry(s.ctx.acl, { remark: a.x }));
cmd('nacl', '<seq> <x...>', (s, a, io, toks) => { if (!/^\d+$/.test(a.seq)) { io.print('% Invalid input detected at \'^\' marker.\n'); return; } nacl(s, io, toks.slice(1), +a.seq); });
cmd('nacl', 'no <seq>', (s, a) => { s.ctx.acl.entries = s.ctx.acl.entries.filter(e => String(e.seq) !== a.seq); });
function nacl(s, io, toks, seq) { const e = parseAclEntry(s.ctx.acl.type, toks.map(t => t.toLowerCase() === 'host' ? 'host' : t)); if (e === 'bad') { io.print('% Invalid input detected at \'^\' marker.\n'); return; } addAclEntry(s.ctx.acl, e, seq); }

/* ---- NAT ---- */
cmd('config', 'ip nat pool <name> <start> <end> netmask <mask>', (s, a) => { const d = s.dev; d.nat.pools = (d.nat.pools || []).filter(p => p.name !== a.name); d.nat.pools.push({ name: a.name, start: IP.parse(a.start), end: IP.parse(a.end), mask: IP.parseMask(a.mask) }); });
cmd('config', 'ip nat inside source list <acl> interface <ifc> [<ov>]', (s, a) => { const d = s.dev; d.nat.dyn = d.nat.dyn.filter(r => !(r.acl === a.acl && r.iface)); d.nat.dyn.push({ acl: a.acl, iface: (d.ifaceByName(a.ifc) || { name: a.ifc }).name, overload: !!a.ov }); });
cmd('config', 'ip nat inside source list <acl> pool <pool> [<ov>]', (s, a) => { const d = s.dev; const pl = (d.nat.pools || []).find(p => p.name === a.pool); d.nat.dyn.push({ acl: a.acl, pool: pl, poolName: a.pool, overload: !!a.ov }); });
cmd('config', 'no ip nat inside source list <acl> [<x...>]', (s, a) => { s.dev.nat.dyn = s.dev.nat.dyn.filter(r => r.acl !== a.acl); });
cmd('config', 'ip nat inside source static <x...>', (s, a, io) => {
  const t = a._rest; const d = s.dev; let proto = null, i = 0; if (t[0] === 'tcp' || t[0] === 'udp') { proto = t[0]; i = 1; }
  const lip = IP.parse(t[i]); if (lip === null) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  if (proto) { const lport = +t[i + 1]; const gtxt = t[i + 2]; const gport = +t[i + 3]; const gip = gtxt === 'interface' ? 0 : IP.parse(gtxt); d.nat.statics = d.nat.statics.filter(x => !(x.lip === lip && x.proto === proto && x.lport === lport)); d.nat.statics.push({ proto, lip, lport, gip, gport }); }
  else { const gip = IP.parse(t[i + 1]); d.nat.statics = d.nat.statics.filter(x => x.lip !== lip); d.nat.statics.push({ lip, gip }); }
});
cmd('config', 'no ip nat inside source static <x...>', (s, a) => { const lip = IP.parse(a._rest.find(x => IP.parse(x) !== null)); s.dev.nat.statics = s.dev.nat.statics.filter(x => x.lip !== lip); });
cmd('config', 'ip nat <x...>', () => { });

/* ---- DHCP ---- */
cmd('config', 'ip dhcp pool <name>', (s, a) => { const p = s.dev.dhcpd.addPool({ name: a.name }); s.mode = 'dhcp'; s.ctx = { pool: p }; s.dev.dhcpd.enabled = true; });
cmd('config', 'no ip dhcp pool <name>', (s, a) => { s.dev.dhcpd.pools = s.dev.dhcpd.pools.filter(p => p.name !== a.name); });
cmd('config', 'ip dhcp excluded-address <a> [<b>]', (s, a) => { const x = IP.parse(a.a), y = a.b ? IP.parse(a.b) : x; if (x !== null && y !== null) s.dev.dhcpd.excluded.push([x, y]); });
cmd('config', 'no ip dhcp excluded-address <a> [<b>]', (s, a) => { const x = IP.parse(a.a); s.dev.dhcpd.excluded = s.dev.dhcpd.excluded.filter(r => r[0] !== x); });
cmd('config', 'ip dhcp <x...>', () => { }); cmd('config', 'no ip dhcp <x...>', () => { });
cmd('dhcp', 'network <ip> <mask>', (s, a, io) => { const n = IP.parse(a.ip), m = IP.parseMask(a.mask); if (n === null || m === null) { io.print('% Invalid input detected at \'^\' marker.\n'); return; } s.ctx.pool.net = IP.net(n, m); s.ctx.pool.mask = m; });
cmd('dhcp', 'default-router <ip>', (s, a) => { s.ctx.pool.router = IP.parse(a.ip) || 0; });
cmd('dhcp', 'dns-server <x...>', (s, a) => { s.ctx.pool.dns = a._rest.map(IP.parse).filter(x => x !== null); });
cmd('dhcp', 'domain-name <x>', (s, a) => { s.ctx.pool.domain = a.x; });
cmd('dhcp', 'lease infinite', (s) => { s.ctx.pool.lease = 365 * 86400; });
cmd('dhcp', 'lease <d> [<h>] [<m>]', (s, a) => { s.ctx.pool.lease = (+a.d) * 86400 + (+a.h || 0) * 3600 + (+a.m || 0) * 60; });
cmd('dhcp', 'no <x...>', () => { });

/* ---- RIP ---- */
cmd('config', 'router rip', (s, a, io) => { if (!s.dev.rip) { io.print('% Invalid input detected at \'^\' marker.\n'); return; } s.dev.rip.start(); s.mode = 'rip'; s.ctx = {}; });
cmd('config', 'no router rip', s => { s.dev.rip.stop(); });
cmd('rip', 'version <v>', () => { }); cmd('rip', 'no auto-summary', () => { }); cmd('rip', 'auto-summary', () => { });
cmd('rip', 'network <ip>', (s, a, io) => { const ip = IP.parse(a.ip); if (ip === null) { io.print('% Invalid input detected at \'^\' marker.\n'); return; } const n = IP.net(ip, IP.classMask(ip)); if (!s.dev.rip.networks.includes(n)) s.dev.rip.networks.push(n); s.dev.sim.at(1, () => { s.dev.rip.request(); s.dev.rip.update(); }); });
cmd('rip', 'no network <ip>', (s, a) => { const ip = IP.parse(a.ip); s.dev.rip.networks = s.dev.rip.networks.filter(n => n !== IP.net(ip, IP.classMask(ip))); });
cmd('rip', 'passive-interface <x>', (s, a) => { const i = s.dev.ifaceByName(a.x); s.dev.rip.passive.add(i ? i.name : a.x); });
cmd('rip', 'no passive-interface <x>', (s, a) => { const i = s.dev.ifaceByName(a.x); s.dev.rip.passive.delete(i ? i.name : a.x); });
cmd('rip', 'default-information originate', s => { s.dev.rip.defaultOrig = true; s.dev.rip.triggered(); });
cmd('rip', 'redistribute static [<x...>]', s => { s.dev.rip.redistStatic = true; s.dev.rip.triggered(); });
cmd('rip', 'redistribute <x...>', () => { });

/* ---- lignes (console / vty) ---- */
cmd('config', 'line <t> [<x...>]', (s, a) => { s.mode = 'line'; s.ctx = { type: a.t.toLowerCase() }; });
cmd('line', 'password <x>', (s, a) => { if (s.ctx.type.startsWith('v')) s.dev.vty.password = a.x; else s.dev.conPassword = a.x; });
cmd('line', 'login local', s => { s.dev.vty.login = true; s.dev.vty.local = true; });
cmd('line', 'login', s => { if (s.ctx.type.startsWith('v')) s.dev.vty.login = true; });
cmd('line', 'no login', s => { s.dev.vty.login = false; s.dev.vty.local = false; });
cmd('line', 'transport input <x...>', (s, a) => { s.dev.vty.transport = a.x; });
cmd('line', 'exec-timeout <x...>', () => { }); cmd('line', 'logging <x...>', () => { }); cmd('line', 'privilege <x...>', () => { }); cmd('line', 'no <x...>', () => { }); cmd('line', 'access-class <x...>', () => { });

/* ------------------------------------------------------------- serveur telnet/ssh du routeur */
function attachRemote(dev) {
  const serve = (port, ssh) => dev.tcpListen(port, conn => {
    const st = { buf: '', stage: 0, s: null, tries: 0 };
    const cr = ssh ? NS.tools.sshCrypt(conn, 'server') : null;
    const out = t => { t = t.replace(/\n/g, '\r\n'); if (ssh) conn.send(cr.enc(B.utf8Bytes(t))); else conn.send(t); };
    const aaaList = () => dev.radius && dev.radius.aaa.newModel ? dev.radius.methods('login', dev.vty.loginList || 'default') : null;
    const needUser = () => dev.vty.local || !!aaaList();
    const startShell = () => { st.s = new Session(dev); st.stage = 2; if (dev.banner) out(dev.banner + '\n'); out('\n' + st.s.prompt()); };
    conn.onClose = () => { if (conn.state === 'CLOSE_WAIT') conn.close(); };
    if (!ssh) {
      if (!dev.vty.password && !dev.vty.local && !aaaList()) { out('\n\n% Password required, but none set\n\n'); conn.close(); return; }
      out('\nUser Access Verification\n\n' + (needUser() ? 'Username: ' : 'Password: ')); st.stage = needUser() ? 0.5 : 1;
    } else { conn.send('SSH-2.0-Cisco-1.25\r\n'); st.stage = 'banner'; }
    conn.onData = buf => {
      let txt;
      if (ssh) {
        if (st.stage === 'banner') { if (/^SSH-/.test(B.bytesStr(buf, 0, 4))) { st.stage = 'kex'; conn.send(dev.sim.rng.bytes(320)); } return; }
        if (st.stage === 'kex') { st.stage = needUser() ? 0.5 : 1; out(needUser() ? 'Username: ' : 'Password: '); return; }
        txt = B.bytesStr(cr.dec(buf));
      } else txt = B.bytesStr(buf);
      st.buf += txt.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      let nl; while ((nl = st.buf.indexOf('\n')) >= 0) { const line = st.buf.slice(0, nl); st.buf = st.buf.slice(nl + 1); handle(line); }
    };
    function handle(line) {
      if (st.stage === 0.5) { st.user = line.trim(); st.stage = 1; out('Password: '); return; }
      if (st.stage === 1) {
        const fail = () => { st.tries++; if (st.tries >= 3) { out('\n% Authentication failed\n'); conn.close(); } else { out('\n% Authentication failed\n\nUsername: '); st.stage = 0.5; } };
        if (aaaList()) { st.stage = 'aaa'; dev.radius.aaaLogin(dev.vty.loginList || 'default', st.user, line.trim(), ok => { if (ok) startShell(); else fail(); }); return; }
        const ok = dev.vty.local ? (dev.users || []).some(u => u.name === st.user && u.secret === line.trim()) : line.trim() === dev.vty.password;
        if (ok) startShell(); else { st.tries++; if (st.tries >= 3) { out('\n% Bad passwords\n'); conn.close(); } else { out('\n% ' + (dev.vty.local ? 'Login invalid\n\nUsername: ' : 'Access denied\n\nPassword: ')); st.stage = dev.vty.local ? 0.5 : 1; } }
        return;
      }
      if (st.stage === 2) {
        const s = st.s; let buf = '';
        s.exec(line, { print: t => { buf += t; }, done: () => { if (s.closed) { if (buf) out(buf); conn.close(); return; } out(buf + s.prompt()); } });
      }
    }
  });
  serve(23, false); serve(22, true);
}

/* ------------------------------------------------------------- configuration <-> texte, réinitialisation */
function cliText(save) { return genConfig(this, save !== false).join('\n'); }
function cliRestore(text, silent) {
  const d = this; d.restoring = true; try { return cliRestore2.call(this, text, silent); } finally { d.restoring = false; }
}
function cliRestore2(text, silent) {
  const d = this; const s = new Session(d); s.mode = 'config';
  if (d instanceof NS.Router) d.ifaceList().forEach(i => { i.adminUp = true; if (i.port) i.port.adminUp = true; });
  const io = { print() { }, done() { } };
  text.split('\n').forEach(l => { if (l.trim() && l.trim() !== '!') { if (/^[^ ]/.test(l)) { if (s.mode !== 'config') { s.mode = 'config'; s.ctx = null; } } s.exec(l.replace(/^\s+/, ''), io); } });
  if (d instanceof NS.Router) d.ifaceList().forEach(i => { if (i.port && !i.sub) d.sim.portChanged(i.port); });
  d.ports.forEach(p => d.sim.portChanged(p));
}
function cliReset() {
  const d = this; if (NS.Qos) NS.Qos.reset(d); if (d.radius) d.radius.reset(); if (d.dot1x) d.dot1x.reset(); if (d.vpn) d.vpn.reset(); if (d.mgmt) d.mgmt.reset(); if (d.ip6) d.ip6.reset(); d.statics = []; d.dynRoutes = []; d.acls.clear(); d.nat = { dyn: [], statics: [], table: [] }; d.enableSecret = ''; d.banner = ''; d.vty = { password: '', login: false }; d.users = []; d.hosts = {}; d.dnsServers = []; d.noDomainLookup = false; d.domain = '';
  if (d.dhcpd) { d.dhcpd.pools = []; d.dhcpd.excluded = []; d.dhcpd.leases.clear(); }
  if (d.rip && d.rip.enabled) d.rip.stop();
  if (d instanceof NS.Router) {
    Array.from(d.ifaces.keys()).forEach(k => { const i = d.ifaces.get(k); if (i.sub || i.loop) d.ifaces.delete(k); else { d.enableDhcp(i, false); Object.assign(i, { ip: 0, mask: 0, adminUp: false, aclIn: null, aclOut: null, nat: null, helper: [], desc: '' }); i.port.adminUp = false; } });
  } else if (d instanceof NS.Switch) {
    Array.from(d.ifaces.keys()).forEach(k => { const i = d.ifaces.get(k); if (i.svi !== null || i.port) d.ifaces.delete(k); });
    d.vlans = new Map([[1, { name: 'default' }]]); d.forwarding = false; d.stp.priority = 32768; if (d.managed && !d.stp.enabled) d.stp.enable();
    d.ports.forEach(p => { Object.assign(p, { mode: 'access', vlan: 1, voiceVlan: 0, native: 1, allowed: null, portfast: false, routed: null, desc: '', adminUp: true, errdis: false }); p.sec = { enabled: false, max: 1, violation: 'shutdown', macs: new Set(), sticky: false }; });
    d.macTable.clear();
  }
}
NS.IosSession = Session; NS.iosCmds = CMDS; NS.iosCmd = cmd; NS.iosUtil = { pad, padL, cm, shortName, vlanListStr, parseVlanList, expandRange, makeItem, needSw, statusOf, fmtDur, aclText: entryText };
[NS.Router, NS.Switch].forEach(C => { if (!C) return; C.prototype.cliText = cliText; C.prototype.cliRestore = cliRestore; C.prototype.cliReset = cliReset; C.prototype.newSession = function () { return new Session(this); }; C.prototype.restore = function (b) { if (b.cli) this.cliRestore(b.cli); if (b.startup) this.startup = b.startup; }; });
NS.attachRemote = attachRemote;
NS.genConfig = genConfig;
})(typeof window !== 'undefined' ? window : globalThis);
