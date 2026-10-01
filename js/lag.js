/* lag.js — EtherChannel : LACP (802.3ad), PAgP (Cisco) et mode « on », ports logiques Port-channel */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { MAC, Codec } = NS;
const LACP_MAC = '01:80:c2:00:00:02', PAGP_MAC = '01:00:0c:cc:cc:cc';

/* Port logique : se comporte comme un port de commutateur (mode, vlan, trunk, STP…) */
class ChanPort {
  constructor(ch) {
    this.ch = ch; this.dev = ch.sw; this.isChannel = true; this.id = ch.id;
    this.name = 'Port-channel' + ch.id; this.short = 'Po' + ch.id; this.idx = 55 + ch.id; this.media = 'cu';
    this.mode = 'access'; this.vlan = 1; this.native = 1; this.allowed = null; this.portfast = false; this.routed = null; this.desc = '';
    this.adminUp = true; this.errdis = false; this.sec = { enabled: false, max: 1, violation: 'shutdown', macs: new Set(), sticky: false };
    this.stp = { state: 'forwarding', role: 'disabled', best: null, timer: null, v: new Map() };
  }
  get bundled() { return this.ch.bundled(); }
  get up() { return this.adminUp && this.bundled.length > 0; }
  get peer() { const b = this.bundled[0] || this.ch.members[0]; return b ? b.peer : null; }
  get mac() { const m = this.ch.members[0]; return m ? m.mac : this.dev.baseMac; }
  get speed() { return this.bundled.length ? this.bundled[0].speed : 1000; }
  speedSum() { return this.bundled.reduce((a, m) => a + m.speed, 0) || 1000; }
}

class Chan {
  constructor(sw, id) { this.sw = sw; this.id = id; this.members = []; this.lp = new ChanPort(this); }
  bundled() { return this.members.filter(m => m.lag && m.lag.bundled && m.up); }
  get proto() { const m = this.members[0]; if (!m) return null; const x = m.lag.mode; return x === 'on' ? 'on' : (x === 'active' || x === 'passive') ? 'lacp' : 'pagp'; }
  /* choix du lien selon la méthode de répartition (Cisco : XOR des bits de poids faible) */
  pick(f) {
    const b = this.bundled().sort((x, y) => x.idx - y.idx); if (!b.length) return null; if (b.length === 1) return b[0];
    const m = this.sw.lbMethod || 'src-mac'; const tagged = f[12] === 0x81 && f[13] === 0; const io = tagged ? 18 : 14; const isIp = (tagged ? (f[16] === 8 && f[17] === 0) : (f[12] === 8 && f[13] === 0)) && f.length >= io + 20;
    let h = 0;
    const smac = f[11], dmac = f[5], sip = isIp ? f[io + 15] : smac, dip = isIp ? f[io + 19] : dmac;
    if (m === 'src-mac') h = smac; else if (m === 'dst-mac') h = dmac; else if (m === 'src-dst-mac') h = smac ^ dmac;
    else if (m === 'src-ip') h = sip; else if (m === 'dst-ip') h = dip; else h = sip ^ dip;
    return b[h % b.length];
  }
}

function install(Switch) {
  const P = Switch.prototype;
  P.initLag = function () { this.chans = new Map(); this.lbMethod = 'src-mac'; this._lagTimer = false; this.lacpPri = 32768; };
  P.allPorts = function () { const r = this.ports.slice(); this.chans.forEach(c => r.push(c.lp)); return r; };
  P.l2ports = function () {
    const r = this.ports.filter(p => !(p.lag && p.lag.bundled));
    this.chans.forEach(c => { if (c.bundled().length || c.members.length === 0) { if (c.bundled().length) r.push(c.lp); } });
    return r;
  };
  P.chanOf = function (id, create) { let c = this.chans.get(id); if (!c && create) { c = new Chan(this, id); this.chans.set(id, c); } return c || null; };
  P.findChanPort = function (str) { const m = /^(?:po|port-?channel)(\d+)$/i.exec(String(str).replace(/\s+/g, '')); if (!m) return null; const c = this.chans.get(+m[1]); return c ? c.lp : null; };
  /* channel-group N mode X (sur un port physique) */
  P.addToChan = function (port, id, mode) {
    this.removeFromChan(port);
    const first = !this.chans.has(id); const c = this.chanOf(id, true);
    if (first) { const lp = c.lp; lp.mode = port.mode; lp.vlan = port.vlan; lp.native = port.native; lp.allowed = port.allowed ? new Set(port.allowed) : null; lp.portfast = port.portfast; }
    port.lag = { id, mode, partner: null, lastRx: 0, lastTx: -1e9, bundled: mode === 'on', ch: c };
    c.members.push(port); c.members.sort((a, b) => a.idx - b.idx);
    this.syncChans(); this.lagStart(); this.chanChanged(c);
    if (mode !== 'on') this.lagSend(port);
  };
  P.removeFromChan = function (port) {
    if (!port.lag) return; const c = port.lag.ch; c.members = c.members.filter(m => m !== port); port.lag = null;
    if (!c.members.length) { this.chans.delete(c.id); c.lp.stp.v.forEach(s => s.timer && this.sim.cancel(s.timer)); for (const [k, e] of this.macTable) if (e.port === c.lp) this.macTable.delete(k); }
    this.chanChanged(c);
  };
  /* propage la configuration du port logique vers les membres (ils l'utilisent tant qu'ils ne sont pas agrégés) */
  P.syncChans = function () {
    this.chans.forEach(c => c.members.forEach(m => { const l = c.lp; m.mode = l.mode; m.vlan = l.vlan; m.native = l.native; m.allowed = l.allowed ? new Set(l.allowed) : null; m.portfast = l.portfast; }));
  };
  P.chanChanged = function (c) {
    c && c.members.forEach(m => { if (m.stp && m.stp.v) { m.stp.v.forEach(s => s.timer && this.sim.cancel(s.timer)); m.stp.v = new Map(); } });
    if (c) for (const [k, e] of this.macTable) if (e.port === c.lp || (c.members.includes(e.port))) this.macTable.delete(k);
    if (this.stp.enabled) this.stp.recompute();
    if (c) this.sim.emit('port', c.lp);
  };
  P.sendL = function (p, f) {
    if (p.isChannel) { const m = p.ch.pick(f); if (m) this.send(m, f); return; }
    this.send(p, f);
  };
  /* ---- protocole ---- */
  P.lagStart = function () { if (this._lagTimer) return; this._lagTimer = true; const tick = () => { if (this.dead || !this.chans.size) { this._lagTimer = false; return; } this.lagTick(); this.sim.at(1000, tick); }; this.sim.at(1000, tick); };
  P.lagFast = function (m) { return !!(m.lacpFast); };
  P.lagInterval = function (m) { return (m.lacpFast ? 1 : 30) * 1000; };
  P.lagTick = function () {
    const now = this.sim.now; const touched = new Set();
    this.chans.forEach(c => c.members.forEach(m => {
      const l = m.lag; if (!l || l.mode === 'on') return;
      if (!m.up) { if (l.partner || l.bundled) { l.partner = null; l.bundled = false; touched.add(c); } return; }
      if (now - l.lastTx >= this.lagInterval(m)) this.lagSend(m);
      if (l.partner && now - l.lastRx > 3 * (m.lacpFast ? 1000 : 30000)) { l.partner = null; l.bundled = false; touched.add(c); }
    }));
    touched.forEach(c => { this.lagEval(c); });
  };
  P.lagSend = function (m) {
    const l = m.lag; if (!l || l.mode === 'on' || !m.up || !this.managed) return;
    if ((l.mode === 'passive' || l.mode === 'auto') && !l.partner) return; l.lastTx = this.sim.now;
    if (l.mode === 'active' || l.mode === 'passive') {
      const st = (l.mode === 'active' ? 1 : 0) | (m.lacpFast ? 2 : 0) | 4 | (l.bundled ? 8 | 16 | 32 : 0) | (l.partner ? 0 : 64);
      const actor = { sysPri: this.lacpPri, sysMac: this.baseMac, key: l.id, portPri: m.lacpPri || 32768, port: m.idx + 1, state: st };
      const pt = l.partner ? { sysPri: l.partner.sysPri, sysMac: l.partner.sysMac, key: l.partner.key, portPri: l.partner.portPri, port: l.partner.port, state: l.partner.state } : null;
      this.send(m, Codec.lacpFrame(m.mac, { actor, partner: pt }));
    } else {
      const p = l.partner;
      const body = Codec.pagp({ flags: (l.mode === 'auto' ? 2 : 0) | (m.lacpFast ? 0 : 1), devId: this.baseMac, group: l.id, ifIndex: m.idx + 1, pDevId: p ? p.devId : null, pGroup: p ? p.group : 0, pIf: p ? p.ifIndex : 0, hello: m.lacpFast ? 1 : 30 });
      this.send(m, Codec.frameSnap({ dst: PAGP_MAC, src: m.mac, oui: [0, 0, 12], pid: 0x0104, payload: body }));
    }
  };
  P.lagInput = function (m, pk) {
    const l = m.lag; if (!l || l.mode === 'on') return;
    if (pk.lacp && (l.mode === 'active' || l.mode === 'passive')) {
      const a = pk.lacp.actor, pt = pk.lacp.partner; const first = !l.partner; l.partner = a; l.lastRx = this.sim.now;
      const mine = pt.sysMac === this.baseMac && pt.key === l.id && pt.port === m.idx + 1;
      l.partnerSees = mine;
      if (first || !mine) this.lagSend(m);
      this.lagEval(l.ch, m);
    } else if (pk.pagp && (l.mode === 'desirable' || l.mode === 'auto')) {
      const a = pk.pagp; const first = !l.partner;
      if (l.mode === 'auto' && (a.flags & 2)) return;
      l.partner = { devId: a.devId, group: a.group, ifIndex: a.ifIndex, sysMac: a.devId, key: a.group }; l.lastRx = this.sim.now;
      l.partnerSees = a.pDevId === this.baseMac;
      if (first || !l.partnerSees) this.lagSend(m);
      this.lagEval(l.ch, m);
    }
  };
  /* décide des membres agrégés : ceux dont le partenaire est identique et qui « nous voient » */
  P.lagEval = function (c) {
    let changed = false; let ref = null;
    c.members.slice().sort((a, b) => a.idx - b.idx).forEach(m => {
      const l = m.lag; if (l.mode === 'on') { if (!l.bundled) { l.bundled = true; changed = true; } return; }
      let ok = !!(l.partner && l.partnerSees && m.up);
      if (ok) { const id = l.partner.sysMac + '/' + l.partner.key; if (ref === null) ref = id; else if (ref !== id) ok = false; }
      if (ok !== l.bundled) { l.bundled = ok; changed = true; if (ok) this.lagSend(m); }
    });
    if (changed) { this.log('%EC-5-BUNDLE: Interface ' + c.members.filter(m => m.lag.bundled).map(m => m.short).join(',') + ' bundled in Port-channel' + c.id); this.chanChanged(c); }
  };
  P.lagMemberChanged = function (port) {
    const l = port.lag; if (!l) return; const c = l.ch;
    if (!port.up) { if (l.mode !== 'on') { l.partner = null; l.partnerSees = false; } l.bundled = l.mode === 'on' ? false : false; this.chanChanged(c); }
    else { if (l.mode === 'on') l.bundled = true; else { l.lastTx = -1e9; this.lagSend(port); } this.chanChanged(c); }
  };
}

NS.installLag = install; NS.ChanPort = ChanPort; NS.LACP_MAC = LACP_MAC; NS.PAGP_MAC = PAGP_MAC;
})(typeof window !== 'undefined' ? window : globalThis);
