/* stp.js — Spanning Tree par VLAN : PVST+ (802.1D) et Rapid-PVST+ (802.1w), root guard, BPDU guard, propagation de changement de topologie */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { MAC, Codec } = NS;

function cmpVec(a, b) { for (let i = 0; i < a.length; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; } return 0; }
const PVST_MAC = '01:00:0c:cc:cc:cd', STP_MAC = '01:80:c2:00:00:00';

class Stp {
  constructor(sw) {
    this.sw = sw; this.enabled = false; this.dead = false; this.mode = 'pvst'; this.defPri = 32768; this.vpri = new Map(); this.off = new Set();
    this.insts = new Map(); this.gPortfast = false; this.gBpduGuard = false; this.helloTimer = null;
  }
  get sim() { return this.sw.sim; }
  get myMac() { return this.sw.baseMac; }
  get rapid() { return this.mode === 'rapid-pvst'; }
  get fwd() { return this.sim.opts.stpFast ? 2000 : 15000; }
  get priority() { return this.pri(1); }
  set priority(p) { this.defPri = p; this.vpri.clear(); }
  pri(v) { return this.vpri.has(v) ? this.vpri.get(v) : this.defPri; }
  setPri(v, p) { this.vpri.set(v, p); this.off.delete(v); if (this.enabled) { this.syncVlans(); this.recompute(); } }
  myPri(v) { return this.pri(v) + v; }
  /* --- accès aux ports L2 (ports physiques hors agrégat + ports logiques Po) --- */
  l2() { return this.sw.l2ports().filter(p => !p.routed); }
  ps(p, v) { return p.stp && p.stp.v ? p.stp.v.get(v) : null; }
  stateFor(p, v) { if (!this.enabled || this.off.has(v)) return 'forwarding'; const s = this.ps(p, v); return s ? s.state : 'forwarding'; }
  cost(p) {
    if (p.stpCost) return p.stpCost;
    const sp = p.isChannel ? p.speedSum() : p.speed;
    return sp >= 10000 ? 2 : sp >= 4000 ? 2 : sp >= 2000 ? 3 : sp >= 1000 ? 4 : sp >= 100 ? 19 : 100;
  }
  portId(p) { return (((p.stpPri === undefined ? 128 : p.stpPri) & 0xf0) << 8) | ((p.idx + 1) & 0xfff); }
  peerStp(p) { const pe = p.peer; return !!(pe && pe.dev instanceof NS.Switch && pe.dev.stp.enabled); }
  p2p(p) { const pe = p.peer; return !!(pe && pe.dev instanceof NS.Switch); }
  isEdge(p) {
    if (p.stp && p.stp.bpduSeen) return false;
    if (p.portfast || (this.gPortfast && p.mode === 'access')) return true;
    if (!this.sim.opts.stpFast) return false;
    return !this.peerStp(p);
  }
  sends(p) { return this.peerStp(p) || !this.sim.opts.stpFast; }
  guardOn(p) { return p.bpduGuard === true || (p.bpduGuard === undefined && this.gBpduGuard && (p.portfast || this.gPortfast)); }
  vlansOf(p) { const r = []; this.insts.forEach((i, v) => { if (this.sw.carries(p, v)) r.push(v); }); return r; }

  /* --- activation --- */
  enable() {
    if (this.enabled) return; this.enabled = true; this.syncVlans(); this.recompute();
    if (!this.helloTimer) this.hello();
  }
  disable() {
    this.enabled = false;
    this.insts.forEach(i => this.clearInst(i)); this.insts.clear();
    this.sw.allPorts().forEach(p => { if (p.stp) { p.stp.state = 'forwarding'; p.stp.role = 'disabled'; p.stp.v = new Map(); } });
    this.sw.macTable.clear();
  }
  clearInst(i) { i.ports && i.ports.forEach(p => { const s = this.ps(p, i.v); if (s && s.timer) this.sim.cancel(s.timer); if (p.stp && p.stp.v) p.stp.v.delete(i.v); }); }
  setMode(m) {
    if (m === this.mode) return; this.mode = m;
    if (this.enabled) { this.insts.forEach(i => this.clearInst(i)); this.insts.clear(); this.sw.allPorts().forEach(p => { p.stp.bpduSeen = false; p.stp.v = new Map(); }); this.syncVlans(); this.recompute(); }
  }
  disableVlan(v) { this.off.add(v); const i = this.insts.get(v); if (i) { this.clearInst(i); this.insts.delete(v); } this.mirrorAll(); this.sw.macTable.clear(); }
  enableVlan(v) { this.off.delete(v); if (this.enabled) { this.syncVlans(); this.recompute(); } }
  syncVlans() {
    if (!this.enabled) return;
    this.insts.forEach((i, v) => { if (!this.sw.vlans.has(v)) { this.clearInst(i); this.insts.delete(v); } });
    this.sw.vlans.forEach((_, v) => { if (!this.off.has(v) && !this.insts.has(v)) { this.insts.set(v, { v, rootPri: this.myPri(v), rootMac: this.myMac, rootCost: 0, rootPort: null, ports: [], tcUntil: 0 }); } });
  }
  get isRoot() { const i = this.insts.get(1) || this.insts.values().next().value; return !!i && i.rootMac === this.myMac; }
  get rootPort() { const i = this.insts.get(1) || this.insts.values().next().value; return i ? i.rootPort : null; }
  get rootMac() { const i = this.insts.get(1) || this.insts.values().next().value; return i ? i.rootMac : this.myMac; }
  get rootCost() { const i = this.insts.get(1) || this.insts.values().next().value; return i ? i.rootCost : 0; }
  get rootPri() { const i = this.insts.get(1) || this.insts.values().next().value; return i ? i.rootPri : this.myPri(1); }

  /* --- émission --- */
  hello() {
    if (this.dead) return;
    this.helloTimer = true;
    if (this.enabled) {
      this.syncVlans();
      let ch = false; this.insts.forEach(i => { if (this.expire(i)) ch = true; });
      if (ch) this.recompute();
      this.insts.forEach(i => this.sendInst(i));
    }
    this.sim.at(2000, () => this.hello());
  }
  sendInst(i) { i.ports.forEach(p => this.sendPort(i, p)); }
  sendPort(i, p, opt) {
    opt = opt || {}; const s = this.ps(p, i.v); if (!s || !p.up || p.routed) return;
    const tc = this.sim.now < i.tcUntil;
    if (!(s.role === 'designated' || (s.role === 'alternate' && opt.agreement) || (s.role === 'root' && (opt.agreement || (this.rapid && tc))))) return;
    if (!this.sends(p) && !opt.force) return;
    let rb = i.rootPort && this.ps(i.rootPort, i.v) && this.ps(i.rootPort, i.v).best;
    const root = i.rootPort === null;
    const b = { rootPri: i.rootPri, rootMac: i.rootMac, cost: i.rootCost, brPri: this.myPri(i.v), brMac: this.myMac, portId: this.portId(p), age: root ? 0 : ((rb ? rb.age : 0) + 1), maxAge: 20, fwd: this.fwd / 1000, rstp: this.rapid };
    if (this.rapid) {
      b.flags = Codec.rstpFlags({ tc, proposal: !!opt.proposal || (s.role === 'designated' && s.proposing && s.state !== 'forwarding'), role: s.role === 'root' ? 2 : s.role === 'designated' ? 3 : 1, learning: s.state === 'learning' || s.state === 'forwarding', forwarding: s.state === 'forwarding', agreement: !!opt.agreement });
    } else b.flags = tc ? 1 : 0;
    const pv = i.v !== 1 || (p.mode === 'access' && p.vlan !== 1);
    let f;
    if (!pv) f = Codec.frame8023({ dst: STP_MAC, src: p.mac, payload: Codec.bpdu(b) });
    else f = Codec.frameSnap({ dst: PVST_MAC, src: p.mac, vlan: p.mode === 'trunk' && i.v !== p.native ? i.v : 0, oui: [0, 0, 12], pid: 0x010b, payload: Codec.pvstBpdu(b, i.v) });
    this.sw.sendL(p, f);
  }

  /* --- réception --- */
  input(port, pk) {
    const b = pk.stp; if (!b || !this.enabled) return;
    if (b.proto !== 0) return;
    if (!port.stp) return;
    if (this.guardOn(port) || port.portfast && this.gBpduGuard) {
      this.sw.log('%SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port ' + port.name + ' with BPDU Guard enabled. Disabling port.', 'warn');
      port.errdis = true; port.errdisReason = 'bpduguard'; this.sim.portChanged(port); if (port.peer) this.sim.portChanged(port.peer); return;
    }
    port.stp.bpduSeen = true;
    let v = b.pvst ? b.vlan : (port.mode === 'access' ? port.vlan : port.native);
    if (!b.pvst && pk.eth.vlan) return;
    const i = this.insts.get(v); if (!i || !this.sw.carries(port, v)) return;
    let s = this.ps(port, v); if (!s && port.up) { this.recompute(v); s = this.ps(port, v); } if (!s) return;
    if (b.age >= b.maxAge) return;
    const cur = s.best; const rec = Object.assign({ t: this.sim.now }, b);
    if (b.rstp === undefined) rec.rstp = false;
    if (!cur || cmpVec(this.vec(rec), this.vec(cur)) <= 0 || (rec.brMac === cur.brMac && rec.portId === cur.portId)) s.best = rec;
    else return;
    const tcRx = !!(b.flags & 1);
    this.recompute(v);
    const s2 = this.ps(port, v);
    if (s2) {
      if (this.rapid && b.rstp) {
        if (s2.role === 'root' && b.proposal) { this.syncOthers(i, port); this.setForwarding(i, port, s2); this.sendPort(i, port, { agreement: true, force: true }); }
        else if (s2.role === 'alternate' && b.proposal) this.sendPort(i, port, { agreement: true, force: true });
        else if (s2.role === 'designated' && b.agreement && b.role !== 3 && s2.state !== 'forwarding' && b.rootMac === i.rootMac && b.rootPri === i.rootPri) { s2.proposing = false; this.setForwarding(i, port, s2); this.sendPort(i, port, { force: true }); }
      }
      if (s2.role === 'designated' && cmpVec(this.vec(rec), this.dvec(i, port)) > 0 && !b.agreement) this.sendPort(i, port, { force: true });
      if (s2.role === 'root' && this.rapid && !b.rstp && s2.state !== 'forwarding') { /* pair héritée : minuteurs classiques */ }
    }
    if (tcRx && this.sim.now >= i.tcUntil) { this.sw.macTable.clear(); i.tcUntil = this.sim.now + 4000; this.sendInst(i); }
  }
  vec(b) { return [b.rootPri, b.rootMac, b.cost, b.brPri, b.brMac, b.portId]; }
  dvec(i, p) { return [i.rootPri, i.rootMac, i.rootCost, this.myPri(i.v), this.myMac, this.portId(p)]; }
  portChanged(port) {
    if (!this.enabled) return;
    if (!port.up) { port.stp.bpduSeen = false; if (port.stp.v) port.stp.v.forEach(s => { s.best = null; s.proposing = false; if (s.timer) { this.sim.cancel(s.timer); s.timer = null; } }); }
    this.recompute();
  }
  expire(i) {
    let ch = false; const age = this.rapid ? 6000 : 20000;
    i.ports.forEach(p => { const s = this.ps(p, i.v); const b = s && s.best; if (b && this.sim.now - b.t > Math.min(age, b.maxAge * 1000)) { s.best = null; ch = true; } });
    return ch;
  }
  syncOthers(i, except) {
    i.ports.forEach(q => {
      if (q === except) return; const s = this.ps(q, i.v); if (!s || s.role !== 'designated' || this.isEdge(q) || !this.p2p(q)) return;
      if (s.state === 'forwarding' || !s.proposing) {
        if (s.timer) { this.sim.cancel(s.timer); s.timer = null; }
        s.state = 'blocking'; s.proposing = true; this.sendPort(i, q, { proposal: true });
      }
    });
    this.mirrorAll();
  }
  setForwarding(i, p, s) {
    if (s.state === 'forwarding') return;
    if (s.timer) { this.sim.cancel(s.timer); s.timer = null; }
    s.state = 'forwarding'; s.proposing = false; i.tcUntil = this.sim.now + 4000; this.sw.macTable.clear(); this.mirror(p); this.sim.emit('port', p);
    this.sendInst(i);
  }

  /* --- calcul des rôles pour une instance (ou toutes) --- */
  recompute(only) {
    if (!this.enabled) return;
    this.syncVlans();
    const all = this.l2();
    this.insts.forEach((i, v) => {
      if (only !== undefined && only !== v) return;
      this.expire(i);
      const old = new Set(i.ports);
      i.ports = all.filter(p => p.up && this.sw.carries(p, v));
      i.ports.forEach(p => { p.stp.v = p.stp.v || new Map(); if (!p.stp.v.has(v)) p.stp.v.set(v, { state: 'blocking', role: 'disabled', best: null, timer: null, proposing: false }); });
      all.forEach(p => { if (!i.ports.includes(p) && p.stp.v && p.stp.v.has(v)) { const s = p.stp.v.get(v); if (s.timer) this.sim.cancel(s.timer); p.stp.v.delete(v); } });
      let best = null, bestP = null; const me = [this.myPri(v), this.myMac];
      i.ports.forEach(p => {
        const s = this.ps(p, v); const b = s.best; if (!b || p.rootGuard) return;
        const vc = [b.rootPri, b.rootMac, b.cost + this.cost(p), b.brPri, b.brMac, b.portId, p.idx];
        if (!best || cmpVec(vc, best) < 0) { best = vc; bestP = p; }
      });
      const prevRoot = i.rootPort, prevInfo = i.rootPri + '/' + i.rootMac + '/' + i.rootCost;
      if (best && cmpVec([best[0], best[1]], me) < 0) { i.rootPri = best[0]; i.rootMac = best[1]; i.rootCost = best[2]; i.rootPort = bestP; }
      else { i.rootPri = me[0]; i.rootMac = me[1]; i.rootCost = 0; i.rootPort = null; }
      let changed = false; const rootChanged = prevRoot !== i.rootPort;
      i.ports.forEach(p => {
        const s = this.ps(p, v); let role, inc = false;
        if (p === i.rootPort) role = 'root';
        else {
          const D = this.dvec(i, p);
          if (s.best && cmpVec(this.vec(s.best), D) < 0) { if (p.rootGuard && s.best.rootPri !== undefined && cmpVec([s.best.rootPri, s.best.rootMac], [i.rootPri, i.rootMac]) < 0) { role = 'designated'; inc = true; } else role = 'alternate'; }
          else role = 'designated';
        }
        if (inc !== !!s.rootInc) { s.rootInc = inc; if (inc) this.sw.log('%SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port ' + p.name + ' on VLAN' + String(v).padStart(4, '0') + '.', 'warn'); else this.sw.log('%SPANTREE-2-ROOTGUARD_UNBLOCK: Root guard unblocking port ' + p.name + ' on VLAN' + String(v).padStart(4, '0') + '.'); changed = true; if (!inc && role === 'designated') { s.role = null; } }
        const needEdge = role === 'designated' && s.state !== 'forwarding' && this.isEdge(p);
        if (role !== s.role || (inc && s.state !== 'blocking') || needEdge) { s.role = role; changed = true; this.applyRole(i, p, s, inc); }
      });
      if (changed || rootChanged) { this.sw.macTable.clear(); i.tcUntil = this.sim.now + 4000; }
      if (prevInfo !== i.rootPri + '/' + i.rootMac + '/' + i.rootCost) this.sendInst(i);
    });
    this.mirrorAll();
  }
  applyRole(i, p, s, inc) {
    if (s.timer) { this.sim.cancel(s.timer); s.timer = null; }
    if (s.role === 'disabled') { s.state = 'disabled'; return; }
    if (s.role === 'alternate' || inc) { s.state = 'blocking'; s.proposing = false; return; }
    if (this.isEdge(p) && s.role === 'designated') { s.state = 'forwarding'; s.proposing = false; return; }
    if (s.state === 'forwarding') return;
    const v = i.v;
    if (this.rapid && s.role === 'root') { this.syncOthers(i, p); s.state = 'forwarding'; s.proposing = false; this.sw.macTable.clear(); this.mirror(p); this.sim.emit('port', p); return; }
    const fin = () => { s.state = 'forwarding'; s.timer = null; s.proposing = false; this.sw.macTable.clear(); this.mirror(p); this.sim.emit('port', p); this.sendPort(i, p, { force: true }); };
    const lrn = () => { s.state = 'learning'; s.timer = this.sim.at(this.fwd, fin); this.mirror(p); this.sim.emit('port', p); };
    if (s.state === 'learning') { s.timer = this.sim.at(this.fwd, fin); return; }
    if (this.rapid && s.role === 'designated' && this.p2p(p)) { s.state = 'blocking'; s.proposing = true; s.timer = this.sim.at(this.fwd, lrn); this.sendPort(i, p, { proposal: true }); return; }
    s.state = this.rapid ? 'blocking' : 'listening'; s.proposing = false;
    s.timer = this.sim.at(this.fwd, lrn);
  }
  /* résumé par port (pour l'affichage) : forwarding si au moins un VLAN transmet */
  mirror(p) {
    if (!p.stp) return; const vs = p.stp.v; if (!vs || !vs.size) { if (!this.enabled) return; p.stp.state = p.up ? 'blocking' : 'disabled'; p.stp.role = 'disabled'; return; }
    const rep = vs.get(p.mode === 'access' ? p.vlan : p.native) || vs.values().next().value;
    let st = rep.state, any = false; vs.forEach(x => { if (x.state === 'forwarding') any = true; });
    if (any) st = 'forwarding';
    p.stp.state = st; p.stp.role = rep.role;
  }
  mirrorAll() {
    this.sw.allPorts().forEach(p => { if (p.lag && p.lag.bundled) { const lp = p.lag.ch.lp; this.mirror(lp); p.stp.state = lp.stp.state; p.stp.role = lp.stp.role; } else this.mirror(p); });
  }
  /* vue synthétique pour les commandes show */
  info(v) {
    const i = this.insts.get(v); if (!i) return null;
    return { v, rootPri: i.rootPri, rootMac: i.rootMac, rootCost: i.rootCost, rootPort: i.rootPort, isRoot: i.rootPort === null, brPri: this.myPri(v), ports: i.ports.map(p => Object.assign({ port: p }, this.ps(p, v))) };
  }
}

NS.Stp = Stp;
})(typeof window !== 'undefined' ? window : globalThis);
