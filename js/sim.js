/* sim.js — simulateur à événements discrets, ports, liens, captures */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { Emitter, Rng } = NS;

class Heap {
  constructor() { this.a = []; }
  get size() { return this.a.length; }
  less(x, y) { return x.t < y.t || (x.t === y.t && x.n < y.n); }
  push(e) { const a = this.a; a.push(e); let i = a.length - 1; while (i > 0) { const p = (i - 1) >> 1; if (this.less(a[i], a[p])) { [a[i], a[p]] = [a[p], a[i]]; i = p; } else break; } }
  peek() { return this.a[0]; }
  pop() {
    const a = this.a; const top = a[0]; const last = a.pop();
    if (a.length) { a[0] = last; let i = 0; for (;;) { let l = 2 * i + 1, r = l + 1, m = i; if (l < a.length && this.less(a[l], a[m])) m = l; if (r < a.length && this.less(a[r], a[m])) m = r; if (m === i) break; [a[i], a[m]] = [a[m], a[i]]; i = m; } }
    return top;
  }
  clear() { this.a.length = 0; }
}

class Port {
  constructor(dev, name, o) {
    o = o || {};
    this.dev = dev; this.name = name; this.short = o.short || name; this.speed = o.speed || 1000; this.media = o.media || 'cu';
    this.mdi = o.mdi || dev.mdi || 'MDI'; this.mac = o.mac || NS.MAC.make(dev.oui || NS.OUI.generic);
    this.kind = o.kind || 'eth'; this.link = null; this.adminUp = true; this.idx = o.idx || 0; this.label = o.label || '';
  }
  get up() {
    const l = this.link; if (!l || !l.ok || !this.adminUp || this.errdis) return false;
    const o = l.other(this);
    return o.adminUp && this.dev.powered !== false && o.dev.powered !== false;
  }
  get peer() { return this.link ? this.link.other(this) : null; }
}

class Link {
  constructor(id, a, b, type) {
    this.id = id; this.a = a; this.b = b; this.type = type; this.ok = true;
    this.speed = Math.min(a.speed, b.speed); this.delay = 0.05;
  }
  other(p) { return p === this.a ? this.b : this.a; }
}

const T0 = Date.UTC(2026, 8, 30, 8, 0, 0); // origine des horodatages pcap

class Sim extends Emitter {
  constructor(opts) {
    super();
    this.now = 0; this.heap = new Heap(); this.n = 0;
    this.devices = new Map(); this.links = []; this.captures = []; this.capMax = 60000; this.capNo = 0;
    this.opts = Object.assign({ strictCables: false, stpFast: true, capture: true }, opts || {});
    this.rng = new Rng(20260930);
    this.paused = false; this.halted = null; this._id = 0; this._lid = 0;
    this.stats = { frames: 0 };
  }
  uid(prefix) { return prefix + (++this._id); }
  /* ---- planification ---- */
  at(delay, fn, kind) { const e = { t: this.now + Math.max(0, delay), n: ++this.n, fn, kind: kind || 't', dead: false }; this.heap.push(e); return e; }
  cancel(e) { if (e) e.dead = true; }
  _next() { let e; while ((e = this.heap.peek()) && e.dead) this.heap.pop(); return e; }
  runNext() { const e = this._next(); if (!e) return false; this.heap.pop(); if (e.t > this.now) this.now = e.t; e.fn(); return e; }
  runFor(ms) { const end = this.now + ms; let e; while ((e = this._next()) && e.t <= end) { this.runNext(); if (this.halted) break; } if (this.now < end) this.now = end; }
  runUntil(pred, maxMs) { const end = this.now + (maxMs || 10000); let e; while (!pred() && (e = this._next()) && e.t <= end) { this.runNext(); if (this.halted) break; } return pred(); }
  /* Avancer l'horloge en temps réel (animation). speed = multiplicateur.
     Deux régimes : « actif » (trames en vol, ralenti pour être visible) et « inactif » (attente de timers :
     le temps simulé s'écoule alors à l'allure normale × speed/5, sans sauter d'événements lointains). */
  tick(realMs, speed) {
    if (this.paused || this.halted) return;
    speed = speed || 1; let left = realMs; const SKIP = 0.3, act = 0.0005 * speed, idle = speed / 5;
    for (let i = 0; i < 4000 && left > 0; i++) {
      const e = this._next();
      if (!e) { this.now += left * idle; return; }
      const gap = e.t - this.now;
      if (gap > SKIP + 1e-6) { const need = (gap - SKIP) / idle; if (need >= left) { this.now += left * idle; return; } this.now = e.t - SKIP; left -= need; continue; }
      const need = Math.max(0, gap) / act;
      if (need > left) { this.now += left * act; return; }
      if (e.t > this.now) this.now = e.t; left -= need; this.heap.pop(); e.fn(); if (this.halted) return;
    }
  }
  /* Mode pas à pas : exécute jusqu'à la prochaine livraison de trame */
  stepFrame() { for (let i = 0; i < 5000; i++) { const e = this.runNext(); if (!e) return false; if (e.kind === 'rx') return true; } return false; }
  advance(ms) { this.runFor(ms); }

  /* ---- topologie ---- */
  addDevice(d) { this.devices.set(d.id, d); this.emit('topology'); return d; }
  removeDevice(d) {
    d.ports.forEach(p => { if (p.link) this.disconnect(p.link); });
    if (d.destroy) d.destroy(); this.devices.delete(d.id); this.emit('topology');
  }
  cableOk(a, b, type) {
    if (type === 'fiber') return a.media === 'fiber' && b.media === 'fiber';
    if (a.media === 'fiber' || b.media === 'fiber') return false;
    if (a.media === 'wifi' || b.media === 'wifi') return type === 'wifi' && a.media === 'wifi' && b.media === 'wifi';
    if (type === 'wifi') return false;
    if (!this.opts.strictCables) return true;
    if (type === 'cross') return a.mdi === b.mdi;
    return a.mdi !== b.mdi; // droit
  }
  autoCable(a, b) {
    if (a.media === 'fiber' && b.media === 'fiber') return 'fiber';
    return a.mdi === b.mdi ? 'cross' : 'straight';
  }
  connect(a, b, type) {
    if (a === b || a.link || b.link) return null;
    if (a.dev === b.dev) return null;
    if (!type || type === 'auto') type = this.autoCable(a, b);
    const l = new Link('L' + (++this._lid), a, b, type);
    l.ok = this.cableOk(a, b, type);
    a.link = l; b.link = l; this.links.push(l);
    this.emit('topology'); this.portChanged(a); this.portChanged(b);
    return l;
  }
  disconnect(l) {
    const a = l.a, b = l.b; a.link = null; b.link = null;
    this.links = this.links.filter(x => x !== l);
    this.emit('topology'); this.portChanged(a); this.portChanged(b);
  }
  refreshCables() { this.links.forEach(l => { l.ok = this.cableOk(l.a, l.b, l.type); }); this.links.forEach(l => { this.portChanged(l.a); this.portChanged(l.b); }); this.emit('topology'); }
  portChanged(p) { if (p.dev.portStateChanged) p.dev.portStateChanged(p); this.emit('port', p); }

  /* ---- émission d'une trame sur un port ---- */
  transmit(port, bytes) {
    if (!port.up) return false;
    const l = port.link, peer = l.other(port);
    let t0, ser;
    if (port.qos) { const r = port.qos.tx(bytes, this.now, l.speed); if (!r) { port.qDrops = (port.qDrops || 0) + 1; return true; } bytes = r.bytes; t0 = r.t0; ser = r.ser; }
    else { ser = (bytes.length + 24) * 8 / (l.speed * 1000); t0 = Math.max(this.now, port.txFree || 0); port.txFree = t0 + ser; }
    const t1 = t0 + ser + l.delay;
    this.stats.frames++; port.txPk = (port.txPk || 0) + 1; port.txB = (port.txB || 0) + bytes.length;
    if (this.opts.capture) {
      const rec = { no: ++this.capNo, t: t0, link: l, from: port, bytes };
      this.captures.push(rec); if (this.captures.length > this.capMax) this.captures.splice(0, 5000);
      this.emit('capture', rec);
    }
    this.emit('frame', { link: l, from: port, to: peer, bytes, t0, t1 });
    const target = peer;
    this.at(t1 - this.now, () => { if (target.up && target.dev.recv) { if (target.qosIn) { bytes = target.qosIn(bytes, this.now); if (!bytes) return; } target.rxPk = (target.rxPk || 0) + 1; target.rxB = (target.rxB || 0) + bytes.length; target.dev.recv(target, bytes); } }, 'rx');
    if (bytes[0] & 1) { // détecteur de boucle : la même trame de diffusion émise un très grand nombre de fois en peu de temps
      let hh = 2166136261 ^ bytes.length; const n = Math.min(bytes.length, 80); for (let i = 0; i < n; i++) { hh ^= bytes[i]; hh = Math.imul(hh, 16777619); }
      const bm = this._bc || (this._bc = new Map()); let e = bm.get(hh);
      if (!e || this.now - e.t > 100) { if (bm.size > 4000) bm.clear(); e = { t: this.now, n: 0 }; bm.set(hh, e); }
      if (++e.n > this.links.length * 3 + 40) { this.halted = 'Tempête de diffusion : une trame de broadcast tourne en boucle (boucle de couche 2 sans STP). Simulation arrêtée.'; this.heap.clear(); this.emit('halt', this.halted); return true; }
    }
    const w = this._w || (this._w = { t: 0, n: 0 }); if (this.now - w.t > 1000) { w.t = this.now; w.n = 0; } w.n++;
    if (this.heap.size > 30000 || w.n > 25000) { this.halted = 'Tempête de diffusion : boucle de couche 2 sans STP détectée. Simulation arrêtée.'; this.heap.clear(); this.emit('halt', this.halted); }
    return true;
  }
  log(dev, msg, lvl) { this.emit('log', { t: this.now, dev, msg, lvl: lvl || 'info' }); }
  reset() { this.heap.clear(); this.halted = null; }
}

NS.Sim = Sim; NS.Port = Port; NS.Link = Link; NS.T0 = T0;
})(typeof window !== 'undefined' ? window : globalThis);
