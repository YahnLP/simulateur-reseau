/* ospf.js — OSPFv2 (RFC 2328) : voisinage, élection DR/BDR, échange de bases (DBD/LSR/LSU/LSAck), LSDB, SPF (Dijkstra),
   multi-aires (ABR, LSA type 3/4), redistribution (LSA type 5, E2). Les paquets sont de vrais paquets OSPF (visibles dans l'analyseur). */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS;
const ALLSPF = IP.parse('224.0.0.5'), ALLDR = IP.parse('224.0.0.6');
const MAXAGE = 3600, INITSEQ = 0x80000001 | 0;
const ORDER = ['Down', 'Attempt', 'Init', '2-Way', 'ExStart', 'Exchange', 'Loading', 'Full'];
const rank = s => ORDER.indexOf(s);
const keyOf = l => l.type + '|' + l.id + '|' + l.adv;
const idStr = IP.str;
const hex8 = n => '0x' + (n >>> 0).toString(16).padStart(8, '0');

class Nbr {
  constructor(oi, rid, ip, mac) {
    this.oi = oi; this.rid = rid; this.ip = ip; this.mac = mac; this.pri = 1; this.dr = 0; this.bdr = 0; this.state = 'Init';
    this.ddSeq = 0; this.master = false; this.hdrs = []; this.hi = 0; this.lastSentMore = true; this.lsReq = []; this.retrans = new Map();
    this.deadT = null; this.dbdT = null; this.lsrT = null; this.retT = null; this.lastReply = null; this.since = 0;
  }
}

class Ospf {
  constructor(node) {
    this.node = node; this.enabled = false; this.pid = 1; this.rid = 0; this.ridActive = 0; this.networks = []; this.passive = new Set(); this.nonPassive = new Set(); this.passiveDefault = false;
    this.defaultOrig = null; this.redist = { static: null, connected: null, rip: null }; this.refBw = 100; this.ifs = new Map(); this.lsdb = new Map(); this.ext = new Map();
    this.self = new Map(); this.selfSeq = new Map(); this.wantSums = new Map(); this.wantExt = new Map(); this.spfT = null; this.orgT = null; this.tickT = null;
    this.routes = []; this.results = new Map(); this.spfCount = 0; this.lastSpf = 0; this.startedAt = 0; this.maxPaths = 4;
    node.protoHandlers.set(89, (i, p) => this.input(i, p));
    node.ifHooks.push(i => { if (this.enabled) this.refresh(); });
  }
  get sim() { return this.node.sim; }
  get now() { return this.node.sim.now; }
  /* ---------------------------------------------------------------- configuration */
  routerId() { return this.ridActive; }
  chooseRid() {
    if (this.rid) return this.rid;
    let best = 0; const ifs = this.node.ifaceList();
    ifs.forEach(i => { if (i.loop && i.ip && i.isUp() && i.ip > best) best = i.ip; });
    if (!best) ifs.forEach(i => { if (i.ip && i.isUp() && i.ip > best) best = i.ip; });
    if (!best) ifs.forEach(i => { if (i.ip && i.ip > best) best = i.ip; });
    return best;
  }
  start(pid) {
    if (pid !== undefined) this.pid = pid;
    if (this.enabled) return; this.enabled = true; this.startedAt = this.now; this.ridActive = this.chooseRid();
    this.mc(ALLSPF, true); this.refresh(); this.tickT = this.sim.at(10000, () => this.tick());
  }
  stop() {
    this.ifs.forEach(oi => this.destroyOif(oi)); this.ifs.clear();
    [this.spfT, this.orgT, this.tickT].forEach(t => t && this.sim.cancel(t)); this.spfT = this.orgT = this.tickT = null;
    this.lsdb.clear(); this.ext.clear(); this.self.clear(); this.wantSums.clear(); this.wantExt.clear(); this.routes = [];
    this.node.dynRoutes = this.node.dynRoutes.filter(r => r.proto !== 'O'); this.mc(ALLSPF, false); this.mc(ALLDR, false); this.enabled = false;
  }
  restart() { const pid = this.pid; this.stop(); this.start(pid); }
  setRouterId(rid) { this.rid = rid; if (this.enabled && this.ridActive !== rid) { this.restart(); } }
  mc(ip, on) { const n = this.node; if (on) { n.joinedIp.add(ip); n.joined.add(IP.multicastMac(ip)); } else { n.joinedIp.delete(ip); n.joined.delete(IP.multicastMac(ip)); } }
  addNetwork(net, wc, area) { net = (net & ~wc) >>> 0; if (!this.networks.some(n => n.net === net && n.wc === wc && n.area === area)) this.networks.push({ net, wc, area }); this.refresh(); }
  removeNetwork(net, wc, area) { net = (net & ~wc) >>> 0; this.networks = this.networks.filter(n => !(n.net === net && n.wc === wc && n.area === area)); this.refresh(); }
  isPassive(i) { return this.passive.has(i.name) || (this.passiveDefault && !this.nonPassive.has(i.name)); }
  cost(i) {
    if (i.ospfCostFix) return i.ospfCostFix; if (i.loop) return 1;
    const sp = i.port ? (i.port.isChannel ? i.port.speedSum() : i.port.speed) : (i.svi !== null ? 1000 : 100);
    return Math.max(1, Math.floor(this.refBw / sp));
  }
  areaFor(i) {
    if (!i.ip || !i.mask) return null; if (i.ospfArea !== null && i.ospfArea !== undefined) return i.ospfArea;
    for (const n of this.networks) if (((i.ip & ~n.wc) >>> 0) === n.net) return n.area;
    return null;
  }
  refresh() {
    if (!this.enabled) return;
    const seen = new Set();
    this.node.ifaceList().forEach(i => {
      const a = this.areaFor(i); if (a === null) return; seen.add(i.name);
      let oi = this.ifs.get(i.name);
      if (oi && (oi.area !== a || oi.ip !== i.ip || oi.mask !== i.mask)) { this.destroyOif(oi); this.ifs.delete(i.name); oi = null; }
      if (!oi) { oi = { iface: i, area: a, ip: i.ip, mask: i.mask, up: false, state: 'Down', dr: 0, bdr: 0, nbrs: new Map(), helloT: null, waitT: null, type: 'broadcast', hello: 10, dead: 40, pri: 1 }; this.ifs.set(i.name, oi); if (!this.lsdb.has(a)) this.lsdb.set(a, new Map()); }
      oi.type = i.loop ? 'loop' : (i.ospfNet || 'broadcast'); oi.hello = i.ospfHello || 10; oi.dead = i.ospfDead || oi.hello * 4; oi.pri = i.ospfPri === undefined || i.ospfPri === null ? 1 : i.ospfPri; oi.passive = this.isPassive(i);
      const up = i.isUp();
      if (up && !oi.up) this.bringUp(oi); else if (!up && oi.up) this.bringDown(oi);
    });
    this.ifs.forEach((oi, name) => { if (!seen.has(name)) { this.destroyOif(oi); this.ifs.delete(name); } });
    this.schedOrig();
  }
  destroyOif(oi) { if (oi.up) this.bringDown(oi, true); }
  bringUp(oi) {
    oi.up = true; oi.dr = 0; oi.bdr = 0;
    if (oi.type === 'loop') { oi.state = 'Loopback'; this.schedOrig(); return; }
    if (oi.passive) { oi.state = oi.type === 'p2p' ? 'P2P' : 'DROther'; this.schedOrig(); return; }
    if (oi.type === 'p2p') oi.state = 'P2P';
    else { oi.state = 'Waiting'; const w = this.sim.opts.stpFast ? 4000 : oi.dead * 1000; oi.waitT = this.sim.at(w, () => { oi.waitT = null; if (oi.state === 'Waiting') this.electDr(oi); }); }
    oi.helloT = this.sim.at(200 + this.sim.rng.int(800), () => this.helloLoop(oi));
    this.schedOrig();
  }
  bringDown(oi, silent) {
    oi.up = false; oi.state = 'Down'; oi.dr = 0; oi.bdr = 0;
    [oi.helloT, oi.waitT].forEach(t => t && this.sim.cancel(t)); oi.helloT = oi.waitT = null;
    Array.from(oi.nbrs.values()).forEach(n => this.killNbr(n, 'Interface down', true)); oi.nbrs.clear();
    if (!silent) this.schedOrig();
  }
  helloLoop(oi) {
    if (!this.enabled || !oi.up || this.ifs.get(oi.iface.name) !== oi) return;
    this.sendHello(oi); oi.helloT = this.sim.at(oi.hello * 1000, () => this.helloLoop(oi));
  }
  tick() {
    if (!this.enabled) return;
    this.refresh(); this.syncExternals(); this.schedOrig();
    // purge des LSA MaxAge anciens
    const purge = db => db.forEach((l, k) => { if (this.ageOf(l) >= MAXAGE && this.now - l.t > 60000 && !this.pendingRetrans(k)) db.delete(k); });
    this.lsdb.forEach(purge); purge(this.ext);
    this.tickT = this.sim.at(10000, () => this.tick());
  }
  pendingRetrans(k) { for (const oi of this.ifs.values()) for (const n of oi.nbrs.values()) if (n.retrans.has(k)) return true; return false; }

  /* ---------------------------------------------------------------- émission */
  tx(oi, dst, type, body, nbr) {
    const pk = Codec.ospf({ type, rid: this.ridActive, area: oi.area, body });
    const ip = Codec.ipPacket({ tos: 0xc0, id: this.node.nextId(), ttl: 1, proto: 89, src: oi.iface.ip, dst, df: 0 }, pk);
    if (nbr && nbr.mac && !IP.isMulticast(dst)) this.node.sendFrame(oi.iface, nbr.mac, 0x0800, ip); else this.node.ipOut(oi.iface, dst, ip, null);
  }
  sendHello(oi) {
    if (!oi.up || oi.passive || oi.type === 'loop') return;
    const nb = Array.from(oi.nbrs.values()).filter(n => rank(n.state) >= rank('Init')).map(n => n.rid);
    this.tx(oi, ALLSPF, 1, Codec.ospfHello({ mask: oi.iface.mask, hello: oi.hello, pri: oi.pri, dead: oi.dead, dr: oi.dr, bdr: oi.bdr, neighbors: nb }));
  }
  /* ---------------------------------------------------------------- réception */
  input(iface, p) {
    if (!this.enabled || !p.ospf) return; const o = p.ospf; const oi = this.ifs.get(iface.name);
    if (!oi || !oi.up || oi.passive || oi.type === 'loop') return;
    if (p.ip.src === iface.ip || o.rid === this.ridActive) return;
    if (o.area !== oi.area) return;
    if (o.type === 1) return this.onHello(oi, p, o);
    const n = oi.nbrs.get(o.rid); if (!n || rank(n.state) < rank('ExStart') && o.type !== 2) return;
    if (o.type === 2) return this.onDbd(oi, n, o);
    if (o.type === 3) return this.onLsr(oi, n, o);
    if (o.type === 4) return this.onLsu(oi, n, o);
    if (o.type === 5) return this.onAck(oi, n, o);
  }
  onHello(oi, p, o) {
    if (oi.type === 'broadcast' && o.mask !== oi.iface.mask) return;
    if (o.hello !== oi.hello || o.dead !== oi.dead) return;
    let n = oi.nbrs.get(o.rid); const isNew = !n;
    if (!n) { n = new Nbr(oi, o.rid, p.ip.src, p.eth.src); oi.nbrs.set(o.rid, n); this.logAdj(n, 'DOWN', 'INIT', 'Neighbor is up'); }
    n.ip = p.ip.src; n.mac = p.eth.src; n.lastHelloAt = this.now;
    const oldPri = n.pri, oldDr = n.dr, oldBdr = n.bdr; n.pri = o.pri; n.dr = o.dr; n.bdr = o.bdr;
    if (n.deadT) this.sim.cancel(n.deadT); n.deadT = this.sim.at(oi.dead * 1000, () => this.killNbr(n, 'Dead timer expired'));
    const sees = o.neighbors.includes(this.ridActive);
    if (sees) {
      if (n.state === 'Init') { n.state = '2-Way'; this.logAdj(n, 'INIT', '2WAY', '2-Way Received'); }
    } else if (rank(n.state) >= rank('2-Way')) {
      this.logAdj(n, n.state.toUpperCase(), 'INIT', '1-Way Received'); this.resetAdj(n); n.state = 'Init'; if (oi.type === 'broadcast' && oi.state !== 'Waiting') this.electDr(oi);
    }
    if (oi.type === 'broadcast') {
      if (oi.state === 'Waiting') {
        if ((o.bdr === n.ip) || (o.dr === n.ip && o.bdr === 0)) { if (oi.waitT) { this.sim.cancel(oi.waitT); oi.waitT = null; } this.electDr(oi); }
      } else if (isNew || sees && rank(n.state) >= rank('2-Way') && (oldDr !== n.dr || oldBdr !== n.bdr || oldPri !== n.pri) || (sees && n.state === '2-Way' && isNew)) this.electDr(oi);
    }
    if (rank(n.state) >= rank('2-Way')) this.evalAdj(n);
  }
  logAdj(n, from, to, why) { this.node.log('%OSPF-5-ADJCHG: Process ' + this.pid + ', Nbr ' + idStr(n.rid) + ' on ' + n.oi.iface.name + ' from ' + from + ' to ' + to + ', ' + why, to === 'FULL' || to === 'DOWN' ? 'warn' : 'info'); }
  resetAdj(n) {
    [n.dbdT, n.lsrT, n.retT].forEach(t => t && this.sim.cancel(t)); n.dbdT = n.lsrT = n.retT = null; n.retrans.clear(); n.lsReq = []; n.hdrs = []; n.hi = 0; n.lastReply = null;
  }
  killNbr(n, why, silent) {
    const oi = n.oi; if (n.deadT) this.sim.cancel(n.deadT); n.deadT = null; const was = n.state; this.resetAdj(n);
    if (oi.nbrs.get(n.rid) === n) oi.nbrs.delete(n.rid);
    this.logAdj(n, was.toUpperCase(), 'DOWN', why); n.state = 'Down';
    if (silent) return;
    if (oi.type === 'broadcast' && oi.state !== 'Waiting') this.electDr(oi);
    this.schedOrig(); this.schedSpf();
  }
  /* ---------------------------------------------------------------- DR / BDR (RFC 2328 §9.4) */
  electDr(oi) {
    if (oi.type !== 'broadcast') return; const myIp = oi.iface.ip;
    if (oi.waitT) { this.sim.cancel(oi.waitT); oi.waitT = null; }
    const me = { rid: this.ridActive, ip: myIp, pri: oi.pri, dr: oi.dr, bdr: oi.bdr };
    const nb = Array.from(oi.nbrs.values()).filter(n => rank(n.state) >= rank('2-Way')).map(n => ({ rid: n.rid, ip: n.ip, pri: n.pri, dr: n.dr, bdr: n.bdr }));
    const best = a => a.slice().sort((x, y) => (y.pri - x.pri) || (y.rid - x.rid))[0] || null;
    const run = () => {
      const c = [me].concat(nb).filter(x => x.pri > 0);
      const nd = c.filter(x => x.dr !== x.ip); const decl = nd.filter(x => x.bdr === x.ip);
      const bdr = best(decl.length ? decl : nd);
      const dd = c.filter(x => x.dr === x.ip); let dr = best(dd); if (!dr) dr = bdr;
      return { dr, bdr };
    };
    let r = run();
    const isDr = r.dr && r.dr.ip === myIp, isBdr = r.bdr && r.bdr.ip === myIp;
    if ((oi.dr === myIp) !== !!isDr || (oi.bdr === myIp) !== !!isBdr) { me.dr = r.dr ? r.dr.ip : 0; me.bdr = r.bdr ? r.bdr.ip : 0; r = run(); }
    const nd = r.dr ? r.dr.ip : 0, nbd = r.bdr ? r.bdr.ip : 0;
    const ns = nd === myIp ? 'DR' : nbd === myIp ? 'BDR' : 'DROther';
    const changed = nd !== oi.dr || nbd !== oi.bdr || ns !== oi.state;
    oi.dr = nd; oi.bdr = nbd; oi.state = ns;
    this.mc(ALLDR, Array.from(this.ifs.values()).some(x => x.state === 'DR' || x.state === 'BDR'));
    if (changed) {
      this.node.log('%OSPF-5-ADJCHG: Process ' + this.pid + ', interface ' + oi.iface.name + ' is ' + ns + (nd ? ', DR ' + IP.str(nd) : ''), 'info');
      oi.nbrs.forEach(n => this.evalAdj(n)); this.sendHello(oi); this.schedOrig();
    }
  }
  evalAdj(n) {
    const oi = n.oi; if (rank(n.state) < rank('2-Way')) return;
    const need = oi.type !== 'broadcast' || oi.state === 'DR' || oi.state === 'BDR' || n.ip === oi.dr || n.ip === oi.bdr;
    if (need && n.state === '2-Way') this.startExStart(n);
    else if (!need && rank(n.state) > rank('2-Way')) { this.logAdj(n, n.state.toUpperCase(), '2WAY', 'AdjOK? failed'); this.resetAdj(n); n.state = '2-Way'; this.schedOrig(); }
  }
  /* ---------------------------------------------------------------- échange de bases (DBD) */
  headersFor(oi) {
    const r = []; const add = l => { if (this.ageOf(l) <= MAXAGE) r.push(Codec.lsaHeader(Object.assign({}, l, { age: this.ageOf(l) }))); };
    (this.lsdb.get(oi.area) || new Map()).forEach(add); this.ext.forEach(add); return r;
  }
  startExStart(n) {
    this.resetAdj(n); n.state = 'ExStart'; this.logAdj(n, '2WAY', 'EXSTART', 'AdjOK?'); n.master = true; n.ddSeq = 1 + this.sim.rng.int(1 << 20);
    n.hdrs = this.headersFor(n.oi); n.hi = 0; n.lastSentMore = true; this.sendInitDbd(n);
  }
  sendInitDbd(n) {
    if (n.state !== 'ExStart') return;
    this.tx(n.oi, n.ip, 2, Codec.ospfDbd({ init: 1, more: 1, master: 1, seq: n.ddSeq, headers: [] }), n);
    n.dbdT = this.sim.at(5000, () => this.sendInitDbd(n));
  }
  chunk(n) { const c = n.hdrs.slice(n.hi, n.hi + 40); n.hi += c.length; n.lastSentMore = n.hi < n.hdrs.length; return c; }
  onDbd(oi, n, o) {
    const d = o.dbd; if (!d) return;
    if (rank(n.state) < rank('ExStart')) return;
    if ((n.state === 'Full' || n.state === 'Loading') && d.init) { this.logAdj(n, n.state === 'Full' ? 'FULL' : 'LOADING', '2WAY', 'SeqNumberMismatch'); n.state = '2-Way'; this.schedOrig(); this.startExStart(n); return; }
    if (n.state === 'ExStart') {
      if (d.init && d.more && d.master && d.headers.length === 0 && n.rid > this.ridActive) { // je suis esclave
        if (n.dbdT) this.sim.cancel(n.dbdT); n.master = false; n.ddSeq = d.seq; n.state = 'Exchange'; this.logAdj(n, 'EXSTART', 'EXCHANGE', 'Negotiation Done');
        // la base peut avoir changé entre l'entrée en ExStart (startExStart) et ce moment réel
        // d'échange (plusieurs secondes, cf. retransmission du DBD initial) : on rafraîchit la
        // liste des en-têtes à envoyer plutôt que d'utiliser l'instantané potentiellement périmé.
        n.hdrs = this.headersFor(n.oi); n.hi = 0;
        this.slaveReply(n, d, true);
      } else if (!d.init && !d.master && d.seq === n.ddSeq && n.rid < this.ridActive) { // je suis maître
        if (n.dbdT) this.sim.cancel(n.dbdT); n.master = true; n.state = 'Exchange'; this.logAdj(n, 'EXSTART', 'EXCHANGE', 'Negotiation Done');
        n.hdrs = this.headersFor(n.oi); n.hi = 0;
        this.takeHeaders(n, d); this.masterNext(n, d);
      }
      return;
    }
    if (n.state === 'Exchange') {
      if (n.master) {
        if (d.master || d.seq !== n.ddSeq) return;
        if (n.dbdT) this.sim.cancel(n.dbdT); this.takeHeaders(n, d); this.masterNext(n, d);
      } else {
        if (!d.master) return;
        if (d.seq === n.ddSeq && n.lastReply) { this.tx(n.oi, n.ip, 2, n.lastReply, n); return; }
        if (d.seq !== ((n.ddSeq + 1) >>> 0)) return;
        n.ddSeq = d.seq; this.takeHeaders(n, d); this.slaveReply(n, d, false);
      }
    } else if (rank(n.state) >= rank('Loading') && n.lastReply && !n.master && d.seq === n.ddSeq) this.tx(n.oi, n.ip, 2, n.lastReply, n);
  }
  takeHeaders(n, d) {
    d.headers.forEach(h => {
      const db = h.type === 5 ? this.ext : this.lsdb.get(n.oi.area); const cur = db && db.get(keyOf(h));
      if (h.age >= MAXAGE && !cur) return;
      if (!cur || this.cmp(h, cur, true) > 0) { if (!n.lsReq.some(r => r.type === h.type && r.id === h.id && r.adv === h.adv)) n.lsReq.push({ type: h.type, id: h.id, adv: h.adv, seq: h.seq }); }
    });
  }
  slaveReply(n, d, first) {
    const hs = this.chunk(n);
    const body = Codec.ospfDbd({ init: 0, more: n.lastSentMore ? 1 : 0, master: 0, seq: n.ddSeq, headers: hs }); n.lastReply = body;
    this.tx(n.oi, n.ip, 2, body, n);
    if (!first && !d.more && !n.lastSentMore) this.exchangeDone(n);
  }
  masterNext(n, d) {
    if (!d.more && !n.lastSentMore) { this.exchangeDone(n); return; }
    n.ddSeq = (n.ddSeq + 1) >>> 0; const hs = this.chunk(n);
    const send = () => { if (n.state !== 'Exchange') return; this.tx(n.oi, n.ip, 2, Codec.ospfDbd({ init: 0, more: n.lastSentMore ? 1 : 0, master: 1, seq: n.ddSeq, headers: hs }), n); n.dbdT = this.sim.at(5000, send); };
    send();
  }
  exchangeDone(n) {
    if (n.dbdT) { this.sim.cancel(n.dbdT); n.dbdT = null; }
    if (!n.lsReq.length) { this.setFull(n, 'Exchange Done'); return; }
    n.state = 'Loading'; this.logAdj(n, 'EXCHANGE', 'LOADING', 'Exchange Done'); this.sendLsr(n);
  }
  sendLsr(n) {
    if (n.state !== 'Loading' || !n.lsReq.length) return;
    this.tx(n.oi, n.ip, 3, Codec.ospfLsr(n.lsReq.slice(0, 60)), n); n.lsrT = this.sim.at(5000, () => this.sendLsr(n));
  }
  setFull(n, why) {
    if (n.lsrT) { this.sim.cancel(n.lsrT); n.lsrT = null; } const from = n.state.toUpperCase(); n.state = 'Full'; n.since = this.now; this.logAdj(n, from, 'FULL', why);
    this.schedOrig(); this.schedSpf();
  }
  onLsr(oi, n, o) {
    if (rank(n.state) < rank('Exchange') || !o.lsr) return; const out = [];
    o.lsr.forEach(r => { const db = r.type === 5 ? this.ext : this.lsdb.get(oi.area); const l = db && db.get(r.type + '|' + r.id + '|' + r.adv); if (l) out.push(this.wire(l)); });
    if (out.length) this.tx(oi, n.ip, 4, Codec.ospfLsu(out), n);
  }
  /* ---------------------------------------------------------------- LSA : base, comparaison, inondation */
  ageOf(l) { return Math.min(MAXAGE, (l.age || 0) + Math.floor((this.now - l.t) / 1000)); }
  wire(l) { return Codec.lsaBytes(Object.assign({}, l, { age: Math.min(MAXAGE, this.ageOf(l) + 1) })); }
  cmp(a, b, hdr) {
    if ((a.seq | 0) !== (b.seq | 0)) return (a.seq | 0) > (b.seq | 0) ? 1 : -1;
    if (a.chk !== b.chk) return a.chk > b.chk ? 1 : -1;
    const aa = hdr ? a.age : this.ageOf(a), ab = this.ageOf(b);
    if (aa >= MAXAGE && ab < MAXAGE) return 1; if (ab >= MAXAGE && aa < MAXAGE) return -1;
    if (Math.abs(aa - ab) > 900) return aa < ab ? 1 : -1; return 0;
  }
  dbFor(area, l) { if (l.type === 5) return this.ext; if (!this.lsdb.has(area)) this.lsdb.set(area, new Map()); return this.lsdb.get(area); }
  install(area, l) { l.t = this.now; this.dbFor(area, l).set(keyOf(l), l); this.schedSpf(); }
  onLsu(oi, n, o) {
    if (rank(n.state) < rank('Exchange') || !o.lsu) return; const acks = [];
    o.lsu.forEach(l0 => {
      if (l0.type < 1 || l0.type > 5) return;
      const l = Object.assign({}, l0); delete l.off; l.t = this.now; const k = keyOf(l);
      const db = this.dbFor(oi.area, l); const cur = db.get(k);
      const req = n.lsReq.findIndex(r => r.type === l.type && r.id === l.id && r.adv === l.adv);
      if (!cur || this.cmp(l, cur) > 0) {
        if (l.adv === this.ridActive) { this.selfConflict(oi, l); if (req >= 0) n.lsReq.splice(req, 1); return; }
        if (this.ageOf(l) >= MAXAGE && !cur) { acks.push(l); return; }
        this.install(oi.area, l); this.flood(l, oi.area, oi, n); acks.push(l);
        if (req >= 0) n.lsReq.splice(req, 1);
      } else if (this.cmp(l, cur) === 0) {
        if (req >= 0) n.lsReq.splice(req, 1);
        if (n.retrans.has(k)) n.retrans.delete(k); else acks.push(l);
      } else { this.tx(oi, n.ip, 4, Codec.ospfLsu([this.wire(cur)]), n); }
    });
    if (acks.length) this.tx(oi, n.ip, 5, Codec.ospfAck(acks.map(l => Codec.lsaHeader(l))), n);
    if (n.state === 'Loading' && !n.lsReq.length) this.setFull(n, 'Loading Done');
  }
  onAck(oi, n, o) {
    (o.acks || []).forEach(h => { const k = keyOf(h); const r = n.retrans.get(k); if (r && (r.seq | 0) === (h.seq | 0)) n.retrans.delete(k); });
  }
  selfConflict(oi, l) {
    const k = keyOf(l);
    const sk = k + '#' + (l.type === 5 ? 0 : oi.area);
    if (this.self.has(sk)) { this.self.get(sk).force = true; this.selfSeq.set(sk, Math.max(this.selfSeq.get(sk) | 0, l.seq | 0)); this.schedOrig(); }
    else { const f = Object.assign({}, l, { age: MAXAGE, seq: ((l.seq | 0) + 1) | 0 }); this.install(oi.area, f); this.floodAll(f, oi.area); }
  }
  floodAll(l, area) { this.flood(l, area, null, null); }
  /* inonde l'LSA vers les voisins ; exceptOi/fromNbr : origine de la réception */
  flood(l, area, exceptOi, fromNbr) {
    const k = keyOf(l); const w = this.wire(l);
    this.ifs.forEach(oi => {
      if (!oi.up || oi.passive || oi.type === 'loop') return; if (l.type !== 5 && oi.area !== area) return;
      if (oi === exceptOi && oi.type === 'broadcast' && oi.state !== 'DR') return;
      let any = false;
      oi.nbrs.forEach(n => { if (rank(n.state) >= rank('Exchange') && n !== fromNbr) { n.retrans.set(k, { seq: l.seq, t: this.now }); any = true; if (!n.retT) this.armRetrans(n); } });
      if (!any) return;
      const dst = oi.type === 'broadcast' && oi.state !== 'DR' && oi.state !== 'BDR' ? ALLDR : ALLSPF;
      this.tx(oi, dst, 4, Codec.ospfLsu([w]));
    });
  }
  armRetrans(n) {
    n.retT = this.sim.at(5000, () => {
      n.retT = null; if (rank(n.state) < rank('Exchange') || !n.retrans.size) return;
      const out = []; n.retrans.forEach((v, k) => { const l = (k.startsWith('5|') ? this.ext : this.lsdb.get(n.oi.area) || new Map()).get(k); if (l) out.push(this.wire(l)); else n.retrans.delete(k); });
      if (out.length) { this.tx(n.oi, n.ip, 4, Codec.ospfLsu(out.slice(0, 20)), n); this.armRetrans(n); }
    });
  }

  /* ---------------------------------------------------------------- origination des LSA propres */
  schedOrig() { if (this.orgT || !this.enabled) return; this.orgT = this.sim.at(50, () => { this.orgT = null; this.orig(); }); }
  areas() { const s = new Set(); this.ifs.forEach(oi => { if (oi.up) s.add(oi.area); }); return Array.from(s).sort((a, b) => a - b); }
  isAbr() { const a = this.areas(); return a.length > 1 && a.includes(0); }
  routerLsa(area) {
    const links = [];
    this.ifs.forEach(oi => {
      if (oi.area !== area || !oi.up) return; const i = oi.iface; const c = this.cost(i);
      if (oi.type === 'loop') { links.push({ id: i.ip, data: 0xFFFFFFFF, type: 3, metric: 0 }); return; }
      const stub = () => links.push({ id: IP.net(i.ip, i.mask), data: i.mask, type: 3, metric: c });
      if (oi.passive) { stub(); return; }
      if (oi.type === 'p2p') { const n = Array.from(oi.nbrs.values()).find(x => x.state === 'Full'); if (n) links.push({ id: n.rid, data: i.ip, type: 1, metric: c }); stub(); return; }
      if (oi.state === 'Waiting' || oi.state === 'Down') { stub(); return; }
      const full = Array.from(oi.nbrs.values()).some(x => x.state === 'Full' && (oi.state === 'DR' || x.ip === oi.dr));
      if (full || (oi.state === 'DR' && Array.from(oi.nbrs.values()).some(x => x.state === 'Full'))) links.push({ id: oi.dr, data: i.ip, type: 2, metric: c }); else stub();
    });
    return { type: 1, id: this.ridActive, adv: this.ridActive, router: { flags: (this.isAbr() ? 1 : 0) | (this.wantExt.size ? 2 : 0), links } };
  }
  orig() {
    if (!this.enabled) return; const want = new Map(); const sk = l => keyOf(l) + '#' + l.area;
    this.areas().forEach(a => { const l = this.routerLsa(a); l.area = a; want.set(sk(l), l); });
    this.ifs.forEach(oi => {
      if (oi.up && oi.state === 'DR' && Array.from(oi.nbrs.values()).some(n => n.state === 'Full')) {
        const routers = [this.ridActive].concat(Array.from(oi.nbrs.values()).filter(n => n.state === 'Full').map(n => n.rid));
        const l = { type: 2, id: oi.iface.ip, adv: this.ridActive, network: { mask: oi.iface.mask, routers }, area: oi.area }; want.set(sk(l), l);
      }
    });
    this.wantSums.forEach((l, k) => want.set(k, l)); this.wantExt.forEach((l, k) => want.set(k, l));
    want.forEach((l, k) => {
      const cur = this.self.get(k); const body = JSON.stringify([l.router, l.network, l.summary, l.ext]);
      if (cur && cur.body === body && !cur.force && this.now - cur.l.t < 1800000) return;
      const prev = this.selfSeq.has(k) ? this.selfSeq.get(k) : null;
      const seq = prev === null ? INITSEQ : ((Math.max(prev | 0, cur ? cur.l.seq | 0 : prev | 0) + 1) | 0);
      this.selfSeq.set(k, seq); const nl = Object.assign({}, l, { seq, age: 0, opts: 0x02 });
      const raw = Codec.lsaBytes(nl); nl.chk = (raw[16] << 8) | raw[17]; nl.len = raw.length; nl.t = this.now;
      this.self.set(k, { l: nl, body, force: false }); this.dbFor(l.area, nl).set(keyOf(nl), nl); this.flood(nl, l.area, null, null); this.schedSpf();
    });
    Array.from(this.self.keys()).forEach(k => { if (!want.has(k)) this.flushSelf(k); });
  }
  flushSelf(k) {
    const cur = this.self.get(k); if (!cur) return; this.self.delete(k);
    const seq = ((this.selfSeq.get(k) | 0) + 1) | 0; this.selfSeq.set(k, seq); const f = Object.assign({}, cur.l, { age: MAXAGE, seq, t: this.now });
    const raw = Codec.lsaBytes(f); f.chk = (raw[16] << 8) | raw[17]; this.dbFor(cur.l.area, f).set(keyOf(f), f); this.flood(f, cur.l.area, null, null); this.schedSpf();
  }
  syncExternals() {
    if (!this.enabled) return; const n = this.node; const w = new Map(); const add = (net, mask, metric) => { const l = { type: 5, id: net, adv: this.ridActive, ext: { mask, e2: true, metric, fwd: 0, tag: 0 }, area: 0 }; w.set(keyOf(l) + '#0', l); };
    const all = n.allRoutes();
    if (this.defaultOrig) { if (this.defaultOrig.always || all.some(r => r.net === 0 && r.mask === 0 && r.proto !== 'O')) add(0, 0, this.defaultOrig.metric || 1); }
    if (this.redist.static) all.filter(r => r.proto === 'S' && !(r.net === 0 && r.mask === 0)).forEach(r => add(r.net, r.mask, this.redist.static.metric || 20));
    if (this.redist.rip) all.filter(r => r.proto === 'R').forEach(r => add(r.net, r.mask, this.redist.rip.metric || 20));
    if (this.redist.connected) all.filter(r => r.proto === 'C' && !Array.from(this.ifs.values()).some(oi => oi.iface === r.iface)).forEach(r => add(r.net, r.mask, this.redist.connected.metric || 20));
    const before = Array.from(this.wantExt.keys()).sort().join(); this.wantExt = w; if (Array.from(w.keys()).sort().join() !== before || w.size) this.schedOrig();
  }

  /* ---------------------------------------------------------------- SPF */
  schedSpf() { if (this.spfT || !this.enabled) return; this.spfT = this.sim.at(300, () => { this.spfT = null; this.runSpf(); }); }
  oifByAddr(ip) { for (const oi of this.ifs.values()) if (oi.iface.ip === ip) return oi; return null; }
  spfArea(area) {
    const db = this.lsdb.get(area); if (!db) return null; const me = this.ridActive;
    const live = l => l && this.ageOf(l) < MAXAGE;
    const rl = id => { const l = db.get('1|' + id + '|' + id); return live(l) && l.router ? l : null; };
    const nets = new Map(); db.forEach(l => { if (l.type === 2 && live(l) && l.network) nets.set(l.id, l); });
    const V = new Map(); const root = { k: 'R:' + me, kind: 'R', id: me, dist: 0, nh: null, oi: null, done: false }; V.set(root.k, root);
    const open = [root]; const stubs = [];
    if (!rl(me)) return { V, routes: [], asbrs: new Map(), root };
    const relax = (k, kind, id, cost, nh, oi) => { const w = V.get(k); if (w && w.dist <= cost) return; const nv = { k, kind, id, dist: cost, nh, oi, done: false }; V.set(k, nv); open.push(nv); };
    while (open.length) {
      open.sort((a, b) => a.dist - b.dist || (a.k < b.k ? -1 : 1)); const v = open.shift(); if (v.done || V.get(v.k) !== v) continue; v.done = true;
      if (v.kind === 'R') {
        const l = rl(v.id); if (!l) continue; v.lsa = l;
        l.router.links.forEach(k => {
          if (k.type === 3) { stubs.push({ net: (k.id & k.data) >>> 0, mask: k.data, cost: v.dist + k.metric, v }); return; }
          if (k.type === 1) {
            const wl = rl(k.id); if (!wl || !wl.router.links.some(x => x.type === 1 && x.id === v.id)) return;
            let nh = v.nh, oi = v.oi;
            if (v === root) { const back = wl.router.links.find(x => x.type === 1 && x.id === me); nh = back ? back.data : null; oi = this.oifByAddr(k.data); }
            relax('R:' + k.id, 'R', k.id, v.dist + k.metric, nh, oi);
          } else if (k.type === 2) {
            const nl = nets.get(k.id); if (!nl || !nl.network.routers.includes(v.id)) return;
            relax('N:' + k.id, 'N', k.id, v.dist + k.metric, v === root ? null : v.nh, v === root ? this.oifByAddr(k.data) : v.oi);
          }
        });
      } else {
        const nl = nets.get(v.id); if (!nl) continue; v.lsa = nl;
        nl.network.routers.forEach(r => {
          const wl = rl(r); if (!wl) return; const back = wl.router.links.find(x => x.type === 2 && x.id === v.id); if (!back) return;
          if (r === me) return;
          let nh = v.nh; if (v.nh === null && v.oi) nh = back.data;
          relax('R:' + r, 'R', r, v.dist, nh, v.oi);
        });
      }
    }
    const routes = []; const asbrs = new Map();
    stubs.forEach(s => { routes.push({ net: s.net, mask: s.mask, cost: s.cost, nh: s.v.nh, oi: s.v.oi, area }); });
    V.forEach(v => {
      if (v.kind === 'N' && v.lsa) routes.push({ net: (v.id & v.lsa.network.mask) >>> 0, mask: v.lsa.network.mask, cost: v.dist, nh: v.nh, oi: v.oi, area });
      if (v.kind === 'R' && v.lsa && (v.lsa.router.flags & 2) && v !== root) asbrs.set(v.id, { cost: v.dist, nh: v.nh, oi: v.oi });
    });
    return { V, routes, asbrs, root };
  }
  runSpf() {
    if (!this.enabled) return; this.spfCount++; this.lastSpf = this.now;
    const results = new Map(); this.areas().forEach(a => { const r = this.spfArea(a); if (r) results.set(a, r); }); this.results = results;
    const conn = new Set(this.node.connectedRoutes().map(r => r.net + '/' + r.mask)); const best = new Map();
    const put = (r, kind) => {
      const key = r.net + '/' + r.mask; if (conn.has(key) || !r.nh || !r.oi) return; const pref = { intra: 1, inter: 2, ext: 3 }[kind]; const cur = best.get(key);
      if (!cur || pref < cur.pref || (pref === cur.pref && r.cost < cur.cost) || (pref === cur.pref && r.cost === cur.cost && r.nh < cur.nh)) best.set(key, Object.assign({ pref, kind }, r));
    };
    results.forEach(res => res.routes.forEach(r => put(r, 'intra')));
    const abr = this.isAbr();
    results.forEach((res, area) => {
      if (abr && area !== 0) return;
      (this.lsdb.get(area) || new Map()).forEach(l => {
        if (l.type !== 3 || l.adv === this.ridActive || this.ageOf(l) >= MAXAGE || !l.summary || l.summary.metric >= 0xFFFFFF) return;
        const v = res.V.get('R:' + l.adv); if (!v || !v.nh) return;
        put({ net: (l.id & l.summary.mask) >>> 0, mask: l.summary.mask, cost: v.dist + l.summary.metric, nh: v.nh, oi: v.oi, area }, 'inter');
      });
    });
    // ASBR joignables (intra ou LSA type 4)
    const asbr = id => {
      let b = null; results.forEach(res => { const a = res.asbrs.get(id); if (a && (!b || a.cost < b.cost)) b = a; });
      if (b) return b;
      results.forEach((res, area) => (this.lsdb.get(area) || new Map()).forEach(l => { if (l.type === 4 && l.id === id && this.ageOf(l) < MAXAGE && l.adv !== this.ridActive) { const v = res.V.get('R:' + l.adv); if (v && v.nh && (!b || v.dist + l.summary.metric < b.cost)) b = { cost: v.dist + l.summary.metric, nh: v.nh, oi: v.oi }; } }));
      return b;
    };
    this.ext.forEach(l => {
      if (l.adv === this.ridActive || this.ageOf(l) >= MAXAGE || !l.ext) return; const a = asbr(l.adv); if (!a) return;
      put({ net: (l.id & l.ext.mask) >>> 0, mask: l.ext.mask, cost: l.ext.metric, nh: a.nh, oi: a.oi, ext: true }, 'ext');
    });
    const old = new Map(); this.node.dynRoutes.forEach(r => { if (r.proto === 'O') old.set(r.net + '/' + r.mask + '/' + r.nh, r); });
    const nr = []; best.forEach(r => {
      const k = r.net + '/' + r.mask + '/' + r.nh; const o = old.get(k);
      nr.push({ net: r.net, mask: r.mask, nh: r.nh, iface: r.oi.iface, proto: 'O', sub: r.kind === 'inter' ? 'IA' : r.kind === 'ext' ? 'E2' : '', ad: 110, metric: r.cost, t: o && o.metric === r.cost ? o.t : this.now });
    });
    this.node.dynRoutes = this.node.dynRoutes.filter(r => r.proto !== 'O').concat(nr); this.routes = nr;
    this.calcSummaries(results, best);
    this.syncExternals();
  }
  calcSummaries(results, best) {
    const w = new Map();
    if (this.isAbr()) {
      this.areas().forEach(A => {
        results.forEach((res, X) => {
          if (X === A) return;
          res.routes.forEach(r => { if (r.cost < 0xFFFFFF) { const l = { type: 3, id: r.net, adv: this.ridActive, summary: { mask: r.mask, metric: r.cost }, area: A }; if (!w.has(keyOf(l) + '@' + A) && !results.get(A).routes.some(q => q.net === r.net && q.mask === r.mask)) w.set(keyOf(l) + '@' + A, l); } });
          res.asbrs.forEach((a, id) => { const l = { type: 4, id, adv: this.ridActive, summary: { mask: 0, metric: a.cost }, area: A }; w.set(keyOf(l) + '@' + A, l); });
        });
        if (A !== 0) best.forEach(r => { if (r.kind === 'inter' && r.oi && r.oi.area !== A && !(results.get(A).routes.some(q => q.net === r.net && q.mask === r.mask))) { const l = { type: 3, id: r.net, adv: this.ridActive, summary: { mask: r.mask, metric: r.cost }, area: A }; w.set(keyOf(l) + '@' + A, l); } });
      });
    }
    const nxt = new Map(); w.forEach(l => nxt.set(keyOf(l) + '#' + l.area, l));
    const prev = this.wantSums; const cmp = a => JSON.stringify([a.summary, a.area]);
    let changed = prev.size !== nxt.size; if (!changed) nxt.forEach((l, k) => { const p = prev.get(k); if (!p || cmp(p) !== cmp(l)) changed = true; });
    this.wantSums = nxt; if (changed) this.schedOrig();
  }

  /* ---------------------------------------------------------------- affichage (show) */
  stateStr(n) {
    const oi = n.oi; let role = '-'; if (oi.type === 'broadcast') role = n.ip === oi.dr ? 'DR' : n.ip === oi.bdr ? 'BDR' : 'DROTHER';
    return { Full: 'FULL', 'Down': 'DOWN', Init: 'INIT', '2-Way': '2WAY', ExStart: 'EXSTART', Exchange: 'EXCHANGE', Loading: 'LOADING' }[n.state] + '/' + role;
  }
  showNeighbors() {
    let o = 'Neighbor ID     Pri   State           Dead Time   Address         Interface\n';
    this.ifs.forEach(oi => oi.nbrs.forEach(n => { const dt = Math.max(0, oi.dead - Math.floor((this.now - (n.lastHelloAt || this.now)) / 1000)); o += String(idStr(n.rid)).padEnd(15) + ' ' + String(n.pri).padStart(3) + '   ' + this.stateStr(n).padEnd(15) + ' 00:00:' + String(dt).padStart(2, '0') + '    ' + String(idStr(n.ip)).padEnd(15) + ' ' + oi.iface.name + '\n'; }));
    return o;
  }
  showInterfaces(filter) {
    let o = '';
    this.ifs.forEach(oi => {
      const i = oi.iface; if (filter && i.name.toLowerCase() !== filter.toLowerCase()) return;
      const nb = Array.from(oi.nbrs.values()); const fullN = nb.filter(n => n.state === 'Full').length;
      o += i.name + ' is ' + (i.adminUp ? 'up' : 'administratively down') + ', line protocol is ' + (i.isUp() ? 'up' : 'down') + '\n  Internet Address ' + idStr(i.ip) + '/' + IP.prefixFromMask(i.mask) + ', Area ' + oi.area + ', Attached via ' + (i.ospfArea !== null && i.ospfArea !== undefined ? 'Interface Enable' : 'Network Statement') + '\n';
      o += '  Process ID ' + this.pid + ', Router ID ' + idStr(this.ridActive) + ', Network Type ' + ({ broadcast: 'BROADCAST', p2p: 'POINT_TO_POINT', loop: 'LOOPBACK' }[oi.type]) + ', Cost: ' + this.cost(i) + '\n';
      if (oi.type === 'loop') { o += '  Loopback interface is treated as a stub Host\n'; return; }
      o += '  Transmit Delay is 1 sec, State ' + oi.state.toUpperCase() + (oi.type === 'broadcast' ? ', Priority ' + oi.pri : '') + '\n';
      if (oi.type === 'broadcast' && oi.dr) { const drN = oi.dr === i.ip ? this.ridActive : (nb.find(n => n.ip === oi.dr) || {}).rid; o += '  Designated Router (ID) ' + idStr(drN || 0) + ', Interface address ' + idStr(oi.dr) + '\n'; if (oi.bdr) { const bd = oi.bdr === i.ip ? this.ridActive : (nb.find(n => n.ip === oi.bdr) || {}).rid; o += '  Backup Designated router (ID) ' + idStr(bd || 0) + ', Interface address ' + idStr(oi.bdr) + '\n'; } }
      o += '  Timer intervals configured, Hello ' + oi.hello + ', Dead ' + oi.dead + ', Wait ' + oi.dead + ', Retransmit 5\n' + (oi.passive ? '  No Hellos (Passive interface)\n' : '    Hello due in 00:00:0' + (oi.hello - Math.floor(this.now / 1000) % oi.hello) % 10 + '\n') + '  Neighbor Count is ' + nb.length + ', Adjacent neighbor count is ' + fullN + '\n';
    });
    return o;
  }
  showBrief() {
    let o = 'Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C\n';
    this.ifs.forEach(oi => { const i = oi.iface; const nb = Array.from(oi.nbrs.values()); o += (i.name.replace('GigabitEthernet', 'Gi').replace('FastEthernet', 'Fa').replace('Serial', 'Se').replace('Loopback', 'Lo')).padEnd(12) + ' ' + String(this.pid).padEnd(5) + ' ' + String(oi.area).padEnd(15) + ' ' + (idStr(i.ip) + '/' + IP.prefixFromMask(i.mask)).padEnd(18) + ' ' + String(this.cost(i)).padEnd(5) + ' ' + ({ Loopback: 'LOOP', Waiting: 'WAIT', DROther: 'DROTH' }[oi.state] || oi.state.toUpperCase()).padEnd(5) + ' ' + nb.filter(n => n.state === 'Full').length + '/' + nb.length + '\n'; });
    return o;
  }
  showDatabase(kind) {
    const rid = idStr(this.ridActive); let o = '\n            OSPF Router with ID (' + rid + ') (Process ID ' + this.pid + ')\n';
    const chk = l => '0x' + (l.chk >>> 0).toString(16).padStart(4, '0').toUpperCase().padStart(6, '0').replace('0X', '0x');
    const line = l => idStr(l.id).padEnd(15) + ' ' + idStr(l.adv).padEnd(15) + ' ' + String(this.ageOf(l)).padEnd(11) + ' ' + hex8(l.seq) + ' 0x' + (l.chk >>> 0).toString(16).padStart(6, '0').toUpperCase();
    const secs = [[1, 'Router Link States', 'Link count', l => l.router ? l.router.links.length : ''], [2, 'Net Link States', null], [3, 'Summary Net Link States', null], [4, 'Summary ASB Link States', null]];
    const want = kind ? { router: 1, network: 2, summary: 3, 'asbr-summary': 4, external: 5 }[kind] : 0;
    Array.from(this.lsdb.keys()).sort((a, b) => a - b).forEach(area => {
      const db = this.lsdb.get(area);
      secs.forEach(([t, title, extra, f]) => {
        if (want && want !== t) return; const ls = Array.from(db.values()).filter(l => l.type === t && this.ageOf(l) < MAXAGE).sort((a, b) => a.id - b.id || a.adv - b.adv); if (!ls.length) return;
        if (!want) { o += '\n                ' + title + ' (Area ' + area + ')\n\nLink ID         ADV Router      Age         Seq#       Checksum' + (extra ? ' ' + extra : '') + '\n'; ls.forEach(l => { o += line(l) + (extra ? ' ' + f(l) : '') + '\n'; }); }
        else {
          o += '\n                ' + title + ' (Area ' + area + ')\n\n';
          ls.forEach(l => {
            o += '  LS age: ' + this.ageOf(l) + '\n  Options: (No TOS-capability, DC)\n  LS Type: ' + Codec.LSA_TYPES[l.type] + '\n  Link State ID: ' + idStr(l.id) + (t === 1 ? ' \n' : t === 2 ? ' (address of Designated Router)\n' : ' (summary Network Number)\n') + '  Advertising Router: ' + idStr(l.adv) + '\n  LS Seq Number: ' + hex8(l.seq) + '\n  Checksum: 0x' + (l.chk >>> 0).toString(16).toUpperCase().padStart(4, '0') + '\n  Length: ' + l.len + '\n';
            if (l.router) { o += '  Number of Links: ' + l.router.links.length + '\n'; l.router.links.forEach(k => { o += '\n    Link connected to: ' + ({ 1: 'another Router (point-to-point)', 2: 'a Transit Network', 3: 'a Stub Network' }[k.type]) + '\n     (Link ID) ' + ({ 1: 'Neighboring Router ID', 2: 'Designated Router address', 3: 'Network/subnet number' }[k.type]) + ': ' + idStr(k.id) + '\n     (Link Data) ' + (k.type === 3 ? 'Network Mask: ' : 'Router Interface address: ') + idStr(k.data) + '\n      Number of MTID metrics: 0\n       TOS 0 Metrics: ' + k.metric + '\n'; }); }
            else if (l.network) { o += '  Network Mask: /' + IP.prefixFromMask(l.network.mask) + '\n'; l.network.routers.forEach(r => { o += '        Attached Router: ' + idStr(r) + '\n'; }); }
            else if (l.summary) o += '  Network Mask: /' + IP.prefixFromMask(l.summary.mask) + '\n        MTID: 0         Metric: ' + l.summary.metric + '\n';
            o += '\n';
          });
        }
      });
    });
    if (!want || want === 5) { const ls = Array.from(this.ext.values()).filter(l => this.ageOf(l) < MAXAGE).sort((a, b) => a.id - b.id); if (ls.length) { if (!want) { o += '\n                Type-5 AS External Link States\n\nLink ID         ADV Router      Age         Seq#       Checksum Tag\n'; ls.forEach(l => { o += line(l) + ' ' + l.ext.tag + '\n'; }); } else { o += '\n                Type-5 AS External Link States\n\n'; ls.forEach(l => { o += '  LS age: ' + this.ageOf(l) + '\n  LS Type: AS External Link\n  Link State ID: ' + idStr(l.id) + ' (External Network Number )\n  Advertising Router: ' + idStr(l.adv) + '\n  LS Seq Number: ' + hex8(l.seq) + '\n  Network Mask: /' + IP.prefixFromMask(l.ext.mask) + '\n        Metric Type: 2 (Larger than any link state path)\n        Metric: ' + l.ext.metric + '\n        Forward Address: ' + idStr(l.ext.fwd) + '\n\n'; }); } } }
    return o;
  }
  showGeneral() {
    let o;
    o = ' Routing Process "ospf ' + this.pid + '" with ID ' + idStr(this.ridActive) + '\n Supports only single TOS(TOS0) routes\n Supports opaque LSA\n It is ' + (this.isAbr() ? 'an area border' : 'an internal') + (this.wantExt.size ? ' and autonomous system boundary' : '') + ' router\n Initial SPF schedule delay 0 msecs\n Reference bandwidth unit is ' + this.refBw + ' mbps\n Number of areas in this router is ' + this.areas().length + '. ' + this.areas().length + ' normal 0 stub 0 nssa\n Number of SPF runs: ' + this.spfCount + '\n';
    this.areas().forEach(a => { const ifs = Array.from(this.ifs.values()).filter(oi => oi.area === a); o += '    Area ' + (a === 0 ? 'BACKBONE(0)' : a) + '\n        Number of interfaces in this area is ' + ifs.length + '\n        SPF algorithm last executed ' + Math.floor((this.now - this.lastSpf) / 1000) + 's ago\n        Number of LSA ' + (this.lsdb.get(a) ? this.lsdb.get(a).size : 0) + '.\n'; });
    return o;
  }
}
NS.Ospf = Ospf;
})(typeof window !== 'undefined' ? window : globalThis);
