/* vpn.js — tunnels GRE, IPsec (IKEv1 phase 1 main mode / phase 2 quick mode, ESP) sur les routeurs */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec, Rng } = NS; const { hex2str } = Codec._h;
const cat = (...a) => { let n = 0; a.forEach(x => n += x.length); const r = new Uint8Array(n); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };
const be32 = v => Uint8Array.of((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255), be16 = v => Uint8Array.of((v >> 8) & 255, v & 255);
const r16 = (u, o) => (u[o] << 8) | u[o + 1], r32 = (u, o) => ((u[o] << 24) | (u[o + 1] << 16) | (u[o + 2] << 8) | u[o + 3]) >>> 0;
const hx = u => Array.from(u).map(b => b.toString(16).padStart(2, '0')).join('');
const toBytes = x => typeof x === 'string' ? Uint8Array.from(Array.from(x).map(c => c.charCodeAt(0) & 255)) : (typeof x === 'number' ? be32(x >>> 0) : x);

/* ---- primitives factices (le chiffrement est simulé : flux pseudo-aléatoire déterministe) ---- */
function h32(...parts) { let h = 2166136261 >>> 0; parts.forEach(p => { const b = toBytes(p); for (let i = 0; i < b.length; i++) { h ^= b[i]; h = Math.imul(h, 16777619) >>> 0; } h ^= 0xa5; h = Math.imul(h, 16777619) >>> 0; }); return h >>> 0; }
function digest(n, ...parts) { const r = new Rng(h32(...parts) || 1); const o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = r.int(256); return o; }
function xorKs(data, ...seed) { const r = new Rng(h32(...seed) || 1); const o = new Uint8Array(data.length); for (let i = 0; i < data.length; i++) o[i] = data[i] ^ r.int(256); return o; }
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/* ---- tables ---- */
const ENC = { des: { id: 1, ike: 1, blk: 8, iv: 8, label: 'esp-des', name: 'DES - Data Encryption Standard (56 bit keys).' }, '3des': { id: 3, ike: 5, blk: 8, iv: 8, label: 'esp-3des', name: 'Three key triple DES' }, aes: { id: 12, ike: 7, blk: 16, iv: 16, label: 'esp-aes', name: 'AES - Advanced Encryption Standard' }, null: { id: 11, ike: 0, blk: 4, iv: 0, label: 'esp-null', name: 'NULL' } };
const HASHES = { md5: { ike: 1, esp: 1, label: 'esp-md5-hmac', name: 'Message Digest 5' }, sha: { ike: 2, esp: 2, label: 'esp-sha-hmac', name: 'Secure Hash Standard' }, sha256: { ike: 4, esp: 5, label: 'esp-sha256-hmac', name: 'Secure Hash Standard 2 (256 bit)' } };
const GROUPS = { 1: { ke: 96, bits: 768 }, 2: { ke: 128, bits: 1024 }, 5: { ke: 192, bits: 1536 }, 14: { ke: 256, bits: 2048 } };
const encById = id => Object.keys(ENC).find(k => ENC[k].id === id), ikeEncById = id => Object.keys(ENC).find(k => ENC[k].ike === id && id), hashByIke = id => Object.keys(HASHES).find(k => HASHES[k].ike === id), hashByEsp = id => Object.keys(HASHES).find(k => HASHES[k].esp === id);
const DEFAULT_POLICY = { prio: 65535, enc: 'des', bits: 56, hash: 'sha', auth: 'rsa-sig', group: 1, life: 86400, isDefault: true };

const maskOf = wc => (~wc) >>> 0;
const idPayload = (net, mask, proto) => (mask === 0xFFFFFFFF ? cat(Uint8Array.of(1, proto || 0, 0, 0), be32(net)) : cat(Uint8Array.of(4, proto || 0, 0, 0), be32(net), be32(mask)));
function parseId(b) { const t = b[0]; if (t === 1 && b.length >= 8) return { net: r32(b, 4), mask: 0xFFFFFFFF }; if (t === 4 && b.length >= 12) return { net: r32(b, 4), mask: r32(b, 8) }; return null; }
const idEq = (a, n, m) => a && a.net === (n >>> 0) && a.mask === (m >>> 0);
const idStr = (n, m) => IP.str(n) + '/' + IP.str(m);

function attrsToMap(b, o, end) { const m = {}; while (o + 4 <= end) { const t = r16(b, o); const tv = t & 0x8000, ty = t & 0x7fff; if (tv) { m[ty] = r16(b, o + 2); o += 4; } else { const l = r16(b, o + 2); m[ty] = l === 4 ? r32(b, o + 4) : l === 2 ? r16(b, o + 4) : 0; o += 4 + l; } } return m; }
function parseSaBody(b) {
  if (b.length < 8) return null; const props = []; let pq = 8;
  while (pq + 8 <= b.length) {
    const ppl = r16(b, pq + 2); if (ppl < 8 || pq + ppl > b.length) return null; const sl = b[pq + 6], nt = b[pq + 7]; const pr = { num: b[pq + 4], proto: b[pq + 5], spi: b.slice(pq + 8, pq + 8 + sl), transforms: [] }; let tq = pq + 8 + sl;
    for (let k = 0; k < nt; k++) { if (tq + 8 > pq + ppl) return null; const tl = r16(b, tq + 2); if (tl < 8) return null; pr.transforms.push({ num: b[tq + 4], id: b[tq + 5], at: attrsToMap(b, tq + 8, tq + tl) }); tq += tl; }
    props.push(pr); pq += ppl;
  }
  return props;
}
const KNOWN = new Set([1, 4, 5, 8, 10, 11, 12, 13]);
function parseChain(first, b) {
  const out = []; let o = 0, t = first;
  while (t !== 0) { if (o + 4 > b.length) return null; const nx = b[o], l = r16(b, o + 2); if (l < 4 || o + l > b.length || !KNOWN.has(t)) return null; out.push({ t, body: b.slice(o + 4, o + l) }); t = nx; o += l; }
  if (b.length - o >= 8) return null; for (let i = o; i < b.length; i++) if (b[i] !== 0) return null;
  return out;
}
const byType = (pls, t) => pls.find(p => p.t === t);

class Vpn {
  constructor(node) { this.node = node; this.active = false; this.timer = null; this.reset(); }
  get sim() { return this.node.sim; }
  reset() {
    if (this.timer) { this.timer.dead = true; this.timer = null; }
    (this.ph1 || []).forEach(p => p.timer && (p.timer.dead = true)); (this.qms || []).forEach(q => q.timer && (q.timer.dead = true));
    if (this.active) { this.node.ifHooks = this.node.ifHooks.filter(f => f !== this.hook); this.node.udpUnbind(500); this.node.protoHandlers.delete(47); this.node.protoHandlers.delete(50); }
    this.active = false; this.policies = []; this.keys = []; this.tsets = new Map(); this.cmaps = new Map(); this.profiles = new Map();
    this.ph1 = []; this.sas = []; this.qms = []; this.trig = new Set(); this.debug = { isakmp: false, ipsec: false }; this.connId = 1000; this.ikeEnabled = true; this.keepalive = null;
    if (this.node.ifaces) Array.from(this.node.ifaces.keys()).forEach(k => { const i = this.node.ifaces.get(k); if (i.tun) this.node.ifaces.delete(k); else i.cmap = null; });
  }
  ensure() {
    if (this.active) return; this.active = true; const n = this.node;
    n.udpBind(500, (p, i) => this.onIke(p, i)); n.protoHandlers.set(47, (i, p) => this.greIn(i, p)); n.protoHandlers.set(50, (i, p) => this.espIn(i, p));
    this.timer = this.sim.at(2000, () => this.tick());
    this.hook = i => { if (!i.tun) this.tunCheckAll(); }; n.ifHooks.push(this.hook);
  }
  tick() { this.timer = null; if (!this.active) return; this.tunCheckAll(); this.timer = this.sim.at(2000, () => this.tick()); }
  log(m, l) { this.node.log(m, l); }
  dbg(kind, text) {
    if (!this.debug[kind]) return; const n = this.node; n.log(text, 'debug');
    const L = n.mgmt && n.mgmt.lg; if (L && L.on) { L.count++; L.buf.push(NS.mib.stamp(this.sim.now, true, true) + ': ' + text); if (L.buf.length > 300) L.buf.shift(); }
  }

  /* ================================================================ GRE */
  tunSrcIp(i) { const t = i.tun; if (t.srcIf) { const s = this.node.ifaceByName(t.srcIf); return s && s.ip && s.isUp() ? s.ip : 0; } return t.srcIp || 0; }
  tunUp(i) {
    if (!i.adminUp) return false; if (i._ev) return false; i._ev = true;
    try {
      const t = i.tun; if (!t.dst) return false; const src = this.tunSrcIp(i); if (!src) return false;
      if (!t.srcIf) { let has = false; this.node.ifaces.forEach(x => { if (!x.tun && x.ip === src && x.isUp()) has = true; }); if (!has) return false; }
      const r = this.node.lookup(t.dst); return !!r && !r.iface.tun;
    } finally { i._ev = false; }
  }
  tunCheckAll() {
    this.node.ifaces.forEach(i => {
      if (!i.tun) return; const up = i.isUp();
      if (i.lastUp === undefined) { i.lastUp = up; if (up) this.tunLog(i, true); return; }
      if (i.lastUp !== up) { i.lastUp = up; this.tunLog(i, up); this.node.ifaceStateChanged(i); }
    });
  }
  tunLog(i, up) { this.log('%LINEPROTO-5-UPDOWN: Line protocol on Interface ' + i.name + ', changed state to ' + (up ? 'up' : 'down'), 'info'); }
  tunOut(i, ipBytes) {
    if (!i.isUp()) return; const t = i.tun; const src = this.tunSrcIp(i);
    const r = this.node.lookup(t.dst); if (!r || r.iface.tun) { this.log('%TUN-5-RECURDOWN: ' + i.name + ' temporarily disabled due to recursive routing', 'warn'); return; }
    i.tunTx = (i.tunTx || 0) + 1;
    const gre = Codec.gre({ proto: 0x0800, key: t.key === null || t.key === undefined ? undefined : t.key, payload: ipBytes });
    this.node.sendIp(t.dst, 47, () => gre, { src, ttl: 255, df: 0 });
  }
  greIn(iface, p) {
    const gre = p.gre; if (!gre || !gre.inner || gre.proto !== 0x0800) return; let found = null;
    this.node.ifaces.forEach(i => { if (!i.tun || found) return; const t = i.tun; if (t.dst !== p.ip.src || this.tunSrcIp(i) !== p.ip.dst) return; if ((t.key === null || t.key === undefined) !== (gre.key === null)) return; if (gre.key !== null && t.key !== gre.key) return; found = i; });
    if (!found || !found.isUp()) return; found.tunRx = (found.tunRx || 0) + 1;
    this.node.ipInput(found, gre.inner);
  }

  /* ================================================================ configuration */
  policy(prio, create) { let p = this.policies.find(x => x.prio === prio); if (!p && create) { p = { prio, enc: 'des', bits: 56, hash: 'sha', auth: 'rsa-sig', group: 1, life: 86400 }; this.policies.push(p); this.policies.sort((a, b) => a.prio - b.prio); } return p; }
  keyFor(peer) { const k = this.keys.find(x => x.addr === peer) || this.keys.find(x => x.addr === 0); return k ? k.key : null; }
  tsetText(ts) { return (ENC[ts.enc].label + (ts.enc === 'aes' && ts.bits !== 128 ? ' ' + ts.bits : '')) + (ts.auth ? ' ' + HASHES[ts.auth].label : ''); }
  entryOK(e) { return !!(e.peer && e.acl && e.tset && this.tsets.has(e.tset)); }

  /* ================================================================ plan de données : hook ipOut */
  /* renvoie true si le paquet a été pris en charge (chiffré, ou abandonné en attendant la SA) */
  cryptoOut(iface, nh, ipBytes, onFail) {
    if (!this.active) return false; const n = this.node;
    if (ipBytes.length < 20) return false; const proto = ipBytes[9]; if (proto === 50) return false;
    let p = null; const parse = () => p || (p = Codec.parseIpAt(ipBytes, 0, ipBytes.length, false));
    if (proto === 17) { parse(); if (p.udp && (p.udp.sport === 500 && p.udp.dport === 500)) return false; }
    let entry = null, line = null;
    if (proto === 47) { // tunnel protection ipsec profile
      n.ifaces.forEach(i => { if (entry || !i.tun || !i.tun.prot) return; const t = i.tun; if (t.dst !== r32(ipBytes, 16) || this.tunSrcIp(i) !== r32(ipBytes, 12)) return; const pr = this.profiles.get(t.prot); if (!pr || !pr.tset) return; entry = { kind: 'prof', name: t.prot, tun: i, peer: t.dst, local: this.tunSrcIp(i), tset: pr.tset, pfs: pr.pfs, life: pr.life, iface }; });
    }
    if (!entry && iface.cmap) {
      const cm = this.cmaps.get(iface.cmap); if (cm) {
        parse(); const seqs = Array.from(cm.entries.keys()).sort((a, b) => a - b);
        for (const s of seqs) {
          const e = cm.entries.get(s); if (!this.entryOK(e)) continue; const acl = n.acls.get(e.acl); if (!acl) continue;
          const l = acl.entries.find(x => x.remark === undefined && n.aclEntryMatch(acl, x, p)); if (!l) continue;
          if (l.action === 'permit') { l.hits = (l.hits || 0) + 1; entry = { kind: 'map', name: iface.cmap, seq: s, e, peer: e.peer, local: iface.ip, tset: e.tset, pfs: e.pfs, life: e.life, iface }; line = l; }
          break;
        }
      }
    }
    if (!entry) return false;
    const sa = this.sas.find(s => s.state === 'up' && s.key === this.entryKey(entry, line));
    if (sa) { this.encap(sa, ipBytes, nh, iface, onFail); return true; }
    this.trigger(entry, line);
    return true; // premier(s) paquet(s) perdus pendant la négociation
  }
  entryKey(entry, line) { return entry.kind === 'prof' ? 'P:' + entry.name + ':' + entry.tun.name : 'M:' + entry.name + ':' + entry.seq + ':' + (line ? line.seq : 0) + ':' + entry.peer; }
  proxies(entry, line) {
    if (entry.kind === 'prof') return { l: { net: entry.local, mask: 0xFFFFFFFF }, r: { net: entry.peer, mask: 0xFFFFFFFF }, proto: 47 };
    return { l: { net: (line.src.ip & maskOf(line.src.wc)) >>> 0, mask: maskOf(line.src.wc) }, r: { net: (line.dst.ip & maskOf(line.dst.wc)) >>> 0, mask: maskOf(line.dst.wc) }, proto: 0 };
  }
  encap(sa, ipBytes, nh, iface, onFail) {
    const ts = sa.ts, E = ENC[ts.enc]; const ihl = (ipBytes[0] & 15) * 4; const total = (ipBytes[2] << 8) | ipBytes[3];
    let plain, nxt; if (ts.mode === 'transport') { plain = ipBytes.subarray(ihl, total); nxt = ipBytes[9]; } else { plain = ipBytes.subarray(0, total); nxt = 4; }
    const tl = plain.length + 2; const padLen = (E.blk - (tl % E.blk)) % E.blk; const trailer = new Uint8Array(padLen + 2); for (let i = 0; i < padLen; i++) trailer[i] = i + 1; trailer[padLen] = padLen; trailer[padLen + 1] = nxt;
    const iv = E.iv ? this.sim.rng.bytes(E.iv) : new Uint8Array(0); const clear = cat(plain, trailer);
    const ct = ts.enc === 'null' ? clear : xorKs(clear, sa.seedOut, 'enc', iv);
    const seq = ++sa.seqOut; const head = cat(be32(sa.spiOut), be32(seq));
    const icv = ts.auth ? digest(12, sa.seedOut, 'icv', head, iv, ct) : new Uint8Array(0);
    const esp = cat(head, iv, ct, icv); let outer;
    if (ts.mode === 'transport') { const h = ipBytes.slice(0, ihl); h[9] = 50; const len = ihl + esp.length; h[2] = len >> 8; h[3] = len & 255; h[10] = 0; h[11] = 0; const c = NS.B.checksum(h, 0, ihl); h[10] = c >> 8; h[11] = c & 255; outer = cat(h, esp); }
    else outer = Codec.ipPacket({ ttl: 255, id: this.node.nextId(), proto: 50, src: sa.local, dst: sa.peer, df: 0 }, esp);
    sa.encaps++; sa.bytesOut += ipBytes.length; this.dbg('ipsec', 'IPSEC(crypto_ipsec_send_encrypted): encrypted packet spi 0x' + hx(be32(sa.spiOut)).toUpperCase() + ' seq ' + seq);
    // le paquet ESP repart par le routage normal
    const r = this.node.lookup(sa.peer); if (!r) { if (onFail) onFail('noroute'); return; }
    this.node.ipOutRaw(r.iface, r.nh || sa.peer, outer, onFail);
  }
  espIn(iface, p) {
    const e = p.esp; if (!e) return; const ip = p.ip; const u = p.bytes; const po = ip.off + ip.ihl; const end = ip.off + ip.total;
    const sa = this.sas.find(s => s.spiIn === e.spi && s.peer === ip.src && s.local === ip.dst && s.state === 'up');
    if (!sa) { this.cnt.invSpi = (this.cnt.invSpi || 0) + 1; this.log('%CRYPTO-4-RECVD_PKT_INV_SPI: decaps: rec\'d IPSEC packet has invalid spi for destaddr=' + IP.str(ip.dst) + ', prot=50, spi=0x' + hx(be32(e.spi)).toUpperCase() + '(' + e.spi + '), srcaddr=' + IP.str(ip.src), 'warn'); return; }
    const ts = sa.ts, E = ENC[ts.enc]; const icvLen = ts.auth ? 12 : 0; const body = u.subarray(po + 8, end);
    if (body.length < E.iv + icvLen + 2) { sa.recvErr++; return; }
    const iv = body.slice(0, E.iv), ct = body.slice(E.iv, body.length - icvLen), icv = body.slice(body.length - icvLen);
    if (ts.auth) { const want = digest(12, sa.seedIn, 'icv', u.slice(po, po + 8), iv, ct); if (!eq(want, icv)) { sa.verifyFail++; sa.recvErr++; this.dbg('ipsec', 'IPSEC(): ICV verification failed spi 0x' + hx(be32(e.spi))); return; } }
    const clear = ts.enc === 'null' ? ct : xorKs(ct, sa.seedIn, 'enc', iv); const nxt = clear[clear.length - 1], padLen = clear[clear.length - 2];
    if (padLen + 2 > clear.length) { sa.recvErr++; return; } const plain = clear.slice(0, clear.length - 2 - padLen);
    let innerBytes;
    if (ts.mode === 'transport') { const h = u.slice(ip.off, ip.off + ip.ihl); h[9] = nxt; const len = ip.ihl + plain.length; h[2] = len >> 8; h[3] = len & 255; h[10] = 0; h[11] = 0; const c = NS.B.checksum(h, 0, ip.ihl); h[10] = c >> 8; h[11] = c & 255; innerBytes = cat(h, plain); }
    else { if (nxt !== 4 || plain.length < 20) { sa.recvErr++; return; } innerBytes = plain; }
    const q = Codec.parseIpAt(innerBytes, 0, innerBytes.length, false); if (!q.ip) { sa.recvErr++; return; }
    if (ts.mode !== 'transport' && sa.line && !(IP.inNet(q.ip.src, sa.proxyR.net, sa.proxyR.mask) && IP.inNet(q.ip.dst, sa.proxyL.net, sa.proxyL.mask))) { sa.notDecr++; this.log('%CRYPTO-4-RECVD_PKT_NOT_IPSEC: Rec\'d packet not an IPSEC packet. (ip) vrf/dest_addr= /' + IP.str(q.ip.dst) + ', src_addr= ' + IP.str(q.ip.src) + ', prot= ' + q.ip.proto, 'warn'); return; }
    sa.decaps++; sa.bytesIn += innerBytes.length; this.dbg('ipsec', 'IPSEC(crypto_ipsec_recv_decrypted): decrypted packet spi 0x' + hx(be32(e.spi)).toUpperCase());
    this.node.ipInput(iface, q);
  }

  /* ================================================================ IKE : envoi / réception */
  sendIke(peer, local, bytes) { this.node.udpSend(peer, 500, 500, bytes, { src: local }); }
  encMsg(seed, label, h, payloads) {
    const m = Codec.isakmp({ ic: h.ic, rc: h.rc, exch: h.exch, flags: 1, mid: h.mid || 0, payloads }); let body = m.slice(28); const pad = (8 - body.length % 8) % 8; if (pad) body = cat(body, new Uint8Array(pad));
    const ct = xorKs(body, seed, label, be32(h.mid || 0)); const out = cat(m.slice(0, 28), ct); out.set(be32(out.length), 24); return out;
  }
  decMsg(seed, label, msg) {
    const mid = r32(msg, 20); const len = Math.min(msg.length, r32(msg, 24)); if (len <= 28) return null; const body = xorKs(msg.slice(28, len), seed, label, be32(mid));
    return parseChain(msg[16], body);
  }
  hashPl(seed, mid, label, ...parts) { return { t: 8, body: digest(20, seed, label, be32(mid), ...parts) }; }
  notify(peer, local, ph, type, mid) {
    if (ph && ph.seed) { const pl = [this.hashPl(ph.seed, mid || 0, 'inf', be32(type)), { t: 11, body: Codec.ikeNotify(type, null) }]; this.sendIke(peer, local, this.encMsg(ph.seed, 'inf', { ic: ph.ic, rc: ph.rc, exch: 5, mid: mid || 0 }, pl)); }
    else this.sendIke(peer, local, Codec.isakmp({ ic: ph ? ph.ic : new Uint8Array(8), rc: ph ? ph.rc : new Uint8Array(8), exch: 5, payloads: [{ t: 11, body: Codec.ikeNotify(type, null) }] }));
  }
  onIke(p, iface) {
    const msg = p.udp.payload; if (!msg || msg.length < 28 || (msg[17] >> 4) !== 1) return; const peer = p.ip.src, local = p.ip.dst;
    const ic = msg.slice(0, 8), rc = msg.slice(8, 16), exch = msg[18], flags = msg[19], mid = r32(msg, 20); const icH = hx(ic);
    if (!this.ikeEnabled) return;
    let ph = this.ph1.find(x => hx(x.ic) === icH && x.peer === peer);
    if (exch === 2) {
      if (!ph && !(flags & 1) && msg[16] === 1) return this.mm1(peer, local, ic, msg);
      if (!ph) { this.log('%CRYPTO-4-IKMP_NO_SA: IKE message from ' + IP.str(peer) + ' has no SA and is not an initialization offer', 'warn'); return; }
      return this.mmNext(ph, msg, flags);
    }
    if (exch === 5) {
      if (!(flags & 1)) { // notification en clair
        const pls = parseChain(msg[16], msg.slice(28, Math.min(msg.length, r32(msg, 24)))); const nt = pls && byType(pls, 11); if (nt) this.gotNotify(ph, peer, r16(nt.body, 6)); return;
      }
      if (!ph || !ph.seed) return; const pls = this.decMsg(ph.seed, 'inf', msg); if (!pls) { this.badMsg(peer); return; }
      const nt = byType(pls, 11), dl = byType(pls, 12); if (nt) this.gotNotify(ph, peer, r16(nt.body, 6), mid); if (dl) this.gotDelete(ph, dl.body); return;
    }
    if (exch === 32) { if (!ph || ph.state !== 'QM_IDLE') return; return this.qmNext(ph, msg, mid); }
  }
  badMsg(peer) { this.log('%CRYPTO-4-IKMP_BAD_MESSAGE: IKE message from ' + IP.str(peer) + ' failed its sanity check or is malformed', 'warn'); this.dbg('isakmp', 'ISAKMP:(0): phase 1 message from ' + IP.str(peer) + ' failed decryption (pre-shared key mismatch ?)'); }
  gotNotify(ph, peer, type, mid) {
    const nm = Codec.IKE_NOTIF[type] || type; this.dbg('isakmp', 'ISAKMP:(' + (ph ? ph.conn : 0) + '): received notify ' + nm + ' from ' + IP.str(peer));
    if (mid) { const q = this.qms.find(x => x.mid === mid && x.ph === ph); if (q) { this.qmFail(q, nm); } return; }
    if (ph && ph.role === 'I' && ph.state !== 'QM_IDLE') this.ph1Fail(ph, nm);
  }
  gotDelete(ph, b) {
    const proto = b[4], sl = b[5]; const nsp = r16(b, 6);
    for (let k = 0; k < nsp; k++) {
      const spi = b.slice(8 + k * sl, 8 + (k + 1) * sl);
      if (proto === 3) { const sa = this.sas.find(s => s.peer === ph.peer && be32(s.spiOut).every((x, i) => x === spi[i])); if (sa) this.delSa(sa, false); }
      else if (proto === 1) { this.delPh1(ph, false); }
    }
  }

  /* ---------------- phase 1 : mode principal ---------------- */
  ph1Trigger(peer, local, cb) {
    let ph = this.ph1.find(x => x.peer === peer && x.local === local && x.state === 'QM_IDLE'); if (ph) { cb(ph); return; }
    ph = this.ph1.find(x => x.peer === peer && x.local === local && x.role === 'I' && x.state !== 'QM_IDLE'); if (ph) { ph.cbs.push(cb); return; }
    const pols = this.policies.length ? this.policies : [DEFAULT_POLICY];
    ph = { role: 'I', peer, local, ic: this.sim.rng.bytes(8), rc: new Uint8Array(8), state: 'MM_NO_STATE', step: 'I1', conn: ++this.connId, t0: this.sim.now, cbs: [cb], pols, tries: 0, seed: null, ke: null };
    this.ph1.push(ph);
    const trs = pols.map((po, k) => { const at = []; at.push([1, ENC[po.enc].ike || 1]); if (po.enc === 'aes') at.push([14, po.bits]); at.push([2, HASHES[po.hash].ike], [3, po.auth === 'pre-share' ? 1 : 3], [4, po.group], [11, 1], [12, po.life]); return { num: k + 1, id: 1, attrs: at }; });
    const sa = Codec.ikeSA([{ num: 1, proto: 1, transforms: trs }]);
    ph.msg = Codec.isakmp({ ic: ph.ic, rc: ph.rc, exch: 2, payloads: [{ t: 1, body: sa }, { t: 13, body: Uint8Array.of(0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12) }] });
    this.dbg('isakmp', 'ISAKMP:(0): beginning Main Mode exchange, sending packet to ' + IP.str(peer) + ' (I) MM_NO_STATE');
    this.txPh1(ph);
  }
  txPh1(ph) {
    this.sendIke(ph.peer, ph.local, ph.msg); if (ph.timer) ph.timer.dead = true;
    ph.timer = this.sim.at(5000, () => { ph.timer = null; if (ph.state === 'QM_IDLE' || !this.ph1.includes(ph)) return; if (++ph.tries > 2) { this.ph1Fail(ph, 'timeout'); return; } this.dbg('isakmp', 'ISAKMP:(' + ph.conn + '): retransmitting phase 1 ' + ph.state + '...'); this.txPh1(ph); });
  }
  ph1Fail(ph, why) {
    this.dbg('isakmp', 'ISAKMP:(' + ph.conn + '): phase 1 failed (' + why + ') with ' + IP.str(ph.peer)); this.delPh1(ph, false);
    (ph.cbs || []).forEach(f => f(null, why)); ph.cbs = [];
  }
  delPh1(ph, send) {
    if (ph.timer) { ph.timer.dead = true; ph.timer = null; } if (ph.expire) ph.expire.dead = true; this.ph1 = this.ph1.filter(x => x !== ph);
    this.qms.filter(q => q.ph === ph).forEach(q => { if (q.timer) q.timer.dead = true; }); this.qms = this.qms.filter(q => q.ph !== ph);
    this.trig.clear();
    if (send && ph.seed) { const dl = cat(be32(1), Uint8Array.of(1, 16), be16(1), ph.ic, ph.rc); this.sendIke(ph.peer, ph.local, this.encMsg(ph.seed, 'inf', { ic: ph.ic, rc: ph.rc, exch: 5, mid: 0x7e57 }, [this.hashPl(ph.seed, 0x7e57, 'inf', dl), { t: 12, body: dl }])); }
  }
  pickPolicy(offered) {
    const pols = this.policies.length ? this.policies.concat([DEFAULT_POLICY]) : [DEFAULT_POLICY];
    for (const po of pols) for (const tr of offered) {
      const a = tr.at; if (ikeEncById(a[1]) !== po.enc) continue;
      if (po.enc === 'aes' && a[14] !== po.bits) continue; if (hashByIke(a[2]) !== po.hash) continue;
      if ((a[3] === 1 ? 'pre-share' : 'rsa-sig') !== po.auth) continue; if (a[4] !== po.group) continue;
      return { po, tr };
    }
    return null;
  }
  mm1(peer, local, ic, msg) {
    const pls = parseChain(msg[16], msg.slice(28, Math.min(msg.length, r32(msg, 24)))); const sa = pls && byType(pls, 1); const props = sa && parseSaBody(sa.body); if (!props || !props[0]) return;
    const m = this.pickPolicy(props[0].transforms);
    if (!m) { this.dbg('isakmp', 'ISAKMP:(0): no offers accepted! phase 1 SA policy not acceptable! (local ' + IP.str(local) + ' remote ' + IP.str(peer) + ')'); this.log('%CRYPTO-4-IKMP_NO_SA: IKE phase 1 policy from ' + IP.str(peer) + ' not acceptable', 'warn'); this.notify(peer, local, { ic, rc: new Uint8Array(8) }, 14); return; }
    const ph = { role: 'R', peer, local, ic, rc: this.sim.rng.bytes(8), state: 'MM_SA_SETUP', step: 'R2', conn: ++this.connId, t0: this.sim.now, cbs: [], pol: m.po, tries: 0, seed: null };
    this.ph1.push(ph); const po = m.po; const at = [[1, ENC[po.enc].ike]]; if (po.enc === 'aes') at.push([14, po.bits]); at.push([2, HASHES[po.hash].ike], [3, po.auth === 'pre-share' ? 1 : 3], [4, po.group], [11, 1], [12, po.life]);
    const rsa = Codec.ikeSA([{ num: 1, proto: 1, transforms: [{ num: m.tr.num, id: 1, attrs: at }] }]);
    ph.msg = Codec.isakmp({ ic, rc: ph.rc, exch: 2, payloads: [{ t: 1, body: rsa }, { t: 13, body: Uint8Array.of(0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12) }] });
    this.dbg('isakmp', 'ISAKMP:(0): processing SA payload, policy ' + po.prio + ' accepted, peer ' + IP.str(peer)); this.sendIke(peer, local, ph.msg);
    ph.expire = this.sim.at(30000, () => { if (ph.state !== 'QM_IDLE') this.delPh1(ph, false); });
  }
  mmNext(ph, msg, flags) {
    const len = Math.min(msg.length, r32(msg, 24)); const first = msg[16]; const enc = !!(flags & 1);
    const dup = () => { if (ph.role === 'R' && ph.msg) this.sendIke(ph.peer, ph.local, ph.msg); };
    if (ph.role === 'I') {
      if (!enc && ph.step === 'I1') { // MM2
        const pls = parseChain(first, msg.slice(28, len)); const sa = pls && byType(pls, 1); const props = sa && parseSaBody(sa.body); if (!props || !props[0] || !props[0].transforms[0]) return;
        const num = props[0].transforms[0].num; const po = ph.pols[num - 1]; const offer = props[0].transforms[0].at; if (!po || (ikeEncById(offer[1]) !== po.enc) || hashByIke(offer[2]) !== po.hash || offer[4] !== po.group) return;
        ph.pol = po; ph.rc = msg.slice(8, 16); ph.key = this.keyFor(ph.peer);
        if (ph.key === null) { this.log('%CRYPTO-4-IKMP_NO_KEY: no pre-shared key for ' + IP.str(ph.peer), 'warn'); this.dbg('isakmp', 'ISAKMP:(0): No pre-shared key with ' + IP.str(ph.peer) + '!'); this.ph1Fail(ph, 'no key'); return; }
        ph.ni = this.sim.rng.bytes(20); ph.kel = this.sim.rng.bytes(GROUPS[po.group].ke); ph.state = 'MM_SA_SETUP'; ph.step = 'I3';
        ph.msg = Codec.isakmp({ ic: ph.ic, rc: ph.rc, exch: 2, payloads: [{ t: 4, body: ph.kel }, { t: 10, body: ph.ni }] }); ph.tries = 0; this.txPh1(ph); return;
      }
      if (!enc && ph.step === 'I3') { // MM4
        const pls = parseChain(first, msg.slice(28, len)); const ke = pls && byType(pls, 4), nn = pls && byType(pls, 10); if (!ke || !nn) return;
        ph.nr = nn.body; ph.seed = digest(32, 'skeyid', ph.key, ph.ni, ph.nr, ph.ic, ph.rc); ph.state = 'MM_KEY_EXCH'; ph.step = 'I5';
        const idb = idPayload(ph.local, 0xFFFFFFFF); const hi = digest(20, ph.seed, 'HASH_I', idb);
        ph.msg = this.encMsg(ph.seed, 'mm5', { ic: ph.ic, rc: ph.rc, exch: 2, mid: 0 }, [{ t: 5, body: idb }, { t: 8, body: hi }]); ph.tries = 0; this.txPh1(ph); return;
      }
      if (enc && ph.step === 'I5') { // MM6
        const pls = this.decMsg(ph.seed, 'mm6', msg); if (!pls) { this.badMsg(ph.peer); return; }
        const id = byType(pls, 5), h = byType(pls, 8); if (!id || !h) { this.badMsg(ph.peer); return; }
        if (!eq(h.body, digest(20, ph.seed, 'HASH_R', id.body))) { this.notify(ph.peer, ph.local, ph, 23); this.ph1Fail(ph, 'invalid hash'); return; }
        ph.state = 'QM_IDLE'; ph.step = 'done'; if (ph.timer) { ph.timer.dead = true; ph.timer = null; }
        this.dbg('isakmp', 'ISAKMP:(' + ph.conn + '): Old State = IKE_I_MM5  New State = IKE_P1_COMPLETE');
        const cbs = ph.cbs; ph.cbs = []; cbs.forEach(f => f(ph)); return;
      }
      return;
    }
    // rôle répondeur
    if (!enc && ph.step === 'R2') { // MM3
      if (first === 1) return dup();
      const pls = parseChain(first, msg.slice(28, len)); const ke = pls && byType(pls, 4), nn = pls && byType(pls, 10); if (!ke || !nn) return;
      ph.key = this.keyFor(ph.peer); if (ph.key === null) { this.dbg('isakmp', 'ISAKMP:(0): No pre-shared key with ' + IP.str(ph.peer) + '!'); this.log('%CRYPTO-4-IKMP_NO_KEY: no pre-shared key for ' + IP.str(ph.peer), 'warn'); return; }
      ph.ni = nn.body; ph.nr = this.sim.rng.bytes(20); ph.seed = digest(32, 'skeyid', ph.key, ph.ni, ph.nr, ph.ic, ph.rc); ph.state = 'MM_KEY_EXCH'; ph.step = 'R4';
      ph.msg = Codec.isakmp({ ic: ph.ic, rc: ph.rc, exch: 2, payloads: [{ t: 4, body: this.sim.rng.bytes(GROUPS[ph.pol.group].ke) }, { t: 10, body: ph.nr }] }); this.sendIke(ph.peer, ph.local, ph.msg); return;
    }
    if (enc && ph.step === 'R4') { // MM5
      const pls = this.decMsg(ph.seed, 'mm5', msg); if (!pls) { this.badMsg(ph.peer); return; }
      const id = byType(pls, 5), h = byType(pls, 8); if (!id || !h) { this.badMsg(ph.peer); return; }
      if (!eq(h.body, digest(20, ph.seed, 'HASH_I', id.body))) { this.notify(ph.peer, ph.local, ph, 23); return; }
      const idb = idPayload(ph.local, 0xFFFFFFFF); const hr = digest(20, ph.seed, 'HASH_R', idb);
      ph.msg = this.encMsg(ph.seed, 'mm6', { ic: ph.ic, rc: ph.rc, exch: 2, mid: 0 }, [{ t: 5, body: idb }, { t: 8, body: hr }]);
      ph.state = 'QM_IDLE'; ph.step = 'done'; if (ph.expire) ph.expire.dead = true; this.sendIke(ph.peer, ph.local, ph.msg);
      return;
    }
    dup();
  }

  /* ---------------- phase 2 : mode rapide ---------------- */
  trigger(entry, line) {
    const key = this.entryKey(entry, line); if (this.trig.has(key)) return; this.trig.add(key);
    if (!entry.local) { this.trig.delete(key); return; }
    this.ph1Trigger(entry.peer, entry.local, (ph, why) => { if (!ph) { this.trig.delete(key); return; } this.qmStart(ph, entry, line, key); });
  }
  tsetOffer(entry, spi) {
    const ts = this.tsets.get(entry.tset); if (!ts) return null; const at = [[1, 1], [2, entry.life || 3600], [4, ts.mode === 'transport' ? 2 : 1]]; if (ts.auth) at.push([5, HASHES[ts.auth].esp]); if (ts.enc === 'aes') at.push([6, ts.bits]); if (entry.pfs) at.push([3, entry.pfs]);
    return { ts, sa: Codec.ikeSA([{ num: 1, proto: 3, spi, transforms: [{ num: 1, id: ENC[ts.enc].id, attrs: at }] }]) };
  }
  qmStart(ph, entry, line, key) {
    const pr = this.proxies(entry, line); const spiIn = be32(1 + this.sim.rng.int(0xfffffffe)); const off = this.tsetOffer(entry, spiIn); if (!off) { this.trig.delete(key); return; }
    const mid = (1 + this.sim.rng.int(0xfffffffe)) >>> 0; const ni = this.sim.rng.bytes(20);
    const idc = idPayload(pr.l.net, pr.l.mask, pr.proto), idr = idPayload(pr.r.net, pr.r.mask, pr.proto);
    const pls = [{ t: 1, body: off.sa }, { t: 10, body: ni }]; if (entry.pfs) pls.push({ t: 4, body: this.sim.rng.bytes(GROUPS[entry.pfs].ke) }); pls.push({ t: 5, body: idc }, { t: 5, body: idr });
    const all = [this.hashPl(ph.seed, mid, 'q1', ...pls.map(x => x.body))].concat(pls);
    const q = { ph, mid, role: 'I', entry, line, key, pr, spiIn, ni, step: 'Q1', tries: 0, timer: null, ts: off.ts };
    q.msg = this.encMsg(ph.seed, 'q1', { ic: ph.ic, rc: ph.rc, exch: 32, mid }, all); this.qms.push(q);
    this.dbg('isakmp', 'ISAKMP:(' + ph.conn + '): beginning Quick Mode exchange, M-ID of ' + mid); this.dbg('ipsec', 'IPSEC(sa_request): ,\n  (key eng. msg.) OUTBOUND local= ' + IP.str(entry.local) + ', remote= ' + IP.str(entry.peer) + ',\n    local_proxy= ' + idStr(pr.l.net, pr.l.mask) + ', remote_proxy= ' + idStr(pr.r.net, pr.r.mask));
    this.txQm(q);
  }
  txQm(q) {
    this.sendIke(q.ph.peer, q.ph.local, q.msg); if (q.timer) q.timer.dead = true;
    q.timer = this.sim.at(5000, () => { q.timer = null; if (!this.qms.includes(q) || q.step === 'done') return; if (++q.tries > 2) { this.qmFail(q, 'timeout'); return; } this.txQm(q); });
  }
  qmFail(q, why) {
    this.dbg('ipsec', 'IPSEC: quick mode failed with ' + IP.str(q.ph.peer) + ' (' + why + ')'); if (q.timer) q.timer.dead = true; this.qms = this.qms.filter(x => x !== q); if (q.key) this.trig.delete(q.key);
  }
  /* candidats côté répondeur */
  candidates(peer, local) {
    const n = this.node, out = [];
    n.ifaces.forEach(i => { if (!i.cmap || i.ip !== local) return; const cm = this.cmaps.get(i.cmap); if (!cm) return;
      Array.from(cm.entries.keys()).sort((a, b) => a - b).forEach(s => { const e = cm.entries.get(s); if (!this.entryOK(e) || e.peer !== peer) return; const acl = n.acls.get(e.acl); if (!acl) return;
        acl.entries.forEach(l => { if (l.remark !== undefined || l.action !== 'permit') return; const entry = { kind: 'map', name: i.cmap, seq: s, e, peer, local, tset: e.tset, pfs: e.pfs, life: e.life, iface: i }; out.push({ entry, line: l, pr: this.proxies(entry, l) }); }); }); });
    n.ifaces.forEach(i => { if (!i.tun || !i.tun.prot || i.tun.dst !== peer || this.tunSrcIp(i) !== local) return; const pr = this.profiles.get(i.tun.prot); if (!pr || !pr.tset) return; const entry = { kind: 'prof', name: i.tun.prot, tun: i, peer, local, tset: pr.tset, pfs: pr.pfs, life: pr.life, iface: i }; out.push({ entry, line: null, pr: this.proxies(entry, null) }); });
    return out;
  }
  qmNext(ph, msg, mid) {
    let q = this.qms.find(x => x.mid === mid && x.ph === ph);
    if (!q) { // QM1 côté répondeur
      const pls = this.decMsg(ph.seed, 'q1', msg); if (!pls) return; return this.qm1(ph, mid, pls);
    }
    if (!q) return;
    if (q.role === 'I' && q.step === 'Q1') {
      const pls = this.decMsg(ph.seed, 'q2', msg); if (!pls) { this.badMsg(ph.peer); return; }
      const sa = byType(pls, 1), nn = byType(pls, 10); const props = sa && parseSaBody(sa.body); if (!props || !props[0] || !props[0].transforms[0] || !nn) return;
      const tr = props[0].transforms[0]; const ts = q.ts; if (tr.id !== ENC[ts.enc].id) { this.qmFail(q, 'transform'); return; }
      const spiOut = props[0].spi; if (spiOut.length !== 4) return; q.nr = nn.body;
      const conf = [this.hashPl(ph.seed, mid, 'q3', q.ni, q.nr)]; const m3 = this.encMsg(ph.seed, 'q3', { ic: ph.ic, rc: ph.rc, exch: 32, mid }, conf); this.sendIke(ph.peer, ph.local, m3);
      q.step = 'done'; if (q.timer) { q.timer.dead = true; q.timer = null; } this.qms = this.qms.filter(x => x !== q);
      this.installSa({ entry: q.entry, line: q.line, key: q.key, pr: q.pr, ts, spiIn: q.spiIn, spiOut, ni: q.ni, nr: q.nr, ph, mode: ts.mode }); this.trig.delete(q.key); return;
    }
    if (q.role === 'R' && q.step === 'Q2') {
      const pls = this.decMsg(ph.seed, 'q3', msg); if (!pls || !byType(pls, 8)) { if (q.msg) this.sendIke(ph.peer, ph.local, q.msg); return; }
      q.step = 'done'; this.qms = this.qms.filter(x => x !== q);
      this.installSa({ entry: q.entry, line: q.line, key: q.key, pr: q.pr, ts: q.ts, spiIn: q.spiIn, spiOut: q.spiOut, ni: q.ni, nr: q.nr, ph, mode: q.ts.mode }); return;
    }
    if (q.role === 'R' && q.step === 'Q2' && q.msg) this.sendIke(ph.peer, ph.local, q.msg);
  }
  qm1(ph, mid, pls) {
    const peer = ph.peer, local = ph.local; const sa = byType(pls, 1), nn = byType(pls, 10), ke = byType(pls, 4); const ids = pls.filter(x => x.t === 5);
    const refuse = (type, txt) => { this.dbg('ipsec', 'IPSEC(validate_proposal_request): ' + txt); this.log('%CRYPTO-4-IKMP_NO_SA: IPsec quick mode from ' + IP.str(peer) + ' refused (' + txt + ')', 'warn'); this.notify(peer, local, ph, type, mid); };
    const props = sa && parseSaBody(sa.body); if (!props || !props[0] || !nn || ids.length < 2) return;
    const idc = parseId(ids[0].body), idr = parseId(ids[1].body); if (!idc || !idr) return;
    const cands = this.candidates(peer, local).filter(c => idEq(idc, c.pr.r.net, c.pr.r.mask) && idEq(idr, c.pr.l.net, c.pr.l.mask));
    if (!cands.length) { refuse(18, 'proxy identities not supported (local ' + idStr(idr.net, idr.mask) + ' remote ' + idStr(idc.net, idc.mask) + ')'); return; }
    let chosen = null;
    for (const c of cands) {
      const ts = this.tsets.get(c.entry.tset); if (!ts) continue;
      for (const tr of props[0].transforms) {
        if (tr.id !== ENC[ts.enc].id) continue; if (ts.enc === 'aes' && tr.at[6] !== ts.bits) continue; if ((tr.at[5] ? hashByEsp(tr.at[5]) : null) !== (ts.auth || null)) continue; if ((tr.at[4] === 2 ? 'transport' : 'tunnel') !== ts.mode) continue;
        if ((tr.at[3] || 0) !== (c.entry.pfs || 0)) continue; if (!!c.entry.pfs !== !!ke) continue;
        chosen = { c, ts, tr }; break;
      }
      if (chosen) break;
    }
    if (!chosen) { refuse(14, 'transform proposal not supported for identity: {' + this.tsetText(this.tsets.get(cands[0].entry.tset) || { enc: 'aes', bits: 128 }) + '}'); return; }
    const spiOut = props[0].spi; if (spiOut.length !== 4) return; const spiIn = be32(1 + this.sim.rng.int(0xfffffffe)); const off = this.tsetOffer(chosen.c.entry, spiIn);
    const nr = this.sim.rng.bytes(20); const rp = [{ t: 1, body: off.sa }, { t: 10, body: nr }]; if (chosen.c.entry.pfs) rp.push({ t: 4, body: this.sim.rng.bytes(GROUPS[chosen.c.entry.pfs].ke) }); rp.push({ t: 5, body: ids[0].body }, { t: 5, body: ids[1].body });
    const all = [this.hashPl(ph.seed, mid, 'q2', ...rp.map(x => x.body))].concat(rp);
    const q = { ph, mid, role: 'R', entry: chosen.c.entry, line: chosen.c.line, key: this.entryKey(chosen.c.entry, chosen.c.line), pr: chosen.c.pr, spiIn, spiOut, ni: nn.body, nr, step: 'Q2', ts: chosen.ts };
    q.msg = this.encMsg(ph.seed, 'q2', { ic: ph.ic, rc: ph.rc, exch: 32, mid }, all); this.qms.push(q); this.sendIke(peer, local, q.msg);
    q.timer = this.sim.at(20000, () => { q.timer = null; this.qms = this.qms.filter(x => x !== q); });
  }
  installSa(o) {
    const { entry, ts, ph } = o; const km = digest(32, 'km', ph.seed, o.ni, o.nr); const spiI = r32(o.spiIn, 0), spiO = r32(o.spiOut, 0);
    // supprime une SA précédente pour le même flux
    this.sas.filter(s => s.key === o.key).forEach(s => this.delSa(s, false));
    const sa = { id: ++this.connId, key: o.key, entry, kind: entry.kind, mapName: entry.name, seq: entry.seq, line: o.line, peer: entry.peer, local: entry.local, iface: entry.iface, ts, spiIn: spiI, spiOut: spiO, seedIn: digest(32, km, be32(spiI)), seedOut: digest(32, km, be32(spiO)), seqOut: 0, encaps: 0, decaps: 0, verifyFail: 0, recvErr: 0, notDecr: 0, bytesIn: 0, bytesOut: 0, t0: this.sim.now, life: entry.life || 3600, state: 'up', proxyL: o.pr.l, proxyR: o.pr.r, ph };
    this.sas.push(sa); this.log('%CRYPTO-5-SESSION_STATUS: Crypto tunnel is UP .  Peer ' + IP.str(sa.peer) + ':500 Id: ' + IP.str(sa.peer), 'info');
    this.dbg('ipsec', 'IPSEC(initialize_sas): ,\n  (key eng. msg.) INBOUND local= ' + IP.str(sa.local) + ', remote= ' + IP.str(sa.peer) + ', spi= 0x' + hx(be32(spiI)).toUpperCase());
  }
  delSa(sa, send) {
    this.sas = this.sas.filter(x => x !== sa); sa.state = 'dead';
    if (send && sa.ph && sa.ph.seed && this.ph1.includes(sa.ph)) { const dl = cat(be32(1), Uint8Array.of(3, 4), be16(1), be32(sa.spiIn)); const mid = 0x7e00 + (sa.id & 255); this.sendIke(sa.peer, sa.local, this.encMsg(sa.ph.seed, 'inf', { ic: sa.ph.ic, rc: sa.ph.rc, exch: 5, mid }, [this.hashPl(sa.ph.seed, mid, 'inf', dl), { t: 12, body: dl }])); }
    this.trig.clear();
  }
  clearSa(peer) { this.sas.filter(s => !peer || s.peer === peer).forEach(s => this.delSa(s, true)); }
  clearIsakmp(peer) { this.ph1.filter(p => !peer || p.peer === peer).forEach(p => { const dels = this.sas.filter(s => s.ph === p); dels.forEach(s => this.delSa(s, true)); this.delPh1(p, true); }); }
}
NS.Vpn = Vpn; NS.vpnUtil = { ENC, HASHES, GROUPS, DEFAULT_POLICY, digest, hx };

/* ---- correctifs sur IPNode : ipOut (crypto map) et sendFrame (interface Tunnel) ---- */
const P = NS.IPNode ? NS.IPNode.prototype : null;
function patch(IPNode) {
  const P = IPNode.prototype; if (P._vpnPatched) return; P._vpnPatched = true;
  const ipOut0 = P.ipOut, sendFrame0 = P.sendFrame;
  P.ipOutRaw = ipOut0;
  P.ipOut = function (iface, nh, ipBytes, onFail) {
    const v = this.vpn; if (v && v.active) { if (iface.tun) { v.tunOut(iface, ipBytes); return; } if (v.cryptoOut(iface, nh, ipBytes, onFail)) return; }
    return ipOut0.call(this, iface, nh, ipBytes, onFail);
  };
  P.sendFrame = function (iface, dstMac, type, payload) {
    if (iface.tun) { if (type === 0x0800 && this.vpn) this.vpn.tunOut(iface, payload); return false; }
    return sendFrame0.call(this, iface, dstMac, type, payload);
  };
}
if (NS.IPNode) patch(NS.IPNode); else NS._vpnPatch = patch;
})(typeof window !== 'undefined' ? window : globalThis);
