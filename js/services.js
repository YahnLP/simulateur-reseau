/* services.js — DHCP (client/serveur/relais), DNS (serveur/résolveur), HTTP/HTTPS (serveur/client), RIPv2 */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, B, Rng } = NS;

/* ================================================================== DHCP client */
class DhcpClient {
  constructor(node, iface) { this.node = node; this.iface = iface; this.state = 'STOPPED'; this.timer = null; this.xid = 0; this.tries = 0; this.info = null; this.offer = null; }
  get sim() { return this.node.sim; }
  start() {
    this.stop(true); const n = this.node;
    if (!this.iface.isUp()) { this.state = 'INIT'; return; }
    this.state = 'SELECTING'; this.tries = 0; this.xid = (this.sim.rng.next() * 4294967295) >>> 0;
    if (this.iface.ip && !this.iface.dhcpLeased) { this.iface.ip = 0; this.iface.mask = 0; }
    this.sim.at(0.3 + this.sim.rng.int(3), () => this.discover());
  }
  stop(silent) {
    if (this.timer) { this.sim.cancel(this.timer); this.timer = null; }
    this.state = 'STOPPED';
  }
  release() {
    const i = this.iface;
    if (this.info && i.ip) {
      const d = Codec.dhcp({ op: 1, xid: this.xid, ciaddr: i.ip, chaddr: i.mac, opts: { msgType: 7, serverId: this.info.server, clientId: i.mac } });
      this.node.udpSendOn(i, i.ip, this.info.server, 67, 68, d, {});
    }
    this.stop(); this.unconfigure();
  }
  unconfigure() {
    const i = this.iface; const n = this.node;
    if (i.dhcpLeased) { i.ip = 0; i.mask = 0; i.dhcpLeased = false; }
    n.statics = n.statics.filter(s => !s.dhcp); if (n.dhcpDns) n.dnsServers = []; this.info = null;
  }
  discover() {
    if (this.state !== 'SELECTING') return;
    const i = this.iface; if (!i.isUp()) return;
    if (this.tries >= 3) { this.giveUp(); return; }
    this.tries++;
    const d = Codec.dhcp({ op: 1, xid: this.xid, flags: 0x8000, chaddr: i.mac, secs: this.tries > 1 ? (this.tries - 1) * 4 : 0, opts: { msgType: 1, clientId: i.mac, hostname: this.node.name.replace(/\s/g, '-'), paramList: [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252] } });
    this.node.udpSendOn(i, 0, 0xFFFFFFFF, 67, 68, d, { dstMac: MAC.BCAST });
    this.timer = this.sim.at(4000, () => this.discover());
  }
  giveUp() {
    this.state = 'FAILED';
    if (this.node.os === 'windows' || this.node.apipa) { // APIPA 169.254.x.y/16
      const i = this.iface; i.ip = IP.parse('169.254.' + (1 + this.sim.rng.int(254)) + '.' + (1 + this.sim.rng.int(254))); i.mask = 0xFFFF0000; i.dhcpLeased = true; i.apipa = true;
      this.state = 'APIPA'; this.node.log('DHCP : aucun serveur, adresse APIPA ' + IP.str(i.ip), 'warn');
      this.node.arpAnnounce && this.node.arpAnnounce(i);
    }
  }
  input(p) {
    const d = p.dhcp; if (!d || d.op !== 2 || d.xid !== this.xid || d.chaddr !== this.iface.mac) return;
    const i = this.iface;
    if (d.msgType === 2 && this.state === 'SELECTING') {
      if (this.timer) this.sim.cancel(this.timer);
      this.state = 'REQUESTING'; this.offer = d;
      const r = Codec.dhcp({ op: 1, xid: this.xid, flags: 0x8000, chaddr: i.mac, opts: { msgType: 3, clientId: i.mac, requested: d.yiaddr, serverId: d.opts.serverId, hostname: this.node.name.replace(/\s/g, '-'), paramList: [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252] } });
      this.node.udpSendOn(i, 0, 0xFFFFFFFF, 67, 68, r, { dstMac: MAC.BCAST });
      this.timer = this.sim.at(4000, () => { if (this.state === 'REQUESTING') this.start(); });
    } else if (d.msgType === 5 && this.state === 'REQUESTING') {
      if (this.timer) this.sim.cancel(this.timer);
      const o = d.opts, n = this.node;
      n.statics = n.statics.filter(s => !s.dhcp);
      i.ip = d.yiaddr; i.mask = o.mask || IP.classMask(d.yiaddr); i.dhcpLeased = true; i.apipa = false;
      if (o.routers && o.routers.length) n.statics.push({ net: 0, mask: 0, nh: o.routers[0], iface: null, ad: 1, dhcp: true });
      if (o.dns) { n.dnsServers = o.dns.slice(); n.dhcpDns = true; }
      if (o.domain) n.domain = o.domain;
      this.info = { server: o.serverId || p.ip.src, lease: o.lease || 86400, t: this.sim.now, yiaddr: d.yiaddr, domain: o.domain };
      this.state = 'BOUND';
      this.node.log('DHCP : bail obtenu ' + IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask), 'info');
      if (n.arpAnnounce) n.arpAnnounce(i);
      // renouvellement à T1 = lease/2 (unicast)
      const t1 = (o.renewal || (this.info.lease / 2)) * 1000;
      this.timer = this.sim.at(t1, () => this.renew());
    } else if (d.msgType === 6) { this.unconfigure(); this.start(); }
  }
  renew() {
    if (this.state !== 'BOUND') return; const i = this.iface;
    const r = Codec.dhcp({ op: 1, xid: (this.xid = (this.xid + 1) >>> 0), ciaddr: i.ip, chaddr: i.mac, opts: { msgType: 3, clientId: i.mac, hostname: this.node.name.replace(/\s/g, '-') } });
    this.state = 'REQUESTING';
    this.node.udpSend(this.info.server, 67, 68, r, {});
    this.timer = this.sim.at(4000, () => { if (this.state === 'REQUESTING') { this.state = 'BOUND'; } });
  }
}

/* ================================================================== DHCP serveur */
class DhcpServer {
  constructor(node) { this.node = node; this.pools = []; this.excluded = []; this.leases = new Map(); this.enabled = false; this.log = []; }
  get sim() { return this.node.sim; }
  addPool(p) {
    const ex = this.pools.findIndex(x => x.name === p.name); if (ex >= 0) this.pools[ex] = Object.assign(this.pools[ex], p); else this.pools.push(Object.assign({ name: 'POOL', net: 0, mask: 0, router: 0, dns: [], domain: '', lease: 86400, start: 0, end: 0 }, p));
    return this.pools.find(x => x.name === p.name);
  }
  isExcluded(ip) { return this.excluded.some(r => ip >= r[0] && ip <= r[1]); }
  poolFor(ip) { return this.pools.find(p => p.net && IP.inNet(ip, p.net, p.mask)); }
  leaseTaken(ip, mac) { for (const [m, l] of this.leases) if (l.ip === ip && m !== mac && l.expires > this.sim.now) return true; return false; }
  pickIp(pool, mac, req) {
    const old = this.leases.get(mac); if (old && old.pool === pool.name && old.expires > this.sim.now) return old.ip;
    if (req && IP.inNet(req, pool.net, pool.mask) && !this.isExcluded(req) && !this.leaseTaken(req, mac) && !this.node.isLocalIp(req)) return req;
    const first = pool.start || ((pool.net + 1) >>> 0), last = pool.end || ((IP.bcast(pool.net, pool.mask) - 1) >>> 0);
    for (let ip = first; ip <= last; ip++) {
      if (this.isExcluded(ip) || this.leaseTaken(ip, mac) || this.node.isLocalIp(ip)) continue;
      return ip >>> 0;
    }
    return 0;
  }
  handle(p, iface) {
    if (!this.enabled) return; const d = p.dhcp; if (!d || d.op !== 1) return;
    const ref = d.giaddr || iface.ip; const pool = this.poolFor(ref); if (!pool) return;
    const t = d.msgType; const mac = d.chaddr;
    if (t === 1) {
      const ip = this.pickIp(pool, mac, d.opts.requested); if (!ip) return;
      this.leases.set(mac, { ip, pool: pool.name, expires: this.sim.now + 10000, offered: true, host: d.opts.hostname || '' });
      this.reply(iface, p, pool, 2, ip);
    } else if (t === 3) {
      if (d.opts.serverId && !this.node.isLocalIp(d.opts.serverId)) { const l = this.leases.get(mac); if (l && l.offered) this.leases.delete(mac); return; }
      const req = d.opts.requested || d.ciaddr; const l = this.leases.get(mac);
      const ok = req && IP.inNet(req, pool.net, pool.mask) && !this.leaseTaken(req, mac) && (!l || l.ip === req || !l.offered);
      if (ok) { this.leases.set(mac, { ip: req, pool: pool.name, expires: this.sim.now + pool.lease * 1000, host: d.opts.hostname || '', t: this.sim.now }); this.reply(iface, p, pool, 5, req); }
      else this.reply(iface, p, pool, 6, 0);
    } else if (t === 7) { this.leases.delete(mac); }
  }
  reply(iface, p, pool, type, yi) {
    const d = p.dhcp; const n = this.node;
    const router = pool.router || 0;
    const opts = { msgType: type, serverId: iface.ip };
    if (type !== 6) { opts.lease = pool.lease; opts.renewal = Math.floor(pool.lease / 2); opts.rebinding = Math.floor(pool.lease * 7 / 8); opts.mask = pool.mask; if (router) opts.routers = [router]; if (pool.dns && pool.dns.length) opts.dns = pool.dns; if (pool.domain) opts.domain = pool.domain; }
    const out = Codec.dhcp({ op: 2, xid: d.xid, flags: d.flags, ciaddr: 0, yiaddr: yi, siaddr: iface.ip, giaddr: d.giaddr, chaddr: d.chaddr, opts });
    if (d.giaddr) { n.udpSend(d.giaddr, 67, 67, out, {}); return; }
    n.udpSendOn(iface, iface.ip, 0xFFFFFFFF, 68, 67, out, { dstMac: MAC.BCAST });
  }
}
/* Relais DHCP (ip helper-address) */
class DhcpRelay {
  constructor(node) { this.node = node; }
  handle(p, iface) {
    const d = p.dhcp; if (!d) return false; const n = this.node;
    if (d.op === 1 && iface.helper && iface.helper.length && !d.giaddr) {
      const bytes = Codec.dhcp({ op: 1, xid: d.xid, flags: d.flags, ciaddr: d.ciaddr, yiaddr: 0, siaddr: 0, giaddr: iface.ip, hops: 1, chaddr: d.chaddr, secs: d.secs, opts: d.opts });
      iface.helper.forEach(h => n.udpSend(h, 67, 67, bytes, {}));
      return true;
    }
    if (d.op === 2 && d.giaddr) {
      const ifc = n.ifaceList().find(i => i.ip === d.giaddr); if (!ifc) return false;
      const bytes = Codec.dhcp({ op: 2, xid: d.xid, flags: d.flags, ciaddr: d.ciaddr, yiaddr: d.yiaddr, siaddr: d.siaddr, giaddr: d.giaddr, chaddr: d.chaddr, opts: d.opts });
      n.udpSendOn(ifc, ifc.ip, 0xFFFFFFFF, 68, 67, bytes, { dstMac: MAC.BCAST });
      return true;
    }
    return false;
  }
}

/* ================================================================== DNS */
class DnsServer {
  constructor(node) { this.node = node; this.enabled = false; this.records = []; this.forwarders = []; this.queries = 0; }
  start() { this.enabled = true; this.node.udpBind(53, (p, i) => this.handle(p, i)); }
  stop() { this.enabled = false; this.node.udpUnbind(53); }
  find(name, type) { const n = name.toLowerCase().replace(/\.$/, ''); return this.records.filter(r => r.name.toLowerCase() === n && r.type === type); }
  answer(q) {
    const ans = []; let known = false; const name = q.name.toLowerCase().replace(/\.$/, '');
    if (q.type === 'PTR') {
      const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$/.exec(name);
      if (m) { const ip = m[4] + '.' + m[3] + '.' + m[2] + '.' + m[1]; this.records.filter(r => r.type === 'A' && r.data === ip).forEach(r => { ans.push({ name: q.name, type: 'PTR', data: r.name, ttl: 3600 }); }); this.records.filter(r => r.type === 'PTR' && r.name.toLowerCase() === name).forEach(r => ans.push({ name: q.name, type: 'PTR', data: r.data, ttl: 3600 })); }
      return ans;
    }
    const direct = this.find(name, q.type); direct.forEach(r => ans.push({ name: r.name, type: r.type, data: r.data, pref: r.pref, ttl: r.ttl || 3600 }));
    if (!direct.length && q.type === 'A') {
      const c = this.find(name, 'CNAME')[0];
      if (c) { ans.push({ name: c.name, type: 'CNAME', data: c.data, ttl: c.ttl || 3600 }); this.find(c.data, 'A').forEach(r => ans.push({ name: r.name, type: 'A', data: r.data, ttl: r.ttl || 3600 })); }
    }
    return ans;
  }
  handle(p, iface) {
    const d = p.dns; if (!d || d.qr || !d.questions.length) return; this.queries++;
    const q = d.questions[0]; const n = this.node;
    const reply = (rcode, answers, aa) => {
      const out = Codec.dns({ id: d.id, qr: 1, aa: aa ? 1 : 0, rd: d.rd, ra: 1, rcode, questions: [{ name: q.name, type: q.type }], answers });
      n.udpSend(p.ip.src, p.udp.sport, 53, out, { src: p.ip.dst });
    };
    const ans = this.answer(q);
    if (ans.length) return reply(0, ans, true);
    // zone connue (le nom existe avec un autre type) -> NOERROR sans réponse
    const exists = this.records.some(r => r.name.toLowerCase() === q.name.toLowerCase());
    if (exists) return reply(0, [], true);
    if (this.forwarders.length && d.rd) {
      n.dnsQuery(this.forwarders[0], q.name, q.type, (err, res) => { if (err) return reply(2, [], false); reply(res.rcode, res.answers, false); });
      return;
    }
    reply(3, [], true);
  }
}
/* Résolveur (côté client) — ajouté à IPNode */
function installResolver(proto) {
  proto.dnsQuery = function (server, name, type, cb, timeout) {
    const id = (this.sim.rng.int(65535)) + 1; const sport = this.nextPort(); let done = false;
    const t0 = this.sim.now;
    const fin = (err, res) => { if (done) return; done = true; this.sim.cancel(tm); this.udpUnbind(sport); cb(err, res, this.sim.now - t0); };
    const tm = this.sim.at(timeout || 2000, () => fin('timeout'));
    this.udpBind(sport, p => { const d = p.dns; if (d && d.id === id && d.qr) fin(null, d); });
    const out = Codec.dns({ id, rd: 1, questions: [{ name, type }] });
    const r = this.udpSend(server, 53, sport, out, { onFail: () => fin('unreachable') });
    if (!r.ok) fin('unreachable');
  };
  proto.resolve = function (name, cb, type) {
    type = type || 'A';
    const ip = IP.parse(name); if (ip !== null) return cb(null, { ip, name });
    if (this.hosts && this.hosts[name.toLowerCase()]) return cb(null, { ip: IP.parse(this.hosts[name.toLowerCase()]), name });
    let full = name; const servers = (this.dnsServers || []).slice();
    if (!servers.length) return cb('nodns');
    const tryName = (nm, si, attempt) => {
      if (si >= servers.length) return cb('timeout');
      this.dnsQuery(servers[si], nm, type, (err, res) => {
        if (err) { if (attempt < 1) return tryName(nm, si, attempt + 1); return tryName(nm, si + 1, 0); }
        const a = res.answers.filter(x => x.type === type)[0];
        if (res.rcode === 3) return cb('nxdomain', res);
        if (!a) return cb('noanswer', res);
        cb(null, { ip: type === 'A' ? IP.parse(a.data) : 0, name: nm, res, server: servers[si], rtt: 0 });
      });
    };
    tryName(full, 0, 0);
  };
}

/* ================================================================== HTTP(S) */
const TLS_SEED = (a, b) => ((B.u32(a, 0) ^ B.u32(b, 0)) >>> 0) || 1;
function keystream(seed, dir) { const r = new Rng(seed + dir * 7919); return r; }
function xorStream(data, rng) { const o = new Uint8Array(data.length); for (let i = 0; i < data.length; i++) o[i] = data[i] ^ rng.int(256); return o; }

class HttpServer {
  constructor(node) {
    this.node = node; this.enabled = false; this.https = false; this.log = [];
    this.pages = { '/': { type: 'text/html; charset=utf-8', body: '<html><head><title>' + node.name + '</title></head><body><h1>Bienvenue sur ' + node.name + '</h1><p>Serveur web du simulateur.</p></body></html>' } };
  }
  start() {
    this.enabled = true;
    this.node.tcpListen(80, c => this.accept(c, false));
    if (this.https) this.node.tcpListen(443, c => this.accept(c, true));
  }
  stop() { this.enabled = false; this.node.tcpUnlisten(80); this.node.tcpUnlisten(443); }
  respond(conn, raw, tls) {
    const h = Codec.parse(Codec.frame({ dst: MAC.BCAST, src: MAC.BCAST, type: 0x0800, payload: Codec.ipPacket({ ttl: 1, proto: 6, src: 1, dst: 2 }, Codec.tcp(1, 2, { sport: 1, dport: 80, seq: 0, ack: 0, flags: 0x18, payload: raw })) })).http;
    let out;
    if (!h || !h.isReq) out = Codec.httpResponse(400, 'Bad Request', '<h1>400 Bad Request</h1>');
    else {
      const path = h.uri.split('?')[0];
      if (h.method === 'POST') {
        const body = B.utf8Str(h.body);
        out = Codec.httpResponse(200, 'OK', '<html><body><h2>Formulaire reçu</h2><pre>' + body.replace(/</g, '&lt;') + '</pre></body></html>');
      } else if (this.pages[path]) out = Codec.httpResponse(200, 'OK', this.pages[path].body, this.pages[path].type);
      else if (path === '/' + 'index.html' && this.pages['/']) out = Codec.httpResponse(200, 'OK', this.pages['/'].body);
      else out = Codec.httpResponse(404, 'Not Found', '<html><body><h1>404 Not Found</h1><p>' + path.replace(/</g, '&lt;') + '</p></body></html>');
      this.log.push({ t: this.node.sim.now, client: IP.str(conn.rip), req: h.method + ' ' + h.uri, status: /^HTTP\/1\.1 (\d+)/.exec(B.bytesStr(out, 0, 15))[1] });
      if (this.log.length > 200) this.log.shift();
    }
    return out;
  }
  accept(conn, tls) {
    let buf = new Uint8Array(0);
    if (!tls) {
      conn.onData = d => {
        buf = B.concat(buf, d); const s = B.bytesStr(buf); const i = s.indexOf('\r\n\r\n'); if (i < 0) return;
        const m = /content-length:\s*(\d+)/i.exec(s); if (m && buf.length < i + 4 + (+m[1])) return;
        const out = this.respond(conn, buf, false); buf = new Uint8Array(0);
        conn.send(out); conn.close();
      };
      return;
    }
    // --- TLS simulé ---
    const st = { step: 0, crand: null, srand: null, seed: 0 };
    conn.onData = d => {
      if (st.step === 0) { // ClientHello
        st.crand = d.subarray(11, 43); st.srand = this.node.sim.rng.bytes(32); st.seed = TLS_SEED(st.crand, st.srand);
        const sh = Codec.tlsServerHello({ bytes: () => st.srand });
        const cert = Codec.tlsRecord(22, 0x0303, B.concat(Uint8Array.of(11, 0, 2, 0xf0), this.node.sim.rng.bytes(0x2f0 + 4 - 4)));
        const done = Codec.tlsRecord(22, 0x0303, Uint8Array.of(14, 0, 0, 0));
        conn.send(B.concat(sh, cert, done)); st.step = 1; st.rx = keystream(st.seed, 1); st.tx = keystream(st.seed, 2);
      } else if (st.step === 1) { // ClientKeyExchange + CCS + Finished
        conn.send(B.concat(Codec.tlsRecord(20, 0x0303, Uint8Array.of(1)), Codec.tlsRecord(22, 0x0303, this.node.sim.rng.bytes(40)))); st.step = 2;
      } else {
        // Application Data : [type 23][ver][len][chiffré]
        const body = xorStream(d.subarray(5), st.rx);
        const out = this.respond(conn, body, true);
        conn.send(Codec.tlsRecord(23, 0x0303, xorStream(out, st.tx))); conn.close();
      }
    };
  }
}
function installHttpClient(proto) {
  /* GET/POST http(s)://hote[:port]/chemin ; cb(err, {status, headers, body(string), ip}) */
  proto.httpRequest = function (url, cb, opts) {
    opts = opts || {};
    const m = /^(https?):\/\/([^\/:]+)(?::(\d+))?(\/.*)?$/i.exec(url.trim()) || /^()([^\/:]+)(?::(\d+))?(\/.*)?$/.exec(url.trim());
    if (!m) return cb('url');
    const tls = (m[1] || 'http').toLowerCase() === 'https'; const host = m[2], port = +(m[3] || (tls ? 443 : 80)), path = m[4] || '/';
    this.resolve(host, (err, r) => {
      if (err) return cb('dns:' + err);
      let buf = new Uint8Array(0); let finished = false; const done = (e, res) => { if (finished) return; finished = true; cb(e, res); };
      const parseResp = () => {
        const s = B.bytesStr(buf); const i = s.indexOf('\r\n\r\n'); if (i < 0) return null;
        const first = s.split('\r\n')[0]; const mm = /^HTTP\/1\.\d (\d+) ?(.*)$/.exec(first); if (!mm) return null;
        const headers = {}; s.slice(0, i).split('\r\n').slice(1).forEach(l => { const k = l.indexOf(':'); if (k > 0) headers[l.slice(0, k).toLowerCase()] = l.slice(k + 1).trim(); });
        return { status: +mm[1], reason: mm[2], headers, body: B.utf8Str(buf.subarray(i + 4)), ip: r.ip, url };
      };
      const st = { step: 0 };
      const req = Codec.httpRequest(opts.method || 'GET', host, path, { body: opts.body });
      const conn = this.tcpConnect(r.ip, port, {
        onOpen: c => {
          if (!tls) c.send(req);
          else { st.crand = this.sim.rng.bytes(32); const ch = Codec.tlsClientHello(host, { bytes: () => st.crand }); c.send(ch); }
        },
        onData: (d, c) => {
          if (!tls) { buf = B.concat(buf, d); return; }
          if (st.step === 0) { st.srand = d.subarray(11, 43); st.seed = TLS_SEED(st.crand, st.srand); st.tx = keystream(st.seed, 1); st.rx = keystream(st.seed, 2); st.step = 1;
            c.send(B.concat(Codec.tlsRecord(22, 0x0303, B.concat(Uint8Array.of(16, 0, 0, 0x42), this.sim.rng.bytes(0x42))), Codec.tlsRecord(20, 0x0303, Uint8Array.of(1)), Codec.tlsRecord(22, 0x0303, this.sim.rng.bytes(40)))); }
          else if (st.step === 1) { st.step = 2; c.send(Codec.tlsRecord(23, 0x0303, xorStream(req, st.tx))); }
          else { buf = B.concat(buf, xorStream(d.subarray(5), st.rx)); }
        },
        onClose: () => { const rr = parseResp(); if (rr) done(null, rr); else done('vide'); },
        onError: e => done(e),
      });
      if (!conn) done('noroute');
    });
  };
}

/* ================================================================== RIPv2 */
class Rip {
  constructor(node) { this.node = node; this.enabled = false; this.networks = []; this.passive = new Set(); this.timer = null; this.redistStatic = false; this.pending = false; this.defaultOrig = false; this.bound = false; }
  get sim() { return this.node.sim; }
  ifaces() {
    return this.node.ifaceList().filter(i => i.ip && i.isUp() && this.networks.some(n => IP.inNet(i.ip, n, IP.classMask(n))));
  }
  start() {
    if (this.enabled) return; this.enabled = true; const n = this.node;
    if (!n.joinedIp) n.joinedIp = new Set();
    n.joinedIp.add(IP.parse('224.0.0.9')); n.joined.add('01:00:5e:00:00:09');
    n.udpBind(520, (p, i) => this.input(p, i));
    this.sim.at(1, () => { this.request(); this.update(); });
    this.timer = this.sim.at(30000 + this.sim.rng.int(2000), () => this.tick());
  }
  stop() { this.enabled = false; if (this.timer) this.sim.cancel(this.timer); this.node.udpUnbind(520); this.node.dynRoutes = this.node.dynRoutes.filter(r => r.proto !== 'R'); }
  tick() {
    if (!this.enabled) return;
    this.expire(); this.update();
    this.timer = this.sim.at(30000, () => this.tick());
  }
  expire() {
    const n = this.node; const before = n.dynRoutes.length;
    n.dynRoutes = n.dynRoutes.filter(r => r.proto !== 'R' || this.sim.now - r.t < 180000);
    return before !== n.dynRoutes.length;
  }
  request() {
    this.ifaces().forEach(i => { if (this.passive.has(i.name)) return; this.node.udpSendOn(i, i.ip, IP.parse('224.0.0.9'), 520, 520, Codec.rip(1, [{ net: 0, mask: 0, metric: 16 }]), { ttl: 2 }); });
  }
  entriesFor(iface) {
    const n = this.node; const out = []; const seen = new Set();
    const add = (net, mask, metric) => { const k = net + '/' + mask; if (seen.has(k)) return; seen.add(k); out.push({ net, mask, nh: 0, metric: Math.min(16, metric) }); };
    this.ifaces().forEach(i => add(IP.net(i.ip, i.mask), i.mask, 1));
    n.dynRoutes.forEach(r => { if (r.proto === 'R' && r.iface !== iface) add(r.net, r.mask, r.metric + 1); });
    if (this.redistStatic) n.statics.forEach(s => { const r = n.allRoutes().find(x => x.proto === 'S' && x.net === s.net && x.mask === s.mask); if (r) add(s.net, s.mask, 1); });
    if (this.defaultOrig) add(0, 0, 1);
    return out.filter(e => !(IP.inNet(e.net, iface.ip, iface.mask) && e.mask === iface.mask && e.net === IP.net(iface.ip, iface.mask) && false));
  }
  update() {
    if (!this.enabled) return; const n = this.node;
    this.ifaces().forEach(i => {
      if (this.passive.has(i.name)) return;
      const es = this.entriesFor(i); if (!es.length) return;
      for (let k = 0; k < es.length; k += 25) n.udpSendOn(i, i.ip, IP.parse('224.0.0.9'), 520, 520, Codec.rip(2, es.slice(k, k + 25)), { ttl: 2 });
    });
  }
  triggered() { if (this.pending || !this.enabled) return; this.pending = true; this.sim.at(300 + this.sim.rng.int(700), () => { this.pending = false; this.update(); }); }
  input(p, iface) {
    if (!this.enabled || !p.rip) return; const r = p.rip; const n = this.node;
    if (!this.ifaces().includes(iface)) return;
    if (r.cmd === 1) { this.sim.at(50, () => { const es = this.entriesFor(iface); if (es.length) n.udpSendOn(iface, iface.ip, p.ip.src, 520, 520, Codec.rip(2, es.slice(0, 25)), { ttl: 2, dstMac: p.eth.src }); }); return; }
    if (p.ip.src === iface.ip) return;
    let changed = false;
    r.entries.forEach(e => {
      if (e.fam !== 2) return;
      const metric = e.metric;
      if (n.connectedRoutes().some(c => c.net === e.net && c.mask === e.mask)) return;
      const ex = n.dynRoutes.find(x => x.proto === 'R' && x.net === e.net && x.mask === e.mask);
      if (metric >= 16) { if (ex && ex.nh === p.ip.src) { n.dynRoutes = n.dynRoutes.filter(x => x !== ex); changed = true; } return; }
      if (!ex) { n.dynRoutes.push({ net: e.net, mask: e.mask, nh: p.ip.src, iface, proto: 'R', ad: 120, metric, t: this.sim.now }); changed = true; }
      else if (ex.nh === p.ip.src) { if (ex.metric !== metric) changed = true; ex.metric = metric; ex.t = this.sim.now; ex.iface = iface; }
      else if (metric < ex.metric) { Object.assign(ex, { nh: p.ip.src, iface, metric, t: this.sim.now }); changed = true; }
    });
    if (changed) this.triggered();
  }
}

NS.svc = { DhcpClient, DhcpServer, DhcpRelay, DnsServer, HttpServer, Rip, installResolver, installHttpClient };
if (NS.IPNode) { installResolver(NS.IPNode.prototype); installHttpClient(NS.IPNode.prototype); }
})(typeof window !== 'undefined' ? window : globalThis);
