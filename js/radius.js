/* radius.js — serveur RADIUS (type FreeRADIUS/NPS), client AAA (routeur/switch), listes de méthodes */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS;
const cat = (...a) => { let n = 0; a.forEach(x => n += x.length); const r = new Uint8Array(n); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };
const sb = s => Uint8Array.from(Array.from(String(s)).map(c => c.charCodeAt(0) & 255)), bs = u => Array.from(u).map(c => String.fromCharCode(c)).join('');
const hx = u => Array.from(u).map(b => b.toString(16).padStart(2, '0')).join('');
const eqb = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const macDash = m => m.toUpperCase().replace(/:/g, '-'), macCisco = m => { const h = m.replace(/:/g, '').toLowerCase(); return h.slice(0, 4) + '.' + h.slice(4, 8) + '.' + h.slice(8, 12); }, macPlain = m => m.replace(/:/g, '').toLowerCase();
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], DAY = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const BASE_T = Date.UTC(2026, 8, 30, 8, 0, 0);
const p2 = n => String(n).padStart(2, '0');
const fdate = ms => { const d = new Date(BASE_T + ms); return DAY[d.getUTCDay()] + ' ' + MON[d.getUTCMonth()] + ' ' + p2(d.getUTCDate()) + ' ' + p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds()) + ' ' + d.getUTCFullYear(); };

/* ---- enrobage TLS factice pour PEAP (enregistrements réalistes, contenu opaque) ---- */
const tlsRec = (type, hsType, total, rng) => { const b = new Uint8Array(total); for (let i = 0; i < total; i++) b[i] = rng.int(256); b[0] = type; b[1] = 3; b[2] = type === 22 && hsType === 1 ? 1 : 3; b[3] = ((total - 5) >> 8) & 255; b[4] = (total - 5) & 255; if (type === 22) { b[5] = hsType; b[6] = 0; b[7] = ((total - 9) >> 8) & 255; b[8] = (total - 9) & 255; } return b; };
const flight = (parts, rng) => cat(...parts.map(p => tlsRec(p[0], p[1], p[2], rng)));
NS.peapTls = { tlsRec, flight };

class Radius {
  constructor(node) {
    this.node = node; this.reset();
  }
  get sim() { return this.node.sim; }
  reset() {
    (this.pend || []).forEach(x => x.timer && (x.timer.dead = true));
    if (this.srv && this.srv.enabled) this.stopSrv();
    this.srv = { enabled: false, clients: [], users: new Map(), eapType: 'peap', log: [], acct: [], stats: { req: 0, acc: 0, rej: 0, chal: 0, dropped: 0, acctReq: 0, badMac: 0 }, sessions: new Map(), seq: 0, cert: 'CN=radius.lab.local' };
    this.servers = []; this.groups = new Map(); this.srcIf = null; this.pend = []; this.idc = 0;
    this.aaa = { newModel: false, login: new Map(), dot1x: new Map(), authz: new Map(), acct: new Map() }; this.deadtime = 0;
    this.defaults = { timeout: 5, retransmit: 3, key: '' };
  }
  /* ================================================================ serveur */
  startSrv() { const s = this.srv; if (s.enabled) return; s.enabled = true; const n = this.node; [1812, 1645].forEach(pt => n.udpBind(pt, (p, i) => this.srvAuth(p, i))); [1813, 1646].forEach(pt => n.udpBind(pt, (p, i) => this.srvAcct(p, i))); this.slog('Info: Ready to process requests'); }
  stopSrv() { const s = this.srv; if (!s.enabled) return; s.enabled = false; [1812, 1645, 1813, 1646].forEach(pt => this.node.udpUnbind(pt)); }
  slog(t) { this.srv.log.push(fdate(this.sim.now) + ' : ' + t); if (this.srv.log.length > 500) this.srv.log.shift(); }
  addClient(ip, mask, secret, name) { const s = this.srv; s.clients = s.clients.filter(c => !(c.ip === ip && c.mask === mask)); s.clients.push({ ip, mask: mask === undefined ? 0xFFFFFFFF : mask, secret, name: name || IP.str(ip) }); }
  addUser(name, pass, o) { this.srv.users.set(name, Object.assign({ name, pass, vlan: null, reply: '', disabled: false }, o || {})); }
  findClient(ip) { let best = null; this.srv.clients.forEach(c => { if (IP.inNet(ip, c.ip & c.mask, c.mask) && (!best || c.mask > best.mask)) best = c; }); return best; }
  reply(p, c, code, attrs, reqAuth) {
    const bytes = Codec.radius({ code, id: p.radius.id, reqAuth: p.radius.auth, secret: c.secret, attrs }); const n = this.node;
    n.udpSend(p.ip.src, p.udp.sport, p.udp.dport, bytes, { src: p.ip.dst });
  }
  acceptAttrs(u, extra) {
    const a = []; if (u && u.reply) a.push({ t: 18, v: u.reply });
    if (u && u.vlan) a.push({ t: 64, v: 13 }, { t: 65, v: 6 }, { t: 81, v: String(u.vlan) });
    return a.concat(extra || []);
  }
  srvAuth(p, iface) {
    const s = this.srv; const r = p.radius; if (!r || r.code !== 1) return; const c = this.findClient(p.ip.src); s.stats.req++;
    if (!c) { s.stats.dropped++; this.slog('Error: Ignoring request to auth address * port ' + p.udp.dport + ' bound to server default from unknown client ' + IP.str(p.ip.src) + ' port ' + p.udp.sport + ' proto udp'); return; }
    if (!Codec.radiusVerifyMac(p.udp.payload, r.auth, c.secret, false)) { s.stats.badMac++; s.stats.dropped++; this.slog('Error: Received packet from ' + IP.str(p.ip.src) + ' with invalid Message-Authenticator!  (Shared secret is incorrect.)'); return; }
    const from = '(from client ' + c.name + ' port ' + (Codec.radiusGet(r.attrs, 5) ? new DataView(Codec.radiusGet(r.attrs, 5).buffer, Codec.radiusGet(r.attrs, 5).byteOffset, 4).getUint32(0) : 0) + (Codec.radiusGetStr(r.attrs, 31) ? ' cli ' + Codec.radiusGetStr(r.attrs, 31) : '') + ')';
    const user = Codec.radiusGetStr(r.attrs, 1) || '';
    if (Codec.radiusGet(r.attrs, 79)) return this.srvEap(p, c, r, user, from);
    const enc = Codec.radiusGet(r.attrs, 2); const pass = enc ? Codec.radiusPapDecode(enc, c.secret, r.auth) : '';
    const u = s.users.get(user); const nseq = ++s.seq;
    if (u && !u.disabled && u.pass === pass) { s.stats.acc++; this.slog('Auth: (' + nseq + ') Login OK: [' + user + '/<via Auth-Type = PAP>] ' + from); this.reply(p, c, 2, this.acceptAttrs(u)); }
    else { s.stats.rej++; this.slog('Auth: (' + nseq + ') Login incorrect (' + (!u ? 'No such user' : u.disabled ? 'Account disabled' : 'pap: Login incorrect (Invalid password)') + '): [' + user + '/' + (u ? '<via Auth-Type = PAP>' : '<no User-Password attribute>') + '] ' + from); this.reply(p, c, 3, [{ t: 18, v: 'Authentication failed' }]); }
  }
  /* ---- EAP ---- */
  eapReq(st, type, data) { st.eid = (st.eid + 1) & 255; return Codec.eap({ code: 1, id: st.eid, type, data }); }
  challenge(p, c, st, eapBytes) {
    const attrs = [{ t: 79, v: eapBytes }, { t: 24, v: st.state }]; this.srv.stats.chal++; this.reply(p, c, 11, attrs);
  }
  finish(p, c, st, ok, user, from) {
    const s = this.srv; const nseq = ++s.seq; s.sessions.delete(hx(st.state));
    if (ok) { s.stats.acc++; this.slog('Auth: (' + nseq + ') Login OK: [' + user + '/<via Auth-Type = EAP>] ' + from); this.reply(p, c, 2, this.acceptAttrs(s.users.get(user), [{ t: 79, v: Codec.eap({ code: 3, id: st.eid }) }])); }
    else { s.stats.rej++; this.slog('Auth: (' + nseq + ') Login incorrect (' + (s.users.get(user) ? 'eap: Failed to validate the credentials' : 'No such user') + '): [' + user + '/<via Auth-Type = EAP>] ' + from); this.reply(p, c, 3, [{ t: 79, v: Codec.eap({ code: 4, id: st.eid }) }]); }
  }
  srvEap(p, c, r, user, from) {
    const s = this.srv; const rng = this.sim.rng; const eap = r.eap; if (!eap) return; const stt = Codec.radiusGet(r.attrs, 24); let st = stt ? s.sessions.get(hx(stt)) : null;
    if (!st) { // nouvelle conversation : attend EAP-Response/Identity
      if (eap.type !== 1 || eap.code !== 2) { this.slog('Error: EAP conversation without state, ignoring'); return; }
      const ident = bs(eap.data); st = { state: rng.bytes(16), eid: eap.id, user: ident, method: s.eapType, step: 0, t: this.sim.now, from };
      s.sessions.set(hx(st.state), st); this.sim.at(120000, () => s.sessions.delete(hx(st.state)));
      const u = s.users.get(ident); this.slog('Info: (' + (s.seq + 1) + ') eap: Peer sent EAP Response (code 2) ID ' + eap.id + ' length ' + (5 + eap.data.length) + ' (Identity: ' + ident + ')');
      if (!u && st.method === 'md5') return this.finish(p, c, st, false, ident, from);
      if (st.method === 'md5') { st.chal = rng.bytes(16); return this.challenge(p, c, st, this.eapReq(st, 4, cat(Uint8Array.of(16), st.chal))); }
      return this.challenge(p, c, st, this.eapReq(st, 25, Uint8Array.of(0x20)));
    }
    st.from = from; const u = s.users.get(st.user);
    if (eap.type === 3) { // NAK : le client propose un autre type
      const want = eap.data[0]; if (want === 4 && !st.tried4) { st.method = 'md5'; st.tried4 = true; st.chal = rng.bytes(16); return this.challenge(p, c, st, this.eapReq(st, 4, cat(Uint8Array.of(16), st.chal))); }
      if (want === 25 && !st.tried25) { st.method = 'peap'; st.tried25 = true; st.step = 0; return this.challenge(p, c, st, this.eapReq(st, 25, Uint8Array.of(0x20))); }
      return this.finish(p, c, st, false, st.user, from);
    }
    if (eap.type === 1 && st.step === 'inner') return this.finish(p, c, st, false, st.user, from);
    if (st.method === 'md5') {
      if (eap.type !== 4) return this.finish(p, c, st, false, st.user, from);
      const want = u && !u.disabled ? Codec.md5(cat(Uint8Array.of(eap.id), sb(u.pass), st.chal)) : null; const got = eap.data.slice(1, 17);
      return this.finish(p, c, st, !!want && eqb(want, got), st.user, from);
    }
    // ---- PEAP (simplifié : poignée de main TLS + MSCHAPv2 dans le tunnel) ----
    if (eap.type !== 25) { return this.finish(p, c, st, false, st.user, from); }
    const pi = Codec.peapInfo(eap.data);
    if (st.step === 0) { // reçu ClientHello -> envoie ServerHello + certificat (fragmenté)
      st.flight = flight([[22, 2, 90], [22, 11, 1210], [22, 14, 9]], rng); st.fo = 0; st.step = 1; const first = st.flight.slice(0, 1002); st.fo = 1002;
      const len = st.flight.length; return this.challenge(p, c, st, this.eapReq(st, 25, cat(Uint8Array.of(0xC0), new Uint8Array([(len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255]), first)));
    }
    if (st.step === 1) { // ack du fragment -> suite du vol
      const rest = st.flight.slice(st.fo); st.step = 2; return this.challenge(p, c, st, this.eapReq(st, 25, cat(Uint8Array.of(0x00), rest)));
    }
    if (st.step === 2) { // ClientKeyExchange/CCS/Finished reçus -> CCS + Finished
      st.step = 3; return this.challenge(p, c, st, this.eapReq(st, 25, cat(Uint8Array.of(0), flight([[20, 0, 6], [22, 20, 45]], rng))));
    }
    if (st.step === 3) { // ack -> demande d'identité interne (chiffrée)
      st.step = 4; return this.challenge(p, c, st, this.eapReq(st, 25, cat(Uint8Array.of(0), tlsRec(23, 0, 34, rng))));
    }
    if (st.step === 4) { // identité interne reçue (chiffrée, contient le nom d'utilisateur en clair dans notre simulation, sous XOR)
      const t = pi.tls; const inner = bs(Codec.md5(sb('peap-id|' + st.user)).slice(0, 0)); st.innerUser = st.user; st.mchal = rng.bytes(16); st.step = 5;
      return this.challenge(p, c, st, this.eapReq(st, 25, cat(Uint8Array.of(0), (() => { const b = tlsRec(23, 0, 5 + 16 + 24, rng); b.set(st.mchal, 5); return b; })())));
    }
    if (st.step === 5) { // réponse MSCHAPv2 : 16 octets de "hash" après l'en-tête d'enregistrement
      const t = pi.tls; const got = t.slice(5, 21); const want = u && !u.disabled ? Codec.md5(cat(sb(u.pass), st.mchal, sb(st.user))) : null; st.ok = !!want && eqb(want, got);
      st.step = 6; const b = tlsRec(23, 0, 5 + 40, rng); return this.challenge(p, c, st, this.eapReq(st, 25, cat(Uint8Array.of(0), b)));
    }
    if (st.step === 6) { return this.finish(p, c, st, st.ok, st.user, from); }
    return this.finish(p, c, st, false, st.user, from);
  }
  srvAcct(p, iface) {
    const s = this.srv; const r = p.radius; if (!r || r.code !== 4) return; const c = this.findClient(p.ip.src); if (!c) { s.stats.dropped++; return; }
    const bytes = p.udp.payload.slice(); bytes.fill(0, 4, 20); const want = Codec.md5(cat(bytes, sb(c.secret))); if (!eqb(want, r.auth)) { s.stats.dropped++; this.slog('Error: Received Accounting-Request packet from client ' + c.name + ' with invalid Request Authenticator!  (Shared secret is incorrect.)'); return; }
    s.stats.acctReq++; const st = Codec.radiusGet(r.attrs, 40); const stv = st ? new DataView(st.buffer, st.byteOffset, 4).getUint32(0) : 0;
    s.acct.push({ t: this.sim.now, client: c.name, user: Codec.radiusGetStr(r.attrs, 1) || '', status: ({ 1: 'Start', 2: 'Stop', 3: 'Interim-Update' })[stv] || String(stv), session: Codec.radiusGetStr(r.attrs, 44) || '', station: Codec.radiusGetStr(r.attrs, 31) || '' });
    this.reply(p, c, 5, []);
  }
  authLog() { return this.srv.log.join('\n') + (this.srv.log.length ? '\n' : ''); }
  acctLog() { return this.srv.acct.map(a => fdate(a.t) + '\n\tAcct-Status-Type = ' + a.status + '\n\tUser-Name = "' + a.user + '"\n\tAcct-Session-Id = "' + a.session + '"\n\tCalling-Station-Id = "' + a.station + '"\n\tNAS = ' + a.client + '\n').join('\n'); }

  /* ================================================================ client (NAS) */
  addServer(o) {
    let s = this.servers.find(x => x.name === o.name || (o.ip && x.ip === o.ip && x.authPort === (o.authPort || 1812)));
    if (!s) { s = { name: o.name || 'RADIUS' + (this.servers.length + 1), ip: 0, authPort: 1812, acctPort: 1813, key: '', timeout: 0, retransmit: 0, stats: { sent: 0, accept: 0, reject: 0, challenge: 0, timeouts: 0, badAuth: 0, retrans: 0 }, dead: 0 }; this.servers.push(s); }
    Object.assign(s, o); return s;
  }
  delServer(name) { this.servers = this.servers.filter(x => x.name !== name && IP.str(x.ip) !== name); this.groups.forEach(g => { g.servers = g.servers.filter(x => x !== name); }); }
  groupServers(group) {
    if (!group || group === 'radius') return this.servers.filter(s => s.ip);
    const gr = this.groups.get(group); if (!gr) return [];
    return gr.servers.map(nm => this.servers.find(s => s.name === nm || IP.str(s.ip) === nm)).filter(Boolean);
  }
  srcAddr(dst) {
    if (this.srcIf) { const i = this.node.ifaceByName(this.srcIf); if (i && i.ip) return i.ip; }
    const r = this.node.lookup(dst); return r && r.iface ? r.iface.ip : 0;
  }
  /* envoie une requête à une liste de serveurs ; cb({res, code, attrs, eap, server, packet}) */
  request(servers, build, cb) {
    const n = this.node; const list = servers.filter(x => !(x.dead && this.sim.now < x.dead));
    if (!list.length) { cb({ res: 'timeout' }); return; }
    let si = 0;
    const tryServer = () => {
      if (si >= list.length) { cb({ res: 'timeout' }); return; }
      const sv = list[si]; let tries = 0; const to = (sv.timeout || this.defaults.timeout) * 1000, maxT = (sv.retransmit !== undefined && sv.retransmit !== 0 ? sv.retransmit : this.defaults.retransmit) + 1;
      const id = (this.idc = (this.idc + 1) & 255); const auth = this.sim.rng.bytes(16); const src = this.srcAddr(sv.ip); const port = n.nextPort(); const pend = { timer: null }; this.pend.push(pend);
      const req = build(sv, id, auth, src);  const ra = req.bytes.slice(4, 20); let done = false;
      const fin = (r) => { if (done) return; done = true; if (pend.timer) pend.timer.dead = true; n.udpUnbind(port); this.pend = this.pend.filter(x => x !== pend); if (r) { cb(Object.assign({ server: sv }, r)); } else { si++; tryServer(); } };
      n.udpBind(port, (p) => {
        const r = p.radius; if (!r || p.ip.src !== sv.ip || r.id !== id) return;
        if (!Codec.radiusVerifyResp(p.udp.payload, ra, sv.key) || !Codec.radiusVerifyMac(p.udp.payload, ra, sv.key, true)) { sv.stats.badAuth++; n.log('RADIUS: response from ' + IP.str(sv.ip) + ' failed the authenticator check (wrong shared key ?)', 'warn'); return; }
        if (r.code === 2) sv.stats.accept++; else if (r.code === 3) sv.stats.reject++; else if (r.code === 11) sv.stats.challenge++;
        fin({ res: r.code === 2 ? 'accept' : r.code === 3 ? 'reject' : r.code === 11 ? 'challenge' : r.code === 5 ? 'acct' : 'other', code: r.code, attrs: r.attrs, eap: r.eap, packet: r });
      });
      const send = () => {
        if (done) return; if (tries >= maxT) { sv.stats.timeouts++; sv.dead = this.deadtime ? this.sim.now + this.deadtime * 60000 : 0; n.log('%RADIUS-4-RADIUS_DEAD: RADIUS server ' + IP.str(sv.ip) + ':' + sv.authPort + ',' + sv.acctPort + ' is not responding.', 'warn'); fin(null); return; }
        if (tries > 0) sv.stats.retrans++; tries++; sv.stats.sent++; n.udpSend(sv.ip, req.dport || sv.authPort, port, req.bytes, { src }); pend.timer = this.sim.at(to, send);
      };
      send();
    };
    tryServer();
  }
  attrsBase(extra, srcIp, nasPort) {
    const a = [{ t: 4, v: { ip: srcIp } }, { t: 32, v: this.node.name }]; if (nasPort !== undefined) a.push({ t: 5, v: nasPort }); return a.concat(extra || []);
  }
  authPap(group, user, pass, cb, extra) {
    const svs = this.groupServers(group); if (!svs.length) { cb({ res: 'timeout', nogroup: true }); return; }
    this.request(svs, (sv, id, auth, src) => ({ dport: sv.authPort, bytes: Codec.radius({ code: 1, id, auth, secret: sv.key, attrs: [{ t: 1, v: user }, { t: 2, v: Codec.radiusPap(pass, sv.key, auth) }].concat(this.attrsBase(extra, src, 0)) }) }), cb);
  }
  /* liste de méthodes : ['group radius', 'local', 'none'] */
  methods(kind, name) { const m = this.aaa[kind].get(name || 'default'); return m || null; }
  aaaLogin(list, user, pass, cb) {
    const methods = this.methods('login', list); const n = this.node; if (!methods) { cb(false, 'nolist'); return; }
    let i = 0; const next = () => {
      if (i >= methods.length) { cb(false, 'exhausted'); return; } const m = methods[i++];
      if (m.startsWith('group')) { const grp = m.split(/\s+/)[1]; this.authPap(grp, user, pass, r => { if (r.res === 'accept') cb(true, 'radius'); else if (r.res === 'reject') cb(false, 'radius'); else next(); }); }
      else if (m === 'local') { const ok = (n.users || []).some(u => u.name === user && u.secret === pass); cb(ok, 'local'); }
      else if (m === 'none') cb(true, 'none'); else if (m === 'enable') cb(pass === n.enableSecret, 'enable'); else if (m === 'line') cb(pass === n.vty.password, 'line'); else next();
    }; next();
  }
  /* comptabilité (accounting) */
  acct(group, status, user, session, station) {
    const svs = this.groupServers(group); if (!svs.length) return;
    this.request(svs, (sv, id, auth, src) => ({ dport: sv.acctPort, bytes: Codec.radius({ code: 4, id, secret: sv.key, attrs: [{ t: 40, v: status }, { t: 1, v: user }, { t: 44, v: session }, { t: 31, v: station }, { t: 61, v: 15 }].concat(this.attrsBase([], src)) }) }), () => { });
  }
}
NS.Radius = Radius; NS.radiusUtil = { macDash, macCisco, macPlain, fdate };
})(typeof window !== 'undefined' ? window : globalThis);
