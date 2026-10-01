/* dot1x.js — IEEE 802.1X : authentificateur (switch) + supplicant (poste), EAP-MD5 et PEAP simplifié, MAB, VLAN dynamique / invité */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec } = NS; const U = NS.radiusUtil; const T = NS.peapTls;
const cat = (...a) => { let n = 0; a.forEach(x => n += x.length); const r = new Uint8Array(n); let o = 0; a.forEach(x => { r.set(x, o); o += x.length; }); return r; };
const sb = s => Uint8Array.from(Array.from(String(s)).map(c => c.charCodeAt(0) & 255));
const hx = u => Array.from(u).map(b => b.toString(16).padStart(2, '0')).join('');
const PAE = '01:80:c2:00:00:03';
const shortIf = n => n.replace('GigabitEthernet', 'Gi').replace('FastEthernet', 'Fa');

class Dot1x {
  constructor(node) { this.node = node; this.enabled = false; this.sidn = 0; this.sup = { enabled: false, user: '', pass: '', method: 'peap', state: 'disabled', log: [], phase: null, app: 0, frag: 0, id: 0 }; node.joined.add(PAE); node.ifHooks.push(i => { const sp = this.sup; if (!sp.enabled) return; if (i.isUp()) this.supStart(); else sp.state = 'connecting'; }); }
  get sim() { return this.node.sim; }
  reset() {
    this.enabled = false; this.node.ports.forEach(p => { this.clearPort(p, true); delete p.dx; delete p.dxs; });
    Object.assign(this.sup, { enabled: false, user: '', pass: '', method: 'peap', state: 'disabled', log: [] });
  }
  /* ================================================================ authentificateur */
  cfg(port) { if (!port.dx) port.dx = { mode: null, host: 'single-host', guest: null, fail: null, order: ['dot1x'], tx: 30, maxReq: 2, reauth: null, mab: false, quiet: 60 }; return port.dx; }
  st(port) { if (!port.dxs) port.dxs = { sess: new Map(), timer: null, tries: 0, seen: new Set(), eapolSeen: false, guestOn: false, nasPortId: 0 }; return port.dxs; }
  active(port) { return this.enabled && port.dx && port.dx.mode === 'auto' && !port.routed && !port.virtual; }
  authorizedCount(port) { let n = 0; const s = port.dxs; if (!s) return 0; s.sess.forEach(x => { if (x.state === 'auth') n++; }); return n; }
  vlanOf(port) { return port.dynVlan || port.vlan; }
  /* filtre en entrée : true = on laisse passer */
  allows(port, src, p) {
    const c = port.dx; if (c.mode === 'force-unauthorized') return false; const s = this.st(port);
    if (s.guestOn) return true; const x = s.sess.get(src);
    if (x && x.state === 'auth') return true;
    if (c.host === 'multi-host' && this.authorizedCount(port) > 0) return true;
    return false;
  }
  egressAllows(port, dst) {
    const c = port.dx; if (c.mode === 'force-unauthorized') return false; const s = this.st(port); if (s.guestOn) return true;
    if (c.host === 'multi-host') return this.authorizedCount(port) > 0;
    if (dst === 'ff:ff:ff:ff:ff:ff' || MAC.isMulticast(dst)) return this.authorizedCount(port) > 0;
    const x = s.sess.get(dst); return !!(x && x.state === 'auth');
  }
  noteDrop(port, src) { const s = this.st(port); if (!MAC.isMulticast(src) && s.seen.size < 8) s.seen.add(src); }
  sid(port) { this.sidn++; const ip = this.node.primaryIface && this.node.primaryIface.ip ? this.node.primaryIface.ip : 0; return (ip >>> 0).toString(16).toUpperCase().padStart(8, '0') + '0000' + this.sidn.toString(16).toUpperCase().padStart(4, '0') + '00' + (Math.floor(this.sim.now / 1000) & 0xffff).toString(16).toUpperCase().padStart(4, '0') + '000'; }
  ifn(port) { return shortIf(port.name); }
  tx(port, dst, eapolType, eap) { const n = this.node; const f = Codec.frame({ dst, src: n.baseMac, type: 0x888e, payload: eapolType === 0 ? Codec.eapol(0, eap) : Codec.eapol(eapolType) }); n.sendL(port, f); }
  portChanged(port) {
    if (!this.enabled || !port.dx) return; if (!port.up) { this.clearPort(port, false); return; }
    if (this.active(port)) this.startPort(port);
  }
  clearPort(port, silent) {
    const s = port.dxs; if (!s) return; if (s.timer) { s.timer.dead = true; s.timer = null; }
    s.sess.forEach(x => { if (x.timer) x.timer.dead = true; if (x.state === 'auth' && !silent) this.acctStop(port, x); }); s.sess.clear(); s.seen.clear(); s.tries = 0; s.eapolSeen = false; s.guestOn = false; port.dynVlan = null;
  }
  startPort(port) {
    if (!port.up) return; this.clearPort(port, false); const s = this.st(port), c = port.dx; s.tries = 0; s.eapolSeen = false; const start = () => {
      s.timer = null; if (!port.up || !this.active(port)) return;
      if (s.eapolSeen || (this.authorizedCount(port) > 0 && c.host !== 'multi-auth')) return;
      if (s.tries > c.maxReq) { this.noResponse(port); return; }
      if (!s.eapolSeen || s.tries === 0) { s.tries++; this.identityReq(port, PAE, 0); }
      s.timer = this.sim.at(c.tx * 1000, start);
    };
    s.timer = this.sim.at(200, start);
  }
  identityReq(port, dst, id) { this.tx(port, dst, 0, Codec.eap({ code: 1, id: id & 255, type: 1, data: new Uint8Array(0) })); }
  noResponse(port) {
    const c = port.dx, s = this.st(port); s.timer = null;
    if (c.order.includes('mab') || c.mab) { const macs = Array.from(s.seen).filter(m => !s.sess.get(m) || s.sess.get(m).state !== 'auth'); if (macs.length && !s.mabDone) { s.mabDone = true; macs.forEach(m => this.mab(port, m)); return; } }
    if (c.guest && !s.guestOn && !s.eapolSeen && this.authorizedCount(port) === 0) { s.guestOn = true; port.dynVlan = c.guest; this.node.log('%AUTHMGR-5-VLANASSIGN: VLAN ' + c.guest + ' assigned to Interface ' + this.ifn(port) + ' (guest VLAN)', 'info'); this.node.stp && this.node.stp.portChanged && 0; }
  }
  /* ---- réception d'une trame EAPOL sur un port authentifié ---- */
  authInput(port, p) {
    const c = port.dx; if (!c || !this.active(port)) return; const s = this.st(port), e = p.eapol, src = p.eth.src;
    s.eapolSeen = true; if (s.guestOn) { s.guestOn = false; port.dynVlan = null; }
    let x = s.sess.get(src); if (!x) { x = { mac: src, state: 'unauth', user: '', sid: this.sid(port), eid: 0, rState: null, t: this.sim.now, method: 'dot1x', vlan: null, busy: false }; s.sess.set(src, x); }
    if (e.type === 1) { x.state = 'unauth'; x.rState = null; x.eid = (x.eid + 1) & 255; this.identityReq(port, src, x.eid); return; }
    if (e.type === 2) { if (x.state === 'auth') { this.deauth(port, x, 'logoff'); } return; }
    if (e.type !== 0 || !e.eap) return; const eap = e.eap;
    if (eap.code !== 2) return; if (x.state === 'held') return;
    if (eap.type === 1) { x.user = String.fromCharCode.apply(null, Array.from(eap.data)); x.rState = null; x.method = 'dot1x'; }
    if (x.busy) return; this.radiusEap(port, x, Codec.eap(eap));
  }
  radiusEap(port, x, eapBytes) {
    const n = this.node, R = n.radius; const list = R.methods('dot1x', 'default'); const grp = list && list.find(m => m.startsWith('group')); const servers = R.groupServers(grp ? grp.split(/\s+/)[1] : null);
    if (!servers.length || !R.aaa.newModel || !list) { n.log('%DOT1X-5-FAIL: Authentication failed for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'warn'); x.state = 'fail'; return; }
    x.busy = true; const nasPort = 50000 + (port.idx || 0) + 1;
    R.request(servers, (sv, id, auth, src) => {
      const attrs = [{ t: 1, v: x.user }, { t: 4, v: { ip: src } }, { t: 5, v: nasPort }, { t: 61, v: 15 }, { t: 6, v: 2 }, { t: 30, v: U.macDash(n.baseMac) + ':' + shortIf(port.name) }, { t: 31, v: U.macDash(x.mac) }, { t: 32, v: n.name }, { t: 79, v: eapBytes }];
      if (x.rState) attrs.push({ t: 24, v: x.rState }); return { dport: sv.authPort, bytes: Codec.radius({ code: 1, id, auth, secret: sv.key, attrs }) };
    }, r => {
      x.busy = false; if (!port.up) return;
      if (r.res === 'timeout') { n.log('%RADIUS-4-RADIUS_DEAD: RADIUS server ' + servers.map(s => IP.str(s.ip) + ':' + s.authPort + ',' + s.acctPort).join(' ') + ' is not responding.', 'warn'); this.fail(port, x, false); return; }
      const eap = r.eap; const rs = Codec.radiusGet(r.attrs, 24); if (rs) x.rState = rs;
      if (r.res === 'challenge' && eap) { x.eid = eap.id; const raw = cat(...r.attrs.filter(a => a.t === 79).map(a => a.v)); this.tx(port, x.mac, 0, raw); return; }
      if (r.res === 'accept') { if (eap) this.tx(port, x.mac, 0, cat(...r.attrs.filter(a => a.t === 79).map(a => a.v))); this.success(port, x, r.attrs, 'dot1x'); return; }
      if (r.res === 'reject') { if (eap) this.tx(port, x.mac, 0, cat(...r.attrs.filter(a => a.t === 79).map(a => a.v))); this.fail(port, x, true); }
    });
  }
  mab(port, mac) {
    const n = this.node, R = n.radius; const list = R.methods('dot1x', 'default'); const grp = list && list.find(m => m.startsWith('group')); const plain = U.macPlain(mac); const s = this.st(port);
    let x = s.sess.get(mac); if (!x) { x = { mac, state: 'unauth', user: plain, sid: this.sid(port), eid: 0, rState: null, t: this.sim.now, method: 'mab', vlan: null }; s.sess.set(mac, x); } x.user = plain; x.method = 'mab';
    if (!R.aaa.newModel || !list) return;
    R.authPap(grp ? grp.split(/\s+/)[1] : null, plain, plain, r => {
      if (!port.up) return;
      if (r.res === 'accept') this.success(port, x, r.attrs, 'mab'); else { x.state = 'fail'; this.node.log('%MAB-5-FAIL: Authentication failed for client (' + U.macCisco(mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'warn'); this.applyFailVlan(port); this.noResponseGuest(port); }
    }, [{ t: 6, v: 10 }, { t: 61, v: 15 }, { t: 31, v: U.macDash(mac) }, { t: 5, v: 50000 + (port.idx || 0) + 1 }]);
  }
  noResponseGuest(port) { const c = port.dx, s = this.st(port); if (c.guest && !s.guestOn && this.authorizedCount(port) === 0 && !c.fail) { s.guestOn = true; port.dynVlan = c.guest; } }
  vlanFromAttrs(attrs) {
    const tt = Codec.radiusGet(attrs, 64), mt = Codec.radiusGet(attrs, 65), gid = Codec.radiusGet(attrs, 81); if (!gid) return null;
    const t = tt ? new DataView(tt.buffer, tt.byteOffset, 4).getUint32(0) : 13; if (t !== 13) return null; let str = String.fromCharCode.apply(null, Array.from(gid)); if (gid[0] < 32) str = str.slice(1); const v = parseInt(str, 10); return isNaN(v) ? null : v;
  }
  success(port, x, attrs, method) {
    const n = this.node; const vlan = this.vlanFromAttrs(attrs);
    if (vlan !== null && !n.vlans.has(vlan)) { n.log('%AUTHMGR-5-FAIL: Authorization failed for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid + ' (VLAN ' + vlan + ' does not exist)', 'warn'); x.state = 'fail'; return; }
    x.state = 'auth'; x.method = method; x.vlan = vlan; x.t = this.sim.now; const s = this.st(port); s.guestOn = false; if (vlan !== null) port.dynVlan = vlan; else port.dynVlan = null;
    if (method === 'dot1x') n.log('%DOT1X-5-SUCCESS: Authentication successful for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'info'); else n.log('%MAB-5-SUCCESS: Authentication successful for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'info');
    n.log('%AUTHMGR-5-SUCCESS: Authorization succeeded for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'info');
    if (vlan !== null) n.log('%AUTHMGR-5-VLANASSIGN: VLAN ' + vlan + ' assigned to Interface ' + this.ifn(port) + ' (dynamic)', 'info');
    this.acctStart(port, x); const c = port.dx; if (c.reauth) { x.timer = this.sim.at(c.reauth * 1000, () => { if (x.state === 'auth' && port.up) this.reauth(port, x); }); }
  }
  fail(port, x, rejected) {
    const n = this.node; x.state = 'fail'; n.log('%DOT1X-5-FAIL: Authentication failed for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'warn'); n.log('%AUTHMGR-5-FAIL: Authorization failed for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'warn');
    this.applyFailVlan(port); const c = port.dx; x.state = 'held'; x.timer = this.sim.at(c.quiet * 1000, () => { if (x.state === 'held') { x.state = 'unauth'; x.rState = null; } });
  }
  applyFailVlan(port) { const c = port.dx; if (c.fail && n_has(this.node, c.fail)) { port.dynVlan = c.fail; const s = this.st(port); s.guestOn = true; s.failOn = true; } }
  deauth(port, x, why) {
    if (x.timer) { x.timer.dead = true; x.timer = null; } this.acctStop(port, x); x.state = 'unauth'; x.rState = null; const s = this.st(port); if (this.authorizedCount(port) === 0) port.dynVlan = null;
    this.node.log('%AUTHMGR-5-' + (why === 'logoff' ? 'LOGOFF' : 'CLEAR') + ': Session cleared for client (' + U.macCisco(x.mac) + ') on Interface ' + this.ifn(port) + ' AuditSessionID ' + x.sid, 'info');
  }
  reauth(port, x) { this.tx(port, x.mac, 0, Codec.eap({ code: 1, id: (x.eid = (x.eid + 1) & 255), type: 1, data: new Uint8Array(0) })); x.rState = null; }
  reauthenticate(port) { const s = this.st(port); if (!s.sess.size) { this.startPort(port); return; } s.sess.forEach(x => { if (x.method === 'mab') { this.mab(port, x.mac); } else { x.state = 'unauth'; this.reauth(port, x); } }); }
  clearSessions(port) { this.clearPort(port, false); if (this.active(port) && port.up) this.startPort(port); }
  acctList() { const l = this.node.radius.methods('acct', 'default'); return l; }
  acctStart(port, x) { const l = this.node.radius.aaa.acct.get('dot1x'); if (!l) return; const grp = l.find(m => m.startsWith('group')); this.node.radius.acct(grp ? grp.split(/\s+/)[1] : null, 1, x.user, x.sid, U.macDash(x.mac)); }
  acctStop(port, x) { const l = this.node.radius.aaa.acct.get('dot1x'); if (!l) return; const grp = l.find(m => m.startsWith('group')); this.node.radius.acct(grp ? grp.split(/\s+/)[1] : null, 2, x.user, x.sid, U.macDash(x.mac)); }

  /* ================================================================ supplicant (poste) */
  supLog(t) { const s = this.sup; s.log.push({ t: this.sim.now, msg: t }); if (s.log.length > 60) s.log.shift(); }
  supSet(o) { Object.assign(this.sup, o); }
  supEnable(on) { const s = this.sup; s.enabled = !!on; s.state = on ? 'connecting' : 'disabled'; if (on) this.supStart(); }
  supIface() { return this.node.ifaceList().find(i => i.port) || null; }
  supStart() {
    const s = this.sup; if (!s.enabled) return; const i = this.supIface(); if (!i || !i.isUp()) return; s.state = 'connecting'; s.phase = null; s.app = 0; s.flight = null;
    this.sim.at(100, () => { if (s.enabled && i.isUp()) { this.node.sendFrame(i, PAE, 0x888e, Codec.eapol(1)); this.supLog('EAPOL-Start envoyé'); } });
  }
  supTx(iface, eap) { this.node.sendFrame(iface, PAE, 0x888e, Codec.eapol(0, eap)); }
  supInput(iface, p) {
    const s = this.sup; if (!s.enabled) return; const e = p.eapol; if (!e || e.type !== 0 || !e.eap) return; const eap = e.eap; const rng = this.sim.rng; const T4 = 4, T25 = 25;
    if (eap.code === 3) { s.state = 'authenticated'; this.supLog('Authentification réussie'); const c = this.node.dhcpClients && this.node.dhcpClients.get(iface.name); if (c && iface.dhcp && c.state !== 'BOUND') { c.start(); } else this.node.arpAnnounce && this.node.arpAnnounce(iface); return; }
    if (eap.code === 4) { s.state = 'failed'; this.supLog('Authentification échouée'); return; }
    if (eap.code !== 1) return; s.state = 'authenticating';
    const reply = (type, data) => this.supTx(iface, Codec.eap({ code: 2, id: eap.id, type, data }));
    if (eap.type === 1) { s.phase = null; s.app = 0; this.supLog('Identité demandée -> ' + s.user); reply(1, sb(s.user)); return; }
    const want = s.method === 'md5' ? T4 : T25;
    if (eap.type !== want && (eap.type === T4 || eap.type === T25)) { this.supLog('Méthode ' + eap.type + ' refusée (NAK, souhaité ' + want + ')'); reply(3, Uint8Array.of(want)); return; }
    if (eap.type === T4) { const vs = eap.data[0]; const chal = eap.data.slice(1, 1 + vs); reply(4, cat(Uint8Array.of(16), Codec.md5(cat(Uint8Array.of(eap.id), sb(s.pass), chal)))); return; }
    if (eap.type === T25) {
      const pi = Codec.peapInfo(eap.data);
      if (pi.start) { s.phase = 'hello'; reply(25, cat(Uint8Array.of(0), T.flight([[22, 1, 187]], rng))); return; }
      if (pi.more) { reply(25, Uint8Array.of(0)); return; }
      if (s.phase === 'hello') { s.phase = 'cke'; reply(25, cat(Uint8Array.of(0), T.flight([[22, 16, 139], [20, 0, 6], [22, 20, 45]], rng))); return; }
      if (s.phase === 'cke') { s.phase = 'app'; reply(25, Uint8Array.of(0)); return; }
      if (s.phase === 'app') {
        s.app++;
        if (s.app === 1) { reply(25, cat(Uint8Array.of(0), T.tlsRec(23, 0, 5 + 27, rng))); return; }
        if (s.app === 2) { const chal = pi.tls.slice(5, 21); const b = T.tlsRec(23, 0, 5 + 16 + 33, rng); b.set(Codec.md5(cat(sb(s.pass), chal, sb(s.user))), 5); reply(25, cat(Uint8Array.of(0), b)); return; }
        reply(25, cat(Uint8Array.of(0), T.tlsRec(23, 0, 5 + 6, rng))); return;
      }
    }
  }
}
function n_has(node, vlan) { return node.vlans && node.vlans.has(vlan); }
NS.Dot1x = Dot1x;
if (NS.IPNode) { const P = NS.IPNode.prototype; const in0 = P.input; P.input = function (iface, p) { if (p.eapol) { if (this.dot1x) this.dot1x.supInput(iface, p); return; } return in0.call(this, iface, p); }; }
})(typeof window !== 'undefined' ? window : globalThis);
