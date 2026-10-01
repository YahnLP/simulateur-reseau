/* host_persist.js — sérialisation des services d'hôte ajoutés après coup : SNMP/syslog, IPv6, serveur RADIUS, supplicant 802.1X */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {}; const { IP, Host } = NS; const IP6 = NS.IP6;
const ser = Host.prototype.serialize, res = Host.prototype.restore;
Host.prototype.serialize = function () {
  const b = ser.call(this);
  const m = this.mgmt; if (m) b.mgmt = { comms: Array.from(m.snmp.comms), location: m.snmp.location, contact: m.snmp.contact, syslogd: m.syslogd.enabled, trapd: m.trapd.enabled };
  if (this.ip6) {
    const ifs = []; this.ifaceList().forEach(i => { if (!i.v6) return; ifs.push({ name: i.name, autoconf: i.v6.autoconf, addrs: i.v6.addrs.filter(a => a.kind === 'manual').map(a => IP6.str(a.addr) + '/' + a.plen) }); });
    b.v6 = { ifs, statics: (this.ip6.statics || []).map(s => ({ net: IP6.str(s.net), plen: s.plen, nh: s.nh === null || s.nh === undefined ? null : IP6.str(s.nh), iface: s.iface, ad: s.ad })) };
  }
  const r = this.radius; if (r && r.srv && (r.srv.enabled || r.srv.users.size || r.srv.clients.length)) b.rad = { enabled: r.srv.enabled, eapType: r.srv.eapType, clients: r.srv.clients.map(c => ({ ip: IP.str(c.ip), mask: IP.str(c.mask), secret: c.secret, name: c.name })), users: Array.from(r.srv.users.values()).map(u => ({ name: u.name, pass: u.pass, vlan: u.vlan, reply: u.reply, disabled: u.disabled })) };
  const d = this.dot1x; if (d && (d.sup.enabled || d.sup.user)) b.sup = { enabled: d.sup.enabled, user: d.sup.user, pass: d.sup.pass, method: d.sup.method };
  const v = this.voip; if (v && v.cfg.ext) b.voip = { cfg: Object.assign({}, v.cfg, { server: IP.str(v.cfg.server || 0) }), reg: v.reg.state === 'registered' };
  const P = this.pbx; if (P && (P.enabled || P.peers.size || P.routes.length)) b.pbx = { enabled: P.enabled, realm: P.realm, peers: Array.from(P.peers.values()).map(p => ({ name: p.name, secret: p.secret, callerid: p.callerid, host: p.host, context: p.context, codecs: p.codecs })), trunks: Array.from(P.trunks.values()).map(t => ({ name: t.name, host: IP.str(t.host), context: t.context })), routes: P.routes };
  return b;
};
Host.prototype.restore = function (b) {
  res.call(this, b);
  if (b.mgmt && this.mgmt) { const m = this.mgmt; (b.mgmt.comms || []).forEach(c => m.setCommunity(c[0], c[1])); m.snmp.location = b.mgmt.location || ''; m.snmp.contact = b.mgmt.contact || ''; if (b.mgmt.syslogd) m.startSyslogd(); if (b.mgmt.trapd) m.startTrapd(); }
  if (b.v6 && this.ip6) {
    (b.v6.ifs || []).forEach(c => { const i = this.ifaceByName(c.name); if (!i) return; const s = this.ip6.enable(i); s.autoconf = c.autoconf !== false; (c.addrs || []).forEach(a => { const [ad, pl] = a.split('/'); this.ip6.addAddr(i, IP6.parse(ad), +pl, 'manual'); }); });
    this.ip6.statics = (b.v6.statics || []).map(s => ({ net: IP6.parse(s.net), plen: s.plen, nh: s.nh === null ? null : IP6.parse(s.nh), iface: s.iface, ad: s.ad }));
  }
  if (b.rad && this.radius) { const r = this.radius; r.srv.eapType = b.rad.eapType || 'peap'; b.rad.clients.forEach(c => r.addClient(IP.parse(c.ip), IP.parse(c.mask), c.secret, c.name)); b.rad.users.forEach(u => r.addUser(u.name, u.pass, { vlan: u.vlan, reply: u.reply, disabled: u.disabled })); if (b.rad.enabled) r.startSrv(); }
  if (b.pbx && this.pbx) { const P = this.pbx; P.realm = b.pbx.realm || 'asterisk'; b.pbx.peers.forEach(p => P.addPeer(p.name, p.secret, p)); b.pbx.trunks.forEach(t => P.addTrunk(t.name, t.host, { context: t.context })); P.routes = b.pbx.routes || []; if (b.pbx.enabled) P.start(); }
  if (b.voip && this.voip) { const v = this.voip; v.configure(Object.assign({}, b.voip.cfg)); if (b.voip.reg) this.sim.at(1000, () => v.register()); }
  if (b.sup && this.dot1x) { this.dot1x.supSet({ user: b.sup.user, pass: b.sup.pass, method: b.sup.method }); if (b.sup.enabled) this.dot1x.supEnable(true); }
};
})(typeof window !== 'undefined' ? window : globalThis);
