/* hostshell_aaa.js — serveur Linux FreeRADIUS (systemctl, radtest, users, clients.conf, radius.log) et supplicant 802.1X côté client */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {}; const { IP, Codec, HostShell } = NS; const L = HostShell.prototype.linCmds;
const USERS = '/etc/freeradius/3.0/users', CLIENTS = '/etc/freeradius/3.0/clients.conf', LOG = '/var/log/freeradius/radius.log', ACCT = '/var/log/freeradius/radacct/detail';
function usersText(r) { let o = '# users (simulateur)\n'; r.srv.users.forEach(u => { o += u.name + '\tCleartext-Password := "' + u.pass + '"' + (u.vlan ? ',\n\tTunnel-Type = VLAN,\n\tTunnel-Medium-Type = IEEE-802,\n\tTunnel-Private-Group-Id = "' + u.vlan + '"' : '') + '\n'; }); return o; }
function clientsText(r) { let o = '# clients.conf (simulateur)\n'; r.srv.clients.forEach(c => { o += 'client ' + c.name + ' {\n\tipaddr = ' + IP.str(c.ip) + ((c.mask >>> 0) !== 0xFFFFFFFF ? '/' + IP.prefixFromMask(c.mask) : '') + '\n\tsecret = ' + c.secret + '\n}\n'; }); return o; }
function fileText(h, p) {
  const r = h.radius; if (!r) return null;
  if (p === USERS) return usersText(r); if (p === CLIENTS) return clientsText(r);
  if (p === LOG) return r.authLog(); if (p === ACCT) return r.acctLog ? r.acctLog() : '';
  return null;
}
/* echo '...' >> fichier : ajout d'utilisateurs / de clients */
const echo0 = L.echo;
L.echo = function (a, io) {
  const i = a.findIndex(t => t === '>>' || t === '>'); if (i < 0) return echo0.call(this, a, io);
  const path = a[i + 1], app = a[i] === '>>'; const txt = a.slice(0, i).join(' ').replace(/^(["'])([\s\S]*)\1$/, '$2'); const h = this.host, r = h.radius;
  if (path !== USERS && path !== CLIENTS) { io.print('bash: ' + path + ': Permission non accordée\n'); return; }
  if (path === USERS) {
    if (!app) r.srv.users.clear();
    const m = /^(\S+)\s+Cleartext-Password\s*:?=\s*"([^"]*)"(.*)$/.exec(txt.trim()); if (!m) { io.print('users: syntaxe invalide (attendu : nom Cleartext-Password := "mot de passe"[, Tunnel-Private-Group-Id = "VLAN"])\n'); return; }
    const v = /Tunnel-Private-Group-Id\s*=\s*"?(\d+)/.exec(m[3]); r.addUser(m[1], m[2], { vlan: v ? +v[1] : null });
  } else {
    if (!app) r.srv.clients = [];
    const nm = /client\s+(\S+)/.exec(txt), ip = /ipaddr\s*=\s*([\d.]+)(?:\/(\d+))?/.exec(txt), sec = /secret\s*=\s*(\S+)/.exec(txt);
    if (!nm || !ip || !sec) { io.print('clients.conf: syntaxe invalide (attendu : client nom { ipaddr = A.B.C.D secret = xxx })\n'); return; }
    const ipv = IP.parse(ip[1]); r.addClient(ipv, ip[2] ? IP.maskFromPrefix(+ip[2]) : 0xFFFFFFFF, sec[1], nm[1]);
  }
};
const cat0 = L.cat; L.cat = function (a, io) { const t = fileText(this.host, a[0] || ''); if (t !== null) { io.print(t); return; } return cat0.call(this, a, io); };
const tail0 = L.tail; L.tail = function (a, io) { const f = a.filter(x => !/^-/.test(x) && !/^\d+$/.test(x))[0]; if (f === LOG || f === ACCT) { let n = 10; const k = a.indexOf('-n'); if (k >= 0) n = +a[k + 1]; const ls = (fileText(this.host, f) || '').split('\n').filter(Boolean); io.print(ls.slice(-n).join('\n') + (ls.length ? '\n' : '')); return; } return tail0.call(this, a, io); };
const grep0 = L.grep; L.grep = function (a, io) { const f = a.filter(x => !/^-/.test(x))[1]; if (f === LOG) { const pat = a.filter(x => !/^-/.test(x))[0].replace(/^"|"$/g, ''); const re = new RegExp(pat, a.includes('-i') ? 'i' : ''); io.print((fileText(this.host, f) || '').split('\n').filter(l => l && re.test(l)).join('\n') + '\n'); return; } return grep0.call(this, a, io); };
/* service */
const sc0 = L.systemctl;
L.systemctl = function (a, io) {
  const svc = (a[1] || '').replace('.service', ''); if (svc !== 'freeradius' && svc !== 'radiusd') return sc0.call(this, a, io);
  const r = this.host.radius, act = a[0];
  if (act === 'start' || act === 'restart') { if (act === 'restart') r.stopSrv(); r.startSrv(); } else if (act === 'stop') r.stopSrv();
  else if (act === 'status') io.print('● freeradius.service - FreeRADIUS multi-protocol policy server\n     Active: ' + (r.srv.enabled ? 'active (running)' : 'inactive (dead)') + '\n     Docs: man:radiusd(8)\n' + (r.srv.enabled ? '  Requêtes : ' + r.srv.stats.req + ' (Accept ' + r.srv.stats.acc + ', Reject ' + r.srv.stats.rej + ')\n' : ''));
  else if (act === 'enable' || act === 'disable') { }
  else return sc0.call(this, a, io);
};
/* radtest user password server[:port] nas-port-number secret */
L.radtest = function (a, io) {
  const h = this.host; const [user, pass, srv, nas, secret] = a; if (!secret) { io.print('Usage: radtest [OPTIONS] user passwd radius-server[:port] nas-port-number secret [<ppphint> <nasname>]\n'); return; }
  const host = srv.replace(/:\d+$/, ''); const port = /:(\d+)$/.exec(srv); const R = h.radius; const doit = ip => {
    const sv = { ip, key: secret, authPort: port ? +port[1] : 1812, acctPort: 1813, timeout: 3, retransmit: 2, stats: { sent: 0, timeouts: 0, retrans: 0, badAuth: 0, accept: 0, reject: 0, challenge: 0 } };
    const svs = [sv]; R.request(svs, (s, id, auth, src) => ({ dport: sv.authPort, bytes: Codec.radius({ code: 1, id, auth, secret, attrs: [{ t: 1, v: user }, { t: 2, v: Codec.radiusPap(pass, secret, auth) }, { t: 4, v: { ip: src } }, { t: 5, v: +nas || 0 }] }) }), res => {
      const hx = x => Array.from(x).map(b => b.toString(16).padStart(2, '0')).join('');
      io.print('Sent Access-Request Id ' + (res.packet ? res.packet.id : 0) + ' from ' + IP.str(h.mainIface.ip) + ' to ' + IP.str(ip) + ':' + sv.authPort + ' length 0\n\tUser-Name = "' + user + '"\n\tUser-Password = "' + pass + '"\n\tNAS-IP-Address = ' + IP.str(h.mainIface.ip) + '\n\tNAS-Port = ' + (+nas || 0) + '\n');
      if (res.res === 'timeout') io.print('radclient: no response from server (' + host + ') for ' + 0 + '\n'); else { const c = res.code; io.print('Received ' + (c === 2 ? 'Access-Accept' : c === 3 ? 'Access-Reject' : 'code ' + c) + ' Id ' + res.packet.id + ' from ' + IP.str(ip) + ':' + sv.authPort + ' to ' + IP.str(h.mainIface.ip) + ' length ' + res.packet.len + '\n'); (res.attrs || []).forEach(t => { if (t.t === 18) io.print('\tReply-Message = "' + Array.from(t.v).map(b => String.fromCharCode(b)).join('') + '"\n'); if (t.t === 81) io.print('\tTunnel-Private-Group-Id:0 = "' + Array.from(t.v).map(b => String.fromCharCode(b)).join('').replace(/^\W/, '') + '"\n'); }); }
      io.done();
    });
  };
  const ip = IP.parse(host); if (ip !== null) { doit(ip); return 'async'; }
  this.lookup(host, io, (err, r) => { if (err || !r) { io.print('radtest: Impossible de résoudre ' + host + '\n'); io.done(); return; } doit(r.ip !== undefined ? r.ip : r); }); return 'async';
};
/* supplicant 802.1X : wpa_supplicant-sim -u utilisateur -p mot_de_passe [-m md5|peap] | off | status */
L['wpa_supplicant-sim'] = function (a, io) {
  const d = this.host.dot1x; if (a[0] === 'off') { d.supEnable(false); io.print('802.1X supplicant arrêté\n'); return; }
  if (a[0] === 'status') { io.print('EAP state: ' + d.sup.state + '\n' + d.sup.log.slice(-6).map(l => l.msg).join('\n') + '\n'); return; }
  const o = { method: 'peap' }; for (let i = 0; i < a.length; i++) { if (a[i] === '-u') o.user = a[++i]; else if (a[i] === '-p') o.pass = a[++i]; else if (a[i] === '-m') o.method = a[++i]; }
  if (!o.user) { io.print('Usage: wpa_supplicant-sim -u utilisateur -p motdepasse [-m md5|peap] | status | off\n'); return; }
  d.supSet({ user: o.user, pass: o.pass || '', method: o.method }); d.supEnable(true); io.print('Successfully initialized wpa_supplicant (EAP-' + o.method.toUpperCase() + ', identité ' + o.user + ')\n');
};
})(typeof window !== 'undefined' ? window : globalThis);
