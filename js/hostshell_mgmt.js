/* hostshell_mgmt.js — commandes Linux de supervision : snmpget/snmpwalk/…, snmptrap, logger, rsyslog/snmpd/snmptrapd */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec, HostShell } = NS; const M = NS.mib; const L = HostShell.prototype.linCmds;

const requote = a => (a.join(' ').match(/"[^"]*"|'[^']*'|\S+/g) || []).map(t => /^(["']).*\1$/.test(t) ? t.slice(1, -1) : t);
function parseOpts(a, name, io) {
  a = requote(a);
  const o = { ver: 1, community: 'public', numeric: false, q: false, v: false, args: [], to: 1000, retries: 2 };
  for (let i = 0; i < a.length; i++) {
    const t = a[i];
    if (/^-v/.test(t)) { const v = t.length > 2 ? t.slice(2) : a[++i]; if (v === '1') o.ver = 0; else if (v === '2c') o.ver = 1; else if (v === '3') { io.print(name + ': SNMPv3 n\'est pas pris en charge dans le simulateur (versions 1 et 2c)\n'); return null; } else { io.print('Invalid version specified after -v flag: ' + v + '\n'); return null; } }
    else if (/^-c/.test(t)) o.community = t.length > 2 ? t.slice(2) : a[++i];
    else if (t === '-On') o.numeric = true; else if (t === '-Oq') o.q = true; else if (t === '-Ov') o.v = true;
    else if (/^-O/.test(t) || /^-C/.test(t)) { if (t === '-Cr') o.rep = +a[++i]; }
    else if (t === '-t') o.to = (+a[++i] || 1) * 1000; else if (t === '-r') o.retries = +a[++i] || 0;
    else if (/^-/.test(t)) { }
    else o.args.push(t);
  }
  return o;
}
function target(o, io, name, cb) {
  const h = o.args.shift(); if (!h) { io.print('Usage: ' + name + ' [OPTIONS] AGENT [OID]...\n'); return false; }
  const host = h.replace(/^udp:/i, '').replace(/:161$/, '');
  return host;
}
function withHost(sh, host, io, name, fn) {
  sh.lookup(host, io, (err, r) => { if (err || !r) { io.print(name + ': Unknown host (' + host + ') ' + (err === 'nodns' ? 'Name or service not known' : 'Temporary failure in name resolution') + '\n'); io.done(); return; } fn(r.ip); });
  return 'async';
}
function reportErr(o, host, err, res, io, vbOids) {
  if (err === 'timeout') { io.print('Timeout: No Response from ' + host + '.\n'); return true; }
  if (err === 'unreachable') { io.print('Timeout: No Response from ' + host + '.\n'); return true; }
  if (err === 'err' && res) { io.print('Error in packet.\nReason: ' + errReason(res.errStatus) + '\n'); return true; }
  if (err) { io.print(err + '\n'); return true; } return false;
}
const ERRTXT = { 1: '(tooBig) Response message would have been too large.', 2: '(noSuchName) There is no such variable name in this MIB.', 3: '(badValue) The value given has the wrong type or length.', 4: '(readOnly) The two parties are not allowed to modify this variable.', 5: '(genError) A general failure occured', 6: '(noAccess) Access denied', 7: '(wrongType) The set datatype does not match the data type the agent expects', 10: '(wrongValue) The set value is illegal or unsupported in some way', 17: '(notWritable) A variable which can not be modified' };
const errReason = c => ERRTXT[c] || 'error ' + c;
function simple(op, name) {
  return function (a, io) {
    const sh = this, h = sh.host; const o = parseOpts(a, name, io); if (!o) return; const host = target(o, io, name); if (!host) return;
    if (!o.args.length && op !== 'walk') { io.print('No log or oid specified\n'); return; }
    if (h.mgmt === null) return;
    const oids = []; for (const x of o.args) { const oo = M.parseOid(x); if (!oo) { io.print(x + ': Unknown Object Identifier (Sub-id not found: (top) -> ' + x + ')\n'); return; } oids.push(oo); }
    return withHost(sh, host, io, name, dst => {
      h.mgmt.query(dst, { ver: o.ver, community: o.community, op, vbs: oids.map(x => ({ oid: M.os(x), t: 'null' })), timeout: o.to, retries: o.retries }, (err, res) => {
        if (reportErr(o, host, err, res, io)) return io.done();
        const P = res.pdu; if (P.errStatus) { io.print('Error in packet.\nReason: ' + errReason(P.errStatus) + '\nFailed object: ' + (P.varbinds[P.errIdx - 1] ? (o.numeric ? '.' : '') + (o.numeric ? P.varbinds[P.errIdx - 1].oid : M.nameOf(P.varbinds[P.errIdx - 1].oid)) : '') + '\n'); return io.done(); }
        P.varbinds.forEach(vb => io.print(M.fmtVb(vb, o) + '\n')); io.done();
      });
    });
  };
}
L.snmpget = simple('get', 'snmpget'); L.snmpgetnext = simple('getnext', 'snmpgetnext');
function walkCmd(bulkDefault, name) {
  return function (a, io) {
    const sh = this, h = sh.host; const o = parseOpts(a, name, io); if (!o) return; const host = target(o, io, name); if (!host) return;
    const root = o.args.length ? M.parseOid(o.args[0]) : [1, 3, 6, 1, 2, 1]; if (!root) { io.print(o.args[0] + ': Unknown Object Identifier (Sub-id not found: (top) -> ' + o.args[0] + ')\n'); return; }
    o.ver = o.ver; let n = 0;
    return withHost(sh, host, io, name, dst => {
      h.mgmt.walk(dst, { ver: o.ver, community: o.community, timeout: o.to, retries: o.retries, abort: () => sh.aborted, noBulk: !bulkDefault && o.ver === 1 && false }, root, vb => { n++; io.print(M.fmtVb(vb, o) + '\n'); }, (err, res) => {
        if (err === 'timeout' || err === 'unreachable') io.print('Timeout: No Response from ' + host + '.\n');
        else if (err === 'err') io.print('Error in packet.\nReason: ' + errReason(res && res.errStatus) + '\n');
        else if (err === 'loop') io.print('Error: OID not increasing: ' + M.os(root) + '\n');
        else if (!err && n === 0) { io.print(M.nameOf(M.os(root)) + ' = No more variables left in this MIB View (It is past the end of the MIB tree)\n'); }
        io.done();
      });
    });
  };
}
L.snmpwalk = walkCmd(false, 'snmpwalk'); L.snmpbulkwalk = walkCmd(true, 'snmpbulkwalk');
/* snmpset host oid type value … */
L.snmpset = function (a, io) {
  const sh = this, h = sh.host; const o = parseOpts(a, 'snmpset', io); if (!o) return; const host = target(o, io, 'snmpset'); if (!host) return;
  if (o.args.length < 3 || (o.args.length - 0) % 3) { io.print('snmpset: Missing type/value for variable\n'); return; }
  const vbs = []; for (let i = 0; i < o.args.length; i += 3) {
    const oo = M.parseOid(o.args[i]); if (!oo) { io.print(o.args[i] + ': Unknown Object Identifier\n'); return; } const ty = o.args[i + 1], v = o.args[i + 2];
    const vb = { oid: M.os(oo) }; if (ty === 'i') { vb.t = 'int'; vb.v = parseInt(v, 10); } else if (ty === 'u') { vb.t = 'g32'; vb.v = +v; } else if (ty === 's') { vb.t = 'oct'; vb.v = v.replace(/^"|"$/g, ''); } else if (ty === 'a') { vb.t = 'ip'; vb.v = IP.parse(v); } else if (ty === 'o') { vb.t = 'oid'; vb.v = v.replace(/^\./, ''); } else if (ty === 't') { vb.t = 'tt'; vb.v = +v; } else { io.print('snmpset: Bad variable type "' + ty + '"\n'); return; } vbs.push(vb);
  }
  return withHost(sh, host, io, 'snmpset', dst => {
    h.mgmt.query(dst, { ver: o.ver, community: o.community, op: 'set', vbs, timeout: o.to, retries: o.retries }, (err, res) => {
      if (reportErr(o, host, err, res, io)) return io.done(); const P = res.pdu;
      if (P.errStatus) { io.print('Error in packet.\nReason: ' + errReason(P.errStatus) + '\nFailed object: ' + M.nameOf(vbs[Math.max(0, P.errIdx - 1)].oid) + '\n'); return io.done(); }
      P.varbinds.forEach(vb => io.print(M.fmtVb(vb, o) + '\n')); io.done();
    });
  });
};
/* snmptrap -v 2c -c public host '' TRAP-OID [oid type value …]  (envoie un trap de test) */
L.snmptrap = function (a, io) {
  const sh = this, h = sh.host; const o = parseOpts(a, 'snmptrap', io); if (!o) return; const host = target(o, io, 'snmptrap'); if (!host) return;
  const up = o.args.shift(); const trapOid = M.parseOid(o.args.shift() || '') || M.parseOid('coldStart');
  return withHost(sh, host, io, 'snmptrap', dst => {
    const tt = Math.floor(h.sim.now / 10); const vbs = [{ oid: '1.3.6.1.2.1.1.3.0', t: 'tt', v: tt }, { oid: '1.3.6.1.6.3.1.1.4.1.0', t: 'oid', v: M.os(trapOid) }];
    for (let i = 0; i + 2 < o.args.length + 0; i += 3) { const oo = M.parseOid(o.args[i]); const ty = o.args[i + 1]; const v = o.args[i + 2]; if (oo) vbs.push({ oid: M.os(oo), t: ty === 'i' ? 'int' : 'oct', v: ty === 'i' ? +v : v }); }
    const b = Codec.snmp({ ver: 1, community: o.community, pdu: { type: 'trap2', reqId: 1 + h.sim.rng.int(2e9), varbinds: vbs } });
    h.udpSend(dst, 162, h.nextPort(), b, {}); io.done();
  });
};
/* logger [-n serveur] [-P port] [-p fac.sev] [-t tag] message */
L.logger = function (a, io) {
  const h = this.host; let host = null, port = 514, fac = 1, sev = 5, tag = 'etudiant'; const msg = [];
  for (let i = 0; i < a.length; i++) { const t = a[i]; if (t === '-n') host = a[++i]; else if (t === '-P') port = +a[++i]; else if (t === '-t') tag = a[++i]; else if (t === '-p') { const m = /^(\w+)\.(\w+)$/.exec(a[++i] || ''); if (m) { const f = Codec.SYSLOG_FAC.indexOf(m[1]); const sv = M.SEVN.findIndex(x => x.startsWith(m[2])) >= 0 ? M.SEVN.findIndex(x => x.startsWith(m[2])) : ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'].indexOf(m[2]); if (f >= 0) fac = f; if (sv >= 0) sev = sv; } } else if (/^-/.test(t) && !msg.length) { } else msg.push(t); }
  if (!msg.length) return; const text = msg.join(' ').replace(/^"|"$/g, '');
  if (!host) { h.mgmt.logger(null, text, { fac, sev, tag }); return; }
  return withHost(this, host, io, 'logger', dst => { h.mgmt.logger(dst, text, { fac, sev, tag, port }); io.done(); });
};
/* fichiers de journaux */
const lcat = L.cat;
function fileText(h, path) {
  if (path === '/var/log/syslog' || path === '/var/log/messages') return h.mgmt.fileSyslog();
  if (path === '/var/log/snmptrapd.log') return h.mgmt.trapd.entries.map(e => h.mgmt.trapLine(e)).join('\n') + (h.mgmt.trapd.entries.length ? '\n' : '');
  if (path === '/etc/snmp/snmpd.conf') { const s = h.mgmt.snmp; let o = '# snmpd.conf (simulateur)\nagentaddress udp:161\nsyslocation ' + (s.location || 'Unknown') + '\nsyscontact ' + (s.contact || 'root@localhost') + '\n'; s.comms.forEach((m, n) => { o += (m === 'rw' ? 'rwcommunity ' : 'rocommunity ') + n + '\n'; }); return o; }
  return null;
}
L.cat = function (a, io) { const t = fileText(this.host, a[0] || ''); if (t !== null) { io.print(t); return; } return lcat.call(this, a, io); };
L.tail = function (a, io) { let n = 10, f = null; for (let i = 0; i < a.length; i++) { if (a[i] === '-n') n = +a[++i]; else if (/^-\d+$/.test(a[i])) n = -a[i]; else if (a[i] === '-f') { } else f = a[i]; } const t = fileText(this.host, f || ''); if (t === null) { io.print('tail: impossible d\'ouvrir \'' + (f || '') + '\' en lecture: Aucun fichier ou dossier de ce type\n'); return; } const ls = t.split('\n').filter(Boolean); io.print(ls.slice(-n).join('\n') + (ls.length ? '\n' : '')); };
L.grep = function (a, io) { let ic = false, f = null, pat = null; a.forEach(t => { if (t === '-i') ic = true; else if (/^-/.test(t)) { } else if (pat === null) pat = t; else f = t; }); const t = f ? fileText(this.host, f) : null; if (pat === null || t === null) { io.print('grep: ' + (f || '') + ': Aucun fichier ou dossier de ce type\n'); return; } const re = new RegExp(pat.replace(/^"|"$/g, ''), ic ? 'i' : ''); io.print(t.split('\n').filter(l => l && re.test(l)).join('\n') + '\n'); };
/* services */
const sysctl = L.systemctl;
L.systemctl = function (a, io) {
  const h = this.host, act = a[0], svc = (a[1] || '').replace('.service', ''); const m = h.mgmt;
  const map = { snmpd: { get on() { return m.snmp.comms.size > 0; }, start() { if (!m.snmp.comms.size) m.setCommunity('public', 'ro'); }, stop() { m.snmp.comms.clear(); m.sync(); } }, rsyslog: { get on() { return m.syslogd.enabled; }, start() { m.startSyslogd(); }, stop() { m.stopSyslogd(); } }, snmptrapd: { get on() { return m.trapd.enabled; }, start() { m.startTrapd(); }, stop() { m.stopTrapd(); } } };
  const s = map[svc]; if (!s) return sysctl.call(this, a, io);
  if (act === 'start' || act === 'restart') { if (act === 'restart') s.stop(); s.start(); } else if (act === 'stop') s.stop(); else if (act === 'status') io.print('● ' + svc + '.service\n     Active: ' + (s.on ? 'active (running)' : 'inactive (dead)') + '\n');
};
})(typeof window !== 'undefined' ? window : globalThis);
