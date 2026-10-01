/* ioscli_mgmt.js — commandes IOS : SNMP et syslog */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, Codec } = NS; const cmd = NS.iosCmd; const { pad } = NS.iosUtil; const { fmtVb, nameOf, SEVN, FACN } = NS.mib;
const bad = io => io.print("% Invalid input detected at '^' marker.\n");
const lvl = t => { t = String(t).toLowerCase(); if (/^[0-7]$/.test(t)) return +t; const k = SEVN.indexOf(t); if (k >= 0) return k; const al = { emergency: 0, alert: 1, error: 3, warning: 4, notification: 5, notice: 5, info: 6 }; return al[t] === undefined ? -1 : al[t]; };
const rtr = s => s.dev.mgmt;

/* ---------------- SNMP ---------------- */
cmd('config', 'snmp-server community <n> [<x...>]', (s, a, io) => { const rw = /\bRW\b/i.test(a.x || ''); rtr(s).setCommunity(a.n, rw ? 'rw' : 'ro'); });
cmd('config', 'no snmp-server community <n> [<x...>]', (s, a) => rtr(s).delCommunity(a.n));
cmd('config', 'snmp-server location <x...>', (s, a) => { rtr(s).snmp.location = a.x; });
cmd('config', 'no snmp-server location [<x...>]', (s) => { rtr(s).snmp.location = ''; });
cmd('config', 'snmp-server contact <x...>', (s, a) => { rtr(s).snmp.contact = a.x; });
cmd('config', 'no snmp-server contact [<x...>]', (s) => { rtr(s).snmp.contact = ''; });
cmd('config', 'snmp-server host <ip> <x...>', (s, a, io) => {
  const ip = IP.parse(a.ip); if (ip === null) { bad(io); return; } const t = a._rest; let ver = 0, inform = false, i = 0;
  while (i < t.length) { const w = t[i].toLowerCase(); if (w === 'informs') { inform = true; i++; } else if (w === 'traps') i++; else if (w === 'version') { const v = (t[i + 1] || '').toLowerCase(); if (v === '1') ver = 0; else if (v === '2c') ver = 1; else { io.print('% SNMPv3 n\'est pas pris en charge dans le simulateur (versions 1 et 2c).\n'); return; } i += 2; } else break; }
  const comm = t[i]; if (!comm) { bad(io); return; } rtr(s).addHost(ip, ver, comm, inform);
});
cmd('config', 'no snmp-server host <ip> [<x...>]', (s, a) => { const ip = IP.parse(a.ip); if (ip !== null) rtr(s).delHost(ip); });
cmd('config', 'snmp-server enable traps [<x...>]', (s, a) => { const x = (a.x || '').toLowerCase(); rtr(s).snmp.traps = true; if (/authentication/.test(x)) rtr(s).snmp.authTrap = true; });
cmd('config', 'no snmp-server enable traps [<x...>]', (s, a) => { rtr(s).snmp.traps = false; rtr(s).snmp.authTrap = false; });
cmd('config', 'snmp-server <x...>', () => { }); cmd('config', 'no snmp-server', (s) => { const m = rtr(s); m.snmp.comms.clear(); m.snmp.hosts = []; m.snmp.traps = false; m.snmp.location = ''; m.snmp.contact = ''; m.sync(); });

/* ---------------- syslog ---------------- */
cmd('config', 'logging <x...>', (s, a, io) => {
  const t = a._rest, L = rtr(s).lg, w = t[0].toLowerCase();
  if (w === 'host' || IP.parse(w) !== null) { const ip = IP.parse(w === 'host' ? t[1] : w); if (ip === null) { bad(io); return; } if (!L.hosts.includes(ip)) L.hosts.push(ip); return; }
  if (w === 'trap') { const k = lvl(t[1] || ''); if (k < 0) { bad(io); return; } L.trap = k; return; }
  if (w === 'buffered') { let i = 1; if (/^\d+$/.test(t[i] || '')) L.bufSize = Math.max(4096, +t[i++]); if (t[i]) { const k = lvl(t[i]); if (k >= 0) L.bufLevel = k; } return; }
  if (w === 'console' || w === 'monitor') { const k = lvl(t[1] || ''); if (k >= 0) L.console = k; return; }
  if (w === 'on') { L.on = true; return; }
  if (w === 'facility') { const f = FACN.indexOf((t[1] || '').toLowerCase()); if (f < 0) { bad(io); return; } L.facility = f; return; }
  if (w === 'source-interface') { const i = s.dev.ifaceByName(t.slice(1).join('')); if (!i) { bad(io); return; } L.src = i.name; return; }
});
cmd('config', 'no logging <x...>', (s, a) => {
  const t = a._rest, L = rtr(s).lg, w = t[0].toLowerCase();
  if (w === 'host' || IP.parse(w) !== null) { const ip = IP.parse(w === 'host' ? t[1] : w); L.hosts = L.hosts.filter(h => h !== ip); return; }
  if (w === 'on') { L.on = false; return; } if (w === 'trap') { L.trap = 6; return; } if (w === 'buffered') { L.bufSize = 4096; return; } if (w === 'source-interface') { L.src = null; return; } if (w === 'facility') { L.facility = 23; }
});
cmd('config', 'service sequence-numbers', (s) => { rtr(s).lg.seq = true; }); cmd('config', 'no service sequence-numbers', (s) => { rtr(s).lg.seq = false; });

/* ---------------- show ---------------- */
cmd('exec', 'show snmp', (s, a, io) => {
  const m = rtr(s), c = m.cnt, sn = m.snmp; let o = 'Chassis: ' + (s.dev.serial || 'FTX1234ABCD') + '\n';
  if (sn.contact) o += 'Contact: ' + sn.contact + '\n'; if (sn.location) o += 'Location: ' + sn.location + '\n';
  if (!sn.comms.size && !sn.hosts.length) { io.print('%SNMP agent not enabled\n'); return; }
  o += c.inPkts + ' SNMP packets input\n    ' + c.badVer + ' Bad SNMP version errors\n    ' + c.badComm + ' Unknown community name\n    0 Illegal operation for community name supplied\n    0 Encoding errors\n    ' + c.vars + ' Number of requested variables\n    ' + c.altered + ' Number of altered variables\n    ' + c.gets + ' Get-request PDUs\n    ' + c.nexts + ' Get-next PDUs\n    ' + c.sets + ' Set-request PDUs\n    0 Input queue packet drops (Maximum queue size 1000)\n';
  o += c.outPkts + ' SNMP packets output\n    ' + c.tooBig + ' Too big errors (Maximum packet size 1500)\n    ' + c.noSuch + ' No such name errors\n    0 Bad values errors\n    0 General errors\n    ' + c.outResp + ' Response PDUs\n    ' + c.traps + ' Trap PDUs\n';
  o += 'SNMP Dispatcher:\n   queue 0/75 (current/max), 0 dropped\nSNMP Engine:\n   queue 0/1000 (current/max), 0 dropped\n';
  o += 'SNMP global trap: ' + (sn.traps ? 'enabled' : 'disabled') + '\n';
  if (sn.hosts.length) { o += '\nSNMP logging: enabled\n'; sn.hosts.forEach(h => { o += '    Logging to ' + IP.str(h.ip) + '.162, 0/10, ' + h.sent + ' sent, 0 dropped.\n'; }); } else o += '\nSNMP logging: disabled\n';
  io.print(o);
});
cmd('exec', 'show snmp community', (s, a, io) => { const sn = rtr(s).snmp; let o = ''; sn.comms.forEach((mode, n) => { o += '\nCommunity name: ' + n + '\nCommunity Index: ' + n + '\nCommunity SecurityName: ' + n + '\nstorage-type: nonvolatile\t active\n'; }); io.print(o || '%No SNMP communities configured\n'); });
cmd('exec', 'show snmp host', (s, a, io) => { const sn = rtr(s).snmp; let o = ''; sn.hosts.forEach(h => { o += 'Notification host: ' + IP.str(h.ip) + '\tudp-port: 162   type: ' + (h.inform ? 'inform' : 'trap') + '\nuser: ' + h.community + '\tsecurity model: ' + (h.ver === 1 ? 'v2c' : 'v1') + '\n\n'; }); io.print(o || '%No SNMP hosts configured\n'); });
cmd('exec', 'show snmp <x...>', (s, a, io) => { io.print('\n'); });
cmd('exec', 'show logging [<x...>]', (s, a, io) => {
  const m = rtr(s), L = m.lg; const n = L.buf.length; let o = 'Syslog logging: ' + (L.on ? 'enabled' : 'disabled') + ' (0 messages dropped, 0 messages rate-limited, 0 flushes, 0 overruns, xml disabled, filtering disabled)\n\nNo Active Message Discriminator.\n\nNo Inactive Message Discriminator.\n\n';
  o += '    Console logging: level ' + SEVN[L.console] + ', ' + L.count + ' messages logged, xml disabled,\n                     filtering disabled\n    Monitor logging: level debugging, 0 messages logged, xml disabled,\n                     filtering disabled\n';
  o += '    Buffer logging:  level ' + SEVN[L.bufLevel] + ', ' + n + ' messages logged, xml disabled,\n                    filtering disabled\n    Exception Logging: size (4096 bytes)\n    Count and timestamp logging messages: ' + (L.seq ? 'enabled' : 'disabled') + '\n    Persistent logging: disabled\n\nNo active filter modules.\n\n';
  o += '    Trap logging: level ' + SEVN[L.trap] + ', ' + L.count + ' message lines logged\n';
  L.hosts.forEach(h => { const k = L.sent.get(h) || 0; o += '        Logging to ' + IP.str(h) + '  (udp port 514, audit disabled,\n              link up),\n              ' + k + ' message lines logged,\n              0 message lines rate-limited,\n              0 message lines dropped-by-MD,\n              xml disabled, sequence number ' + (L.seq ? 'enabled' : 'disabled') + '\n              filtering disabled\n'; });
  o += '\nLog Buffer (' + L.bufSize + ' bytes):\n\n' + L.buf.join('\n') + (n ? '\n' : ''); io.print(o);
});
cmd('exec', 'clear logging', (s) => { rtr(s).lg.buf = []; });

/* ---------------- running-config ---------------- */
NS.mgmtConfig = function (dev, p) {
  const m = dev.mgmt; if (!m) return; const L = m.lg, sn = m.snmp; let any = false; const q = t => { p(t); any = true; };
  if (L.seq) q('service sequence-numbers');
  if (L.bufSize !== 4096 || L.bufLevel !== 7) q('logging buffered ' + L.bufSize + (L.bufLevel !== 7 ? ' ' + SEVN[L.bufLevel] : ''));
  if (!L.on) q('no logging on'); if (L.trap !== 6) q('logging trap ' + SEVN[L.trap]); if (L.facility !== 23) q('logging facility ' + FACN[L.facility]); if (L.src) q('logging source-interface ' + L.src);
  L.hosts.forEach(h => q('logging host ' + IP.str(h)));
  if (sn.location) q('snmp-server location ' + sn.location); if (sn.contact) q('snmp-server contact ' + sn.contact);
  sn.comms.forEach((mode, n) => q('snmp-server community ' + n + ' ' + mode.toUpperCase()));
  if (sn.traps) q('snmp-server enable traps' + (sn.authTrap ? ' snmp authentication' : ''));
  sn.hosts.forEach(h => q('snmp-server host ' + IP.str(h.ip) + (h.inform ? ' informs' : ' traps') + ' version ' + (h.ver === 1 ? '2c' : '1') + ' ' + h.community));
  if (any) p('!');
};
})(typeof window !== 'undefined' ? window : globalThis);
