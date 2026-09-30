/* ioscli_aaa.js — commandes IOS : AAA, RADIUS, 802.1X (dot1x / MAB), show / test / clear */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP } = NS; const cmd = NS.iosCmd; const { pad, padL } = NS.iosUtil; const U = NS.radiusUtil;
const bad = io => io.print("% Invalid input detected at '^' marker.\n");
const R = s => s.dev.radius, D = s => s.dev.dot1x;
const ports = s => s.items().map(it => it.port).filter(Boolean);
const shortIf = n => n.replace('GigabitEthernet', 'Gi').replace('FastEthernet', 'Fa');

/* ------------------------------------------------------------------ AAA */
function parseMethods(toks) {
  const m = []; for (let i = 0; i < toks.length; i++) { const t = toks[i].toLowerCase(); if (t === 'group') { if (!toks[i + 1]) return null; m.push('group ' + toks[++i]); } else if (['local', 'none', 'enable', 'line', 'local-case'].includes(t)) m.push(t); else if (['start-stop', 'stop-only', 'start-only'].includes(t)) continue; else return null; }
  return m;
}
cmd('config', 'aaa new-model', s => { R(s).aaa.newModel = true; }); cmd('config', 'no aaa new-model', s => { R(s).aaa.newModel = false; });
cmd('config', 'aaa authentication login <n> <x...>', (s, a, io) => { const m = parseMethods(a._rest); if (!m || !m.length) return bad(io); R(s).aaa.login.set(a.n, m); });
cmd('config', 'no aaa authentication login <n>', (s, a) => R(s).aaa.login.delete(a.n));
cmd('config', 'aaa authentication dot1x <n> <x...>', (s, a, io) => { const m = parseMethods(a._rest); if (!m || !m.length) return bad(io); R(s).aaa.dot1x.set(a.n, m); });
cmd('config', 'no aaa authentication dot1x <n>', (s, a) => R(s).aaa.dot1x.delete(a.n));
cmd('config', 'aaa authorization network <n> <x...>', (s, a, io) => { const m = parseMethods(a._rest); if (!m) return bad(io); R(s).aaa.authz.set(a.n, m); });
cmd('config', 'aaa accounting dot1x <n> <x...>', (s, a, io) => { const m = parseMethods(a._rest); if (!m) return bad(io); R(s).aaa.acct.set('dot1x', m); });
cmd('config', 'no aaa accounting dot1x <n>', (s) => R(s).aaa.acct.delete('dot1x'));
cmd('config', 'aaa authentication <x...>', () => { }); cmd('config', 'aaa authorization <x...>', () => { }); cmd('config', 'aaa accounting <x...>', () => { }); cmd('config', 'aaa <x...>', () => { }); cmd('config', 'no aaa <x...>', () => { });
cmd('line', 'login authentication <l>', (s, a) => { s.dev.vty.loginList = a.l; s.dev.vty.login = true; s.dev.vty.local = false; });
cmd('line', 'no login authentication [<l>]', (s) => { s.dev.vty.loginList = null; });

/* ------------------------------------------------------------------ serveurs RADIUS */
function srvOpts(sv, toks, io) {
  for (let i = 0; i < toks.length; i++) { const t = toks[i].toLowerCase(); if (t === 'auth-port') sv.authPort = +toks[++i]; else if (t === 'acct-port') sv.acctPort = +toks[++i]; else if (t === 'key') { let k = toks[++i]; if (k === '0' || k === '7') k = toks[++i]; sv.key = k; } else if (t === 'timeout') sv.timeout = +toks[++i]; else if (t === 'retransmit') sv.retransmit = +toks[++i]; else if (t === 'pac' || t === 'test') { i++; } }
}
cmd('config', 'radius server <n>', (s, a) => { const r = R(s); let sv = r.servers.find(x => x.name === a.n); if (!sv) sv = r.addServer({ name: a.n, key: r.defaults.key }); s.mode = 'radsrv'; s.ctx = { name: a.n }; });
cmd('config', 'no radius server <n>', (s, a) => R(s).delServer(a.n));
const sv = s => R(s).servers.find(x => x.name === s.ctx.name);
cmd('radsrv', 'address ipv4 <ip> [<x...>]', (s, a, io) => { const ip = IP.parse(a.ip); if (ip === null) return bad(io); const v = sv(s); v.ip = ip; srvOpts(v, a._rest || [], io); });
cmd('radsrv', 'key <k> [<x...>]', (s, a) => { let k = a.k; if ((k === '0' || k === '7') && a._rest && a._rest[0]) k = a._rest[0]; sv(s).key = k; });
cmd('radsrv', 'timeout <n>', (s, a) => { sv(s).timeout = +a.n; }); cmd('radsrv', 'retransmit <n>', (s, a) => { sv(s).retransmit = +a.n; });
cmd('radsrv', 'pac <x...>', () => { }); cmd('radsrv', 'automate-tester <x...>', () => { }); cmd('radsrv', 'no <x...>', () => { });
cmd('config', 'radius-server host <ip> [<x...>]', (s, a, io) => { const ip = IP.parse(a.ip); if (ip === null) return bad(io); const r = R(s); const v = r.addServer({ name: a.ip, ip, key: (r.servers.find(x => x.ip === ip) || {}).key || r.defaults.key }); srvOpts(v, a._rest || [], io); });
cmd('config', 'no radius-server host <ip> [<x...>]', (s, a) => { const ip = IP.parse(a.ip); R(s).servers = R(s).servers.filter(x => x.ip !== ip); });
cmd('config', 'radius-server key <k> [<x...>]', (s, a) => { let k = a.k; if ((k === '0' || k === '7') && a._rest && a._rest[0]) k = a._rest[0]; R(s).defaults.key = k; R(s).servers.forEach(x => { if (!x.key) x.key = k; }); });
cmd('config', 'radius-server timeout <n>', (s, a) => { R(s).defaults.timeout = +a.n; }); cmd('config', 'radius-server retransmit <n>', (s, a) => { R(s).defaults.retransmit = +a.n; }); cmd('config', 'radius-server deadtime <n>', (s, a) => { R(s).deadtime = +a.n; });
cmd('config', 'radius-server <x...>', () => { }); cmd('config', 'no radius-server <x...>', () => { });
cmd('config', 'ip radius source-interface <i>', (s, a) => { R(s).srcIf = a.i; }); cmd('config', 'no ip radius source-interface [<i>]', (s) => { R(s).srcIf = null; });
cmd('config', 'aaa group server radius <n>', (s, a) => { const r = R(s); if (!r.groups.has(a.n)) r.groups.set(a.n, { name: a.n, servers: [] }); s.mode = 'aaagrp'; s.ctx = { g: r.groups.get(a.n) }; });
cmd('config', 'no aaa group server radius <n>', (s, a) => R(s).groups.delete(a.n));
cmd('aaagrp', 'server name <n>', (s, a) => { if (!s.ctx.g.servers.includes(a.n)) s.ctx.g.servers.push(a.n); });
cmd('aaagrp', 'server <ip> [<x...>]', (s, a, io) => { const ip = IP.parse(a.ip); if (ip === null) return bad(io); const r = R(s); if (!r.servers.find(x => x.ip === ip)) { const v = r.addServer({ name: a.ip, ip, key: r.defaults.key }); srvOpts(v, a._rest || [], io); } if (!s.ctx.g.servers.includes(a.ip)) s.ctx.g.servers.push(a.ip); });
cmd('aaagrp', 'no <x...>', () => { }); cmd('aaagrp', 'ip <x...>', () => { });

/* ------------------------------------------------------------------ 802.1X */
const refreshAll = s => { const d = D(s); if (d.enabled) s.dev.ports.forEach(p => { if (d.active(p) && p.up) d.startPort(p); }); };
cmd('config', 'dot1x system-auth-control', s => { D(s).enabled = true; refreshAll(s); });
cmd('config', 'no dot1x system-auth-control', s => { const d = D(s); d.enabled = false; s.dev.ports.forEach(p => d.clearPort(p, false)); });
cmd('config', 'dot1x <x...>', () => { }); cmd('config', 'no dot1x <x...>', () => { }); cmd('config', 'authentication <x...>', () => { });
const setMode = (s, io, m) => { if (!s.isSwitch) return bad(io); ports(s).forEach(p => { const c = D(s).cfg(p); c.mode = m; if (m === 'auto') { if (D(s).enabled && p.up) D(s).startPort(p); } else D(s).clearPort(p, false); }); };
const PCM = { auto: 'auto', 'force-authorized': 'force-authorized', 'force-unauthorized': 'force-unauthorized' };
cmd('if', 'authentication port-control <m>', (s, a, io) => { const m = PCM[a.m.toLowerCase()]; if (!m) return bad(io); setMode(s, io, m); });
cmd('if', 'dot1x port-control <m>', (s, a, io) => { const m = PCM[a.m.toLowerCase()]; if (!m) return bad(io); setMode(s, io, m); });
cmd('if', 'no authentication port-control', (s, a, io) => setMode(s, io, null)); cmd('if', 'no dot1x port-control', (s, a, io) => setMode(s, io, null));
cmd('if', 'authentication host-mode <h>', (s, a, io) => { const h = a.h.toLowerCase(); if (!['single-host', 'multi-host', 'multi-auth', 'multi-domain'].includes(h)) return bad(io); ports(s).forEach(p => { D(s).cfg(p).host = h === 'multi-domain' ? 'multi-auth' : h; }); });
cmd('if', 'authentication order <x...>', (s, a, io) => { const o = a._rest.map(x => x.toLowerCase()).filter(x => x === 'dot1x' || x === 'mab'); if (!o.length) return bad(io); ports(s).forEach(p => { D(s).cfg(p).order = o; }); });
cmd('if', 'mab [<x...>]', (s) => ports(s).forEach(p => { D(s).cfg(p).mab = true; })); cmd('if', 'no mab [<x...>]', (s) => ports(s).forEach(p => { D(s).cfg(p).mab = false; }));
cmd('if', 'authentication event no-response action authorize vlan <v>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).guest = +a.v; }));
cmd('if', 'authentication event fail action authorize vlan <v>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).fail = +a.v; }));
cmd('if', 'no authentication event no-response action authorize vlan [<v>]', (s) => ports(s).forEach(p => { D(s).cfg(p).guest = null; }));
cmd('if', 'no authentication event fail action authorize vlan [<v>]', (s) => ports(s).forEach(p => { D(s).cfg(p).fail = null; }));
cmd('if', 'dot1x guest-vlan <v>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).guest = +a.v; })); cmd('if', 'no dot1x guest-vlan [<v>]', (s) => ports(s).forEach(p => { D(s).cfg(p).guest = null; }));
cmd('if', 'authentication timer reauthenticate <n>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).reauth = +a.n; }));
cmd('if', 'dot1x timeout tx-period <n>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).tx = +a.n; }));
cmd('if', 'dot1x timeout quiet-period <n>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).quiet = +a.n; }));
cmd('if', 'dot1x max-reauth-req <n>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).maxReq = +a.n; })); cmd('if', 'dot1x max-req <n>', (s, a) => ports(s).forEach(p => { D(s).cfg(p).maxReq = +a.n; }));
cmd('if', 'authentication <x...>', () => { }); cmd('if', 'no authentication <x...>', () => { }); cmd('if', 'dot1x <x...>', () => { }); cmd('if', 'no dot1x <x...>', () => { });

NS.aaaGlobal = function (dev, p) {
  const r = dev.radius; if (!r) return; const a = r.aaa; const any = a.newModel || r.servers.length || (dev.dot1x && dev.dot1x.enabled); if (!any) return;
  if (a.newModel) { p('aaa new-model'); a.login.forEach((m, n) => p('aaa authentication login ' + n + ' ' + m.join(' '))); a.dot1x.forEach((m, n) => p('aaa authentication dot1x ' + n + ' ' + m.join(' '))); a.authz.forEach((m, n) => p('aaa authorization network ' + n + ' ' + m.join(' '))); if (a.acct.get('dot1x')) p('aaa accounting dot1x default start-stop ' + a.acct.get('dot1x').join(' ')); p('!'); }
  r.groups.forEach(gr => { p('aaa group server radius ' + gr.name); gr.servers.forEach(x => p(' server name ' + x)); p('!'); });
  if (dev.dot1x && dev.dot1x.enabled) { p('dot1x system-auth-control'); p('!'); }
  r.servers.forEach(v => { p('radius server ' + v.name); p(' address ipv4 ' + IP.str(v.ip) + ' auth-port ' + v.authPort + ' acct-port ' + v.acctPort); if (v.timeout) p(' timeout ' + v.timeout); if (v.retransmit) p(' retransmit ' + v.retransmit); if (v.key) p(' key ' + v.key); p('!'); });
  if (r.srcIf) p('ip radius source-interface ' + r.srcIf); if (r.deadtime) p('radius-server deadtime ' + r.deadtime);
};
NS.dotIfLines = function (pt, ln) {
  const c = pt.dx; if (!c) return; if (c.mode) ln.push('authentication port-control ' + c.mode); else return;
  if (c.host !== 'single-host') ln.push('authentication host-mode ' + c.host); if (c.order.join(' ') !== 'dot1x') ln.push('authentication order ' + c.order.join(' ')); if (c.mab) ln.push('mab');
  if (c.guest) ln.push('authentication event no-response action authorize vlan ' + c.guest); if (c.fail) ln.push('authentication event fail action authorize vlan ' + c.fail); if (c.reauth) ln.push('authentication timer reauthenticate ' + c.reauth);
  if (c.tx !== 30) ln.push('dot1x timeout tx-period ' + c.tx); if (c.quiet !== 60) ln.push('dot1x timeout quiet-period ' + c.quiet); if (c.maxReq !== 2) ln.push('dot1x max-reauth-req ' + c.maxReq); ln.push('dot1x pae authenticator');
};

/* ------------------------------------------------------------------ show / test / clear */
cmd('exec', 'show dot1x all [<x...>]', (s, a, io) => {
  const d = D(s); if (!d) return bad(io); let o = 'Sysauthcontrol                     ' + (d.enabled ? 'Enabled' : 'Disabled') + '\nDot1x Protocol Version                   3\n';
  s.dev.ports.forEach(p => { if (!p.dx || !p.dx.mode) return; const c = p.dx; o += '\nDot1x Info for ' + p.name + '\n-----------------------------------\nPAE                       = AUTHENTICATOR\nQuietPeriod               = ' + c.quiet + '\nServerTimeout             = 0\nSuppTimeout               = 30\nReAuthMax                 = ' + c.maxReq + '\nMaxReq                    = ' + c.maxReq + '\nTxPeriod                  = ' + c.tx + '\n'; });
  io.print(o);
}, { priv: true });
cmd('exec', 'show dot1x interface <i> [<x...>]', (s, a, io) => {
  const p = s.dev.findPort(a.i); if (!p || !p.dx) return bad(io); const c = p.dx, d = D(s);
  io.print('Dot1x Info for ' + p.name + '\n-----------------------------------\nPAE                       = AUTHENTICATOR\nPortControl               = ' + ({ auto: 'AUTO', 'force-authorized': 'FORCE_AUTHORIZED', 'force-unauthorized': 'FORCE_UNAUTHORIZED' })[c.mode || 'force-authorized'] + '\nControlDirection          = Both\nHostMode                  = ' + c.host.toUpperCase().replace('-', '_') + '\nQuietPeriod               = ' + c.quiet + '\nServerTimeout             = 0\nSuppTimeout               = 30\nReAuthMax                 = ' + c.maxReq + '\nMaxReq                    = ' + c.maxReq + '\nTxPeriod                  = ' + c.tx + '\nRateLimitPeriod           = 0\n' + (c.guest ? 'Guest-Vlan                = ' + c.guest + '\n' : '') + (c.fail ? 'Auth-Fail-Vlan            = ' + c.fail + '\n' : ''));
}, { priv: true });
function sessRows(s, only) {
  const rows = []; s.dev.ports.forEach(p => { if (only && p !== only) return; if (!p.dxs) return; p.dxs.sess.forEach(x => rows.push({ p, x })); if (p.dxs.guestOn && !p.dxs.sess.size) rows.push({ p, x: null }); }); return rows;
}
cmd('exec', 'show authentication sessions [<x...>]', (s, a, io) => {
  const d = D(s); if (!d) return bad(io); const r = a._rest || []; let only = null; if (r[0] && r[0].toLowerCase().startsWith('int')) { only = s.dev.findPort(r.slice(1).join('')); if (!only) return bad(io); }
  const rows = sessRows(s, only);
  if (only && rows.length) { const x = rows[0].x; if (x) {
    const ip = (() => { for (const [, e] of s.dev.arpTable || []) { } return 'Unknown'; })();
    io.print('            Interface:  ' + only.name + '\n          MAC Address:  ' + U.macCisco(x.mac) + '\n           IPv6 Address:  Unknown\n         IPv4 Address:  Unknown\n            User-Name:  ' + (x.user || 'Unknown') + '\n               Status:  ' + ({ auth: 'Authorized', unauth: 'Unauthorized', fail: 'Unauthorized', held: 'Unauthorized' })[x.state] + '\n               Domain:  DATA\n       Oper host mode:  ' + only.dx.host + '\n     Oper control dir:  both\n' + (x.vlan ? '      Vlan Policy:  ' + x.vlan + '\n' : '') + '      Session timeout:  N/A\n   Common Session ID:  ' + x.sid + '\n     Acct Session ID:  Unknown\n              Handle:  0x' + (0xa4000001 + rows.length).toString(16).toUpperCase() + '\nRunnable methods list:\n       Method   State\n       dot1x    ' + (x.method === 'dot1x' ? (x.state === 'auth' ? 'Authc Success' : x.state === 'unauth' ? 'Running' : 'Authc Failed') : 'Not run') + '\n       mab      ' + (x.method === 'mab' ? (x.state === 'auth' ? 'Authc Success' : 'Authc Failed') : 'Not run') + '\n'); return; } }
  let o = 'Interface  MAC Address     Method   Domain   Status Fg Session ID\n';
  rows.forEach(({ p, x }) => { if (x) o += pad(shortIf(p.name), 10) + ' ' + pad(U.macCisco(x.mac), 15) + pad(x.method, 8) + ' DATA     ' + pad(x.state === 'auth' ? 'Auth' : 'Unauth', 7) + '   ' + x.sid + '\n'; });
  const n = rows.filter(r => r.x).length; o += '\nSession count = ' + n + '\n'; io.print(o);
}, { priv: true });
cmd('exec', 'show aaa servers', (s, a, io) => {
  const r = R(s); let o = ''; r.servers.forEach((v, i) => { const st = v.stats; o += 'RADIUS: id ' + (i + 1) + ', priority ' + (i + 1) + ', host ' + IP.str(v.ip) + ', auth-port ' + v.authPort + ', acct-port ' + v.acctPort + '\n     State: current ' + (v.dead && s.dev.sim.now < v.dead ? 'DEAD' : 'UP') + ', duration ' + Math.floor(s.dev.sim.now / 1000) + 's, previous duration 0s\n     Dead: total time 0s, count ' + st.timeouts + '\n     Quarantined: No\n     Authen: request ' + st.sent + ', timeouts ' + st.timeouts + '\n             Response: accept ' + st.accept + ', reject ' + st.reject + ', challenge ' + st.challenge + '\n             Response: unexpected ' + st.badAuth + ', server error 0, incorrect 0, time 0ms\n             Transaction: success ' + (st.accept + st.reject) + ', failure ' + st.timeouts + '\n     Author: request 0, timeouts 0\n     Account: request 0, timeouts 0\n     Elapsed time since counters last cleared: ' + Math.floor(s.dev.sim.now / 60000) + 'm\n\n'; });
  io.print(o || 'No RADIUS servers configured\n');
}, { priv: true });
cmd('exec', 'show radius statistics', (s, a, io) => { const r = R(s); let o = '                  Auth.    Acct.    Both\nMaximum inQ length:       NA       NA       0\n'; let sent = 0, ret = 0; r.servers.forEach(v => { sent += v.stats.sent; ret += v.stats.retrans; }); o += 'Total responses seen:     ' + r.servers.reduce((n, v) => n + v.stats.accept + v.stats.reject + v.stats.challenge, 0) + '\nPacket send count:        ' + sent + '\nRetransmissions:          ' + ret + '\n'; io.print(o); }, { priv: true });
cmd('priv', 'test aaa group <g> <u> <p> <x...>', (s, a, io) => {
  const r = R(s); io.print('Sending password\n');
  r.authPap(a.g, a.u, a.p, res => { if (res.res === 'accept') io.print('User successfully authenticated\n\nUSER ATTRIBUTES\n\nusername             0   "' + a.u + '"\n'); else if (res.res === 'reject') io.print('User rejected\n'); else io.print('Server not responding (no reply from ' + (res.nogroup ? 'any server' : 'the RADIUS server') + ')\n'); io.done(); });
  return 'async';
});
cmd('priv', 'dot1x re-authenticate interface <i>', (s, a, io) => { const p = s.dev.findPort(a.i); if (!p || !p.dx) return bad(io); D(s).reauthenticate(p); });
cmd('priv', 'clear authentication sessions [<x...>]', (s, a, io) => { const r = a._rest || []; if (r[0] && r[0].toLowerCase().startsWith('int')) { const p = s.dev.findPort(r.slice(1).join('')); if (p) D(s).clearSessions(p); } else s.dev.ports.forEach(p => { if (p.dxs) D(s).clearSessions(p); }); });
})(typeof window !== 'undefined' ? window : globalThis);
