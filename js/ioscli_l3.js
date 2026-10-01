/* ioscli_l3.js — commandes IOS : OSPF */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP } = NS; const cmd = NS.iosCmd; const { pad } = NS.iosUtil;
const bad = io => io.print("% Invalid input detected at '^' marker.\n");
const hasOspf = s => !!s.dev.ospf;
function areaVal(x) { if (/^\d+$/.test(x)) return +x; const ip = IP.parse(x); return ip === null ? null : ip; }

cmd('config', 'router ospf <pid>', (s, a, io) => { if (!hasOspf(s) || !(+a.pid >= 1 && +a.pid <= 65535)) { bad(io); return; } s.dev.ospf.start(+a.pid); s.mode = 'ospf'; s.ctx = {}; });
cmd('config', 'no router ospf <pid>', (s, a, io) => { if (!hasOspf(s)) { bad(io); return; } s.dev.ospf.stop(); s.dev.ospf.networks = []; s.dev.ospf.passive.clear(); s.dev.ospf.defaultOrig = null; s.dev.ospf.redist = { static: null, connected: null, rip: null }; s.dev.ospf.rid = 0; });
cmd('ospf', 'router-id <ip>', (s, a, io) => { const ip = IP.parse(a.ip); if (ip === null) { bad(io); return; } const o = s.dev.ospf; if (o.enabled && o.ridActive !== ip && o.ifs.size && Array.from(o.ifs.values()).some(x => x.nbrs.size)) io.print('% OSPF: Reload or use "clear ip ospf process" command, for this to take effect\n'); o.rid = ip; if (!Array.from(o.ifs.values()).some(x => x.nbrs.size)) o.setRouterId(ip); });
cmd('ospf', 'no router-id [<ip>]', (s) => { s.dev.ospf.rid = 0; });
cmd('ospf', 'network <net> <wc> area <a>', (s, a, io) => { const net = IP.parse(a.net), wc = IP.parse(a.wc), ar = areaVal(a.a); if (net === null || wc === null || ar === null) { bad(io); return; } s.dev.ospf.addNetwork(net, wc, ar); });
cmd('ospf', 'no network <net> <wc> area <a>', (s, a, io) => { const net = IP.parse(a.net), wc = IP.parse(a.wc), ar = areaVal(a.a); if (net === null || wc === null || ar === null) { bad(io); return; } s.dev.ospf.removeNetwork(net, wc, ar); });
cmd('ospf', 'passive-interface <x>', (s, a) => { const o = s.dev.ospf; if (a.x.toLowerCase() === 'default') { o.passiveDefault = true; o.nonPassive.clear(); } else { const i = s.dev.ifaceByName(a.x); const n = i ? i.name : a.x; o.passive.add(n); o.nonPassive.delete(n); } o.refresh(); });
cmd('ospf', 'no passive-interface <x>', (s, a) => { const o = s.dev.ospf; if (a.x.toLowerCase() === 'default') { o.passiveDefault = false; } else { const i = s.dev.ifaceByName(a.x); const n = i ? i.name : a.x; o.passive.delete(n); o.nonPassive.add(n); } o.refresh(); });
cmd('ospf', 'default-information originate [<x...>]', (s, a) => { const t = (a.x || '').toLowerCase().split(/\s+/); const m = /metric\s+(\d+)/.exec(a.x || ''); s.dev.ospf.defaultOrig = { always: t.includes('always'), metric: m ? +m[1] : 1 }; s.dev.ospf.syncExternals(); });
cmd('ospf', 'no default-information originate [<x...>]', (s) => { s.dev.ospf.defaultOrig = null; s.dev.ospf.syncExternals(); });
cmd('ospf', 'redistribute <p> [<x...>]', (s, a, io) => { const p = a.p.toLowerCase(); const k = p.startsWith('st') ? 'static' : p.startsWith('c') ? 'connected' : p.startsWith('r') ? 'rip' : null; if (!k) { io.print('% Redistribution de « ' + a.p + ' » non pris en charge dans le simulateur.\n'); return; } const m = /metric\s+(\d+)/.exec(a.x || ''); s.dev.ospf.redist[k] = { metric: m ? +m[1] : 0 }; s.dev.ospf.syncExternals(); });
cmd('ospf', 'no redistribute <p> [<x...>]', (s, a) => { const p = a.p.toLowerCase(); const k = p.startsWith('st') ? 'static' : p.startsWith('c') ? 'connected' : p.startsWith('r') ? 'rip' : null; if (k) { s.dev.ospf.redist[k] = null; s.dev.ospf.syncExternals(); } });
cmd('ospf', 'auto-cost reference-bandwidth <n>', (s, a) => { s.dev.ospf.refBw = +a.n; s.dev.ospf.schedOrig(); s.dev.ospf.refresh(); });
cmd('ospf', 'log-adjacency-changes [<x...>]', () => { }); cmd('ospf', 'maximum-paths <n>', () => { }); cmd('ospf', 'area <a> <x...>', () => { }); cmd('ospf', 'distance <x...>', () => { }); cmd('ospf', 'timers <x...>', () => { });
cmd('ospf', 'no <x...>', () => { });

const each = (s, f) => s.items().forEach(it => { if (it.iface) f(it.iface); });
function reOspf(s) { if (s.dev.ospf && s.dev.ospf.enabled) { s.dev.ospf.refresh(); s.dev.ospf.schedOrig(); } }
cmd('if', 'ip ospf cost <n>', (s, a) => { each(s, i => i.ospfCostFix = +a.n); reOspf(s); });
cmd('if', 'no ip ospf cost', (s) => { each(s, i => i.ospfCostFix = 0); reOspf(s); });
cmd('if', 'ip ospf hello-interval <n>', (s, a) => { each(s, i => { i.ospfHello = +a.n; if (!i.ospfDead) { } }); reOspf(s); s.dev.ospf && s.dev.ospf.enabled && s.dev.ospf.ifs.forEach(oi => oi.up && oi.iface.ospfHello && s.dev.ospf.refresh()); });
cmd('if', 'ip ospf dead-interval <n>', (s, a) => { each(s, i => i.ospfDead = +a.n); reOspf(s); });
cmd('if', 'no ip ospf hello-interval', (s) => { each(s, i => i.ospfHello = 0); reOspf(s); });
cmd('if', 'no ip ospf dead-interval', (s) => { each(s, i => i.ospfDead = 0); reOspf(s); });
cmd('if', 'ip ospf priority <n>', (s, a) => { each(s, i => i.ospfPri = +a.n); reOspf(s); });
cmd('if', 'no ip ospf priority', (s) => { each(s, i => i.ospfPri = null); reOspf(s); });
cmd('if', 'ip ospf network <x>', (s, a, io) => { const x = a.x.toLowerCase(); if (x.startsWith('point')) each(s, i => i.ospfNet = 'p2p'); else if (x.startsWith('b')) each(s, i => i.ospfNet = null); else { bad(io); return; } reOspf(s); if (s.dev.ospf) s.dev.ospf.refresh(); });
cmd('if', 'no ip ospf network', (s) => { each(s, i => i.ospfNet = null); reOspf(s); });
cmd('if', 'ip ospf <pid> area <a>', (s, a, io) => { const ar = areaVal(a.a); if (ar === null) { bad(io); return; } if (s.dev.ospf && !s.dev.ospf.enabled) s.dev.ospf.start(+a.pid); each(s, i => i.ospfArea = ar); reOspf(s); });
cmd('if', 'no ip ospf <pid> area <a>', (s) => { each(s, i => i.ospfArea = null); reOspf(s); });

/* ---- show ---- */
const need = (s, io) => { if (!s.dev.ospf || !s.dev.ospf.enabled) { io.print('%OSPF: Router process not configured\n'); return false; } return true; };
cmd('exec', 'show ip ospf', (s, a, io) => { if (!need(s, io)) return; io.print(s.dev.ospf.showGeneral()); });
cmd('exec', 'show ip ospf neighbor [<x...>]', (s, a, io) => { if (!need(s, io)) return; io.print(s.dev.ospf.showNeighbors()); });
cmd('exec', 'show ip ospf interface [<x...>]', (s, a, io) => { if (!need(s, io)) return; const x = (a.x || '').trim(); if (x.toLowerCase() === 'brief') io.print(s.dev.ospf.showBrief()); else { const i = x ? s.dev.ifaceByName(x) : null; io.print(s.dev.ospf.showInterfaces(i ? i.name : '')); } });
cmd('exec', 'show ip ospf database [<x...>]', (s, a, io) => { if (!need(s, io)) return; const x = (a.x || '').trim().toLowerCase(); const map = { router: 'router', network: 'network', summary: 'summary', external: 'external', 'asbr-summary': 'asbr-summary' }; io.print(s.dev.ospf.showDatabase(map[x] || '')); });
cmd('exec', 'clear ip ospf process', (s, a, io) => { if (s.dev.ospf && s.dev.ospf.enabled) { s.dev.ospf.restart(); } });
cmd('exec', 'clear ip ospf <x...>', (s, a, io) => { if (s.dev.ospf && s.dev.ospf.enabled) { s.dev.ospf.restart(); } });
cmd('exec', 'show ip protocols', (s, a, io) => {
  const d = s.dev; let o = '';
  if (d.rip && d.rip.enabled) o += 'Routing Protocol is "rip"\n  Sending updates every 30 seconds, next due in ' + (30 - Math.floor(d.sim.now / 1000) % 30) + ' seconds\n  Default version control: send version 2, receive version 2\n  Automatic network summarization is not in effect\n  Routing for Networks:\n' + d.rip.networks.map(n => '    ' + IP.str(n) + '\n').join('') + '  Passive Interface(s):\n' + Array.from(d.rip.passive).map(x => '    ' + x + '\n').join('') + '  Routing Information Sources:\n    Gateway         Distance      Last Update\n' + Array.from(new Set(d.dynRoutes.filter(r => r.proto === 'R').map(r => r.nh))).map(g2 => '    ' + pad(IP.str(g2), 15) + ' 120\n').join('');
  if (d.ospf && d.ospf.enabled) {
    const w = d.ospf; o += 'Routing Protocol is "ospf ' + w.pid + '"\n  Outgoing update filter list for all interfaces is not set\n  Incoming update filter list for all interfaces is not set\n  Router ID ' + IP.str(w.ridActive) + '\n' + (w.isAbr() ? '  It is an area border router\n' : '') + (w.wantExt.size ? '  It is an autonomous system boundary router\n' : '') + '  Number of areas in this router is ' + w.areas().length + '. ' + w.areas().length + ' normal 0 stub 0 nssa\n  Maximum path: 4\n  Routing for Networks:\n' + w.networks.map(n => '    ' + IP.str(n.net) + ' ' + IP.str(n.wc) + ' area ' + n.area + '\n').join('') + '  Passive Interface(s):\n' + Array.from(w.passive).map(x => '    ' + x + '\n').join('') + '  Routing Information Sources:\n    Gateway         Distance      Last Update\n' + Array.from(new Set(Array.from(w.ifs.values()).reduce((r, oi) => r.concat(Array.from(oi.nbrs.values()).map(n => n.rid)), []))).map(r => '    ' + pad(IP.str(r), 15) + ' 110\n').join('') + '  Distance: (default is 110)\n';
  }
  io.print(o);
});
})(typeof window !== 'undefined' ? window : globalThis);
