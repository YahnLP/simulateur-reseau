/* ioscli_qos.js — commandes IOS : class-map, policy-map, service-policy, mls qos, auto qos voip, show policy-map / mls qos */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const cmd = NS.iosCmd; const { pad, padL } = NS.iosUtil; const Q = NS.Qos;
const bad = io => io.print("% Invalid input detected at '^' marker.\n");
const QS = s => Q.ensure(s.dev);
const portsOf = s => s.items().map(it => it.port || (it.iface && it.iface.port)).filter(Boolean);
const re = s => Q.apply(s.dev);

/* ---- class-map ---- */
cmd('config', 'class-map <a> [<b>]', (s, a) => { const q = QS(s); let any = false, name = a.a; if (/^match-(any|all)$/.test(a.a) && a.b) { any = a.a === 'match-any'; name = a.b; } let c = q.cmaps.get(name); if (!c) { c = { name, any, matches: [] }; q.cmaps.set(name, c); } else if (name !== a.a) c.any = any; s.mode = 'cmapq'; s.ctx = { cm: c }; });
cmd('config', 'no class-map <n>', (s, a) => { QS(s).cmaps.delete(a.n); re(s); });
const addM = (s, m) => { s.ctx.cm.matches.push(m); re(s); };
cmd('cmapq', 'match ip dscp <x...>', (s, a, io) => { const v = [a._rest[0]].concat(a._rest.slice(1)); addD(s, io, a._rest || [a.x]); });
cmd('cmapq', 'match dscp <x...>', (s, a, io) => addD(s, io, a._rest || [a.x]));
function addD(s, io, toks) { const v = toks.map(Q.parseDscp); if (v.some(x => x === null)) return bad(io); addM(s, { t: 'dscp', v }); }
cmd('cmapq', 'match cos <x...>', (s, a, io) => { const v = (a._rest || [a.x]).map(Number); if (v.some(x => !(x >= 0 && x < 8))) return bad(io); addM(s, { t: 'cos', v }); });
cmd('cmapq', 'match access-group name <n>', (s, a) => addM(s, { t: 'acl', v: a.n })); cmd('cmapq', 'match access-group <n>', (s, a) => addM(s, { t: 'acl', v: a.n }));
cmd('cmapq', 'match protocol <n>', (s, a) => addM(s, { t: 'proto', v: a.n.toLowerCase() }));
cmd('cmapq', 'match ip rtp <x...>', (s) => addM(s, { t: 'proto', v: 'rtp' }));
cmd('cmapq', 'match any', s => addM(s, { t: 'any' }));
cmd('cmapq', 'description <x...>', () => { }); cmd('cmapq', 'no <x...>', () => { });
/* ---- policy-map ---- */
cmd('config', 'policy-map <n>', (s, a) => { const q = QS(s); let p = q.pmaps.get(a.n); if (!p) { p = { name: a.n, classes: [] }; q.pmaps.set(a.n, p); } s.mode = 'pmapq'; s.ctx = { pm: p }; });
cmd('config', 'no policy-map <n>', (s, a) => { QS(s).pmaps.delete(a.n); re(s); });
cmd('pmapq', 'class <n>', (s, a, io) => { if (a.n !== 'class-default' && !QS(s).cmaps.has(a.n)) { io.print('% Class-map ' + a.n + ' does not exist\n'); } let c = s.ctx.pm.classes.find(x => x.cm === a.n); if (!c) { c = { cm: a.n, act: {} }; s.ctx.pm.classes.push(c); } s.mode = 'pmapc'; s.ctx = { pm: s.ctx.pm, c }; });
cmd('pmapq', 'description <x...>', () => { });
cmd('pmapq', 'exit', s => { s.mode = 'config'; s.ctx = null; }); cmd('cmapq', 'exit', s => { s.mode = 'config'; s.ctx = null; });
cmd('pmapc', 'exit', s => { s.mode = 'pmapq'; s.ctx = { pm: s.ctx.pm }; });
cmd('pmapc', 'class <n>', (s, a, io) => { let c = s.ctx.pm.classes.find(x => x.cm === a.n); if (!c) { c = { cm: a.n, act: {} }; s.ctx.pm.classes.push(c); } s.ctx = { pm: s.ctx.pm, c }; });
const bps = (v, u) => { let n = +v; if (!(n >= 0)) return null; const m = { k: 1e3, m: 1e6, g: 1e9 }[(u || '').toLowerCase()[0]]; return m ? n * m : n; };
cmd('pmapc', 'priority percent <n>', (s, a) => { s.ctx.c.act.prioPct = +a.n; s.ctx.c.act.priority = 1; re(s); });
cmd('pmapc', 'priority <n>', (s, a, io) => { const v = +a.n; if (!(v > 0)) return bad(io); s.ctx.c.act.priority = v * 1000; s.ctx.c.act.prioPct = 0; re(s); });
cmd('pmapc', 'priority', s => { s.ctx.c.act.priority = 1; re(s); });
cmd('pmapc', 'bandwidth percent <n>', (s, a) => { s.ctx.c.act.bwPct = +a.n; s.ctx.c.act.bw = 0; }); cmd('pmapc', 'bandwidth remaining percent <n>', (s, a) => { s.ctx.c.act.bwPct = +a.n; });
cmd('pmapc', 'bandwidth <n>', (s, a) => { s.ctx.c.act.bw = +a.n; s.ctx.c.act.bwPct = 0; });
cmd('pmapc', 'set dscp <v>', (s, a, io) => { const v = Q.parseDscp(a.v); if (v === null) return bad(io); s.ctx.c.act.dscp = v; re(s); });
cmd('pmapc', 'set ip dscp <v>', (s, a, io) => { const v = Q.parseDscp(a.v); if (v === null) return bad(io); s.ctx.c.act.dscp = v; re(s); });
cmd('pmapc', 'police rate <n> [<x...>]', (s, a, io) => { const v = bps(a.n, (a._rest || []).find(t => /^(bps|kbps|mbps)$/i.test(t)) ? ((a._rest || []).find(t => /^(bps|kbps|mbps)$/i.test(t))).replace(/bps/i, '') : ''); if (v === null) return bad(io); s.ctx.c.act.police = v; re(s); });
cmd('pmapc', 'police <n> [<x...>]', (s, a, io) => { const v = bps(a.n); if (v === null || v < 8000) return bad(io); s.ctx.c.act.police = v; re(s); });
cmd('pmapc', 'shape average <n> [<x...>]', (s, a, io) => { const v = bps(a.n); if (v === null || v < 8000) return bad(io); s.ctx.c.act.shape = v; re(s); });
cmd('pmapc', 'queue-limit <x...>', () => { }); cmd('pmapc', 'fair-queue', () => { }); cmd('pmapc', 'random-detect <x...>', () => { });
cmd('pmapc', 'no priority', s => { s.ctx.c.act.priority = 0; re(s); }); cmd('pmapc', 'no <x...>', (s, a) => { const w = a.x.toLowerCase(); const k = { set: 'dscp', police: 'police', shape: 'shape', bandwidth: 'bw' }[w]; if (k) { delete s.ctx.c.act[k]; re(s); } });
/* ---- interface ---- */
cmd('if', 'service-policy input <n>', (s, a, io) => { if (!QS(s).pmaps.has(a.n)) { io.print('% policy map ' + a.n + ' not configured\n'); return; } portsOf(s).forEach(p => { p.svcIn = a.n; }); re(s); });
cmd('if', 'service-policy output <n>', (s, a, io) => { if (!QS(s).pmaps.has(a.n)) { io.print('% policy map ' + a.n + ' not configured\n'); return; } portsOf(s).forEach(p => { p.svcOut = a.n; }); re(s); });
cmd('if', 'no service-policy input <n>', s => { portsOf(s).forEach(p => { p.svcIn = null; }); re(s); }); cmd('if', 'no service-policy output <n>', s => { portsOf(s).forEach(p => { p.svcOut = null; }); re(s); });
cmd('if', 'mls qos trust dscp', s => { portsOf(s).forEach(p => { p.trust = 'dscp'; }); re(s); }); cmd('if', 'mls qos trust cos', s => { portsOf(s).forEach(p => { p.trust = 'cos'; }); re(s); });
cmd('if', 'mls qos trust device cisco-phone', s => { portsOf(s).forEach(p => { p.trust = 'phone'; }); re(s); });
cmd('if', 'no mls qos trust', s => { portsOf(s).forEach(p => { p.trust = null; }); re(s); });
cmd('if', 'priority-queue out', s => { portsOf(s).forEach(p => { p.prioQ = true; }); re(s); }); cmd('if', 'no priority-queue out', s => { portsOf(s).forEach(p => { p.prioQ = false; }); re(s); });
cmd('if', 'auto qos voip cisco-phone', s => { QS(s).mls = true; portsOf(s).forEach(p => { p.trust = 'phone'; p.prioQ = true; p.autoQos = 'cisco-phone'; }); re(s); });
cmd('if', 'auto qos voip trust', s => { QS(s).mls = true; portsOf(s).forEach(p => { p.trust = 'dscp'; p.prioQ = true; p.autoQos = 'trust'; }); re(s); });
cmd('if', 'no auto qos voip [<x...>]', s => { portsOf(s).forEach(p => { p.trust = null; p.prioQ = false; p.autoQos = null; }); re(s); });
cmd('config', 'mls qos', s => { QS(s).mls = true; re(s); }); cmd('config', 'no mls qos', s => { QS(s).mls = false; re(s); });
cmd('config', 'mls qos <x...>', () => { }); cmd('config', 'auto qos <x...>', () => { });
/* ---- show ---- */
const rate = b => b >= 1e6 ? (b / 1e6) + ' Mbps' : (b / 1e3) + ' kbps';
function showPm(io, name, p, live) {
  io.print('  Policy Map ' + name + '\n'); p.classes.forEach(c => {
    io.print('    Class ' + c.cm + '\n'); const a = c.act;
    if (a.priority) io.print('      priority ' + (a.prioPct ? 'percent ' + a.prioPct : a.priority > 1 ? a.priority / 1000 + ' (kbps)' : '') + '\n');
    if (a.bw) io.print('      bandwidth ' + a.bw + ' (kbps)\n'); if (a.bwPct) io.print('      bandwidth ' + a.bwPct + ' (%)\n');
    if (a.dscp !== undefined) io.print('      set dscp ' + Q.dscpName(a.dscp) + '\n'); if (a.police) io.print('      police ' + a.police + '\n'); if (a.shape) io.print('      Traffic Shaping\n        Average Rate Traffic Shaping\n        Shape ' + a.shape + ' (bps)\n');
  });
}
cmd('priv', 'show policy-map [<n>]', (s, a, io) => { const q = QS(s); if (a.n && a.n !== 'interface') { const p = q.pmaps.get(a.n); if (!p) { io.print('Error: policy-map ' + a.n + ' not found\n'); return; } showPm(io, a.n, p); return; } q.pmaps.forEach((p, n) => showPm(io, n, p)); });
cmd('priv', 'show policy-map interface [<i...>]', (s, a, io) => {
  const it = NS.iosUtil.makeItem(s, a.i || '', io); const p = it && (it.port || (it.iface && it.iface.port)); const q = QS(s);
  if (!p) { io.print('% Invalid interface\n'); return; }
  [['Service-policy input', p.svcIn], ['Service-policy output', p.svcOut]].forEach(([lab, n]) => {
    if (!n) return; const pol = q.pmaps.get(n); if (!pol) return; io.print(' ' + p.name.replace('GigabitEthernet', 'GigabitEthernet').replace(/^/, '') + '\n\n  ' + lab + ': ' + n + '\n');
    pol.classes.forEach(c => { const st = c.st || { pk: 0, by: 0, drop: 0, marked: 0 }; io.print('\n    Class-map: ' + c.cm + ' (' + (c.cm === 'class-default' ? 'match-any' : (q.cmaps.get(c.cm) && q.cmaps.get(c.cm).any ? 'match-any' : 'match-all')) + ')\n      ' + st.pk + ' packets, ' + st.by + ' bytes\n'); const a2 = c.act;
      if (a2.priority) io.print('      Priority: ' + (a2.priority > 1 ? a2.priority / 1000 + ' kbps' : 'Strict') + ', b/w exceed drops: ' + st.drop + '\n'); if (a2.dscp !== undefined) io.print('      QoS Set\n        dscp ' + Q.dscpName(a2.dscp) + '\n          Packets marked ' + st.marked + '\n'); if (a2.police) io.print('      police:\n          rate ' + a2.police + ' bps\n          conformed/exceeded drops ' + st.drop + '\n'); if (!a2.priority && !a2.police) io.print('      (drops ' + st.drop + ')\n'); });
    const qq = p.qos; if (qq && lab.includes('output')) io.print('\n      Queue: priority ' + qq.hiPk + ' pkts (drops ' + qq.hiDrops + '), standard ' + qq.loPk + ' pkts (drops ' + qq.loDrops + '), max queueing delay ' + qq.maxDelay.toFixed(1) + ' ms\n');
  });
});
cmd('priv', 'show class-map [<n>]', (s, a, io) => { QS(s).cmaps.forEach((c, n) => { if (a.n && a.n !== n) return; io.print(' Class Map ' + (c.any ? 'match-any' : 'match-all') + ' ' + n + '\n'); c.matches.forEach(m => io.print('   Match ' + (m.t === 'dscp' ? 'ip dscp ' + m.v.map(Q.dscpName).join(' ') : m.t === 'cos' ? 'cos ' + m.v.join(' ') : m.t === 'acl' ? 'access-group name ' + m.v : m.t === 'proto' ? 'protocol ' + m.v : 'any') + '\n')); }); });
cmd('priv', 'show mls qos', (s, a, io) => { if (!s.isSwitch) { bad(io); return; } io.print('QoS is ' + (QS(s).mls ? 'enabled' : 'disabled') + '\n'); if (QS(s).mls) io.print('QoS ip packet dscp rewrite is enabled\n'); });
cmd('priv', 'show mls qos interface <i...>', (s, a, io) => {
  const it = NS.iosUtil.makeItem(s, a.i, io); const p = it && it.port; if (!p) { bad(io); return; }
  io.print(p.name + '\ntrust state: ' + (p.trust === 'dscp' ? 'trust dscp' : p.trust === 'cos' ? 'trust cos' : 'not trusted') + '\ntrust mode: ' + (p.trust === 'dscp' ? 'trust dscp' : p.trust === 'cos' ? 'trust cos' : p.trust === 'phone' ? 'trust device cisco-phone' : 'not trusted') + '\ntrust enabled flag: ' + (p.trust ? 'ena' : 'dis') + '\nCOS override: dis\ndefault COS: 0\nDSCP Mutation Map: Default DSCP Mutation Map\nTrust device: ' + (p.trust === 'phone' ? 'cisco-phone' : 'none') + '\n' + (p.prioQ ? 'Priority queue (expedite): enabled\n' : ''));
});
cmd('priv', 'show mls qos maps cos-dscp', (s, a, io) => { io.print('   Cos-dscp map:\n     cos:   0  1  2  3  4  5  6  7\n     --------------------------------\n     dscp:  ' + Q.COS_DSCP.join('  ') + '\n'); });
/* ---- sauvegarde ---- */
NS.qosGlobal = function (dev, p) {
  const q = dev.qos; if (!q) return; let any = false;
  if (q.mls) { p('mls qos'); any = true; }
  q.cmaps.forEach(c => { p('class-map ' + (c.any ? 'match-any' : 'match-all') + ' ' + c.name); c.matches.forEach(m => p(' match ' + (m.t === 'dscp' ? 'ip dscp ' + m.v.map(Q.dscpName).join(' ') : m.t === 'cos' ? 'cos ' + m.v.join(' ') : m.t === 'acl' ? 'access-group name ' + m.v : m.t === 'proto' ? (m.v === 'rtp' ? 'ip rtp 16384 16383' : 'protocol ' + m.v) : 'any'))); p('!'); any = true; });
  q.pmaps.forEach(pm => { p('policy-map ' + pm.name); pm.classes.forEach(c => { p(' class ' + c.cm); const a = c.act; if (a.priority) p('  priority' + (a.prioPct ? ' percent ' + a.prioPct : a.priority > 1 ? ' ' + a.priority / 1000 : '')); if (a.bw) p('  bandwidth ' + a.bw); if (a.bwPct) p('  bandwidth percent ' + a.bwPct); if (a.dscp !== undefined) p('  set dscp ' + Q.dscpName(a.dscp)); if (a.police) p('  police ' + a.police); if (a.shape) p('  shape average ' + a.shape); }); p('!'); any = true; });
};
NS.qosIfLines = function (pt, ln) {
  if (pt.autoQos) { ln.push('auto qos voip ' + pt.autoQos); return; }
  if (pt.trust === 'dscp') ln.push('mls qos trust dscp'); else if (pt.trust === 'cos') ln.push('mls qos trust cos'); else if (pt.trust === 'phone') ln.push('mls qos trust device cisco-phone');
  if (pt.prioQ) ln.push('priority-queue out'); if (pt.svcIn) ln.push('service-policy input ' + pt.svcIn); if (pt.svcOut) ln.push('service-policy output ' + pt.svcOut);
};
})(typeof window !== 'undefined' ? window : globalThis);
