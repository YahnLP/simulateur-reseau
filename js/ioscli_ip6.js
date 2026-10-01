/* ioscli_ip6.js — commandes IOS : IPv6 (adresses, ND, routes statiques, show, clear) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP6 } = NS; const cmd = NS.iosCmd; const { pad, statusOf } = NS.iosUtil;
const bad = io => io.print("% Invalid input detected at '^' marker.\n");
const up = IP6.strUp;
const has = s => !!s.dev.ip6;
const each = (s, f) => s.items().forEach(it => { if (it.iface) f(it.iface); });

/* ---------------- global ---------------- */
cmd('config', 'ipv6 unicast-routing', (s) => s.dev.ip6.setRouting(true)); cmd('config', 'no ipv6 unicast-routing', (s) => s.dev.ip6.setRouting(false));
cmd('config', 'ipv6 cef', () => { }); cmd('config', 'no ipv6 cef', () => { }); cmd('config', 'ipv6 hop-limit <n>', (s, a) => { s.dev.ip6.hopLimit = +a.n; });
function parseRoute(s, a, io) {
  const c = IP6.parseCidr(a.p); if (!c) { bad(io); return null; } const r = { net: IP6.net(c.addr, c.plen), plen: c.plen, nh: null, iface: null, ad: 1 };
  for (const t of (a._rest || [])) { const v = IP6.parse(t); if (v !== null) r.nh = v; else if (/^\d+$/.test(t)) r.ad = +t; else { const i = s.dev.ifaceByName(t); if (!i) { io.print('% Invalid interface ' + t + '\n'); return null; } r.iface = i.name; } }
  if (r.nh === null && !r.iface) { bad(io); return null; }
  if (r.nh !== null && IP6.isLinkLocal(r.nh) && !r.iface) { io.print('%Interface has to be specified for a link-local nexthop\n'); return null; }
  return r;
}
const sameRoute = (a, b) => a.net === b.net && a.plen === b.plen && a.nh === b.nh && (a.iface || '') === (b.iface || '');
cmd('config', 'ipv6 route <p> <x...>', (s, a, io) => { const r = parseRoute(s, a, io); if (!r) return; const d = s.dev.ip6; d.statics = d.statics.filter(x => !sameRoute(x, r)); d.statics.push(r); });
cmd('config', 'no ipv6 route <p> [<x...>]', (s, a, io) => { const c = IP6.parseCidr(a.p); if (!c) { bad(io); return; } const d = s.dev.ip6; if (!(a._rest || []).length) { d.statics = d.statics.filter(x => !(x.net === IP6.net(c.addr, c.plen) && x.plen === c.plen)); return; } const r = parseRoute(s, a, io); if (r) d.statics = d.statics.filter(x => !sameRoute(x, r)); });

/* ---------------- interface ---------------- */
cmd('if', 'ipv6 enable', (s) => each(s, i => s.dev.ip6.enable(i))); cmd('if', 'no ipv6 enable', (s) => each(s, i => { if (i.v6 && !i.v6.addrs.some(a => a.kind !== 'll')) s.dev.ip6.disable(i); }));
cmd('if', 'ipv6 address <a> [<x...>]', (s, a, io) => {
  const x = (a._rest || []).map(t => t.toLowerCase());
  if (a.a.toLowerCase() === 'autoconfig') { each(s, i => { const st = s.dev.ip6.enable(i); st.autoconf = true; st.raSuppress = true; if (i.isUp()) s.dev.ip6.sendRS(i); }); return; }
  if (x[0] === 'link-local') { const v = IP6.parse(a.a); if (v === null || !IP6.isLinkLocal(v)) { io.print('% Invalid link-local address\n'); return; } each(s, i => { const st = s.dev.ip6.enable(i); st.addrs.filter(q => q.kind === 'll').forEach(q => { s.dev.sim.cancel(q.dadT); }); st.addrs = st.addrs.filter(q => q.kind !== 'll'); s.dev.ip6.addAddr(i, v, 64, 'll', { manual: true }).manual = true; }); return; }
  const c = IP6.parseCidr(a.a); if (!c) { bad(io); return; }
  if (IP6.isMulticast(c.addr) || IP6.isLoopback(c.addr) || IP6.isUnspecified(c.addr)) { io.print('% Invalid address\n'); return; }
  each(s, i => { const d = s.dev.ip6; d.enable(i); if (x[0] === 'eui-64') { if (c.plen > 64) { io.print('% Prefix length must be <= 64 for eui-64\n'); return; } d.addAddr(i, IP6.withIid(c.addr, i.mac), c.plen, 'manual', { eui: true }); } else d.addAddr(i, c.addr, c.plen, 'manual'); });
});
cmd('if', 'no ipv6 address [<a>] [<x...>]', (s, a) => each(s, i => { const d = s.dev.ip6, st = i.v6; if (!st) return; if (!a.a) { st.addrs = st.addrs.filter(q => q.kind === 'll'); st.autoconf = false; return; } if (a.a.toLowerCase() === 'autoconfig') { st.autoconf = false; st.addrs = st.addrs.filter(q => q.kind !== 'slaac'); return; } const c = IP6.parseCidr(a.a); if (!c) return; const isEui = (a._rest || [])[0] === 'eui-64'; st.addrs = st.addrs.filter(q => !(q.kind !== 'll' && (isEui ? q.eui && IP6.net(q.addr, q.plen) === IP6.net(c.addr, c.plen) : q.addr === c.addr))); }));
cmd('if', 'ipv6 mtu <n>', (s, a) => each(s, i => { if (i.v6) i.v6.mtu = Math.max(1280, Math.min(9000, +a.n)); }));
cmd('if', 'ipv6 nd ra suppress [<x...>]', (s) => each(s, i => { if (i.v6) i.v6.raSuppress = true; })); cmd('if', 'no ipv6 nd ra suppress [<x...>]', (s) => each(s, i => { if (i.v6) { i.v6.raSuppress = false; s.dev.ip6.raSoon(i); } }));
cmd('if', 'ipv6 nd suppress-ra', (s) => each(s, i => { if (i.v6) i.v6.raSuppress = true; })); cmd('if', 'no ipv6 nd suppress-ra', (s) => each(s, i => { if (i.v6) { i.v6.raSuppress = false; s.dev.ip6.raSoon(i); } }));
cmd('if', 'ipv6 nd ra-interval <n>', (s, a) => each(s, i => { if (i.v6) i.v6.raInterval = Math.max(4, +a.n); })); cmd('if', 'no ipv6 nd ra-interval', (s) => each(s, i => { if (i.v6) i.v6.raInterval = 200; }));
cmd('if', 'ipv6 nd ra-lifetime <n>', (s, a) => each(s, i => { if (i.v6) i.v6.raLife = +a.n; })); cmd('if', 'no ipv6 nd ra-lifetime', (s) => each(s, i => { if (i.v6) i.v6.raLife = 1800; }));
cmd('if', 'ipv6 nd managed-config-flag', (s) => each(s, i => { if (i.v6) i.v6.m = true; })); cmd('if', 'no ipv6 nd managed-config-flag', (s) => each(s, i => { if (i.v6) i.v6.m = false; }));
cmd('if', 'ipv6 nd other-config-flag', (s) => each(s, i => { if (i.v6) i.v6.o = true; })); cmd('if', 'no ipv6 nd other-config-flag', (s) => each(s, i => { if (i.v6) i.v6.o = false; }));
cmd('if', 'ipv6 nd dad attempts <n>', (s, a) => each(s, i => { if (i.v6) i.v6.dad = +a.n > 0; }));
cmd('if', 'ipv6 nd prefix <p> [<x...>]', (s, a, io) => {
  const c = IP6.parseCidr(a.p); if (!c) { bad(io); return; } const t = (a._rest || []).map(x => x.toLowerCase()); const nums = t.filter(x => /^\d+$/.test(x)).map(Number);
  each(s, i => { const st = i.v6; if (!st) return; st.prefixes = st.prefixes || []; st.prefixes = st.prefixes.filter(q => q.prefix !== IP6.net(c.addr, c.plen)); if (t.includes('no-advertise')) { st.prefixes.push({ prefix: IP6.net(c.addr, c.plen), plen: c.plen, hidden: true, l: true, a: true, vl: 0, pl: 0 }); return; } st.prefixes.push({ prefix: IP6.net(c.addr, c.plen), plen: c.plen, l: !t.includes('no-onlink'), a: !t.includes('no-autoconfig'), vl: nums[0] === undefined ? 2592000 : nums[0], pl: nums[1] === undefined ? 604800 : nums[1], cfg: true }); st.prefixes = st.prefixes.filter(q => !q.hidden); });
});
cmd('if', 'ipv6 nd ra dns server <a> [<x...>]', (s, a, io) => { const v = IP6.parse(a.a); if (v === null) { bad(io); return; } each(s, i => { if (i.v6 && !i.v6.dnsRa.includes(v)) i.v6.dnsRa.push(v); }); });
cmd('if', 'no ipv6 nd ra dns server [<a>]', (s) => each(s, i => { if (i.v6) i.v6.dnsRa = []; }));
cmd('if', 'ipv6 <x...>', () => { }); cmd('if', 'no ipv6 <x...>', () => { });

/* ---------------- show ---------------- */
const ifName = (s, i) => i.svi !== null ? 'Vlan' + i.svi : i.name;
function v6ifaces(s) { return s.dev.ifaceList().filter(i => i.v6 || true); }
cmd('exec', 'show ipv6 interface brief', (s, a, io) => {
  const d = s.dev; let o = '';
  const list = s.isSwitch ? d.ifaceList().filter(i => i.svi !== null).concat(d.ports.filter(p => p.routed).map(p => p.routed)) : d.ifaceList();
  list.forEach(i => { const st = statusOf(d, i); o += pad(ifName(s, i), 23) + '[' + (st[0] === 'up' ? 'up' : st[0]) + '/' + st[1] + ']\n'; const v = i.v6; if (!v || !v.addrs.length) { o += '    unassigned\n'; return; } v.addrs.slice().sort((x, y) => (x.kind === 'll' ? 0 : 1) - (y.kind === 'll' ? 0 : 1)).forEach(q => { o += '    ' + up(q.addr) + (q.state === 'tentative' ? ' [TEN]' : q.state === 'duplicate' ? ' [DUP]' : '') + '\n'; }); });
  io.print(o);
});
function ifDetail(s, i) {
  const d = s.dev, v = i.v6, st = statusOf(d, i); let o = ifName(s, i) + ' is ' + st[0] + ', line protocol is ' + st[1] + '\n';
  if (!v) return o + '  IPv6 is disabled, link-local address unassigned\n';
  const ll = v.addrs.find(q => q.kind === 'll'); o += '  IPv6 is ' + (v.addrs.some(q => q.state === 'tentative') ? 'tentative' : 'enabled') + ', link-local address is ' + (ll ? up(ll.addr) : 'unassigned') + (ll && ll.state === 'tentative' ? ' [TEN]' : '') + '\n  No Virtual link-local address(es):\n';
  const gl = v.addrs.filter(q => q.kind !== 'll'); if (gl.length) { o += '  Global unicast address(es):\n'; gl.forEach(q => { o += '    ' + up(q.addr) + ', subnet is ' + up(IP6.net(q.addr, q.plen)) + '/' + q.plen + (q.kind === 'slaac' ? ' [EUI/CAL/PRE]\n      valid lifetime ' + q.vl + ', preferred lifetime ' + q.pl : q.eui ? ' [EUI]' : '') + (q.state === 'tentative' ? ' [TEN]' : q.state === 'duplicate' ? ' [DUP]' : '') + '\n'; }); }
  else o += '  No global unicast address is configured\n';
  o += '  Joined group address(es):\n    FF02::1\n'; if (d.ip6.routing) o += '    FF02::2\n'; const seen = new Set(); v.addrs.forEach(q => { const m = up(IP6.solicited(q.addr)); if (!seen.has(m)) { seen.add(m); o += '    ' + m + '\n'; } });
  o += '  MTU is ' + v.mtu + ' bytes\n  ICMP error messages limited to one every 100 milliseconds\n  ICMP redirects are enabled\n  ICMP unreachables are sent\n  ND DAD is ' + (v.dad ? 'enabled, number of DAD attempts: 1' : 'disabled') + '\n  ND reachable time is 30000 milliseconds (using 30000)\n  ND advertised reachable time is 0 (unspecified)\n  ND advertised retransmit interval is 0 (unspecified)\n';
  if (d.ip6.routing && !v.raSuppress) o += '  ND router advertisements are sent every ' + v.raInterval + ' seconds\n  ND router advertisements live for ' + v.raLife + ' seconds\n  ND advertised default router preference is Medium\n  Hosts use ' + (v.m ? 'DHCP for addresses' : 'stateless autoconfig for addresses') + '.\n'; else if (d.ip6.routing) o += '  ND router advertisements are disabled\n';
  return o;
}
cmd('exec', 'show ipv6 interface [<x...>]', (s, a, io) => {
  const d = s.dev; const x = (a.x || '').trim(); let list;
  if (x) { const i = d.ifaceByName(x.replace(/\s+/g, '')) || (s.isSwitch && /^vlan\s*\d+$/i.test(x) ? d.ifaceList().find(q => q.svi === +x.replace(/\D/g, '')) : null); if (!i) { bad(io); return; } list = [i]; }
  else list = (s.isSwitch ? d.ifaceList().filter(i => i.svi !== null) : d.ifaceList()).filter(i => i.v6);
  io.print(list.map(i => ifDetail(s, i)).join(''));
});
const CODES = 'Codes: C - Connected, L - Local, S - Static, U - Per-user Static route\n       B - BGP, R - RIP, H - NHRP, I1 - ISIS L1\n       I2 - ISIS L2, IA - ISIS interarea, IS - ISIS summary, D - EIGRP\n       EX - EIGRP external, ND - ND Default, NDp - ND Prefix, DCE - Destination\n       NDr - Redirect, RL - RPL, O - OSPF Intra, OI - OSPF Inter\n       OE1 - OSPF ext 1, OE2 - OSPF ext 2, ON1 - OSPF NSSA ext 1\n       ON2 - OSPF NSSA ext 2, a - Application\n';
cmd('exec', 'show ipv6 route [<x...>]', (s, a, io) => {
  const d = s.dev; const f = (a.x || '').toLowerCase().split(/\s+/)[0]; const dp = d.ip6;
  let rs = dp.allRoutes().concat(dp.locals()); if (!dp.routing && !rs.length) { io.print('% IPv6 routing table is empty or ipv6 unicast-routing is not enabled\n'); return; }
  rs.push({ net: 0xffn << 120n, plen: 8, iface: null, proto: 'L', ad: 0, metric: 0, null0: true });
  const code = { C: 'C', L: 'L', S: 'S', ND: 'ND' }; const want = { static: 'S', connected: 'C', local: 'L' }[f];
  if (want) rs = rs.filter(r => r.proto === want);
  rs.sort((x, y) => (x.net < y.net ? -1 : x.net > y.net ? 1 : x.plen - y.plen));
  let o = 'IPv6 Routing Table - default - ' + rs.length + ' entries\n' + CODES;
  rs.forEach(r => { o += pad(code[r.proto], 4) + up(r.net) + '/' + r.plen + ' [' + r.ad + '/' + r.metric + ']\n     via ' + (r.null0 ? 'Null0, receive' : r.proto === 'C' ? ifName(s, r.iface) + ', directly connected' : r.proto === 'L' ? ifName(s, r.iface) + ', receive' : (r.nh ? up(r.nh) + (IP6.isLinkLocal(r.nh) ? ', ' + ifName(s, r.iface) : '') : ifName(s, r.iface) + ', directly connected')) + '\n'; });
  io.print(o);
});
cmd('exec', 'show ipv6 neighbors [<x...>]', (s, a, io) => {
  const d = s.dev; const dp = d.ip6; let o = pad('IPv6 Address', 41) + ' Age Link-layer Addr State Interface\n';
  const ab = { REACHABLE: 'REACH', STALE: 'STALE', DELAY: 'DELAY', PROBE: 'PROBE', INCOMPLETE: 'INCMP' };
  const rows = Array.from(dp.nc.values()).filter(e => e.mac || e.state === 'INCOMPLETE').sort((x, y) => (x.addr < y.addr ? -1 : 1));
  rows.forEach(e => { const st = dp.nstate(e); o += pad(up(e.addr), 41) + String(Math.floor((d.sim.now - e.t) / 60000)).padStart(4) + ' ' + (e.mac ? NS.MAC.cisco(e.mac) : '-').padEnd(14) + ' ' + pad(ab[st], 5) + ' ' + ifName(s, e.iface).replace('GigabitEthernet', 'Gi').replace('FastEthernet', 'Fa') + '\n'; });
  io.print(o);
});
cmd('exec', 'show ipv6 routers', (s, a, io) => { const dp = s.dev.ip6; let o = ''; dp.raDefaults.forEach(r => { o += 'Router ' + up(r.nh) + ' on ' + ifName(s, r.iface) + ', last update time ' + Math.floor((s.dev.sim.now - (r.exp - r.life * 1000)) / 60000) + ' min\n  Hops 64, Lifetime ' + r.life + ' sec\n'; }); io.print(o); });
cmd('exec', 'clear ipv6 neighbors', (s) => { const dp = s.dev.ip6; for (const [k, e] of Array.from(dp.nc)) { if (e.state !== 'INCOMPLETE') { s.dev.sim.cancel(e.timer); dp.nc.delete(k); } } });

/* ---------------- running-config ---------------- */
NS.ip6Global = function (dev, p, when) {
  const d = dev.ip6; if (!d) return;
  if (when === 'pre') { if (d.routing) { p('ipv6 unicast-routing'); p('!'); } return; }
  if (d.statics.length) { d.statics.forEach(r => p('ipv6 route ' + up(r.net) + '/' + r.plen + (r.iface ? ' ' + r.iface : '') + (r.nh !== null ? ' ' + up(r.nh) : '') + (r.ad !== 1 ? ' ' + r.ad : ''))); p('!'); }
};
NS.ip6Lines = function (i, ln) {
  const v = i.v6; if (!v) return; const gl = v.addrs.filter(q => q.kind === 'manual');
  const ll = v.addrs.find(q => q.kind === 'll' && q.manual); if (ll) ln.push('ipv6 address ' + up(ll.addr) + ' link-local');
  if (!gl.length && !v.autoconf && !ll) ln.push('ipv6 enable');
  gl.forEach(q => ln.push('ipv6 address ' + up(q.eui ? IP6.net(q.addr, q.plen) : q.addr) + '/' + q.plen + (q.eui ? ' eui-64' : '')));
  if (v.autoconf && !NS.ip6IsHost(i)) ln.push('ipv6 address autoconfig');
  if (v.mtu !== 1500) ln.push('ipv6 mtu ' + v.mtu); if (!v.dad) ln.push('ipv6 nd dad attempts 0');
  if (v.raSuppress && !NS.ip6IsHost(i) && !v.autoconf) ln.push('ipv6 nd ra suppress all'); if (v.raInterval !== 200) ln.push('ipv6 nd ra-interval ' + v.raInterval); if (v.raLife !== 1800) ln.push('ipv6 nd ra-lifetime ' + v.raLife);
  if (v.m) ln.push('ipv6 nd managed-config-flag'); if (v.o) ln.push('ipv6 nd other-config-flag');
  if (v.prefixes) v.prefixes.filter(q => q.cfg).forEach(q => ln.push('ipv6 nd prefix ' + up(q.prefix) + '/' + q.plen + ' ' + q.vl + ' ' + q.pl + (q.a ? '' : ' no-autoconfig') + (q.l ? '' : ' no-onlink')));
  v.dnsRa.forEach(x => ln.push('ipv6 nd ra dns server ' + up(x)));
};
NS.ip6IsHost = () => false;
})(typeof window !== 'undefined' ? window : globalThis);
