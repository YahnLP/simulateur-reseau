/* ioscli_l2.js — commandes IOS : Spanning Tree (PVST+/Rapid-PVST+, guards) et EtherChannel (LACP/PAgP) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const cmd = NS.iosCmd; const { pad, padL, cm, shortName, vlanListStr, parseVlanList, needSw } = NS.iosUtil;

const short = p => p.isChannel ? p.short : shortName(p.name);
const vname = v => 'VLAN' + String(v).padStart(4, '0');
const stName = { forwarding: 'FWD', blocking: 'BLK', listening: 'LIS', learning: 'LRN' };
const roleName = { root: 'Root', designated: 'Desg', alternate: 'Altn' };
function pvst(s) { return s.dev.stp.rapid ? 'rstp' : 'ieee'; }
function invalid(io) { io.print("% Invalid input detected at '^' marker.\n"); }

/* ------------------------------------------------------------------ configuration STP */
cmd('config', 'spanning-tree mode <x>', (s, a, io) => {
  if (!needSw(s, io)) return; const m = a.x.toLowerCase();
  if (m === 'pvst') s.dev.stp.setMode('pvst'); else if (m === 'rapid-pvst' || m === 'mst') { s.dev.stp.setMode('rapid-pvst'); if (m === 'mst') io.print('% MST n\'est pas simulé : Rapid-PVST+ est utilisé.\n'); } else invalid(io);
});
cmd('config', 'no spanning-tree mode', (s) => s.dev.stp.setMode('pvst'));
cmd('config', 'spanning-tree vlan <v> priority <p>', (s, a, io) => {
  if (!needSw(s, io)) return; const p = +a.p;
  if (!(p >= 0 && p <= 61440) || p % 4096) { io.print('% Bridge Priority must be in increments of 4096.\n% Allowed values are:\n  0     4096  8192  12288 16384 20480 24576 28672\n  32768 36864 40960 45056 49152 53248 57344 61440\n'); return; }
  const ids = Array.from(parseVlanList(a.v)); if (ids.length > 200) { s.dev.stp.defPri = p; s.dev.stp.vpri.clear(); s.dev.stp.recompute(); return; }
  ids.forEach(v => s.dev.stp.vpri.set(v, p)); s.dev.stp.enableVlan && ids.forEach(v => s.dev.stp.off.delete(v)); s.dev.stp.recompute();
});
cmd('config', 'no spanning-tree vlan <v> priority', (s, a) => { parseVlanList(a.v).forEach(v => s.dev.stp.vpri.delete(v)); s.dev.stp.recompute(); });
cmd('config', 'spanning-tree vlan <v> root <x> [<y...>]', (s, a, io) => {
  if (!needSw(s, io)) return; const st = s.dev.stp;
  parseVlanList(a.v).forEach(v => {
    const i = st.insts.get(v); let cur = i && i.rootPort !== null ? (i.rootPri - v) : null;
    let p;
    if (a.x.toLowerCase().startsWith('sec')) p = 28672;
    else if (cur === null) p = Math.min(st.pri(v), 24576);
    else p = cur > 24576 ? 24576 : Math.max(0, cur - 4096);
    st.vpri.set(v, p); st.off.delete(v);
  });
  st.recompute();
});
cmd('config', 'spanning-tree vlan <v> [<x...>]', () => { });
cmd('config', 'no spanning-tree vlan <v>', (s, a, io) => { if (!needSw(s, io)) return; parseVlanList(a.v).forEach(v => s.dev.stp.disableVlan(v)); });
cmd('config', 'spanning-tree portfast default', (s) => { s.dev.stp.gPortfast = true; s.dev.stp.recompute(); });
cmd('config', 'spanning-tree portfast edge default', (s) => { s.dev.stp.gPortfast = true; s.dev.stp.recompute(); });
cmd('config', 'no spanning-tree portfast default', (s) => { s.dev.stp.gPortfast = false; s.dev.stp.recompute(); });
cmd('config', 'spanning-tree portfast bpduguard default', (s) => { s.dev.stp.gBpduGuard = true; });
cmd('config', 'spanning-tree portfast edge bpduguard default', (s) => { s.dev.stp.gBpduGuard = true; });
cmd('config', 'no spanning-tree portfast bpduguard default', (s) => { s.dev.stp.gBpduGuard = false; });
cmd('config', 'spanning-tree <x...>', () => { });
cmd('config', 'no spanning-tree <x...>', () => { });

cmd('if', 'spanning-tree bpduguard <x>', (s, a, io) => { const m = a.x.toLowerCase(); s.items().forEach(it => { if (it.port) it.port.bpduGuard = m.startsWith('e') ? true : m.startsWith('d') ? false : undefined; }); });
cmd('if', 'no spanning-tree bpduguard', (s) => s.items().forEach(it => { if (it.port) it.port.bpduGuard = undefined; }));
cmd('if', 'spanning-tree guard <x>', (s, a) => s.items().forEach(it => { if (it.port) { it.port.rootGuard = a.x.toLowerCase() === 'root'; } }));
cmd('if', 'no spanning-tree guard', (s) => s.items().forEach(it => { if (it.port) it.port.rootGuard = false; }));
cmd('if', 'spanning-tree cost <n>', (s, a) => s.items().forEach(it => { if (it.port) it.port.stpCost = +a.n; }));
cmd('if', 'spanning-tree vlan <v> cost <n>', (s, a) => s.items().forEach(it => { if (it.port) it.port.stpCost = +a.n; }));
cmd('if', 'no spanning-tree cost', (s) => s.items().forEach(it => { if (it.port) it.port.stpCost = 0; }));
cmd('if', 'spanning-tree port-priority <n>', (s, a, io) => { const n = +a.n; if (n % 16 || n > 240) { invalid(io); return; } s.items().forEach(it => { if (it.port) it.port.stpPri = n; }); });
cmd('if', 'spanning-tree link-type <x>', () => { });

/* ------------------------------------------------------------------ show spanning-tree */
function showVlan(s, v, io) {
  const d = s.dev, st = d.stp, info = st.info(v); if (!info) return '';
  let o = vname(v) + '\n  Spanning tree enabled protocol ' + pvst(s) + '\n  Root ID    Priority    ' + info.rootPri + '\n             Address     ' + cm(info.rootMac) + '\n';
  if (info.isRoot) o += '             This bridge is the root\n'; else o += '             Cost        ' + info.rootCost + '\n             Port        ' + (info.rootPort.idx + 1) + '(' + info.rootPort.name + ')\n';
  o += '             Hello Time   2 sec  Max Age 20 sec  Forward Delay ' + st.fwd / 1000 + ' sec\n\n  Bridge ID  Priority    ' + info.brPri + '  (priority ' + st.pri(v) + ' sys-id-ext ' + v + ')\n             Address     ' + cm(d.baseMac) + '\n             Hello Time   2 sec  Max Age 20 sec  Forward Delay ' + st.fwd / 1000 + ' sec\n             Aging Time  300 sec\n\n';
  o += 'Interface           Role Sts Cost      Prio.Nbr Type\n------------------- ---- --- --------- -------- --------------------------------\n';
  info.ports.forEach(x => {
    const p = x.port; if (x.role === 'disabled' || !x.role) return;
    const inc = x.rootInc; const R = roleName[x.role] || '?'; const S = inc ? 'BKN' : (stName[x.state] || '?');
    const type = (st.isEdge(p) ? 'P2p Edge' : st.p2p(p) ? 'P2p' : 'Shr') + (inc ? ' *ROOT_Inc' : '') + (!st.rapid && x.best && x.best.rstp ? ' Peer(RSTP)' : st.rapid && x.best && x.best.rstp === false ? ' Peer(STP)' : '');
    o += pad(short(p), 19) + ' ' + R.padEnd(4) + ' ' + S.padEnd(3) + ' ' + String(st.cost(p)).padEnd(9) + ' ' + ((p.stpPri === undefined ? 128 : p.stpPri) + '.' + (p.idx + 1)).padEnd(8) + ' ' + type + '\n';
  });
  return o + '\n';
}
cmd('exec', 'show spanning-tree [<x...>]', (s, a, io) => {
  const d = s.dev; const st = d.stp; if (!s.isSwitch) { invalid(io); return; }
  if (!st.enabled || !st.insts.size) { io.print('No spanning tree instance exists.\n'); return; }
  const x = (a.x || '').trim(); const t = x.toLowerCase().split(/\s+/);
  if (t[0] === 'summary') return summary(s, io);
  if (t[0] === 'root') return rootTable(s, io);
  if (t[0] === 'blockedports') { let o = 'Name                 Blocked Interfaces List\n-------------------- ------------------------------------\n'; let n = 0; st.insts.forEach((i, v) => { const b = i.ports.filter(p => st.ps(p, v).state === 'blocking' && st.ps(p, v).role !== 'disabled').map(short); if (b.length) { o += pad(vname(v), 20) + ' ' + b.join(', ') + '\n'; n += b.length; } }); io.print(o + '\nNumber of blocked ports (segments) in the system : ' + n + '\n'); return; }
  if (t[0] === 'interface' || t[0] === 'int') {
    const p = (d.findChanPort && d.findChanPort(t[1])) || d.findPort(t[1]); if (!p) { invalid(io); return; }
    let o = 'Vlan             Role Sts Cost      Prio.Nbr Type\n---------------- ---- --- --------- -------- --------------------------------\n';
    st.insts.forEach((i, v) => { const x = st.ps(p, v); if (x && x.role !== 'disabled') o += pad(vname(v), 16) + ' ' + (roleName[x.role] || '?').padEnd(4) + ' ' + (stName[x.state] || '?').padEnd(3) + ' ' + String(st.cost(p)).padEnd(9) + ' ' + ((p.stpPri === undefined ? 128 : p.stpPri) + '.' + (p.idx + 1)).padEnd(8) + ' P2p\n'; });
    io.print(o); return;
  }
  let vids = Array.from(st.insts.keys()).sort((p, q) => p - q);
  if (t[0] === 'vlan') { const req = parseVlanList(t.slice(1).join(',')); vids = vids.filter(v => req.has ? req.has(v) : req.includes(v)); }
  let o = ''; vids.forEach(v => { o += showVlan(s, v, io); }); io.print(o);
});
function summary(s, io) {
  const d = s.dev, st = d.stp; const roots = []; st.insts.forEach((i, v) => { if (i.rootPort === null) roots.push(v); });
  let o = 'Switch is in ' + st.mode + ' mode\n';
  if (roots.length) o += 'Root bridge for: ' + roots.sort((a, b) => a - b).map(vname).join(', ') + '\n';
  o += 'Extended system ID           is enabled\nPortfast Default             is ' + (st.gPortfast ? 'enabled' : 'disabled') + '\nPortFast BPDU Guard Default  is ' + (st.gBpduGuard ? 'enabled' : 'disabled') + '\nPortfast BPDU Filter Default is disabled\nLoopguard Default            is disabled\nEtherChannel misconfig guard is enabled\nUplinkFast                   is disabled\nBackboneFast                 is disabled\nConfigured Pathcost method used is short\n\nName                   Blocking Listening Learning Forwarding STP Active\n---------------------- -------- --------- -------- ---------- ----------\n';
  let T = [0, 0, 0, 0, 0], n = 0;
  Array.from(st.insts.keys()).sort((a, b) => a - b).forEach(v => {
    const c = [0, 0, 0, 0]; st.insts.get(v).ports.forEach(p => { const x = st.ps(p, v); if (!x || x.role === 'disabled') return; c[{ blocking: 0, listening: 1, learning: 2, forwarding: 3 }[x.state] || 0]++; });
    const tot = c[0] + c[1] + c[2] + c[3]; n++; c.forEach((x, k) => T[k] += x); T[4] += tot;
    o += pad(vname(v), 22) + ' ' + padL(c[0], 8) + ' ' + padL(c[1], 9) + ' ' + padL(c[2], 8) + ' ' + padL(c[3], 10) + ' ' + padL(tot, 10) + '\n';
  });
  o += '---------------------- -------- --------- -------- ---------- ----------\n' + pad(n + ' vlan' + (n > 1 ? 's' : ''), 22) + ' ' + padL(T[0], 8) + ' ' + padL(T[1], 9) + ' ' + padL(T[2], 8) + ' ' + padL(T[3], 10) + ' ' + padL(T[4], 10) + '\n';
  io.print(o);
}
function rootTable(s, io) {
  const st = s.dev.stp; let o = '                                        Root    Hello Max Fwd\nVlan                   Root ID          Cost    Time  Age Dly  Root Port\n---------------- -------------------- --------- ----- --- ---  ------------------------\n';
  Array.from(st.insts.keys()).sort((a, b) => a - b).forEach(v => { const i = st.insts.get(v); o += pad(vname(v), 16) + ' ' + pad(i.rootPri + ' ' + cm(i.rootMac), 20) + ' ' + padL(i.rootCost, 9) + '     2  20  ' + String(st.fwd / 1000).padEnd(3) + ' ' + (i.rootPort ? short(i.rootPort) : '') + '\n'; });
  io.print(o);
}

/* ------------------------------------------------------------------ EtherChannel */
cmd('if', 'channel-group <n> mode <x>', (s, a, io) => {
  if (!needSw(s, io)) return; const n = +a.n, m = a.x.toLowerCase();
  if (!(n >= 1 && n <= 48)) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
  if (!['active', 'passive', 'on', 'desirable', 'auto'].includes(m)) { invalid(io); return; }
  s.items().forEach(it => {
    if (!it.port || it.port.isChannel) { io.print('% Invalid input detected at \'^\' marker.\n'); return; }
    if (it.port.routed) { io.print('% Interface ' + it.port.name + ' est routé : ne peut pas rejoindre un channel-group.\n'); return; }
    const c = s.dev.chans.get(n);
    if (c && c.members.length && c.proto !== ((m === 'on') ? 'on' : (m === 'active' || m === 'passive') ? 'lacp' : 'pagp')) { io.print('% Cannot mix protocols in a channel-group : ' + it.port.name + '\n'); return; }
    s.dev.addToChan(it.port, n, m);
    s.notice(io, '%EC-5-L3DONTBNDL2: (info) ' + shortName(it.port.name) + ' ajouté au channel-group ' + n);
  });
});
cmd('if', 'no channel-group [<n>]', (s, a, io) => s.items().forEach(it => { if (it.port && it.port.lag) s.dev.removeFromChan(it.port); }));
cmd('if', 'lacp rate <x>', (s, a) => s.items().forEach(it => { if (it.port) it.port.lacpFast = a.x.toLowerCase() === 'fast'; }));
cmd('if', 'lacp port-priority <n>', (s, a) => s.items().forEach(it => { if (it.port) it.port.lacpPri = +a.n; }));
cmd('config', 'lacp system-priority <n>', (s, a) => { s.dev.lacpPri = +a.n; });
cmd('config', 'port-channel load-balance <x>', (s, a, io) => { const m = a.x.toLowerCase(); if (!['src-mac', 'dst-mac', 'src-dst-mac', 'src-ip', 'dst-ip', 'src-dst-ip'].includes(m)) { invalid(io); return; } s.dev.lbMethod = m; });
cmd('config', 'no port-channel load-balance', (s) => { s.dev.lbMethod = 'src-mac'; });
cmd('config', 'no interface <x...>', (s, a, io) => { if (s.isRouter) { const t = /^(tunnel|tu|loopback|lo)\s*(\d+)$/i.exec(a.x.trim()); if (t) { const nm = (/^t/i.test(t[1]) ? 'Tunnel' : 'Loopback') + t[2]; const i = s.dev.ifaces.get(nm); if (i) { s.dev.ifaces.delete(nm); if (i.tun && s.dev.ospf && s.dev.ospf.refresh) s.dev.ospf.refresh(); } return; } const sb = /^(.+)\.(\d+)$/.exec(a.x.trim().replace(/\s+/g, '')); if (sb) { const par = s.dev.ifaceByName(sb[1]); if (par) s.dev.ifaces.delete(par.name + '.' + sb[2]); return; } } const m = /^(?:po|port-?channel)\s*(\d+)$/i.exec(a.x.trim()); if (m) { const c = s.dev.chans.get(+m[1]); if (c) c.members.slice().forEach(p => s.dev.removeFromChan(p)); } });
cmd('config', 'channel-protocol <x>', () => { });

function memberFlag(m) { if (!m.up) return 'D'; if (m.lag.bundled) return 'P'; return 'I'; }
cmd('exec', 'show etherchannel [<x...>]', (s, a, io) => {
  const d = s.dev; if (!s.isSwitch) { invalid(io); return; }
  const x = (a.x || '').trim().toLowerCase().split(/\s+/); const chans = Array.from(d.chans.values()).sort((p, q) => p.id - q.id);
  if (x[0] === 'load-balance') { io.print('EtherChannel Load-Balancing Configuration:\n        ' + d.lbMethod + '\n\nEtherChannel Load-Balancing Addresses Used Per-Protocol:\nNon-IP: ' + (d.lbMethod.includes('mac') ? d.lbMethod : 'Source MAC address') + '\n  IPv4: ' + (d.lbMethod.includes('ip') ? d.lbMethod : d.lbMethod) + '\n'); return; }
  if (x[0] === 'port-channel') { let o = ''; chans.forEach(c => { o += '                Port-channels in the group: \n                ---------------------------\n\nPort-channel: Po' + c.id + '    (Primary Aggregator)\n\n------------\n\nAge of the Port-channel   = 0d:00h:10m:00s\nLogical slot/port   = 1/' + c.id + '          Number of ports = ' + c.bundled().length + '\nPort state          = Port-channel ' + (c.lp.up ? 'Ag-Inuse' : 'Ag-Not-Inuse') + '\nProtocol            =   ' + (c.proto === 'lacp' ? 'LACP' : c.proto === 'pagp' ? 'PAgP' : '-') + '\n\n'; }); io.print(o); return; }
  const sel = /^\d+$/.test(x[0] || '') ? chans.filter(c => c.id === +x[0]) : chans;
  if (x[0] === 'detail') { let o = ''; sel.forEach(c => { o += 'Group state = ' + (c.proto === 'on' ? 'L2' : 'L2') + '\nPorts: ' + c.members.length + '   Maxports = 16\nPort-channels: 1 Max Port-channels = 16\nProtocol:   ' + (c.proto === 'lacp' ? 'LACP' : c.proto === 'pagp' ? 'PAgP' : '-') + '\n\n'; c.members.forEach(m => { o += 'Ports in the group:\n-------------------\nPort: ' + shortName(m.name) + '\n------------\nPort state    = ' + (m.up ? (m.lag.bundled ? 'Up Mstr In-Bndl' : 'Up Sngl-port-Bndl Mstr') : 'Down') + '\nChannel group = ' + c.id + '    Mode = ' + (m.lag.mode[0].toUpperCase() + m.lag.mode.slice(1)) + '   Gcchange = -\n\n'; }); }); io.print(o); return; }
  let o = 'Flags:  D - down        P - bundled in port-channel\n        I - stand-alone s - suspended\n        H - Hot-standby (LACP only)\n        R - Layer3      S - Layer2\n        U - in use      f - failed to allocate aggregator\n\n        M - not in use, minimum links not met\n        u - unsuitable for bundling\n        w - waiting to be aggregated\n        d - default port\n\n\nNumber of channel-groups in use: ' + chans.length + '\nNumber of aggregators:           ' + chans.length + '\n\nGroup  Port-channel  Protocol    Ports\n------+-------------+-----------+-----------------------------------------------\n';
  sel.forEach(c => { const up = c.lp.up; o += pad(c.id, 6) + ' ' + pad('Po' + c.id + '(' + (up ? 'SU' : 'SD') + ')', 13) + ' ' + pad(c.proto === 'lacp' ? 'LACP' : c.proto === 'pagp' ? 'PAgP' : '-', 11) + ' ' + c.members.map(m => shortName(m.name) + '(' + memberFlag(m) + ')').join('  ') + '\n'; });
  io.print(o);
});
function lacpState(st) { return ['Activity', 'Timeout', 'Aggregation', 'Synchronization', 'Collecting', 'Distributing', 'Defaulted', 'Expired'].filter((n, i) => (st >> i) & 1).join(','); }
cmd('exec', 'show lacp [<x>] [<y>]', (s, a, io) => {
  const d = s.dev; if (!s.isSwitch) { invalid(io); return; }
  const w = (a.x || 'internal').toLowerCase();
  if (w.startsWith('sys')) { io.print(d.lacpPri + ', ' + cm(d.baseMac) + '\n'); return; }
  let o = '';
  const chans = Array.from(d.chans.values()).filter(c => c.proto === 'lacp').sort((p, q) => p.id - q.id); o = '';
  if (w.startsWith('n')) {
    o = 'Flags:  S - Device is requesting Slow LACPDUs\n        F - Device is requesting Fast LACPDUs\n        A - Device is in Active mode       P - Device is in Passive mode\n\n';
    chans.forEach(c => { o += 'Channel group ' + c.id + ' neighbors\n\nPartner\'s information:\n\n                  LACP port                        Admin  Oper   Port    Port\nPort      Flags   Priority  Dev ID          Age    key    Key    Number  State\n'; c.members.forEach(m => { const p = m.lag.partner; if (p) o += pad(shortName(m.name), 9) + ' ' + pad((p.state & 2 ? 'F' : 'S') + (p.state & 1 ? 'A' : 'P'), 7) + ' ' + pad(p.portPri, 9) + ' ' + pad(cm(p.sysMac), 15) + ' ' + pad(Math.floor((d.sim.now - m.lag.lastRx) / 1000) + 's', 6) + ' 0x0    0x' + p.key.toString(16) + '    0x' + p.port.toString(16) + '  0x' + p.state.toString(16) + '\n'; }); o += '\n'; });
  } else {
    o = 'Flags:  S - Device is requesting Slow LACPDUs\n        F - Device is requesting Fast LACPDUs\n        A - Device is in Active mode       P - Device is in Passive mode\n\n';
    chans.forEach(c => { o += 'Channel group ' + c.id + '\n                            LACP port     Admin     Oper    Port        Port\nPort      Flags   State     Priority  Key       Key     Number      State\n'; c.members.forEach(m => { const st = (m.lag.bundled ? 'bndl' : m.up ? 'susp' : 'down'); o += pad(shortName(m.name), 9) + ' ' + pad((m.lacpFast ? 'F' : 'S') + (m.lag.mode === 'active' ? 'A' : 'P'), 7) + ' ' + pad(st, 9) + ' ' + pad(m.lacpPri || 32768, 9) + ' 0x' + c.id.toString(16).padEnd(7) + ' 0x' + c.id.toString(16).padEnd(6) + ' 0x' + (m.idx + 1).toString(16).padEnd(9) + ' 0x' + (m.lag.bundled ? 0x3d : 0x5).toString(16) + '\n'; }); o += '\n'; });
  }
  io.print(o);
});
cmd('exec', 'show pagp [<x>] [<y>]', (s, a, io) => {
  const d = s.dev; if (!s.isSwitch) { invalid(io); return; } const w = (a.x || 'neighbor').toLowerCase();
  const chans = Array.from(d.chans.values()).filter(c => c.proto === 'pagp').sort((p, q) => p.id - q.id);
  let o = 'Flags:  S - Device is sending Slow hello.  C - Device is in Consistent state.\n        A - Device is in Auto mode.        P - Device learns on physical port.\n\n';
  if (w.startsWith('n')) { chans.forEach(c => { o += 'Channel group ' + c.id + ' neighbors\n          Partner              Partner          Partner         Partner Group\nPort      Name                 Device ID        Port       Age  Flags   Cap.\n'; c.members.forEach(m => { const p = m.lag.partner; if (p) o += pad(shortName(m.name), 9) + ' ' + pad('-', 20) + ' ' + pad(cm(p.devId), 16) + ' ' + pad(p.ifIndex, 10) + ' ' + pad(Math.floor((d.sim.now - m.lag.lastRx) / 1000) + 's', 4) + ' SC      ' + p.group + '\n'; }); o += '\n'; }); }
  else { chans.forEach(c => { o += 'Channel group ' + c.id + '\n                          Hello    Partner  PAgP       Learning  Group\nPort      State    Interval Count   Priority   Method    Ifindex\n'; c.members.forEach(m => { o += pad(shortName(m.name), 9) + ' ' + pad(m.lag.bundled ? 'Py' : 'U6/S7', 8) + ' ' + pad(m.lacpFast ? '1s' : '30s', 8) + ' 1       128        Any       ' + (m.idx + 1) + '\n'; }); o += '\n'; }); }
  io.print(o);
});
})(typeof window !== 'undefined' ? window : globalThis);
