/* hostshell_ip6.js — IPv6 côté postes : ip -6, ping -6/ping6, traceroute6, ipconfig, netsh interface ipv6 */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, IP6, MAC, HostShell, tools } = NS; const L = HostShell.prototype.linCmds, W = HostShell.prototype.winCmds;
const pad = (s, n) => { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); };
const padL = (s, n) => { s = String(s); return s.length >= n ? s : ' '.repeat(n - s.length) + s; };
const s6 = IP6.str;
const zoneIdx = i => i.port ? i.port.idx + 4 : 1;

/* résout "adresse[%zone]" -> {addr, iface|null} */
function parseTarget(h, s) {
  const m = /^([^%]+)(?:%(.+))?$/.exec(String(s)); if (!m) return null; const a = IP6.parse(m[1]); if (a === null) return null;
  let iface = null; if (m[2]) iface = h.ifaceList().find(i => i.name.toLowerCase() === m[2].toLowerCase() || String(zoneIdx(i)) === m[2]) || null;
  return { addr: a, iface };
}
const v6ifaces = h => h.ifaceList().filter(i => i.v6);
function defaultIface(h) { return h.ifaceList().find(i => i.v6 && i.isUp()) || h.mainIface; }
function llOf(i) { const a = i.v6 && i.v6.addrs.find(x => x.kind === 'll'); return a ? a.addr : null; }

/* ---------------- ping / traceroute ---------------- */
function ping6(sh, io, t, o, win) {
  const h = sh.host; const dst = t.addr; const zone = t.iface; const size = o.size; const fs = win ? null : null; const t0 = h.sim.now;
  if (win) io.print('\nEnvoi d\'une requête \'Ping\'  ' + s6(dst) + ' avec ' + size + ' octets de données :\n');
  else io.print('PING ' + s6(dst) + '(' + s6(dst) + ') ' + size + ' data bytes\n');
  const src = () => (h.mainIface.v6 ? llOf(h.mainIface) : 0n);
  tools.pingSeries(h, dst, { count: o.count, size, interval: o.interval, ttl: o.ttl, zone, abort: () => sh.aborted }, (r, seq) => {
    if (win) {
      const tm = r.rtt < 1 ? '<1ms' : '=' + Math.round(r.rtt) + 'ms';
      if (r.type === 'reply') io.print('Réponse de ' + s6(r.from) + ' : temps' + tm + '\n');
      else if (r.type === 'timeout') io.print('Délai d\'attente de la demande dépassé.\n');
      else if (r.type === 'unreach') io.print('Réponse de ' + s6(r.from) + ' : ' + ({ 0: 'Impossible de joindre le réseau de destination.', 3: 'Impossible de joindre l\'hôte de destination.', 1: 'Communication administrativement filtrée.' }[r.code] || 'Destination inaccessible.') + '\n');
      else if (r.type === 'ttl') io.print('Réponse de ' + s6(r.from) + ' : TTL expiré lors du transit.\n');
      else if (r.type === 'ptb') io.print('Réponse de ' + s6(r.from) + ' : Paquet trop volumineux (MTU=' + r.mtu + ').\n');
      else if (r.type === 'arpfail') io.print('Réponse de ' + s6(src() || 0n) + ' : Impossible de joindre l\'hôte de destination.\n');
      else io.print('PING : échec général.\n');
    } else {
      if (r.type === 'reply') io.print((size + 8) + ' bytes from ' + s6(r.from) + ': icmp_seq=' + seq + ' ttl=' + r.ttl + ' time=' + r.rtt.toFixed(3) + ' ms\n');
      else if (r.type === 'unreach') io.print('From ' + s6(r.from) + ' icmp_seq=' + seq + ' Destination unreachable: ' + ({ 0: 'No route', 1: 'Administratively prohibited', 3: 'Address unreachable', 4: 'Port unreachable' }[r.code] || 'Unreachable') + '\n');
      else if (r.type === 'ttl') io.print('From ' + s6(r.from) + ' icmp_seq=' + seq + ' Time exceeded: Hop limit\n');
      else if (r.type === 'ptb') io.print('From ' + s6(r.from) + ' icmp_seq=' + seq + ' Packet too big: mtu=' + r.mtu + '\n');
      else if (r.type === 'arpfail') io.print('From ' + s6(src() || 0n) + ' icmp_seq=' + seq + ' Destination unreachable: Address unreachable\n');
      else if (r.type === 'noroute') io.print('ping: connect: Network is unreachable\n');
    }
  }, st => {
    const rt = tools.fmtStats(st.rtts); const loss = Math.round((st.sent - st.recv) * 100 / Math.max(1, st.sent));
    if (win) { io.print('\nStatistiques Ping pour ' + s6(dst) + ':\n    Paquets : envoyés = ' + st.sent + ', reçus = ' + st.recv + ', perdus = ' + (st.sent - st.recv) + ' (perte ' + loss + '%),\n'); if (rt) io.print('Durée approximative des boucles en millisecondes :\n    Minimum = ' + Math.floor(rt.mn) + 'ms, Maximum = ' + Math.floor(rt.mx) + 'ms, Moyenne = ' + Math.floor(rt.av) + 'ms\n'); }
    else { io.print('\n--- ' + s6(dst) + ' ping statistics ---\n' + st.sent + ' packets transmitted, ' + st.recv + ' received, ' + loss + '% packet loss, time ' + Math.round(h.sim.now - t0) + 'ms\n'); if (rt) io.print('rtt min/avg/max/mdev = ' + rt.mn.toFixed(3) + '/' + rt.av.toFixed(3) + '/' + rt.mx.toFixed(3) + '/0.000 ms\n'); }
    io.done();
  });
}
function trace6(sh, io, t, win) {
  const h = sh.host; const dst = t.addr;
  if (win) io.print('\nDétermination de l\'itinéraire vers ' + s6(dst) + '\navec un maximum de 30 sauts :\n\n');
  else io.print('traceroute to ' + s6(dst) + ' (' + s6(dst) + ') from ' + s6(llOf(defaultIface(h)) || 0n) + ', 30 hops max, 80 byte packets\n');
  tools.trace(h, dst, { maxHops: 30, probes: 3, zone: t.iface, abort: () => sh.aborted }, (ttl, rs) => {
    const first = rs.find(r => r.from !== undefined);
    if (win) { let line = padL(ttl, 3) + '  '; rs.forEach(r => { line += r.type === 'reply' || r.type === 'ttl' || r.type === 'unreach' ? padL(r.rtt < 1 ? '<1 ms' : Math.round(r.rtt) + ' ms', 7) + ' ' : padL('*', 7) + ' '; }); io.print(line + ' ' + (first ? s6(first.from) : 'Délai d\'attente de la demande dépassé.') + '\n'); }
    else { let line = padL(ttl, 2) + '  ' + (first ? s6(first.from) + ' (' + s6(first.from) + ')' : '* * *'); if (first) rs.forEach(r => { line += r.type === 'timeout' ? '  *' : '  ' + r.rtt.toFixed(3) + ' ms'; }); io.print(line + '\n'); }
  }, ok => { if (win) io.print(ok ? '\nItinéraire déterminé.\n' : '\nItinéraire non déterminé.\n'); io.done(); });
}
/* ---- Linux ---- */
const linPing = L.ping, linTrace = L.traceroute;
function linPing6(a, io) {
  const o = { count: Infinity, size: 56, interval: 1000, ttl: undefined }; let name = null;
  for (let i = 0; i < a.length; i++) { if (a[i] === '-c') o.count = +a[++i] || 4; else if (a[i] === '-s') o.size = +a[++i] || 56; else if (a[i] === '-i') o.interval = (+a[++i] || 1) * 1000; else if (a[i] === '-t') o.ttl = +a[++i]; else if (!a[i].startsWith('-')) name = a[i]; }
  if (!name) { io.print('Usage: ping [-6] [-c count] [-s size] destination\n'); return; }
  const t = parseTarget(this.host, name); if (!t) { io.print('ping: ' + name + ': Name or service not known\n'); return; }
  ping6(this, io, t, o, false); return 'async';
}
const isV6Arg = a => a.some(x => !x.startsWith('-') && /:/.test(x) && IP6.parse(x.replace(/%.*/, '')) !== null);
L.ping = function (a, io) { if (a.includes('-6') || isV6Arg(a)) return linPing6.call(this, a.filter(x => x !== '-6'), io); return linPing.call(this, a, io); };
L.ping6 = function (a, io) { return linPing6.call(this, a, io); };
L.traceroute = function (a, io) { if (a.includes('-6') || isV6Arg(a)) { const n = a.filter(x => !x.startsWith('-'))[0]; const t = n && parseTarget(this.host, n); if (!t) { io.print('traceroute: unknown host\n'); return; } trace6(this, io, t, false); return 'async'; } return linTrace.call(this, a, io); };
L.traceroute6 = function (a, io) { return L.traceroute.call(this, ['-6'].concat(a), io); }; L.tracepath = L.traceroute; L.tracepath6 = L.traceroute6;
/* ip addr avec inet6 */
const linIp = L.ip;
function fmtLife(a) { return a.vl === null ? 'forever' : Math.max(0, Math.floor(a.vl - (a.tt || 0))) + 'sec'; }
function ipAddrShow(h, io, only6, only) {
  let n = 1;
  if (!only) io.print('1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n' + (only6 ? '' : '    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n') + '    inet6 ::1/128 scope host\n       valid_lft forever preferred_lft forever\n');
  h.ifaceList().forEach(i => {
    n++; if (only && i.name !== only) return;
    io.print(n + ': ' + i.name + ': <BROADCAST,MULTICAST' + (i.isUp() ? ',UP,LOWER_UP' : '') + '> mtu ' + (i.v6 ? i.v6.mtu : 1500) + ' qdisc fq_codel state ' + (i.isUp() ? 'UP' : 'DOWN') + ' group default qlen 1000\n    link/ether ' + i.mac + ' brd ff:ff:ff:ff:ff:ff\n');
    if (!only6 && i.ip) io.print('    inet ' + IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask) + ' brd ' + IP.str(IP.bcast(i.ip, i.mask)) + ' scope global' + (i.dhcp ? ' dynamic' : '') + ' ' + i.name + '\n       valid_lft forever preferred_lft forever\n');
    if (i.v6) i.v6.addrs.filter(a => a.state !== 'duplicate').sort((x, y) => (y.kind === 'll' ? 0 : 1) - (x.kind === 'll' ? 0 : 1)).forEach(a => {
      const el = a.vl === null ? null : Math.max(0, a.vl - Math.floor((h.sim.now - a.t) / 1000)), pl = a.pl === null ? null : Math.max(0, a.pl - Math.floor((h.sim.now - a.t) / 1000));
      io.print('    inet6 ' + s6(a.addr) + '/' + a.plen + ' scope ' + (a.kind === 'll' ? 'link' : 'global') + (a.kind === 'slaac' ? ' dynamic mngtmpaddr' : '') + (a.state === 'tentative' ? ' tentative' : '') + '\n       valid_lft ' + (el === null ? 'forever' : el + 'sec') + ' preferred_lft ' + (pl === null ? 'forever' : pl + 'sec') + '\n');
    });
  });
}
L.ip = function (a, io) {
  const h = this.host; const six = a.includes('-6'); const args = a.filter(x => x !== '-6' && x !== '-4'); const sub = (args[0] || '').toLowerCase();
  const isAddr = ['a', 'addr', 'address'].includes(sub), isRoute = ['r', 'route'].includes(sub), isNeigh = ['n', 'neigh', 'neighbor', 'neighbour'].includes(sub);
  if (isAddr && (args[1] === 'add' || args[1] === 'del')) {
    const c = IP6.parseCidr(args[2] || ''); if (!c) { if (six) { io.print('Error: any valid prefix is expected rather than "' + (args[2] || '') + '".\n'); return; } return linIp.call(this, a, io); }
    const i = h.ifaceByName(args[4] || '') || h.mainIface; if (!i.v6) h.ip6.enable(i);
    if (args[1] === 'add') { if (i.v6.addrs.some(x => x.addr === c.addr)) { io.print('RTNETLINK answers: File exists\n'); return; } h.ip6.addAddr(i, c.addr, c.plen, IP6.isLinkLocal(c.addr) ? 'll' : 'manual'); } else { if (!i.v6.addrs.some(x => x.addr === c.addr)) { io.print('RTNETLINK answers: Cannot assign requested address\n'); return; } h.ip6.removeAddr(i, c.addr); }
    return;
  }
  if (isAddr && (six || !args[1] || args[1] === 'show')) { if (six && args[1] === 'show' && args[2] === 'dev') return ipAddrShow(h, io, true, args[3]); return ipAddrShow(h, io, six, null); }
  if (isRoute && six) {
    const d = h.ip6;
    if (args[1] === 'add' || args[1] === 'replace') {
      const isDef = args[2] === 'default'; const c = isDef ? { addr: 0n, plen: 0 } : IP6.parseCidr(args[2] || ''); if (!c) { io.print('Error: inet6 prefix is expected rather than "' + (args[2] || '') + '".\n'); return; }
      const vi = args.indexOf('via'), di = args.indexOf('dev'); const nh = vi >= 0 ? IP6.parse((args[vi + 1] || '').replace(/%.*/, '')) : null; const ifc = di >= 0 ? h.ifaceByName(args[di + 1]) : null;
      if (nh === null && !ifc) { io.print('Error: either "to" is duplicate, or "' + (args[3] || '') + '" is a garbage.\n'); return; }
      if (nh !== null && IP6.isLinkLocal(nh) && !ifc) { const i = defaultIface(h); d.statics = d.statics.filter(x => !(x.net === c.addr && x.plen === c.plen)); d.statics.push({ net: IP6.net(c.addr, c.plen), plen: c.plen, nh, iface: i.name, ad: 1 }); return; }
      d.statics = d.statics.filter(x => !(x.net === IP6.net(c.addr, c.plen) && x.plen === c.plen)); d.statics.push({ net: IP6.net(c.addr, c.plen), plen: c.plen, nh, iface: ifc ? ifc.name : null, ad: 1 }); return;
    }
    if (args[1] === 'del' || args[1] === 'delete' || args[1] === 'flush') { if (args[2] && args[2] !== 'default' && IP6.parseCidr(args[2])) { const c = IP6.parseCidr(args[2]); d.statics = d.statics.filter(x => !(x.net === IP6.net(c.addr, c.plen) && x.plen === c.plen)); } else if (args[2] === 'default') d.statics = d.statics.filter(x => x.plen !== 0); else d.statics = []; return; }
    const rs = d.allRoutes().filter(r => r.proto !== 'ND' || true).sort((x, y) => (x.plen - y.plen) || (x.net < y.net ? -1 : 1));
    rs.forEach(r => { const dev = r.iface.name; const pre = r.plen === 0 ? 'default' : s6(r.net) + '/' + r.plen; if (r.proto === 'C') io.print(pre + ' dev ' + dev + ' proto kernel metric 256 pref medium\n'); else io.print(pre + ' via ' + (r.nh ? s6(r.nh) : '::') + ' dev ' + dev + (r.proto === 'ND' ? ' proto ra metric 1024 pref medium' : ' metric 1024 pref medium') + '\n'); });
    h.ifaceList().forEach(i => { if (i.v6 && i.isUp() && i.v6.addrs.some(a => a.kind === 'll')) io.print('fe80::/64 dev ' + i.name + ' proto kernel metric 256 pref medium\n'); });
    return;
  }
  if (isNeigh && six) {
    const ab = { REACHABLE: 'REACHABLE', STALE: 'STALE', DELAY: 'DELAY', PROBE: 'PROBE', INCOMPLETE: 'INCOMPLETE' };
    h.ip6.nc.forEach(e => { const st = h.ip6.nstate(e); io.print(s6(e.addr) + ' dev ' + e.iface.name + (e.mac ? ' lladdr ' + e.mac : '') + (e.router ? ' router' : '') + ' ' + ab[st] + '\n'); }); return;
  }
  return linIp.call(this, a, io);
};
/* ---- Windows ---- */
const winPing = W.ping;
W.ping = function (a, io, toks) {
  const six = a.some(x => x === '-6'); const lit = a.filter(x => !x.startsWith('-') && !/^\d+$/.test(x)).find(x => IP6.parse(x.replace(/%.*/, '')) !== null);
  if (!six && !lit) return winPing.call(this, a, io, toks);
  const o = { count: 4, size: 32, interval: 1000, ttl: undefined }; let name = null;
  for (let i = 0; i < a.length; i++) { const t = a[i].toLowerCase(); if (t === '-n') o.count = +a[++i] || 4; else if (t === '-l') o.size = +a[++i] || 32; else if (t === '-t') o.count = Infinity; else if (t === '-i') o.ttl = +a[++i]; else if (t === '-6' || t === '-4' || t === '-a') { } else if (t === '-s') i++; else name = a[i]; }
  if (!name) { io.print('\nUtilisation : ping [-t] [-a] [-n échos] [-l taille] [-i TTL] nom_cible\n'); return; }
  const t = parseTarget(this.host, name); if (!t) { io.print('La requête Ping n\'a pas pu trouver l\'hôte ' + name + '. Vérifiez le nom et essayez à nouveau.\n'); return; }
  ping6(this, io, t, o, true); return 'async';
};
const winTr = W.tracert;
W.tracert = function (a, io) { const six = a.includes('-6'); const n = a.filter(x => !x.startsWith('-'))[0]; const t = n && IP6.parse(String(n).replace(/%.*/, '')) !== null ? parseTarget(this.host, n) : null; if (six && !t) { io.print('\nImpossible de résoudre le nom de la cible ' + (n || '') + '.\n'); return; } if (t) { trace6(this, io, t, true); return 'async'; } return winTr.call(this, a, io); };
/* ipconfig : lignes IPv6 */
const ipcBlock = HostShell.prototype.ipconfigBlock;
HostShell.prototype.ipconfigBlock = function (i, all) {
  let o = ipcBlock.call(this, i, all); if (!i.isUp() || !i.v6) return o;
  const dots = (lbl, v) => '   ' + lbl + ' ' + '. '.repeat(Math.max(1, Math.floor((38 - lbl.length - 1) / 2))) + ': ' + v + '\n';
  let add = ''; const z = '%' + zoneIdx(i);
  i.v6.addrs.filter(a => a.kind !== 'll' && a.state !== 'duplicate').forEach(a => { add += dots('Adresse IPv6', s6(a.addr)); });
  const ll = i.v6.addrs.find(a => a.kind === 'll'); if (ll) add += dots('Adresse IPv6 de liaison locale', s6(ll.addr) + z + (ll.state === 'tentative' ? '(tentative)' : ''));
  const k = o.indexOf('   Suffixe DNS propre'); if (k >= 0) { const e = o.indexOf('\n', k) + 1; o = o.slice(0, e) + add + o.slice(e); }
  const gws = this.host.ip6.allRoutes().filter(r => r.plen === 0 && r.iface === i).map(r => s6(r.nh) + (IP6.isLinkLocal(r.nh) ? z : ''));
  if (gws.length) { const m = /   Passerelle par défaut[^\n]*\n/.exec(o); const line = dots('Passerelle par défaut', gws[0]) + gws.slice(1).map(x => ' '.repeat(39) + x + '\n').join(''); if (m) { const cur = m[0].split(': ')[1]; const v4 = cur.replace('\n', '').trim(); o = o.replace(m[0], line.replace(/\n$/, '') + (v4 ? '\n' + ' '.repeat(39) + v4 : '') + '\n'); } else o = o.replace(/\n\n$/, '\n' + line + '\n'); }
  return o;
};
/* netsh interface ipv6 */
function netshV6(sh, a, io) {
  const h = sh.host, d = h.ip6; const t = a.map(x => x.replace(/^"|"$/g, '')); const low = t.map(x => x.toLowerCase());
  const kv = {}; t.forEach(x => { const m = /^(\w+)=(.*)$/.exec(x); if (m) kv[m[1].toLowerCase()] = m[2].replace(/^"|"$/g, ''); });
  const verb = low[2], obj = low[3];
  const pos = t.slice(4).filter(x => !/=/.test(x));
  const ifn = kv.interface || kv.name || (obj === 'address' || obj === 'route' ? pos[obj === 'address' ? 0 : 1] : null);
  const findIf = n => h.ifaceList().find(i => i.name.toLowerCase() === String(n || '').toLowerCase() || String(zoneIdx(i)) === String(n)) || null;
  if (verb === 'show') {
    if (obj === 'addresses' || obj === 'address') {
      h.ifaceList().forEach(i => { if (!i.v6) return; io.print('\nInterface ' + zoneIdx(i) + ' : ' + i.name + '\n\nType d\'adresse     DAD État        Durée de vie valide   Durée de vie préférée  Adresse\n-----------------  --------------  --------------------  ---------------------  ---------------------\n');
        i.v6.addrs.filter(a => a.state !== 'duplicate' || true).forEach(a => io.print(pad(a.kind === 'manual' ? 'Manuel' : a.kind === 'slaac' ? 'Public' : 'Autre', 19) + pad(a.state === 'preferred' ? 'Préféré' : a.state === 'tentative' ? 'Provisoire' : 'Dupliqué', 16) + pad(a.vl === null ? 'infinite' : a.vl + 's', 22) + pad(a.pl === null ? 'infinite' : a.pl + 's', 23) + s6(a.addr) + (a.kind === 'll' ? '%' + zoneIdx(i) : '') + '\n')); }); return;
    }
    if (obj === 'neighbors' || obj === 'neighbor') { h.ifaceList().forEach(i => { const es = Array.from(d.nc.values()).filter(e => e.iface === i); if (!i.v6) return; io.print('\nInterface ' + zoneIdx(i) + ': ' + i.name + '\n\nAdresse Internet                              Adresse physique   Type\n--------------------------------------------  -----------------  -----------\n'); es.forEach(e => io.print(pad(s6(e.addr), 46) + pad(e.mac ? e.mac.toUpperCase().replace(/:/g, '-') : '', 19) + ({ REACHABLE: 'Accessible', STALE: 'Périmé', DELAY: 'Délai', PROBE: 'Sonde', INCOMPLETE: 'Incomplet' }[d.nstate(e)]) + '\n')); }); return; }
    if (obj === 'route' || obj === 'routes') {
      io.print('\nPublication  Type      Mét  Préfixe                    Idx  Nom de la passerelle/l\'interface\n-----------  --------  ---  ------------------------  ---  --------------------------------\n');
      d.allRoutes().forEach(r => io.print(pad(r.proto === 'S' ? 'Oui' : 'Non', 13) + pad(r.proto === 'C' ? 'Manuel' : r.proto === 'ND' ? 'Autoconf' : 'Manuel', 10) + pad(r.proto === 'S' ? 256 : 256, 5) + pad(r.plen === 0 ? '::/0' : s6(r.net) + '/' + r.plen, 26) + pad(zoneIdx(r.iface), 5) + (r.nh ? s6(r.nh) + (IP6.isLinkLocal(r.nh) ? '%' + zoneIdx(r.iface) : '') : r.iface.name) + '\n')); return;
    }
    if (obj === 'interfaces' || obj === 'interface') { io.print('\nIdx  Met         MTU          État                Nom\n---  ---  ----------  -----------  ---------------------------\n'); h.ifaceList().forEach(i => io.print(pad(zoneIdx(i), 5) + pad(25, 5) + pad(i.v6 ? i.v6.mtu : 1500, 12) + pad(i.isUp() ? 'connected' : 'disconnected', 13) + i.name + '\n')); return; }
  }
  if (verb === 'add' || verb === 'set' || verb === 'delete') {
    if (obj === 'address') {
      const raw = kv.address || pos.find(x => /:/.test(x)) || ''; const c = IP6.parseCidr(raw.includes('/') ? raw : raw + '/64'); const i = findIf(ifn) || defaultIface(h); if (!c || !i) { io.print('Paramètre incorrect.\n'); return; }
      if (!i.v6) d.enable(i);
      if (verb === 'delete') { d.removeAddr(i, c.addr); return; }
      if (verb === 'set') i.v6.addrs = i.v6.addrs.filter(x => x.kind !== 'manual'); if (i.v6.addrs.some(x => x.addr === c.addr)) { io.print('Le fichier existe déjà.\n'); return; } d.addAddr(i, c.addr, c.plen, 'manual'); i.v6.autoconf = i.v6.autoconf; return;
    }
    if (obj === 'route') {
      const pfx = kv.prefix || pos[0]; const c = IP6.parseCidr(pfx || ''); if (!c) { io.print('Paramètre incorrect.\n'); return; }
      const i = findIf(kv.interface || pos[1]); const nhs = kv.nexthop || pos.slice(2).find(x => IP6.parse(x.replace(/%.*/, '')) !== null); const nh = nhs ? IP6.parse(nhs.replace(/%.*/, '')) : null;
      if (verb === 'delete') { d.statics = d.statics.filter(x => !(x.net === IP6.net(c.addr, c.plen) && x.plen === c.plen)); return; }
      if (!i) { io.print('Le paramètre est incorrect.\n'); return; }
      d.statics = d.statics.filter(x => !(x.net === IP6.net(c.addr, c.plen) && x.plen === c.plen)); d.statics.push({ net: IP6.net(c.addr, c.plen), plen: c.plen, nh, iface: i.name, ad: 1 }); return;
    }
  }
  io.print('Utilisation : netsh interface ipv6 [show|add|set|delete] [addresses|neighbors|route|address]\n');
}
const winNetsh = W.netsh;
W.netsh = function (a, io) { if ((a[0] || '').toLowerCase() === 'interface' && /^ipv6$/i.test(a[1] || '')) { netshV6(this, a, io); return; } return winNetsh.call(this, a, io); };
const winRoute = W.route;
W.route = function (a, io) {
  if ((a[0] || '').toLowerCase() === 'print' && (a[1] || '') === '-6') {
    const h = this.host; io.print('===========================================================================\nListe d\'interfaces\n' + h.ifaceList().map(i => padL(zoneIdx(i), 3) + '...' + i.mac.replace(/:/g, ' ') + ' ......' + 'Intel(R) Ethernet (simulé)').join('\n') + '\n  1...........................Software Loopback Interface 1\n===========================================================================\n\nTable de routage IPv6\n===========================================================================\nItinéraires actifs :\n If Métrique Destination réseau      Passerelle\n');
    const rows = []; h.ip6.allRoutes().forEach(r => rows.push([zoneIdx(r.iface), r.proto === 'ND' ? 266 : 266, r.plen === 0 ? '::/0' : s6(r.net) + '/' + r.plen, r.nh ? s6(r.nh) : 'On-link']));
    h.ifaceList().forEach(i => { if (i.v6) { const ll = i.v6.addrs.find(a => a.kind === 'll'); if (ll) { rows.push([zoneIdx(i), 266, 'fe80::/64', 'On-link']); rows.push([zoneIdx(i), 266, s6(ll.addr) + '/128', 'On-link']); } } });
    rows.push([1, 331, '::1/128', 'On-link'], [1, 331, 'ff00::/8', 'On-link']);
    rows.forEach(r => io.print(padL(r[0], 3) + padL(r[1], 8) + ' ' + pad(r[2], 26) + r[3] + '\n')); io.print('===========================================================================\nItinéraires persistants :\n  Aucun\n'); return;
  }
  return winRoute.call(this, a, io);
};
})(typeof window !== 'undefined' ? window : globalThis);
