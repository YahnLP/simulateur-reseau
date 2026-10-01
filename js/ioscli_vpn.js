/* ioscli_vpn.js — commandes IOS : GRE (interface Tunnel), IPsec/IKE (crypto isakmp, transform-set, crypto map, profile) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP } = NS; const cmd = NS.iosCmd; const { pad, padL, fmtDur } = NS.iosUtil; const U = NS.vpnUtil;
const bad = io => io.print("% Invalid input detected at '^' marker.\n");
const V = s => s.dev.vpn; const rtr = s => !!(s.isRouter && s.dev.vpn);
const each = (s, f) => s.items().forEach(it => { if (it.iface) f(it.iface); });
const hx = n => (n >>> 0).toString(16).padStart(8, '0').toUpperCase();

/* ------------------------------------------------------------------ IKE : politiques et clés */
cmd('config', 'crypto isakmp policy <n>', (s, a, io) => { if (!rtr(s)) return bad(io); const n = +a.n; if (!(n >= 1 && n <= 10000)) return bad(io); V(s).ensure(); V(s).policy(n, true); s.mode = 'isakmp'; s.ctx = { prio: n }; });
cmd('config', 'no crypto isakmp policy <n>', (s, a) => { const v = V(s); if (v) v.policies = v.policies.filter(p => p.prio !== +a.n); });
const pol = s => V(s).policy(s.ctx.prio, true);
cmd('isakmp', 'encryption <e> [<b>]', (s, a, io) => { const p = pol(s); const e = a.e.toLowerCase(); if (e === 'aes') { const b = a.b ? +a.b : 128; if (![128, 192, 256].includes(b)) return bad(io); p.enc = 'aes'; p.bits = b; } else if (e === '3des') { p.enc = '3des'; p.bits = 168; } else if (e === 'des') { p.enc = 'des'; p.bits = 56; } else bad(io); });
cmd('isakmp', 'hash <h>', (s, a, io) => { const h = a.h.toLowerCase(); if (!['sha', 'md5', 'sha256'].includes(h)) return bad(io); pol(s).hash = h; });
cmd('isakmp', 'authentication <m>', (s, a, io) => { const m = a.m.toLowerCase(); if (m === 'pre-share') pol(s).auth = 'pre-share'; else if (m === 'rsa-sig') pol(s).auth = 'rsa-sig'; else bad(io); });
cmd('isakmp', 'group <g>', (s, a, io) => { if (!U.GROUPS[+a.g]) return bad(io); pol(s).group = +a.g; });
cmd('isakmp', 'lifetime <n>', (s, a, io) => { const n = +a.n; if (!(n >= 60 && n <= 86400)) return bad(io); pol(s).life = n; });
cmd('isakmp', 'no <x...>', () => { });
cmd('config', 'crypto isakmp key <k> address <a> [<m>]', (s, a, io) => {
  const v = V(s); if (!v) return bad(io); const ip = IP.parse(a.a); if (ip === null) return bad(io); v.ensure(); v.keys = v.keys.filter(k => k.addr !== ip); v.keys.push({ addr: ip, key: a.k });
});
cmd('config', 'no crypto isakmp key <k> address <a> [<m>]', (s, a) => { const v = V(s); if (v) { const ip = IP.parse(a.a); v.keys = v.keys.filter(k => k.addr !== ip); } });
cmd('config', 'crypto isakmp enable', (s) => { if (V(s)) V(s).ikeEnabled = true; }); cmd('config', 'no crypto isakmp enable', (s) => { if (V(s)) V(s).ikeEnabled = false; });
cmd('config', 'crypto isakmp <x...>', () => { }); cmd('config', 'crypto ipsec security-association <x...>', (s, a) => { const m = /lifetime seconds (\d+)/.exec(a.x); if (m && V(s)) V(s).saLife = +m[1]; });
cmd('config', 'crypto ipsec <x...>', () => { }, {});

/* ------------------------------------------------------------------ IPsec : transform-set */
function parseXforms(toks) {
  const ts = { enc: null, bits: 128, auth: null }; let i = 0; if (!toks.length || toks.length > 3) return null;
  for (; i < toks.length; i++) {
    const t = toks[i].toLowerCase();
    if (t === 'esp-aes') { ts.enc = 'aes'; if (/^(128|192|256)$/.test(toks[i + 1] || '')) { ts.bits = +toks[i + 1]; i++; } }
    else if (t === 'esp-3des') ts.enc = '3des'; else if (t === 'esp-des') ts.enc = 'des'; else if (t === 'esp-null') ts.enc = 'null';
    else if (t === 'esp-sha-hmac') ts.auth = 'sha'; else if (t === 'esp-md5-hmac') ts.auth = 'md5'; else if (t === 'esp-sha256-hmac') ts.auth = 'sha256';
    else return null;
  }
  if (!ts.enc) return null; return ts;
}
cmd('config', 'crypto ipsec transform-set <n> <x...>', (s, a, io) => {
  const v = V(s); if (!v) return bad(io); const x = parseXforms(a._rest); if (!x) return bad(io); v.ensure(); const old = v.tsets.get(a.n);
  v.tsets.set(a.n, Object.assign({ name: a.n, mode: old ? old.mode : 'tunnel' }, x)); s.mode = 'tset'; s.ctx = { name: a.n };
});
cmd('config', 'no crypto ipsec transform-set <n>', (s, a) => { if (V(s)) V(s).tsets.delete(a.n); });
cmd('tset', 'mode <m>', (s, a, io) => { const m = a.m.toLowerCase(); if (m !== 'tunnel' && m !== 'transport') return bad(io); V(s).tsets.get(s.ctx.name).mode = m; });
cmd('tset', 'no <x...>', () => { });

/* ------------------------------------------------------------------ crypto map */
cmd('config', 'crypto map <n> <q> [<x...>]', (s, a, io) => {
  const v = V(s); if (!rtr(s)) return bad(io); const seq = +a.q; if (!(seq >= 1 && seq <= 65535)) return bad(io); const kind = (a._rest || [])[0]; if (kind && kind.toLowerCase() !== 'ipsec-isakmp') return bad(io);
  v.ensure(); let cm = v.cmaps.get(a.n); if (!cm) { cm = { name: a.n, entries: new Map() }; v.cmaps.set(a.n, cm); }
  let e = cm.entries.get(seq); if (!e) { if (!kind) { io.print('% Crypto map entry ' + a.n + ' ' + seq + ' does not exist\n'); return; } e = { seq, peer: 0, acl: null, tset: null, pfs: null, life: 3600 }; cm.entries.set(seq, e); io.print('% NOTE: This new crypto map will remain disabled until a peer\n        and a valid access list have been configured.\n'); }
  s.mode = 'cmap'; s.ctx = { cm, e };
});
cmd('config', 'no crypto map <n> [<q>]', (s, a) => { const v = V(s); if (!v) return; const cm = v.cmaps.get(a.n); if (!cm) return; if (a.q) cm.entries.delete(+a.q); else v.cmaps.delete(a.n); if (!cm.entries.size) v.cmaps.delete(a.n); });
cmd('cmap', 'set peer <ip> [<x...>]', (s, a, io) => { const ip = IP.parse(a.ip); if (ip === null) return bad(io); s.ctx.e.peer = ip; });
cmd('cmap', 'no set peer [<x...>]', (s) => { s.ctx.e.peer = 0; });
cmd('cmap', 'set transform-set <n> [<x...>]', (s, a, io) => { if (!V(s).tsets.has(a.n) && !s.dev.restoring) { io.print('% Transform set ' + a.n + ' cannot be found\n'); return; } s.ctx.e.tset = a.n; });
cmd('cmap', 'no set transform-set [<x...>]', (s) => { s.ctx.e.tset = null; });
cmd('cmap', 'match address <acl>', (s, a) => { s.ctx.e.acl = a.acl; });
cmd('cmap', 'no match address [<x...>]', (s) => { s.ctx.e.acl = null; });
cmd('cmap', 'set pfs <g>', (s, a, io) => { const m = /^group(\d+)$/.exec(a.g.toLowerCase()); if (!m || !U.GROUPS[+m[1]]) return bad(io); s.ctx.e.pfs = +m[1]; });
cmd('cmap', 'set pfs', (s) => { s.ctx.e.pfs = 1; });
cmd('cmap', 'no set pfs', (s) => { s.ctx.e.pfs = null; });
cmd('cmap', 'set security-association lifetime <k> <n>', (s, a) => { if (a.k.toLowerCase() === 'seconds') s.ctx.e.life = +a.n; });
cmd('cmap', 'set <x...>', () => { }); cmd('cmap', 'reverse-route <x...>', () => { }); cmd('cmap', 'reverse-route', () => { }); cmd('cmap', 'no <x...>', () => { });
/* profil IPsec (tunnel protection) */
cmd('config', 'crypto ipsec profile <n>', (s, a, io) => { const v = V(s); if (!rtr(s)) return bad(io); v.ensure(); if (!v.profiles.has(a.n)) v.profiles.set(a.n, { name: a.n, tset: null, pfs: null, life: 3600 }); s.mode = 'ipsecprof'; s.ctx = { p: v.profiles.get(a.n) }; });
cmd('config', 'no crypto ipsec profile <n>', (s, a) => { if (V(s)) V(s).profiles.delete(a.n); });
cmd('ipsecprof', 'set transform-set <n> [<x...>]', (s, a, io) => { if (!V(s).tsets.has(a.n) && !s.dev.restoring) { io.print('% Transform set ' + a.n + ' cannot be found\n'); return; } s.ctx.p.tset = a.n; });
cmd('ipsecprof', 'set pfs <g>', (s, a, io) => { const m = /^group(\d+)$/.exec(a.g.toLowerCase()); if (!m || !U.GROUPS[+m[1]]) return bad(io); s.ctx.p.pfs = +m[1]; });
cmd('ipsecprof', 'set security-association lifetime <k> <n>', (s, a) => { if (a.k.toLowerCase() === 'seconds') s.ctx.p.life = +a.n; });
cmd('ipsecprof', 'set <x...>', () => { }); cmd('ipsecprof', 'no <x...>', () => { });

/* ------------------------------------------------------------------ interface : crypto map + tunnel */
cmd('if', 'crypto map <n>', (s, a, io) => { if (!rtr(s)) return bad(io); const v = V(s); v.ensure(); each(s, i => { if (i.tun) return; i.cmap = a.n; }); if (!v.cmaps.has(a.n) && !s.dev.restoring) io.print('% Crypto map ' + a.n + ' not found (yet)\n'); s.dev.log('%CRYPTO-6-ISAKMP_ON_OFF: ISAKMP is ON', 'info'); });
cmd('if', 'no crypto map [<n>]', (s) => each(s, i => { i.cmap = null; }));
cmd('if', 'crypto <x...>', () => { });
const tun = (s, io, f) => { let n = 0; each(s, i => { if (i.tun) { f(i); n++; } }); if (!n) io.print('% Invalid input detected at \'^\' marker.\n'); else V(s).tunCheckAll(); };
cmd('if', 'tunnel source <x>', (s, a, io) => tun(s, io, i => { const ip = IP.parse(a.x); if (ip !== null) { i.tun.srcIp = ip; i.tun.srcIf = null; } else { if (!s.dev.ifaceByName(a.x) && !s.dev.restoring) { io.print('%Invalid source: interface ' + a.x + ' not found\n'); return; } i.tun.srcIf = a.x; i.tun.srcIp = 0; } }));
cmd('if', 'no tunnel source', (s, a, io) => tun(s, io, i => { i.tun.srcIf = null; i.tun.srcIp = 0; }));
cmd('if', 'tunnel destination <ip>', (s, a, io) => tun(s, io, i => { const ip = IP.parse(a.ip); if (ip === null) { io.print('%Bad IP address or host name\n'); return; } i.tun.dst = ip; }));
cmd('if', 'no tunnel destination', (s, a, io) => tun(s, io, i => { i.tun.dst = 0; }));
cmd('if', 'tunnel mode <x...>', (s, a, io) => tun(s, io, i => { const m = a._rest.join(' ').toLowerCase(); if (m !== 'gre ip' && m !== 'gre') { io.print('% Mode non simulé (seul « tunnel mode gre ip » est disponible)\n'); return; } i.tun.mode = 'gre'; }));
cmd('if', 'tunnel key <n>', (s, a, io) => tun(s, io, i => { const k = +a.n; if (!(k >= 0 && k <= 4294967295)) return bad(io); i.tun.key = k; }));
cmd('if', 'no tunnel key', (s, a, io) => tun(s, io, i => { i.tun.key = null; }));
cmd('if', 'tunnel protection ipsec profile <p> [<x...>]', (s, a, io) => tun(s, io, i => { i.tun.prot = a.p; if (!V(s).profiles.has(a.p) && !s.dev.restoring) io.print('% IPSec profile ' + a.p + ' does not exist yet\n'); }));
cmd('if', 'no tunnel protection ipsec profile [<x...>]', (s, a, io) => tun(s, io, i => { i.tun.prot = null; }));
cmd('if', 'tunnel <x...>', () => { }); cmd('if', 'keepalive [<x...>]', () => { }); cmd('if', 'no keepalive', () => { });
cmd('if', 'ip mtu <n>', (s, a) => each(s, i => { i.mtu = +a.n; })); cmd('if', 'ip tcp adjust-mss <n>', () => { });

/* ------------------------------------------------------------------ configuration → texte */
NS.vpnGlobal = function (dev, p) {
  const v = dev.vpn; if (!v || !v.active) return;
  const pols = v.policies.slice(); if (!v.ikeEnabled) p('no crypto isakmp enable');
  pols.forEach(po => { p('crypto isakmp policy ' + po.prio); if (po.enc !== 'des') p(' encryption ' + po.enc + (po.enc === 'aes' ? ' ' + po.bits : '')); if (po.hash !== 'sha') p(' hash ' + po.hash); if (po.auth === 'pre-share') p(' authentication pre-share'); if (po.group !== 1) p(' group ' + po.group); if (po.life !== 86400) p(' lifetime ' + po.life); p('!'); });
  v.keys.forEach(k => p('crypto isakmp key ' + k.key + ' address ' + IP.str(k.addr)));
  if (v.keys.length) p('!'); if (v.saLife) { p('crypto ipsec security-association lifetime seconds ' + v.saLife); p('!'); }
  v.tsets.forEach(ts => { p('crypto ipsec transform-set ' + ts.name + ' ' + v.tsetText(ts)); if (ts.mode !== 'tunnel') p(' mode ' + ts.mode); p('!'); });
  v.profiles.forEach(pr => { p('crypto ipsec profile ' + pr.name); if (pr.tset) p(' set transform-set ' + pr.tset); if (pr.life !== 3600) p(' set security-association lifetime seconds ' + pr.life); if (pr.pfs) p(' set pfs group' + pr.pfs); p('!'); });
  v.cmaps.forEach(cm => Array.from(cm.entries.keys()).sort((a, b) => a - b).forEach(sq => {
    const e = cm.entries.get(sq); p('crypto map ' + cm.name + ' ' + sq + ' ipsec-isakmp'); if (e.peer) p(' set peer ' + IP.str(e.peer)); if (e.tset) p(' set transform-set ' + e.tset); if (e.life !== 3600) p(' set security-association lifetime seconds ' + e.life); if (e.pfs) p(' set pfs group' + e.pfs); if (e.acl) p(' match address ' + e.acl); p('!');
  }));
};
NS.vpnIfLines = function (i, ln) {
  if (i.cmap) ln.push('crypto map ' + i.cmap);
  if (i.tun) { const t = i.tun; if (t.srcIf) ln.push('tunnel source ' + t.srcIf); else if (t.srcIp) ln.push('tunnel source ' + IP.str(t.srcIp)); if (t.dst) ln.push('tunnel destination ' + IP.str(t.dst)); if (t.key !== null && t.key !== undefined) ln.push('tunnel key ' + t.key); if (t.prot) ln.push('tunnel protection ipsec profile ' + t.prot); if (i.mtu !== 1476) ln.push('ip mtu ' + i.mtu); }
};

/* ------------------------------------------------------------------ show */
const ENCN = { des: 'DES - Data Encryption Standard (56 bit keys).', '3des': 'Three key triple DES', aes: null };
const HASHN = { sha: 'Secure Hash Standard', md5: 'Message Digest 5', sha256: 'Secure Hash Standard 2 (256 bit)' };
cmd('exec', 'show crypto isakmp policy', (s, a, io) => {
  const v = V(s); if (!v) return bad(io); let o = 'Global IKE policy\n';
  v.policies.forEach(p => { o += 'Protection suite of priority ' + p.prio + '\n\tencryption algorithm:\t' + (p.enc === 'aes' ? 'AES - Advanced Encryption Standard (' + p.bits + ' bit keys).' : ENCN[p.enc]) + '\n\thash algorithm:\t\t' + HASHN[p.hash] + '\n\tauthentication method:\t' + (p.auth === 'pre-share' ? 'Pre-Shared Key' : 'Rivest-Shamir-Adleman Signature') + '\n\tDiffie-Hellman group:\t#' + p.group + ' (' + U.GROUPS[p.group].bits + ' bit)\n\tlifetime:\t\t' + p.life + ' seconds, no volume limit\n'; });
  o += 'Default protection suite\n\tencryption algorithm:\tDES - Data Encryption Standard (56 bit keys).\n\thash algorithm:\t\tSecure Hash Standard\n\tauthentication method:\tRivest-Shamir-Adleman Signature\n\tDiffie-Hellman group:\t#1 (768 bit)\n\tlifetime:\t\t86400 seconds, no volume limit\n'; io.print(o);
}, { priv: true });
cmd('exec', 'show crypto isakmp key', (s, a, io) => { const v = V(s); if (!v) return bad(io); let o = 'Keyring      Hostname/Address                            Preshared Key\n\ndefault      ' + '\n'; v.keys.forEach(k => { o += '             ' + pad(IP.str(k.addr), 44) + k.key + '\n'; }); io.print(o); }, { priv: true });
const p1 = (v, s, det) => {
  let o = 'IPv4 Crypto ISAKMP SA\ndst             src             state          conn-id status\n';
  v.ph1.forEach(p => { const dst = p.role === 'I' ? p.peer : p.local, src = p.role === 'I' ? p.local : p.peer; o += pad(IP.str(dst), 16) + pad(IP.str(src), 16) + pad(p.state, 15) + padL(p.conn, 7) + ' ' + (p.state === 'QM_IDLE' ? 'ACTIVE' : 'ACTIVE') + '\n'; });
  o += '\nIPv6 Crypto ISAKMP SA\n'; return o;
};
cmd('exec', 'show crypto isakmp sa [<x...>]', (s, a, io) => { const v = V(s); if (!v) return bad(io); io.print(p1(v, s) + '\n'); }, { priv: true });
cmd('exec', 'show crypto isakmp <x...>', (s, a, io) => bad(io), { priv: true });
cmd('exec', 'show crypto ipsec transform-set [<x...>]', (s, a, io) => { const v = V(s); if (!v) return bad(io); let o = ''; v.tsets.forEach(ts => { o += 'Transform set ' + ts.name + ': { ' + v.tsetText(ts) + '   } \n   will negotiate = { ' + (ts.mode === 'tunnel' ? 'Tunnel' : 'Transport') + ',  },\n\n'; }); io.print(o); }, { priv: true });
cmd('exec', 'show crypto map [<x...>]', (s, a, io) => {
  const v = V(s); if (!v) return bad(io); let o = '';
  v.cmaps.forEach(cm => {
    Array.from(cm.entries.keys()).sort((x, y) => x - y).forEach(sq => {
      const e = cm.entries.get(sq); o += 'Crypto Map "' + cm.name + '" ' + sq + ' ipsec-isakmp\n';
      if (!v.entryOK(e)) o += '\t% Incomplete (peer, access list or transform-set missing)\n';
      if (e.peer) o += '\tPeer = ' + IP.str(e.peer) + '\n'; const acl = e.acl && s.dev.acls.get(e.acl); o += '\tExtended IP access list ' + (e.acl || '') + '\n'; if (acl) acl.entries.forEach(x => { if (x.remark === undefined) o += '\t    access-list ' + e.acl + ' ' + NS.iosUtil.aclText(acl, x) + '\n'; });
      o += '\tCurrent peer: ' + (e.peer ? IP.str(e.peer) : '') + '\n\tSecurity association lifetime: 4608000 kilobytes/' + e.life + ' seconds\n\tResponder-Only (Y/N): N\n\tPFS (Y/N): ' + (e.pfs ? 'Y' : 'N') + (e.pfs ? '\n\tDH group:  group' + e.pfs : '') + '\n\tTransform sets={ \n\t\t' + (e.tset ? e.tset + ':  { ' + (v.tsets.get(e.tset) ? v.tsetText(v.tsets.get(e.tset)) : '') + '   } ,' : '') + '\n\t} \n\tInterfaces using crypto map ' + cm.name + ':\n';
      s.dev.ifaceList().forEach(i => { if (i.cmap === cm.name) o += '\t\t' + i.name + '\n'; });
    });
  }); io.print(o);
}, { priv: true });
function ipsecBlock(v, sa) {
  const ts = sa.ts; const now = v.sim.now; const rem = Math.max(0, sa.life - Math.floor((now - sa.t0) / 1000)); const E = U.ENC[ts.enc];
  const tname = v.tsetText(ts) + ' '; const mode = ts.mode === 'transport' ? 'Transport' : 'Tunnel';
  const l = sa.proxyL, r = sa.proxyR; const pr = sa.kind === 'prof' ? '47' : '0';
  let o = '\n   protected vrf: (none)\n   local  ident (addr/mask/prot/port): (' + IP.str(l.net) + '/' + IP.str(l.mask) + '/' + pr + '/0)\n   remote ident (addr/mask/prot/port): (' + IP.str(r.net) + '/' + IP.str(r.mask) + '/' + pr + '/0)\n   current_peer ' + IP.str(sa.peer) + ' port 500\n     PERMIT, flags={' + (sa.kind === 'map' ? 'origin_is_acl,' : 'origin_is_acl,') + '}\n';
  o += '    #pkts encaps: ' + sa.encaps + ', #pkts encrypt: ' + sa.encaps + ', #pkts digest: ' + (ts.auth ? sa.encaps : 0) + '\n    #pkts decaps: ' + sa.decaps + ', #pkts decrypt: ' + sa.decaps + ', #pkts verify: ' + (ts.auth ? sa.decaps : 0) + '\n    #pkts compressed: 0, #pkts decompressed: 0\n    #pkts not compressed: 0, #pkts compr. failed: 0\n    #pkts not decompressed: 0, #pkts decompress failed: 0\n    #send errors 0, #recv errors ' + sa.recvErr + '\n\n';
  o += '     local crypto endpt.: ' + IP.str(sa.local) + ', remote crypto endpt.: ' + IP.str(sa.peer) + '\n     path mtu 1500, ip mtu 1500, ip mtu idb ' + (sa.iface ? sa.iface.name : '') + '\n     current outbound spi: 0x' + hx(sa.spiOut) + '(' + sa.spiOut + ')\n     PFS (Y/N): ' + (sa.entry.pfs ? 'Y' : 'N') + ', DH group: ' + (sa.entry.pfs ? 'group' + sa.entry.pfs : 'none') + '\n\n';
  const half = (nm, spi) => '     ' + nm + ' esp sas:\n      spi: 0x' + hx(spi) + '(' + spi + ')\n        transform: ' + tname + ',\n        in use settings ={' + mode + ', }\n        conn id: ' + (sa.id + 1000) + ', flow_id: SW:' + (sa.id - 1000) + ', sibling_flags 80004040, crypto map: ' + sa.mapName + '\n        sa timing: remaining key lifetime (k/sec): (4608000/' + rem + ')\n        IV size: ' + E.iv + ' bytes\n        replay detection support: Y\n        Status: ACTIVE(ACTIVE)\n\n';
  o += half('inbound', sa.spiIn) + '     inbound ah sas:\n\n     inbound pcp sas:\n\n' + half('outbound', sa.spiOut) + '     outbound ah sas:\n\n     outbound pcp sas:\n'; return o;
}
cmd('exec', 'show crypto ipsec sa [<x...>]', (s, a, io) => {
  const v = V(s); if (!v) return bad(io); let o = '';
  const groups = new Map(); v.sas.forEach(sa => { const k = sa.iface ? sa.iface.name : '?'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(sa); });
  const peerFilter = (a._rest || [])[0] === 'peer' ? IP.parse(a._rest[1]) : null;
  groups.forEach((list, ifn) => { const l = list.filter(x => peerFilter === null || x.peer === peerFilter); if (!l.length) return; o += '\ninterface: ' + ifn + '\n    Crypto map tag: ' + l[0].mapName + ', local addr ' + IP.str(l[0].local) + '\n'; l.forEach(sa => { o += ipsecBlock(v, sa); }); });
  io.print(o || '\n');
}, { priv: true });
cmd('exec', 'show crypto session [<x...>]', (s, a, io) => {
  const v = V(s); if (!v) return bad(io); let o = 'Crypto session current status\n\n';
  v.ph1.forEach(p => { const sas = v.sas.filter(x => x.ph === p); const ifn = sas.length && sas[0].iface ? sas[0].iface.name : (s.dev.ifaceList().find(i => i.ip === p.local) || {}).name || '';
    o += 'Interface: ' + ifn + '\nSession status: ' + (sas.length ? 'UP-ACTIVE' : (p.state === 'QM_IDLE' ? 'UP-IDLE' : 'DOWN-NEGOTIATING')) + '\nPeer: ' + IP.str(p.peer) + ' port 500\n  IKEv1 SA: local ' + IP.str(p.local) + '/500 remote ' + IP.str(p.peer) + '/500 ' + (p.state === 'QM_IDLE' ? 'Active' : 'Negotiating') + '\n';
    sas.forEach(sa => { o += '  IPSEC FLOW: permit ' + (sa.kind === 'prof' ? '47' : 'ip') + ' ' + IP.str(sa.proxyL.net) + '/' + IP.str(sa.proxyL.mask) + ' ' + IP.str(sa.proxyR.net) + '/' + IP.str(sa.proxyR.mask) + '\n        Active SAs: 2, origin: crypto map\n'; }); o += '\n'; });
  io.print(o);
}, { priv: true });
NS.vpnShowIf = function (s, a, io) {
  if (!a.x || !/^tu/i.test(a.x)) return false; const d = s.dev; const i = d.ifaceByName(a.x + (a.y || '')) || d.ifaceByName(a.x + ' ' + (a.y || '')); if (!i || !i.tun) { io.print('% Invalid input detected at \'^\' marker.\n'); return true; }
  const t = i.tun; const st = !i.adminUp ? 'administratively down' : 'up'; const lp = i.isUp() ? 'up' : 'down';
  let o = i.name + ' is ' + st + ', line protocol is ' + lp + '\n  Hardware is Tunnel\n' + (i.desc ? '  Description: ' + i.desc + '\n' : '') + '  Internet address is ' + (i.ip ? IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask) : 'not set') + '\n  MTU 9976 bytes, BW 100 Kbit/sec, DLY 50000 usec,\n     reliability 255/255, txload 1/255, rxload 1/255\n  Encapsulation TUNNEL, loopback not set\n  Keepalive not set\n  Tunnel source ' + (t.srcIf ? (d.ifaceByName(t.srcIf) && d.ifaceByName(t.srcIf).ip ? IP.str(d.ifaceByName(t.srcIf).ip) + ' (' + d.ifaceByName(t.srcIf).name + ')' : t.srcIf) : t.srcIp ? IP.str(t.srcIp) : 'unknown') + ', destination ' + (t.dst ? IP.str(t.dst) : 'unknown') + '\n  Tunnel protocol/transport GRE/IP\n    Key ' + (t.key === null || t.key === undefined ? 'disabled' : '0x' + hx(t.key).replace(/^0+(?=.)/, '') + ', ') + ' sequencing disabled\n    Checksumming of packets disabled\n' + (t.prot ? '  Tunnel TTL 255, Fast tunneling enabled\n  Tunnel protection via IPSec (profile "' + t.prot + '")\n' : '  Tunnel TTL 255, Fast tunneling enabled\n') + '  Last input never, output never, output hang never\n  5 minute input rate 0 bits/sec, 0 packets/sec\n     ' + (i.tunRx || 0) + ' packets input, 0 bytes, 0 no buffer\n     ' + (i.tunTx || 0) + ' packets output, 0 bytes, 0 underruns\n';
  io.print(o); return true;
};

/* ------------------------------------------------------------------ clear / debug */
cmd('priv', 'clear crypto sa [<x...>]', (s, a, io) => { const v = V(s); if (!v) return bad(io); const r = a._rest || []; const peer = r[0] === 'peer' ? IP.parse(r[1]) : null; v.clearSa(peer); });
cmd('priv', 'clear crypto ipsec sa [<x...>]', (s, a, io) => { const v = V(s); if (v) v.clearSa(null); });
cmd('priv', 'clear crypto isakmp [<x...>]', (s, a, io) => { const v = V(s); if (!v) return bad(io); v.clearIsakmp(null); });
cmd('priv', 'clear crypto session [<x...>]', (s, a, io) => { const v = V(s); if (!v) return; v.clearIsakmp(null); });
cmd('priv', 'debug crypto isakmp', (s, a, io) => { V(s).debug.isakmp = true; io.print('Crypto ISAKMP debugging is on\n'); });
cmd('priv', 'debug crypto ipsec', (s, a, io) => { V(s).debug.ipsec = true; io.print('Crypto IPSEC debugging is on\n'); });
cmd('priv', 'debug crypto <x...>', () => { });
cmd('priv', 'undebug all', (s, a, io) => { if (V(s)) { V(s).debug.isakmp = false; V(s).debug.ipsec = false; } io.print('All possible debugging has been turned off\n'); });
cmd('priv', 'no debug all', (s, a, io) => { if (V(s)) { V(s).debug.isakmp = false; V(s).debug.ipsec = false; } io.print('All possible debugging has been turned off\n'); });
cmd('priv', 'no debug crypto isakmp', (s) => { if (V(s)) V(s).debug.isakmp = false; });
cmd('priv', 'no debug crypto ipsec', (s) => { if (V(s)) V(s).debug.ipsec = false; });
cmd('priv', 'undebug crypto isakmp', (s) => { if (V(s)) V(s).debug.isakmp = false; });
cmd('priv', 'undebug crypto ipsec', (s) => { if (V(s)) V(s).debug.ipsec = false; });
})(typeof window !== 'undefined' ? window : globalThis);
