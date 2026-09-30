/* tools.js — outils réseau partagés (ping en série, traceroute) utilisés par les terminaux */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP } = NS;
const tools = {};
/* ping en série : onEach(res, i) ; onDone(stats) */
tools.pingSeries = function (node, dst, o, onEach, onDone) {
  o = o || {}; const count = o.count || 4; let i = 0; const stats = { sent: 0, recv: 0, rtts: [], dst }; const id = (node.pingId = (node.pingId || 0) + 1) & 0xffff;
  const next = () => {
    if (i >= count || (o.abort && o.abort())) return onDone(stats);
    const seq = ++i; stats.sent++;
    node.pingOnce(dst, { id, seq, size: o.size, ttl: o.ttl, timeout: o.timeout || 2000, src: o.src }, res => {
      if (res.type === 'reply') { stats.recv++; stats.rtts.push(res.rtt); }
      onEach(res, seq);
      node.sim.at(o.interval === undefined ? 1000 : o.interval, next);
    });
  };
  next();
};
/* traceroute par TTL croissant (écho ICMP) : onHop(ttl, [res,res,res]) ; onDone(reached) */
tools.trace = function (node, dst, o, onHop, onDone) {
  o = o || {}; const maxHops = o.maxHops || 30, probes = o.probes || 3; let ttl = 0; const id = (node.pingId = (node.pingId || 0) + 1) & 0xffff; let seqN = 100;
  const hop = () => {
    if (++ttl > maxHops || (o.abort && o.abort())) return onDone(false);
    const rs = []; let k = 0;
    const probe = () => {
      if (k >= probes) { onHop(ttl, rs); const last = rs.find(r => r.type === 'reply'); if (last || rs.some(r => r.type === 'unreach' && r.from === dst)) return onDone(!!last); if (rs.every(r => r.type === 'noroute' || r.type === 'arpfail')) return onDone(false); return hop(); }
      k++; node.pingOnce(dst, { id, seq: ++seqN, ttl, timeout: o.timeout || 2000, size: o.size }, r => { rs.push(r); probe(); });
    };
    probe();
  };
  hop();
};
tools.fmtStats = function (arr) { if (!arr.length) return null; const mn = Math.min(...arr), mx = Math.max(...arr), av = arr.reduce((a, b) => a + b, 0) / arr.length; return { mn, mx, av }; };
/* Chiffrement SSH simulé : flux pseudo-aléatoire par sens, messages [longueur 4 octets][chiffré] */
tools.sshCrypt = function (conn, role) {
  const seed = ((conn.rip ^ conn.lip ^ conn.rport ^ conn.lport) >>> 0) || 7;
  const c2s = new NS.Rng(seed + 1), s2c = new NS.Rng(seed + 2);
  const xor = (d, r) => { const o = new Uint8Array(d.length); for (let i = 0; i < d.length; i++) o[i] = d[i] ^ r.int(256); return o; };
  const e = role === 'server' ? s2c : c2s, dd = role === 'server' ? c2s : s2c;
  return {
    enc: b => { const c = xor(b, e); return NS.B.concat(Uint8Array.of(0, 0, (c.length >> 8) & 255, c.length & 255), c); },
    dec: b => xor(b.subarray(4), dd),
  };
};
/* Ouvre une session distante telnet (clair) ou ssh (chiffré) ; h = {onOpen(sendLine), onText, onClose, onError} */
tools.openRemote = function (node, dst, mode, h) {
  const B = NS.B; let stage = mode === 'ssh' ? 'banner' : 'ready'; let cr = null; let opened = false;
  node.tcpConnect(dst, mode === 'ssh' ? 22 : 23, {
    onOpen: c => {
      if (mode === 'ssh') { c.send('SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n'); cr = tools.sshCrypt(c, 'client'); }
      else h.onOpen(line => c.send(line + '\r\n'));
    },
    onData: (buf, c) => {
      if (mode === 'telnet') { h.onText(B.bytesStr(buf)); return; }
      if (stage === 'banner') { if (/^SSH-/.test(B.bytesStr(buf, 0, 4))) { c.send(node.sim.rng.bytes(320)); stage = 'kex'; } return; }
      if (stage === 'kex') { stage = 'enc'; if (!opened) { opened = true; h.onOpen(line => c.send(cr.enc(B.utf8Bytes(line + '\r\n')))); } return; }
      h.onText(B.bytesStr(cr.dec(buf)));
    },
    onClose: () => h.onClose && h.onClose(),
    onError: e => h.onError && h.onError(e),
  });
};
NS.tools = tools;
})(typeof window !== 'undefined' ? window : globalThis);
