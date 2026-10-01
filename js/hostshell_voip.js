/* hostshell_voip.js — Linux : Asterisk (asterisk -rx, systemctl, sip.conf/extensions.conf, journaux) ; Linux/Windows : softphone en ligne de commande `sipphone` */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {}; const { IP, Codec, HostShell } = NS; const L = HostShell.prototype.linCmds, W = HostShell.prototype.winCmds; const U = NS.voipUtil;
const SIPC = '/etc/asterisk/sip.conf', EXTC = '/etc/asterisk/extensions.conf', LOGF = '/var/log/asterisk/full', CDRF = '/var/log/asterisk/cdr-csv/Master.csv';
const fmtD = ms => { const s = Math.floor(ms / 1000); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
function cdrText(P) { return P.cdr.map(c => '"","' + c.src + '","' + c.dst + '","default","","SIP/' + c.src + '","SIP/' + c.dst + '","Dial","SIP/' + c.dst + ',20","' + Math.round(c.dur / 1000 + 1) + '","' + Math.round(c.dur / 1000) + '","' + c.disp + '"').join('\n') + (P.cdr.length ? '\n' : ''); }
function fileText(h, p) { const P = h.pbx; if (!P) return null; if (p === SIPC) return P.sipConf(); if (p === EXTC) return P.extConf(); if (p === LOGF) return P.log.join('\n') + (P.log.length ? '\n' : ''); if (p === CDRF) return cdrText(P); return null; }
const echo0 = L.echo;
L.echo = function (a, io) {
  const i = a.findIndex(t => t === '>>' || t === '>'); if (i < 0) return echo0.call(this, a, io); const path = a[i + 1]; if (path !== SIPC && path !== EXTC) return echo0.call(this, a, io);
  const P = this.host.pbx, app = a[i] === '>>'; const txt = a.slice(0, i).join(' ').replace(/^(["'])([\s\S]*)\1$/, '$2').replace(/\\n/g, '\n');
  if (!app) { if (path === SIPC) { P.peers.clear(); P.trunks.clear(); } else P.routes = []; }
  P.parseText(path === SIPC ? 'sip' : 'ext', txt, app);
};
const cat0 = L.cat; L.cat = function (a, io) { const t = fileText(this.host, a[0] || ''); if (t !== null) { io.print(t); return; } return cat0.call(this, a, io); };
const tail0 = L.tail; L.tail = function (a, io) { const f = a.filter(x => !/^-/.test(x) && !/^\d+$/.test(x))[0]; if (f === LOGF || f === CDRF) { let n = 10; const k = a.indexOf('-n'); if (k >= 0) n = +a[k + 1]; const ls = (fileText(this.host, f) || '').split('\n').filter(Boolean); io.print(ls.slice(-n).join('\n') + (ls.length ? '\n' : '')); return; } return tail0.call(this, a, io); };
const grep0 = L.grep; L.grep = function (a, io) { const ar = a.filter(x => !/^-/.test(x)); if (ar[1] === LOGF) { const re = new RegExp(ar[0].replace(/^["']|["']$/g, ''), a.includes('-i') ? 'i' : ''); io.print((fileText(this.host, LOGF) || '').split('\n').filter(l => l && re.test(l)).join('\n') + '\n'); return; } return grep0.call(this, a, io); };
const sc0 = L.systemctl;
L.systemctl = function (a, io) {
  const svc = (a[1] || '').replace('.service', ''); if (svc !== 'asterisk') return sc0.call(this, a, io); const P = this.host.pbx, act = a[0];
  if (act === 'start' || act === 'restart') { if (act === 'restart') P.stop(); P.start(); } else if (act === 'stop') P.stop();
  else if (act === 'status') io.print('● asterisk.service - Asterisk PBX\n     Active: ' + (P.enabled ? 'active (running)' : 'inactive (dead)') + '\n     Docs: man:asterisk(8)\n');
  else if (act !== 'enable' && act !== 'disable') return sc0.call(this, a, io);
};
function peersTable(P) {
  const pad = (s, n) => String(s).padEnd(n); let o = pad('Name/username', 27) + pad('Host', 41) + pad('Dyn', 4) + pad('Forcerport', 11) + pad('Comedia', 8) + pad('ACL', 4) + pad('Port', 6) + 'Status\n'; let n = 0, on = 0;
  P.peers.forEach(p => { n++; const r = p.reg; if (r) on++; o += pad(p.name + '/' + p.name, 27) + pad(r ? IP.str(r.ip) : '(Unspecified)', 41) + pad(p.host === 'dynamic' ? 'D' : '', 4) + pad('a', 11) + pad('', 8) + pad('', 4) + pad(r ? r.port : 0, 6) + (r ? 'OK (1 ms)' : 'UNKNOWN') + '\n'; });
  P.trunks.forEach(t => { n++; on++; o += pad(t.name + '/' + t.name, 27) + pad(IP.str(t.host), 41) + pad('', 4) + pad('a', 11) + pad('', 8) + pad('', 4) + pad(5060, 6) + 'OK (2 ms)\n'; });
  return o + n + ' sip peers [Monitored: ' + on + ' online, ' + (n - on) + ' offline Unmonitored: 0 online, 0 offline]\n';
}
function channels(P, sim) {
  const pad = (s, n) => String(s).padEnd(n); let o = pad('Channel', 28) + pad('Location', 22) + pad('State', 8) + 'Application(Data)\n'; let n = 0;
  P.calls.forEach(c => { if (c.state === 'ended' || c.state === 'cancelled') return; n += 2; o += pad('SIP/' + c.from + '-0000000' + n, 28) + pad(c.to + '@default:1', 22) + pad(c.answered ? 'Up' : 'Ring', 8) + 'Dial(SIP/' + c.to + ',20)\n' + pad('SIP/' + c.to + '-0000000' + (n + 1), 28) + pad('s@default:1', 22) + pad(c.answered ? 'Up' : 'Ring', 8) + 'AppDial((Outgoing Line))\n'; });
  return o + n + ' active channels\n' + (n / 2) + ' active calls\n';
}
L.asterisk = function (a, io) {
  const P = this.host.pbx; const i = a.findIndex(t => /^-\w*rx$/.test(t) || t === '-rx'); if (i < 0) { io.print('Asterisk 20.5.0 (simulé) — utilisez : asterisk -rx "<commande>"\n'); return; }
  if (!P.enabled) { io.print('Unable to connect to remote asterisk (does /var/run/asterisk/asterisk.ctl exist?)\n'); return; }
  const c = a.slice(i + 1).join(' ').replace(/^["']|["']$/g, '').trim().toLowerCase();
  if (c === 'sip show peers') io.print(peersTable(P));
  else if (c === 'sip show registry') io.print('Host                                    dnsmgr Username       Refresh State                Reg.Time\n0 SIP registrations.\n');
  else if (c === 'sip show channels' || c === 'core show channels') io.print(channels(P, this.host.sim));
  else if (c === 'sip show users') { let o = 'Username                   Secret           Accountcode      Def.Context      ACL  Forcerport\n'; P.peers.forEach(p => { o += String(p.name).padEnd(27) + String(p.secret).padEnd(17) + ''.padEnd(17) + String(p.context).padEnd(17) + 'No   Yes\n'; }); io.print(o); }
  else if (/^sip show peer \S+/.test(c)) { const p = P.peers.get(c.split(/\s+/)[3]); if (!p) io.print('Peer ' + c.split(/\s+/)[3] + ' not found.\n'); else io.print('\n  * Name       : ' + p.name + '\n  Secret       : <Set>\n  Context      : ' + p.context + '\n  Callerid     : "' + p.callerid + '" <' + p.name + '>\n  Addr->IP     : ' + (p.reg ? IP.str(p.reg.ip) + ':' + p.reg.port : '(Unspecified)') + '\n  Status       : ' + (p.reg ? 'OK (1 ms)' : 'UNKNOWN') + '\n  Useragent    : ' + (p.reg ? p.reg.ua : '') + '\n\n'); }
  else if (c === 'dialplan show') { let o = '[ Context \'default\' created by \'pbx_config\' ]\n'; P.routes.forEach(r => { o += '  \'' + r.pattern + '\' =>          1. Dial(' + r.target + ',20)                       [pbx_config]\n                            2. Hangup()                                     [pbx_config]\n'; }); io.print(o + '\n-= ' + P.routes.length + ' extension(s) (' + P.routes.length * 2 + ' priorities) in 1 context. =-\n'); }
  else if (c === 'sip set debug on') { P.debug = true; io.print('SIP Debugging enabled\n'); } else if (c === 'sip set debug off') { P.debug = false; io.print('SIP Debugging Disabled\n'); }
  else if (c === 'sip reload' || c === 'core reload' || c === 'dialplan reload' || c === 'reload') io.print('');
  else if (c === 'core show version') io.print('Asterisk 20.5.0 built by simulateur on a x86_64 running Linux\n');
  else if (c === 'core show uptime') io.print('System uptime: ' + fmtD(this.host.sim.now) + '\n');
  else io.print('No such command \'' + c + '\' (type \'core show help ' + c.split(' ')[0] + '\' for other possible commands)\n');
};
/* softphone : sipphone register|call|answer|hangup|reject|status|log|codec|autoanswer|dnd|debug */
function sipphone(a, io) {
  const h = this.host, v = h.voip; const cmd = (a[0] || '').toLowerCase(); const fmtCall = c => c ? (c.dir === 'out' ? 'sortant vers ' : 'entrant de ') + c.peer + ' — ' + c.state + (c.state === 'talking' ? ' depuis ' + fmtD(h.sim.now - c.tAns) : '') : 'aucun appel';
  if (cmd === 'register') { if (a.length < 4) { io.print('Usage: sipphone register <extension> <mot de passe> <serveur> [nom]\n'); return; } v.configure({ ext: a[1], user: a[1], secret: a[2], server: a[3], name: a[4] || '' }); v.register(); io.print('REGISTER envoyé à ' + a[3] + ' pour l\'extension ' + a[1] + '\n'); return; }
  if (cmd === 'unregister') { v.register(0); return; }
  if (cmd === 'call') { if (!a[1]) { io.print('Usage: sipphone call <numéro | numéro@adresse>\n'); return; } if (v.call(a[1])) io.print('INVITE vers ' + a[1] + '...\n'); else io.print('Appel impossible : ' + (v.log.length ? v.log[v.log.length - 1].msg : '') + '\n'); return; }
  if (cmd === 'answer') { if (!v.answer()) io.print('Aucun appel entrant à décrocher\n'); return; } if (cmd === 'reject') { v.reject(603); return; } if (cmd === 'hangup') { if (!v.cur) io.print('Aucun appel en cours\n'); else v.hangup(); return; }
  if (cmd === 'codec') { const l = (a[1] || '').toUpperCase().split(',').filter(x => U.CODECS[x]); if (!l.length) { io.print('Codecs disponibles : PCMU, PCMA, G722, G729 (ex. sipphone codec G729,PCMU)\n'); return; } v.configure({ codecs: l }); return; }
  if (cmd === 'autoanswer') { v.configure({ autoAnswer: a[1] === 'on' }); return; } if (cmd === 'dnd') { v.configure({ dnd: a[1] === 'on' }); return; }
  if (cmd === 'debug') { v.debug = a[1] === 'on'; return; }
  if (cmd === 'log') { io.print(v.log.slice(-15).map(l => '[' + fmtD(l.t) + '] ' + l.msg).join('\n') + '\n'); return; }
  if (cmd === 'status' || cmd === '') {
    let o = 'Compte : ' + (v.cfg.user || '(non configuré)') + ' @ ' + (v.cfg.server ? IP.str(v.cfg.server) : '-') + '\nEnregistrement : ' + v.reg.state + (v.reg.reason ? ' (' + v.reg.reason + ')' : '') + '\nCodecs : ' + v.cfg.codecs.join(', ') + '\nAppel : ' + fmtCall(v.cur) + '\n';
    const st = v.stats(); if (st) o += 'RTP : ' + st.codec + ', émis ' + st.tx + ', reçus ' + st.rx + ', perdus ' + st.lost + ' (' + st.lossPct + ' %), gigue ' + st.jitter + ' ms, délai moyen ' + st.delay + ' ms, MOS ' + st.mos + ' (' + U.mosLabel(st.mos) + ')' + (st.oneWay ? ' — AUDIO UNIDIRECTIONNEL' : '') + '\n';
    if (v.hist.length) { o += 'Historique :\n'; v.hist.slice(-5).forEach(c => { o += '  ' + (c.dir === 'out' ? '→ ' : '← ') + c.peer + '  ' + c.result + (c.dur ? '  (' + fmtD(c.dur) + ', ' + c.codec + (c.stats ? ', MOS ' + c.stats.mos : '') + ')' : '') + '\n'; }); }
    io.print(o); return;
  }
  io.print('Usage: sipphone register|call|answer|reject|hangup|status|log|codec|autoanswer|dnd|debug\n');
}
L.sipphone = sipphone; if (W) W.sipphone = sipphone;
})(typeof window !== 'undefined' ? window : globalThis);
