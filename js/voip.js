/* voip.js — téléphonie IP : agent SIP (téléphone IP / softphone), PBX de type Asterisk (enregistrement, digest, appels, trunks),
   RTP G.711/G.722/G.729 avec statistiques (perte, gigue, délai, MOS E-model), téléphone à 2 ports avec VLAN voix appris par CDP. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {}; const { IP, Codec } = NS;
const md5 = s => Codec.md5hex(s);
const CODECS = { PCMU: { pt: 0, name: 'PCMU', size: 160, step: 160, ie: 0, bpl: 25.1, kbps: 64 }, PCMA: { pt: 8, name: 'PCMA', size: 160, step: 160, ie: 0, bpl: 25.1, kbps: 64 }, G722: { pt: 9, name: 'G722', size: 160, step: 160, ie: 0, bpl: 25.1, kbps: 64 }, G729: { pt: 18, name: 'G729', size: 20, step: 160, ie: 11, bpl: 19, kbps: 8 } };
const byPt = pt => Object.values(CODECS).find(c => c.pt === pt) || null;
const rnd = (sim, n) => { let s = ''; for (let i = 0; i < n; i++) s += 'abcdefghijklmnopqrstuvwxyz0123456789'[sim.rng.int(36)]; return s; };
function digest(user, realm, pass, method, uri, nonce) { return md5(md5(user + ':' + realm + ':' + pass) + ':' + nonce + ':' + md5(method + ':' + uri)); }
const authParams = v => { const o = {}; String(v || '').replace(/(\w+)="([^"]*)"/g, (m, k, x) => { o[k.toLowerCase()] = x; return m; }); return o; };
/* E-model (ITU-T G.107 simplifié) : délai en ms (sens unique, tampon de gigue inclus), perte en % */
function mos(codec, delayMs, lossPct) {
  const d = delayMs; const Id = 0.024 * d + (d > 177.3 ? 0.11 * (d - 177.3) : 0);
  const Ie = codec.ie + (95 - codec.ie) * lossPct / (lossPct + codec.bpl); const R = Math.max(0, Math.min(100, 93.2 - Id - Ie));
  const M = R <= 0 ? 1 : R >= 100 ? 4.5 : 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R); return { R: Math.round(R * 10) / 10, mos: Math.round(M * 100) / 100 };
}
const mosLabel = m => m >= 4.3 ? 'excellent' : m >= 4 ? 'bon' : m >= 3.6 ? 'acceptable' : m >= 3.1 ? 'médiocre' : 'mauvais';

/* ================================================================== Agent SIP (UA) */
class Sip {
  constructor(node) { this.node = node; this.sim = node.sim; this.bound = false; this.reset(); }
  reset() {
    (this.txns || new Map()).forEach(t => t.timer && (t.timer.dead = true)); if (this.cur) this.endMedia(this.cur);
    this.cfg = { ext: '', user: '', name: '', secret: '', server: 0, codecs: ['PCMU', 'PCMA'], autoAnswer: true, answerDelay: 3000, dnd: false, dscpRtp: 46, dscpSip: 24, expires: 3600 };
    this.reg = { state: 'unregistered', reason: '', t: 0, timer: null, nonce: '' }; this.cur = null; this.hist = []; this.log = []; this.txns = new Map(); this.seen = new Map(); this.rtpN = 0; this.cseq = 0; this.ring = false;
    this.onEvent = null; this.debug = false;
  }
  get enabled() { return !!this.cfg.ext; }
  lg(t) { this.log.push({ t: this.sim.now, msg: t }); if (this.log.length > 200) this.log.shift(); if (this.onEvent) this.onEvent('log'); }
  ensure() { if (this.bound) return; this.bound = true; this.node.udpBind(5060, (p, i) => { if (this.node.pbx && this.node.pbx.enabled) this.node.pbx.input(p, i); else this.input(p, i); }); }
  configure(o) { Object.assign(this.cfg, o); if (o.ext !== undefined && !o.user) this.cfg.user = o.ext; if (typeof this.cfg.server === 'string') this.cfg.server = IP.parse(this.cfg.server) || 0; this.ensure(); }
  myIp(dst) { const r = this.node.lookup(dst); return r ? r.iface.ip : (this.node.primaryIface ? this.node.primaryIface.ip : 0); }
  srvStr() { return IP.str(this.cfg.server); }
  /* ---- transactions ---- */
  send(m, dst, o) {
    o = o || {}; const bytes = Codec.sip(m); const key = o.key || null;
    const tx = () => { this.node.udpSend(dst, 5060, 5060, bytes, { tos: this.cfg.dscpSip << 2 }); };
    if (this.debug) this.lg('Sent to ' + IP.str(dst) + ': ' + Codec.sipSummary(Codec.parseSipText(String.fromCharCode.apply(null, bytes))));
    tx();
    if (key) { const t = { key, tries: 1, delay: 500, tx, onTimeout: o.onTimeout, m }; const tick = () => { if (t.done) return; if (t.tries >= (o.maxTries || 6)) { this.txns.delete(key); if (t.onTimeout) t.onTimeout(); return; } t.tries++; tx(); t.delay = Math.min(t.delay * 2, 4000); t.timer = this.sim.at(t.delay, tick); }; t.timer = this.sim.at(t.delay, tick); this.txns.set(key, t); }
  }
  stopTx(key) { const t = this.txns.get(key); if (t) { t.done = true; if (t.timer) t.timer.dead = true; this.txns.delete(key); } }
  branch() { return 'z9hG4bK' + rnd(this.sim, 10); }
  base(method, uri, o) { // en-têtes communs
    const c = this.cfg, me = this.myIp(o.dst);
    const h = [['Via', 'SIP/2.0/UDP ' + IP.str(me) + ':5060;branch=' + o.branch + ';rport'], ['Max-Forwards', '70'], ['From', (c.name ? '"' + c.name + '" ' : '') + '<sip:' + c.user + '@' + (o.domain || this.srvStr()) + '>;tag=' + o.ftag], ['To', '<sip:' + (o.toUser !== undefined ? o.toUser + '@' : '') + (o.domain || this.srvStr()) + '>' + (o.ttag ? ';tag=' + o.ttag : '')], ['Call-ID', o.callId], ['CSeq', o.cseq + ' ' + method], ['Contact', '<sip:' + c.user + '@' + IP.str(me) + ':5060>'], ['User-Agent', this.node.phone ? 'Yealink SIP-T31P 124.86.0.75' : 'SimSoftphone/1.0'], ['Allow', 'INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY']];
    return h;
  }
  authHdr(ch, method, uri) { const a = authParams(ch); const c = this.cfg; return ['Authorization', 'Digest username="' + c.user + '", realm="' + a.realm + '", nonce="' + a.nonce + '", uri="' + uri + '", response="' + digest(c.user, a.realm, c.secret, method, uri, a.nonce) + '", algorithm=MD5']; }
  /* ---- enregistrement ---- */
  register(expires) {
    const c = this.cfg; if (!c.ext || !c.server) return; this.ensure(); const r = this.reg; if (r.timer) r.timer.dead = true;
    const exp = expires === undefined ? c.expires : expires; r.state = exp ? 'registering' : r.state; r.callId = rnd(this.sim, 12) + '@' + IP.str(this.myIp(c.server)); r.ftag = rnd(this.sim, 8); r.cseq = 1; this.doRegister(null, exp);
  }
  doRegister(chal, exp) {
    const c = this.cfg, r = this.reg; const uri = 'sip:' + this.srvStr(); const br = this.branch(); r.branch = br;
    const h = this.base('REGISTER', uri, { branch: br, ftag: r.ftag, callId: r.callId, cseq: r.cseq, dst: c.server, ttag: '', toUser: c.user }); h[3] = ['To', '<sip:' + c.user + '@' + this.srvStr() + '>'];
    h.push(['Expires', String(exp)]); if (chal) h.push(this.authHdr(chal, 'REGISTER', uri));
    this.send({ method: 'REGISTER', uri, headers: h }, c.server, { key: 'REG', maxTries: 5, onTimeout: () => { r.state = 'failed'; r.reason = 'Request Timeout'; this.lg('REGISTER : pas de réponse de ' + this.srvStr()); if (this.onEvent) this.onEvent('reg'); } }); r.exp = exp;
  }
  onRegResp(s) {
    const r = this.reg, c = this.cfg; if (s.cmethod !== 'REGISTER') return; if (s.status === 100) return; this.stopTx('REG');
    if ((s.status === 401 || s.status === 407) && !r.authed) { r.authed = true; r.cseq++; this.doRegister(s.h('WWW-Authenticate') || s.h('Proxy-Authenticate'), r.exp); return; }
    r.authed = false;
    if (s.status === 200) { if (r.exp === 0) { r.state = 'unregistered'; } else { r.state = 'registered'; r.t = this.sim.now; r.reason = ''; this.lg('Enregistré sur ' + this.srvStr() + ' (extension ' + c.user + ')'); r.timer = this.sim.at(Math.max(10, r.exp / 2) * 1000, () => this.register()); } }
    else { r.state = 'failed'; r.reason = s.status + ' ' + s.reason; this.lg('Échec de l\'enregistrement : ' + s.status + ' ' + s.reason); }
    if (this.onEvent) this.onEvent('reg');
  }
  /* ---- appel sortant ---- */
  call(number) {
    const c = this.cfg; if (!c.ext) { this.lg('Compte SIP non configuré'); return false; } if (this.cur) { this.lg('Ligne occupée'); return false; }
    let dst = c.server, domain = this.srvStr(); const m = /^([^@]+)@([\d.]+)$/.exec(number); if (m) { number = m[1]; dst = IP.parse(m[2]); domain = m[2]; } if (!dst) { this.lg('Aucun serveur SIP : composez utilisateur@adresse'); return false; }
    this.ensure(); const call = this.cur = { dir: 'out', peer: number, domain, dst, callId: rnd(this.sim, 12) + '@' + IP.str(this.myIp(dst)), ftag: rnd(this.sim, 8), ttag: '', cseq: 1, state: 'calling', t0: this.sim.now, tAns: 0, media: null, codec: null, authed: false };
    this.rtpN++; call.lport = 10000 + 2 * this.rtpN; this.sendInvite(call, null); if (this.onEvent) this.onEvent('call'); return true;
  }
  offer(call) { const pts = this.cfg.codecs.map(n => CODECS[n].pt).concat([101]); return Codec.sdp({ user: this.cfg.user || 'sim', sid: 1000 + this.sim.rng.int(9000), ip: this.myIp(call.dst), port: call.lport, pts }); }
  sendInvite(call, chal) {
    const uri = 'sip:' + call.peer + '@' + call.domain; call.branch = this.branch();
    const h = this.base('INVITE', uri, { branch: call.branch, ftag: call.ftag, callId: call.callId, cseq: call.cseq, dst: call.dst, toUser: call.peer, domain: call.domain }); h.push(['Content-Type', 'application/sdp']); if (chal) h.push(this.authHdr(chal, 'INVITE', uri));
    call.inv = { method: 'INVITE', uri, headers: h, body: this.offer(call) }; this.send(call.inv, call.dst, { key: 'INV' + call.callId, maxTries: 6, onTimeout: () => this.endCall(call, 'Pas de réponse (timeout)', 408) });
  }
  hangup() {
    const call = this.cur; if (!call) return; this.stopTx('ANS' + call.callId);
    if (call.state === 'calling' || call.state === 'ringing') { if (call.dir === 'out') { const h = this.base('CANCEL', 'sip:' + call.peer + '@' + call.domain, { branch: call.branch, ftag: call.ftag, callId: call.callId, cseq: call.cseq, dst: call.dst, toUser: call.peer, domain: call.domain }); call.cancelled = true; this.send({ method: 'CANCEL', uri: 'sip:' + call.peer + '@' + call.domain, headers: h }, call.dst, { key: 'CAN' + call.callId, maxTries: 3 }); this.lg('CANCEL envoyé'); } else this.reject(603); return; }
    if (call.state === 'talking') { const cs = ++call.cseq; const uri = call.dir === 'out' ? 'sip:' + call.peer + '@' + call.domain : call.remoteContact || 'sip:' + call.peer + '@' + call.domain; const h = this.dialogHdr(call, 'BYE', cs, uri); this.send({ method: 'BYE', uri, headers: h }, call.dst, { key: 'BYE' + call.callId, maxTries: 4 }); this.endCall(call, 'Raccroché', 200, true); }
  }
  dialogHdr(call, method, cs, uri) {
    const c = this.cfg, me = this.myIp(call.dst); const out = call.dir === 'out';
    const from = out ? ['From', (c.name ? '"' + c.name + '" ' : '') + '<sip:' + c.user + '@' + call.domain + '>;tag=' + call.ftag] : ['From', call.toHdr + ''];
    const to = out ? ['To', '<sip:' + call.peer + '@' + call.domain + '>;tag=' + call.ttag] : ['To', call.fromHdr];
    return [['Via', 'SIP/2.0/UDP ' + IP.str(me) + ':5060;branch=' + this.branch() + ';rport'], ['Max-Forwards', '70'], out ? from : ['From', call.myHdr], out ? to : ['To', call.fromHdr], ['Call-ID', call.callId], ['CSeq', cs + ' ' + method], ['Contact', '<sip:' + c.user + '@' + IP.str(me) + ':5060>']];
  }
  /* ---- entrée ---- */
  input(p) {
    const s = p.sip; if (!s) return; if (this.debug) this.lg('Reçu de ' + IP.str(p.ip.src) + ' : ' + Codec.sipSummary(s));
    if (!s.isReq) return this.onResp(s, p);
    const key = s.callId + '|' + s.cseq + '|' + s.method; if (this.seen.has(key) && s.method !== 'ACK') { const last = this.seen.get(key); if (last) this.node.udpSend(p.ip.src, 5060, 5060, last, { tos: this.cfg.dscpSip << 2 }); return; }
    switch (s.method) { case 'INVITE': return this.onInvite(s, p); case 'ACK': return this.onAck(s, p); case 'BYE': return this.onBye(s, p); case 'CANCEL': return this.onCancel(s, p); case 'OPTIONS': return this.reply(s, p, 200, []); default: return this.reply(s, p, 501, []); }
  }
  reply(s, p, status, extra, body, ttag) {
    const h = []; ['Via', 'From'].forEach(n => s.headers.filter(x => x[0] === n).forEach(x => h.push(x))); let to = s.h('To'); if (ttag && !/tag=/.test(to)) to += ';tag=' + ttag; h.push(['To', to]); h.push(['Call-ID', s.callId]); h.push(['CSeq', s.cseq + ' ' + s.cmethod]);
    (extra || []).forEach(x => h.push(x)); if (body) h.push(['Content-Type', 'application/sdp']);
    const m = Codec.sip({ status, headers: h, body: body || '' }); this.seen.set(s.callId + '|' + s.cseq + '|' + s.method, m); if (this.seen.size > 200) this.seen.delete(this.seen.keys().next().value);
    this.node.udpSend(p.ip.src, 5060, 5060, m, { tos: this.cfg.dscpSip << 2 }); return m;
  }
  onInvite(s, p) {
    const c = this.cfg; if (!c.ext) return this.reply(s, p, 404, []);
    if (this.cur && this.cur.callId !== s.callId) { this.reply(s, p, 486, []); this.lg('INVITE de ' + s.from + ' rejeté : occupé'); return; }
    if (this.cur && this.cur.callId === s.callId) return;
    if (c.dnd) { this.reply(s, p, 486, []); this.lg('Ne pas déranger : appel de ' + s.from + ' refusé'); return; }
    const ttag = rnd(this.sim, 8); this.rtpN++;
    const call = this.cur = { dir: 'in', peer: s.from || 'inconnu', dst: p.ip.src, callId: s.callId, ftag: ttag, ttag: '', cseq: s.cseq, state: 'ringing', t0: this.sim.now, tAns: 0, media: null, codec: null, lport: 10000 + 2 * this.rtpN, inv: s, invSrc: p.ip.src, lttag: ttag, fromHdr: s.h('From'), myHdr: s.h('To') + ';tag=' + ttag, remoteSdp: s.sdp, domain: this.srvStr(), remoteContact: (/<([^>]+)>/.exec(s.h('Contact') || '') || [])[1] };
    const rr = s.headers.filter(x => x[0] === 'Record-Route'); this.reply(s, p, 180, [['Contact', '<sip:' + c.user + '@' + IP.str(this.myIp(p.ip.src)) + ':5060>']].concat(rr), null, ttag);
    this.lg('Appel entrant de ' + call.peer); this.ring = true; if (this.onEvent) this.onEvent('ring');
    if (c.autoAnswer) call.ansT = this.sim.at(c.answerDelay, () => { if (this.cur === call && call.state === 'ringing') this.answer(); });
  }
  answer() {
    const call = this.cur; if (!call || call.dir !== 'in' || call.state !== 'ringing') return false; if (call.ansT) call.ansT.dead = true;
    const s = call.inv, c = this.cfg; const offered = (call.remoteSdp && call.remoteSdp.pts) || []; let chosen = null; for (const n of c.codecs) { if (offered.includes(CODECS[n].pt)) { chosen = CODECS[n]; break; } }
    if (!chosen) { this.reject(488); return false; }
    call.codec = chosen; const sdp = Codec.sdp({ user: c.user || 'sim', sid: 1000 + this.sim.rng.int(9000), ip: this.myIp(call.dst), port: call.lport, pts: [chosen.pt, 101] });
    const rr = s.headers.filter(x => x[0] === 'Record-Route'); const m = this.reply(s, { ip: { src: call.invSrc } }, 200, [['Contact', '<sip:' + c.user + '@' + IP.str(this.myIp(call.dst)) + ':5060>'], ['Allow', 'INVITE, ACK, CANCEL, BYE']].concat(rr), sdp, call.lttag);
    call.state = 'talking'; call.tAns = this.sim.now; this.ring = false; this.startMedia(call, call.remoteSdp);
    const t = { key: 'ANS' + call.callId, tries: 1, delay: 500, tx: () => this.node.udpSend(call.invSrc, 5060, 5060, m, { tos: this.cfg.dscpSip << 2 }) }; const tick = () => { if (t.done || t.tries >= 5) { this.txns.delete(t.key); return; } t.tries++; t.tx(); t.delay *= 2; t.timer = this.sim.at(t.delay, tick); }; t.timer = this.sim.at(t.delay, tick); this.txns.set(t.key, t);
    this.lg('Appel décroché (' + chosen.name + ')'); if (this.onEvent) this.onEvent('call'); return true;
  }
  reject(code) { const call = this.cur; if (!call || call.dir !== 'in') return; if (call.ansT) call.ansT.dead = true; this.reply(call.inv, { ip: { src: call.invSrc } }, code || 603, [], null, call.lttag); this.endCall(call, 'Appel refusé (' + (code || 603) + ')', code || 603); }
  onAck(s) { const call = this.cur; if (call && call.callId === s.callId) this.stopTx('ANS' + call.callId); }
  onBye(s, p) { const call = this.cur; if (!call || call.callId !== s.callId) { this.reply(s, p, 481, []); return; } this.reply(s, p, 200, []); this.endCall(call, 'Correspondant a raccroché', 200, true); }
  onCancel(s, p) { const call = this.cur; if (!call || call.callId !== s.callId || call.state !== 'ringing') { this.reply(s, p, 481, []); return; } this.reply(s, p, 200, []); this.reply(call.inv, { ip: { src: call.invSrc } }, 487, [], null, call.lttag); this.endCall(call, 'Appel manqué (annulé par ' + call.peer + ')', 487); }
  onResp(s, p) {
    if (s.cmethod === 'REGISTER') return this.onRegResp(s);
    if (s.cmethod === 'BYE') { this.stopTx('BYE' + s.callId); return; } if (s.cmethod === 'CANCEL') { this.stopTx('CAN' + s.callId); return; }
    const call = this.cur; if (!call || call.callId !== s.callId) return;
    if (s.cmethod === 'INVITE' && call.dir === 'out') {
      if (s.status === 100) { this.stopTxKeep(call); return; }
      if (s.status < 200) { this.stopTx('INV' + call.callId); if (call.state === 'calling') { call.state = 'ringing'; const tg = /tag=([^;>\s]+)/.exec(s.h('To') || ''); if (tg) call.ttag = tg[1]; this.lg('Ça sonne (' + s.status + ' ' + s.reason + ')'); if (this.onEvent) this.onEvent('call'); } return; }
      this.stopTx('INV' + call.callId);
      const tg = /tag=([^;>\s]+)/.exec(s.h('To') || ''); if (tg) call.ttag = tg[1];
      if (s.status === 200) {
        call.remoteContact = (/<([^>]+)>/.exec(s.h('Contact') || '') || [])[1]; const ack = this.dialogHdr(call, 'ACK', call.cseq, 'sip:' + call.peer + '@' + call.domain); this.send({ method: 'ACK', uri: 'sip:' + call.peer + '@' + call.domain, headers: ack }, call.dst, {});
        if (call.cancelled) { this.hangupEstablished(call); return; }
        if (s.sdp) { const pt = s.sdp.pts.find(x => x !== 101); call.codec = byPt(pt) || CODECS.PCMU; call.state = 'talking'; call.tAns = this.sim.now; this.startMedia(call, s.sdp); this.lg('Communication établie (' + call.codec.name + ')'); if (this.onEvent) this.onEvent('call'); } else this.endCall(call, 'Pas de SDP dans le 200 OK', 488);
        return;
      }
      // échec : ACK dans la transaction (même branche)
      const hAck = [['Via', 'SIP/2.0/UDP ' + IP.str(this.myIp(call.dst)) + ':5060;branch=' + call.branch], ['Max-Forwards', '70'], ['From', call.inv.headers.find(x => x[0] === 'From')[1]], ['To', s.h('To')], ['Call-ID', call.callId], ['CSeq', call.cseq + ' ACK']];
      this.send({ method: 'ACK', uri: 'sip:' + call.peer + '@' + call.domain, headers: hAck }, call.dst, {});
      if ((s.status === 401 || s.status === 407) && !call.authed) { call.authed = true; call.cseq++; this.sendInvite(call, s.h('WWW-Authenticate') || s.h('Proxy-Authenticate')); return; }
      this.endCall(call, s.status + ' ' + s.reason, s.status); return;
    }
    if (s.cmethod === 'CANCEL') { this.stopTx('CAN' + call.callId); return; }
    if (s.cmethod === 'BYE') { this.stopTx('BYE' + call.callId); return; }
  }
  stopTxKeep(call) { const t = this.txns.get('INV' + call.callId); if (t) { t.tries = 0; t.delay = 4000; } }
  hangupEstablished(call) { call.state = 'talking'; this.hangup(); }
  /* ---- fin d'appel ---- */
  endCall(call, reason, code, wasTalking) {
    if (this.cur !== call) return; this.stopTx('INV' + call.callId); this.stopTx('ANS' + call.callId);
    const st = this.endMedia(call); const rec = { peer: call.peer, dir: call.dir, t0: call.t0, dur: call.tAns ? this.sim.now - call.tAns : 0, result: reason, code, codec: call.codec ? call.codec.name : '', stats: st, answered: !!call.tAns };
    this.hist.push(rec); if (this.hist.length > 50) this.hist.shift(); this.cur = null; this.ring = false;
    this.lg('Fin d\'appel avec ' + call.peer + ' : ' + reason + (st ? ' — MOS ' + st.mos + ' (' + mosLabel(st.mos) + ')' : '')); if (this.onEvent) this.onEvent('call');
  }
  /* ---- RTP ---- */
  startMedia(call, sdp) {
    if (!sdp || !sdp.ip || !sdp.port || !call.codec) return; const codec = call.codec, node = this.node, sim = this.sim; const ssrc = sim.rng.int(0x7fffffff);
    const m = call.media = { codec, ssrc, seq: sim.rng.int(60000), remote: sdp.ip, rport: sdp.port, lport: call.lport, tx: 0, rx: 0, lost: 0, jit: 0, lastTransit: null, base: -1, maxSeq: 0, delaySum: 0, delayMax: 0, started: sim.now, badFirst: 0, lastRx: 0, cycles: 0 };
    node.udpBind(call.lport, p => { const r = p.rtp; if (!r) return; const tr = sim.now - r.ts / 8; m.rx++; m.lastRx = sim.now; m.delaySum += tr; if (tr > m.delayMax) m.delayMax = tr; if (m.lastTransit !== null) { const d = Math.abs(tr - m.lastTransit); m.jit += (d - m.jit) / 16; } m.lastTransit = tr; if (m.base < 0) { m.base = r.seq; m.maxSeq = r.seq; } else { const gap = ((r.seq - m.maxSeq) & 0xffff); if (gap > 0 && gap < 3000) { m.lost += gap - 1; m.maxSeq = r.seq; } } });
    const step = codec.step / 8; let ts = 0; const dscp = this.cfg.dscpRtp;
    const tick = () => { if (call.media !== m || m.stop) return; const b = Codec.rtp({ pt: codec.pt, seq: m.seq, ts: Math.floor(sim.now * 8) >>> 0, ssrc, mark: m.tx === 0, payload: new Uint8Array(codec.size) }); m.seq = (m.seq + 1) & 0xffff; m.tx++; node.udpSend(m.remote, m.rport, m.lport, b, { tos: dscp << 2 }); m.timer = sim.at(step, tick); };
    m.timer = sim.at(step, tick);
  }
  stats(m) {
    m = m || (this.cur && this.cur.media); if (!m) return null; const exp = m.base < 0 ? 0 : m.maxSeq - m.base + 1; const lost = Math.max(0, m.lost); const pct = exp ? 100 * lost / (exp) : (m.tx > 50 && m.rx === 0 ? 100 : 0);
    const delay = m.rx ? m.delaySum / m.rx : 0; const eff = delay + 40 + 2 * m.jit; const e = mos(m.codec, eff, pct);
    return { codec: m.codec.name, tx: m.tx, rx: m.rx, lost, lossPct: Math.round(pct * 10) / 10, jitter: Math.round(m.jit * 10) / 10, delay: Math.round(delay * 10) / 10, delayMax: Math.round(m.delayMax * 10) / 10, R: e.R, mos: e.mos, oneWay: m.tx > 50 && m.rx === 0 };
  }
  endMedia(call) { const m = call.media; if (!m) return null; m.stop = true; if (m.timer) m.timer.dead = true; this.node.udpUnbind(m.lport); const st = this.stats(m); call.media = null; return st; }
}

/* ================================================================== PBX (type Asterisk) */
class Pbx {
  constructor(node) { this.node = node; this.sim = node.sim; this.reset(); }
  reset() { this.enabled = false; this.realm = 'asterisk'; this.peers = new Map(); this.trunks = new Map(); this.routes = []; this.calls = new Map(); this.cdr = []; this.log = []; this.nonces = new Map(); this.debug = false; this.sec = null; this.stat = { reg: 0, inv: 0, auth: 0 }; }
  lg(t) { const d = new Date(1780000000000 + this.sim.now); const ts = d.toISOString().slice(0, 19).replace('T', ' '); this.log.push('[' + ts + '] ' + t); if (this.log.length > 500) this.log.shift(); }
  start() { if (this.enabled) return; this.enabled = true; this.node.voip.ensure(); this.lg('NOTICE: Asterisk Ready.'); }
  stop() { this.enabled = false; this.peers.forEach(p => { p.reg = null; }); this.calls.clear(); }
  addPeer(name, secret, o) { this.peers.set(name, Object.assign({ name, secret, callerid: name, host: 'dynamic', context: 'default', reg: null, codecs: [] }, o || {})); }
  addTrunk(name, host, o) { this.trunks.set(name, Object.assign({ name, host: typeof host === 'string' ? IP.parse(host) : host }, o || {})); }
  addRoute(pattern, target) { this.routes.push({ pattern, target }); }
  /* motif Asterisk : _XXXX, N Z, X. */
  static match(pat, num) {
    if (pat[0] !== '_') return pat === num; let re = ''; for (let i = 1; i < pat.length; i++) { const c = pat[i]; if (c === 'X') re += '[0-9]'; else if (c === 'Z') re += '[1-9]'; else if (c === 'N') re += '[2-9]'; else if (c === '.') re += '.+'; else if (c === '!') re += '.*'; else if (c === '[') { const j = pat.indexOf(']', i); re += pat.slice(i, j + 1); i = j; } else re += c.replace(/[.*+?^${}()|\\]/g, '\\$&'); }
    return new RegExp('^' + re + '$').test(num);
  }
  route(num) { for (const r of this.routes) if (Pbx.match(r.pattern, num)) return r; return null; }
  /* ---- fichiers de configuration (texte) ---- */
  sipConf() {
    let o = '[general]\nudpbindaddr=0.0.0.0:5060\nallowguest=no\nrealm=' + this.realm + '\n\n';
    this.peers.forEach(p => { o += '[' + p.name + ']\ntype=friend\nsecret=' + p.secret + '\nhost=' + p.host + '\ncontext=' + p.context + '\ncallerid=' + p.callerid + ' <' + p.name + '>\ndisallow=all\nallow=' + (p.codecs.length ? p.codecs.join(',') : 'ulaw,alaw') + '\n\n'; });
    this.trunks.forEach(t => { o += '[' + t.name + ']\ntype=peer\nhost=' + IP.str(t.host) + '\ncontext=' + (t.context || 'default') + '\ninsecure=invite,port\n\n'; }); return o;
  }
  extConf() { let o = '[default]\n'; this.routes.forEach(r => { o += 'exten => ' + r.pattern + ',1,Dial(' + r.target + ',20)\nexten => ' + r.pattern + ',n,Hangup()\n'; }); return o; }
  parseText(kind, text, append) {
    if (kind === 'sip') {
      let cur = null; text.split('\n').forEach(l0 => { const l = l0.trim(); if (!l || l[0] === ';') return; let m;
        if ((m = /^\[(.+)\]$/.exec(l))) { cur = m[1]; if (cur !== 'general' && !this.peers.has(cur) && !this.trunks.has(cur)) this.peers.set(cur, { name: cur, secret: '', callerid: cur, host: 'dynamic', context: 'default', reg: null, codecs: [], type: 'friend' }); this._sec = cur; return; }
        cur = cur || this._sec; if (!cur || cur === 'general') { if ((m = /^realm\s*=\s*(\S+)/.exec(l))) this.realm = m[1]; return; }
        m = /^(\w+)\s*=>?\s*(.*)$/.exec(l); if (!m) return; const p = this.peers.get(cur) || this.trunks.get(cur); if (!p) return; const k = m[1].toLowerCase(), v = m[2].trim();
        if (k === 'secret') p.secret = v; else if (k === 'host') { if (/^\d+\.\d+\.\d+\.\d+$/.test(v) && (p.type === 'peer' || !this.peers.get(cur))) { this.peers.delete(cur); this.trunks.set(cur, { name: cur, host: IP.parse(v), context: 'default' }); } else p.host = v; } else if (k === 'callerid') p.callerid = v.replace(/<.*>/, '').replace(/"/g, '').trim() || cur; else if (k === 'type') { p.type = v; if (v === 'peer' && p.secret === '' && this.peers.has(cur)) { } } else if (k === 'context') p.context = v; else if (k === 'allow') p.codecs = v.split(',').map(x => x.trim());
      });
    } else {
      text.split('\n').forEach(l0 => { const l = l0.trim(); const m = /^exten\s*=>\s*([^,]+),\s*1\s*,\s*Dial\(\s*([^,)]+)/i.exec(l); if (m) { this.routes = this.routes.filter(r => r.pattern !== m[1].trim()); this.routes.push({ pattern: m[1].trim(), target: m[2].trim() }); } });
    }
  }
  /* ---- entrée SIP ---- */
  input(p) {
    const s = p.sip; if (!s || !this.enabled) return; if (this.debug) this.lg('SIP/2.0 <-- ' + IP.str(p.ip.src) + ' : ' + Codec.sipSummary(s));
    if (!s.isReq) return this.onResp(s, p);
    if (s.method === 'REGISTER') return this.onRegister(s, p); if (s.method === 'INVITE') return this.onInvite(s, p);
    if (s.method === 'OPTIONS') return this.reply(s, p, 200, []);
    const call = this.calls.get(s.callId); if (!call) { if (s.method !== 'ACK') this.reply(s, p, 481, []); return; }
    this.forwardInDialog(call, s, p);
  }
  reply(s, p, status, extra, body, ttag) {
    const h = []; ['Via', 'From'].forEach(n => s.headers.filter(x => x[0] === n).forEach(x => h.push(x))); let to = s.h('To') || ''; if (ttag && !/tag=/.test(to)) to += ';tag=' + ttag; h.push(['To', to]); h.push(['Call-ID', s.callId]); h.push(['CSeq', s.cseq + ' ' + s.cmethod]); (extra || []).forEach(x => h.push(x)); h.push(['Server', 'Asterisk PBX 20.5.0']);
    const m = Codec.sip({ status, headers: h, body: body || '' }); this.node.udpSend(p.ip.src, 5060, 5060, m, { tos: 24 << 2 }); }
  nonce() { const n = rnd(this.sim, 16); this.nonces.set(n, this.sim.now); return n; }
  challenge(s, p, code) { this.reply(s, p, code || 401, [['WWW-Authenticate', 'Digest algorithm=MD5, realm="' + this.realm + '", nonce="' + this.nonce() + '"']]); }
  checkAuth(s, peer) { const a = authParams(s.h('Authorization')); if (!a.nonce || !this.nonces.has(a.nonce)) return null; return a.response === digest(a.username, this.realm, peer.secret, s.method, a.uri, a.nonce) && a.username === peer.name; }
  srcStr(p) { return IP.str(p.ip.src) + ':' + p.udp.sport; }
  onRegister(s, p) {
    const user = s.from; const peer = this.peers.get(user); this.stat.reg++;
    if (!s.h('Authorization')) { if (!peer) { this.lg('NOTICE: Registration from \'' + (s.h('From') || '') + '\' failed for \'' + this.srcStr(p) + '\' - No matching peer found'); this.reply(s, p, 403, []); return; } this.challenge(s, p); return; }
    const a = authParams(s.h('Authorization')); const pe = this.peers.get(a.username);
    if (!pe) { this.lg('NOTICE: Registration from \'' + (s.h('From') || '') + '\' failed for \'' + this.srcStr(p) + '\' - No matching peer found'); this.reply(s, p, 403, []); return; }
    const ok = this.checkAuth(s, pe); if (!ok) { this.stat.auth++; this.lg('NOTICE: Registration from \'' + (s.h('From') || '') + '\' failed for \'' + this.srcStr(p) + '\' - Wrong password'); this.reply(s, p, 403, []); return; }
    const exp = +(s.h('Expires') || 3600); const c = (/<sip:[^@]+@([\d.]+):?(\d*)/.exec(s.h('Contact') || '') || []);
    if (exp === 0) { pe.reg = null; this.lg('NOTICE: Unregistered SIP \'' + pe.name + '\''); } else { pe.reg = { ip: c[1] ? IP.parse(c[1]) : p.ip.src, port: c[2] ? +c[2] : p.udp.sport, t: this.sim.now, exp, ua: s.h('User-Agent') || '' }; this.lg('NOTICE: Registered SIP \'' + pe.name + '\' at ' + IP.str(pe.reg.ip) + ':' + pe.reg.port); this.node.log('%SIP-6-REGISTER: extension ' + pe.name + ' enregistrée depuis ' + IP.str(pe.reg.ip), 'info'); }
    this.reply(s, p, 200, [['Contact', s.h('Contact') + ';expires=' + exp], ['Date', 'Wed, 30 Sep 2026 10:00:00 GMT']]);
  }
  fwd(bytesMsg, dst, tos) { this.node.udpSend(dst.ip, dst.port || 5060, 5060, bytesMsg, { tos: 24 << 2 }); }
  onInvite(s, p) {
    const existing = this.calls.get(s.callId); if (existing) { this.forwardInDialog(existing, s, p); return; }
    this.stat.inv++; let caller = null, fromTrunk = null;
    for (const t of this.trunks.values()) if (t.host === p.ip.src) fromTrunk = t;
    if (!fromTrunk) {
      const a = authParams(s.h('Authorization')); caller = this.peers.get(a.username || s.from);
      if (!s.h('Authorization')) { if (!this.peers.get(s.from)) { this.lg('NOTICE: Sending fake auth rejection for device ' + (s.h('From') || '') + ': ' + this.srcStr(p)); this.reply(s, p, 403, []); return; } this.challenge(s, p); return; }
      if (!caller || !this.checkAuth(s, caller)) { this.stat.auth++; this.lg('NOTICE: Failed to authenticate device ' + (s.h('From') || '') + ' (' + this.srcStr(p) + ')'); this.reply(s, p, 403, []); return; }
    }
    const num = (/sip:([^@;>]+)@/.exec(s.h('To') || '') || /^sip:([^@]+)@/.exec(s.headers.length ? (s.uri || '') : '') || [])[1] || (/^sip:([^@]+)@/.exec(s.uri) || [])[1];
    const r = this.route(num); if (!r) { this.lg('NOTICE: No such extension \'' + num + '\' in context \'default\' (' + this.srcStr(p) + ')'); this.reply(s, p, 404, []); return; }
    const m = /^SIP\/([^@]+?)(?:@(.+))?$/i.exec(r.target); let dest = null, uri;
    if (!m) { this.reply(s, p, 500, []); return; }
    const who = m[1].replace(/\$\{EXTEN\}/, num), trunkName = m[2];
    if (trunkName) { const t = this.trunks.get(trunkName); if (!t) { this.reply(s, p, 503, []); return; } dest = { ip: t.host, port: 5060 }; uri = 'sip:' + who + '@' + IP.str(t.host); }
    else { const pe = this.peers.get(who); if (!pe || !pe.reg) { this.lg('NOTICE: Peer \'' + who + '\' is not registered (unavailable)'); this.reply(s, p, 480, []); return; } dest = { ip: pe.reg.ip, port: pe.reg.port }; uri = 'sip:' + who + '@' + IP.str(pe.reg.ip) + ':' + pe.reg.port; }
    if (dest.ip === p.ip.src && !fromTrunk && caller && caller.reg && caller.name === who) { this.reply(s, p, 482, []); return; }
    const call = { callId: s.callId, caller: { ip: p.ip.src, port: p.udp.sport }, callee: dest, from: s.from, to: num, t0: this.sim.now, state: 'ringing', answered: 0, viaTag: this.sim.rng.int(1e6) };
    this.calls.set(s.callId, call); this.reply(s, p, 100, []); this.lg('== Using SIP RTP CoS mark 5'); this.lg('-- Executing [' + num + '@default:1] Dial("SIP/' + (caller ? caller.name : 'trunk') + '", "' + r.target + ',20") in new stack');
    this.fwdReq(call, s, dest, uri, true);
  }
  fwdReq(call, s, dest, uri, isInvite) {
    const me = this.node.primaryIface.ip; const via = ['Via', 'SIP/2.0/UDP ' + IP.str(me) + ':5060;branch=z9hG4bK' + call.viaTag + rnd(this.sim, 4)];
    const h = [via].concat(s.headers.filter(x => x[0] === 'Via')).concat(s.headers.filter(x => x[0] !== 'Via' && x[0] !== 'Max-Forwards' && x[0] !== 'Record-Route' && x[0] !== 'Content-Length')); h.splice(1 + s.headers.filter(x => x[0] === 'Via').length, 0, ['Max-Forwards', String(Math.max(0, +(s.h('Max-Forwards') || 70) - 1))], ['Record-Route', '<sip:' + IP.str(me) + ';lr>']);
    const msg = { method: s.method, uri, headers: h.filter(x => x[0] !== 'Authorization'), body: s.body }; this.node.udpSend(dest.ip, dest.port || 5060, 5060, Codec.sip(msg), { tos: 24 << 2 });
  }
  forwardInDialog(call, s, p) {
    const fromCaller = p.ip.src === call.caller.ip; const dest = fromCaller ? call.callee : call.caller;
    if (s.method === 'BYE' && call.state === 'ended') { /* retransmission */ } else if (s.method === 'BYE') { this.lg('-- Called SIP/' + call.to + ' hangup'); call.state = 'ended'; this.cdr.push({ src: call.from, dst: call.to, t: call.t0, dur: call.answered ? this.sim.now - call.answered : 0, disp: call.answered ? 'ANSWERED' : 'NO ANSWER' }); }
    if (s.method === 'CANCEL') { call.state = 'cancelled'; this.cdr.push({ src: call.from, dst: call.to, t: call.t0, dur: 0, disp: 'NO ANSWER' }); }
    const uri = s.method === 'ACK' || s.method === 'BYE' ? 'sip:' + (fromCaller ? call.to : call.from) + '@' + IP.str(dest.ip) + ':' + dest.port : s.uri;
    this.fwdReq(call, s, dest, s.method === 'CANCEL' || s.method === 'ACK' || s.method === 'BYE' ? uri : s.uri, false);
    if (s.method === 'BYE' || s.method === 'CANCEL') this.sim.at(32000, () => this.calls.delete(call.callId));
  }
  onResp(s, p) {
    const call = this.calls.get(s.callId); if (!call) return; const me = IP.str(this.node.primaryIface.ip);
    const vias = s.headers.filter(x => x[0] === 'Via'); if (vias.length < 2) return; const rest = s.headers.filter(x => x[0] !== 'Via' && x[0] !== 'Content-Length'); const h = vias.slice(1).concat(rest);
    if (s.cmethod === 'INVITE' && s.status === 200 && !call.answered) { call.answered = this.sim.now; call.state = 'up'; this.lg('-- SIP/' + call.to + ' answered SIP/' + call.from); }
    if (s.cmethod === 'INVITE' && s.status >= 300 && s.status !== 401 && s.status !== 407) { this.cdr.push({ src: call.from, dst: call.to, t: call.t0, dur: 0, disp: s.status === 486 ? 'BUSY' : 'NO ANSWER' }); call.state = 'ended'; }
    const m = Codec.sip({ status: s.status, reason: s.reason, headers: h, body: s.body }); this.node.udpSend(call.caller.ip, call.caller.port || 5060, 5060, m, { tos: 24 << 2 });
  }
}

/* ================================================================== Téléphone IP à 2 ports (Internet / PC) : pont L2 + VLAN voix appris par CDP */
function initPhone(h) {
  h.phone = { voiceVlan: 0, cdpFrom: '', reqT: null };
  const pc = h.ports.find(p => p.name === 'PC'), up = h.ports.find(p => p.name === 'Internet');
  if (pc) h.ifaces.delete('PC'); const ifc = h.ifaces.get('Internet'); h.phone.up = up; h.phone.pc = pc;
  const setVlan = v => { const ph = h.phone; if (ph.voiceVlan === v) return; ph.voiceVlan = v; if (ifc) { ifc.vid = v || null; h.sim.log(h, 'VLAN voix appris par CDP : ' + v, 'info'); const c = h.dhcpClients.get(ifc.name); if (c) { c.start && c.start(); } } };
  h.phone.setVlan = setVlan;
  const sendQuery = () => { if (!up || !up.up) return; const pl = Codec.cdp({ device: 'SEP' + up.mac.replace(/:/g, '').toUpperCase(), port: 'Internet', platform: 'Yealink SIP-T31P', caps: 0x90, query: true }); h.send(up, Codec.frameSnap({ dst: Codec.CDP_MAC, src: up.mac, oui: [0, 0, 12], pid: 0x2000, payload: pl })); };
  const base = h.portStateChanged.bind(h); h.portStateChanged = port => { base(port); if (port === up && !port.up) { setVlan(0); } if (port === up && port.up) { h.sim.at(200, sendQuery); h.sim.at(3000, () => { if (!h.phone.voiceVlan) sendQuery(); }); } };
  h.recv = function (port, bytes) {
    if (!port.up) return;
    if (port === pc) { if (up && up.up) h.send(up, bytes); return; }
    const p = Codec.parse(bytes, false); if (!p.eth) return;
    if (p.cdp) { if (p.cdp.voiceVlan) { h.phone.cdpFrom = p.cdp.device; setVlan(p.cdp.voiceVlan); } return; }
    const vid = p.eth.vlan ? p.eth.vlan.vid : null; const vv = h.phone.voiceVlan;
    if (vv && vid === vv) { NS.IPNode.prototype.recv.call(h, port, bytes); return; }
    if (vid) { return; }          // autre VLAN étiqueté : ignoré
    const dst = p.eth.dst; if (pc && pc.up) h.send(pc, bytes);
    if (!vv) NS.IPNode.prototype.recv.call(h, port, bytes);
    else if (dst === 'ff:ff:ff:ff:ff:ff') { /* diffusion données : non traitée par la pile voix */ }
  };
  const sf = h.sendFrame.bind(h); h.sendFrame = function (iface, dst, type, payload) {
    if (iface.vid && type === 0x0800) { const pcp = payload[1] >> 5; const f = Codec.frame({ dst, src: iface.mac, vlan: { vid: iface.vid, pcp }, type, payload }); return h.txIface(iface, f); }
    return sf(iface, dst, type, payload);
  };
  h.voip.configure({ codecs: ['PCMU', 'PCMA', 'G729'] });
}
NS.Sip = Sip; NS.Pbx = Pbx; NS.initPhone = initPhone; NS.voipUtil = { mos, mosLabel, CODECS, digest };
})(typeof window !== 'undefined' ? window : globalThis);
