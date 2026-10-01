/* devwin_ext.js — onglets d'équipement ajoutés : téléphonie SIP, PBX, RADIUS, supplicant 802.1X, supervision SNMP/syslog, IPv6, et « Suivi » (états live des protocoles) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { h, clear, ui, IP } = NS;
const inp = (v, ph, extra) => h('input', Object.assign({ type: 'text', value: v === undefined || v === null ? '' : v, placeholder: ph || '', spellcheck: 'false' }, extra || {}));
const chk = (label, v, fn) => { const c = h('input', { type: 'checkbox', checked: !!v }); if (fn) c.addEventListener('change', () => fn(c.checked)); return h('label.chk', c, ' ' + label); };
const sel = (opts, v, fn) => { const s = h('select', opts.map(o => { const [val, lab] = Array.isArray(o) ? o : [o, o]; return h('option', { value: val }, lab); })); s.value = v; if (fn) s.addEventListener('change', () => fn(s.value)); return s; };
const fmtT = ms => { const s = Math.floor(ms / 1000); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); };
const mosCol = m => m >= 4 ? '#16a34a' : m >= 3.6 ? '#ca8a04' : '#dc2626';
function shellRun(dev, cmd, cb) {
  if (!NS.HostShell) return cb('(terminal indisponible)'); const sh = dev._uiShell || (dev._uiShell = new NS.HostShell(dev)); let out = '', fin = false;
  sh.exec(cmd, { print: t => { out += t; }, done: () => { fin = true; cb(out); }, clear() { } });
}
function table(head, rows, empty) { if (!rows.length) return h('div.muted.small', empty || '—'); return h('table.tbl', h('tr', head.map(x => h('th', x))), rows.map(r => h('tr', r.map(c => h('td', c))))); }

/* ---------------------------------------------------------------- téléphonie */
function voipTab(app, dev) {
  const v = dev.voip; v.ensure(); const c = v.cfg; const root = h('div.form.full'); const isPhone = !!dev.phone;
  const ext = inp(c.ext, '1001'), pw = inp(c.secret, 'mot de passe SIP'), srv = inp(c.server ? IP.str(c.server) : '', '192.168.20.5'), nm = inp(c.name, 'Nom affiché');
  const cod = ['PCMU', 'PCMA', 'G722', 'G729'].map(k => { const cb = h('input', { type: 'checkbox', checked: c.codecs.includes(k) }); return { k, cb, el: h('label.chk', cb, ' ' + k) }; });
  const msgBox = h('div.fmsg');
  const save = () => { const l = cod.filter(x => x.cb.checked).map(x => x.k); if (!ext.value.trim() || !IP.parse(srv.value.trim())) { msgBox.className = 'fmsg err'; msgBox.textContent = 'Extension et adresse IP du serveur SIP obligatoires.'; return; } v.configure({ ext: ext.value.trim(), user: ext.value.trim(), secret: pw.value, server: srv.value.trim(), name: nm.value.trim(), codecs: l.length ? l : ['PCMU'] }); v.register(); msgBox.className = 'fmsg ok'; msgBox.textContent = 'REGISTER envoyé.'; };
  root.appendChild(h('fieldset', h('legend', isPhone ? 'Compte SIP du téléphone' : 'Softphone (compte SIP)'), h('div.grid2', ui.field('Extension / utilisateur', ext), ui.field('Mot de passe', pw), ui.field('Serveur SIP (PBX)', srv), ui.field('Nom affiché', nm)),
    h('div.row', h('span.muted', 'Codecs : '), cod.map(x => x.el)), h('div.row', chk('Réponse automatique (après 3 s)', c.autoAnswer, x => v.configure({ autoAnswer: x })), chk('Ne pas déranger', c.dnd, x => v.configure({ dnd: x }))),
    h('div.row', h('button.primary', { onclick: save }, 'Enregistrer sur le PBX'), h('button', { onclick: () => v.register(0) }, 'Se désinscrire')), msgBox));
  let vv = null; if (isPhone) { vv = inp(dev.phone.voiceVlan || '', 'auto (CDP)'); root.appendChild(h('fieldset', h('legend', 'VLAN voix'), h('div.row', ui.field('VLAN voix (manuel)', vv), h('button', { onclick: () => { dev.phone.setVlan(+vv.value || 0); } }, 'Appliquer')), h('div.muted.small', 'Le VLAN voix est normalement appris par CDP (switch Cisco : « switchport voice vlan N »). Il peut être saisi à la main (ex. avec un OmniSwitch).'), h('div.mono.small.vstate'))); }
  const num = inp('', 'numéro (ex. 1002)'); const st = h('div.mono.small'), stat = h('div'), hist = h('div'), lg = h('pre.log', { style: 'max-height:130px;overflow:auto;font-size:11px' });
  root.appendChild(h('fieldset', h('legend', 'Appels'), h('div.row', num, h('button.primary', { onclick: () => v.call(num.value.trim()) }, 'Appeler'), h('button', { onclick: () => v.answer() }, 'Décrocher'), h('button', { onclick: () => v.reject(603) }, 'Refuser'), h('button', { onclick: () => v.hangup() }, 'Raccrocher')), st, stat));
  root.appendChild(h('h4', 'Historique')); root.appendChild(hist); root.appendChild(h('h4', 'Journal SIP')); root.appendChild(lg);
  const upd = () => {
    const r = v.reg; st.textContent = 'Enregistrement : ' + ({ registered: '● enregistré', registering: '… en cours', failed: '✖ échec (' + r.reason + ')', unregistered: '○ non enregistré' }[r.state]) + '   |   Appel : ' + (v.cur ? (v.cur.dir === 'out' ? 'vers ' : 'de ') + v.cur.peer + ' — ' + ({ calling: 'appel…', ringing: v.cur.dir === 'in' ? 'sonnerie' : 'ça sonne', talking: 'communication ' + fmtT(dev.sim.now - v.cur.tAns) }[v.cur.state] || v.cur.state) : 'aucun');
    clear(stat); const s = v.stats(); if (s) stat.appendChild(h('div', h('b', 'Qualité audio : '), h('span', { style: 'color:' + mosCol(s.mos) + ';font-weight:700' }, 'MOS ' + s.mos + ' (' + NS.voipUtil.mosLabel(s.mos) + ')'), ' — ' + s.codec + ' · émis ' + s.tx + ' · reçus ' + s.rx + ' · perdus ' + s.lost + ' (' + s.lossPct + ' %) · gigue ' + s.jitter + ' ms · délai ' + s.delay + ' ms' + (s.oneWay ? ' — ⚠ audio unidirectionnel' : '')));
    clear(hist); hist.appendChild(table(['Sens', 'Numéro', 'Résultat', 'Durée', 'Codec', 'MOS'], v.hist.slice().reverse().map(x => [x.dir === 'out' ? '→ sortant' : '← entrant', x.peer, x.result, x.dur ? fmtT(x.dur) : '—', x.codec || '—', x.stats ? x.stats.mos : '—']), 'Aucun appel.'));
    lg.textContent = v.log.slice(-25).map(l => '[' + fmtT(l.t) + '] ' + l.msg).join('\n');
    if (isPhone) { const e = root.querySelector('.vstate'); if (e) e.textContent = 'VLAN voix actuel : ' + (dev.phone.voiceVlan || 'aucun (trames non étiquetées)') + (dev.phone.cdpFrom ? '  — annoncé par CDP depuis ' + dev.phone.cdpFrom : ''); }
  };
  return { el: root, update: upd };
}

/* ---------------------------------------------------------------- PBX */
function pbxTab(app, dev) {
  const P = dev.pbx; const root = h('div.form.full'); const dyn = h('div');
  root.appendChild(h('div.row', chk('Service Asterisk démarré', P.enabled, x => { if (x) P.start(); else P.stop(); }), h('span.muted', 'Équivalent de « systemctl start asterisk »')));
  const en = inp('', '1003'), es = inp('', 'secret'), ec = inp('', 'Nom'); root.appendChild(h('fieldset', h('legend', 'Ajouter un poste (sip.conf)'), h('div.grid2', ui.field('Extension', en), ui.field('Mot de passe', es), ui.field('Nom (callerid)', ec)), h('button.primary', { onclick: () => { if (!en.value.trim()) return; P.addPeer(en.value.trim(), es.value, { callerid: ec.value.trim() || en.value.trim() }); if (!P.routes.some(r => Codec_match(r, en.value.trim()))) P.addRoute(en.value.trim(), 'SIP/' + en.value.trim()); en.value = es.value = ec.value = ''; upd(); } }, 'Ajouter')));
  const rp = inp('', '_2XXX'), rt = inp('', 'SIP/${EXTEN}@site2'); root.appendChild(h('fieldset', h('legend', 'Plan de numérotation (extensions.conf)'), h('div.grid2', ui.field('Motif', rp, 'X = chiffre, _ = motif'), ui.field('Cible', rt)), h('button', { onclick: () => { if (rp.value.trim() && rt.value.trim()) { P.addRoute(rp.value.trim(), rt.value.trim()); rp.value = rt.value = ''; upd(); } } }, 'Ajouter la règle')));
  const tn = inp('', 'site2'), th = inp('', '10.2.0.5'); root.appendChild(h('fieldset', h('legend', 'Trunk SIP vers un autre PBX'), h('div.grid2', ui.field('Nom', tn), ui.field('Adresse IP', th)), h('button', { onclick: () => { const ip = IP.parse(th.value.trim()); if (tn.value.trim() && ip !== null) { P.addTrunk(tn.value.trim(), ip); tn.value = th.value = ''; upd(); } } }, 'Ajouter le trunk')));
  root.appendChild(dyn);
  function Codec_match(r, n) { return NS.Pbx.match(r.pattern, n); }
  const upd = () => {
    clear(dyn);
    dyn.appendChild(h('h4', 'Postes (sip show peers)')); dyn.appendChild(table(['Extension', 'Nom', 'Statut', 'Adresse', 'Agent', ''], Array.from(P.peers.values()).map(p => [p.name, p.callerid, p.reg ? '● OK' : '○ non enregistré', p.reg ? IP.str(p.reg.ip) + ':' + p.reg.port : '—', p.reg ? p.reg.ua : '', h('button.small', { onclick: () => { P.peers.delete(p.name); upd(); } }, '✕')]), 'Aucun poste.'));
    dyn.appendChild(h('h4', 'Plan de numérotation')); dyn.appendChild(table(['Motif', 'Cible', ''], P.routes.map((r, i) => [r.pattern, 'Dial(' + r.target + ')', h('button.small', { onclick: () => { P.routes.splice(i, 1); upd(); } }, '✕')]), 'Aucune règle.'));
    if (P.trunks.size) { dyn.appendChild(h('h4', 'Trunks')); dyn.appendChild(table(['Nom', 'Adresse'], Array.from(P.trunks.values()).map(t => [t.name, IP.str(t.host)]))); }
    dyn.appendChild(h('h4', 'Appels détaillés (CDR)')); dyn.appendChild(table(['De', 'Vers', 'Durée', 'Résultat'], P.cdr.slice(-10).reverse().map(c => [c.src, c.dst, fmtT(c.dur), c.disp]), 'Aucun appel terminé.'));
    dyn.appendChild(h('h4', 'Journal Asterisk (/var/log/asterisk/full)')); dyn.appendChild(h('pre.log', { style: 'max-height:130px;overflow:auto;font-size:11px' }, P.log.slice(-15).join('\n')));
  };
  return { el: root, update: (() => { let k = 0; return () => { if (k++ % 3 === 0) upd(); }; })(), init: upd };
}

/* ---------------------------------------------------------------- RADIUS */
function radiusTab(app, dev) {
  const R = dev.radius; const root = h('div.form.full'); const dyn = h('div');
  root.appendChild(h('div.row', chk('Service FreeRADIUS démarré', R.srv.enabled, x => { if (x) R.startSrv(); else R.stopSrv(); }), ui.field('Méthode EAP proposée', sel([['peap', 'PEAP (MSCHAPv2)'], ['md5', 'EAP-MD5']], R.srv.eapType, v => { R.srv.eapType = v; }))));
  const ci = inp('', '192.168.1.0'), cm = inp('255.255.255.0', '255.255.255.0'), cs = inp('', 'secret partagé'), cn = inp('', 'sw1');
  root.appendChild(h('fieldset', h('legend', 'Clients RADIUS (clients.conf) : les équipements NAS'), h('div.grid2', ui.field('Adresse / réseau', ci), ui.field('Masque', cm), ui.field('Secret partagé', cs), ui.field('Nom', cn)), h('button.primary', { onclick: () => { const ip = IP.parse(ci.value.trim()), mk = IP.parseMask(cm.value.trim()); if (ip === null || mk === null || !cs.value) return; R.addClient(ip, mk, cs.value, cn.value.trim() || ci.value.trim()); upd(); } }, 'Ajouter le client')));
  const un = inp('', 'alice'), up = inp('', 'mot de passe'), uv = inp('', 'VLAN (option)');
  root.appendChild(h('fieldset', h('legend', 'Utilisateurs (users)'), h('div.grid2', ui.field('Nom (ou MAC pour MAB)', un), ui.field('Mot de passe', up), ui.field('VLAN dynamique', uv, 'Tunnel-Private-Group-Id')), h('button.primary', { onclick: () => { if (!un.value.trim()) return; R.addUser(un.value.trim(), up.value, { vlan: +uv.value || null }); un.value = up.value = uv.value = ''; upd(); } }, 'Ajouter / modifier')));
  root.appendChild(dyn);
  const upd = () => {
    clear(dyn); const s = R.srv;
    dyn.appendChild(h('h4', 'Clients')); dyn.appendChild(table(['Nom', 'Réseau', 'Secret', ''], s.clients.map((c, i) => [c.name, IP.str(c.ip) + '/' + IP.prefixFromMask(c.mask), c.secret, h('button.small', { onclick: () => { s.clients.splice(i, 1); upd(); } }, '✕')]), 'Aucun client : toute requête sera ignorée.'));
    dyn.appendChild(h('h4', 'Utilisateurs')); dyn.appendChild(table(['Nom', 'Mot de passe', 'VLAN', 'Actif', ''], Array.from(s.users.values()).map(u => [u.name, u.pass, u.vlan || '—', h('input', { type: 'checkbox', checked: !u.disabled, onchange: e => { u.disabled = !e.target.checked; } }), h('button.small', { onclick: () => { s.users.delete(u.name); upd(); } }, '✕')]), 'Aucun utilisateur.'));
    dyn.appendChild(h('div.muted.small', 'Requêtes : ' + s.stats.req + ' · Accept : ' + s.stats.acc + ' · Reject : ' + s.stats.rej + ' · Challenge : ' + s.stats.chal));
    dyn.appendChild(h('h4', 'Journal (/var/log/freeradius/radius.log)')); dyn.appendChild(h('pre.log', { style: 'max-height:150px;overflow:auto;font-size:11px' }, s.log.slice(-14).join('\n')));
  };
  return { el: root, update: (() => { let k = 0; return () => { if (k++ % 3 === 0) upd(); }; })(), init: upd };
}

/* ---------------------------------------------------------------- supplicant 802.1X */
function supplicantTab(app, dev) {
  const D = dev.dot1x, s = D.sup; const root = h('div.form.full'); const u = inp(s.user, 'alice'), p = inp(s.pass, 'mot de passe'), m = sel([['peap', 'PEAP / MSCHAPv2'], ['md5', 'EAP-MD5']], s.method); const st = h('div.mono.small'), lg = h('pre.log', { style: 'max-height:150px;overflow:auto;font-size:11px' });
  root.appendChild(h('p.muted', 'Supplicant 802.1X du poste : il répond aux EAPOL-Start / EAP-Request-Identity envoyés par le switch (authentificateur).'));
  root.appendChild(h('fieldset', h('legend', 'Identifiants'), h('div.grid2', ui.field('Identité', u), ui.field('Mot de passe', p), ui.field('Méthode EAP', m)), h('div.row', h('button.primary', { onclick: () => { D.supSet({ user: u.value.trim(), pass: p.value, method: m.value }); D.supEnable(true); } }, 'Activer / (re)lancer l\'authentification'), h('button', { onclick: () => D.supEnable(false) }, 'Désactiver'))));
  root.appendChild(st); root.appendChild(h('h4', 'Journal du supplicant')); root.appendChild(lg);
  return { el: root, update() { st.textContent = 'État : ' + s.state; lg.textContent = s.log.slice(-15).map(l => '[' + fmtT(l.t) + '] ' + l.msg).join('\n'); } };
}

/* ---------------------------------------------------------------- supervision SNMP / syslog */
function mgmtTab(app, dev) {
  const M = dev.mgmt; const root = h('div.form.full'); const dyn = h('div');
  const cn = inp('', 'public'), cmode = sel([['ro', 'lecture seule (ro)'], ['rw', 'lecture/écriture (rw)']], 'ro'), loc = inp(M.snmp.location, 'Salle serveur'), con = inp(M.snmp.contact, 'admin@lycee.local');
  root.appendChild(h('fieldset', h('legend', 'Agent SNMP (snmpd)'), h('div.row', cn, cmode, h('button.primary', { onclick: () => { if (cn.value.trim()) { M.setCommunity(cn.value.trim(), cmode.value); cn.value = ''; upd(); } } }, 'Ajouter la communauté')), h('div.grid2', ui.field('sysLocation', loc), ui.field('sysContact', con)), h('button', { onclick: () => { M.snmp.location = loc.value; M.snmp.contact = con.value; } }, 'Appliquer')));
  root.appendChild(h('fieldset', h('legend', 'Collecteurs'), h('div.row', chk('Serveur syslog (rsyslog, UDP 514)', M.syslogd.enabled, x => { if (x) M.startSyslogd(); else M.stopSyslogd(); }), chk('Récepteur de traps (snmptrapd, UDP 162)', M.trapd.enabled, x => { if (x) M.startTrapd(); else M.stopTrapd(); }))));
  const tg = inp('', '192.168.1.1'), tc = inp('public', 'public'), to = inp('sysName.0', 'sysName.0'), out = h('pre.log', { style: 'max-height:170px;overflow:auto;font-size:11px' }, '(mini-NMS : interrogez un équipement)');
  const run = (cmd) => { out.textContent = '…'; shellRun(dev, cmd, o => { out.textContent = o; }); };
  root.appendChild(h('fieldset', h('legend', 'Mini-NMS : interroger un agent SNMP'), h('div.grid2', ui.field('Adresse de l\'agent', tg), ui.field('Communauté', tc), ui.field('OID / nom', to)), h('div.row', h('button.primary', { onclick: () => run('snmpget -v2c -c ' + tc.value + ' ' + tg.value + ' ' + to.value) }, 'GET'), h('button', { onclick: () => run('snmpwalk -v2c -c ' + tc.value + ' ' + tg.value + ' ' + (to.value || 'system')) }, 'WALK'), h('button', { onclick: () => run('snmpwalk -v2c -c ' + tc.value + ' ' + tg.value + ' ifDescr') }, 'Interfaces')), out));
  root.appendChild(dyn);
  const upd = () => {
    clear(dyn);
    dyn.appendChild(h('h4', 'Communautés')); dyn.appendChild(table(['Nom', 'Mode', ''], Array.from(M.snmp.comms).map(([n, mo]) => [n, mo, h('button.small', { onclick: () => { M.delCommunity(n); upd(); } }, '✕')]), 'Agent SNMP inactif (aucune communauté).'));
    dyn.appendChild(h('h4', 'Messages syslog reçus')); dyn.appendChild(table(['Heure', 'Source', 'Message'], M.syslogd.entries.slice(-15).reverse().map(e => [fmtT(e.t), e.src, e.msg]), M.syslogd.enabled ? 'Aucun message reçu.' : 'Serveur syslog arrêté.'));
    dyn.appendChild(h('h4', 'Traps reçus')); dyn.appendChild(table(['Heure', 'Source', 'Trap'], M.trapd.entries.slice(-10).reverse().map(e => [fmtT(e.t), e.src, M.trapLine(e).replace(/^.*?\] /, '')]), M.trapd.enabled ? 'Aucun trap reçu.' : 'Récepteur de traps arrêté.'));
  };
  return { el: root, update: (() => { let k = 0; return () => { if (k++ % 3 === 0) upd(); }; })(), init: upd };
}

/* ---------------------------------------------------------------- IPv6 */
function ip6Tab(app, dev) {
  const D = dev.ip6; const root = h('div.form.full'); const dyn = h('div'); const IP6 = NS.IP6; const msgBox = h('div.fmsg');
  const ifs = dev.ifaceList().filter(i => i.port); const isel = sel(ifs.map(i => i.name), ifs[0] && ifs[0].name); const ad = inp('', '2001:db8:1::10/64'), gw = inp('', 'fe80::1 ou 2001:db8:1::1');
  root.appendChild(h('p.muted', 'IPv6 : adresse link-local automatique (EUI-64), auto-configuration SLAAC via les RA du routeur, ou adresse statique.'));
  root.appendChild(h('fieldset', h('legend', 'Configuration'), h('div.grid2', ui.field('Interface', isel), ui.field('Adresse / préfixe', ad)), h('div.row', h('button.primary', { onclick: () => { const i = dev.ifaceByName(isel.value); const m = /^([^\/]+)\/(\d+)$/.exec(ad.value.trim()); const a = m && IP6.parse(m[1]); if (!i || !m || a === null) { msgBox.className = 'fmsg err'; msgBox.textContent = 'Adresse invalide (ex. 2001:db8:1::10/64).'; return; } D.enable(i); D.addAddr(i, a, +m[2], 'manual'); msgBox.className = 'fmsg ok'; msgBox.textContent = 'Adresse ajoutée (DAD en cours).'; upd(); } }, 'Ajouter l\'adresse'), h('button', { onclick: () => { const i = dev.ifaceByName(isel.value); if (i) { D.enable(i); msgBox.className = 'fmsg ok'; msgBox.textContent = 'IPv6 activé (link-local + SLAAC).'; upd(); } } }, 'Activer IPv6 (SLAAC)'), h('button', { onclick: () => { const i = dev.ifaceByName(isel.value); if (i) { D.disable(i); upd(); } } }, 'Désactiver')), h('div.row', ui.field('Passerelle par défaut', gw), h('button', { onclick: () => { const a = IP6.parse(gw.value.trim()); if (a === null) return; const i = dev.ifaceByName(isel.value); D.statics = (D.statics || []).filter(x => !(x.plen === 0)); D.statics.push({ net: 0n, plen: 0, nh: a, iface: IP6.isLinkLocal(a) && i ? i.name : null, ad: 1 }); upd(); } }, 'Définir')), msgBox));
  root.appendChild(dyn);
  const upd = () => {
    clear(dyn); const rows = []; dev.ifaceList().forEach(i => { if (i.v6) i.v6.addrs.forEach(a => rows.push([i.name, IP6.str(a.addr) + '/' + a.plen, a.kind, a.state])); });
    dyn.appendChild(h('h4', 'Adresses IPv6')); dyn.appendChild(table(['Interface', 'Adresse', 'Origine', 'État'], rows, 'IPv6 non activé.'));
    const nb = []; if (D.nc) D.nc.forEach(e => nb.push([e.iface.name, IP6.str(e.addr), e.mac || '—', e.state])); dyn.appendChild(h('h4', 'Voisins (NDP)')); dyn.appendChild(table(['Interface', 'Voisin', 'MAC', 'État'], nb, 'Aucun voisin.'));
  };
  return { el: root, update: (() => { let k = 0; return () => { if (k++ % 3 === 0) upd(); }; })(), init: upd };
}

/* ---------------------------------------------------------------- Suivi (états live des protocoles pour routeur / switch) */
const SUIVI = {
  ios: [['Interfaces (résumé)', 'show ip interface brief'], ['Table de routage', 'show ip route'], ['OSPF : voisins', 'show ip ospf neighbor'], ['OSPF : interfaces', 'show ip ospf interface brief'], ['OSPF : base LSDB', 'show ip ospf database'], ['VPN : ISAKMP SA', 'show crypto isakmp sa'], ['VPN : IPsec SA', 'show crypto ipsec sa'], ['VPN : sessions', 'show crypto session'], ['Tunnels GRE', 'show interfaces tunnel'], ['IPv6 : interfaces', 'show ipv6 interface brief'], ['IPv6 : routes', 'show ipv6 route'], ['IPv6 : voisins', 'show ipv6 neighbors'], ['SNMP', 'show snmp'], ['Journal (syslog)', 'show logging'], ['QoS : policy-map', 'show policy-map interface'], ['RADIUS : serveurs', 'show aaa servers'], ['ACL', 'show access-lists'], ['NAT', 'show ip nat translations']],
  iosSw: [['VLAN', 'show vlan brief'], ['Trunks', 'show interfaces trunk'], ['STP', 'show spanning-tree'], ['STP : résumé', 'show spanning-tree summary'], ['EtherChannel', 'show etherchannel summary'], ['LACP voisins', 'show lacp neighbor'], ['802.1X : ports', 'show dot1x all'], ['Sessions d\'authentification', 'show authentication sessions'], ['RADIUS : serveurs', 'show aaa servers'], ['QoS (mls qos)', 'show mls qos'], ['Voisins CDP', 'show cdp neighbors'], ['Table MAC', 'show mac address-table'], ['Journal (syslog)', 'show logging'], ['SNMP', 'show snmp'], ['Port-security', 'show port-security'], ['Table de routage', 'show ip route']],
  aos: [['VLAN', 'show vlan'], ['Interfaces IP', 'show ip interface'], ['Routes', 'show ip routes'], ['Table MAC', 'show mac-learning'], ['Spanning tree', 'show spantree'], ['STP : ports', 'show spantree ports'], ['Agrégats (linkagg)', 'show linkagg'], ['PoE (lanpower)', 'show lanpower 1'], ['État des ports', 'show interfaces status'], ['Système', 'show system'], ['Châssis', 'show chassis'], ['802.1X', 'show 802.1x'], ['Sécurité des ports', 'show port-security']],
};
function suiviTab(app, dev, kind) {
  const list = SUIVI[kind]; const root = h('div.form.full'); const s = sel(list.map(([l, c]) => [c, l]), list[0][1]); const out = h('pre.log', { style: 'flex:1;min-height:300px;max-height:none;overflow:auto;font-size:11.5px;white-space:pre' }); const cmdTxt = h('span.mono.muted.small');
  const run = () => { const ses = dev.newSession(); if (kind !== 'aos') { ses.mode = 'priv'; } let o = ''; try { ses.exec(s.value, { print: t => { o += t; }, done() { }, clear() { } }); } catch (e) { o = 'Erreur : ' + e.message; } out.textContent = o || '(aucune sortie)'; cmdTxt.textContent = (kind === 'aos' ? '-> ' : dev.name + '# ') + s.value; };
  s.addEventListener('change', run); root.appendChild(h('div.row', ui.field('Vue', s), cmdTxt)); root.appendChild(out); root.appendChild(h('div.muted.small', 'État en direct (rafraîchi automatiquement). La configuration se fait dans la console (CLI).'));
  return { el: root, update: run, init: run };
}

NS.extraTabs = function (app, dev, m, add) {
  const kind = m.kind;
  if (kind === 'host') {
    add('voip', m.phone ? 'Téléphone (SIP)' : 'Téléphonie', () => voipTab(app, dev));
    if (m.server) { add('pbx', 'PBX (Asterisk)', () => pbxTab(app, dev)); add('rad', 'RADIUS', () => radiusTab(app, dev)); }
    if (!m.peripheral) add('sup', '802.1X', () => supplicantTab(app, dev));
    add('mgmt', 'Supervision', () => mgmtTab(app, dev));
    if (!m.peripheral || m.phone) add('ip6', 'IPv6', () => ip6Tab(app, dev));
  } else if (kind === 'router') add('suivi', 'Suivi', () => suiviTab(app, dev, 'ios'));
  else if (kind === 'switch' && dev.managed) add('suivi', 'Suivi', () => suiviTab(app, dev, m.aos ? 'aos' : 'iosSw'));
};
})(typeof window !== 'undefined' ? window : globalThis);
