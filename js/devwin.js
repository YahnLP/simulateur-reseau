/* devwin.js — fenêtres d'équipements : configuration graphique, terminal, services, navigateur, fiche technique */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { h, clear, ui, IP } = NS;

const inp = (v, ph, extra) => h('input', Object.assign({ type: 'text', value: v === undefined || v === null ? '' : v, placeholder: ph || '', spellcheck: 'false' }, extra || {}));
const sel = (opts, v) => { const s = h('select', opts.map(o => { const [val, lab] = Array.isArray(o) ? o : [o, o]; return h('option', { value: val, selected: String(val) === String(v) }, lab); })); s.value = v; return s; };
const chk = (label, v, fn) => { const c = h('input', { type: 'checkbox', checked: !!v }); if (fn) c.addEventListener('change', () => fn(c.checked)); return h('label.chk', c, ' ' + label); };
const ipStr = n => (n ? IP.str(n) : '');
const msg = (root, text, ok) => { const m = root.querySelector('.fmsg') || root.appendChild(h('div.fmsg')); m.className = 'fmsg ' + (ok ? 'ok' : 'err'); m.textContent = text; };
const parseIpList = s => String(s || '').split(/[\s,;]+/).filter(Boolean).map(x => IP.parse(x));

/* ------------------------------------------------------------------ fiche technique */
function datasheetTab(dev) {
  const m = NS.CATALOG[dev.model]; const root = h('div.sheet');
  root.appendChild(h('div.sheet-head', h('div.sheet-icon', { html: NS.iconSvg(m.icon, m.cat, 56) }), h('div', h('h2', m.label), h('div.muted', m.vendor + ' · ' + m.cat))));
  root.appendChild(m.ok ? h('div.badge.ok', '✔ Caractéristiques relevées sur la fiche du constructeur') : h('div.badge.warn', '≈ Valeurs typiques ou indicatives — à vérifier sur la fiche du produit réellement utilisé'));
  if (m.source) root.appendChild(h('div.muted.small', 'Source : ' + m.source));
  root.appendChild(h('table.specs', m.specs.map(s => h('tr', h('th', s[0]), h('td', s[1])))));
  if (m.tags) root.appendChild(h('div.chips', m.tags.map(t => h('span.chip', t))));
  const pt = h('table.ports', h('tr', h('th', 'Port'), h('th', 'Débit'), h('th', 'Adresse MAC'), h('th', 'État'), h('th', 'Relié à')));
  dev.ports.filter(p => !p.virtual).forEach(p => {
    const pe = p.peer;
    pt.appendChild(h('tr', h('td', p.name), h('td', p.speed >= 1000 ? p.speed / 1000 + ' Gb/s' : p.speed + ' Mb/s'), h('td.mono', p.mac), h('td', p.up ? h('span.up', '● actif') : h('span.down', '○ inactif')), h('td', pe ? pe.dev.name + ' ' + pe.short : '—')));
  });
  root.appendChild(h('h3', 'Ports')); root.appendChild(pt);
  return root;
}

/* ------------------------------------------------------------------ poste : configuration IP */
function hostConfigTab(app, dev) {
  const root = h('div.form');
  const rows = [];
  dev.ifaceList().forEach(i => {
    const wifi = i.port && i.port.media === 'wifi';
    const dhcpR = h('input', { type: 'radio', name: 'm' + dev.id + i.name, checked: !!i.dhcp }), statR = h('input', { type: 'radio', name: 'm' + dev.id + i.name, checked: !i.dhcp });
    const ip = inp(!i.dhcp ? ipStr(i.ip) : '', '192.168.1.10'), mask = inp(!i.dhcp && i.mask ? IP.str(i.mask) : '', '255.255.255.0');
    const status = h('div.status.mono');
    const upd = () => { const en = statR.checked; ip.disabled = !en; mask.disabled = !en; };
    dhcpR.addEventListener('change', upd); statR.addEventListener('change', upd); upd();
    root.appendChild(h('fieldset', h('legend', i.name + (wifi ? ' (Wi-Fi)' : '') + '  —  MAC ' + i.mac),
      h('div.row', h('label.chk', dhcpR, ' DHCP'), h('label.chk', statR, ' Statique')),
      h('div.grid2', ui.field('Adresse IPv4', ip), ui.field('Masque', mask, 'ex. 255.255.255.0 ou /24')), status));
    rows.push({ i, dhcpR, ip, mask, status });
  });
  const gw = inp(ipStr(dev.gateway), '192.168.1.1'), dns = inp((dev.dnsServers || []).map(IP.str).join(', '), '8.8.8.8, 1.1.1.1');
  root.appendChild(h('div.grid2', ui.field('Passerelle par défaut', gw), ui.field('Serveurs DNS', dns, 'séparés par des virgules')));
  let ssid, key;
  if (dev.kindModel.wifi) {
    ssid = inp(dev.wifi.ssid, 'LYCEE-WIFI'); key = inp(dev.wifi.key, 'clé WPA2');
    root.appendChild(h('fieldset', h('legend', 'Sans-fil'), h('div.grid2', ui.field('SSID', ssid), ui.field('Clé (WPA2/WPA3)', key))));
  }
  const echo = chk('Répondre aux requêtes ping (pare-feu du poste)', dev.allowIcmpEcho, v => { dev.allowIcmpEcho = v; });
  root.appendChild(echo);
  root.appendChild(h('div.row', h('button.primary', {
    onclick: () => {
      const errs = [];
      rows.forEach(r => {
        if (r.dhcpR.checked) return;
        if (r.ip.value.trim() && IP.parse(r.ip.value) === null) errs.push('Adresse IP invalide : ' + r.ip.value);
        if (r.ip.value.trim() && (!r.mask.value.trim() || IP.parseMask(r.mask.value) === null)) errs.push('Masque invalide : ' + r.mask.value);
      });
      if (gw.value.trim() && IP.parse(gw.value) === null) errs.push('Passerelle invalide');
      if (parseIpList(dns.value).some(x => x === null)) errs.push('Serveur DNS invalide');
      if (errs.length) { msg(root, errs[0], false); return; }
      rows.forEach(r => dev.applyIp(r.i.name, r.dhcpR.checked ? { dhcp: true } : { ip: r.ip.value.trim(), mask: r.mask.value.trim() }));
      const anyDhcp = rows.some(r => r.dhcpR.checked);
      if (gw.value.trim() || !anyDhcp) dev.setGateway(gw.value.trim());
      if (dns.value.trim() || !anyDhcp) { dev.dnsServers = parseIpList(dns.value); dev.dhcpDns = false; }
      if (ssid) { dev.wifi = { ssid: ssid.value.trim(), key: key.value }; NS.wifiRefresh(app.sim); }
      msg(root, 'Configuration appliquée.', true); app.refresh();
    },
  }, 'Appliquer')));
  root.appendChild(h('div.fmsg'));
  return { el: root, update() { rows.forEach(r => { const i = r.i; r.status.textContent = 'État : ' + (i.isUp() ? 'lien actif' : 'lien inactif') + (i.ip ? ' — IP effective ' + IP.str(i.ip) + ' / ' + IP.prefixFromMask(i.mask) + (i.dhcp ? '  (DHCP : ' + (i.dhcpLeased ? 'bail obtenu' : 'en attente') + ')' : '') : (i.dhcp ? ' — DHCP en cours…' : ' — non configuré')); }); } };
}

/* ------------------------------------------------------------------ serveur : services */
function poolForm(dev, refresh) {
  const d = dev.dhcpd; const f = {};
  const mk = (k, ph, v) => (f[k] = inp(v || '', ph));
  const form = h('div.grid3', ui.field('Nom du pool', mk('name', 'LAN', 'LAN')), ui.field('Réseau', mk('net', '192.168.1.0')), ui.field('Masque', mk('mask', '255.255.255.0')),
    ui.field('Passerelle', mk('router', '192.168.1.1')), ui.field('DNS', mk('dns', '192.168.1.2')), ui.field('Domaine', mk('domain', 'lycee.local')),
    ui.field('Première adresse', mk('start', '192.168.1.10')), ui.field('Dernière adresse', mk('end', '192.168.1.100')), ui.field('Durée du bail (s)', mk('lease', '86400', '86400')));
  const add = h('button.primary', {
    onclick: () => {
      const net = IP.parse(f.net.value), mask = IP.parseMask(f.mask.value), st = IP.parse(f.start.value), en = IP.parse(f.end.value), rt = f.router.value.trim() ? IP.parse(f.router.value) : 0;
      if (net === null || mask === null || st === null || en === null || rt === null) { ui.toast('Champs réseau/masque/plage invalides', 'err'); return; }
      const dn = parseIpList(f.dns.value); if (dn.some(x => x === null)) { ui.toast('DNS invalide', 'err'); return; }
      if (!IP.inNet(st, net, mask) || !IP.inNet(en, net, mask) || st > en) { ui.toast('La plage doit appartenir au réseau (début ≤ fin)', 'err'); return; }
      d.addPool({ name: f.name.value.trim() || 'POOL', net: IP.net(net, mask), mask, router: rt, dns: dn, domain: f.domain.value.trim(), lease: +f.lease.value || 86400, start: st, end: en });
      refresh(); ui.toast('Pool enregistré', 'ok');
    },
  }, 'Ajouter / remplacer le pool');
  return h('div', form, h('div.row', add));
}
function dhcpServerTab(app, dev) {
  const d = dev.dhcpd; const root = h('div.form'); const list = h('div');
  const exA = inp('', '192.168.1.1'), exB = inp('', '192.168.1.9');
  function render() {
    clear(list);
    list.appendChild(h('table.tbl', h('tr', h('th', 'Pool'), h('th', 'Réseau'), h('th', 'Passerelle'), h('th', 'DNS'), h('th', 'Plage'), h('th', 'Bail'), h('th', '')),
      d.pools.map(p => h('tr', h('td', p.name), h('td', ipStr(p.net) + '/' + IP.prefixFromMask(p.mask)), h('td', ipStr(p.router)), h('td', (p.dns || []).map(IP.str).join(', ')), h('td', ipStr(p.start) + ' → ' + ipStr(p.end)), h('td', p.lease + ' s'), h('td', h('button.small', { onclick: () => { d.pools = d.pools.filter(x => x !== p); render(); } }, '✕'))))));
    if (!d.pools.length) list.appendChild(h('p.muted', 'Aucun pool défini.'));
    list.appendChild(h('h4', 'Adresses exclues'));
    list.appendChild(h('div', d.excluded.map((r, k) => h('span.chip', ipStr(r[0]) + (r[1] !== r[0] ? ' → ' + ipStr(r[1]) : ''), h('button.x', { onclick: () => { d.excluded.splice(k, 1); render(); } }, '×')))));
    list.appendChild(h('div.row', exA, exB, h('button', { onclick: () => { const a = IP.parse(exA.value), b = exB.value.trim() ? IP.parse(exB.value) : a; if (a === null || b === null) return ui.toast('Adresse invalide', 'err'); d.excluded.push([a, b]); render(); } }, 'Exclure')));
    list.appendChild(h('h4', 'Baux actifs'));
    const leases = Array.from(d.leases.entries()).filter(([, l]) => !l.offered);
    list.appendChild(leases.length ? h('table.tbl', h('tr', h('th', 'Adresse MAC'), h('th', 'Adresse IP'), h('th', 'Nom'), h('th', 'Expire dans')), leases.map(([m, l]) => h('tr', h('td.mono', m), h('td', ipStr(l.ip)), h('td', l.host || ''), h('td', Math.max(0, Math.round((l.expires - dev.sim.now) / 1000)) + ' s')))) : h('p.muted', 'Aucun bail.'));
  }
  root.appendChild(chk('Service DHCP activé', d.enabled, v => { d.enabled = v; }));
  root.appendChild(poolForm(dev, render)); root.appendChild(list); render();
  return { el: root, update: render };
}
function dnsServerTab(app, dev) {
  const d = dev.dnsd; const root = h('div.form'); const list = h('div');
  const nm = inp('', 'www.lycee.local'), ty = sel(['A', 'CNAME', 'MX', 'PTR', 'NS', 'TXT'], 'A'), da = inp('', '192.168.1.10'), pr = inp('10', 'préf.', { style: { width: '60px' } });
  const fw = inp((d.forwarders || []).map(IP.str).join(', '), '8.8.8.8');
  function render() {
    clear(list);
    list.appendChild(h('table.tbl', h('tr', h('th', 'Nom'), h('th', 'Type'), h('th', 'Valeur'), h('th', '')), d.records.map(r => h('tr', h('td', r.name), h('td', r.type), h('td', (r.pref !== undefined && r.type === 'MX' ? r.pref + ' ' : '') + r.data), h('td', h('button.small', { onclick: () => { d.records = d.records.filter(x => x !== r); render(); } }, '✕'))))));
    if (!d.records.length) list.appendChild(h('p.muted', 'Zone vide : ajoutez des enregistrements ci-dessous.'));
  }
  root.appendChild(chk('Service DNS activé (UDP 53)', d.enabled, v => { if (v) d.start(); else d.stop(); }));
  root.appendChild(h('div.row', ui.field('Nom', nm), ui.field('Type', ty), ui.field('Valeur', da), ui.field('Préf. (MX)', pr), h('button.primary', { onclick: () => { const n = nm.value.trim().toLowerCase(); if (!n || !da.value.trim()) return ui.toast('Nom et valeur requis', 'err'); if (ty.value === 'A' && IP.parse(da.value) === null) return ui.toast('Adresse IPv4 invalide', 'err'); const r = { name: n, type: ty.value, data: da.value.trim() }; if (ty.value === 'MX') r.pref = +pr.value || 10; d.records.push(r); nm.value = ''; da.value = ''; render(); } }, 'Ajouter')));
  root.appendChild(list); render();
  root.appendChild(h('div.row', ui.field('Redirecteurs (forwarders)', fw), h('button', { onclick: () => { const l = parseIpList(fw.value); if (l.some(x => x === null)) return ui.toast('Adresse invalide', 'err'); d.forwarders = l; ui.toast('Redirecteurs enregistrés', 'ok'); } }, 'Enregistrer')));
  return { el: root, update() { } };
}
function httpServerTab(app, dev) {
  const d = dev.httpd; const root = h('div.form'); let cur = '/';
  const paths = h('select', { size: 5, style: { minWidth: '160px' } }), ta = h('textarea', { rows: 10, spellcheck: 'false', style: { width: '100%', fontFamily: 'monospace' } }), np = inp('', '/page.html');
  function fill() { clear(paths); Object.keys(d.pages).forEach(p => paths.appendChild(h('option', { value: p, selected: p === cur }, p))); ta.value = d.pages[cur] ? d.pages[cur].body : ''; }
  paths.addEventListener('change', () => { cur = paths.value; ta.value = d.pages[cur].body; });
  root.appendChild(h('div.row', chk('Serveur web activé (HTTP 80)', d.enabled, v => { if (v) d.start(); else d.stop(); }), chk('HTTPS (443, TLS simulé)', d.https, v => { d.https = v; if (d.enabled) { d.stop(); d.start(); } })));
  root.appendChild(h('div.row', paths, h('div', { style: { flex: 1 } }, ta)));
  root.appendChild(h('div.row', h('button.primary', { onclick: () => { d.pages[cur] = { type: (d.pages[cur] && d.pages[cur].type) || 'text/html; charset=utf-8', body: ta.value, _custom: true }; ui.toast('Page ' + cur + ' enregistrée', 'ok'); } }, 'Enregistrer la page'), np, h('button', { onclick: () => { let p = np.value.trim(); if (!p) return; if (p[0] !== '/') p = '/' + p; d.pages[p] = { type: 'text/html; charset=utf-8', body: '<html><body><h1>' + p + '</h1></body></html>', _custom: true }; cur = p; np.value = ''; fill(); } }, 'Nouvelle page'), h('button', { onclick: () => { if (cur === '/') return ui.toast('La page d\'accueil ne peut pas être supprimée', 'err'); delete d.pages[cur]; cur = '/'; fill(); } }, 'Supprimer')));
  fill();
  return { el: root, update() { } };
}
function servicesTab(app, dev) {
  const subs = [['dhcp', 'DHCP', dhcpServerTab], ['dns', 'DNS', dnsServerTab], ['http', 'Web (HTTP/HTTPS)', httpServerTab]];
  const box = h('div.subtabs'); const upd = [];
  const t = ui.tabs(subs.map(([id, label, fn]) => ({ id, label, render() { const r = fn(app, dev); upd.length = 0; upd.push(r.update); return r.el; } })));
  box.appendChild(t);
  return { el: box, update() { upd.forEach(f => f && f()); } };
}

/* ------------------------------------------------------------------ navigateur */
function browserTab(app, dev) {
  const url = inp('http://', 'http://serveur.local/'); const frame = h('iframe.bframe', { sandbox: '', title: 'Page web' }); const st = h('div.bstatus.muted', 'Saisissez une adresse et validez.');
  function go() {
    let u = url.value.trim(); if (!u) return; if (!/^https?:\/\//.test(u)) u = 'http://' + u; url.value = u;
    st.textContent = 'Chargement…'; frame.srcdoc = '';
    dev.httpRequest(u, (err, r) => {
      if (err) { const T = { timeout: 'Délai dépassé : le serveur ne répond pas.', refused: 'Connexion refusée (aucun service sur ce port).' }; st.textContent = err.startsWith('dns') ? 'Nom introuvable (erreur DNS).' : (T[err] || 'Erreur : ' + err); frame.srcdoc = '<body style="font-family:sans-serif;color:#555;padding:2em"><h2>Impossible de joindre la page</h2><p>' + NS.esc(st.textContent) + '</p></body>'; return; }
      st.textContent = 'HTTP ' + r.status + ' ' + r.reason + (u.startsWith('https') ? '  🔒 (TLS simulé)' : '  (non chiffré)'); frame.srcdoc = r.body;
    });
  }
  url.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  return h('div.browser', h('div.urlbar', url, h('button.primary', { onclick: go }, 'Aller')), frame, st);
}

/* ------------------------------------------------------------------ routeur / commutateur : CLI + config texte */
const QUICK = {
  aos: [['show vlan', 'show vlan'], ['show ip interface', 'show ip interface'], ['show ip routes', 'show ip routes'], ['show mac-learning', 'show mac-learning'], ['show spantree', 'show spantree'], ['show linkagg', 'show linkagg'], ['show lanpower 1', 'show lanpower 1'], ['show interfaces status', 'show interfaces status'], ['show system', 'show system'], ['write memory', 'write memory']],
  router: [['show ip int br', 'show ip interface brief'], ['show ip route', 'show ip route'], ['show run', 'show running-config'], ['show arp', 'show arp'], ['show access-lists', 'show access-lists'], ['show ip nat trans', 'show ip nat translations'], ['show ip protocols', 'show ip protocols']],
  switch: [['show vlan br', 'show vlan brief'], ['show int trunk', 'show interfaces trunk'], ['show mac addr', 'show mac address-table'], ['show run', 'show running-config'], ['show spanning-tree', 'show spanning-tree'], ['show ip int br', 'show ip interface brief'], ['show port-security', 'show port-security']],
};
function cliTab(app, dev, kind) {
  const t = dev._termApi || (dev._termApi = NS.Terminal(dev));
  const chips = h('div.quick', h('span.muted', 'Raccourcis : '), (QUICK[kind] || QUICK.router).map(([lab, cmd]) => h('button.small', { title: cmd, onclick: () => { const s = t.session; const pre = s.mode === 'user' ? ['enable'] : (s.mode === 'priv' ? [] : ['end']); t.runLines(pre.concat([cmd])); t.focus(); } }, lab)));
  const root = h('div.clitab', chips, t.el); setTimeout(() => t.focus(), 50);
  return root;
}
function configTextTab(app, dev) {
  const ta = h('textarea.cfg', { spellcheck: 'false' }); const root = h('div.form.full');
  const load = () => { ta.value = dev.cliText(false); };
  root.appendChild(h('p.muted', 'Configuration en cours (running-config). Vous pouvez la modifier ou coller une configuration, puis l\'appliquer : les commandes sont rejouées après remise à zéro.'));
  root.appendChild(ta);
  root.appendChild(h('div.row', h('button', { onclick: load }, 'Actualiser'), h('button.primary', { onclick: () => { dev.cliReset(); dev.cliRestore(ta.value); app.refresh(); ui.toast('Configuration appliquée', 'ok'); load(); } }, 'Appliquer'), h('button', { onclick: () => { dev.startup = dev.cliText(true); ui.toast('Enregistrée dans la startup-config', 'ok'); } }, 'Enregistrer (write memory)'),
    h('button', { onclick: () => { const b = new Blob([ta.value], { type: 'text/plain' }); const a = h('a', { href: URL.createObjectURL(b), download: dev.name + '-config.txt' }); a.click(); } }, 'Exporter .txt')));
  load(); return root;
}

/* ------------------------------------------------------------------ pare-feu */
function fwInterfacesTab(app, dev) {
  const root = h('div.form'); const rows = [];
  const zones = ['LAN', 'WAN', 'DMZ', 'DMZ2'];
  dev.ifaceList().forEach(i => {
    const dh = chk('DHCP', i.dhcp), ip = inp(i.dhcp ? '' : ipStr(i.ip)), mk = inp(i.dhcp || !i.mask ? '' : IP.str(i.mask)), z = sel(zones, i.zone), up = chk('Actif', i.adminUp !== false);
    const st = h('span.mono.muted');
    root.appendChild(h('fieldset', h('legend', i.name), h('div.grid4', ui.field('Zone', z), ui.field('Adresse IPv4', ip), ui.field('Masque', mk), h('div', dh, up)), st));
    rows.push({ i, dh, ip, mk, z, up, st });
  });
  const gws = dev.statics.find(x => x.net === 0 && x.mask === 0 && !x.dhcp); const gw = inp(gws ? IP.str(gws.nh) : '', '203.0.113.1');
  root.appendChild(h('div.grid4', ui.field('Passerelle par défaut (vers Internet)', gw, 'vide si fournie par DHCP')));
  root.appendChild(h('div.row', chk('Répondre au ping depuis le WAN', dev.wanPing, v => { dev.wanPing = v; }), h('button.primary', { onclick: () => {
    if (gw.value.trim() && IP.parse(gw.value) === null) return msg(root, 'Passerelle invalide', false);
    if (gw.value.trim() || gws) { dev.statics = dev.statics.filter(x => !(x.net === 0 && x.mask === 0 && !x.dhcp)); if (gw.value.trim()) dev.statics.push({ net: 0, mask: 0, nh: IP.parse(gw.value), iface: null, ad: 1 }); }
    for (const r of rows) { const dhc = r.dh.querySelector('input').checked; if (!dhc && r.ip.value.trim() && (IP.parse(r.ip.value) === null || IP.parseMask(r.mk.value) === null)) return msg(root, 'Adresse/masque invalides sur ' + r.i.name, false); }
    rows.forEach(r => { const i = r.i; i.zone = r.z.value; i.adminUp = r.up.querySelector('input').checked; if (i.port) i.port.adminUp = i.adminUp; const dhc = r.dh.querySelector('input').checked; if (dhc) dev.enableDhcp(i, true); else { dev.enableDhcp(i, false); i.ip = r.ip.value.trim() ? IP.parse(r.ip.value) : 0; i.mask = r.mk.value.trim() ? IP.parseMask(r.mk.value) : 0; if (i.ip) dev.arpAnnounce && dev.arpAnnounce(i); } dev.sim.portChanged(i.port); });
    dev.rebuildNat(); msg(root, 'Interfaces appliquées.', true); app.refresh();
  } }, 'Appliquer')));
  root.appendChild(h('div.fmsg'));
  return { el: root, update() { rows.forEach(r => { r.st.textContent = (r.i.isUp() ? '● lien actif' : '○ lien inactif') + (r.i.ip ? '  IP effective ' + IP.str(r.i.ip) + '/' + IP.prefixFromMask(r.i.mask) : ''); }); } };
}
function fwRulesTab(app, dev) {
  const root = h('div.form'); const box = h('div');
  const zones = ['any', 'LAN', 'WAN', 'DMZ', 'DMZ2'];
  const f = { action: sel([['pass', 'Autoriser'], ['block', 'Bloquer'], ['reject', 'Rejeter']], 'pass'), from: sel(zones, 'LAN'), to: sel(zones, 'WAN'), proto: sel(['any', 'tcp', 'udp', 'icmp'], 'tcp'), src: inp('any'), dst: inp('any'), dport: inp('80,443'), comment: inp('', 'commentaire') };
  function render() {
    clear(box);
    const t = h('table.tbl', h('tr', h('th', '#'), h('th', 'On'), h('th', 'Action'), h('th', 'Source zone'), h('th', 'Dest. zone'), h('th', 'Proto'), h('th', 'IP src'), h('th', 'IP dst'), h('th', 'Port dst'), h('th', 'Commentaire'), h('th', 'Hits'), h('th', '')));
    dev.rules.forEach((r, k) => t.appendChild(h('tr', { class: r.on ? '' : 'off' }, h('td', k + 1), h('td', h('input', { type: 'checkbox', checked: r.on, onchange: e => { r.on = e.target.checked; render(); } })),
      h('td', h('span.act.' + r.action, r.action === 'pass' ? 'Autoriser' : r.action === 'block' ? 'Bloquer' : 'Rejeter')), h('td', r.from), h('td', r.to), h('td', r.proto), h('td', r.src), h('td', r.dst), h('td', r.dport), h('td', r.comment || ''), h('td', r.hits || 0),
      h('td.nowrap', h('button.small', { title: 'Monter', onclick: () => { if (k > 0) { [dev.rules[k - 1], dev.rules[k]] = [dev.rules[k], dev.rules[k - 1]]; render(); } } }, '↑'), h('button.small', { title: 'Descendre', onclick: () => { if (k < dev.rules.length - 1) { [dev.rules[k + 1], dev.rules[k]] = [dev.rules[k], dev.rules[k + 1]]; render(); } } }, '↓'), h('button.small', { onclick: () => { dev.rules.splice(k, 1); render(); } }, '✕')))));
    t.appendChild(h('tr.dflt', h('td', '∞'), h('td'), h('td', h('span.act.block', 'Bloquer')), h('td', 'any'), h('td', 'any'), h('td', 'any'), h('td', 'any'), h('td', 'any'), h('td', 'any'), h('td', 'Politique par défaut (implicite)'), h('td'), h('td')));
    box.appendChild(t);
  }
  root.appendChild(h('p.muted', 'Les règles sont évaluées dans l\'ordre, de haut en bas ; la première qui correspond s\'applique. Le pare-feu est à états : le trafic retour d\'une connexion autorisée est accepté automatiquement.'));
  root.appendChild(box); render();
  root.appendChild(h('fieldset', h('legend', 'Nouvelle règle'), h('div.grid4', ui.field('Action', f.action), ui.field('Zone source', f.from), ui.field('Zone destination', f.to), ui.field('Protocole', f.proto), ui.field('IP/réseau source', f.src, 'any ou 10.0.0.0/24'), ui.field('IP/réseau destination', f.dst), ui.field('Port(s) destination', f.dport, 'ex. 80,443 ou 1000-2000'), ui.field('Commentaire', f.comment)),
    h('div.row', h('button.primary', { onclick: () => { const c = s => s.value.trim() || 'any'; for (const k of ['src', 'dst']) { const v = c(f[k]); if (v !== 'any' && IP.parseCidr(v.indexOf('/') < 0 ? v + '/32' : v) === null) return ui.toast('Adresse ou réseau invalide : ' + v, 'err'); } dev.rules.push({ on: true, action: f.action.value, from: f.from.value, to: f.to.value, proto: f.proto.value, src: c(f.src), dst: c(f.dst), dport: f.proto.value === 'icmp' ? 'any' : c(f.dport), comment: f.comment.value }); render(); } }, 'Ajouter en fin de liste'), h('button', { onclick: () => { dev.rules = []; render(); } }, 'Tout effacer'), h('button', { onclick: () => { dev.defaultPolicy(); render(); } }, 'Politique par défaut'))));
  return { el: root, update() { } };
}
function fwNatTab(app, dev) {
  const root = h('div.form'); const box = h('div');
  const zones = ['LAN', 'WAN', 'DMZ', 'DMZ2']; const a = sel(zones, 'LAN'), b = sel(zones, 'WAN');
  const pr = sel(['tcp', 'udp'], 'tcp'), pp = inp('80', '80', { style: { width: '80px' } }), ti = inp('', '172.16.0.10'), tp = inp('', 'idem', { style: { width: '80px' } });
  function render() {
    clear(box);
    box.appendChild(h('h4', 'Translation d\'adresses (masquerade / PAT)'));
    box.appendChild(h('table.tbl', h('tr', h('th', 'Zone interne'), h('th', 'Zone externe'), h('th', '')), dev.natMasq.map((r, k) => h('tr', h('td', r.from), h('td', r.to), h('td', h('button.small', { onclick: () => { dev.natMasq.splice(k, 1); dev.rebuildNat(); render(); } }, '✕'))))));
    box.appendChild(h('div.row', a, '→', b, h('button', { onclick: () => { dev.natMasq.push({ from: a.value, to: b.value }); dev.rebuildNat(); render(); } }, 'Ajouter')));
    box.appendChild(h('h4', 'Redirections de ports (DNAT / port-forwarding)'));
    box.appendChild(h('table.tbl', h('tr', h('th', 'Proto'), h('th', 'Port externe'), h('th', 'Vers'), h('th', 'Port interne'), h('th', '')), dev.forwards.map((f, k) => h('tr', h('td', f.proto), h('td', f.port), h('td', f.toIp), h('td', f.toPort || f.port), h('td', h('button.small', { onclick: () => { dev.forwards.splice(k, 1); dev.rebuildNat(); render(); } }, '✕'))))));
    box.appendChild(h('div.row', pr, pp, '→', ti, tp, h('button.primary', { onclick: () => { if (IP.parse(ti.value) === null || !+pp.value) return ui.toast('Adresse ou port invalide', 'err'); dev.forwards.push({ proto: pr.value, port: +pp.value, toIp: ti.value.trim(), toPort: +tp.value || +pp.value }); dev.rebuildNat(); render(); ui.toast('N\'oubliez pas la règle de filtrage WAN → zone de destination', 'warn', 5000); } }, 'Ajouter')));
  }
  render(); root.appendChild(box); return { el: root, update() { } };
}
function fwLogTab(app, dev) {
  const root = h('div.form.full'); const box = h('div.logbox');
  const st = h('div.muted');
  function update() {
    st.textContent = 'Sessions suivies : ' + dev.sessions.size + ' — événements : ' + dev.fwlog.length;
    clear(box); box.appendChild(h('table.tbl', h('tr', h('th', 't (s)'), h('th', 'Action'), h('th', 'Proto'), h('th', 'Source'), h('th', 'Destination'), h('th', 'Zones'), h('th', 'Motif')), dev.fwlog.slice(-120).reverse().map(e => h('tr', h('td', (e.t / 1000).toFixed(3)), h('td', h('span.act.' + (e.action === 'pass' ? 'pass' : 'block'), e.action)), h('td', e.proto), h('td', e.src + (e.sport !== '' ? ':' + e.sport : '')), h('td', e.dst + (e.dport !== '' ? ':' + e.dport : '')), h('td', e.zin + ' → ' + e.zout), h('td', e.why)))));
  }
  root.appendChild(h('div.row', st, h('button', { onclick: () => { dev.fwlog.length = 0; dev.sessions.clear(); update(); } }, 'Vider'))); root.appendChild(box); update();
  return { el: root, update };
}
function diagTab(app, dev) {
  const root = h('div.form.full'); const dst = inp('', '192.168.1.10'), out = h('pre.tout.small'); let ab = false;
  const run = () => {
    const ip = IP.parse(dst.value); if (ip === null) return ui.toast('Adresse invalide', 'err'); out.textContent = 'PING ' + IP.str(ip) + '\n'; ab = false;
    NS.tools.pingSeries(dev, ip, { count: 4, interval: 1000, abort: () => ab }, (r, seq) => { out.textContent += (r.type === 'reply' ? 'Réponse de ' + IP.str(r.from || ip) + ' : seq=' + seq + ' temps=' + Math.max(0.1, r.rtt).toFixed(2) + ' ms' : r.type === 'timeout' ? 'Délai dépassé (seq=' + seq + ')' : 'Erreur : ' + r.type) + '\n'; }, () => { out.textContent += 'Terminé.\n'; });
  };
  root.appendChild(h('div.row', ui.field('Ping depuis l\'équipement vers', dst), h('button.primary', { onclick: run }, 'Ping'), h('button', { onclick: () => { ab = true; } }, 'Stop'))); root.appendChild(out);
  return { el: root, update() { } };
}

/* ------------------------------------------------------------------ box */
function boxTab(app, dev) {
  const root = h('div.form'); const lan = dev.ifaces.get('Vlan1'), wan = dev.ifaces.get('WAN'); const pool = dev.dhcpd.pools[0];
  const lip = inp(ipStr(lan.ip)), lmk = inp(IP.str(lan.mask)), ds = inp(pool ? ipStr(pool.start) : ''), de = inp(pool ? ipStr(pool.end) : '');
  const wd = chk('WAN en DHCP (fourni par le FAI)', wan.dhcp); const wi = inp(wan.dhcp ? '' : ipStr(wan.ip)), wm = inp(wan.dhcp ? '' : ipStr(wan.mask)), wg = inp('');
  root.appendChild(h('fieldset', h('legend', 'Réseau local (LAN)'), h('div.grid2', ui.field('Adresse de la box', lip), ui.field('Masque', lmk), ui.field('DHCP : première adresse', ds), ui.field('DHCP : dernière adresse', de))));
  root.appendChild(h('fieldset', h('legend', 'Accès Internet (WAN)'), wd, h('div.grid3', ui.field('IP WAN', wi), ui.field('Masque', wm), ui.field('Passerelle', wg))));
  root.appendChild(h('div.row', chk('DHCP activé', dev.dhcpd.enabled, v => { dev.dhcpd.enabled = v; }), h('button.primary', { onclick: () => {
    const a = IP.parse(lip.value), m = IP.parseMask(lmk.value), s = IP.parse(ds.value), e = IP.parse(de.value);
    if (a === null || m === null || s === null || e === null || !IP.inNet(s, a, m) || !IP.inNet(e, a, m)) return msg(root, 'Paramètres LAN invalides (la plage DHCP doit être dans le réseau).', false);
    lan.ip = a; lan.mask = m; if (pool) Object.assign(pool, { net: IP.net(a, m), mask: m, router: a, dns: [a], start: s, end: e });
    const dc = wd.querySelector('input').checked;
    if (dc) dev.enableDhcp(wan, true); else { const x = IP.parse(wi.value), y = IP.parseMask(wm.value); if (x === null || y === null) return msg(root, 'IP/masque WAN invalides', false); dev.enableDhcp(wan, false); wan.ip = x; wan.mask = y; dev.statics = dev.statics.filter(r => !(r.net === 0 && r.mask === 0)); const gw = IP.parse(wg.value); if (gw) dev.statics.push({ net: 0, mask: 0, nh: gw, iface: null, ad: 1 }); }
    msg(root, 'Configuration appliquée.', true); app.refresh();
  } }, 'Appliquer')));
  root.appendChild(h('div.fmsg'));
  return { el: root, update() { } };
}
function apTab(app, dev) {
  const root = h('div.form'); const ssid = inp(dev.ssid), key = inp(dev.key), sec = sel(['WPA2', 'WPA3', 'Ouvert'], dev.security); const clients = h('div');
  root.appendChild(h('div.grid3', ui.field('SSID', ssid), ui.field('Clé', key), ui.field('Sécurité', sec)));
  root.appendChild(h('div.row', h('button.primary', { onclick: () => { dev.ssid = ssid.value.trim() || 'WIFI'; dev.key = key.value; dev.security = sec.value; NS.wifiRefresh(app.sim); ui.toast('Borne configurée', 'ok'); app.refresh(); } }, 'Appliquer')));
  root.appendChild(h('p.muted', 'Un portable s\'associe automatiquement lorsque son SSID et sa clé correspondent (à saisir dans sa fenêtre de configuration).'));
  root.appendChild(h('h4', 'Clients associés')); root.appendChild(clients);
  return { el: root, update() { clear(clients); const cl = dev.ports.filter(p => p.virtual && p.peer); clients.appendChild(cl.length ? h('ul', cl.map(p => h('li', p.peer.dev.name + ' — ' + p.peer.mac))) : h('p.muted', 'Aucun client.')); } };
}
function switchInfoTab(app, dev) {
  const root = h('div.form.full'); const box = h('div');
  return { el: h('div.form.full', h('p.muted', 'Table d\'adresses MAC apprises (mise à jour en direct) :'), box), update() { clear(box); const rows = Array.from(dev.macTable.entries()); box.appendChild(rows.length ? h('table.tbl', h('tr', h('th', 'VLAN'), h('th', 'Adresse MAC'), h('th', 'Port')), rows.map(([k, e]) => h('tr', h('td', k.split('|')[0]), h('td.mono', k.split('|')[1]), h('td', e.port.name)))) : h('p.muted', 'Table vide.')); } };
}

/* ------------------------------------------------------------------ ouverture */
NS.openDevice = function (app, dev, first) {
  const m = NS.CATALOG[dev.model]; const kind = m.kind;
  const w = ui.openWindow({ id: 'dev-' + dev.id, title: dev.name + ' — ' + m.label, w: kind === 'firewall' ? 780 : 640, h: 470 });
  const live = []; let timer = null;
  const wrap = (fn) => ({ id: fn.id, label: fn.label, render() { const r = fn.make(); if (r.init) r.init(); if (r.update) { live.length = 0; live.push(r.update); r.update(); } else live.length = 0; return r.el || r; } });
  const defs = [];
  const add = (id, label, make) => defs.push(wrap({ id, label, make }));
  if (kind === 'host') {
    add('term', 'Terminal', () => { const t = dev._termApi || (dev._termApi = NS.Terminal(dev)); setTimeout(() => t.focus(), 30); return { el: h('div.clitab', t.el) }; });
    add('conf', 'Configuration IP', () => hostConfigTab(app, dev));
    if (!m.peripheral) add('web', 'Navigateur', () => ({ el: browserTab(app, dev) }));
    if (m.server) add('svc', 'Services', () => servicesTab(app, dev));
  } else if (kind === 'router') {
    add('cli', 'Console (CLI)', () => ({ el: cliTab(app, dev, 'router') })); add('cfg', 'Configuration', () => ({ el: configTextTab(app, dev) }));
  } else if (kind === 'switch') {
    if (dev.managed) { add('cli', 'Console (CLI)', () => ({ el: cliTab(app, dev, m.aos ? 'aos' : 'switch') })); add('cfg', 'Configuration', () => ({ el: configTextTab(app, dev) })); }
    add('mac', 'Table MAC', () => switchInfoTab(app, dev));
  } else if (kind === 'hub') {
    add('info', 'Fonctionnement', () => ({ el: h('div.form', h('p', 'Un concentrateur (hub) répète chaque trame reçue sur tous les autres ports : tous les postes voient tout le trafic. Utilisez l\'analyseur de trames sur une liaison pour le constater, puis comparez avec un switch.')) }));
  } else if (kind === 'box') {
    add('box', 'Configuration', () => boxTab(app, dev)); add('cli', 'Console (CLI)', () => ({ el: cliTab(app, dev, 'switch') }));
  } else if (kind === 'firewall') {
    add('if', 'Interfaces', () => fwInterfacesTab(app, dev)); add('rules', 'Règles de filtrage', () => fwRulesTab(app, dev)); add('nat', 'NAT / redirections', () => fwNatTab(app, dev)); add('log', 'Journal', () => fwLogTab(app, dev)); add('diag', 'Diagnostic', () => diagTab(app, dev));
  } else if (kind === 'ap') {
    add('wifi', 'Wi-Fi', () => apTab(app, dev));
  }
  if (NS.extraTabs) NS.extraTabs(app, dev, m, add);
  add('sheet', 'Fiche technique', () => ({ el: datasheetTab(dev) }));
  const t = ui.tabs(defs, { first: first && defs.find(d => d.id === first) ? first : defs[0].id });
  clear(w.body).appendChild(t);
  timer = setInterval(() => live.forEach(f => f && f()), 900);
  const oc = w.onClose; w.onClose = () => { clearInterval(timer); if (oc) oc(); };
  return w;
};
})(typeof window !== 'undefined' ? window : globalThis);
