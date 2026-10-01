/* wireshark.js — interface de l'analyseur de trames intégré (liste, détail, hexdump, filtres, flux TCP, stats, pcap) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { h, clear, ui } = NS; const A = NS.Analyzer;
const ROW = 20;

NS.createAnalyzerUI = function (app, host) {
  const sim = app.sim;
  let ctx = A.newCtx(), capturing = true, frozenAt = Infinity, linkSel = 'all', filterFn = null, filterSrc = '', auto = true, selNo = null, dirty = true, rows = [], scanned = 0;
  let selRec = null, selSum = null, hlRange = null;

  /* ---------- barre d'outils ---------- */
  const btnCap = h('button.cap', { title: 'Démarrer / arrêter la capture', onclick: () => { capturing = !capturing; frozenAt = capturing ? Infinity : sim.capNo; if (capturing) { scanned = 0; rows = []; } upd(); mark(); } });
  const linkSelect = h('select', { title: 'Point de capture', 'aria-label': 'Point de capture', onchange: () => { linkSel = linkSelect.value; reset(); } });
  const fin = h('input.filter', { type: 'text', placeholder: 'Filtre d\'affichage — ex. ip.addr == 10.0.0.1 && tcp.port == 80', spellcheck: 'false', 'aria-label': 'Filtre d\'affichage', list: 'wsfilters' });
  const fmsg = h('span.fmsgw');
  const presets = h('datalist#wsfilters', ['arp', 'icmp', 'dns', 'dhcp', 'http', 'tls', 'ssh', 'telnet', 'stp', 'rip', 'ospf', 'snmp', 'syslog', 'lacp', 'gre', 'esp', 'isakmp', 'sip', 'rtp', 'cdp', 'ip.dsfield.dscp == 46', 'sip.method == "INVITE"', 'radius', 'eapol', 'eap', 'eap.type == 4', 'radius.code == 3', 'tcp.flags.syn == 1', 'tcp.flags.syn == 1 && tcp.flags.ack == 0', 'tcp.flags.reset == 1', 'ip.addr == 192.168.1.0/24', 'icmp.type == 8', 'icmp.type == 0', 'dns.qry.name contains "lycee"', 'http.request.method == "GET"', 'not arp and not stp', 'vlan.id == 10', 'eth.addr == ff:ff:ff:ff:ff:ff', 'tcp.port in {80 443 22 23}', 'udp.port == 67 || udp.port == 68', 'frame contains "password"'].map(v => h('option', { value: v })));
  function applyFilter() {
    const v = fin.value.trim();
    try { filterFn = A.compile(v); filterSrc = v; fin.classList.toggle('ok', !!v); fin.classList.remove('err'); fmsg.textContent = ''; }
    catch (e) { fin.classList.add('err'); fin.classList.remove('ok'); fmsg.textContent = e.message; return; }
    reset();
  }
  fin.addEventListener('input', () => { const v = fin.value.trim(); try { A.compile(v); fin.classList.toggle('ok', !!v); fin.classList.remove('err'); fmsg.textContent = ''; } catch (e) { fin.classList.add('err'); fin.classList.remove('ok'); fmsg.textContent = e.message; } });
  fin.addEventListener('keydown', e => { if (e.key === 'Enter') applyFilter(); });
  const autoChk = h('input', { type: 'checkbox', checked: true, onchange: e => { auto = e.target.checked; } });
  const counts = h('span.counts');
  const bar = h('div.wsbar',
    btnCap, h('label.inl', 'Capture sur ', linkSelect), h('button', { title: 'Effacer les paquets capturés', onclick: () => clearAll() }, 'Effacer'),
    h('span.fwrap', fin, presets), h('button', { onclick: applyFilter }, 'Appliquer'), h('button', { onclick: () => { fin.value = ''; applyFilter(); } }, '✕'), fmsg,
    h('span.spacer'), h('label.inl', autoChk, ' Défilement auto'), h('button', { title: 'Suivre le flux TCP du paquet sélectionné', onclick: () => followSel() }, 'Suivre le flux TCP'), h('button', { onclick: () => stats() }, 'Statistiques'), h('button', { onclick: () => exportPcap() }, 'Exporter .pcap'), counts);

  /* ---------- liste de paquets (défilement virtuel) ---------- */
  const head = h('div.wshead');
  const inner = h('div.wsinner'); const list = h('div.wslist', { tabindex: '0', role: 'listbox', 'aria-label': 'Liste des paquets', onscroll: () => drawRows() }, inner);
  const cols = () => (linkSel === 'all' ? [['No.', 56], ['Temps', 92], ['Trajet', 120], ['Source', 130], ['Destination', 130], ['Protocole', 74], ['Long.', 54], ['Info', 0]] : [['No.', 56], ['Temps', 92], ['Source', 130], ['Destination', 130], ['Protocole', 74], ['Long.', 54], ['Info', 0]]);
  function setHead() { clear(head); const c = cols(); const tpl = c.map(x => x[1] ? x[1] + 'px' : '1fr').join(' '); head.style.gridTemplateColumns = tpl; inner.style.setProperty('--cols', tpl); c.forEach(x => head.appendChild(h('div', x[0]))); }
  const pathOf = r => r.from.dev.name + ' → ' + (r.from.peer ? r.from.peer.dev.name : '?');
  function drawRows() {
    const top = list.scrollTop, hgt = list.clientHeight || 200;
    const i0 = Math.max(0, Math.floor(top / ROW) - 3), i1 = Math.min(rows.length, Math.ceil((top + hgt) / ROW) + 3);
    inner.style.height = rows.length * ROW + 'px'; clear(inner);
    const t0 = rows.length ? rows[0].t : 0;
    for (let i = i0; i < i1; i++) {
      const s = rows[i]; const c = s.color;
      const cells = [s.no, ((s.t - t0) / 1000).toFixed(6)];
      if (linkSel === 'all') cells.push(pathOf(s.rec));
      cells.push(s.src, s.dst, s.proto, s.len, s.info);
      inner.appendChild(h('div.wsrow' + (s.no === selNo ? '.sel' : ''), { style: { top: i * ROW + 'px', background: s.no === selNo ? '' : c[0], color: s.no === selNo ? '' : c[1] }, role: 'option', onclick: () => select(s) }, cells.map(x => h('div', String(x)))));
    }
  }
  /* ---------- détail + hexdump ---------- */
  const tree = h('div.wstree', { role: 'tree', 'aria-label': 'Détail du paquet' }), hex = h('div.wshex', { 'aria-label': 'Octets' });
  function drawTree(nodes) {
    clear(tree);
    const build = (n, depth, host, expand) => {
      const has = n.ch && n.ch.length; const row = h('div.tn', { style: { paddingLeft: depth * 16 + 'px' }, role: 'treeitem' }); let open = expand; let kids = null;
      const tog = h('span.tog', has ? (open ? '▾' : '▸') : ' ');
      row.appendChild(tog); row.appendChild(h('span.tt', n.t));
      row.addEventListener('click', e => { e.stopPropagation(); tree.querySelectorAll('.tn.on').forEach(x => x.classList.remove('on')); row.classList.add('on'); hlRange = n.len ? [n.off, n.off + n.len] : null; drawHex(); if (has) { open = !open; tog.textContent = open ? '▾' : '▸'; kids.style.display = open ? '' : 'none'; } });
      host.appendChild(row);
      if (has) { kids = h('div.tk', { style: { display: open ? '' : 'none' } }); n.ch.forEach(c => build(c, depth + 1, kids, false)); host.appendChild(kids); }
    };
    nodes.forEach((n, i) => build(n, 0, tree, i === nodes.length - 1 && n.layer !== 'frame' || i === nodes.length - 1));
  }
  function drawHex() {
    clear(hex); if (!selRec) return; const u = selRec.bytes, rs = A.hexRows(u);
    rs.forEach(r => {
      const hx = h('span.hx'), as = h('span.as');
      r.bytes.forEach((b, j) => { const idx = r.off + j; const on = hlRange && idx >= hlRange[0] && idx < hlRange[1]; hx.appendChild(h('span' + (on ? '.hl' : ''), (b < 16 ? '0' : '') + b.toString(16) + (j === 7 ? '  ' : ' '))); as.appendChild(h('span' + (on ? '.hl' : ''), b >= 32 && b < 127 ? String.fromCharCode(b) : '.')); });
      hex.appendChild(h('div.hr', h('span.off', r.off.toString(16).padStart(4, '0') + '  '), hx, ' ', as));
    });
  }
  function select(s) { selNo = s.no; selRec = s.rec; selSum = s; hlRange = null; drawRows(); drawTree(A.detail(ctx, s.rec)); drawHex(); }

  /* ---------- données ---------- */
  function visible(r) { return (linkSel === 'all' || r.link.id === linkSel) && r.no <= frozenAt; }
  function scan() {
    const caps = sim.captures;
    if (scanned > caps.length) { scanned = 0; rows = []; }
    for (; scanned < caps.length; scanned++) {
      const r = caps[scanned]; if (!visible(r)) continue;
      const s = A.summarize(ctx, r);
      if (filterFn) { let ok = false; try { ok = filterFn(s); } catch (e) { } if (!ok) continue; }
      rows.push(s);
    }
  }
  function reset() { ctx = A.newCtx(); rows = []; scanned = 0; setHead(); mark(); refresh(true); }
  function mark() { dirty = true; }
  function refresh(force) {
    if (!dirty && !force) return; dirty = false;
    if (!capturing) { if (!force) return; }
    const wasBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - ROW * 2;
    scan(); counts.textContent = rows.length + ' affichés / ' + sim.captures.length + ' capturés';
    inner.style.height = rows.length * ROW + 'px';
    if (auto && wasBottom || auto && force) list.scrollTop = list.scrollHeight;
    drawRows();
  }
  function clearAll() { sim.captures.length = 0; sim.capNo = 0; frozenAt = capturing ? Infinity : 0; ctx = A.newCtx(); rows = []; scanned = 0; selRec = null; selNo = null; clear(tree); clear(hex); mark(); refresh(true); }
  function upd() { btnCap.textContent = capturing ? '■ Arrêter' : '● Démarrer'; btnCap.classList.toggle('rec', capturing); btnCap.setAttribute('aria-pressed', capturing); }
  function fillLinks() {
    const cur = linkSel; clear(linkSelect); linkSelect.appendChild(h('option', { value: 'all' }, 'Toutes les liaisons'));
    sim.links.forEach(l => linkSelect.appendChild(h('option', { value: l.id }, l.a.dev.name + ' ' + l.a.short + ' ↔ ' + l.b.dev.name + ' ' + l.b.short)));
    if (cur !== 'all' && !sim.links.some(l => l.id === cur)) linkSel = 'all'; linkSelect.value = linkSel;
  }
  function followSel() {
    if (!selSum || !selSum.tcp) { ui.toast('Sélectionnez d\'abord un paquet TCP', 'warn'); return; }
    const id = selSum.tcp.id; const segs = A.followTcp(ctx, sim.captures.filter(r => linkSel === 'all' || r.link.id === linkSel), id);
    const first = segs[0]; let mode = 'ascii';
    const box = h('div.follow'); const info = h('div.muted');
    const render = () => {
      clear(box); let a = 0, b = 0;
      segs.forEach(sg => { if (sg.dir === 0) a += sg.data.length; else b += sg.data.length; });
      info.textContent = segs.length + ' segments — ' + a + ' octets du client → serveur (rouge), ' + b + ' octets du serveur → client (bleu)';
      const items = mode === 'ascii' ? A.streamText(segs) : segs.map(sg => ({ dir: sg.dir, text: Array.from(sg.data).map(x => (x < 16 ? '0' : '') + x.toString(16)).join(' ') }));
      items.forEach(it => box.appendChild(h('pre.fseg.' + (it.dir === 0 ? 'c' : 's'), it.text)));
      if (!segs.length) box.appendChild(h('p.muted', 'Aucune donnée applicative dans ce flux (poignée de main seulement ?).'));
    };
    const sel = h('select', { onchange: e => { mode = e.target.value; render(); } }, h('option', { value: 'ascii' }, 'ASCII'), h('option', { value: 'hex' }, 'Hexadécimal'));
    render();
    ui.modal('Suivre le flux TCP n° ' + id + (first ? ' — ' + first.src + ' ↔ ' + first.dst : ''), h('div', info, h('label.inl', 'Afficher : ', sel), box), [{ label: 'Fermer' }]);
  }
  function stats() {
    const st = A.stats(ctx, rows);
    const fmt = b => b > 1024 ? (b / 1024).toFixed(1) + ' Ko' : b + ' o';
    ui.modal('Statistiques (paquets affichés)', h('div', h('p', st.total + ' paquets — ' + fmt(st.bytes)), h('h4', 'Hiérarchie des protocoles'),
      h('table.tbl', h('tr', h('th', 'Protocole'), h('th', 'Paquets'), h('th', '%'), h('th', 'Octets')), st.proto.map(p => h('tr', h('td', p.proto), h('td', p.n), h('td', (p.n * 100 / st.total).toFixed(1)), h('td', fmt(p.b))))),
      h('h4', 'Conversations'), h('table.tbl', h('tr', h('th', 'Adresses'), h('th', 'Paquets'), h('th', 'Octets')), st.conv.slice(0, 20).map(c => h('tr', h('td', c.conv), h('td', c.n), h('td', fmt(c.b)))))), [{ label: 'Fermer' }]);
  }
  function exportPcap() {
    const recs = sim.captures.filter(r => linkSel === 'all' || r.link.id === linkSel); if (!recs.length) return ui.toast('Aucun paquet à exporter', 'warn');
    const sel = filterFn ? recs.filter(r => { try { return filterFn(A.summarize(ctx, r)); } catch (e) { return false; } }) : recs;
    const u = A.toPcap(sel); const a = h('a', { href: URL.createObjectURL(new Blob([u], { type: 'application/vnd.tcpdump.pcap' })), download: 'capture.pcap' }); document.body.appendChild(a); a.click(); a.remove();
    ui.toast(sel.length + ' paquets exportés (ouvrable dans Wireshark)', 'ok');
  }

  const split = h('div.wssplit', h('div.wsleft', head, list), h('div.wsright', tree, hex));
  host.appendChild(h('div.ws', bar, split));
  setHead(); upd(); fillLinks();
  sim.on('capture', mark); sim.on('topology', () => { fillLinks(); });
  setInterval(() => refresh(), 250);
  return {
    refresh: () => refresh(true), setFilter(v) { fin.value = v; applyFilter(); }, selectLink(id) { linkSel = id || 'all'; linkSelect.value = linkSel; reset(); }, clear: clearAll, fillLinks,
    setCapturing(v) { capturing = v; frozenAt = v ? Infinity : sim.capNo; upd(); mark(); },
    get count() { return rows.length; }, get rows() { return rows; }, selectFirst(pred) { const s = rows.find(pred); if (s) select(s); return !!s; },
  };
};
})(typeof window !== 'undefined' ? window : globalThis);
