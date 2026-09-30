/* app.js — application : canvas de topologie, palette, câblage, boucle de simulation, inspecteur */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { h, $, clear, ui, IP } = NS;
const SVGNS = 'http://www.w3.org/2000/svg';
const CW = 92, CH = 74; // taille des cartes d'équipement

class App {
  constructor() {
    this.sim = new NS.Sim(); this.view = { x: 0, y: 0, k: 1 }; this.sel = null; this.tool = 'select'; this.cableType = 'auto'; this.placing = null;
    this.cab = null; this.running = true; this.speed = 4; this.showPorts = true; this.nodes = new Map(); this.linkEls = new Map(); this.fx = []; this.mouse = { x: 0, y: 0 };
    this.dirtyTopo = true; this.last = performance.now(); this.tpCurrent = null;
  }
  /* ------------------------------------------------ mise en place */
  init() {
    const svg = this.svg = $('#canvas');
    this.gGrid = svg.querySelector('#grid'); this.gWorld = svg.querySelector('#world'); this.gLinks = svg.querySelector('#links'); this.gFx = svg.querySelector('#fx'); this.gNodes = svg.querySelector('#nodes'); this.gRubber = svg.querySelector('#rubber');
    this.buildPalette(); this.bindCanvas(); this.applyView();
    this.sim.on('topology', () => { this.dirtyTopo = true; });
    this.sim.on('port', () => { this.dirtyStates = true; });
    this.sim.on('frame', f => this.onFrame(f));
    this.sim.on('halt', m => this.showHalt(m));
    window.addEventListener('keydown', e => this.onKey(e));
    requestAnimationFrame(t => this.loop(t));
    setInterval(() => this.slowTick(), 500);
    this.renderInspector();
  }
  /* ------------------------------------------------ palette */
  buildPalette() {
    const pal = $('#palette'); clear(pal);
    const search = h('input', { type: 'search', placeholder: 'Rechercher un équipement…', 'aria-label': 'Rechercher un équipement', oninput: () => fill() });
    const cont = h('div.pal-items');
    pal.appendChild(search); pal.appendChild(cont);
    const fill = () => {
      clear(cont); const q = search.value.trim().toLowerCase();
      NS.CAT_ORDER.forEach(cat => {
        const keys = Object.keys(NS.CATALOG).filter(k => NS.CATALOG[k].cat === cat && (!q || (NS.CATALOG[k].label + ' ' + NS.CATALOG[k].vendor + ' ' + cat).toLowerCase().includes(q)));
        if (!keys.length) return;
        const det = h('details', { open: true }, h('summary', cat));
        keys.forEach(k => {
          const m = NS.CATALOG[k];
          const it = h('button.pal-item', { draggable: 'true', title: m.label + (m.ok ? ' — fiche constructeur' : ' — valeurs typiques'), 'data-model': k, onclick: () => this.armPlace(k), ondragstart: e => { e.dataTransfer.setData('text/plain', k); e.dataTransfer.effectAllowed = 'copy'; } },
            h('span.pi', { html: NS.iconSvg(m.icon, m.cat, 30) }), h('span.pl', m.label), m.ok ? h('span.ok', { title: 'Caractéristiques relevées sur fiche constructeur' }, '✔') : null);
          det.appendChild(it);
        });
        cont.appendChild(det);
      });
      if (!cont.firstChild) cont.appendChild(h('p.muted', 'Aucun résultat.'));
    };
    fill();
  }
  armPlace(k) { this.placing = k; this.setTool('select', true); $$('.pal-item').forEach(b => b.classList.toggle('armed', b.dataset.model === k)); this.svg.classList.add('placing'); ui.toast('Cliquez sur le plan pour placer : ' + NS.CATALOG[k].label + '  (Maj : en placer plusieurs, Échap : annuler)', 'info', 2500); }
  disarm() { this.placing = null; $$('.pal-item.armed').forEach(b => b.classList.remove('armed')); this.svg.classList.remove('placing'); }
  setTool(t, keepPlacing) {
    this.tool = t; if (!keepPlacing) this.disarm(); this.cab = null; clear(this.gRubber);
    $$('.tool').forEach(b => b.classList.toggle('on', b.dataset.tool === t)); this.svg.dataset.tool = t;
    $('#cabtype').style.display = t === 'cable' ? '' : 'none';
    $('#toolhint').textContent = t === 'cable' ? 'Câble : cliquez sur un équipement, choisissez le port, puis cliquez sur le second équipement.' : t === 'delete' ? 'Suppression : cliquez sur un équipement ou un câble.' : '';
  }
  /* ------------------------------------------------ coordonnées / vue */
  toWorld(cx, cy) { const r = this.svg.getBoundingClientRect(); return { x: (cx - r.left - this.view.x) / this.view.k, y: (cy - r.top - this.view.y) / this.view.k }; }
  applyView() { const v = this.view; this.gWorld.setAttribute('transform', 'translate(' + v.x + ' ' + v.y + ') scale(' + v.k + ')'); const gs = 40 * v.k; this.svg.style.setProperty('--gs', gs + 'px'); this.svg.style.backgroundPosition = (v.x % gs) + 'px ' + (v.y % gs) + 'px'; }
  fit() {
    const ds = Array.from(this.sim.devices.values()); const r = this.svg.getBoundingClientRect(); if (!ds.length) { this.view = { x: 0, y: 0, k: 1 }; return this.applyView(); }
    const x0 = Math.min(...ds.map(d => d.x)) - CW, x1 = Math.max(...ds.map(d => d.x)) + CW, y0 = Math.min(...ds.map(d => d.y)) - CH, y1 = Math.max(...ds.map(d => d.y)) + CH + 20;
    const k = Math.max(0.3, Math.min(1.4, Math.min(r.width / (x1 - x0), r.height / (y1 - y0)))); this.view = { k, x: (r.width - (x1 - x0) * k) / 2 - x0 * k, y: (r.height - (y1 - y0) * k) / 2 - y0 * k }; this.applyView();
  }
  /* ------------------------------------------------ événements canvas */
  bindCanvas() {
    const svg = this.svg; let pan = null, drag = null;
    svg.addEventListener('mousedown', e => {
      ui.closeMenu(); if (e.button === 2) return;
      const nodeEl = e.target.closest('.node'), linkEl = e.target.closest('.link');
      const w = this.toWorld(e.clientX, e.clientY);
      if (this.placing) { this.placeAt(w.x, w.y, e.shiftKey); return; }
      if (this.tool === 'cable') { if (nodeEl) this.cableClick(this.sim.devices.get(nodeEl.dataset.id), e); else if (this.cab) { this.cab = null; clear(this.gRubber); } return; }
      if (this.tool === 'delete') { if (nodeEl) this.removeDevice(this.sim.devices.get(nodeEl.dataset.id)); else if (linkEl) this.removeLink(this.linkById(linkEl.dataset.id)); return; }
      if (nodeEl) { const d = this.sim.devices.get(nodeEl.dataset.id); this.select(d); drag = { d, dx: w.x - d.x, dy: w.y - d.y, moved: false }; e.preventDefault(); }
      else if (linkEl) { this.select(this.linkById(linkEl.dataset.id)); }
      else { this.select(null); pan = { x: e.clientX - this.view.x, y: e.clientY - this.view.y }; svg.classList.add('panning'); }
    });
    window.addEventListener('mousemove', e => {
      const w = this.toWorld(e.clientX, e.clientY); this.mouse = w;
      if (drag) { drag.moved = true; drag.d.x = Math.round((w.x - drag.dx) / 4) * 4; drag.d.y = Math.round((w.y - drag.dy) / 4) * 4; this.moveNode(drag.d); }
      else if (pan) { this.view.x = e.clientX - pan.x; this.view.y = e.clientY - pan.y; this.applyView(); }
      if (this.cab) this.drawRubber();
    });
    window.addEventListener('mouseup', () => { drag = null; pan = null; svg.classList.remove('panning'); });
    svg.addEventListener('wheel', e => {
      e.preventDefault(); const r = svg.getBoundingClientRect(); const mx = e.clientX - r.left, my = e.clientY - r.top;
      const f = e.deltaY < 0 ? 1.12 : 1 / 1.12; const nk = Math.max(0.25, Math.min(2.5, this.view.k * f)); const wx = (mx - this.view.x) / this.view.k, wy = (my - this.view.y) / this.view.k;
      this.view.k = nk; this.view.x = mx - wx * nk; this.view.y = my - wy * nk; this.applyView();
    }, { passive: false });
    svg.addEventListener('dblclick', e => { const n = e.target.closest('.node'); if (n && this.tool === 'select') this.openDevice(this.sim.devices.get(n.dataset.id)); });
    svg.addEventListener('contextmenu', e => {
      e.preventDefault(); const n = e.target.closest('.node'), l = e.target.closest('.link');
      if (n) this.deviceMenu(this.sim.devices.get(n.dataset.id), e.clientX, e.clientY); else if (l) this.linkMenu(this.linkById(l.dataset.id), e.clientX, e.clientY);
      else ui.menu(e.clientX, e.clientY, [{ label: 'Recentrer la vue', fn: () => this.fit() }, { label: 'Tout sélectionner : non disponible', disabled: true }]);
    });
    svg.addEventListener('dragover', e => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    svg.addEventListener('drop', e => { e.preventDefault(); const k = e.dataTransfer.getData('text/plain'); if (NS.CATALOG[k]) { const w = this.toWorld(e.clientX, e.clientY); this.addDevice(k, w.x, w.y); } });
  }
  onKey(e) {
    if (e.target.closest('input,textarea,select')) return;
    if (e.key === 'Escape') { this.disarm(); this.setTool('select'); ui.closeMenu(); }
    else if (e.key === 'Delete' || e.key === 'Backspace') { if (this.sel) { if (this.sel instanceof NS.Link) this.removeLink(this.sel); else this.removeDevice(this.sel); } }
    else if (e.key === 'v') this.setTool('select'); else if (e.key === 'c') this.setTool('cable'); else if (e.key === 'x') this.setTool('delete');
    else if (e.key === ' ') { this.toggleRun(); e.preventDefault(); }
  }
  placeAt(x, y, keep) { const k = this.placing; this.addDevice(k, Math.round(x / 4) * 4, Math.round(y / 4) * 4); if (!keep) this.disarm(); }
  addDevice(model, x, y) {
    const d = NS.createDevice(this.sim, model, { x, y }); this.select(d); this.dirtyTopo = true; this.afterChange(); return d;
  }
  removeDevice(d) { if (!d) return; d._sess = null; d._termApi = null; ui.closeWindow('dev-' + d.id); this.sim.removeDevice(d); if (this.sel === d) this.select(null); this.afterChange(); }
  removeLink(l) { if (!l) return; this.sim.disconnect(l); if (this.sel === l) this.select(null); NS.wifiRefresh(this.sim); this.afterChange(); }
  linkById(id) { return this.sim.links.find(l => l.id === id); }
  afterChange() { this.refresh(); if (this.onChange) this.onChange(); }
  refresh() { this.dirtyTopo = true; this.dirtyStates = true; this.renderInspector(); }
  openDevice(d, tab) { if (d) NS.openDevice(this, d, tab); }
  /* ------------------------------------------------ câblage */
  cableClick(dev, e) {
    const free = dev.ports.filter(p => !p.link && !p.virtual && !(p.media === 'wifi'));
    const finish = (port) => {
      if (!this.cab) { this.cab = { port, dev }; this.drawRubber(); return; }
      const a = this.cab.port; this.cab = null; clear(this.gRubber);
      if (a.dev === dev) { ui.toast('Impossible de relier un équipement à lui-même', 'warn'); return; }
      const l = this.sim.connect(a, port, this.cableType);
      if (!l) { ui.toast('Connexion impossible', 'err'); return; }
      if (!l.ok) ui.toast('Câble inadapté (' + (l.type === 'fiber' ? 'fibre sur port cuivre' : 'droit/croisé incorrect') + ') : le lien ne monte pas. Changez de type de câble.', 'warn', 5000);
      this.afterChange();
    };
    if (!free.length) { ui.toast(dev.name + ' : aucun port libre', 'warn'); return; }
    if (free.length === 1) { finish(free[0]); return; }
    const items = [{ title: dev.name + ' — choisir un port' }].concat(free.map(p => ({ label: p.name + '  (' + (p.speed >= 1000 ? p.speed / 1000 + ' Gb/s' : p.speed + ' Mb/s') + (p.media === 'fiber' ? ', fibre' : '') + ')', fn: () => finish(p) })));
    ui.menu(e.clientX, e.clientY, items);
  }
  drawRubber() {
    clear(this.gRubber); if (!this.cab) return; const d = this.cab.dev, m = this.mouse;
    this.gRubber.appendChild(h('svg:line', { x1: d.x, y1: d.y, x2: m.x, y2: m.y, class: 'rubber' }));
  }
  /* ------------------------------------------------ sélection / menus */
  select(o) { this.sel = o; this.updateSelClass(); this.renderInspector(); }
  updateSelClass() { this.nodes.forEach((n, id) => n.classList.toggle('sel', this.sel && this.sel.id === id)); this.linkEls.forEach((n, id) => n.classList.toggle('sel', this.sel && this.sel.id === id)); }
  deviceMenu(d, x, y) {
    this.select(d); const m = NS.CATALOG[d.model];
    ui.menu(x, y, [{ title: d.name }, { label: 'Ouvrir / configurer…', fn: () => this.openDevice(d) },
      m.kind === 'router' || (m.kind === 'switch' && d.managed) || m.kind === 'host' ? { label: 'Ouvrir le terminal', fn: () => this.openDevice(d, m.kind === 'host' ? 'term' : 'cli') } : { label: 'Fiche technique', fn: () => this.openDevice(d, 'sheet') },
      { label: 'Renommer…', fn: () => ui.ask('Nom de l\'équipement', d.name, v => { v = v.trim(); if (v) { d.name = v; this.refresh(); this.afterChange(); } }) },
      { label: d.powered ? 'Éteindre' : 'Allumer', fn: () => { d.powered = !d.powered; d.ports.forEach(p => this.sim.portChanged(p)); if (d.ports.some(p => p.link)) d.ports.forEach(p => p.peer && this.sim.portChanged(p.peer)); NS.wifiRefresh(this.sim); this.refresh(); } }, '-',
      { label: 'Supprimer', fn: () => this.removeDevice(d) }]);
  }
  linkMenu(l, x, y) {
    this.select(l);
    ui.menu(x, y, [{ title: l.a.dev.name + ' ' + l.a.short + ' ↔ ' + l.b.dev.name + ' ' + l.b.short }, { label: 'Analyser cette liaison (Wireshark)', fn: () => this.analyzeLink(l) }, { label: l.ok ? 'Simuler une coupure du câble' : 'Rétablir le câble', fn: () => { l.ok = !l.ok; this.sim.portChanged(l.a); this.sim.portChanged(l.b); this.refresh(); } }, '-', { label: 'Supprimer le câble', fn: () => this.removeLink(l) }]);
  }
  analyzeLink(l) { if (this.analyzer) { this.analyzer.fillLinks(); this.analyzer.selectLink(l.id); this.showDock('analyzer'); } }
  showDock(tab) { if (this.dockShow) this.dockShow(tab); }
  /* ------------------------------------------------ rendu du plan */
  devCenter(d) { return { x: d.x, y: d.y }; }
  render() {
    if (this.dirtyTopo) { this.dirtyTopo = false; this.renderLinks(); this.renderNodes(); this.updateSelClass(); this.dirtyStates = true; if (this.analyzer) this.analyzer.fillLinks(); }
    if (this.dirtyStates) { this.dirtyStates = false; this.renderStates(); }
  }
  renderNodes() {
    const seen = new Set();
    this.sim.devices.forEach(d => {
      seen.add(d.id); let n = this.nodes.get(d.id); const m = NS.CATALOG[d.model];
      if (!n) {
        n = h('svg:g', { class: 'node', 'data-id': d.id, tabindex: '0', role: 'button', 'aria-label': d.name });
        n.appendChild(h('svg:rect', { class: 'card', x: -CW / 2, y: -CH / 2, width: CW, height: CH, rx: 10 }));
        n.appendChild(h('svg:g', { class: 'ico', transform: 'translate(-22 -33) scale(0.92)', html: NS.iconInner(m.icon, m.cat) }));
        n.appendChild(h('svg:text', { class: 'nm', x: 0, y: 24, 'text-anchor': 'middle' }));
        n.appendChild(h('svg:text', { class: 'ipl', x: 0, y: 36, 'text-anchor': 'middle' }));
        n.appendChild(h('svg:circle', { class: 'pwr', cx: CW / 2 - 8, cy: -CH / 2 + 8, r: 4 }));
        n.addEventListener('keydown', ev => { if (ev.key === 'Enter') this.openDevice(d); });
        this.gNodes.appendChild(n); this.nodes.set(d.id, n);
      }
      n.setAttribute('transform', 'translate(' + d.x + ' ' + d.y + ')'); n.querySelector('.nm').textContent = d.name; n.setAttribute('aria-label', d.name + ', ' + m.label);
    });
    this.nodes.forEach((n, id) => { if (!seen.has(id)) { n.remove(); this.nodes.delete(id); } });
  }
  moveNode(d) { const n = this.nodes.get(d.id); if (n) n.setAttribute('transform', 'translate(' + d.x + ' ' + d.y + ')'); this.positionLinks(); if (this.cab) this.drawRubber(); }
  edge(d, tx, ty) { const dx = tx - d.x, dy = ty - d.y; if (!dx && !dy) return { x: d.x, y: d.y, ux: 0, uy: -1 }; const t = Math.min(dx ? (CW / 2) / Math.abs(dx) : 1e9, dy ? (CH / 2) / Math.abs(dy) : 1e9); const L = Math.hypot(dx, dy); return { x: d.x + dx * t, y: d.y + dy * t, ux: dx / L, uy: dy / L }; }
  renderLinks() {
    const seen = new Set();
    this.sim.links.forEach(l => {
      seen.add(l.id); let g = this.linkEls.get(l.id);
      if (!g) {
        g = h('svg:g', { class: 'link', 'data-id': l.id });
        g.appendChild(h('svg:line', { class: 'hit' })); g.appendChild(h('svg:line', { class: 'wire' }));
        g.appendChild(h('svg:circle', { class: 'pa', r: 5 })); g.appendChild(h('svg:circle', { class: 'pb', r: 5 }));
        g.appendChild(h('svg:text', { class: 'la' })); g.appendChild(h('svg:text', { class: 'lb' }));
        this.gLinks.appendChild(g); this.linkEls.set(l.id, g);
      }
    });
    this.linkEls.forEach((g, id) => { if (!seen.has(id)) { g.remove(); this.linkEls.delete(id); } });
    this.positionLinks();
  }
  positionLinks() {
    const groups = new Map(); this.sim.links.forEach(l => { const k = [l.a.dev.id, l.b.dev.id].sort().join('|'); (groups.get(k) || groups.set(k, []).get(k)).push(l); });
    this.sim.links.forEach(l => {
      const g = this.linkEls.get(l.id); if (!g) return; const A = l.a.dev, B = l.b.dev;
      const grp = groups.get([A.id, B.id].sort().join('|')); const idx = grp.indexOf(l); const off = (idx - (grp.length - 1) / 2) * 14;
      const dx = B.x - A.x, dy = B.y - A.y, L = Math.hypot(dx, dy) || 1; const nx = -dy / L * off, ny = dx / L * off;
      const a = this.edge({ x: A.x + nx, y: A.y + ny }, B.x + nx, B.y + ny), b = this.edge({ x: B.x + nx, y: B.y + ny }, A.x + nx, A.y + ny);
      l._pa = { x: a.x, y: a.y }; l._pb = { x: b.x, y: b.y };
      const set = (sel, o) => { const el = g.querySelector(sel); for (const k in o) el.setAttribute(k, o[k]); };
      set('.hit', { x1: a.x, y1: a.y, x2: b.x, y2: b.y }); set('.wire', { x1: a.x, y1: a.y, x2: b.x, y2: b.y });
      set('.pa', { cx: a.x, cy: a.y }); set('.pb', { cx: b.x, cy: b.y });
      const ta = g.querySelector('.la'), tb = g.querySelector('.lb');
      const lab = (el, e) => { el.setAttribute('x', e.x + e.ux * 17 - e.uy * 9); el.setAttribute('y', e.y + e.uy * 17 + e.ux * 9 + 3); el.setAttribute('text-anchor', 'middle'); };
      lab(ta, a); lab(tb, b);
      ta.textContent = this.showPorts ? l.a.short : ''; tb.textContent = this.showPorts ? l.b.short : '';
    });
  }
  linkColor(l, p) {
    if (!l.ok || !p.up) { const stpBlock = p.dev.stp && p.dev.stp.enabled && p.up; return '#dc2626'; }
    const st = p.stp; if (p.dev.stp && p.dev.stp.enabled && st) { if (st.state === 'blocking') return '#f59e0b'; if (st.state === 'listening' || st.state === 'learning') return '#f59e0b'; }
    return '#16a34a';
  }
  renderStates() {
    this.sim.links.forEach(l => {
      const g = this.linkEls.get(l.id); if (!g) return; const w = g.querySelector('.wire');
      w.setAttribute('class', 'wire ' + l.type + (l.ok ? '' : ' cut'));
      const ca = this.linkColor(l, l.a), cb = this.linkColor(l, l.b);
      g.querySelector('.pa').setAttribute('fill', ca); g.querySelector('.pb').setAttribute('fill', cb);
      const oa = l.a.dev.stp && l.a.dev.stp.enabled && l.a.up && l.a.stp && l.a.stp.state === 'blocking', ob = l.b.dev.stp && l.b.dev.stp.enabled && l.b.up && l.b.stp && l.b.stp.state === 'blocking';
      g.classList.toggle('blocked', !!(oa || ob));
    });
    this.nodes.forEach((n, id) => {
      const d = this.sim.devices.get(id); if (!d) return; n.querySelector('.pwr').setAttribute('fill', d.powered ? '#22c55e' : '#94a3b8'); n.classList.toggle('off', !d.powered);
      let ip = ''; if (d.ifaceList) { const i = d.ifaceList().find(x => x.ip && !x.loop) || null; if (i) ip = IP.str(i.ip); else if (d.dhcpClients && d.dhcpClients.size) ip = 'DHCP…'; }
      const t = n.querySelector('.ipl'); if (t.textContent !== ip) t.textContent = ip;
    });
    this.updateSelClass();
  }
  /* ------------------------------------------------ animation des trames */
  onFrame(f) {
    if (this.fx.length > 400) return; const s = this.frameStyle(f.bytes); this.fx.push({ link: f.link, from: f.from, t0: f.t0, t1: f.t1, color: s, el: null });
  }
  frameStyle(bytes) {
    if (bytes.length > 13) { const t = (bytes[12] << 8) | bytes[13]; if (t === 0x0806) return '#eab308'; if (t === 0x0800 || t === 0x8100) { const off = t === 0x8100 ? 18 : 14; const pr = bytes[off + 9 - (t === 0x8100 ? 0 : 0)]; const p = bytes[(t === 0x8100 ? 18 : 14) + 9]; if (p === 1) return '#ec4899'; if (p === 6) return '#7c3aed'; if (p === 17) return '#0ea5e9'; return '#64748b'; } if (t <= 1500) return '#2563eb'; }
    return '#64748b';
  }
  drawFx() {
    const now = this.sim.now; const keep = [];
    this.fx.forEach(f => {
      const p = (now - f.t0) / Math.max(1e-6, f.t1 - f.t0);
      if (p >= 1 || !this.linkEls.has(f.link.id)) { if (f.el) f.el.remove(); return; }
      if (p < 0) { keep.push(f); return; }
      const l = f.link; if (!l._pa) { keep.push(f); return; }
      const A = f.from === l.a ? l._pa : l._pb, B = f.from === l.a ? l._pb : l._pa;
      if (!f.el) { f.el = h('svg:rect', { class: 'pkt', width: 12, height: 8, rx: 2, fill: f.color }); this.gFx.appendChild(f.el); }
      f.el.setAttribute('x', A.x + (B.x - A.x) * p - 6); f.el.setAttribute('y', A.y + (B.y - A.y) * p - 4); keep.push(f);
    });
    this.fx = keep;
  }
  /* ------------------------------------------------ boucle de simulation */
  loop(t) {
    const dt = Math.min(100, t - this.last); this.last = t;
    if (this.running && !this.sim.halted) this.sim.tick(dt, this.speed);
    this.render(); this.drawFx();
    requestAnimationFrame(tt => this.loop(tt));
  }
  slowTick() {
    this.dirtyStates = true; const el = $('#simtime'); if (el) el.textContent = 't = ' + (this.sim.now / 1000).toFixed(3) + ' s';
    if (this.inspDirty) this.renderInspector();
  }
  toggleRun() { this.running = !this.running; const b = $('#btn-run'); if (b) { b.textContent = this.running ? '⏸ Pause' : '▶ Lecture'; b.classList.toggle('on', !this.running); } }
  showHalt(m) { const b = $('#haltbar'); if (b) { b.style.display = ''; $('#haltmsg').textContent = m; } }
  clearHalt() { this.sim.reset(); const b = $('#haltbar'); if (b) b.style.display = 'none'; }
  /* ------------------------------------------------ inspecteur */
  renderInspector() {
    const box = $('#inspector'); if (!box) return; clear(box); const s = this.sel;
    if (!s) { box.appendChild(h('div.insp-empty', h('h3', 'Aucune sélection'), h('p.muted', 'Cliquez sur un équipement ou un câble pour voir ses propriétés. Double-clic sur un équipement pour l\'ouvrir (terminal, configuration).'), h('p.muted', 'Astuce : molette = zoom, glisser le fond = déplacer la vue.'))); return; }
    if (s instanceof NS.Link) {
      box.appendChild(h('h3', 'Câble ' + ({ auto: 'auto', straight: 'droit', cross: 'croisé', fiber: 'fibre', wifi: 'Wi-Fi' }[s.type] || s.type)));
      box.appendChild(h('table.kv', h('tr', h('th', 'Extrémité A'), h('td', s.a.dev.name + ' — ' + s.a.name)), h('tr', h('th', 'Extrémité B'), h('td', s.b.dev.name + ' — ' + s.b.name)), h('tr', h('th', 'Débit négocié'), h('td', s.speed + ' Mb/s')), h('tr', h('th', 'État'), h('td', s.ok ? (s.a.up && s.b.up ? '● actif' : '○ inactif (port éteint)') : '✖ câble coupé / inadapté'))));
      box.appendChild(h('div.btns', h('button.primary', { onclick: () => this.analyzeLink(s) }, '🔍 Analyser cette liaison'), h('button', { onclick: () => this.removeLink(s) }, 'Supprimer')));
      return;
    }
    const m = NS.CATALOG[s.model];
    const nm = h('input', { type: 'text', value: s.name, 'aria-label': 'Nom', onchange: e => { const v = e.target.value.trim(); if (v) { s.name = v; this.refresh(); this.afterChange(); } } });
    box.appendChild(h('div.insp-head', h('span.pi', { html: NS.iconSvg(m.icon, m.cat, 44) }), h('div', nm, h('div.muted.small', m.label))));
    const rows = [['MAC de base', s.baseMac], ['Alimentation', s.powered ? 'allumé' : 'éteint']];
    if (s.ifaceList) s.ifaceList().filter(i => !i.loop).slice(0, 6).forEach(i => rows.push([i.name, i.ip ? IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask) + (i.isUp() ? '' : '  (down)') : (i.dhcp ? 'DHCP…' : '—')]));
    if (s.gateway) rows.push(['Passerelle', IP.str(s.gateway)]);
    box.appendChild(h('table.kv', rows.map(r => h('tr', h('th', r[0]), h('td.mono', r[1])))));
    box.appendChild(h('div.btns', h('button.primary', { onclick: () => this.openDevice(s) }, 'Ouvrir / configurer'), h('button', { onclick: () => this.openDevice(s, 'sheet') }, 'Fiche technique'), h('button', { onclick: () => this.removeDevice(s) }, 'Supprimer')));
    box.appendChild(h('h4', 'Ports'));
    box.appendChild(h('ul.portlist', s.ports.filter(p => !p.virtual).map(p => h('li', h('span', { class: p.up ? 'up' : 'down' }, p.up ? '●' : '○'), ' ' + p.name, h('span.muted', p.peer ? '  → ' + p.peer.dev.name + ' ' + p.peer.short : '')))));
  }
}
const $$ = (s) => Array.from(document.querySelectorAll(s));
NS.App = App;
})(typeof window !== 'undefined' ? window : globalThis);
