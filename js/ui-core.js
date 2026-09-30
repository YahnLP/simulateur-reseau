/* ui-core.js — utilitaires d'interface : création DOM, fenêtres, menus, boîtes de dialogue, icônes */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const SVGNS = 'http://www.w3.org/2000/svg';

/* h('div.classe#id', {attrs}, ...enfants) */
function h(tag, attrs, ...kids) {
  let svg = false; if (tag.startsWith('svg:')) { svg = true; tag = tag.slice(4); }
  const m = /^([a-zA-Z0-9]+)((?:[.#][\w-]+)*)$/.exec(tag);
  const el = svg ? document.createElementNS(SVGNS, m ? m[1] : tag) : document.createElement(m ? m[1] : tag);
  if (m && m[2]) m[2].replace(/([.#])([\w-]+)/g, (_, k, v) => { if (k === '.') el.classList.add(v); else el.id = v; });
  if (attrs && (typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs))) { kids.unshift(attrs); attrs = null; }
  if (attrs) for (const k in attrs) {
    const v = attrs[k]; if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.setAttribute('class', (el.getAttribute('class') ? el.getAttribute('class') + ' ' : '') + v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v;
    else if (k === 'value' && !svg) el.value = v;
    else if (k === 'checked' && !svg) el.checked = !!v;
    else if (k === 'disabled' && !svg) el.disabled = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  const add = (c) => { if (c === null || c === undefined || c === false) return; if (Array.isArray(c)) c.forEach(add); else el.appendChild(c instanceof Node ? c : document.createTextNode(String(c))); };
  kids.forEach(add);
  return el;
}
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/* ---------- icônes d'équipements (viewBox 48×48) ---------- */
const CATCOL = { Postes: '#2563eb', Serveurs: '#0f766e', Commutateurs: '#15803d', Routeurs: '#c2410c', 'Sécurité': '#b91c1c', 'Sans-fil': '#7e22ce' };
const ICONS = {
  pc: c => `<rect x="7" y="8" width="34" height="23" rx="2.5" fill="#fff" stroke="${c}" stroke-width="2.6"/><rect x="11" y="12" width="26" height="15" rx="1" fill="${c}" opacity=".18"/><path d="M19 38h10M24 31v7" stroke="${c}" stroke-width="2.6" stroke-linecap="round"/>`,
  laptop: c => `<rect x="10" y="10" width="28" height="19" rx="2" fill="#fff" stroke="${c}" stroke-width="2.6"/><rect x="13" y="13" width="22" height="13" fill="${c}" opacity=".18"/><path d="M4 34h40l-3 4H7z" fill="${c}"/>`,
  server: c => `<rect x="9" y="6" width="30" height="10" rx="2" fill="#fff" stroke="${c}" stroke-width="2.4"/><rect x="9" y="19" width="30" height="10" rx="2" fill="#fff" stroke="${c}" stroke-width="2.4"/><rect x="9" y="32" width="30" height="10" rx="2" fill="#fff" stroke="${c}" stroke-width="2.4"/><circle cx="15" cy="11" r="1.8" fill="${c}"/><circle cx="15" cy="24" r="1.8" fill="${c}"/><circle cx="15" cy="37" r="1.8" fill="${c}"/><path d="M24 11h10M24 24h10M24 37h10" stroke="${c}" stroke-width="2" opacity=".5"/>`,
  nas: c => `<rect x="10" y="6" width="28" height="36" rx="3" fill="#fff" stroke="${c}" stroke-width="2.6"/><rect x="14" y="11" width="9" height="22" rx="1" fill="${c}" opacity=".25"/><rect x="25" y="11" width="9" height="22" rx="1" fill="${c}" opacity=".25"/><circle cx="24" cy="38" r="1.8" fill="${c}"/>`,
  printer: c => `<rect x="14" y="7" width="20" height="10" fill="#fff" stroke="${c}" stroke-width="2.4"/><rect x="7" y="17" width="34" height="17" rx="3" fill="#fff" stroke="${c}" stroke-width="2.6"/><rect x="14" y="28" width="20" height="13" fill="#fff" stroke="${c}" stroke-width="2.4"/><circle cx="35" cy="22" r="1.6" fill="${c}"/>`,
  phone: c => `<path d="M8 30l4-18h24l4 18z" fill="#fff" stroke="${c}" stroke-width="2.6" stroke-linejoin="round"/><rect x="6" y="30" width="36" height="10" rx="2" fill="${c}" opacity=".25" stroke="${c}" stroke-width="2.2"/><path d="M15 17h18M15 22h18" stroke="${c}" stroke-width="2" opacity=".6"/>`,
  switch: c => `<rect x="4" y="15" width="40" height="18" rx="3" fill="#fff" stroke="${c}" stroke-width="2.6"/><path d="M10 24h6M20 24h6M30 24h6" stroke="${c}" stroke-width="3.5" stroke-linecap="round"/><path d="M12 10l-4 4 4 4M36 10l4 4-4 4" stroke="${c}" stroke-width="2.2" fill="none" transform="translate(0 -2)"/><path d="M12 38l-4-4M36 38l4-4" stroke="${c}" stroke-width="2.2"/>`,
  switchl3: c => `<rect x="4" y="15" width="40" height="18" rx="3" fill="#fff" stroke="${c}" stroke-width="2.6"/><path d="M10 24h6M20 24h6M30 24h6" stroke="${c}" stroke-width="3.5" stroke-linecap="round"/><text x="24" y="11" font-size="9" font-weight="700" text-anchor="middle" fill="${c}" font-family="sans-serif">L3</text><path d="M12 38l-4-4M36 38l4-4" stroke="${c}" stroke-width="2.2"/>`,
  hub: c => `<rect x="6" y="17" width="36" height="14" rx="3" fill="#fff" stroke="${c}" stroke-width="2.6"/><circle cx="14" cy="24" r="2.4" fill="${c}"/><circle cx="24" cy="24" r="2.4" fill="${c}"/><circle cx="34" cy="24" r="2.4" fill="${c}"/><path d="M12 12v5M24 12v5M36 12v5M12 31v5M24 31v5M36 31v5" stroke="${c}" stroke-width="2.2"/>`,
  router: c => `<circle cx="24" cy="24" r="16" fill="#fff" stroke="${c}" stroke-width="2.8"/><path d="M24 12v9M24 27v9M12 24h9M27 24h9" stroke="${c}" stroke-width="2.6"/><path d="M20 15l4-4 4 4M20 33l4 4 4-4M15 20l-4 4 4 4M33 20l4 4-4 4" stroke="${c}" stroke-width="2.2" fill="none" stroke-linejoin="round"/>`,
  cloud: c => `<path d="M14 36c-5 0-9-3.5-9-8 0-4 3-7 7-7.6C13 15 17.5 11 23 11c5 0 9 3 10.5 7.4C38.5 18.6 43 22 43 27c0 5-4.5 9-10 9z" fill="#fff" stroke="${c}" stroke-width="2.8" stroke-linejoin="round"/><path d="M16 27h16M27 23l5 4-5 4" stroke="${c}" stroke-width="2.4" fill="none"/>`,
  box: c => `<rect x="9" y="13" width="30" height="24" rx="4" fill="#fff" stroke="${c}" stroke-width="2.6"/><circle cx="16" cy="31" r="1.8" fill="${c}"/><circle cx="22" cy="31" r="1.8" fill="${c}"/><path d="M17 8c4-4 10-4 14 0M20 11.5c2.4-2.2 5.6-2.2 8 0" stroke="${c}" stroke-width="2.2" fill="none" stroke-linecap="round"/>`,
  firewall: c => `<rect x="6" y="9" width="36" height="30" rx="2" fill="#fff" stroke="${c}" stroke-width="2.6"/><path d="M6 19h36M6 29h36M18 9v10M30 9v10M12 19v10M24 19v10M36 19v10M18 29v10M30 29v10" stroke="${c}" stroke-width="2.2"/><path d="M24 18c2 3 5 4 5 8a5 5 0 01-10 0c0-2 1-3 2-4 .3 1.4 1 2 1.6 2C22.4 22 23 20 24 18z" fill="${c}" transform="translate(0 -1)"/>`,
  ap: c => `<ellipse cx="24" cy="33" rx="15" ry="6" fill="#fff" stroke="${c}" stroke-width="2.6"/><path d="M13 22c6-7 16-7 22 0M18 26.5c3.6-4 8.4-4 12 0" stroke="${c}" stroke-width="2.6" fill="none" stroke-linecap="round"/><circle cx="24" cy="31" r="2" fill="${c}"/>`,
};
NS.iconSvg = function (name, cat, size) {
  const c = CATCOL[cat] || '#334155';
  return '<svg xmlns="' + SVGNS + '" viewBox="0 0 48 48" width="' + (size || 40) + '" height="' + (size || 40) + '">' + (ICONS[name] || ICONS.pc)(c) + '</svg>';
};
NS.iconInner = function (name, cat) { return (ICONS[name] || ICONS.pc)(CATCOL[cat] || '#334155'); };
NS.CATCOL = CATCOL;

/* ---------- toasts ---------- */
let toastBox = null;
function toast(msg, kind, ms) {
  if (!toastBox) toastBox = h('div#toasts', { role: 'status', 'aria-live': 'polite' }), document.body.appendChild(toastBox);
  const t = h('div.toast' + (kind ? '.' + kind : ''), msg); toastBox.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, ms || 3500);
}

/* ---------- menu contextuel ---------- */
let curMenu = null;
function closeMenu() { if (curMenu) { curMenu.remove(); curMenu = null; } }
function menu(x, y, items) {
  closeMenu();
  const m = h('div.ctxmenu', { role: 'menu' });
  items.forEach(it => {
    if (it === '-') { m.appendChild(h('div.sep')); return; }
    if (it.title) { m.appendChild(h('div.mtitle', it.title)); return; }
    m.appendChild(h('button.mitem', { role: 'menuitem', disabled: !!it.disabled, onclick: () => { closeMenu(); it.fn && it.fn(); } }, it.label));
  });
  document.body.appendChild(m); curMenu = m;
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + 'px'; m.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + 'px';
  setTimeout(() => document.addEventListener('mousedown', function f(e) { if (!m.contains(e.target)) { closeMenu(); } document.removeEventListener('mousedown', f); }, { once: false }), 0);
  return m;
}

/* ---------- dialogues ---------- */
function modal(title, body, buttons) {
  const back = h('div.modal-back');
  const box = h('div.modal', { role: 'dialog', 'aria-label': title }, h('h3', title), h('div.modal-body', body), h('div.modal-btns', (buttons || [{ label: 'Fermer' }]).map(b => h('button' + (b.primary ? '.primary' : ''), { onclick: () => { if (!b.fn || b.fn() !== false) back.remove(); } }, b.label))));
  back.appendChild(box); back.addEventListener('mousedown', e => { if (e.target === back) back.remove(); });
  document.body.appendChild(back);
  const f = box.querySelector('input,select,textarea'); if (f) f.focus();
  return back;
}
function ask(title, value, cb, label) {
  const inp = h('input', { type: 'text', value: value || '', style: { width: '100%' } });
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') { const v = inp.value; inp.closest('.modal-back').remove(); cb(v); } });
  modal(title, [label ? h('label', label) : null, inp], [{ label: 'Annuler' }, { label: 'OK', primary: true, fn: () => { cb(inp.value); } }]);
  inp.select();
}
function confirmBox(title, msg, cb) { modal(title, h('p', msg), [{ label: 'Annuler' }, { label: 'Confirmer', primary: true, fn: () => { cb(); } }]); }

/* ---------- fenêtres flottantes ---------- */
let zTop = 50; const wins = new Map();
function openWindow(o) {
  if (o.id && wins.has(o.id)) { const w = wins.get(o.id); w.el.style.display = ''; focus(w); return w; }
  const layer = $('#winlayer');
  const title = h('span.wtitle', o.title || '');
  const closeBtn = h('button.wclose', { 'aria-label': 'Fermer', title: 'Fermer', onclick: () => w.close() }, '×');
  const minBtn = h('button.wmin', { 'aria-label': 'Réduire', title: 'Réduire', onclick: () => { w.el.classList.toggle('min'); } }, '–');
  const head = h('div.whead', title, h('span.wbtns', minBtn, closeBtn));
  const body = h('div.wbody');
  const el = h('div.win', { role: 'dialog', 'aria-label': o.title || 'Fenêtre', style: { left: (o.x || 120 + wins.size * 26) + 'px', top: (o.y || 80 + wins.size * 26) + 'px', width: (o.w || 560) + 'px', height: (o.h || 400) + 'px' } }, head, body);
  layer.appendChild(el);
  const w = { el, body, title, id: o.id, onClose: o.onClose, close() { if (this.onClose) this.onClose(); el.remove(); if (o.id) wins.delete(o.id); }, setTitle(t) { title.textContent = t; } };
  if (o.id) wins.set(o.id, w);
  el.addEventListener('mousedown', () => focus(w));
  let drag = null;
  head.addEventListener('mousedown', e => { if (e.target.closest('button')) return; drag = { x: e.clientX - el.offsetLeft, y: e.clientY - el.offsetTop }; e.preventDefault(); });
  document.addEventListener('mousemove', e => { if (!drag) return; el.style.left = Math.max(-200, Math.min(innerWidth - 60, e.clientX - drag.x)) + 'px'; el.style.top = Math.max(0, Math.min(innerHeight - 30, e.clientY - drag.y)) + 'px'; });
  document.addEventListener('mouseup', () => { drag = null; });
  head.addEventListener('dblclick', () => el.classList.toggle('max'));
  focus(w);
  return w;
}
function focus(w) { w.el.style.zIndex = ++zTop; $$('.win.focus').forEach(x => x.classList.remove('focus')); w.el.classList.add('focus'); }
function closeWindow(id) { const w = wins.get(id); if (w) w.close(); }
function closeAllWindows() { Array.from(wins.values()).forEach(w => w.close()); }

/* ---------- onglets ---------- */
function tabs(defs, opts) {
  const bar = h('div.tabbar', { role: 'tablist' }), body = h('div.tabbody'); const map = {};
  const root = h('div.tabs', bar, body);
  function show(id) {
    Object.keys(map).forEach(k => { map[k].btn.classList.toggle('on', k === id); map[k].btn.setAttribute('aria-selected', k === id); });
    clear(body); const d = map[id].def; const c = d.render(); body.appendChild(c); root.current = id; if (d.onShow) d.onShow(c);
    if (opts && opts.onChange) opts.onChange(id);
  }
  defs.forEach(d => { const btn = h('button.tab', { role: 'tab', onclick: () => show(d.id) }, d.label); map[d.id] = { btn, def: d }; bar.appendChild(btn); });
  root.show = show; root.body = body;
  if (defs.length) show((opts && opts.first) || defs[0].id);
  return root;
}
/* champ de formulaire étiqueté */
function field(label, input, hint) { return h('label.fld', h('span', label), input, hint ? h('small', hint) : null); }

NS.h = h; NS.$ = $; NS.$$ = $$; NS.clear = clear; NS.esc = esc;
NS.ui = { toast, menu, closeMenu, modal, ask, confirmBox, openWindow, closeAllWindows, closeWindow, tabs, field };
})(typeof window !== 'undefined' ? window : globalThis);
