/* topology.js — sauvegarde / chargement d'une topologie (JSON) */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};

NS.saveTopology = function (sim, extra) {
  const devices = Array.from(sim.devices.values()).map(d => {
    const b = d.serialize();
    if (d instanceof NS.AP) { b.ap = { ssid: d.ssid, key: d.key, security: d.security }; }
    if (d.model === undefined) b.model = d.model;
    b.label = d.label || '';
    return b;
  });
  const links = sim.links.filter(l => !(l.type === 'wifi')).map(l => ({ a: [l.a.dev.id, l.a.name], b: [l.b.dev.id, l.b.name], type: l.type }));
  return Object.assign({ app: 'simulateur-reseau', v: 1, opts: { strictCables: !!sim.opts.strictCables, stpFast: !!sim.opts.stpFast }, devices, links, notes: '' }, extra || {});
};

NS.clearTopology = function (sim) {
  Array.from(sim.devices.values()).forEach(d => sim.removeDevice(d));
  sim.links.slice().forEach(l => sim.disconnect(l));
  sim.captures.length = 0; sim.heap.clear(); sim.halted = null; sim.now = 0; sim.capNo = 0; sim._w = null;
};

NS.loadTopology = function (sim, data) {
  if (!data || !Array.isArray(data.devices)) throw new Error('Fichier de topologie invalide');
  NS.clearTopology(sim);
  if (data.opts) { sim.opts.strictCables = !!data.opts.strictCables; if (data.opts.stpFast !== undefined) sim.opts.stpFast = !!data.opts.stpFast; }
  const map = new Map();
  data.devices.forEach(b => {
    if (!NS.CATALOG[b.model]) return;
    const n = /(\d+)$/.exec(b.id || ''); if (n) sim._id = Math.max(sim._id, +n[1]);
    const d = NS.createDevice(sim, b.model, { id: b.id, name: b.name, x: b.x, y: b.y });
    d.powered = b.powered !== false; d.label = b.label || '';
    map.set(b.id, { d, b });
  });
  (data.links || []).forEach(l => {
    const A = map.get(l.a[0]), B = map.get(l.b[0]); if (!A || !B) return;
    const pa = A.d.ports.find(p => p.name === l.a[1]), pb = B.d.ports.find(p => p.name === l.b[1]);
    if (pa && pb) sim.connect(pa, pb, l.type);
  });
  map.forEach(({ d, b }) => {
    if (b.ap && d instanceof NS.AP) { d.ssid = b.ap.ssid; d.key = b.ap.key; d.security = b.ap.security || 'WPA2'; }
    if (d.restore) d.restore(b);
    if (d.startServices) d.startServices();
  });
  NS.wifiRefresh(sim);
  sim.refreshCables();
  sim.emit('topology');
  return sim;
};
})(typeof window !== 'undefined' ? window : globalThis);
