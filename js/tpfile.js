/* tpfile.js — TP « fichier » : un plan .json qui embarque ses consignes, ses vérifications et sa correction */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const IP = NS.IP;
const KINDS = ['ping', 'noping', 'http', 'cli'];

/* Texte fourni par un fichier : tout est échappé, seules les balises <code> et <b> sont conservées. */
function safeHtml(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/&lt;(\/?)(code|b)&gt;/g, '<$1$2>');
}
NS.tpSafeHtml = safeHtml;

/* Exécute une commande dans le terminal d'un équipement et renvoie la sortie (synchrone, temps simulé). */
function runCli(sim, dev, cmd) {
  const s = dev.newSession(); let out = ''; let done = false;
  if (NS.Host && !(dev instanceof NS.Host)) s.mode = 'priv'; /* la vérification lit la configuration sans connaître les mots de passe */
  const io = { print: t => { out += t; }, done: () => { done = true; }, clear() { } };
  s.exec(cmd, io); sim.runUntil(() => done, 60000);
  return out;
}
NS.tpRunCli = runCli;

function compile(chk) {
  const lbl = chk.label || chk.t;
  if (chk.t === 'ping') return { label: lbl, run: c => { if (chk.wait) c.wait(chk.wait); return c.ping(chk.from, chk.to); } };
  if (chk.t === 'noping') return { label: lbl, run: c => { if (chk.wait) c.wait(chk.wait); return !c.ping(chk.from, chk.to, 2); } };
  if (chk.t === 'http') return { label: lbl, run: c => { const r = c.http(chk.from, chk.url); if (!r) return false; return chk.contains ? JSON.stringify(r).toLowerCase().includes(String(chk.contains).toLowerCase()) : true; } };
  if (chk.t === 'cli') {
    const re = new RegExp(chk.match, chk.flags || 'i');
    return { label: lbl, run: c => { const d = [].concat(chk.dev).map(n => c.get(n)).find(Boolean); if (!d) return false; const out = runCli(c.sim, d, chk.cmd); return chk.not ? !re.test(out) : re.test(out); } };
  }
  throw new Error('Vérification inconnue : ' + chk.t);
}

NS.checkTpFile = function (data) {
  if (!data || !Array.isArray(data.devices) || !data.tpfile) throw new Error('Ce fichier ne contient pas de TP');
  const t = data.tpfile;
  if (typeof t.title !== 'string' || !Array.isArray(t.steps) || !Array.isArray(t.checks)) throw new Error('TP incomplet (titre, étapes ou vérifications manquants)');
  t.checks.forEach(k => { if (!KINDS.includes(k.t)) throw new Error('Vérification inconnue : ' + k.t); if (k.t === 'cli') new RegExp(k.match, k.flags || 'i'); });
  return data;
};

/* Transforme un fichier chargé en « scénario » utilisable par le panneau TP. */
NS.tpFromFile = function (data) {
  NS.checkTpFile(data);
  const t = data.tpfile;
  const start = t.start || { app: data.app, v: data.v, opts: data.opts, devices: data.devices, links: data.links };
  const sc = {
    id: 'fichier:' + (t.id || 'tp'), file: true, type: t.type || 'decouverte', diff: t.diff || 1, cat: t.cat || 'Cours',
    title: safeHtml(t.title).replace(/<[^>]+>/g, ''), level: String(t.level || ''), duration: String(t.duration || ''),
    desc: String(t.desc || ''), objectives: (t.objectives || []).map(String), stepsRaw: t.steps.map(String),
    steps: t.steps.map(safeHtml),
    build(sim) { NS.loadTopology(sim, start); },
    checks: t.checks.map(compile),
    meta: t, start,
  };
  if (t.solution) sc.solve = sim => { NS.loadTopology(sim, t.solution); };
  return sc;
};

/* Représentation à enregistrer avec le plan de l'élève (le bloc tpfile voyage avec le fichier). */
NS.tpFileBlock = function (sc) { return Object.assign({}, sc.meta, { start: sc.start }); };

/* Construit un fichier de TP à partir d'un plan de départ, d'une correction et des consignes (outil auteur). */
NS.makeTpFile = function (meta, startSnap, solutionSnap) {
  const f = Object.assign({}, startSnap);
  f.tpfile = Object.assign({ v: 1 }, meta, { solution: solutionSnap });
  delete f.tpfile.start; delete f.tp;
  return f;
};
})(typeof window !== 'undefined' ? window : globalThis);
