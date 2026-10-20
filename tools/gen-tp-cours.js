/* Génère les TP de cours (fichiers .json ouvrables dans le simulateur) :  node tools/gen-tp-cours.js <dossier> [filtre] */
const fs = require('fs'), path = require('path');
const { NS, Sim, mk } = require('./tp-lib');
const out = process.argv[2]; const only = process.argv[3];
if (!out) { console.error('usage : node tools/gen-tp-cours.js <dossier> [filtre]'); process.exit(2); }
fs.mkdirSync(out, { recursive: true });
const dir = path.join(__dirname, 'tp-cours'); let bad = 0;
for (const f of fs.readdirSync(dir).filter(x => x.endsWith('.js') && (!only || x.includes(only))).sort()) {
  const spec = require(path.join(dir, f));
  const sim = new Sim(); spec.build(sim); sim.runFor(3000);
  const start = NS.saveTopology(sim);
  /* vérification : avant la correction il y a des échecs, après tout est réussi */
  const sc0 = NS.tpFromFile(NS.makeTpFile(spec.meta, start, start));
  const run = (s) => { const c = NS.checker(s); return sc0.checks.map(k => { try { return !!k.run(c); } catch (e) { return 'ERR ' + e.message; } }); };
  const before = run(sim);
  spec.solve(sim); sim.runFor(4000);
  const solution = NS.saveTopology(sim);
  const after = run(sim);
  const ok = after.every(x => x === true) && before.some(x => x !== true);
  if (!ok) bad++;
  const file = NS.makeTpFile(spec.meta, start, solution);
  fs.writeFileSync(path.join(out, spec.file), JSON.stringify(file));
  console.log((ok ? 'OK   ' : 'ECHEC') + ' ' + spec.file + ' avant=' + before.map(x => x === true ? 1 : x === false ? 0 : x).join('') + ' après=' + after.map(x => x === true ? 1 : x === false ? 0 : x).join('') + ' ' + (JSON.stringify(file).length / 1024).toFixed(0) + ' Ko');
}
process.exit(bad ? 1 : 0);
