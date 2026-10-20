/* TP « fichier » : aller-retour JSON, départ en échec, correction réussie, refus des fichiers invalides */
const { NS, Sim } = require('./helpers');
const fs = require('fs'), path = require('path'), os = require('os');
const { execFileSync } = require('child_process');
let bad = 0; const ok = (c, m) => { if (!c) { bad++; console.log('FAIL ' + m); } else console.log('ok   ' + m); };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tpc-'));
execFileSync('node', [path.join(__dirname, '..', 'tools', 'gen-tp-cours.js'), tmp], { stdio: 'pipe' });
for (const f of fs.readdirSync(tmp).filter(x => x.endsWith('.json'))) {
  const data = JSON.parse(fs.readFileSync(path.join(tmp, f), 'utf8'));
  const sc = NS.tpFromFile(data);
  const run = s => { s.runFor(3000); const c = NS.checker(s); return sc.checks.map(k => { try { return !!k.run(c); } catch (e) { return false; } }); };
  const s1 = new Sim(); sc.build(s1); const a = run(s1);
  ok(a.some(x => !x), f + ' : le départ échoue à au moins une vérification');
  sc.solve(s1); s1.runFor(4000); const b = run(s1);
  ok(b.every(Boolean), f + ' : la correction réussit tout (' + b.length + ' vérifications)');
  /* sauvegarde de progression : le bloc tpfile traverse un enregistrement */
  const snap = NS.saveTopology(s1, { tpfile: NS.tpFileBlock(sc) });
  const sc2 = NS.tpFromFile(JSON.parse(JSON.stringify(snap)));
  const s2 = new Sim(); sc2.build(s2); ok(run(s2).some(x => !x), f + ' : « Recommencer » repart bien du plan de départ');
}
ok(NS.tpSafeHtml('<img src=x onerror=1><code>a</code>') === '&lt;img src=x onerror=1&gt;<code>a</code>', 'HTML échappé hors <code>/<b>');
{ const { mk, cliRun } = require('../tools/tp-lib'); const s = new Sim(); const SW = mk(s).dev('sw-2960', 'SW', 1, 1);
  cliRun(s, SW, 'enable\nconf t\nline vty 0 15\npassword V\nlogin\nend');
  const o = NS.tpRunCli(s, SW, 'show running-config | section line vty');
  ok(/^line vty 0 15\n password 7|^line vty 0 15\n password V/.test(o) && !/FastEthernet/.test(o), 'show running-config | section filtre la sortie'); }
let threw = false; try { NS.tpFromFile({ devices: [], tpfile: { title: 'x', steps: [], checks: [{ t: 'exec' }] } }); } catch (e) { threw = true; } ok(threw, 'vérification inconnue refusée');
threw = false; try { NS.tpFromFile({ devices: [] }); } catch (e) { threw = true; } ok(threw, 'fichier sans tpfile refusé');
console.log(bad ? 'ECHECS ' + bad : 'tpfile OK'); process.exit(bad ? 1 : 0);
