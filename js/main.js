/* main.js — démarrage : barre d'outils, dock (analyseur/journal), fichiers, TP, aide */
(function () {
'use strict';
const NS = window.NS; const { h, $, $$, clear, ui } = NS;
const app = window.__app = new NS.App();
const sim = app.sim;
const LS = 'simreseau.v1';

app.init();
/* type de câble */
NS.CABLES.forEach(c => $('#cabtype').appendChild(h('option', { value: c.id, title: c.desc }, c.label + ' — ' + c.desc)));
$('#cabtype').addEventListener('change', e => { app.cableType = e.target.value; });
$$('.tool').forEach(b => b.addEventListener('click', () => app.setTool(b.dataset.tool)));

/* ------------------------------------------------ simulation */
const spd = $('#speed');
const setSpeed = () => { app.speed = 0.5 * Math.pow(100, spd.value / 100); $('#speedv').textContent = '×' + (app.speed < 10 ? app.speed.toFixed(1).replace('.0', '') : Math.round(app.speed)); };
spd.value = 50; spd.addEventListener('input', setSpeed); setSpeed();
$('#btn-run').addEventListener('click', () => app.toggleRun());
$('#btn-step').addEventListener('click', () => { if (app.running) app.toggleRun(); if (!sim.stepFrame()) ui.toast('Plus aucune trame en attente', 'info'); });
$('#btn-t1').addEventListener('click', () => { sim.runFor(60000); ui.toast('Temps simulé avancé d\'une minute', 'info', 1500); });
$('#opt-strict').addEventListener('change', e => { sim.opts.strictCables = e.target.checked; sim.refreshCables(); app.refresh(); });
$('#opt-stp').addEventListener('change', e => { sim.opts.stpFast = e.target.checked; ui.toast('STP ' + (e.target.checked ? 'rapide (2 s)' : 'standard (15 s)') + ' — appliqué aux prochaines transitions', 'info'); });
$('#opt-ports').addEventListener('change', e => { app.showPorts = e.target.checked; app.dirtyTopo = true; });
$('#btn-fit').addEventListener('click', () => app.fit());
$('#halt-ok').addEventListener('click', () => app.clearHalt());

/* ------------------------------------------------ dock : analyseur + journal */
app.analyzer = NS.createAnalyzerUI(app, $('#pane-analyzer'));
const logPane = $('#pane-log'); const logBox = h('div.logpane', { style: { height: '100%', overflow: 'auto', font: '12px var(--mono)', padding: '4px 8px' } });
logPane.appendChild(h('div', { style: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column' } }, h('div.wsbar', h('button', { onclick: () => clear(logBox) }, 'Effacer'), h('span.muted', 'Événements des équipements (ACL, port-security, pare-feu, DHCP…)')), logBox));
sim.on('log', e => {
  const near = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 30;
  logBox.appendChild(h('div', { style: { color: e.lvl === 'warn' ? '#b45309' : e.lvl === 'err' ? '#b91c1c' : '#334155' } }, '[' + (e.t / 1000).toFixed(3) + '] ' + (e.dev ? e.dev.name + ' : ' : '') + e.msg));
  while (logBox.childNodes.length > 600) logBox.removeChild(logBox.firstChild); if (near) logBox.scrollTop = logBox.scrollHeight;
});
app.dockShow = tab => { $$('.dtab').forEach(b => b.classList.toggle('on', b.dataset.dock === tab)); $('#pane-analyzer').style.display = tab === 'analyzer' ? '' : 'none'; $('#pane-log').style.display = tab === 'log' ? '' : 'none'; $('#dock').classList.remove('min'); $('#dockmin').textContent = '▾'; if (tab === 'analyzer') app.analyzer.refresh(); };
$$('.dtab').forEach(b => b.addEventListener('click', () => app.dockShow(b.dataset.dock)));
$('#dockmin').addEventListener('click', () => { const d = $('#dock'); d.classList.toggle('min'); $('#dockmin').textContent = d.classList.contains('min') ? '▴' : '▾'; });
$('#dockmax').addEventListener('click', () => { const d = $('#dock'); d.classList.remove('min'); const big = d.dataset.big === '1'; d.style.height = big ? '' : Math.round(innerHeight * 0.72) + 'px'; d.dataset.big = big ? '0' : '1'; });
(function grip() { const gp = $('#dockgrip'), dock = $('#dock'); let y0 = null, h0 = 0; gp.addEventListener('mousedown', e => { y0 = e.clientY; h0 = dock.offsetHeight; e.preventDefault(); }); window.addEventListener('mousemove', e => { if (y0 === null) return; dock.style.height = Math.max(120, Math.min(innerHeight - 200, h0 + (y0 - e.clientY))) + 'px'; }); window.addEventListener('mouseup', () => { y0 = null; }); })();
$$('.rtab').forEach(b => b.addEventListener('click', () => { $$('.rtab').forEach(x => x.classList.toggle('on', x === b)); $('#inspector').style.display = b.dataset.r === 'insp' ? '' : 'none'; $('#tppane').style.display = b.dataset.r === 'tp' ? '' : 'none'; }));
const showRight = r => $$('.rtab').find(b => b.dataset.r === r).click();

/* ------------------------------------------------ fichiers */
function snapshot() { return NS.saveTopology(sim, { tp: app.tpCurrent ? app.tpCurrent.id : null }); }
function autosave() { try { localStorage.setItem(LS, JSON.stringify(snapshot())); } catch (e) { } }
function loadData(d, quiet) {
  try { closeAllDev(); NS.loadTopology(sim, d); app.sel = null; app.tpCurrent = SCbyId(d.tp); renderTp(); $('#opt-strict').checked = !!sim.opts.strictCables; $('#opt-stp').checked = !!sim.opts.stpFast; app.refresh(); app.fit(); if (app.analyzer) { app.analyzer.clear(); app.analyzer.fillLinks(); } if (!quiet) ui.toast('Plan chargé', 'ok'); }
  catch (e) { ui.toast('Fichier invalide : ' + e.message, 'err'); console.error(e); }
}
function closeAllDev() { ui.closeAllWindows(); sim.devices.forEach(d => { d._sess = null; d._termApi = null; d._termBanner = false; }); }
function resetAll() { closeAllDev(); NS.clearTopology(sim); app.sel = null; app.tpCurrent = null; renderTp(); app.clearHalt(); app.refresh(); if (app.analyzer) { app.analyzer.clear(); app.analyzer.fillLinks(); } }
$('#btn-new').addEventListener('click', () => { const go = () => { resetAll(); app.fit(); autosave(); }; if (sim.devices.size) ui.confirmBox('Nouveau plan', 'Effacer le plan actuel ? (le plan courant est déjà sauvegardé automatiquement dans ce navigateur, mais pas exporté)', go); else go(); });
let saveHandle = null;
async function saveAs(forcePicker) {
  const data = JSON.stringify(snapshot(), null, 1);
  if (window.showSaveFilePicker) {
    try {
      const handle = (!forcePicker && saveHandle) ? saveHandle : await window.showSaveFilePicker({ suggestedName: 'reseau.json', types: [{ description: 'Plan réseau (JSON)', accept: { 'application/json': ['.json'] } }] });
      const w = await handle.createWritable(); await w.write(data); await w.close();
      saveHandle = handle; ui.toast('Plan enregistré (' + handle.name + ')', 'ok'); return;
    } catch (e) { if (e && e.name === 'AbortError') return; /* API indisponible ou refusée : repli ci-dessous */ }
  }
  const b = new Blob([data], { type: 'application/json' }); const a = h('a', { href: URL.createObjectURL(b), download: 'reseau.json' }); document.body.appendChild(a); a.click(); a.remove(); ui.toast('Plan enregistré (reseau.json)', 'ok');
}
$('#btn-save').addEventListener('click', () => saveAs(false));
$('#btn-save').addEventListener('contextmenu', e => { e.preventDefault(); saveAs(true); });
$('#btn-open').addEventListener('click', () => $('#filein').click());
$('#filein').addEventListener('change', e => { const f = e.target.files[0]; if (!f) return; const r = new FileReader(); r.onload = () => { try { loadData(JSON.parse(r.result)); } catch (x) { ui.toast('Fichier illisible', 'err'); } }; r.readAsText(f); e.target.value = ''; });
setInterval(() => { if (sim.devices.size) autosave(); }, 5000); window.addEventListener('beforeunload', autosave);
app.onChange = () => { autosave(); };

/* ------------------------------------------------ TP */
const SCbyId = id => NS.SCENARIOS.find(s => s.id === id) || null;
const DIFF_LABEL = { 1: 'Facile', 2: 'Intermédiaire', 3: 'Avancé' };
function diffStars(n) { n = n || 1; return '★'.repeat(n) + '☆'.repeat(3 - n); }
function diffText(n) { return diffStars(n) + ' ' + (DIFF_LABEL[n] || DIFF_LABEL[1]); }
function startScenario(sc) {
  const go = () => {
    resetAll(); sim.opts.strictCables = false; $('#opt-strict').checked = false;
    try { sc.build(sim); } catch (e) { ui.toast('Erreur de construction du TP : ' + e.message, 'err'); console.error(e); return; }
    app.tpCurrent = sc; renderTp(); showRight('tp'); app.refresh(); app.fit(); sim.runFor(2000); autosave();
    ui.toast('TP chargé : ' + sc.title, 'ok');
  };
  if (sim.devices.size) ui.confirmBox('Charger un TP', 'Le plan actuel sera remplacé. Continuer ?', go); else go();
}
function renderTp() {
  const box = $('#tppane'); clear(box); const sc = app.tpCurrent;
  if (!sc) { box.appendChild(h('div', h('h3', 'Aucun TP chargé'), h('p.muted', 'Utilisez « TP d\'exemple » en haut de l\'écran pour charger un sujet avec sa topologie de départ, ses étapes, une correction et des vérifications automatiques.'))); return; }
  const res = h('div.tpres');
  box.appendChild(h('div.tp', h('h3', sc.title), h('span.lvl', sc.level + ' · ' + sc.duration + ' · ' + diffText(sc.diff)), h('p', sc.desc),
    (sc.cat === 'Cybersécurité' ? h('div.legal', h('b', '⚠ Cadre légal — à lire avant de commencer. '),
      'Les techniques présentées dans ce TP (scan, usurpation ARP, saturation de commutateur, serveur DHCP non autorisé…) ne s\'exécutent ici que sur des équipements simulés, isolés de tout réseau réel. ',
      'En France, accéder ou se maintenir sans autorisation dans un système informatique, l\'entraver ou y introduire, modifier ou supprimer des données sont des délits pénaux (articles ',
      h('a', { href: 'https://www.legifrance.gouv.fr/codes/section_lc/LEGITEXT6000000707722/LEGISCTA000006165314/', target: '_blank', rel: 'noopener' }, '323-1 à 323-3-1 du code pénal'),
      ', jusqu\'à 5 ans d\'emprisonnement et 150 000 € d\'amende, davantage sur un système d\'un opérateur d\'importance vitale). ',
      'Reproduire ces manipulations sur un réseau, un poste ou un service que vous ne possédez pas et pour lequel vous n\'avez pas d\'autorisation écrite est strictement interdit, y compris « pour tester » ou « par curiosité ». Ce TP reste un support pédagogique de compréhension et de défense, pas un mode d\'emploi.') : null),
    h('h4', 'Objectifs'), h('ul', sc.objectives.map(o => h('li', o))), h('h4', 'Déroulé'), h('ol', sc.steps.map(s => h('li', { html: s }))),
    h('div.btns', h('button.primary', { onclick: () => { res.textContent = 'Vérification en cours…'; setTimeout(() => runChecks(sc, res), 20); } }, '✔ Vérifier mon travail'), sc.solve ? h('button', { onclick: () => ui.confirmBox('Correction', 'Appliquer la configuration corrigée ? Votre travail sera écrasé.', () => { sc.solve(sim); app.refresh(); ui.toast('Correction appliquée', 'ok'); }) }, 'Charger la correction') : h('span.muted.small', 'Pas de correction automatique : ce TP est un TP d\'observation.'), h('button', { onclick: () => startScenarioNow(sc) }, 'Recommencer')), res));
}
function startScenarioNow(sc) { ui.confirmBox('Recommencer', 'Repartir de la topologie de départ ?', () => { const keep = sim.devices.size; resetAll(); sc.build(sim); app.tpCurrent = sc; renderTp(); app.refresh(); app.fit(); sim.runFor(2000); }); }
function runChecks(sc, res) {
  clear(res); const c = NS.checker(sim); let okN = 0;
  sc.checks.forEach(k => { let ok = false; try { ok = !!k.run(c); } catch (e) { console.error(e); } if (ok) okN++; res.appendChild(h('div.check', { style: { borderColor: ok ? '#86efac' : '#fca5a5' } }, (ok ? '✔ ' : '✖ ') + k.label)); });
  res.insertBefore(h('p', { style: { fontWeight: 600, color: okN === sc.checks.length ? '#166534' : '#92400e' } }, okN + ' / ' + sc.checks.length + ' vérifications réussies'), res.firstChild);
  app.refresh();
}
$('#btn-scen').addEventListener('click', () => {
  const cats = []; NS.SCENARIOS.forEach(sc => { const c = sc.cat || 'Réseau'; if (!cats.includes(c)) cats.push(c); });
  const catSel = h('select', cats.map(c => h('option', { value: c }, c)));
  const tpSel = h('select');
  const info = h('div.tp-preview');
  function fillTp() {
    clear(tpSel);
    NS.SCENARIOS.filter(sc => (sc.cat || 'Réseau') === catSel.value).forEach(sc => tpSel.appendChild(h('option', { value: sc.id }, diffStars(sc.diff) + ' ' + sc.title)));
    updateInfo();
  }
  function updateInfo() {
    const sc = SCbyId(tpSel.value); clear(info);
    if (sc) info.appendChild(h('p.muted', h('b', diffText(sc.diff) + ' · ' + sc.level + ' · ' + sc.duration), h('br'), sc.desc));
  }
  catSel.addEventListener('change', fillTp); tpSel.addEventListener('change', updateInfo);
  fillTp();
  ui.modal('TP d\'exemple', [ui.field('Section', catSel), ui.field('Sujet', tpSel), info],
    [{ label: 'Annuler' }, { label: 'Charger', primary: true, fn: () => { const sc = SCbyId(tpSel.value); if (sc) startScenario(sc); } }]);
});

/* ------------------------------------------------ aide / couverture / fiches */
function helpModal(first) {
  const cov = NS.COVERAGE; const ST = { ok: ['✔ simulé', 'st-ok'], part: ['◐ partiel', 'st-part'], no: ['○ prévu', 'st-no'] };
  const t = ui.tabs([
    { id: 'use', label: 'Prise en main', render: () => h('div', { style: { maxWidth: '760px' } },
      h('h4', 'Dessiner un réseau'), h('ul', h('li', 'Cliquez un équipement dans la palette (ou glissez-le) puis cliquez sur le plan.'), h('li', 'Outil Câble (C) : cliquez un équipement, choisissez le port, cliquez le second équipement. Types : auto, droit, croisé, fibre. Option « Câbles stricts » : un mauvais câble empêche le lien de monter.'), h('li', 'Double-clic sur un équipement : terminal, configuration, services, navigateur, fiche technique. Clic droit : menu.'), h('li', 'Molette : zoom. Glisser le fond : déplacer. Suppr : supprimer la sélection.')),
      h('h4', 'Analyser les trames'), h('ul', h('li', 'Les paquets colorés qui glissent sur les câbles sont de vraies trames (octets réels). Couleurs : ARP jaune, ICMP rose, TCP violet, UDP bleu.'), h('li', 'Analyseur (bas) : choisissez la liaison, utilisez un filtre d\'affichage comme dans Wireshark (<code>ip.addr == 10.0.0.1 && tcp.port == 80</code>, <code>dns</code>, <code>icmp.type == 8</code>, <code>http contains "GET"</code>…), cliquez un paquet pour le décoder ; cliquez un champ pour surligner ses octets.'), h('li', 'Clic droit sur un câble → « Analyser cette liaison ». « Exporter .pcap » produit un fichier ouvrable dans Wireshark.'), h('li', 'Mode pas à pas : ⏸ Pause puis ⏭ Trame avance jusqu\'à la prochaine trame reçue.')),
      h('h4', 'Terminaux'), h('p', 'Postes Windows (ipconfig, ping, tracert, nslookup, arp, netstat, curl, telnet, ssh), Linux (ip, ping, traceroute, dig, curl, ss…), routeurs et switches Cisco IOS (Tab pour compléter, ? pour l\'aide, abréviations acceptées). Ctrl+C interrompt un ping.'),
      h('h4', 'Raccourcis'), h('p', 'V sélection · C câble · X suppression · Espace pause/lecture · Échap annuler')) },
    { id: 'cov', label: 'Couverture du programme', render: () => h('div', h('p.muted', cov.note),
      h('table.cov', h('tr', h('th', 'Thème'), h('th', 'CIEL'), h('th', 'SIO'), h('th', 'État'), h('th', 'TP'), h('th', 'Remarque')), cov.rows.map(r => h('tr', h('td', r[0]), h('td', r[1]), h('td', r[2]), h('td', { class: ST[r[3]][1] }, ST[r[3]][0]), h('td', r[4]), h('td', r[5])))),
      h('p.small', 'Références : ', cov.sources.map(s => h('span', h('a', { href: s[1], target: '_blank', rel: 'noopener' }, s[0]), ' · ')))) },
    { id: 'prod', label: 'Produits et fiches', render: () => h('div', h('p.muted', '✔ = caractéristiques relevées sur la fiche constructeur (source indiquée). ≈ = valeurs typiques ou indicatives : à vérifier sur la fiche du produit réel.'),
      h('table.cov', h('tr', h('th', 'Équipement'), h('th', 'Catégorie'), h('th', 'Fiche'), h('th', 'Source')), NS.CAT_ORDER.flatMap(c => Object.keys(NS.CATALOG).filter(k => NS.CATALOG[k].cat === c).map(k => { const m = NS.CATALOG[k]; return h('tr', h('td', m.label), h('td', m.cat), h('td', m.ok ? '✔ constructeur' : '≈ typique'), h('td', m.source || '—')); })))) },
  ], { first: first || 'use' });
  ui.modal('Aide', h('div', { style: { width: 'min(860px,86vw)', height: '62vh', display: 'flex' } }, t), [{ label: 'Fermer' }]);
}
$('#btn-help').addEventListener('click', () => helpModal());
app.help = helpModal;

/* ------------------------------------------------ restauration / accueil */
let restored = false;
try { const raw = localStorage.getItem(LS); if (raw) { const d = JSON.parse(raw); if (d && d.devices && d.devices.length) { loadData(d, true); restored = true; } } } catch (e) { }
renderTp();
if (!restored) { app.fit(); setTimeout(() => ui.toast('Bienvenue ! Chargez un « TP d\'exemple » ou glissez des équipements depuis la palette.', 'info', 6000), 400); }
})();
