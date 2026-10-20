const { mk, cliRun, hostIp } = require('../tp-lib');
module.exports = {
  file: 'TP-S08-stp.json',
  meta: {
    id: 'cours-s08-stp', type: 'decouverte', diff: 2, cat: 'Cours BTS SIO — S08', level: 'BTS SIO SISR 1re année — Bloc 2 — S08', duration: '45 min',
    title: 'S08 — Spanning Tree sur trois commutateurs en triangle',
    desc: 'Trois commutateurs reliés en triangle forment une boucle de niveau 2 : observer l\'élection du root bridge, les rôles et états des ports, puis imposer le root bridge de son choix.',
    objectives: ['Identifier le root bridge, les ports racine, désignés et bloqués', 'Expliquer l\'élection (priorité puis adresse MAC) et le choix du port bloqué', 'Imposer le root bridge et un root de secours par la priorité, puis constater la reconvergence'],
    steps: [
      'Le plan est câblé : SW1, SW2 et SW3 en triangle (SW1 fa0/1 – SW2 fa0/1, SW1 fa0/2 – SW3 fa0/1, SW2 fa0/2 – SW3 fa0/2), un PC sur fa0/3 de chaque commutateur (<code>192.168.1.11</code> à <code>.13</code>). Laissez la simulation converger une trentaine de secondes de temps simulé (<b>+1 min</b>).',
      'Sur chaque commutateur, <code>show spanning-tree</code> : repérez la ligne « This bridge is the root », la priorité (<code>32769</code> = 32768 + numéro de VLAN) et, pour chaque port, le rôle (Root, Desg, Altn) et l\'état (FWD, BLK). Quel port est bloqué ? Pourquoi celui-là ?',
      'Les PC se joignent malgré la boucle : <code>ping</code> entre PC1, PC2 et PC3. Le port bloqué empêche la tempête de diffusion mais laisse un chemin unique actif.',
      'Le root bridge par défaut est le commutateur de plus petite adresse MAC, ce qui n\'est pas un choix d\'architecture. Sur <b>SW3</b> : <code>spanning-tree vlan 1 priority 4096</code>. Attendez la reconvergence puis relisez <code>show spanning-tree</code> : SW3 est-il root ? Quel port est maintenant bloqué ?',
      'Prévoyez un root de secours : sur <b>SW2</b>, <code>spanning-tree vlan 1 priority 8192</code>. Contrôlez que SW3 reste root et que SW2 deviendrait root en cas de panne de SW3.',
      'Testez les pings puis cliquez sur « Vérifier mon travail ». Dans l\'analyseur (liaison entre deux commutateurs), filtre <code>stp</code> : lisez Root Identifier, Root Path Cost et Port identifier.'],
    checks: [
      { t: 'cli', label: 'SW3 est le root bridge du VLAN 1', dev: 'SW3', cmd: 'show spanning-tree', match: 'This bridge is the root' },
      { t: 'cli', label: 'SW3 a la priorité 4096 (affichée 4097 avec le VLAN)', dev: 'SW3', cmd: 'show spanning-tree', match: 'Bridge ID\\s+Priority\\s+4097' },
      { t: 'cli', label: 'SW2 est root de secours : priorité 8192 (affichée 8193)', dev: 'SW2', cmd: 'show spanning-tree', match: 'Bridge ID\\s+Priority\\s+8193' },
      { t: 'cli', label: 'Exactement un port est bloqué dans le triangle (sur SW1, le plus éloigné du root)', dev: 'SW1', cmd: 'show spanning-tree', match: 'Altn\\s+BLK' },
      { t: 'ping', label: 'PC1 joint PC2', from: 'PC1', to: '192.168.1.12', wait: 20000 },
      { t: 'ping', label: 'PC1 joint PC3', from: 'PC1', to: '192.168.1.13' },
      { t: 'ping', label: 'PC2 joint PC3', from: 'PC2', to: '192.168.1.13' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW1', 400, 100); dev('sw-2960', 'SW2', 220, 280); dev('sw-2960', 'SW3', 580, 280);
    [['PC1', 'SW1', 400, 20, 11], ['PC2', 'SW2', 100, 400, 12], ['PC3', 'SW3', 700, 400, 13]].forEach(([p, s, x, y, n]) => { dev('pc-win', p, x, y + (p === 'PC1' ? 0 : 0)); link(p, 'eth0', s, 'fa0/3'); hostIp(get(p), `192.168.1.${n}`, '24'); });
    link('SW1', 'fa0/1', 'SW2', 'fa0/1'); link('SW1', 'fa0/2', 'SW3', 'fa0/1'); link('SW2', 'fa0/2', 'SW3', 'fa0/2');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('SW3'), 'enable\nconf t\nspanning-tree vlan 1 priority 4096\nend');
    cliRun(sim, get('SW2'), 'enable\nconf t\nspanning-tree vlan 1 priority 8192\nend');
  },
};
