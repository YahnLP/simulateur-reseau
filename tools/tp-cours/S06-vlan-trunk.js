const { mk, cliRun, hostIp } = require('../tp-lib');
const sw = (n) => `enable
conf t
hostname ${n}
no ip domain-lookup
vlan 10
name DIRECTION
vlan 20
name COMMERCIAL
vlan 30
name INFORMATIQUE
interface fa0/1
switchport mode access
switchport access vlan 10
interface fa0/2
switchport mode access
switchport access vlan 20
interface fa0/3
switchport mode access
switchport access vlan 30
interface fa0/24
switchport mode trunk
switchport trunk allowed vlan 10,20,30
end`;
module.exports = {
  file: 'TP-S06-vlan-trunk.json',
  meta: {
    id: 'cours-s06-vlan-trunk', type: 'decouverte', diff: 2, cat: 'Cours BTS SIO — S06', level: 'BTS SIO SISR 1re année — Bloc 2 — S06', duration: '1 h',
    title: 'S06 — VLAN et trunk entre deux commutateurs',
    desc: 'Trois services (direction, commercial, informatique) répartis sur deux commutateurs : créer les VLAN, affecter les ports et configurer le trunk.',
    objectives: ['Créer 3 VLAN et affecter les ports en mode access', 'Configurer un trunk entre deux commutateurs', 'Démontrer l\'isolation entre VLAN et la communication dans un même VLAN à travers le trunk'],
    steps: [
      'Le plan est câblé et les PC sont adressés (VLAN 10 : <code>192.168.10.0/24</code>, VLAN 20 : <code>192.168.20.0/24</code>, VLAN 30 : <code>192.168.30.0/24</code>). Avant toute configuration, anticipez par écrit : <code>PC-Dir-A</code> joint-il <code>PC-Dir-B</code> ?',
      'Sur <b>SW-A</b> : créez les VLAN 10 <code>DIRECTION</code>, 20 <code>COMMERCIAL</code>, 30 <code>INFORMATIQUE</code>, puis placez <code>fa0/1</code>, <code>fa0/2</code>, <code>fa0/3</code> en mode access dans les VLAN 10, 20 et 30.',
      'Sur <b>SW-A</b> : <code>fa0/24</code> en <code>switchport mode trunk</code> et <code>switchport trunk allowed vlan 10,20,30</code>. Contrôlez avec <code>show vlan brief</code> et <code>show interfaces trunk</code>.',
      'Reproduisez la même configuration sur <b>SW-B</b> (VLAN, ports, trunk).',
      'Testez : même VLAN sur deux commutateurs (succès attendu), VLAN différents (échec attendu). Cliquez sur « Vérifier mon travail ».',
      'Analyseur sur la liaison SW-A – SW-B : filtre <code>vlan.id == 10</code> pour voir l\'étiquette 802.1Q.'],
    checks: [
      { t: 'cli', label: 'SW-A : VLAN 10 DIRECTION, 20 COMMERCIAL et 30 INFORMATIQUE existent', dev: 'SW-A', cmd: 'show vlan brief', match: '10\\s+DIRECTION[\\s\\S]*20\\s+COMMERCIAL[\\s\\S]*30\\s+INFORMATIQUE' },
      { t: 'cli', label: 'SW-A : fa0/1, fa0/2, fa0/3 dans les VLAN 10, 20 et 30', dev: 'SW-A', cmd: 'show vlan brief', match: '10\\s+DIRECTION.*Fa0/1[\\s\\S]*20\\s+COMMERCIAL.*Fa0/2[\\s\\S]*30\\s+INFORMATIQUE.*Fa0/3' },
      { t: 'cli', label: 'SW-A : fa0/24 est un trunk', dev: 'SW-A', cmd: 'show interfaces trunk', match: 'Fa0/24\\s+on' },
      { t: 'cli', label: 'SW-B : VLAN 10, 20 et 30 existent', dev: 'SW-B', cmd: 'show vlan brief', match: '10\\s+DIRECTION[\\s\\S]*20\\s+COMMERCIAL[\\s\\S]*30\\s+INFORMATIQUE' },
      { t: 'cli', label: 'SW-B : fa0/24 est un trunk', dev: 'SW-B', cmd: 'show interfaces trunk', match: 'Fa0/24\\s+on' },
      { t: 'ping', label: 'VLAN 10 : PC-Dir-A joint PC-Dir-B à travers le trunk', from: 'PC-Dir-A', to: '192.168.10.21', wait: 6000 },
      { t: 'ping', label: 'VLAN 20 : PC-Com-A joint PC-Com-B', from: 'PC-Com-A', to: '192.168.20.21' },
      { t: 'ping', label: 'VLAN 30 : PC-Info-A joint PC-Info-B', from: 'PC-Info-A', to: '192.168.30.21' },
      { t: 'noping', label: 'Isolation : PC-Dir-A ne joint pas PC-Info-B', from: 'PC-Dir-A', to: '192.168.30.21' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW-A', 260, 120); dev('sw-2960', 'SW-B', 600, 120);
    const rows = [['Dir', 10, 11, 21], ['Com', 20, 12, 22], ['Info', 30, 13, 23]];
    rows.forEach(([n, v], i) => { dev('pc-win', `PC-${n}-A`, 100 + i * 120, 330); dev('pc-win', `PC-${n}-B`, 500 + i * 120, 330); });
    rows.forEach(([n, v], i) => {
      link(`PC-${n}-A`, 'eth0', 'SW-A', `fa0/${i + 1}`); link(`PC-${n}-B`, 'eth0', 'SW-B', `fa0/${i + 1}`);
      hostIp(get(`PC-${n}-A`), `192.168.${v}.11`, '24', `192.168.${v}.1`); hostIp(get(`PC-${n}-B`), `192.168.${v}.21`, '24', `192.168.${v}.1`);
    });
    link('SW-A', 'fa0/24', 'SW-B', 'fa0/24');
  },
  solve(sim) { const { get } = mk(sim); cliRun(sim, get('SW-A'), sw('SW-A')); cliRun(sim, get('SW-B'), sw('SW-B')); },
};
