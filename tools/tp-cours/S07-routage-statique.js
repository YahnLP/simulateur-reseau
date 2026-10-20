const { mk, cliRun, hostIp } = require('../tp-lib');
module.exports = {
  file: 'TP-S07-routage-statique.json',
  meta: {
    id: 'cours-s07-routage-statique', type: 'decouverte', diff: 2, cat: 'Cours BTS SIO — S07', level: 'BTS SIO SISR 1re année — Bloc 2 — S07', duration: '1 h',
    title: 'S07 — Deux réseaux reliés par un routeur : routes statiques',
    desc: 'Les réseaux Informatique (192.168.10.0/24) et Direction (192.168.20.0/24) sont reliés par une liaison WAN 10.0.0.0/30 : configurer les interfaces des deux routeurs et les routes statiques.',
    objectives: ['Adresser les interfaces LAN et WAN des routeurs', 'Écrire une route statique vers un réseau distant', 'Lire la table de routage (codes C et S) et valider la connectivité inter-réseaux'],
    steps: [
      'Le plan est câblé et les PC sont adressés (passerelles .1). La liaison WAN utilise ici le port <code>gi0/1</code> des deux routeurs (le simulateur n\'a pas de port série ; sur matériel, c\'est <code>Se0/0/0</code>). Anticipez : <code>PC-INFO-01</code> joint-il <code>PC-DIR-01</code> avant toute configuration ?',
      'Sur <b>R1_INFO</b> : <code>gi0/0</code> en <code>192.168.10.1/24</code>, <code>gi0/1</code> (WAN) en <code>10.0.0.1/30</code>, <code>no shutdown</code> sur les deux, <code>description</code> sur chacune.',
      'Sur <b>R2_DIR</b> : <code>gi0/0</code> en <code>192.168.20.1/24</code>, <code>gi0/1</code> (WAN) en <code>10.0.0.2/30</code>, <code>no shutdown</code>.',
      'Vérifiez avec <code>show ip interface brief</code> et <code>show ip route</code> : seules les routes connectées (code C) apparaissent. Testez : <code>ping 10.0.0.2</code> depuis R1 fonctionne, mais un PC ne joint pas l\'autre réseau.',
      'Ajoutez les routes statiques : sur R1, <code>ip route 192.168.20.0 255.255.255.0 10.0.0.2</code> ; sur R2, <code>ip route 192.168.10.0 255.255.255.0 10.0.0.1</code>. Relisez <code>show ip route</code> (code S).',
      'Testez de bout en bout puis cliquez sur « Vérifier mon travail ». Dans l\'analyseur, observez le TTL d\'un ping qui traverse les deux routeurs.'],
    checks: [
      { t: 'cli', label: 'R1_INFO : interfaces gi0/0 et gi0/1 configurées et actives', dev: 'R1_INFO', cmd: 'show ip interface brief', match: 'GigabitEthernet0/0\\s+192\\.168\\.10\\.1\\s.*up\\s+up\\s*\\nGigabitEthernet0/1\\s+10\\.0\\.0\\.1\\s.*up\\s+up' },
      { t: 'cli', label: 'R2_DIR : interfaces gi0/0 et gi0/1 configurées et actives', dev: 'R2_DIR', cmd: 'show ip interface brief', match: 'GigabitEthernet0/0\\s+192\\.168\\.20\\.1\\s.*up\\s+up\\s*\\nGigabitEthernet0/1\\s+10\\.0\\.0\\.2\\s.*up\\s+up' },
      { t: 'cli', label: 'R1_INFO : route statique vers 192.168.20.0/24 via 10.0.0.2', dev: 'R1_INFO', cmd: 'show ip route', match: 'S\\s+192\\.168\\.20\\.0/24.*10\\.0\\.0\\.2' },
      { t: 'cli', label: 'R2_DIR : route statique vers 192.168.10.0/24 via 10.0.0.1', dev: 'R2_DIR', cmd: 'show ip route', match: 'S\\s+192\\.168\\.10\\.0/24.*10\\.0\\.0\\.1' },
      { t: 'ping', label: 'R1_INFO joint R2_DIR sur le lien WAN', from: 'R1_INFO', to: '10.0.0.2' },
      { t: 'ping', label: 'PC-INFO-01 joint PC-DIR-01', from: 'PC-INFO-01', to: '192.168.20.11' },
      { t: 'ping', label: 'PC-DIR-02 joint PC-INFO-02', from: 'PC-DIR-02', to: '192.168.10.12' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-1941', 'R1_INFO', 200, 250); dev('r-1941', 'R2_DIR', 600, 250); dev('sw-2960', 'SW-INFO', 200, 130); dev('sw-2960', 'SW-DIR', 600, 130);
    [['PC-INFO-01', 'SW-INFO', 1, '10', 11, 100], ['PC-INFO-02', 'SW-INFO', 2, '10', 12, 300], ['PC-DIR-01', 'SW-DIR', 1, '20', 11, 500], ['PC-DIR-02', 'SW-DIR', 2, '20', 12, 700]].forEach(([n, s, p, net, h, x]) => {
      dev('pc-win', n, x, 20); link(n, 'eth0', s, `fa0/${p}`); hostIp(get(n), `192.168.${net}.${h}`, '24', `192.168.${net}.1`);
    });
    link('SW-INFO', 'fa0/24', 'R1_INFO', 'gi0/0'); link('SW-DIR', 'fa0/24', 'R2_DIR', 'gi0/0'); link('R1_INFO', 'gi0/1', 'R2_DIR', 'gi0/1');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('R1_INFO'), `enable
conf t
interface gi0/0
description LAN Informatique 192.168.10.0/24
ip address 192.168.10.1 255.255.255.0
no shutdown
interface gi0/1
description WAN vers R2_DIR
ip address 10.0.0.1 255.255.255.252
no shutdown
exit
ip route 192.168.20.0 255.255.255.0 10.0.0.2
end`);
    cliRun(sim, get('R2_DIR'), `enable
conf t
interface gi0/0
description LAN Direction 192.168.20.0/24
ip address 192.168.20.1 255.255.255.0
no shutdown
interface gi0/1
description WAN vers R1_INFO
ip address 10.0.0.2 255.255.255.252
no shutdown
exit
ip route 192.168.10.0 255.255.255.0 10.0.0.1
end`);
  },
};
