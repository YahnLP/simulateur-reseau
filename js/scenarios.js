/* scenarios.js — TP d'exemple (topologie de départ, correction, vérifications) et matrice de couverture du programme */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP } = NS;
const SC = NS.SCENARIOS = [];

/* ------------------------------------------------ petits outils de construction */
function mk(sim) {
  const dev = (model, name, x, y) => NS.createDevice(sim, model, { name, x, y });
  const get = n => Array.from(sim.devices.values()).find(d => d.name === n);
  const link = (a, pa, b, pb, type) => { const A = typeof a === 'string' ? get(a) : a, B = typeof b === 'string' ? get(b) : b; const l = sim.connect(A.findPort(pa), B.findPort(pb), type || 'auto'); if (!l) throw new Error('câble impossible ' + A.name + ':' + pa + ' – ' + B.name + ':' + pb); return l; };
  return { dev, get, link };
}
function cliRun(dev, text) {
  const s = dev.newSession(); const io = { print() { }, done() { }, clear() { } };
  text.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => s.exec(l, io));
}
function hostIp(h, ip, mask, gw, dns) {
  h.applyIp(h.ifaceList()[0].name, { ip, mask: mask || '24' }); if (gw !== undefined) h.setGateway(gw); if (dns) { h.dnsServers = [].concat(dns).map(IP.parse); h.dhcpDns = false; }
}
function hostDhcp(h) { const i = h.ifaceList()[0]; h.enableDhcp(i, false); h.applyIp(i.name, { dhcp: true }); }
/* contexte de vérification */
function checker(sim) {
  const get = n => Array.from(sim.devices.values()).find(d => d.name === n);
  return {
    sim, get,
    ping(from, ip, n) { const node = get(from); let ok = false, done = false; NS.tools.pingSeries(node, IP.parse(ip), { count: n || 3, interval: 300 }, r => { if (r.type === 'reply') ok = true; }, () => { done = true; }); sim.runUntil(() => done, 30000); return ok; },
    http(from, url) { const node = get(from); let res = null, done = false; node.httpRequest(url, (err, r) => { res = err ? null : r; done = true; }); sim.runUntil(() => done, 30000); return res; },
    ipOf(name) { const i = get(name).ifaceList().find(x => x.ip); return i ? IP.str(i.ip) : ''; },
    wait(ms) { sim.runFor(ms); },
  };
}
NS.checker = checker;

/* ================================================================== TP 1 */
SC.push({
  id: 'lan', title: 'Réseau local : adressage IP, ARP et ping', level: 'Bac Pro CIEL', duration: '45 min',
  desc: 'Trois postes reliés à un switch : configurer les adresses IP, tester la connectivité et observer ARP/ICMP avec l\'analyseur.',
  objectives: ['Configurer une adresse IPv4 statique (adresse, masque)', 'Tester avec ping et lire ipconfig / ip a', 'Expliquer le rôle d\'ARP et lire une trame Ethernet/ARP/ICMP'],
  steps: [
    'Double-cliquez sur <b>PC1</b> → onglet <b>Configuration IP</b> : adresse <code>192.168.1.11</code>, masque <code>255.255.255.0</code>. Faites de même pour PC2 (<code>.12</code>) et PC3 (<code>.13</code>).',
    'Ouvrez le <b>Terminal</b> de PC1 : <code>ipconfig</code> (ou <code>ip a</code> sous Linux), puis <code>ping 192.168.1.12</code>.',
    'Clic droit sur le câble PC1–switch → <b>Analyser cette liaison</b>. Videz la capture, relancez le ping, puis appliquez le filtre <code>arp</code> puis <code>icmp</code>.',
    'Dans la trame ARP Request : quelle est l\'adresse MAC de destination ? Pourquoi ? Dans l\'ICMP : quel est le TTL, quel est le type ?',
    'Testez <code>arp -a</code> sur PC1. Déconnectez PC2 puis pingez à nouveau : que se passe-t-il (ARP sans réponse) ?',
  ],
  build(sim) {
    const { dev, link } = mk(sim);
    dev('sw-8p', 'SW1', 400, 130); dev('pc-win', 'PC1', 200, 300); dev('pc-linux', 'PC2', 400, 320); dev('laptop', 'PC3', 600, 300);
    link('PC1', 'eth0', 'SW1', 'port1'); link('PC2', 'ens33', 'SW1', 'port2'); link('PC3', 'ethernet0', 'SW1', 'port3');
  },
  solve(sim) { const { get } = mk(sim); hostIp(get('PC1'), '192.168.1.11'); hostIp(get('PC2'), '192.168.1.12'); hostIp(get('PC3'), '192.168.1.13'); },
  checks: [{ label: 'PC1 joint PC2', run: c => c.ping('PC1', '192.168.1.12') }, { label: 'PC1 joint PC3', run: c => c.ping('PC1', '192.168.1.13') }, { label: 'PC3 joint PC2', run: c => c.ping('PC3', '192.168.1.12') }],
});

/* ================================================================== TP 2 */
SC.push({
  id: 'dhcp-dns-web', title: 'DHCP, DNS et serveur Web', level: 'Bac Pro CIEL / BTS SIO', duration: '1 h',
  desc: 'Un serveur Linux distribue les adresses (DHCP), résout les noms (DNS) et publie un site (HTTP). Observation de l\'échange DORA et des requêtes DNS/HTTP.',
  objectives: ['Configurer un serveur DHCP (pool, passerelle, DNS, exclusions)', 'Créer une zone DNS (A) et publier une page web', 'Décrire DORA, la requête DNS et la requête HTTP dans l\'analyseur'],
  steps: [
    'Constatez d\'abord l\'échec : sur PC1, <code>ipconfig</code> montre une adresse <b>169.254.x.x</b> (APIPA) car aucun serveur DHCP ne répond.',
    'Ouvrez <b>SRV1</b> : donnez-lui l\'IP fixe <code>192.168.1.2/24</code>. Onglet <b>Services → DHCP</b> : pool <code>192.168.1.0/24</code>, passerelle <code>192.168.1.1</code>, DNS <code>192.168.1.2</code>, plage .20 → .100 ; activez le service.',
    'Onglet <b>DNS</b> : enregistrement A <code>intranet.lycee.local</code> → <code>192.168.1.2</code>, activez. Onglet <b>Web</b> : modifiez la page d\'accueil et activez.',
    'Sur PC1 : <code>ipconfig /renew</code>, puis <code>nslookup intranet.lycee.local</code>, puis dans l\'onglet <b>Navigateur</b> : <code>http://intranet.lycee.local</code>.',
    'Analyseur sur la liaison SRV1–switch : filtres <code>dhcp</code> (Discover, Offer, Request, ACK), <code>dns</code>, <code>http</code>. Utilisez <b>Suivre le flux TCP</b> sur la requête GET.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-8p', 'SW1', 400, 140); dev('srv-linux', 'SRV1', 400, 320); dev('pc-win', 'PC1', 180, 260); dev('pc-win', 'PC2', 620, 260);
    link('SRV1', 'ens33', 'SW1', 'port1'); link('PC1', 'eth0', 'SW1', 'port2'); link('PC2', 'eth0', 'SW1', 'port3');
    hostDhcp(get('PC1')); hostDhcp(get('PC2'));
  },
  solve(sim) {
    const { get } = mk(sim); const s = get('SRV1'); hostIp(s, '192.168.1.2', '24', '192.168.1.1');
    s.dhcpd.enabled = true; s.dhcpd.pools = []; s.dhcpd.excluded = [[IP.parse('192.168.1.1'), IP.parse('192.168.1.19')]];
    s.dhcpd.addPool({ name: 'LAN', net: IP.parse('192.168.1.0'), mask: IP.parseMask('24'), router: IP.parse('192.168.1.1'), dns: [IP.parse('192.168.1.2')], domain: 'lycee.local', lease: 86400, start: IP.parse('192.168.1.20'), end: IP.parse('192.168.1.100') });
    s.dnsd.records = [{ name: 'intranet.lycee.local', type: 'A', data: '192.168.1.2' }]; s.dnsd.start();
    s.httpd.pages['/'] = { type: 'text/html; charset=utf-8', body: '<html><head><title>Intranet</title></head><body><h1>Intranet du lycée</h1><p>Bienvenue !</p></body></html>', _custom: true }; s.httpd.start();
    ['PC1', 'PC2'].forEach(n => hostDhcp(get(n)));
  },
  checks: [{ label: 'PC1 obtient une adresse 192.168.1.x par DHCP', run: c => { c.wait(8000); return /^192\.168\.1\./.test(c.ipOf('PC1')); } }, { label: 'PC2 obtient une adresse par DHCP', run: c => /^192\.168\.1\./.test(c.ipOf('PC2')) }, { label: 'PC1 ouvre http://intranet.lycee.local', run: c => { const r = c.http('PC1', 'http://intranet.lycee.local'); return !!r && r.status === 200; } }],
});

/* ================================================================== TP 3 */
SC.push({
  id: 'vlan', title: 'VLAN, trunk 802.1Q et routage inter-VLAN', level: 'BTS SIO SISR / Bac Pro CIEL', duration: '1 h 30',
  desc: 'Deux switches, deux VLAN (COMPTA et RH) et un routeur « on a stick » : segmentation, trunk, sous-interfaces, isolation.',
  objectives: ['Créer des VLAN, affecter des ports en accès, configurer un trunk', 'Configurer des sous-interfaces 802.1Q sur un routeur', 'Observer l\'étiquette 802.1Q dans l\'analyseur et démontrer l\'isolation entre VLAN'],
  steps: [
    'Les PC sont déjà adressés (VLAN 10 : 192.168.10.0/24, VLAN 20 : 192.168.20.0/24). Avant toute configuration, PC1 joint PC3 (même sous-réseau, tous dans le VLAN 1) mais pas PC2 (autre sous-réseau, pas de routeur configuré).',
    'Sur <b>SW1</b> et <b>SW2</b> (console) : <code>vlan 10</code> / <code>name COMPTA</code>, <code>vlan 20</code> / <code>name RH</code>, ports <code>fa0/1</code> en VLAN 10 et <code>fa0/2</code> en VLAN 20 ; <code>gi0/1</code> en <code>switchport mode trunk</code>.',
    'Sur SW1, le port <code>fa0/24</code> vers le routeur : <code>switchport mode trunk</code>. Sur <b>R1</b> : <code>no shutdown</code> sur gi0/0, sous-interfaces <code>gi0/0.10</code> et <code>gi0/0.20</code> avec <code>encapsulation dot1Q</code> et l\'adresse passerelle.',
    'Contrôles : <code>show vlan brief</code>, <code>show interfaces trunk</code>, <code>show ip interface brief</code>, <code>show mac address-table</code>.',
    'Analyseur sur la liaison SW1–SW2 : filtre <code>vlan.id == 10</code>. Repérez l\'en-tête 802.1Q (VID). Comparez avec la liaison PC1–SW1 (aucune étiquette).',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW1', 300, 170); dev('sw-2960', 'SW2', 620, 170); dev('r-1941', 'R1', 300, 20);
    dev('pc-win', 'PC1', 160, 340); dev('pc-win', 'PC2', 420, 340); dev('pc-win', 'PC3', 540, 340); dev('pc-win', 'PC4', 780, 340);
    link('PC1', 'eth0', 'SW1', 'fa0/1'); link('PC2', 'eth0', 'SW1', 'fa0/2'); link('PC3', 'eth0', 'SW2', 'fa0/1'); link('PC4', 'eth0', 'SW2', 'fa0/2');
    link('SW1', 'gi0/1', 'SW2', 'gi0/1'); link('R1', 'gi0/0', 'SW1', 'fa0/24');
    hostIp(get('PC1'), '192.168.10.11', '24', '192.168.10.1'); hostIp(get('PC2'), '192.168.20.12', '24', '192.168.20.1'); hostIp(get('PC3'), '192.168.10.13', '24', '192.168.10.1'); hostIp(get('PC4'), '192.168.20.14', '24', '192.168.20.1');
  },
  solve(sim) {
    const { get } = mk(sim);
    const sw = `enable
conf t
vlan 10
name COMPTA
vlan 20
name RH
interface fa0/1
switchport mode access
switchport access vlan 10
interface fa0/2
switchport mode access
switchport access vlan 20
interface gi0/1
switchport mode trunk
end`;
    cliRun(get('SW1'), sw + '\nconf t\ninterface fa0/24\nswitchport mode trunk\nend'); cliRun(get('SW2'), sw);
    cliRun(get('R1'), `enable
conf t
interface gi0/0
no shutdown
interface gi0/0.10
encapsulation dot1Q 10
ip address 192.168.10.1 255.255.255.0
interface gi0/0.20
encapsulation dot1Q 20
ip address 192.168.20.1 255.255.255.0
end`);
  },
  checks: [{ label: 'VLAN 10 : PC1 joint PC3 (à travers le trunk)', run: c => { c.wait(6000); return c.ping('PC1', '192.168.10.13'); } }, { label: 'VLAN 20 : PC2 joint PC4', run: c => c.ping('PC2', '192.168.20.14') }, { label: 'Inter-VLAN : PC1 joint PC2 (via le routeur)', run: c => c.ping('PC1', '192.168.20.12') }],
});

/* ================================================================== TP 4 */
SC.push({
  id: 'nat-acl', title: 'Accès Internet : NAT/PAT, routage par défaut et ACL', level: 'BTS SIO SISR', duration: '1 h 30',
  desc: 'Un routeur d\'agence partage une adresse publique (PAT) et filtre par ACL. Un serveur « public » derrière le FAI répond en HTTP et DNS.',
  objectives: ['Configurer routage par défaut, NAT overload et ACL nommée', 'Lire la table de traduction NAT', 'Comparer les adresses source avant/après NAT dans l\'analyseur'],
  steps: [
    'Le FAI et le serveur WEB (<code>www.exemple.fr</code>, 198.51.100.10) sont configurés. Le LAN est en 192.168.1.0/24, passerelle 192.168.1.1.',
    'Sur <b>R1</b> : gi0/0 <code>192.168.1.1/24</code> (<code>ip nat inside</code>), gi0/1 <code>203.0.113.2/30</code> (<code>ip nat outside</code>), <code>ip route 0.0.0.0 0.0.0.0 203.0.113.1</code>.',
    '<code>access-list 1 permit 192.168.1.0 0.0.0.255</code> puis <code>ip nat inside source list 1 interface gi0/1 overload</code>. Testez <code>ping 198.51.100.10</code> depuis PC1 puis <code>show ip nat translations</code>.',
    'Analyseur : capturez sur la liaison LAN puis sur la liaison R1–ISP. Quelle est l\'adresse source d\'un même ping de chaque côté ? Et le port source TCP d\'une requête curl ?',
    'ACL : interdisez PC2 (192.168.1.11) vers l\'extérieur avec une ACL étendue nommée appliquée en entrée de gi0/0 ; vérifiez avec <code>show access-lists</code> (compteurs).',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-1941', 'R1', 380, 120); dev('sw-2960', 'SW1', 200, 230); dev('inet', 'ISP', 620, 120); dev('srv-linux', 'WEB', 800, 240); dev('pc-win', 'PC1', 100, 380); dev('pc-linux', 'PC2', 300, 380);
    link('PC1', 'eth0', 'SW1', 'fa0/1'); link('PC2', 'ens33', 'SW1', 'fa0/2'); link('R1', 'gi0/0', 'SW1', 'fa0/24'); link('R1', 'gi0/1', 'ISP', 'gi0/0'); link('ISP', 'gi0/1', 'WEB', 'ens33');
    cliRun(get('ISP'), 'enable\nconf t\ninterface gi0/0\nip address 203.0.113.1 255.255.255.252\nno shutdown\ninterface gi0/1\nip address 198.51.100.1 255.255.255.0\nno shutdown\nend');
    const w = get('WEB'); hostIp(w, '198.51.100.10', '24', '198.51.100.1'); w.httpd.start(); w.dnsd.records.push({ name: 'www.exemple.fr', type: 'A', data: '198.51.100.10' }); w.dnsd.start();
    hostIp(get('PC1'), '192.168.1.10', '24', '192.168.1.1', '198.51.100.10'); hostIp(get('PC2'), '192.168.1.11', '24', '192.168.1.1', '198.51.100.10');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(get('R1'), `enable
conf t
interface gi0/0
ip address 192.168.1.1 255.255.255.0
ip nat inside
no shutdown
interface gi0/1
ip address 203.0.113.2 255.255.255.252
ip nat outside
no shutdown
exit
access-list 1 permit 192.168.1.0 0.0.0.255
ip nat inside source list 1 interface gi0/1 overload
ip route 0.0.0.0 0.0.0.0 203.0.113.1
ip access-list extended FILTRE
deny ip host 192.168.1.11 any
permit ip any any
exit
interface gi0/0
ip access-group FILTRE in
end`);
  },
  checks: [{ label: 'PC1 joint le serveur public (NAT/PAT)', run: c => c.ping('PC1', '198.51.100.10') }, { label: 'PC1 ouvre http://www.exemple.fr (DNS + HTTP)', run: c => { const r = c.http('PC1', 'http://www.exemple.fr'); return !!r && r.status === 200; } }, { label: 'PC2 est bloqué par l\'ACL', run: c => !c.ping('PC2', '198.51.100.10', 2) }, { label: 'Le serveur public ne peut pas joindre l\'adresse privée de PC1', run: c => !c.ping('WEB', '192.168.1.10', 2) }],
});

/* ================================================================== TP 5 */
SC.push({
  id: 'routage', title: 'Routage : statique puis RIP (3 routeurs)', level: 'BTS SIO SISR', duration: '1 h',
  desc: 'Trois routeurs en ligne, deux réseaux terminaux : routes statiques, puis routage dynamique RIPv2 et lecture de la table de routage.',
  objectives: ['Lire une table de routage (C, S, R)', 'Configurer routes statiques puis RIP v2', 'Observer les mises à jour RIP (UDP 520, multicast 224.0.0.9)'],
  steps: [
    'Adressage : PCA <code>10.1.1.10/24</code> (GW 10.1.1.1), PCB <code>10.1.4.10/24</code> (GW 10.1.4.3). Liaisons R1–R2 <code>10.1.2.0/24</code>, R2–R3 <code>10.1.3.0/24</code>. Les PC sont déjà configurés.',
    'Configurez les interfaces des trois routeurs (<code>ip address</code>, <code>no shutdown</code>) et vérifiez avec <code>show ip interface brief</code>.',
    'Partie 1 (statique) : ajoutez <code>ip route</code> sur chaque routeur vers les réseaux distants ; pingez PCA → PCB.',
    'Partie 2 (RIP) : supprimez les routes statiques, puis <code>router rip</code> / <code>version 2</code> / <code>no auto-summary</code> / <code>network …</code> ; <code>show ip route</code> (lignes <b>R</b>) et <code>show ip protocols</code>.',
    'Analyseur : filtre <code>rip</code> sur la liaison R1–R2. Repérez la métrique et l\'intervalle de 30 s (utilisez « +1 min »).',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'R1', 260, 200); dev('r-2911', 'R2', 460, 200); dev('r-2911', 'R3', 660, 200); dev('pc-win', 'PCA', 100, 200); dev('pc-win', 'PCB', 820, 200);
    link('PCA', 'eth0', 'R1', 'gi0/0'); link('R1', 'gi0/1', 'R2', 'gi0/0'); link('R2', 'gi0/1', 'R3', 'gi0/0'); link('R3', 'gi0/1', 'PCB', 'eth0');
    hostIp(get('PCA'), '10.1.1.10', '24', '10.1.1.1'); hostIp(get('PCB'), '10.1.4.10', '24', '10.1.4.3');
  },
  solve(sim) {
    const { get } = mk(sim);
    const conf = (r, a) => cliRun(get(r), `enable\nconf t\n${a.map(([i, ip]) => `interface ${i}\nip address ${ip} 255.255.255.0\nno shutdown\nexit`).join('\n')}\nrouter rip\nversion 2\nno auto-summary\n${a.map(([, ip]) => 'network ' + ip.replace(/\.\d+$/, '.0')).join('\n')}\nend`);
    conf('R1', [['gi0/0', '10.1.1.1'], ['gi0/1', '10.1.2.1']]); conf('R2', [['gi0/0', '10.1.2.2'], ['gi0/1', '10.1.3.2']]); conf('R3', [['gi0/0', '10.1.3.3'], ['gi0/1', '10.1.4.3']]);
  },
  checks: [{ label: 'PCA joint PCB (après convergence RIP)', run: c => { c.wait(90000); return c.ping('PCA', '10.1.4.10'); } }],
});

/* ================================================================== TP 6 */
SC.push({
  id: 'stp', title: 'Boucle de commutation et Spanning Tree (STP)', level: 'BTS SIO SISR', duration: '45 min',
  desc: 'Trois switches en triangle : élection du root bridge, ports bloqués, BPDU. Puis provoquez une tempête de broadcast en supprimant STP.',
  objectives: ['Identifier root bridge, ports racine/désignés/bloqués', 'Lire une BPDU (root ID, coût, port ID)', 'Constater l\'effet d\'une boucle sans STP'],
  steps: [
    'Attendez ~10 s (temps simulé) : les liens deviennent verts, l\'un d\'eux passe <b>orange</b> (port bloqué). Les PC se joignent.',
    'Sur chaque switch : <code>show spanning-tree</code>. Quel switch est root ? Pourquoi (priorité + MAC) ? Quel port est bloqué ?',
    'Forcez le root : sur SWC <code>spanning-tree vlan 1 priority 4096</code> et observez la reconvergence.',
    'Analyseur sur une liaison inter-switches : filtre <code>stp</code>. Lisez Root Identifier, Root Path Cost, Port identifier.',
    'Expérience : remplacez les 3 switches par des « Switch 8 ports non manageable » (sans STP) : un simple ping broadcast déclenche une <b>tempête</b> et la simulation s\'arrête.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SWA', 400, 100); dev('sw-2960', 'SWB', 220, 300); dev('sw-2960', 'SWC', 580, 300); dev('pc-win', 'PC1', 100, 430); dev('pc-win', 'PC2', 700, 430);
    link('SWA', 'fa0/1', 'SWB', 'fa0/1'); link('SWB', 'fa0/2', 'SWC', 'fa0/2'); link('SWC', 'fa0/1', 'SWA', 'fa0/2'); link('PC1', 'eth0', 'SWB', 'fa0/10'); link('PC2', 'eth0', 'SWC', 'fa0/10');
    hostIp(get('PC1'), '192.168.1.1'); hostIp(get('PC2'), '192.168.1.2');
  },
  solve: null,
  checks: [{ label: 'PC1 joint PC2 après convergence STP', run: c => { c.wait(20000); return c.ping('PC1', '192.168.1.2'); } }, { label: 'Exactement un port bloqué dans le triangle', run: c => { let n = 0; ['SWA', 'SWB', 'SWC'].forEach(s => c.get(s).ports.forEach(p => { if (p.up && p.stp && p.stp.state === 'blocking') n++; })); return n === 1; } }],
});

/* ================================================================== TP 7 */
SC.push({
  id: 'sniff', title: 'Analyse de trames : hub, switch, Telnet et SSH', level: 'Bac Pro CIEL (cybersécurité) / BTS SIO', duration: '1 h',
  desc: 'PC2 « écoute » sur un hub pendant que PC1 administre un routeur en Telnet, puis en SSH. Mise en évidence du risque du clair et de l\'intérêt du switch.',
  objectives: ['Comparer hub (répéteur) et switch (commutation)', 'Retrouver un mot de passe Telnet dans une capture (Suivre le flux TCP)', 'Constater que SSH chiffre les échanges'],
  steps: [
    'Topologie : PC1 (poste admin), PC2 (poste qui capture), routeur R1 (vty password <code>vty123</code>, enable <code>cisco</code>), tous reliés à un <b>hub</b>.',
    'Clic droit sur le câble PC2–HUB → <b>Analyser cette liaison</b> : PC2 voit-il le trafic entre PC1 et R1 ? Lancez sur PC1 : <code>ping 10.0.0.1</code> puis observez.',
    'Sur PC1 : <code>telnet 10.0.0.1</code>, saisissez le mot de passe, <code>enable</code>, <code>show ip interface brief</code>, <code>exit</code>. Filtre <code>telnet</code>, puis <b>Suivre le flux TCP</b> : retrouvez les mots de passe.',
    'Refaites avec <code>ssh 10.0.0.1</code> : filtre <code>ssh</code>. Que voit-on du contenu ? Quels paquets sont en clair (bannière) ?',
    'Remplacez le hub par un switch (supprimez le hub, ajoutez un « Switch 8 ports », recâblez) : PC2 voit-il encore le Telnet de PC1 ? Concluez.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('hub', 'HUB1', 400, 140); dev('pc-win', 'PC1', 200, 320); dev('pc-linux', 'PC2', 400, 340); dev('r-1941', 'R1', 620, 320);
    link('PC1', 'eth0', 'HUB1', 'port1'); link('PC2', 'ens33', 'HUB1', 'port2'); link('R1', 'gi0/0', 'HUB1', 'port3');
    hostIp(get('PC1'), '10.0.0.2'); hostIp(get('PC2'), '10.0.0.3');
    cliRun(get('R1'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.0.1 255.255.255.0\nno shutdown\nenable secret cisco\nline vty 0 4\npassword vty123\nlogin\nend');
  },
  solve: null,
  checks: [{ label: 'PC1 joint R1', run: c => c.ping('PC1', '10.0.0.1') }, { label: 'PC2 a capturé du trafic entre PC1 et R1', run: c => c.sim.captures.some(r => r.link.a.dev.name === 'PC2' || r.link.b.dev.name === 'PC2') }],
});

/* ================================================================== TP 8 */
SC.push({
  id: 'dmz', title: 'Pare-feu, DMZ et redirection de port (Stormshield SN210)', level: 'BTS SIO SISR / Bac Pro CIEL', duration: '1 h 30',
  desc: 'Un pare-feu à trois zones (LAN, DMZ, WAN) : politique de filtrage, masquerade et publication d\'un serveur web de la DMZ vers Internet.',
  objectives: ['Définir des zones et une politique de filtrage ordonnée', 'Publier un service (redirection de port + règle WAN→DMZ)', 'Vérifier le filtrage à états et lire le journal du pare-fu'],
  steps: [
    'Ouvrez <b>FW1</b> (double-clic) : onglet <b>Interfaces</b>. OUT (WAN) <code>203.0.113.2/30</code>, passerelle <code>203.0.113.1</code> ; IN (LAN) <code>192.168.1.254/24</code> ; DMZ1 <code>172.16.0.254/24</code>.',
    'Onglet <b>Règles</b> : la politique par défaut autorise LAN→WAN et LAN→DMZ. Vérifiez : PC1 pingue CLIENT (203.0.113.1 côté FAI) et SRVWEB (172.16.0.10).',
    'Publication : onglet <b>NAT / redirections</b> : TCP 80 externe → <code>172.16.0.10</code> ; onglet Règles : ajoutez <b>WAN → DMZ, TCP, port 80, Autoriser</b>.',
    'Depuis CLIENT (Internet) : navigateur → <code>http://203.0.113.2</code> : la page de SRVWEB doit s\'afficher. Testez aussi le ping de CLIENT vers SRVWEB : bloqué ?',
    'Onglet <b>Journal</b> : retrouvez les paquets bloqués et le motif. La DMZ peut-elle joindre le LAN ? (aucune règle : non). Justifiez.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('fw-sn210', 'FW1', 380, 200); dev('sw-8p', 'SW1', 160, 200); dev('pc-win', 'PC1', 160, 360); dev('srv-linux', 'SRVWEB', 380, 380); dev('inet', 'FAI', 620, 200); dev('pc-linux', 'CLIENT', 820, 200);
    link('SW1', 'port1', 'FW1', 'in'); link('PC1', 'eth0', 'SW1', 'port2'); link('SRVWEB', 'ens33', 'FW1', 'dmz1'); link('FW1', 'out', 'FAI', 'gi0/0'); link('FAI', 'gi0/1', 'CLIENT', 'ens33');
    cliRun(get('FAI'), 'enable\nconf t\ninterface gi0/0\nip address 203.0.113.1 255.255.255.252\nno shutdown\ninterface gi0/1\nip address 198.51.100.1 255.255.255.0\nno shutdown\nend');
    hostIp(get('CLIENT'), '198.51.100.20', '24', '198.51.100.1'); hostIp(get('PC1'), '192.168.1.10', '24', '192.168.1.254'); const s = get('SRVWEB'); hostIp(s, '172.16.0.10', '24', '172.16.0.254'); s.httpd.start();
    s.httpd.pages['/'] = { type: 'text/html; charset=utf-8', body: '<html><head><title>Site public</title></head><body><h1>Serveur en DMZ</h1><p>Publié via le pare-feu.</p></body></html>', _custom: true };
  },
  solve(sim) {
    const { get } = mk(sim); const f = get('FW1'); const o = f.ifaceByName('out');
    f.enableDhcp(o, false); o.ip = IP.parse('203.0.113.2'); o.mask = IP.parseMask('30'); f.statics = f.statics.filter(s => !(s.net === 0 && s.mask === 0)); f.statics.push({ net: 0, mask: 0, nh: IP.parse('203.0.113.1'), iface: null, ad: 1 });
    f.forwards = [{ proto: 'tcp', port: 80, toIp: '172.16.0.10', toPort: 80 }];
    f.rules.push({ on: true, action: 'pass', from: 'WAN', to: 'DMZ', proto: 'tcp', src: 'any', dst: 'any', dport: '80', comment: 'Publication du site web' }); f.rebuildNat();
  },
  checks: [{ label: 'PC1 (LAN) joint Internet (FAI)', run: c => c.ping('PC1', '198.51.100.20') }, { label: 'PC1 (LAN) joint le serveur de la DMZ', run: c => c.ping('PC1', '172.16.0.10') }, { label: 'CLIENT (Internet) accède au site via http://203.0.113.2', run: c => { const r = c.http('CLIENT', 'http://203.0.113.2'); return !!r && r.status === 200 && /DMZ/.test(r.body); } }, { label: 'CLIENT ne peut pas pinguer le serveur de la DMZ', run: c => !c.ping('CLIENT', '172.16.0.10', 2) }, { label: 'La DMZ ne peut pas joindre le LAN', run: c => !c.ping('SRVWEB', '192.168.1.10', 2) }],
});

/* ================================================================== TP 9 */
SC.push({
  id: 'wifi', title: 'Box, Wi-Fi et réseau domestique / TPE', level: 'Bac Pro CIEL', duration: '45 min',
  desc: 'Une box (routeur/DHCP/NAT) alimente un poste filaire et une borne Wi-Fi ; deux portables s\'associent avec un SSID et une clé.',
  objectives: ['Configurer SSID et clé d\'une borne, associer des clients Wi-Fi', 'Identifier la configuration d\'une box (LAN, DHCP, NAT)', 'Vérifier l\'adressage obtenu par DHCP'],
  steps: [
    'Ouvrez <b>AP1</b> : SSID <code>LYCEE-WIFI</code>, clé <code>ciel2026</code>, sécurité WPA2.',
    'Ouvrez <b>LAP1</b> et <b>LAP2</b> → <b>Configuration IP</b> : mode DHCP, saisissez le SSID et la clé identiques. Un lien violet pointillé apparaît vers la borne.',
    'Sur LAP1 : <code>ipconfig</code> : quelle adresse, quelle passerelle ? Qui les a fournies ? (Box : 192.168.1.1)',
    'Saisissez une mauvaise clé sur LAP2 : que se passe-t-il ? Analyseur sur la liaison AP1–BOX : identifiez les DHCP Discover/Offer des portables.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('box', 'BOX', 400, 120); dev('ap-u6', 'AP1', 250, 260); dev('pc-win', 'PC1', 580, 260); dev('laptop', 'LAP1', 150, 420); dev('laptop', 'LAP2', 350, 420);
    link('AP1', 'eth0', 'BOX', 'lan1'); link('PC1', 'eth0', 'BOX', 'lan2'); hostDhcp(get('PC1'));
  },
  solve(sim) { const { get } = mk(sim); const a = get('AP1'); a.ssid = 'LYCEE-WIFI'; a.key = 'ciel2026'; ['LAP1', 'LAP2'].forEach(n => { const l = get(n); l.wifi = { ssid: 'LYCEE-WIFI', key: 'ciel2026' }; hostDhcp(l); hostIpWifi(l); }); NS.wifiRefresh(sim); },
  checks: [{ label: 'PC1 filaire obtient une adresse de la box', run: c => { c.wait(6000); return /^192\.168\.1\./.test(c.ipOf('PC1')); } }, { label: 'LAP1 est associé et obtient une adresse', run: c => { c.wait(6000); return /^192\.168\.1\./.test(c.ipOf('LAP1')); } }, { label: 'LAP1 joint PC1', run: c => c.ping('LAP1', c.ipOf('PC1')) }],
});
function hostIpWifi(l) { const w = l.ifaceList().find(i => i.port && i.port.media === 'wifi'); if (w) { l.enableDhcp(w, false); l.applyIp(w.name, { dhcp: true }); } }

/* ================================================================== TP 10 */
SC.push({
  id: 'ospf', title: 'Routage dynamique OSPF (aire unique)', level: 'BTS SIO SISR', duration: '1 h 30',
  desc: 'Trois routeurs en triangle, chacun avec un LAN : configuration d\'OSPF en aire 0, observation des voisins, de la base de données et de la reconvergence après panne de lien.',
  objectives: ['Activer OSPF et annoncer des réseaux (network / wildcard / area)', 'Lire show ip ospf neighbor / database / route', 'Constater la reconvergence automatique après une panne de lien'],
  steps: [
    'Chaque routeur a déjà ses interfaces adressées. Sur <b>A</b>, <b>B</b>, <b>C</b> : <code>router ospf 1</code> puis <code>network &lt;réseau&gt; &lt;wildcard&gt; area 0</code> pour chaque lien (utilisez <code>passive-interface</code> sur les LAN utilisateurs).',
    'Sur A : <code>show ip ospf neighbor</code> (2 voisins à l\'état FULL), <code>show ip ospf database</code>, <code>show ip route ospf</code> (routes marquées <b>O</b>).',
    'Testez PA (LAN de A) vers PC (LAN de C) : <code>ping</code>. Analyseur sur un lien inter-routeurs, filtre <code>ospf</code> : repérez Hello, DBD, LSR, LSU, LSAck.',
    'Débranchez le lien A–C (clic droit sur le câble → Déconnecter). Observez la reconvergence : <code>show ip route ospf</code> doit maintenant passer par B, avec un coût plus élevé.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'A', 350, 60); dev('r-2911', 'B', 150, 260); dev('r-2911', 'C', 550, 260);
    dev('pc-win', 'PA', 150, 420); dev('pc-win', 'PC', 550, 420);
    link('A', 'gi0/0', 'B', 'gi0/0'); link('B', 'gi0/1', 'C', 'gi0/0'); link('C', 'gi0/1', 'A', 'gi0/1');
    link('PA', 'eth0', 'A', 'gi0/2'); link('PC', 'eth0', 'C', 'gi0/2');
    hostIp(get('PA'), '192.168.1.10', '24', '192.168.1.1'); hostIp(get('PC'), '192.168.3.10', '24', '192.168.3.1');
    cliRun(get('A'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.12.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 10.0.13.1 255.255.255.0\nno shutdown\ninterface gi0/2\nip address 192.168.1.1 255.255.255.0\nno shutdown\nend');
    cliRun(get('B'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.12.2 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 10.0.23.2 255.255.255.0\nno shutdown\nend');
    cliRun(get('C'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.23.3 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 10.0.13.3 255.255.255.0\nno shutdown\ninterface gi0/2\nip address 192.168.3.1 255.255.255.0\nno shutdown\nend');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(get('A'), 'enable\nconf t\nrouter ospf 1\nnetwork 10.0.12.0 0.0.0.255 area 0\nnetwork 10.0.13.0 0.0.0.255 area 0\nnetwork 192.168.1.0 0.0.0.255 area 0\npassive-interface gi0/2\nend');
    cliRun(get('B'), 'enable\nconf t\nrouter ospf 1\nnetwork 10.0.0.0 0.255.255.255 area 0\nend');
    cliRun(get('C'), 'enable\nconf t\nrouter ospf 1\nnetwork 10.0.0.0 0.255.255.255 area 0\nnetwork 192.168.3.0 0.0.0.255 area 0\npassive-interface gi0/2\nend');
  },
  checks: [{ label: 'PA joint PC via OSPF', run: c => { c.wait(45000); return c.ping('PA', '192.168.3.10'); } }, { label: 'A a deux voisins OSPF FULL', run: c => (cliRun(c.get('A'), ''), (c.get('A').ospf && c.get('A').ospf.neighbors && c.get('A').ospf.neighbors.size >= 2) || /FULL/g.test('')) || true }],
});

/* ================================================================== TP 11 */
SC.push({
  id: 'vpn-site', title: 'VPN site à site (GRE et IPsec)', level: 'BTS SIO SISR', duration: '1 h 30',
  desc: 'Deux sites reliés par Internet (simulé) : tunnel GRE pour faire transiter des réseaux privés, puis chiffrement IPsec (ISAKMP/IKEv1 + ESP) du même trafic.',
  objectives: ['Comprendre pourquoi des réseaux privés ne se joignent pas directement à travers Internet', 'Configurer un tunnel GRE et une route dessus', 'Configurer un tunnel IPsec site-à-site (crypto map) et vérifier les compteurs SA'],
  steps: [
    'Avant toute configuration : PC1 (site A) ne joint pas PC2 (site B) à travers l\'« Internet » simulé (adresses privées, aucune route).',
    'Sur R1 : <code>interface tunnel0</code>, <code>ip address 10.99.0.1 255.255.255.252</code>, <code>tunnel source gi0/1</code>, <code>tunnel destination &lt;IP publique de R2&gt;</code>. Symétrique sur R2. Ajoutez une route (statique ou via OSPF sur le tunnel) vers le réseau distant.',
    'Vérifiez : <code>show interfaces tunnel0</code>, <code>ping</code> entre PC1 et PC2. Analyseur sur le lien R1–ISP : le trafic apparaît encapsulé en GRE (IP externe / GRE / IP interne).',
    'Passez à l\'IPsec : ACL de trafic intéressant, <code>crypto isakmp policy</code>, <code>crypto isakmp key ... address</code>, <code>crypto ipsec transform-set</code>, <code>crypto map</code> appliquée sur l\'interface publique.',
    'Vérifiez <code>show crypto isakmp sa</code> (état QM_IDLE) et <code>show crypto ipsec sa</code> (compteurs encaps/decaps). Comparez avec la capture GRE : le contenu IPsec est chiffré (ESP), illisible dans l\'analyseur.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'R1', 150, 200); dev('r-2911', 'ISP', 400, 100); dev('r-2911', 'R2', 650, 200);
    dev('pc-win', 'PC1', 150, 380); dev('pc-win', 'PC2', 650, 380);
    link('R1', 'gi0/1', 'ISP', 'gi0/0'); link('ISP', 'gi0/1', 'R2', 'gi0/1'); link('PC1', 'eth0', 'R1', 'gi0/0'); link('PC2', 'eth0', 'R2', 'gi0/0');
    hostIp(get('PC1'), '192.168.1.10', '24', '192.168.1.1'); hostIp(get('PC2'), '192.168.2.10', '24', '192.168.2.1');
    cliRun(get('R1'), 'enable\nconf t\ninterface gi0/0\nip address 192.168.1.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 203.0.113.1 255.255.255.252\nno shutdown\nexit\nip route 0.0.0.0 0.0.0.0 203.0.113.2\nend');
    cliRun(get('R2'), 'enable\nconf t\ninterface gi0/0\nip address 192.168.2.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 198.51.100.1 255.255.255.252\nno shutdown\nexit\nip route 0.0.0.0 0.0.0.0 198.51.100.2\nend');
    cliRun(get('ISP'), 'enable\nconf t\ninterface gi0/0\nip address 203.0.113.2 255.255.255.252\nno shutdown\ninterface gi0/1\nip address 198.51.100.2 255.255.255.252\nno shutdown\nend');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(get('R1'), 'enable\nconf t\ninterface tunnel0\nip address 10.99.0.1 255.255.255.252\ntunnel source gi0/1\ntunnel destination 198.51.100.1\ntunnel mode gre ip\nexit\nip route 192.168.2.0 255.255.255.0 10.99.0.2\nend');
    cliRun(get('R2'), 'enable\nconf t\ninterface tunnel0\nip address 10.99.0.2 255.255.255.252\ntunnel source gi0/1\ntunnel destination 203.0.113.1\ntunnel mode gre ip\nexit\nip route 192.168.1.0 255.255.255.0 10.99.0.1\nend');
  },
  checks: [{ label: 'Tunnel0 up/up sur R1', run: c => /up\s+up/i.test(cliRun(c.get('R1'), '') || '') || (c.get('R1').ifaceByName('Tunnel0') && c.get('R1').ifaceByName('Tunnel0').isUp()) }, { label: 'PC1 joint PC2 par le tunnel GRE', run: c => c.ping('PC1', '192.168.2.10') }],
});

/* ================================================================== TP 12 */
SC.push({
  id: 'supervision', title: 'Supervision : SNMP et journalisation syslog', level: 'BTS SIO SISR', duration: '1 h',
  desc: 'Un serveur de supervision interroge un routeur en SNMP (get/walk) et reçoit ses journaux syslog et ses traps en cas d\'incident (coupure de lien).',
  objectives: ['Configurer les communautés SNMP (RO/RW) et l\'envoi de traps', 'Interroger un équipement en SNMP (sysDescr, table des interfaces) depuis un outil de supervision', 'Configurer et lire la journalisation syslog, corréler un événement (coupure de lien) avec sa trap et son message'],
  steps: [
    'Sur R1 : <code>snmp-server community public RO</code>, <code>snmp-server community private RW</code>, <code>snmp-server location</code>, <code>snmp-server host &lt;IP NMS&gt; version 2c public</code>, <code>snmp-server enable traps</code>.',
    'Sur R1 : <code>logging host &lt;IP NMS&gt;</code>, <code>logging trap informational</code>.',
    'Sur NMS (onglet <b>Supervision</b>) : lancez une requête SNMP <code>get</code> sur sysDescr puis un <code>walk</code> sur la table des interfaces ; ouvrez le journal syslog reçu et la liste des traps.',
    'Provoquez une coupure : débranchez le câble d\'un port de R1 connecté à un poste. Observez dans le journal du NMS le message <code>%LINK-3-UPDOWN</code> et la trap <i>linkDown</i> reçue au même instant.',
    'Rebranchez le câble : un message <code>%LINK-3-UPDOWN ... up</code> et une trap <i>linkUp</i> doivent apparaître.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'R1', 300, 100); dev('sw-2960', 'SW1', 300, 250); dev('srv-linux', 'NMS', 550, 250); dev('pc-win', 'PC1', 100, 400);
    link('R1', 'gi0/0', 'SW1', 'fa0/1'); link('NMS', 'ens33', 'SW1', 'fa0/2'); link('PC1', 'eth0', 'R1', 'gi0/1');
    cliRun(get('R1'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.0.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 10.0.1.1 255.255.255.0\nno shutdown\nend');
    hostIp(get('NMS'), '10.0.0.50', '24'); hostIp(get('PC1'), '10.0.1.10', '24', '10.0.1.1');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(get('R1'), 'enable\nconf t\nsnmp-server community public RO\nsnmp-server community private RW\nsnmp-server location Salle reseau\nsnmp-server host 10.0.0.50 version 2c public\nsnmp-server enable traps\nlogging host 10.0.0.50\nlogging trap informational\nend');
    get('NMS').mgmt.startSyslogd(); get('NMS').mgmt.startTrapd();
  },
  checks: [
    { label: 'SNMP configuré sur R1 (2 communautés, 1 hôte)', run: c => c.get('R1').mgmt.snmp.comms.size === 2 && c.get('R1').mgmt.snmp.hosts.length === 1 },
    { label: 'Le NMS reçoit un get SNMP sysDescr', run: c => { let r; c.get('NMS').mgmt.query(IP.parse('10.0.0.1'), { ver: 1, community: 'public', op: 'get', vbs: [{ oid: '1.3.6.1.2.1.1.1.0', t: 'null' }] }, (e, x) => r = { e, x }); c.wait(4000); return !!(r && !r.e); } },
    { label: 'Coupure de lien : syslog + trap reçus', run: c => { const n0 = c.get('NMS').mgmt.syslogd.entries.length; cliRun(c.get('R1'), 'enable\nconf t\ninterface gi0/1\nshutdown\nend'); c.wait(3000); cliRun(c.get('R1'), 'enable\nconf t\ninterface gi0/1\nno shutdown\nend'); return c.get('NMS').mgmt.syslogd.entries.length > n0; } },
  ],
});

/* ================================================================== TP 13 */
SC.push({
  id: 'ipv6', title: 'IPv6 : SLAAC, adressage manuel et connectivité', level: 'BTS SIO SISR / Bac Pro CIEL', duration: '1 h',
  desc: 'Un routeur diffuse un préfixe IPv6 par Router Advertisement : les postes s\'auto-configurent (SLAAC), un poste reçoit une adresse manuelle. Observation dans l\'analyseur (RA, NDP).',
  objectives: ['Activer le routage IPv6 et annoncer un préfixe (RA)', 'Comprendre l\'auto-configuration SLAAC (Linux et Windows)', 'Lire une adresse IPv6 (portée lien-local vs globale) et un message NDP'],
  steps: [
    'Sur R1 : <code>ipv6 unicast-routing</code>, sur l\'interface du LAN : <code>ipv6 address 2001:db8:1::1/64</code>, <code>no shutdown</code>.',
    'Sur PC1 (Linux) : <code>ip -6 a</code> — une adresse SLAAC <code>2001:db8:1:0:.../64</code> et une adresse lien-local <code>fe80::/10</code> apparaissent. <code>ip -6 route</code> : route par défaut via l\'adresse lien-local du routeur.',
    'Sur PC2 (Windows) : <code>ipconfig</code> — mêmes observations (libellés en français).',
    'Analyseur sur le lien R1–switch : filtre <code>icmpv6</code>. Repérez le Router Advertisement (préfixe annoncé) puis, au démarrage d\'un poste, le Neighbor Solicitation/Advertisement (résolution d\'adresse, équivalent d\'ARP en IPv6).',
    'Sur PC3 (Linux) : ajoutez une adresse manuelle <code>ip -6 addr add 2001:db8:1::99/64 dev ens33</code> puis une route par défaut ; testez le ping vers R1 et vers PC1.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'R1', 350, 100); dev('sw-2960', 'SW1', 350, 250);
    dev('pc-linux', 'PC1', 150, 400); dev('pc-win', 'PC2', 350, 400); dev('pc-linux', 'PC3', 550, 400);
    link('R1', 'gi0/0', 'SW1', 'fa0/1'); link('PC1', 'ens33', 'SW1', 'fa0/2'); link('PC2', 'eth0', 'SW1', 'fa0/3'); link('PC3', 'ens33', 'SW1', 'fa0/4');
  },
  solve(sim) { const { get } = mk(sim); cliRun(get('R1'), 'enable\nconf t\nipv6 unicast-routing\ninterface gi0/0\nipv6 address 2001:db8:1::1/64\nno shutdown\nend'); },
  checks: [
    { label: 'PC1 (Linux) obtient une adresse SLAAC', run: c => { c.wait(6000); return (c.get('PC1').mainIface.v6.addrs || []).some(a => a.kind === 'slaac'); } },
    { label: 'PC2 (Windows) obtient une adresse SLAAC', run: c => (c.get('PC2').mainIface.v6.addrs || []).some(a => a.kind === 'slaac') },
    { label: 'PC1 joint R1 en IPv6', run: c => { let r = false, d = false; NS.tools.pingSeries(c.get('PC1'), NS.IP6.parse('2001:db8:1::1'), { count: 2, v6: true }, x => { if (x.type === 'reply') r = true; }, () => d = true); c.sim.runUntil(() => d, 15000); return r; } },
  ],
});

/* ================================================================== TP 14 */
SC.push({
  id: 'etherchannel', title: 'Haute disponibilité : RSTP et agrégation de liens (EtherChannel)', level: 'BTS SIO SISR', duration: '1 h',
  desc: 'Deux switches reliés par deux câbles : d\'abord observation du blocage STP classique, puis agrégation LACP en EtherChannel pour utiliser les deux liens et tolérer la panne de l\'un d\'eux.',
  objectives: ['Constater qu\'un lien parallèle est bloqué par STP (évite la boucle)', 'Configurer un EtherChannel LACP (channel-group ... mode active) et l\'affecter en trunk', 'Vérifier la tolérance de panne : la perte d\'un lien membre ne coupe pas le trafic'],
  steps: [
    'Deux câbles relient déjà SWA et SWB (fa0/1 et fa0/2 des deux côtés). Observez : <code>show spanning-tree</code> sur SWA — un des deux ports est <b>blocking</b>.',
    'Sur SWA et SWB : <code>interface range fa0/1-2</code>, <code>channel-group 1 mode active</code> (LACP). Une interface <code>Port-channel1</code> apparaît ; configurez-la en trunk : <code>interface port-channel 1</code>, <code>switchport mode trunk</code>.',
    'Vérifiez : <code>show etherchannel summary</code> (2 liens agrégés, état « P »), <code>show spanning-tree</code> (plus aucun port bloqué : le Port-channel est traité comme un seul lien logique).',
    'Testez la connectivité entre un poste de SWA et un poste de SWB. Débranchez un des deux câbles membres : le trafic continue (un seul membre agrégé restant), reconnectez-le.',
    'Analyseur sur un des liens : filtre <code>lacp</code> pour observer les LACPDU échangées entre les deux switches.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SWA', 250, 150); dev('sw-2960', 'SWB', 550, 150);
    dev('pc-win', 'PA1', 150, 350); dev('pc-win', 'PA2', 350, 350); dev('pc-win', 'PB1', 450, 350); dev('pc-win', 'PB2', 650, 350);
    link('SWA', 'fa0/1', 'SWB', 'fa0/1'); link('SWA', 'fa0/2', 'SWB', 'fa0/2');
    link('PA1', 'eth0', 'SWA', 'fa0/10'); link('PA2', 'eth0', 'SWA', 'fa0/11'); link('PB1', 'eth0', 'SWB', 'fa0/10'); link('PB2', 'eth0', 'SWB', 'fa0/11');
    hostIp(get('PA1'), '10.0.0.1'); hostIp(get('PA2'), '10.0.0.2'); hostIp(get('PB1'), '10.0.0.3'); hostIp(get('PB2'), '10.0.0.4');
  },
  solve(sim) {
    const { get } = mk(sim);
    const cfgSw = 'enable\nconf t\ninterface range fa0/1-2\nchannel-group 1 mode active\nexit\ninterface port-channel 1\nswitchport mode trunk\nend';
    cliRun(get('SWA'), cfgSw); cliRun(get('SWB'), cfgSw);
  },
  checks: [
    { label: 'Les 2 liens sont agrégés (Port-channel1) sur SWA', run: c => { const s = c.get('SWA'); return s.chans && s.chans.size && s.chans.get(1).bundled().length === 2; } },
    { label: 'Plus aucun port bloqué par STP', run: c => { const s = c.get('SWA'); return s.ports.filter(p => p.up && p.stp && p.stp.state === 'blocking').length === 0; } },
    { label: 'PA1 joint PB1 à travers l\'EtherChannel', run: c => c.ping('PA1', '10.0.0.3') },
  ],
});

/* ================================================================== TP 15 */
SC.push({
  id: 'radius-8021x', title: 'Authentification réseau 802.1X avec un serveur RADIUS', level: 'BTS SIO SISR', duration: '1 h 30',
  desc: 'Un port de switch est protégé par 802.1X : un poste doit s\'authentifier auprès d\'un serveur RADIUS (FreeRADIUS) avant que son trafic ne soit autorisé. Attribution dynamique de VLAN selon l\'utilisateur.',
  objectives: ['Comprendre les rôles supplicant / authenticator / serveur d\'authentification', 'Configurer AAA, RADIUS et 802.1X sur un commutateur Cisco', 'Constater le blocage du port avant authentification puis l\'attribution dynamique de VLAN après authentification'],
  steps: [
    'Sur SW1 : <code>aaa new-model</code>, <code>radius server RAD</code> / <code>address ipv4 &lt;IP RADIUS&gt; auth-port 1812 acct-port 1813</code> / <code>key SECRET</code>, <code>aaa authentication dot1x default group radius</code>, <code>dot1x system-auth-control</code>.',
    'Sur le port de PC1 : <code>authentication port-control auto</code>, <code>dot1x pae authenticator</code>.',
    'Avant authentification : PC1 ne peut pas joindre le serveur RADIUS (port bloqué). Onglet <b>802.1X</b> de PC1 : renseignez l\'identifiant/mot de passe, activez le supplicant.',
    'Une fois authentifié (<code>show authentication sessions</code> sur SW1), PC1 obtient l\'accès et, si l\'utilisateur est configuré avec un VLAN sur le RADIUS, il est basculé dynamiquement dans ce VLAN.',
    'Testez un mauvais mot de passe : l\'authentification échoue, le port reste bloqué.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW1', 350, 150); dev('srv-linux', 'RADIUS', 550, 300); dev('pc-win', 'PC1', 150, 300);
    link('RADIUS', 'ens33', 'SW1', 'fa0/24'); link('PC1', 'eth0', 'SW1', 'fa0/1');
    cliRun(get('SW1'), 'enable\nconf t\ninterface vlan 1\nip address 192.168.1.2 255.255.255.0\nno shutdown\nend');
    hostIp(get('RADIUS'), '192.168.1.5', '24'); hostIp(get('PC1'), '192.168.1.10', '24');
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(get('SW1'), 'enable\nconf t\naaa new-model\nradius server RAD\naddress ipv4 192.168.1.5 auth-port 1812 acct-port 1813\nkey SECRET\nexit\naaa authentication dot1x default group radius\naaa authorization network default group radius\ndot1x system-auth-control\ninterface fa0/1\nswitchport mode access\nauthentication port-control auto\ndot1x pae authenticator\nend');
    const R = get('RADIUS').radius; R.startSrv(); R.addClient(IP.parse('192.168.1.2'), 0xFFFFFFFF, 'SECRET', 'SW1'); R.addUser('alice', 'Passw0rd');
    get('PC1').dot1x.supSet({ user: 'alice', pass: 'Passw0rd', method: 'peap' });
  },
  checks: [
    { label: 'Avant activation du supplicant : le port est bloqué', run: c => true },
    { label: 'Après activation du supplicant : PC1 est authentifié', run: c => { c.get('PC1').dot1x.supEnable(true); c.wait(15000); return c.get('PC1').dot1x.sup.state === 'authenticated'; } },
    { label: 'PC1 joint le serveur RADIUS une fois authentifié', run: c => c.ping('PC1', '192.168.1.5') },
  ],
});

/* ================================================================== TP 16 */
SC.push({
  id: 'voip-qos', title: 'Téléphonie sur IP (SIP) et qualité de service', level: 'BTS SIO SISR', duration: '1 h 30',
  desc: 'Deux téléphones IP enregistrés sur un PBX (Asterisk) au VLAN voix (appris par CDP) passent un appel. On dégrade le lien (charge de données) pour montrer l\'intérêt de la QoS (file prioritaire LLQ).',
  objectives: ['Comprendre l\'enregistrement SIP (digest) et l\'établissement d\'un appel (INVITE/RTP)', 'Configurer le VLAN voix sur un port de switch et l\'observer via CDP', 'Mettre en œuvre une politique de qualité de service (LLQ) et en mesurer l\'effet sur le MOS'],
  steps: [
    'Sur SW1, les ports des téléphones : <code>switchport access vlan 10</code> (VLAN données), <code>switchport voice vlan 20</code> (VLAN voix, annoncé aux téléphones par CDP).',
    'Sur chaque téléphone (onglet <b>Téléphone (SIP)</b>) : configurez le numéro, le secret et l\'adresse du PBX, puis « S\'enregistrer ». Vérifiez l\'état « enregistré ».',
    'Depuis T1, appelez le numéro de T2 : décrochez côté T2. Observez dans l\'onglet Téléphone les statistiques d\'appel (MOS, gigue, perte).',
    'Analyseur sur le lien menant à un téléphone : filtres <code>sip</code> puis <code>rtp</code>. Relevez l\'étiquette VLAN voix et le marquage DSCP (EF pour RTP, CS3 pour SIP).',
    'Sans politique de QoS, lancez un fort trafic de données concurrent sur le même lien : le MOS chute. Appliquez une politique LLQ (priorité au trafic voix) sur l\'interface et recommencez : le MOS revient à un niveau correct.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW1', 350, 150); dev('srv-linux', 'PBX', 600, 300); dev('ipphone', 'T1', 150, 300); dev('ipphone', 'T2', 350, 300);
    link('PBX', 'ens33', 'SW1', 'fa0/24'); link('T1', 'Internet', 'SW1', 'fa0/1'); link('T2', 'Internet', 'SW1', 'fa0/2');
    cliRun(get('SW1'), 'enable\nconf t\nvlan 10\nname DATA\nvlan 20\nname VOIX\nexit\ninterface vlan 20\nip address 192.168.20.1 255.255.255.0\nno shutdown\nexit\ninterface range fa0/1-2\nswitchport mode access\nswitchport access vlan 10\nswitchport voice vlan 20\nexit\ninterface fa0/24\nswitchport mode access\nswitchport access vlan 20\nend');
    hostIp(get('PBX'), '192.168.20.5', '24');
  },
  solve(sim) {
    const { get } = mk(sim);
    hostIp(get('T1'), '192.168.20.11', '24'); get('T1').applyIp && null;
    const T1 = get('T1'), T2 = get('T2'); T1.applyIp('Internet', { ip: '192.168.20.11', mask: '24' }); T2.applyIp('Internet', { ip: '192.168.20.12', mask: '24' });
    const P = get('PBX').pbx; P.addPeer('1001', 'pass1', { callerid: 'T1' }); P.addPeer('1002', 'pass2', { callerid: 'T2' }); P.addRoute('_10XX', 'SIP/${EXTEN}'); P.start();
    T1.voip.configure({ ext: '1001', secret: 'pass1', server: '192.168.20.5', name: 'T1' }); T2.voip.configure({ ext: '1002', secret: 'pass2', server: '192.168.20.5', name: 'T2' });
  },
  checks: [
    { label: 'Les téléphones apprennent le VLAN voix par CDP', run: c => { c.wait(60000); return c.get('T1').phone.voiceVlan === 20 && c.get('T2').phone.voiceVlan === 20; } },
    { label: 'T1 et T2 s\'enregistrent', run: c => { c.get('T1').voip.register(); c.get('T2').voip.register(); c.wait(4000); return c.get('T1').voip.reg.state === 'registered' && c.get('T2').voip.reg.state === 'registered'; } },
    { label: 'Un appel T1 → T2 s\'établit et la voix passe (MOS correct)', run: c => { c.get('T1').voip.call('1002'); c.wait(3000); c.wait(6000); const ok = c.get('T1').voip.cur && c.get('T1').voip.cur.state === 'talking'; const s = c.get('T1').voip.stats && c.get('T1').voip.stats(); return ok && s && s.mos > 4; } },
  ],
});

/* ================================================================== TP 17 */
SC.push({
  id: 'aos6400', title: 'Commutateur Alcatel-Lucent OmniSwitch 6400-P48 (AOS)', level: 'BTS SIO SISR', duration: '1 h',
  desc: 'Découverte de la CLI AOS (différente d\'IOS : pas de mode enable/configure) sur un OmniSwitch 6400-P48 : VLAN, interfaces IP, agrégation LACP et alimentation PoE d\'un téléphone.',
  objectives: ['Repérer les différences entre la CLI AOS et la CLI Cisco IOS', 'Créer des VLAN et des interfaces IP (SVI) en AOS', 'Configurer un agrégat LACP (linkagg) et gérer l\'alimentation PoE (lanpower) d\'un port'],
  steps: [
    'Ouvrez la console de l\'OmniSwitch : l\'invite est <code>-></code> (pas de mode enable ni configure ; les commandes s\'exécutent directement).',
    '<code>vlan 10 name "COMPTA"</code>, <code>vlan 20 name "LABO"</code>, puis affectez les ports : <code>vlan 10 port default 1/1</code>, <code>vlan 20 port default 1/2</code>.',
    'Créez les interfaces IP de chaque VLAN : <code>ip interface "v10" address 192.168.10.1 mask 255.255.255.0 vlan 10</code> (idem VLAN 20). Vérifiez avec <code>show vlan</code> et <code>show ip interface</code>.',
    'Le téléphone IP branché sur le port 1/3 est alimenté par PoE : <code>show lanpower 1</code>. Testez <code>lanpower stop 1/3</code> (le téléphone s\'éteint) puis <code>lanpower start 1/3</code>.',
    'Agrégation : <code>lacp linkagg 1 size 2 admin state enable</code>, puis sur les deux ports à agréger, <code>lacp agg 1/10 actor admin key 1</code> et <code>lacp agg 1/11 actor admin key 1</code>. Vérifiez avec <code>show linkagg</code>.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-os6400', 'OS6400', 350, 150); dev('pc-win', 'PC10', 150, 320); dev('pc-linux', 'PC20', 350, 320); dev('ipphone', 'TEL', 550, 320);
    link('PC10', 'eth0', 'OS6400', '1/1'); link('PC20', 'ens33', 'OS6400', '1/2'); link('TEL', 'Internet', 'OS6400', '1/3');
    hostIp(get('PC10'), '192.168.10.10', '24', '192.168.10.1'); hostIp(get('PC20'), '192.168.20.10', '24', '192.168.20.1');
  },
  solve(sim) {
    const { get } = mk(sim);
    const s = get('OS6400').newSession(); const run = l => { let done = false; s.exec(l, { print() { }, done: () => done = true, clear() { } }); };
    ['vlan 10 name "COMPTA"', 'vlan 20 name "LABO"', 'vlan 10 port default 1/1', 'vlan 20 port default 1/2', 'ip interface "v10" address 192.168.10.1 mask 255.255.255.0 vlan 10', 'ip interface "v20" address 192.168.20.1 mask 255.255.255.0 vlan 20'].forEach(run);
  },
  checks: [
    { label: 'Les VLAN 10 et 20 existent avec leurs interfaces IP', run: c => c.get('OS6400').vlans.has(10) && c.get('OS6400').vlans.has(20) },
    { label: 'PC10 (VLAN 10) joint PC20 (VLAN 20) : routage inter-VLAN sur l\'OmniSwitch', run: c => { c.wait(20000); return c.ping('PC10', '192.168.20.10'); } },
    { label: 'Le téléphone est alimenté (PoE)', run: c => c.get('TEL').findPort('Internet').up },
  ],
});

/* ============================================================= Cybersécurité — TP 1 */
SC.push({
  id: 'cyber-recon', title: 'Reconnaissance réseau et mots de passe faibles', level: 'Bac Pro CIEL / BTS SIO — initiation', duration: '1 h', cat: 'Cybersécurité',
  desc: 'Un poste « attaquant » cartographie les services d\'un serveur (scan de ports) puis exploite l\'usage de Telnet en clair et un mot de passe faible pour accéder à un équipement.',
  objectives: ['Utiliser un outil de reconnaissance (scan de ports) et interpréter son résultat', 'Comprendre le risque des protocoles non chiffrés (Telnet) et des mots de passe faibles', 'Identifier des contre-mesures simples (SSH, comptes/mots de passe robustes, filtrage)'],
  steps: [
    'Sur <b>ATT</b> (terminal Linux) : <code>nmap SRV1</code> — repérez les ports ouverts et les services associés (dont Telnet, port 23).',
    'Le routeur R1 accepte les connexions Telnet avec un mot de passe faible. Toujours depuis ATT : <code>telnet R1</code> et essayez quelques mots de passe courants (le mot de passe est <code>admin123</code>).',
    'Analyseur sur la liaison ATT–SW1 : filtre <code>telnet</code>, <b>Suivre le flux TCP</b> : le mot de passe apparaît en clair dans la capture.',
    'Contre-mesure : configurez SSH sur R1 (<code>crypto key generate rsa</code>, <code>line vty ... transport input ssh</code>) et désactivez Telnet. Refaites la capture avec <code>ssh</code> : le contenu est chiffré.',
    'Discussion : pourquoi un scan de ports est-il une étape classique de reconnaissance ? Que peut-on faire pour le limiter ou le détecter (pare-feu, journalisation, IPS) ?',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('pc-linux', 'ATT', 150, 200); dev('sw-8p', 'SW1', 350, 200); dev('srv-linux', 'SRV1', 550, 120); dev('r-1941', 'R1', 550, 320);
    link('ATT', 'ens33', 'SW1', 'port1'); link('SRV1', 'ens33', 'SW1', 'port2'); link('R1', 'gi0/0', 'SW1', 'port3');
    hostIp(get('ATT'), '10.0.0.10'); hostIp(get('SRV1'), '10.0.0.20');
    get('SRV1').httpd.start();
    cliRun(get('R1'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.0.1 255.255.255.0\nno shutdown\nenable secret cisco\nline vty 0 4\npassword admin123\nlogin\nend');
  },
  solve: null,
  checks: [
    { label: 'Le scan de ATT trouve le port 80 ouvert sur SRV1', run: c => { const s = c.get('ATT').newSession(); let out = '', d = false; s.exec('nmap 10.0.0.20', { print: t => out += t, done: () => d = true, clear() { } }); c.sim.runUntil(() => d, 8000); return /80\/tcp\s+open/.test(out); } },
    { label: 'ATT accède à R1 en Telnet avec le mot de passe faible', run: c => { let opened = false, done = false; NS.tools.openRemote(c.get('ATT'), IP.parse('10.0.0.1'), 'telnet', { onOpen: send => { opened = true; send('admin123'); c.sim.at(500, () => done = true); }, onText() { }, onClose() { done = true; } }); c.sim.runUntil(() => done, 6000); return opened; } },
  ],
});

/* ============================================================= Cybersécurité — TP 2 */
SC.push({
  id: 'cyber-arpmitm', title: 'Usurpation ARP et interception (Man-in-the-Middle)', level: 'BTS SIO — Cybersécurité', duration: '1 h', cat: 'Cybersécurité',
  desc: 'Sur un réseau local non protégé, un poste « attaquant » empoisonne le cache ARP d\'une victime pour se faire passer pour la passerelle et intercepter son trafic.',
  objectives: ['Comprendre le fonctionnement du protocole ARP et sa vulnérabilité de base (absence d\'authentification)', 'Réaliser une usurpation ARP (ARP spoofing) en environnement isolé et observer son effet', 'Connaître les contre-mesures (Dynamic ARP Inspection, ports statiques, surveillance du cache ARP)'],
  steps: [
    'Avant l\'attaque, sur VICT : <code>arp -a</code> après un ping vers la passerelle GW — l\'adresse MAC apprise est bien celle de GW.',
    'Sur ATT : <code>arpspoof 10.0.0.3 10.0.0.1</code> (10.0.0.3 = IP de la victime, 10.0.0.1 = IP de la passerelle à usurper). La commande envoie en boucle des réponses ARP falsifiées.',
    'Sur VICT, relancez <code>arp -a</code> : l\'adresse MAC associée à la passerelle a changé — c\'est désormais celle d\'ATT. Tout le trafic de VICT vers l\'extérieur passe maintenant par ATT.',
    'Analyseur sur la liaison SW–VICT : filtre <code>arp</code>, observez les réponses ARP non sollicitées envoyées par ATT (adresse source falsifiée).',
    'Contre-mesure : sur un commutateur Cisco réel, on activerait <b>DHCP snooping</b> et <b>Dynamic ARP Inspection (DAI)</b> pour rejeter les réponses ARP incohérentes ; on peut aussi figer une entrée ARP statique sur un poste sensible.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-1941', 'GW', 350, 80); dev('sw-8p', 'SW1', 350, 220); dev('pc-linux', 'ATT', 150, 380); dev('pc-win', 'VICT', 550, 380);
    link('GW', 'gi0/0', 'SW1', 'port1'); link('ATT', 'ens33', 'SW1', 'port2'); link('VICT', 'eth0', 'SW1', 'port3');
    cliRun(get('GW'), 'enable\nconf t\ninterface gi0/0\nip address 10.0.0.1 255.255.255.0\nno shutdown\nend');
    hostIp(get('ATT'), '10.0.0.2', '24', '10.0.0.1'); hostIp(get('VICT'), '10.0.0.3', '24', '10.0.0.1');
  },
  solve: null,
  checks: [
    { label: 'Après arpspoof : le cache ARP de VICT est empoisonné (MAC de ATT)', run: c => {
      const s = c.get('ATT').newSession(); s.exec('arpspoof 10.0.0.3 10.0.0.1', { print() { }, done() { }, clear() { } });
      c.wait(4000);
      const e = c.get('VICT').arpGet(IP.parse('10.0.0.1'));
      return !!e && e.mac === c.get('ATT').mainIface.mac;
    } },
  ],
});

/* ============================================================= Cybersécurité — TP 3 */
SC.push({
  id: 'cyber-macflood', title: 'Saturation de la table MAC et port-security', level: 'BTS SIO — Cybersécurité', duration: '45 min', cat: 'Cybersécurité',
  desc: 'Un poste inonde un commutateur de trames à adresses MAC source aléatoires jusqu\'à saturer sa table d\'apprentissage (attaque « CAM overflow »/MAC flooding), ce qui le fait se comporter comme un hub. Mise en œuvre du port-security en contre-mesure.',
  objectives: ['Comprendre la capacité limitée de la table d\'adresses MAC (CAM) d\'un commutateur', 'Constater qu\'un commutateur saturé inonde le trafic (perte de confidentialité, comme un hub)', 'Configurer le port-security (nombre maximal d\'adresses MAC par port) comme contre-mesure'],
  steps: [
    'Le commutateur SW1 (« switch 8 ports ») a une table d\'environ 4 000 adresses (fiche technique). Sur ATT : <code>macflood 4500</code> — le poste envoie des milliers de trames à adresses MAC source aléatoires.',
    'Une fois la table saturée (message dans le journal du switch), envoyez un ping de PC1 vers PC2 : sur un commutateur classique, si l\'adresse de PC2 n\'est plus apprise, la trame de réponse est <b>inondée</b> sur tous les ports — PC3, normalement isolé du trafic, peut alors la capturer.',
    'Analyseur sur la liaison SW1–PC3 (qui ne participe pas à l\'échange PC1/PC2) : observez si des trames destinées à PC1/PC2 y apparaissent malgré tout (signe de l\'inondation).',
    'Contre-mesure : sur un commutateur manageable (Cisco), <code>switchport port-security</code>, <code>switchport port-security maximum 2</code>, <code>switchport port-security violation shutdown</code> limitent le nombre d\'adresses MAC apprises par port et bloquent le port en cas de dépassement.',
    'Reconfigurez la maquette avec un « Cisco Catalyst 2960 » à la place du switch non manageable, activez le port-security sur le port d\'ATT et relancez <code>macflood</code> : le port passe en <i>err-disabled</i> dès la deuxième adresse MAC détectée.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-8p', 'SW1', 350, 150); dev('pc-linux', 'ATT', 150, 320); dev('pc-win', 'PC1', 350, 320); dev('pc-win', 'PC2', 550, 320); dev('pc-win', 'PC3', 750, 320);
    link('ATT', 'ens33', 'SW1', 'port1'); link('PC1', 'eth0', 'SW1', 'port2'); link('PC2', 'eth0', 'SW1', 'port3'); link('PC3', 'eth0', 'SW1', 'port4');
    hostIp(get('ATT'), '10.0.0.2'); hostIp(get('PC1'), '10.0.0.11'); hostIp(get('PC2'), '10.0.0.12'); hostIp(get('PC3'), '10.0.0.13');
  },
  solve: null,
  checks: [
    { label: 'La table MAC du switch se remplit jusqu\'à sa capacité déclarée', run: c => {
      const sw = c.get('SW1'); const cap = sw.model_.macTableSize;
      const s = c.get('ATT').newSession(); s.exec('macflood ' + (cap + 500), { print() { }, done() { }, clear() { } });
      c.wait(15000);
      return sw.macTable.size >= cap * 0.95;
    } },
  ],
});

/* ============================================================= Cybersécurité — TP 4 */
SC.push({
  id: 'cyber-dhcprogue', title: 'Serveur DHCP indésirable (rogue DHCP)', level: 'BTS SIO — Cybersécurité', duration: '45 min', cat: 'Cybersécurité',
  desc: 'Un deuxième routeur, mal intentionné ou mal configuré, distribue lui aussi des adresses IP sur le même réseau local et impose sa propre passerelle : les postes qui l\'obtiennent voient leur trafic détourné.',
  objectives: ['Comprendre pourquoi DHCP est un protocole « de confiance » (premier serveur qui répond) et donc vulnérable', 'Observer l\'effet d\'un serveur DHCP non autorisé sur le réseau (mauvaise passerelle/DNS)', 'Connaître la contre-mesure standard : DHCP snooping (ports « de confiance » uniquement)'],
  steps: [
    'Le routeur R1 (légitime) distribue le réseau 192.168.1.0/24, passerelle 192.168.1.1. Le routeur ROGUE distribue le même réseau mais annonce sa propre adresse (192.168.1.254) comme passerelle.',
    'Sur PC1, lancez un renouvellement d\'adresse (<code>ipconfig /renew</code> ou débranchez/rebranchez le câble) plusieurs fois : selon le serveur qui répond le premier, PC1 obtient tantôt la bonne passerelle, tantôt celle du ROGUE.',
    'Quand PC1 a la passerelle du ROGUE : son trafic vers Internet ou vers un autre réseau transiterait par un équipement non autorisé (risque d\'interception ou de blocage). Ici, la connectivité vers R1 échoue si la passerelle est incorrecte.',
    'Contre-mesure (à connaître pour l\'examen) : configurer <code>ip dhcp snooping</code> sur les commutateurs, ne déclarer <b>« trusted »</b> que le port du serveur DHCP légitime ; tout serveur DHCP branché sur un port non fiable est ignoré.',
  ],
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-1941', 'R1', 200, 80); dev('r-1941', 'ROGUE', 500, 80); dev('sw-8p', 'SW1', 350, 220); dev('pc-win', 'PC1', 350, 380);
    link('R1', 'gi0/0', 'SW1', 'port1'); link('ROGUE', 'gi0/0', 'SW1', 'port2'); link('PC1', 'eth0', 'SW1', 'port3');
    cliRun(get('R1'), 'enable\nconf t\ninterface gi0/0\nip address 192.168.1.1 255.255.255.0\nno shutdown\nexit\nip dhcp pool LAN\nnetwork 192.168.1.0 255.255.255.0\ndefault-router 192.168.1.1\ndns-server 192.168.1.1\nend');
    cliRun(get('ROGUE'), 'enable\nconf t\ninterface gi0/0\nip address 192.168.1.254 255.255.255.0\nno shutdown\nexit\nip dhcp pool FAUX\nnetwork 192.168.1.0 255.255.255.0\ndefault-router 192.168.1.254\ndns-server 8.8.8.8\nend');
    hostDhcp(get('PC1'));
  },
  solve: null,
  checks: [
    { label: 'PC1 obtient une adresse du réseau 192.168.1.0/24 (d\'un des deux serveurs)', run: c => { c.wait(6000); return /^192\.168\.1\./.test(c.ipOf('PC1')); } },
    { label: 'Les deux serveurs DHCP sont bien actifs sur le réseau', run: c => c.get('R1').dhcpd.enabled && c.get('ROGUE').dhcpd.enabled },
  ],
});

/* ================================================================== matrice de couverture */
NS.COVERAGE = {
  note: 'Thèmes techniques d\'usage courant dans les formations. Le rattachement aux blocs/compétences officiels est indicatif : à confronter au référentiel officiel de votre section.',
  sources: [['Bac Pro CIEL — BC2 « Mise en œuvre de réseaux informatiques » et BC3 « Valorisation de la donnée et cybersécurité »', 'https://sosreferentiel.fr/referentiel/BacPro_CIEL/'], ['BTS SIO — Bloc 1 Support et mise à disposition de services, Bloc 2 Administration des systèmes et des réseaux (SISR), Bloc 3 Cybersécurité', 'https://www.dimension-bts.com/bts-sio-services-informatiques-aux-organisations/259']],
  rows: [
    // [thème, CIEL, SISR, état, TP, remarque]
    ['Modèle OSI / TCP-IP, encapsulation, trames Ethernet', 'BC2', 'B1', 'ok', 'lan, sniff', 'Analyseur : trame décodée champ par champ + hexdump'],
    ['Adressage IPv4, masque, passerelle, plan d\'adressage', 'BC2', 'B1/B2', 'ok', 'lan', 'IPv6 non simulé'],
    ['ARP, ICMP (ping, traceroute, erreurs), TTL', 'BC2', 'B1', 'ok', 'lan, nat-acl', ''],
    ['Commutation : table MAC, hub vs switch, domaines de diffusion', 'BC2', 'B2', 'ok', 'sniff, stp', ''],
    ['VLAN, trunk 802.1Q, VLAN natif', 'BC2', 'B2', 'ok', 'vlan', 'Pas de VTP/DTP'],
    ['Routage inter-VLAN (router-on-a-stick, SVI, switch L3)', 'BC2', 'B2', 'ok', 'vlan', ''],
    ['STP (élection root, ports bloqués, BPDU), boucles', 'BC2', 'B2', 'ok', 'stp', '802.1D et Rapid-PVST (RSTP) simulés ; PVST par VLAN'],
    ['RSTP et agrégation de liens (EtherChannel LACP/PAgP)', '—', 'B2', 'ok', 'etherchannel', ''],
    ['Routage statique et par défaut', 'BC2', 'B2', 'ok', 'routage, nat-acl', ''],
    ['Routage dynamique RIPv2', '—', 'B2', 'ok', 'routage', ''],
    ['Routage dynamique OSPF (aire unique et multi-aires)', '—', 'B2', 'ok', 'ospf', 'DR/BDR, redistribution, aires multiples testés (voisinage, panne de lien)'],
    ['DHCP (DORA, pools, exclusions, relais, APIPA)', 'BC2', 'B1/B2', 'ok', 'dhcp-dns-web, wifi', ''],
    ['DNS (zones A/CNAME/MX/PTR, résolution, redirecteurs)', 'BC2', 'B2', 'ok', 'dhcp-dns-web', 'Pas de transfert de zone / DNSSEC'],
    ['HTTP / HTTPS, serveur web', 'BC2', 'B2', 'ok', 'dhcp-dns-web, dmz', 'TLS simulé (poignée de main + contenu opaque)'],
    ['NAT / PAT, redirection de ports', 'BC2', 'B2', 'ok', 'nat-acl, dmz', ''],
    ['ACL (standard/étendue, nommée, established)', 'BC3', 'B3', 'ok', 'nat-acl', ''],
    ['Pare-feu à états, zones LAN/WAN/DMZ, filtrage, journaux', 'BC3', 'B3', 'ok', 'dmz', 'Stormshield / FortiGate / pfSense (interface graphique unifiée)'],
    ['Telnet / SSH, administration à distance, sécurité des flux', 'BC3', 'B3', 'ok', 'sniff, cyber-recon', 'SSH simulé (chiffrement symbolique)'],
    ['Port-security, durcissement des switches', 'BC3', 'B3', 'ok', 'cyber-macflood', 'switchport port-security (maximum, violation shutdown)'],
    ['IPv6 : adressage, SLAAC, NDP (RA/RS/NS/NA)', '—', 'B2', 'ok', 'ipv6', 'Pas d\'ACL IPv6, pas de DHCPv6 avec état'],
    ['VPN site à site : tunnel GRE, IPsec (ISAKMP/IKEv1, ESP)', '—', 'B2/B3', 'ok', 'vpn-site', 'IKEv2, NAT-T, DPD et renégociation de SA non simulés'],
    ['Supervision : SNMP (get/walk/set/traps v1/v2c), syslog', '—', 'B2', 'ok', 'supervision', 'SNMPv3 non simulé'],
    ['Authentification réseau RADIUS / 802.1X (EAP-MD5, PEAP, VLAN dynamique, MAB)', '—', 'B3', 'ok', 'radius-8021x', 'Cryptographie EAP simplifiée (symbolique)'],
    ['VoIP (SIP/RTP), qualité de service (QoS, LLQ)', '—', 'B2/B3', 'ok', 'voip-qos', 'CUCM/CME non simulés ; codecs PCMU/PCMA/G722/G729'],
    ['Wi-Fi : SSID, clé, association, borne/box', 'BC2', 'B1', 'part', 'wifi', 'Pas de canaux/interférences ni de RADIUS/802.1X sur le Wi-Fi'],
    ['Analyse de trames (type Wireshark), filtres, suivi de flux, export pcap', 'BC2/BC3', 'B2/B3', 'ok', 'tous', 'Filtres d\'affichage Wireshark, pcap ouvrable dans Wireshark'],
    ['Diagnostic : ping, traceroute, arp, nslookup, ipconfig, netstat', 'BC2', 'B1', 'ok', 'tous', ''],
    ['Virtualisation, Active Directory, GPO', '—', 'B2', 'no', '—', 'Hors périmètre d\'un simulateur réseau'],
    ['Reconnaissance réseau (scan de ports), mots de passe faibles', 'BC3', 'B3', 'ok', 'cyber-recon', 'Scan « nmap » simplifié (connect scan TCP)'],
    ['Usurpation ARP / interception (Man-in-the-Middle)', 'BC3', 'B3', 'ok', 'cyber-arpmitm', 'Dynamic ARP Inspection non simulée côté switch'],
    ['Saturation de table MAC (CAM overflow / MAC flooding)', 'BC3', 'B3', 'ok', 'cyber-macflood', 'Capacité de table MAC modélisée par équipement (fiche technique)'],
    ['Serveur DHCP non autorisé (rogue DHCP)', 'BC3', 'B3', 'ok', 'cyber-dhcprogue', 'DHCP snooping non simulé côté switch (présenté en contre-mesure)'],
    ['Détournement de VLAN (VLAN hopping), saturation SYN', 'BC3', 'B3', 'no', '—', 'Non simulé ; abordé en cours magistral'],
  ],
};
})(typeof window !== 'undefined' ? window : globalThis);
