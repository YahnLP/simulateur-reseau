const { mk, cliRun, hostIp, hostDhcp, IP } = require('../tp-lib');
module.exports = {
  file: 'TP-S09-inter-vlan-relais-dhcp.json',
  meta: {
    id: 'cours-s09-intervlan-dhcp', type: 'decouverte', diff: 3, cat: 'Cours BTS SIO — S09', level: 'BTS SIO SISR 1re année — Bloc 2 — S09', duration: '1 h 30',
    title: 'S09 — Routage inter-VLAN et relais DHCP',
    desc: 'Trois VLAN (Informatique, Direction, Serveurs), un routeur « on a stick » et un serveur DHCP/DNS situé dans le VLAN Serveurs : configurer le commutateur, les sous-interfaces et le relais DHCP.',
    objectives: ['Créer les VLAN, affecter les ports et configurer le trunk vers le routeur', 'Configurer les sous-interfaces 802.1Q du routeur (une passerelle par VLAN)', 'Expliquer et configurer le relais DHCP (ip helper-address) pour un serveur situé dans un autre réseau'],
    steps: [
      'Le plan est câblé. Le serveur <code>SRV-INFRA</code> (192.168.30.10) est <b>déjà configuré</b> : DHCP pour les VLAN 10 (.100-.200) et 20 (.100-.180), DNS <code>infra.local</code>. Les clients <code>PC-INFO</code> (fa0/1) et <code>PC-DIR</code> (fa0/6) sont en DHCP. Constatez : ils n\'obtiennent qu\'une adresse 169.254.x.x (APIPA).',
      'Sur <b>SW_ACCES</b> : VLAN 10 <code>Informatique</code>, 20 <code>Direction</code>, 30 <code>Serveurs</code> ; <code>fa0/1 - 5</code> en VLAN 10, <code>fa0/6 - 10</code> en VLAN 20, <code>fa0/11 - 15</code> en VLAN 30 (mode access) ; <code>fa0/24</code> en trunk (VLAN 10, 20, 30).',
      'Sur <b>R1_INFRA</b> : <code>no shutdown</code> sur <code>gi0/0</code> ; sous-interfaces <code>gi0/0.10</code>, <code>.20</code>, <code>.30</code> avec <code>encapsulation dot1Q</code> et les passerelles <code>192.168.10.1</code>, <code>192.168.20.1</code>, <code>192.168.30.1</code> (masque /24).',
      'Les clients sont dans un autre réseau que le serveur DHCP : ajoutez <code>ip helper-address 192.168.30.10</code> sur les sous-interfaces des VLAN 10 et 20 (pas sur le VLAN 30).',
      'Sur les clients : <code>ipconfig /renew</code>, puis <code>ipconfig /all</code> (adresse, passerelle, serveur DHCP, DNS). Testez <code>nslookup ns1.infra.local</code> et <code>ping 192.168.30.10</code>.',
      'Dans l\'analyseur (liaison routeur – commutateur), filtre <code>dhcp</code> : comparez le Discover (diffusion) et le paquet relayé vers le serveur (unicast, champ giaddr). Cliquez sur « Vérifier mon travail ».'],
    checks: [
      { t: 'cli', label: 'SW_ACCES : VLAN 10, 20 et 30 créés', dev: ['SW_ACCES', 'Switch'], cmd: 'show vlan brief', match: '10\\s+Informatique[\\s\\S]*20\\s+Direction[\\s\\S]*30\\s+Serveurs' },
      { t: 'cli', label: 'SW_ACCES : fa0/24 est un trunk', dev: ['SW_ACCES', 'Switch'], cmd: 'show interfaces trunk', match: 'Fa0/24\\s+on' },
      { t: 'cli', label: 'R1_INFRA : sous-interfaces .10, .20 et .30 avec leurs passerelles', dev: ['R1_INFRA', 'Router'], cmd: 'show ip interface brief', match: '\\.10\\s+192\\.168\\.10\\.1[\\s\\S]*\\.20\\s+192\\.168\\.20\\.1[\\s\\S]*\\.30\\s+192\\.168\\.30\\.1' },
      { t: 'cli', label: 'R1_INFRA : relais DHCP (ip helper-address) sur les VLAN 10 et 20', dev: ['R1_INFRA', 'Router'], cmd: 'show running-config', match: '\\.10\\n[\\s\\S]*?ip helper-address 192\\.168\\.30\\.10[\\s\\S]*\\.20\\n[\\s\\S]*?ip helper-address 192\\.168\\.30\\.10' },
      { t: 'cli', label: 'PC-INFO obtient une adresse 192.168.10.100-200 par DHCP', dev: 'PC-INFO', cmd: 'ipconfig', match: '192\\.168\\.10\\.(1\\d\\d|200)\\b' },
      { t: 'cli', label: 'PC-DIR obtient une adresse 192.168.20.100-180 par DHCP', dev: 'PC-DIR', cmd: 'ipconfig', match: '192\\.168\\.20\\.(1[0-7]\\d|180)\\b' },
      { t: 'cli', label: 'PC-INFO résout ns1.infra.local', dev: 'PC-INFO', cmd: 'nslookup ns1.infra.local', match: '192\\.168\\.30\\.10' },
      { t: 'ping', label: 'PC-INFO joint PC-DIR (routage inter-VLAN)', from: 'PC-INFO', to: '192.168.20.1' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'Switch', 330, 150); dev('r-1941', 'Router', 330, 10);
    dev('pc-win', 'PC-INFO', 100, 330); dev('pc-win', 'PC-DIR', 330, 330); dev('srv-linux', 'SRV-INFRA', 560, 330);
    link('PC-INFO', 'eth0', 'Switch', 'fa0/1'); link('PC-DIR', 'eth0', 'Switch', 'fa0/6'); link('SRV-INFRA', 'ens33', 'Switch', 'fa0/11'); link('Router', 'gi0/0', 'Switch', 'fa0/24');
    const s = get('SRV-INFRA'); hostIp(s, '192.168.30.10', '24', '192.168.30.1');
    s.dhcpd.enabled = true; s.dhcpd.pools = []; s.dhcpd.excluded = [];
    s.dhcpd.addPool({ name: 'VLAN10', net: IP.parse('192.168.10.0'), mask: IP.parseMask('24'), router: IP.parse('192.168.10.1'), dns: [IP.parse('192.168.30.10')], domain: 'infra.local', lease: 3600, start: IP.parse('192.168.10.100'), end: IP.parse('192.168.10.200') });
    s.dhcpd.addPool({ name: 'VLAN20', net: IP.parse('192.168.20.0'), mask: IP.parseMask('24'), router: IP.parse('192.168.20.1'), dns: [IP.parse('192.168.30.10')], domain: 'infra.local', lease: 3600, start: IP.parse('192.168.20.100'), end: IP.parse('192.168.20.180') });
    s.dnsd.records = [{ name: 'ns1.infra.local', type: 'A', data: '192.168.30.10' }, { name: 'gw.infra.local', type: 'A', data: '192.168.30.1' }, { name: 'intranet.infra.local', type: 'A', data: '192.168.10.50' }]; s.dnsd.start();
    hostDhcp(get('PC-INFO')); hostDhcp(get('PC-DIR'));
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('Switch'), `enable
conf t
hostname SW_ACCES
vlan 10
name Informatique
vlan 20
name Direction
vlan 30
name Serveurs
interface range fa0/1 - 5
switchport mode access
switchport access vlan 10
interface range fa0/6 - 10
switchport mode access
switchport access vlan 20
interface range fa0/11 - 15
switchport mode access
switchport access vlan 30
interface fa0/24
switchport mode trunk
switchport trunk allowed vlan 10,20,30
end`);
    cliRun(sim, get('Router'), `enable
conf t
hostname R1_INFRA
interface gi0/0
no shutdown
interface gi0/0.10
encapsulation dot1Q 10
ip address 192.168.10.1 255.255.255.0
ip helper-address 192.168.30.10
interface gi0/0.20
encapsulation dot1Q 20
ip address 192.168.20.1 255.255.255.0
ip helper-address 192.168.30.10
interface gi0/0.30
encapsulation dot1Q 30
ip address 192.168.30.1 255.255.255.0
end`);
    sim.runFor(8000);
    ['PC-INFO', 'PC-DIR'].forEach(n => { const h = get(n); const i = h.ifaceList()[0]; h.enableDhcp(i, false); h.applyIp(i.name, { dhcp: true }); });
  },
};
