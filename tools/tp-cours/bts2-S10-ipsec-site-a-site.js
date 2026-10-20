const { mk, cliRun, hostIp, NS, IP } = require('../tp-lib');
const base = {
  R1: 'enable\nconf t\nhostname R1\nno ip domain-lookup\ninterface gi0/0\nip address 192.168.1.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 203.0.113.1 255.255.255.252\nno shutdown\nexit\nip route 0.0.0.0 0.0.0.0 203.0.113.2\nend',
  R2: 'enable\nconf t\nhostname R2\nno ip domain-lookup\ninterface gi0/0\nip address 192.168.2.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 198.51.100.1 255.255.255.252\nno shutdown\nexit\nip route 0.0.0.0 0.0.0.0 198.51.100.2\nend',
  ISP: 'enable\nconf t\nhostname ISP\ninterface gi0/0\nip address 203.0.113.2 255.255.255.252\nno shutdown\ninterface gi0/1\nip address 198.51.100.2 255.255.255.252\nno shutdown\nend',
};
const ipsec = (peer, local, remote) => `enable
conf t
ip access-list extended VPN
permit ip ${local} 0.0.0.255 ${remote} 0.0.0.255
exit
crypto isakmp policy 10
encryption aes 256
hash sha
authentication pre-share
group 2
exit
crypto isakmp key CIEL2026 address ${peer}
crypto ipsec transform-set TS esp-aes 256 esp-sha-hmac
exit
crypto map CMAP 10 ipsec-isakmp
set peer ${peer}
set transform-set TS
match address VPN
exit
interface gi0/1
crypto map CMAP
end`;
module.exports = {
  file: 'TP-bts2-S10-ipsec-site-a-site.json',
  meta: {
    id: 'cours-bts2-s10-ipsec', type: 'decouverte', diff: 3, cat: 'Cours BTS SIO — 2e année', level: 'BTS SIO SISR 2e année — Bloc 2 — S10', duration: '1 h',
    title: 'S10 — Tunnel IPsec site à site entre deux routeurs Cisco',
    desc: 'Comparaison avec WireGuard : le même besoin (relier deux agences à travers Internet) réalisé avec IPsec (ISAKMP/IKEv1 + ESP) sur deux routeurs Cisco, avec preuve du chiffrement dans l\'analyseur.',
    objectives: ['Configurer une politique ISAKMP, une clé pré-partagée, un transform-set et une crypto map', 'Définir le trafic à protéger par une ACL', 'Prouver le fonctionnement : association de sécurité (SA), compteurs, trames ESP chiffrées'],
    steps: [
      'Deux agences (<code>192.168.1.0/24</code> et <code>192.168.2.0/24</code>) sont reliées par un « Internet » simulé (<code>203.0.113.0/30</code> et <code>198.51.100.0/30</code>). Les adresses privées ne sont pas routées sur Internet : <code>PC-A</code> ne joint pas <code>PC-B</code>.',
      'Sur <b>R1</b>, l\'ACL du trafic à protéger : <code>ip access-list extended VPN</code>, <code>permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255</code>.',
      'Phase 1 (ISAKMP) : <code>crypto isakmp policy 10</code> avec <code>encryption aes 256</code>, <code>hash sha</code>, <code>authentication pre-share</code>, <code>group 2</code> ; puis <code>crypto isakmp key CIEL2026 address 198.51.100.1</code>.',
      'Phase 2 (IPsec) : <code>crypto ipsec transform-set TS esp-aes 256 esp-sha-hmac</code>, puis <code>crypto map CMAP 10 ipsec-isakmp</code> avec <code>set peer 198.51.100.1</code>, <code>set transform-set TS</code> et <code>match address VPN</code>. Appliquez-la : <code>interface gi0/1</code> puis <code>crypto map CMAP</code>.',
      'Faites la configuration <b>symétrique sur R2</b> (pair <code>203.0.113.1</code>, ACL dans l\'autre sens, même clé et mêmes paramètres : une différence empêche le tunnel de monter).',
      'Générez du trafic (<code>ping 192.168.2.10</code> depuis PC-A) puis vérifiez : <code>show crypto isakmp sa</code> (état QM_IDLE) et <code>show crypto ipsec sa</code> (compteurs encaps/decaps).',
      'Analyseur sur le lien R1 – ISP : filtre <code>esp</code>. Le contenu est illisible : comparez avec WireGuard. Cliquez sur « Vérifier mon travail ».'],
    checks: [
      { t: 'ping', label: 'PC-A joint PC-B à travers le tunnel', from: 'PC-A', to: '192.168.2.10', wait: 3000 },
      { t: 'cli', label: 'R1 : ISAKMP SA établie (QM_IDLE)', dev: 'R1', cmd: 'show crypto isakmp sa', match: 'QM_IDLE' },
      { t: 'cli', label: 'R1 : paquets chiffrés (encaps)', dev: 'R1', cmd: 'show crypto ipsec sa', match: '#pkts encaps: [1-9]' },
      { t: 'cli', label: 'R2 : paquets déchiffrés (decaps)', dev: 'R2', cmd: 'show crypto ipsec sa', match: '#pkts decaps: [1-9]' },
      { t: 'cli', label: 'R1 : crypto map appliquée sur gi0/1', dev: 'R1', cmd: 'show running-config', match: 'interface GigabitEthernet0/1[\\s\\S]*?crypto map CMAP' },
      { t: 'cli', label: 'R1 : chiffrement AES 256 et clé pré-partagée', dev: 'R1', cmd: 'show crypto isakmp policy', match: 'aes[\\s\\S]*Pre-Shared' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'R1', 150, 200); dev('r-2911', 'ISP', 400, 100); dev('r-2911', 'R2', 650, 200); dev('pc-win', 'PC-A', 150, 380); dev('pc-win', 'PC-B', 650, 380);
    link('R1', 'gi0/1', 'ISP', 'gi0/0'); link('ISP', 'gi0/1', 'R2', 'gi0/1'); link('PC-A', 'eth0', 'R1', 'gi0/0'); link('PC-B', 'eth0', 'R2', 'gi0/0');
    hostIp(get('PC-A'), '192.168.1.10', '24', '192.168.1.1'); hostIp(get('PC-B'), '192.168.2.10', '24', '192.168.2.1');
    Object.keys(base).forEach(n => cliRun(sim, get(n), base[n]));
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('R1'), ipsec('198.51.100.1', '192.168.1.0', '192.168.2.0'));
    cliRun(sim, get('R2'), ipsec('203.0.113.1', '192.168.2.0', '192.168.1.0'));
    sim.runFor(1000);
    const p = get('PC-A'); let d = false; NS.tools.pingSeries(p, IP.parse('192.168.2.10'), { count: 4, interval: 300 }, () => { }, () => { d = true; }); sim.runUntil(() => d, 30000);
  },
};
