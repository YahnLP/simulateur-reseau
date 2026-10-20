const { mk, cliRun, hostIp, IP } = require('../tp-lib');
module.exports = {
  file: 'TP-bts2b3-S07-8021x-radius.json',
  meta: {
    id: 'cours-bts2b3-s07-8021x', type: 'decouverte', diff: 3, cat: 'Cours BTS SIO — 2e année', level: 'BTS SIO SISR 2e année — Bloc 3 — S07', duration: '1 h',
    title: 'S07 — 802.1X : un commutateur authentifie un poste auprès d\'un serveur RADIUS',
    desc: 'Côté réseau du TP RADIUS : configurer un commutateur Cisco comme authentificateur 802.1X, vers un serveur RADIUS déjà prêt (utilisateur alice placée dans le VLAN 20), puis constater le blocage avant authentification et l\'attribution du VLAN après.',
    objectives: ['Configurer AAA, le serveur RADIUS et le secret partagé sur un commutateur', 'Activer 802.1X sur un port d\'accès', 'Constater le refus avant authentification, puis l\'acceptation et le VLAN attribué'],
    steps: [
      'Le plan : un commutateur <code>SW1</code>, un serveur <code>RADIUS</code> (<code>192.168.20.5</code>, VLAN 20, utilisateur <code>alice</code> / <code>Lab-2026</code>, secret partagé <code>Secret-Borne-Lab</code>) et un poste <code>PC1</code> sur <code>fa0/1</code>. Le serveur est déjà configuré : vous configurez l\'<b>authentificateur</b>.',
      'Sur <b>SW1</b> : <code>aaa new-model</code>, puis <code>radius server RAD</code> avec <code>address ipv4 192.168.20.5 auth-port 1812 acct-port 1813</code> et <code>key Secret-Borne-Lab</code>.',
      '<code>aaa authentication dot1x default group radius</code>, <code>aaa authorization network default group radius</code> (pour le VLAN attribué) et <code>dot1x system-auth-control</code>.',
      'Sur le port du poste : <code>interface fa0/1</code>, <code>switchport mode access</code>, <code>authentication port-control auto</code> et <code>dot1x pae authenticator</code>.',
      'Avant authentification : <code>PC1</code> ne joint pas le serveur (le port est fermé, sauf pour les trames d\'authentification). Ouvrez l\'onglet <b>802.1X</b> de PC1, saisissez <code>alice</code> / <code>Lab-2026</code>, méthode PEAP, puis activez le demandeur (<i>supplicant</i>).',
      'Contrôlez sur SW1 : <code>show authentication sessions</code> (état Auth) puis <code>show authentication sessions interface fa0/1</code> (utilisateur, état Authorized, <i>Vlan Policy</i> : 20). Testez le ping vers le serveur, puis un mauvais mot de passe : le port reste fermé. Cliquez sur « Vérifier mon travail ».'],
    checks: [
      { t: 'cli', label: 'SW1 : AAA activé et serveur RADIUS déclaré avec son secret', dev: 'SW1', cmd: 'show running-config', match: 'aaa new-model[\\s\\S]*radius server RAD[\\s\\S]*address ipv4 192\\.168\\.20\\.5[\\s\\S]*key Secret-Borne-Lab' },
      { t: 'cli', label: 'SW1 : authentification 802.1X par RADIUS et dot1x system-auth-control', dev: 'SW1', cmd: 'show running-config', match: 'aaa authentication dot1x default group radius[\\s\\S]*dot1x system-auth-control' },
      { t: 'cli', label: 'SW1 : fa0/1 en port-control auto avec dot1x pae authenticator', dev: 'SW1', cmd: 'show running-config', match: 'interface FastEthernet0/1[\\s\\S]*?authentication port-control auto[\\s\\S]*?dot1x pae authenticator' },
      { t: 'cli', label: 'SW1 : le poste est authentifié sur fa0/1', dev: 'SW1', cmd: 'show authentication sessions', match: 'Fa0/1\\s+\\S+\\s+dot1x\\s+\\S+\\s+Auth' },
      { t: 'cli', label: 'SW1 : alice est autorisée sur fa0/1 avec le VLAN 20 attribué par RADIUS', dev: 'SW1', cmd: 'show authentication sessions interface fa0/1', match: 'User-Name:\\s+alice[\\s\\S]*Status:\\s+Authorized[\\s\\S]*Vlan Policy:\\s+20' },
      { t: 'ping', label: 'PC1 joint le serveur RADIUS une fois authentifié', from: 'PC1', to: '192.168.20.5', wait: 3000 }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW1', 350, 150); dev('srv-linux', 'RADIUS', 600, 300); dev('pc-win', 'PC1', 150, 300);
    link('RADIUS', 'ens33', 'SW1', 'fa0/24'); link('PC1', 'eth0', 'SW1', 'fa0/1');
    cliRun(sim, get('SW1'), 'enable\nconf t\nhostname SW1\nvlan 20\nname PERSONNEL\nexit\ninterface vlan 20\nip address 192.168.20.2 255.255.255.0\nno shutdown\nexit\ninterface fa0/24\nswitchport mode access\nswitchport access vlan 20\nend');
    hostIp(get('RADIUS'), '192.168.20.5', '24'); hostIp(get('PC1'), '192.168.20.10', '24');
    const R = get('RADIUS').radius; R.startSrv(); R.addClient(IP.parse('192.168.20.2'), 0xFFFFFFFF, 'Secret-Borne-Lab', 'SW1'); R.addUser('alice', 'Lab-2026', { vlan: 20 });
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('SW1'), 'enable\nconf t\naaa new-model\nradius server RAD\naddress ipv4 192.168.20.5 auth-port 1812 acct-port 1813\nkey Secret-Borne-Lab\nexit\naaa authentication dot1x default group radius\naaa authorization network default group radius\ndot1x system-auth-control\ninterface fa0/1\nswitchport mode access\nauthentication port-control auto\ndot1x pae authenticator\nend');
    const d = get('PC1').dot1x; d.supSet({ user: 'alice', pass: 'Lab-2026', method: 'peap' }); d.supEnable(true);
  },
};
