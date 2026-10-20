const { mk, cliRun, hostIp } = require('../tp-lib');
const HN = 'SW_BUREAU_01';
module.exports = {
  file: 'TP-S05-commutation-cisco.json',
  meta: {
    id: 'cours-s05-commutation', type: 'decouverte', diff: 1, cat: 'Cours BTS SIO — S05', level: 'BTS SIO SISR 1re année — Bloc 2 — S05', duration: '45 min',
    title: 'S05 — Premiers réglages et sécurisation d\'un commutateur Cisco',
    desc: 'Un commutateur neuf et trois postes du cabinet TechPro : nommer l\'équipement, afficher un avertissement légal, protéger les accès (privilégié, console, VTY), chiffrer les mots de passe et sauvegarder.',
    objectives: ['Naviguer entre les modes User EXEC, Privileged EXEC et Global Config', 'Appliquer une configuration de base sécurisée', 'Vérifier et sauvegarder la configuration (running-config, startup-config)'],
    steps: [
      'Ouvrez le terminal du commutateur (double-clic). Il est au prompt <code>Switch&gt;</code>. Passez en mode privilégié avec <code>enable</code>, puis en configuration globale avec <code>configure terminal</code>.',
      'Nommez-le <code>SW_BUREAU_01</code> (<code>hostname</code>) et désactivez la résolution de noms (<code>no ip domain-lookup</code>).',
      'Ajoutez un avertissement : <code>banner motd #ACCES RESERVE AU PERSONNEL AUTORISE#</code>.',
      'Protégez le mode privilégié : <code>enable secret Cisco@2024</code>.',
      'Protégez la console : <code>line console 0</code>, <code>password Console@2024</code>, <code>login</code>, <code>exec-timeout 5 0</code>. Puis les accès distants : <code>line vty 0 15</code>, <code>password Vty@2024</code>, <code>login</code>, <code>exec-timeout 5 0</code>.',
      'Chiffrez les mots de passe en clair : <code>service password-encryption</code>. Terminez par <code>end</code>.',
      'Vérifiez avec <code>show running-config</code> (lisez ligne par ligne) puis sauvegardez avec <code>copy running-config startup-config</code>. Cliquez sur « Vérifier mon travail ».'],
    checks: [
      { t: 'cli', label: 'Le commutateur s\'appelle SW_BUREAU_01', dev: HN, cmd: 'show running-config', match: 'hostname SW_BUREAU_01' },
      { t: 'cli', label: 'La résolution de noms est désactivée', dev: [HN, 'Switch'], cmd: 'show running-config', match: 'no ip domain-lookup' },
      { t: 'cli', label: 'Un banner motd est configuré', dev: [HN, 'Switch'], cmd: 'show running-config', match: 'banner motd .*AUTORIS' },
      { t: 'cli', label: 'enable secret est défini (haché, pas enable password)', dev: [HN, 'Switch'], cmd: 'show running-config', match: 'enable secret 5' },
      { t: 'cli', label: 'Console protégée : mot de passe, login et exec-timeout', dev: [HN, 'Switch'], cmd: 'show running-config', match: 'line con 0[\\s\\S]*?password[\\s\\S]*?login' },
      { t: 'cli', label: 'Lignes VTY 0 15 protégées par mot de passe et login', dev: [HN, 'Switch'], cmd: 'show running-config', match: 'line vty 0 15[\\s\\S]*?password[\\s\\S]*?login' },
      { t: 'cli', label: 'service password-encryption est actif (mots de passe en type 7)', dev: [HN, 'Switch'], cmd: 'show running-config', match: '\\nservice password-encryption[\\s\\S]*password 7' },
      { t: 'cli', label: 'La configuration est sauvegardée dans la startup-config', dev: [HN, 'Switch'], cmd: 'show startup-config', match: 'hostname SW_BUREAU_01' },
      { t: 'ping', label: 'PC-Alice joint PC-Bob', from: 'PC-Alice', to: '192.168.10.20' },
      { t: 'ping', label: 'PC-Alice joint PC-Clara', from: 'PC-Alice', to: '192.168.10.30' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'Switch', 330, 110);
    [['PC-Alice', 10, 120], ['PC-Bob', 20, 330], ['PC-Clara', 30, 540]].forEach(([n, ip, x], i) => { dev('pc-win', n, x, 320); link(n, 'eth0', 'Switch', `fa0/${i + 1}`); hostIp(get(n), `192.168.10.${ip}`, '24'); });
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('Switch'), `enable
configure terminal
hostname ${HN}
no ip domain-lookup
banner motd #ACCES RESERVE AU PERSONNEL AUTORISE#
enable secret Cisco@2024
line console 0
password Console@2024
login
exec-timeout 5 0
exit
line vty 0 15
password Vty@2024
login
exec-timeout 5 0
exit
service password-encryption
end
copy running-config startup-config

`);
  },
};
