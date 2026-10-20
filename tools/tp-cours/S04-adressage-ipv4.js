const { mk, cliRun, hostIp } = require('../tp-lib');
module.exports = {
  file: 'TP-S04-adressage-ipv4.json',
  meta: {
    id: 'cours-s04-adressage', type: 'probleme', diff: 1, cat: 'Cours BTS SIO — S04', level: 'BTS SIO SISR 1re année — Bloc 2 — S04', duration: '45 min',
    title: 'S04 — Configuration IPv4 d\'un poste et diagnostic d\'un masque erroné',
    desc: 'Le réseau 192.168.50.0/24 est relié à un serveur distant par une passerelle. Un poste est à configurer, un autre a une erreur de masque : configurer, tester avec ipconfig et ping, puis corriger.',
    objectives: ['Configurer une adresse IPv4 statique (adresse, masque, passerelle, DNS) et la contrôler avec ipconfig', 'Tester la connectivité locale, vers la passerelle puis vers un réseau distant', 'Diagnostiquer une erreur de masque et comprendre pourquoi la passerelle devient injoignable'],
    steps: [
      '<code>PC-05</code> n\'est pas configuré. Double-clic → onglet <b>Configuration IP</b> : adresse <code>192.168.50.5</code>, masque <code>255.255.255.0</code>, passerelle <code>192.168.50.1</code>, DNS <code>8.8.8.8</code>. Contrôlez avec <code>ipconfig /all</code> (notez l\'adresse MAC).',
      'Tests par paliers, de PC-05 : <code>ping 127.0.0.1</code> (pile IP), <code>ping 192.168.50.5</code> (sa propre carte), <code>ping 192.168.50.1</code> (passerelle), <code>ping 203.0.113.10</code> (serveur distant, à travers le routeur). Notez où le premier échec apparaît, s\'il y en a un.',
      'Testez <code>ping 192.168.50.140</code> (PC-06). Ça échoue. Sur PC-06, lancez <code>ipconfig</code> puis <code>ping 192.168.50.1</code> : la passerelle est aussi injoignable. Comparez l\'adresse, le masque et la passerelle de PC-06 : calculez la plage du réseau pour le masque configuré.',
      'Corrigez PC-06 (le masque doit être <code>255.255.255.0</code>) puis retestez : <code>ping 192.168.50.1</code> et <code>ping 203.0.113.10</code>.',
      '<code>arp -a</code> sur PC-05 : quelles adresses MAC sont apprises ? Analyseur sur la liaison PC-05 – commutateur : filtre <code>arp</code>. Cliquez sur « Vérifier mon travail ».'],
    checks: [
      { t: 'cli', label: 'PC-05 : 192.168.50.5, masque 255.255.255.0, passerelle 192.168.50.1', dev: 'PC-05', cmd: 'ipconfig', match: '192\\.168\\.50\\.5\\b[\\s\\S]*255\\.255\\.255\\.0[\\s\\S]*192\\.168\\.50\\.1\\b' },
      { t: 'cli', label: 'PC-06 : le masque est corrigé (255.255.255.0)', dev: 'PC-06', cmd: 'ipconfig', match: '255\\.255\\.255\\.0' },
      { t: 'ping', label: 'PC-05 joint la passerelle 192.168.50.1', from: 'PC-05', to: '192.168.50.1' },
      { t: 'ping', label: 'PC-05 joint PC-06 (192.168.50.140)', from: 'PC-05', to: '192.168.50.140' },
      { t: 'ping', label: 'PC-06 joint la passerelle 192.168.50.1', from: 'PC-06', to: '192.168.50.1' },
      { t: 'ping', label: 'PC-05 joint le serveur distant 203.0.113.10 (à travers le routeur)', from: 'PC-05', to: '203.0.113.10' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-2960', 'SW1', 200, 150); dev('r-1941', 'GW', 400, 40); dev('srv-linux', 'SRV-WEB', 620, 150); dev('pc-win', 'PC-05', 90, 330); dev('pc-win', 'PC-06', 310, 330);
    link('PC-05', 'eth0', 'SW1', 'fa0/1'); link('PC-06', 'eth0', 'SW1', 'fa0/2'); link('SW1', 'fa0/24', 'GW', 'gi0/0'); link('GW', 'gi0/1', 'SRV-WEB', 'ens33');
    cliRun(sim, get('GW'), 'enable\nconf t\ninterface gi0/0\nip address 192.168.50.1 255.255.255.0\nno shutdown\ninterface gi0/1\nip address 203.0.113.1 255.255.255.0\nno shutdown\nend');
    hostIp(get('SRV-WEB'), '203.0.113.10', '24', '203.0.113.1');
    hostIp(get('PC-06'), '192.168.50.140', '25', '192.168.50.1');
  },
  solve(sim) { const { get } = mk(sim); hostIp(get('PC-05'), '192.168.50.5', '24', '192.168.50.1', '8.8.8.8'); hostIp(get('PC-06'), '192.168.50.140', '24', '192.168.50.1'); },
};
