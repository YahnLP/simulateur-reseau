const { mk, hostIp } = require('../tp-lib');
const REC = [
  { name: 'ns1.techpro.local', type: 'A', data: '192.168.10.1' }, { name: 'www.techpro.local', type: 'A', data: '192.168.10.50' },
  { name: 'mail.techpro.local', type: 'A', data: '192.168.10.51' }, { name: 'srv-fichier.techpro.local', type: 'A', data: '192.168.10.20' },
  { name: 'srv-nas.techpro.local', type: 'A', data: '192.168.10.10' },
  { name: 'intranet.techpro.local', type: 'CNAME', data: 'www.techpro.local' }, { name: 'ftp.techpro.local', type: 'CNAME', data: 'srv-fichier.techpro.local' }];
module.exports = {
  file: 'TP-S08-dns.json',
  meta: {
    id: 'cours-s08-dns', type: 'decouverte', diff: 2, cat: 'Cours BTS SIO — S08', level: 'BTS SIO SISR 1re année — Bloc 2 — S08', duration: '45 min',
    title: 'S08 — Zone DNS techpro.local : enregistrements A et CNAME',
    desc: 'Le serveur DNS du cabinet TechPro est installé mais sa zone est vide : créer les enregistrements A et les alias CNAME, puis tester la résolution directe et inverse depuis un poste. (Le TP Bind9 complet reste à faire sur la machine virtuelle Debian.)',
    objectives: ['Distinguer un enregistrement A d\'un alias CNAME', 'Alimenter la zone techpro.local du serveur DNS', 'Tester la résolution directe et inverse avec nslookup et lire la requête DNS dans l\'analyseur'],
    steps: [
      'Le serveur <code>SRV-DNS</code> (192.168.10.1) et le poste <code>PC-01</code> (DNS = 192.168.10.1) sont prêts. Sur <code>PC-01</code> : <code>nslookup www.techpro.local</code> échoue, car la zone est vide.',
      'Ouvrez <b>SRV-DNS</b> → onglet <b>Services → DNS</b>. Créez les enregistrements <b>A</b> : <code>ns1</code> 192.168.10.1, <code>www</code> 192.168.10.50, <code>mail</code> 192.168.10.51, <code>srv-fichier</code> 192.168.10.20, <code>srv-nas</code> 192.168.10.10 (noms complets en <code>.techpro.local</code>).',
      'Créez les alias <b>CNAME</b> : <code>intranet.techpro.local</code> → <code>www.techpro.local</code> et <code>ftp.techpro.local</code> → <code>srv-fichier.techpro.local</code>. Activez le service DNS.',
      'Sur <code>PC-01</code> : <code>nslookup www.techpro.local</code>, <code>nslookup mail.techpro.local</code>, <code>nslookup intranet.techpro.local</code> (réponse CNAME puis A), et la résolution inverse <code>nslookup 192.168.10.50</code>.',
      'Dans l\'analyseur (liaison SRV-DNS – commutateur), filtre <code>dns</code> : repérez la question (type A), la réponse et le champ TTL. Cliquez sur « Vérifier mon travail ».'],
    checks: [
      { t: 'cli', label: 'www.techpro.local se résout en 192.168.10.50', dev: 'PC-01', cmd: 'nslookup www.techpro.local', match: '192\\.168\\.10\\.50' },
      { t: 'cli', label: 'mail.techpro.local se résout en 192.168.10.51', dev: 'PC-01', cmd: 'nslookup mail.techpro.local', match: '192\\.168\\.10\\.51' },
      { t: 'cli', label: 'srv-fichier.techpro.local se résout en 192.168.10.20', dev: 'PC-01', cmd: 'nslookup srv-fichier.techpro.local', match: '192\\.168\\.10\\.20' },
      { t: 'cli', label: 'L\'alias intranet.techpro.local mène à 192.168.10.50 (CNAME)', dev: 'PC-01', cmd: 'nslookup intranet.techpro.local', match: '192\\.168\\.10\\.50' },
      { t: 'cli', label: 'L\'alias ftp.techpro.local mène à 192.168.10.20 (CNAME)', dev: 'PC-01', cmd: 'nslookup ftp.techpro.local', match: '192\\.168\\.10\\.20' },
      { t: 'cli', label: 'Résolution inverse : 192.168.10.50 donne www.techpro.local', dev: 'PC-01', cmd: 'nslookup 192.168.10.50', match: 'www\\.techpro\\.local' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('sw-8p', 'SW1', 330, 130); dev('srv-linux', 'SRV-DNS', 150, 320); dev('pc-win', 'PC-01', 510, 320);
    link('SRV-DNS', 'ens33', 'SW1', 'port1'); link('PC-01', 'eth0', 'SW1', 'port2');
    hostIp(get('SRV-DNS'), '192.168.10.1', '24'); hostIp(get('PC-01'), '192.168.10.100', '24', undefined, '192.168.10.1');
  },
  solve(sim) { const { get } = mk(sim); const s = get('SRV-DNS'); s.dnsd.records = REC.map(r => Object.assign({}, r)); s.dnsd.start(); },
};
