const { mk, cliRun, hostIp } = require('../tp-lib');
const R1 = `enable
conf t
hostname R1
no ip domain-lookup
interface gi0/0
ip address 192.168.10.1 255.255.255.0
no shutdown
interface gi0/1
ip address 10.0.0.1 255.255.255.252
bandwidth 512
no shutdown
exit
ip route 192.168.20.0 255.255.255.0 10.0.0.2
end`;
const R2 = `enable
conf t
hostname R2
no ip domain-lookup
interface gi0/0
ip address 192.168.20.1 255.255.255.0
no shutdown
interface gi0/1
ip address 10.0.0.2 255.255.255.252
bandwidth 512
no shutdown
exit
ip route 192.168.10.0 255.255.255.0 10.0.0.1
end`;
module.exports = {
  file: 'TP-bts2-S04-qos-llq.json',
  meta: {
    id: 'cours-bts2-s04-qos-llq', type: 'decouverte', diff: 3, cat: 'Cours BTS SIO — 2e année', level: 'BTS SIO SISR 2e année — Bloc 2 — S04', duration: '30 min',
    title: 'S04 — QoS : file prioritaire (LLQ) sur le lien WAN d\'un routeur Cisco',
    desc: 'Transposition sur un routeur Cisco de la politique vue avec tc sous Linux : classer la voix marquée DSCP EF, lui réserver 128 kbit/s en priorité et appliquer la politique en sortie du lien WAN.',
    objectives: ['Écrire une configuration QoS Cisco (class-map, policy-map, service-policy)', 'Réserver une bande passante prioritaire à la voix', 'Vérifier l\'application de la politique avec show policy-map interface'],
    steps: [
      'Le plan relie deux sites par un lien WAN limité à 512 kbit/s (<code>R1 gi0/1</code> – <code>R2 gi0/1</code>, <code>10.0.0.0/30</code>). Les routes statiques sont déjà en place : vérifiez que <code>PC-SiteA</code> joint <code>PC-SiteB</code>.',
      'Sur <b>R1</b>, créez la classe de la voix : <code>class-map match-any VOIX</code> puis <code>match ip dscp ef</code>.',
      'Créez la politique : <code>policy-map QOS-WAN</code>, classe <code>VOIX</code> avec <code>priority 128</code> (128 kbit/s en priorité), classe <code>class-default</code> avec <code>fair-queue</code> (partage équitable du reste).',
      'Appliquez-la en sortie du lien WAN : sur <code>gi0/1</code>, <code>service-policy output QOS-WAN</code>. Sur matériel, l\'interface serait <code>serial 0/0/0</code>.',
      'Vérifiez avec <code>show policy-map QOS-WAN</code> puis <code>show policy-map interface gi0/1</code> (classes, priorité, politique en sortie). Lancez un ping pour voir évoluer les compteurs, puis cliquez sur « Vérifier mon travail ».',
      'Réfléchissez : pourquoi applique-t-on la politique en <b>sortie</b> ? Que se passe-t-il pour la voix si la classe prioritaire est trop petite ?'],
    checks: [
      { t: 'ping', label: 'PC-SiteA joint PC-SiteB', from: 'PC-SiteA', to: '192.168.20.10' },
      { t: 'cli', label: 'Classe VOIX : match sur DSCP EF', dev: 'R1', cmd: 'show class-map VOIX', match: 'VOIX[\\s\\S]*dscp\\s+ef' },
      { t: 'cli', label: 'Politique QOS-WAN : VOIX en priorité 128 kbit/s', dev: 'R1', cmd: 'show policy-map QOS-WAN', match: 'Class VOIX\\s+priority 128' },
      { t: 'cli', label: 'Politique QOS-WAN : classe par défaut', dev: 'R1', cmd: 'show policy-map QOS-WAN', match: 'Class class-default' },
      { t: 'cli', label: 'Politique appliquée en sortie de gi0/1', dev: 'R1', cmd: 'show policy-map interface gi0/1', match: 'Service-policy output: QOS-WAN' }],
  },
  build(sim) {
    const { dev, link, get } = mk(sim);
    dev('r-2911', 'R1', 250, 200); dev('r-2911', 'R2', 550, 200); dev('pc-win', 'PC-SiteA', 100, 360); dev('pc-win', 'PC-SiteB', 700, 360);
    link('PC-SiteA', 'eth0', 'R1', 'gi0/0'); link('R1', 'gi0/1', 'R2', 'gi0/1'); link('R2', 'gi0/0', 'PC-SiteB', 'eth0');
    hostIp(get('PC-SiteA'), '192.168.10.10', '24', '192.168.10.1'); hostIp(get('PC-SiteB'), '192.168.20.10', '24', '192.168.20.1');
    cliRun(sim, get('R1'), R1); cliRun(sim, get('R2'), R2);
  },
  solve(sim) {
    const { get } = mk(sim);
    cliRun(sim, get('R1'), `enable
conf t
class-map match-any VOIX
match ip dscp ef
exit
policy-map QOS-WAN
class VOIX
priority 128
exit
class class-default
fair-queue
exit
exit
interface gi0/1
service-policy output QOS-WAN
end`);
  },
};
