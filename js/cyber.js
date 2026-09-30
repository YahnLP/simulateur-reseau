/* cyber.js — outils pédagogiques de cybersécurité (postes Linux uniquement, réseau simulé et isolé)
   nmap-lite : sonde une plage de ports TCP courants (connect scan) sur une cible.
   arpspoof   : empoisonnement de cache ARP (usurpation) — illustre le MITM sur un LAN non protégé.
   macflood   : sature la table d'adresses MAC d'un commutateur (attaque « CAM overflow » / macof).
   Ces commandes n'existent que dans ce simulateur hors-ligne : elles agissent uniquement sur les
   équipements de la maquette et ne produisent aucun trafic réel. Objectif : comprendre les attaques
   de couche 2/3 les plus courantes en TP et vérifier les contre-mesures (port-security, DAI, etc.). */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, tools } = NS;
const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389, 8080];
const SVC_NAME = { 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 3389: 'ms-wbt-server', 8080: 'http-proxy' };

/* ---- nmap-lite : scan TCP connect sur une liste de ports ---- */
function nmapScan(host, io, args, shell) {
  let name = args.find(a => !a.startsWith('-'));
  const pspec = args.find(a => a.startsWith('-p'));
  if (!name) { io.print('Usage: nmap [-p ports] cible\n'); return; }
  const ports = pspec ? pspec.replace('-p', '').split(',').map(Number).filter(Boolean) : COMMON_PORTS;
  shell.resolveOrFail(name, io, (dst) => {
    io.print('Starting Nmap ( simulateur pédagogique ) sur ' + name + '\n');
    io.print('Nmap scan report for ' + name + ' (' + IP.str(dst) + ')\n');
    io.print('PORT     STATE    SERVICE\n');
    let i = 0; const rows = [];
    const next = () => {
      if (i >= ports.length) { io.print(rows.join('')); io.print('\nNmap done: 1 IP address scanned.\n'); io.done(); return; }
      const port = ports[i++];
      const c = host.tcpConnect(dst, port, {
        onOpen: () => { rows.push(pad(port + '/tcp', 9) + pad('open', 9) + (SVC_NAME[port] || 'unknown') + '\n'); if (c && c.close) c.close(); host.sim.at(30, next); },
        onError: (e) => { if (e === 'refused') rows.push(pad(port + '/tcp', 9) + pad('closed', 9) + (SVC_NAME[port] || 'unknown') + '\n'); else rows.push(pad(port + '/tcp', 9) + pad('filtered', 9) + (SVC_NAME[port] || 'unknown') + '\n'); host.sim.at(30, next); },
      });
      if (!c) { rows.push(pad(port + '/tcp', 9) + pad('filtered', 9) + (SVC_NAME[port] || 'unknown') + '\n'); host.sim.at(30, next); }
    };
    next();
  });
}
function pad(s, n) { s = String(s); return s.length >= n ? s + ' ' : s + ' '.repeat(n - s.length); }

/* ---- arpspoof : usurpation ARP périodique tant que la commande tourne (Ctrl+C = abort) ---- */
function arpSpoof(host, io, args, shell) {
  const targetName = args[0], impersonateName = args[1];
  if (!targetName || !impersonateName) { io.print('Usage: arpspoof <IP cible> <IP à usurper (ex. la passerelle)>\n'); return; }
  const target = IP.parse(targetName), imp = IP.parse(impersonateName);
  if (!target || !imp) { io.print('arpspoof: adresses IP invalides\n'); return; }
  const iface = host.mainIface;
  io.print(IP.str(host.mainIface.ip) + ' is-at ' + host.mainIface.mac + ' (envoi de réponses ARP falsifiées, Ctrl+C pour arrêter)\n');
  let n = 0;
  const tick = () => {
    if (shell.aborted) { io.print('\n^C\n'); io.done(); return; }
    /* réponse ARP non sollicitée : « imp est à l'adresse MAC de l'attaquant », envoyée à target */
    host.arpResolve(iface, target, mac => {
      if (mac) host.sendArp(iface, 2, mac, target, mac, imp);
    });
    n++;
    host.sim.at(1500, tick);
  };
  tick();
  return 'async';
}

/* ---- macflood : envoie des trames avec des adresses MAC source aléatoires (attaque CAM overflow) ---- */
function macFlood(host, io, args, shell) {
  const n = Math.min(+(args[0]) || 20000, 200000);
  const iface = host.mainIface; const port = iface && iface.port;
  if (!port) { io.print('macflood: aucune interface câblée\n'); return; }
  io.print('Envoi de ' + n + ' trames à adresses MAC source aléatoires sur ' + iface.name + '…\n');
  let i = 0;
  const batch = () => {
    if (shell.aborted) { io.print('^C\n'); io.done(); return; }
    const end = Math.min(i + 500, n);
    for (; i < end; i++) {
      const src = MAC.fromBytes(host.sim.rng.bytes(6).map((b, k) => k === 0 ? (b & 0xfe) | 0x02 : b), 0);
      const frame = Codec.frame({ dst: MAC.BCAST, src, type: 0x0800, payload: host.sim.rng.bytes(46) });
      host.send(port, frame);
    }
    if (i < n) host.sim.at(20, batch);
    else { io.print('Terminé : ' + n + ' trames envoyées.\n'); io.done(); }
  };
  batch();
  return 'async';
}

if (NS.HostShell) {
  const HostShell = NS.HostShell;
  HostShell.prototype.linCmds.nmap = function (a, io) { nmapScan(this.host, io, a, this); return 'async'; };
  HostShell.prototype.linCmds.arpspoof = function (a, io) { return arpSpoof(this.host, io, a, this); };
  HostShell.prototype.linCmds.macflood = function (a, io) { return macFlood(this.host, io, a, this); };
  const oldHelp = HostShell.prototype.linCmds.help;
  HostShell.prototype.linCmds.help = function (a, io) { oldHelp.call(this, a, io); io.print('Outils cybersécurité (TP) : nmap [-p ports] cible, arpspoof <cible> <à usurper>, macflood [n]\n'); };
}
})(typeof window !== 'undefined' ? window : globalThis);
