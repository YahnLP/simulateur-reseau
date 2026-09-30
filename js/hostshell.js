/* hostshell.js — terminaux des postes : invite de commandes Windows (FR) et shell Linux simplifié */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, tools, B } = NS;
const pad = (s, n) => { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); };
const padL = (s, n) => { s = String(s); return s.length >= n ? s : ' '.repeat(n - s.length) + s; };
const macWin = m => m.toUpperCase().replace(/:/g, '-');

class HostShell {
  constructor(host) { this.host = host; this.win = host.os === 'windows'; this.remote = null; this.remoteIo = null; this.aborted = false; this.busy = false; this.history = []; this.cwd = this.win ? 'C:\\Users\\Etudiant' : '~'; this.pending = null; }
  get masking() { return false; }
  prompt() { if (this.remote) return ''; return this.win ? this.cwd + '>' : 'etudiant@' + this.host.name.toLowerCase() + ':' + this.cwd + '$ '; }
  abort() { this.aborted = true; }
  exec(line, io) {
    const h = this.host;
    if (this.remote) { this.remoteIo = io; this.remote.send(line); io.done(); return; }
    const l = line.trim(); if (l) this.history.push(l); if (!l) { io.done(); return; }
    this.aborted = false;
    const toks = l.split(/\s+/); let c = toks[0].toLowerCase(); let args = toks.slice(1);
    if (!this.win && c === 'sudo') { c = (args.shift() || '').toLowerCase(); }
    const fn = this.win ? this.winCmds[c] : this.linCmds[c];
    if (!fn) { io.print(this.win ? '\'' + toks[0] + '\' n\'est pas reconnu en tant que commande interne\nou externe, un programme exécutable ou un fichier de commandes.\n' : toks[0] + ': commande introuvable\n'); io.done(); return; }
    let r;
    try { r = fn.call(this, args, io, toks); } catch (e) { io.print('Erreur interne : ' + e.message + '\n'); console.error(e); }
    if (r !== 'async') io.done();
  }
  /* ---------- utilitaires ---------- */
  ifaces() { return this.host.ifaceList(); }
  waitDhcp(iface, cb) {
    const h = this.host; const c = h.dhcpClients.get(iface.name); const t0 = h.sim.now;
    const chk = () => { if (this.aborted) return cb(); if (!c || c.state === 'BOUND' || c.state === 'APIPA' || c.state === 'FAILED' || h.sim.now - t0 > 30000) return cb(); h.sim.at(100, chk); };
    chk();
  }
  lookup(name, io, cb) {
    const h = this.host;
    h.resolve(name, (err, r) => { if (err) return cb(err, null); cb(null, r); });
  }
  resolveOrFail(name, io, cb, nameFmt) {
    if (IP.parse(name) !== null) return cb(IP.parse(name), false);
    this.lookup(name, io, (err, r) => {
      if (err) { io.print(this.win ? 'La requête Ping n\'a pas pu trouver l\'hôte ' + name + '. Vérifiez le nom et essayez à nouveau.\n' : 'ping: ' + name + ': Temporary failure in name resolution\n'); io.done(); return; }
      cb(r.ip, true);
    });
  }

  /* ---------- Windows ---------- */
  ipconfigBlock(i, all) {
    const h = this.host; const wifi = i.port && i.port.media === 'wifi';
    let o = (wifi ? 'Carte réseau sans fil ' : 'Carte Ethernet ') + i.name + ' :\n\n';
    if (!i.isUp()) return o + '   Statut du média. . . . . . . . . . . . : Média déconnecté\n   Suffixe DNS propre à la connexion. . . :\n\n';
    const dots = (lbl, v) => '   ' + lbl + ' ' + '. '.repeat(Math.max(1, Math.floor((38 - lbl.length - 1) / 2))) + ': ' + v + '\n';
    if (all) { o += dots('Description', 'Intel(R) Ethernet Connection (simulé)'); o += dots('Adresse physique', macWin(i.mac)); o += dots('DHCP activé', i.dhcp ? 'Oui' : 'Non'); o += dots('Configuration automatique activée', 'Oui'); }
    o += dots('Suffixe DNS propre à la connexion', h.domain || '');
    if (i.ip) {
      const apipa = i.apipa; o += dots(apipa ? 'Adresse IPv4 configurée automatiquement' : 'Adresse IPv4', IP.str(i.ip) + (apipa ? '(préféré)' : all ? '(préféré)' : '')); o += dots('Masque de sous-réseau', IP.str(i.mask));
      const gw = h.gateway; o += dots('Passerelle par défaut', gw && !apipa ? IP.str(gw) : '');
      if (all && i.dhcp) { const c = h.dhcpClients.get(i.name); if (c && c.info) { o += dots('Serveur DHCP', IP.str(c.info.server)); o += dots('Bail obtenu', 'mercredi 30 septembre 2026 08:00:00'); o += dots('Bail expirant', 'jeudi 1 octobre 2026 08:00:00'); } }
      if (all && h.dnsServers && h.dnsServers.length) o += dots('Serveurs DNS', h.dnsServers.map(IP.str).join('\n' + ' '.repeat(39)));
    } else { o += dots('Adresse IPv4', ''); }
    return o + '\n';
  }
  ipconfig(a, io) {
    const h = this.host; const f = (a[0] || '').toLowerCase();
    const ifs = this.ifaces();
    if (f === '/release') { ifs.forEach(i => { const c = h.dhcpClients.get(i.name); if (c) c.release(); }); io.print('\nConfiguration IP de Windows\n\n'); ifs.forEach(i => io.print(this.ipconfigBlock(i))); return; }
    if (f === '/renew') {
      const dh = ifs.filter(i => i.dhcp && i.isUp());
      if (!dh.length) { io.print('\nAucune carte ne peut effectuer cette opération.\n'); return; }
      io.print('\nConfiguration IP de Windows\n\n'); let n = dh.length;
      dh.forEach(i => { const c = h.dhcpClients.get(i.name); c.unconfigure(); c.start(); this.waitDhcp(i, () => { if (--n === 0) { io.print(ifs.map(x => this.ipconfigBlock(x)).join('')); io.done(); } }); });
      return 'async';
    }
    if (f === '/flushdns') { io.print('\nConfiguration IP de Windows\n\nLe cache de résolution DNS a été vidé.\n'); return; }
    if (f === '/displaydns') { io.print('\nConfiguration IP de Windows\n\n'); return; }
    io.print('\nConfiguration IP de Windows\n\n'); if (f === '/all') io.print('   Nom d\'hôte . . . . . . . . . . . . . : ' + h.name + '\n   Type de nœud. . . . . . . . . . . . . : Hybride\n   Routage IP activé . . . . . . . . . . : Non\n\n');
    ifs.forEach(i => io.print(this.ipconfigBlock(i, f === '/all')));
  }
  pingWin(a, io, toks) {
    const h = this.host; let count = 4, size = 32, cont = false, name = null; let src;
    for (let i = 0; i < a.length; i++) { const t = a[i].toLowerCase(); if (t === '-n') count = +a[++i] || 4; else if (t === '-l') size = +a[++i] || 32; else if (t === '-t') { cont = true; count = Infinity; } else if (t === '-i') i++; else if (t === '-a') { } else if (t === '-s') src = IP.parse(a[++i]) || undefined; else name = a[i]; }
    if (!name) { io.print('\nUtilisation : ping [-t] [-a] [-n échos] [-l taille] [-i TTL] nom_cible\n'); return; }
    this.resolveOrFail(name, io, (dst, named) => {
      io.print('\nEnvoi d\'une requête \'Ping\'  ' + (named ? name + ' [' + IP.str(dst) + ']' : IP.str(dst)) + ' avec ' + size + ' octets de données :\n');
      tools.pingSeries(h, dst, { count, size, src, abort: () => this.aborted }, (r, seq) => {
        const t = r.rtt < 1 ? '<1ms' : '=' + Math.round(r.rtt) + 'ms';
        if (r.type === 'reply') io.print('Réponse de ' + IP.str(r.from) + ' : octets=' + size + ' temps' + t + ' TTL=' + r.ttl + '\n');
        else if (r.type === 'timeout') io.print('Délai d\'attente de la demande dépassé.\n');
        else if (r.type === 'unreach') io.print('Réponse de ' + IP.str(r.from) + ' : ' + ({ 0: 'Impossible de joindre le réseau de destination.', 1: 'Impossible de joindre l\'hôte de destination.', 3: 'Impossible de joindre le port de destination.', 13: 'Communication administrativement filtrée.' }[r.code] || 'Destination inaccessible.') + '\n');
        else if (r.type === 'ttl') io.print('Réponse de ' + IP.str(r.from) + ' : TTL expiré lors du transit.\n');
        else if (r.type === 'arpfail') io.print('Réponse de ' + IP.str(h.primaryIface.ip) + ' : Impossible de joindre l\'hôte de destination.\n');
        else if (r.type === 'noroute') io.print('PING : échec général.\n');
      }, st => {
        const rt = tools.fmtStats(st.rtts);
        io.print('\nStatistiques Ping pour ' + IP.str(dst) + ':\n    Paquets : envoyés = ' + st.sent + ', reçus = ' + st.recv + ', perdus = ' + (st.sent - st.recv) + ' (perte ' + Math.round((st.sent - st.recv) * 100 / Math.max(1, st.sent)) + '%),\n');
        if (rt) io.print('Durée approximative des boucles en millisecondes :\n    Minimum = ' + Math.floor(rt.mn) + 'ms, Maximum = ' + Math.floor(rt.mx) + 'ms, Moyenne = ' + Math.floor(rt.av) + 'ms\n');
        io.done();
      });
    });
    return 'async';
  }
  tracertWin(a, io) {
    const h = this.host; const name = a.filter(x => !x.startsWith('-'))[0]; if (!name) { io.print('\nUtilisation : tracert [-d] nom_cible\n'); return; }
    this.resolveOrFail(name, io, (dst, named) => {
      io.print('\nDétermination de l\'itinéraire vers ' + (named ? name + ' [' + IP.str(dst) + ']' : IP.str(dst)) + '\navec un maximum de 30 sauts :\n\n');
      tools.trace(h, dst, { maxHops: 30, probes: 3, abort: () => this.aborted }, (ttl, rs) => {
        let line = padL(ttl, 3) + '  ';
        rs.forEach(r => { line += r.type === 'reply' || r.type === 'ttl' || r.type === 'unreach' ? padL(r.rtt < 1 ? '<1 ms' : Math.round(r.rtt) + ' ms', 7) + ' ' : padL('*', 7) + ' '; });
        const first = rs.find(r => r.from !== undefined); line += ' ' + (first ? IP.str(first.from) : 'Délai d\'attente de la demande dépassé.'); io.print(line + '\n');
      }, ok => { io.print(ok ? '\nItinéraire déterminé.\n' : '\nItinéraire non déterminé.\n'); io.done(); });
    });
    return 'async';
  }
  arpWin(a, io) {
    const h = this.host; const f = (a[0] || '').toLowerCase();
    if (f === '-d') { h.arpTable.clear(); return; }
    let any = false;
    this.ifaces().forEach(i => { if (!i.ip || !i.isUp()) return; const es = []; h.arpTable.forEach((e, ip) => { if (e.iface === i) es.push([ip, e]); });
      if (!es.length) return; any = true; io.print('\nInterface : ' + IP.str(i.ip) + ' --- 0x' + (i.port.idx + 4) + '\n  Adresse Internet      Adresse physique      Type\n');
      es.forEach(([ip, e]) => io.print('  ' + pad(IP.str(ip), 22) + pad(macWin(e.mac), 22) + 'dynamique\n')); });
    if (!any) io.print('Aucune entrée ARP trouvée.\n'); else io.print('\n');
  }
  nslookup(a, io) {
    const h = this.host; const name = a[0]; const server = a[1] ? IP.parse(a[1]) : (h.dnsServers || [])[0];
    if (!name) { io.print('Utilisation : nslookup nom [serveur]\n'); return; }
    if (!server) { io.print('*** Aucun serveur DNS configuré\n'); return; }
    const isPtr = IP.parse(name) !== null; const qname = isPtr ? name.split('.').reverse().join('.') + '.in-addr.arpa' : name;
    return this._nslookup(qname, isPtr ? 'PTR' : 'A', server, io, name);
  }
  _nslookup(qname, type, server, io, orig) {
    const h = this.host;
    io.print((this.win ? 'Serveur :  ' : 'Server:\t\t') + IP.str(server) + '\n' + (this.win ? 'Address:  ' : 'Address:\t') + IP.str(server) + (this.win ? '' : '#53') + '\n\n');
    h.dnsQuery(server, qname, type, (err, res) => {
      if (err) io.print(this.win ? '*** Délai d\'attente dépassé (le serveur ' + IP.str(server) + ' ne répond pas)\n' : ';; connection timed out; no servers could be reached\n');
      else if (res.rcode === 3) io.print(this.win ? '*** ' + IP.str(server) + ' ne parvient pas à trouver ' + orig + ' : Non-existent domain\n' : '** server can\'t find ' + orig + ': NXDOMAIN\n');
      else if (!res.answers.length) io.print(this.win ? '*** Aucun enregistrement ' + type + ' disponible pour ' + orig + '\n' : '');
      else { io.print((this.win ? 'Réponse ne faisant pas autorité :\n' : 'Non-authoritative answer:\n')); res.answers.forEach(x => { if (x.type === 'A') io.print((this.win ? 'Nom :    ' : 'Name:\t') + x.name + '\n' + (this.win ? 'Address:  ' : 'Address: ') + x.data + '\n'); else if (x.type === 'CNAME') io.print(x.name + '\tcanonical name = ' + x.data + '\n'); else if (x.type === 'PTR') io.print(qname + '\tname = ' + x.data + '\n'); else if (x.type === 'MX') io.print(x.name + '\tMX preference = ' + x.pref + ', mail exchanger = ' + x.data + '\n'); }); }
      io.done();
    });
    return 'async';
  }
  netstat(a, io) {
    const h = this.host; let o = this.win ? '\nConnexions actives\n\n  Proto  Adresse locale         Adresse distante       État\n' : 'Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\n';
    const row = (pr, l, r, st) => this.win ? '  ' + pad(pr, 7) + pad(l, 22) + pad(r, 23) + st + '\n' : pad(pr.toLowerCase(), 6) + '     0      0 ' + pad(l, 23) + ' ' + pad(r, 23) + ' ' + st + '\n';
    const ST = { ESTABLISHED: this.win ? 'ESTABLISHED' : 'ESTABLISHED', SYN_SENT: 'SYN_SENT', SYN_RCVD: 'SYN_RECV', CLOSE_WAIT: 'CLOSE_WAIT', FIN_WAIT_1: 'FIN_WAIT1', FIN_WAIT_2: 'FIN_WAIT2', TIME_WAIT: 'TIME_WAIT', LAST_ACK: 'LAST_ACK' };
    const ip0 = h.primaryIface ? h.primaryIface.ip : 0;
    h.tcpL.forEach((l, p) => { o += row('TCP', '0.0.0.0:' + p, '0.0.0.0:0', 'LISTENING'); });
    h.udp.forEach((f, p) => { if (p < 1024 || p === 68) o += row('UDP', '0.0.0.0:' + p, '*:*', ''); });
    h.tcpC.forEach(c => { o += row('TCP', IP.str(c.lip) + ':' + c.lport, IP.str(c.rip) + ':' + c.rport, ST[c.state] || c.state); });
    io.print(o);
  }
  routePrint(io) {
    const h = this.host; let o = '===========================================================================\nListe d\'Interfaces\n===========================================================================\nTable de routage IPv4\n===========================================================================\nItinéraires actifs :\nDestination réseau    Masque réseau  Adr. passerelle   Adr. interface Métrique\n';
    h.allRoutes().forEach(r => { o += pad(IP.str(r.net), 18) + pad(IP.str(r.mask), 16) + pad(r.nh ? IP.str(r.nh) : 'On-link', 18) + pad(IP.str(r.iface.ip), 16) + (r.proto === 'C' ? 281 : 25) + '\n'; });
    io.print(o + '===========================================================================\n');
  }
  curl(a, io) {
    const h = this.host; let url = a.filter(x => !x.startsWith('-'))[0]; const head = a.includes('-I'); if (!url) { io.print('curl: try \'curl --help\' for more information\n'); return; }
    h.httpRequest(url, (err, r) => {
      if (err) { io.print(err.startsWith('dns') ? 'curl: (6) Could not resolve host: ' + url.replace(/^https?:\/\//, '').split('/')[0] + '\n' : err === 'timeout' ? 'curl: (28) Failed to connect: Connection timed out\n' : err === 'refused' ? 'curl: (7) Failed to connect: Connection refused\n' : 'curl: (7) Failed to connect (' + err + ')\n'); }
      else if (head) io.print('HTTP/1.1 ' + r.status + ' ' + r.reason + '\n' + Object.keys(r.headers).map(k => k + ': ' + r.headers[k]).join('\n') + '\n');
      else io.print(r.body + (r.body.endsWith('\n') ? '' : '\n'));
      io.done();
    });
    return 'async';
  }
  remote_(a, io, mode) {
    const h = this.host; let target = a.filter(x => !x.startsWith('-')).pop(); if (!target) { io.print(mode === 'ssh' ? 'usage: ssh [user@]hostname\n' : 'Utilisation : telnet hôte\n'); return; }
    if (target.indexOf('@') >= 0) target = target.split('@')[1];
    this.resolveOrFail(target, io, dst => {
      tools.openRemote(h, dst, mode, {
        onOpen: send => { this.remote = { send }; this.remoteIo = io; if (mode === 'ssh') io.print('Warning: Permanently added \'' + IP.str(dst) + '\' (RSA) to the list of known hosts.\n'); io.done(); },
        onText: t => { (this.remoteIo || io).print(t.replace(/\r\n/g, '\n').replace(/\r/g, '')); },
        onClose: () => { const r = this.remote; this.remote = null; (this.remoteIo || io).print('\nConnexion perdue.\n'); if (r) (this.remoteIo || io).done(); },
        onError: e => { io.print(e === 'refused' ? (this.win ? 'La connexion à l\'hôte a échoué sur le port ' + (mode === 'ssh' ? 22 : 23) + ' : échec de la connexion\n' : (mode === 'ssh' ? 'ssh: connect to host ' + IP.str(dst) + ' port 22: Connection refused\n' : 'telnet: Unable to connect to remote host: Connection refused\n')) : 'Impossible d\'atteindre l\'hôte (' + e + ')\n'); io.done(); },
      });
    });
    return 'async';
  }
}

/* ---------- table des commandes Windows ---------- */
HostShell.prototype.winCmds = {
  ipconfig(a, io) { return this.ipconfig(a, io); },
  ping(a, io, t) { return this.pingWin(a, io, t); },
  tracert(a, io) { return this.tracertWin(a, io); },
  arp(a, io) { return this.arpWin(a, io); },
  nslookup(a, io) { return this.nslookup(a, io); },
  netstat(a, io) { return this.netstat(a, io); },
  route(a, io) { if ((a[0] || '').toLowerCase() === 'print') this.routePrint(io); else io.print('Utilisation : route print\n'); },
  hostname(a, io) { io.print(this.host.name + '\n'); },
  whoami(a, io) { io.print(this.host.name.toLowerCase() + '\\etudiant\n'); },
  getmac(a, io) { io.print('\nAdresse physique    Nom de transport\n=================== ==========================================================\n' + macWin(this.host.mainIface.mac) + '   \\Device\\Tcpip_{SIM}\n'); },
  cls(a, io) { io.clear && io.clear(); },
  echo(a, io) { io.print(a.join(' ') + '\n'); },
  curl(a, io) { return this.curl(a, io); },
  telnet(a, io) { return this.remote_(a, io, 'telnet'); },
  ssh(a, io) { return this.remote_(a, io, 'ssh'); },
  ver(a, io) { io.print('\nMicrosoft Windows [version 10.0.22631.4037]\n'); },
  help(a, io) { io.print('Commandes réseau disponibles : ipconfig, ping, tracert, arp, nslookup, netstat, route print, curl, telnet, ssh, hostname, getmac, cls\n'); },
  netsh(a, io) { io.print('Utilisez l\'onglet Configuration du poste pour modifier l\'adresse IP.\n'); },
};
/* ---------- table des commandes Linux ---------- */
HostShell.prototype.linCmds = {
  ip(a, io) {
    const h = this.host; const sub = (a[0] || '').toLowerCase();
    if (sub === 'a' || sub === 'addr' || sub === 'address' || sub === 'l' || sub === 'link' || (sub === 'a' && a[1])) {
      if ((a[1] || '') === 'add') { const m = /^([\d.]+)\/(\d+)$/.exec(a[2] || ''); const i = h.ifaceByName(a[4] || '') || h.mainIface; if (!m) { io.print('Error: any valid prefix is expected rather than "' + a[2] + '".\n'); return; } h.enableDhcp(i, false); i.ip = IP.parse(m[1]); i.mask = IP.maskFromPrefix(+m[2]); h.arpAnnounce(i); return; }
      let n = 1; io.print('1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n' + (sub[0] === 'a' ? '    inet 127.0.0.1/8 scope host lo\n' : ''));
      this.ifaces().forEach(i => { n++; io.print(n + ': ' + i.name + ': <BROADCAST,MULTICAST' + (i.isUp() ? ',UP,LOWER_UP' : '') + '> mtu 1500 qdisc fq_codel state ' + (i.isUp() ? 'UP' : 'DOWN') + ' group default qlen 1000\n    link/ether ' + i.mac + ' brd ff:ff:ff:ff:ff:ff\n'); if (sub[0] === 'a' && i.ip) io.print('    inet ' + IP.str(i.ip) + '/' + IP.prefixFromMask(i.mask) + ' brd ' + IP.str(IP.bcast(i.ip, i.mask)) + ' scope global' + (i.dhcp ? ' dynamic' : '') + ' ' + i.name + '\n'); });
      return;
    }
    if (sub === 'r' || sub === 'route') {
      if ((a[1] || '') === 'add') { if (a[2] === 'default') { h.setGateway(a[4]); return; } const c = IP.parseCidr(a[2] || ''); if (c) { h.addStatic(c.ip, c.mask, IP.parse(a[4]), null, 1); return; } }
      if ((a[1] || '') === 'del' || a[1] === 'flush') { h.statics = []; return; }
      h.allRoutes().sort((x, y) => x.mask - y.mask).forEach(r => { if (r.net === 0 && r.mask === 0) io.print('default via ' + IP.str(r.nh) + ' dev ' + r.iface.name + (h.dhcpClients.get(r.iface.name) ? ' proto dhcp' : '') + '\n'); else io.print(IP.str(r.net) + '/' + IP.prefixFromMask(r.mask) + ' dev ' + r.iface.name + ' proto kernel scope link src ' + IP.str(r.iface.ip) + '\n'); });
      return;
    }
    if (sub === 'n' || sub === 'neigh' || sub === 'neighbor') { h.arpTable.forEach((e, ip) => io.print(IP.str(ip) + ' dev ' + (e.iface ? e.iface.name : '?') + ' lladdr ' + e.mac + ' REACHABLE\n')); return; }
    io.print('Usage: ip [ addr | route | neigh | link ]\n');
  },
  ifconfig(a, io) { this.ifaces().forEach(i => { io.print(i.name + ': flags=' + (i.isUp() ? '4163<UP,BROADCAST,RUNNING,MULTICAST>' : '4098<BROADCAST,MULTICAST>') + '  mtu 1500\n' + (i.ip ? '        inet ' + IP.str(i.ip) + '  netmask ' + IP.str(i.mask) + '  broadcast ' + IP.str(IP.bcast(i.ip, i.mask)) + '\n' : '') + '        ether ' + i.mac + '  txqueuelen 1000  (Ethernet)\n\n'); }); },
  ping(a, io) {
    const h = this.host; let count = Infinity, size = 56, name = null, interval = 1000;
    for (let i = 0; i < a.length; i++) { if (a[i] === '-c') count = +a[++i] || 4; else if (a[i] === '-s') size = +a[++i] || 56; else if (a[i] === '-i') interval = (+a[++i] || 1) * 1000; else if (!a[i].startsWith('-')) name = a[i]; }
    if (!name) { io.print('Usage: ping [-c count] [-s size] destination\n'); return; }
    this.resolveOrFail(name, io, (dst, named) => {
      io.print('PING ' + (named ? name + ' (' + IP.str(dst) + ')' : IP.str(dst) + ' (' + IP.str(dst) + ')') + ' ' + size + '(' + (size + 28) + ') bytes of data.\n');
      const t0 = h.sim.now;
      tools.pingSeries(h, dst, { count, size, interval, abort: () => this.aborted }, (r, seq) => {
        if (r.type === 'reply') io.print((size + 8) + ' bytes from ' + IP.str(r.from) + ': icmp_seq=' + seq + ' ttl=' + r.ttl + ' time=' + r.rtt.toFixed(3) + ' ms\n');
        else if (r.type === 'unreach') io.print('From ' + IP.str(r.from) + ' icmp_seq=' + seq + ' ' + ({ 0: 'Destination Net Unreachable', 1: 'Destination Host Unreachable', 3: 'Destination Port Unreachable', 13: 'Packet filtered' }[r.code] || 'Destination Unreachable') + '\n');
        else if (r.type === 'ttl') io.print('From ' + IP.str(r.from) + ' icmp_seq=' + seq + ' Time to live exceeded\n');
        else if (r.type === 'arpfail') io.print('From ' + IP.str(h.primaryIface.ip) + ' icmp_seq=' + seq + ' Destination Host Unreachable\n');
        else if (r.type === 'noroute') io.print('ping: connect: Network is unreachable\n');
      }, st => {
        const rt = tools.fmtStats(st.rtts);
        io.print('\n--- ' + (named ? name : IP.str(dst)) + ' ping statistics ---\n' + st.sent + ' packets transmitted, ' + st.recv + ' received, ' + Math.round((st.sent - st.recv) * 100 / Math.max(1, st.sent)) + '% packet loss, time ' + Math.round(h.sim.now - t0) + 'ms\n');
        if (rt) io.print('rtt min/avg/max/mdev = ' + rt.mn.toFixed(3) + '/' + rt.av.toFixed(3) + '/' + rt.mx.toFixed(3) + '/0.000 ms\n'); io.done();
      });
    });
    return 'async';
  },
  traceroute(a, io) {
    const h = this.host; const name = a.filter(x => !x.startsWith('-'))[0]; if (!name) { io.print('Usage: traceroute host\n'); return; }
    this.resolveOrFail(name, io, (dst) => {
      io.print('traceroute to ' + name + ' (' + IP.str(dst) + '), 30 hops max, 60 byte packets\n');
      tools.trace(h, dst, { maxHops: 30, probes: 3, abort: () => this.aborted }, (ttl, rs) => {
        const first = rs.find(r => r.from !== undefined); let line = padL(ttl, 2) + '  ' + (first ? IP.str(first.from) + ' (' + IP.str(first.from) + ')' : '* * *');
        if (first) rs.forEach(r => { line += r.type === 'timeout' ? '  *' : '  ' + r.rtt.toFixed(3) + ' ms'; }); io.print(line + '\n');
      }, () => io.done());
    });
    return 'async';
  },
  tracepath(a, io) { return this.linCmds.traceroute.call(this, a, io); },
  arp(a, io) { const h = this.host; io.print('Address                  HWtype  HWaddress           Flags Mask            Iface\n'); h.arpTable.forEach((e, ip) => io.print(pad(IP.str(ip), 24) + ' ether   ' + pad(e.mac, 19) + ' C                     ' + (e.iface ? e.iface.name : '') + '\n')); },
  nslookup(a, io) { return this.nslookup(a, io); },
  dig(a, io) { const name = a.filter(x => !x.startsWith('@') && !x.startsWith('-'))[0]; const at = a.find(x => x.startsWith('@')); return this.nslookup([name, at ? at.slice(1) : undefined], io); },
  host(a, io) { return this.nslookup(a, io); },
  netstat(a, io) { return this.netstat(a, io); }, ss(a, io) { return this.netstat(a, io); },
  curl(a, io) { return this.curl(a, io); }, wget(a, io) { return this.curl(a, io); },
  telnet(a, io) { return this.remote_(a, io, 'telnet'); }, ssh(a, io) { return this.remote_(a, io, 'ssh'); },
  hostname(a, io) { io.print(this.host.name.toLowerCase() + '\n'); },
  whoami(a, io) { io.print('etudiant\n'); },
  clear(a, io) { io.clear && io.clear(); },
  echo(a, io) { io.print(a.join(' ') + '\n'); },
  uname(a, io) { io.print('Linux ' + this.host.name.toLowerCase() + ' 6.1.0-13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.55-1 x86_64 GNU/Linux\n'); },
  cat(a, io) { if (a[0] === '/etc/resolv.conf') { io.print('# Generated by simulateur\n' + (this.host.domain ? 'search ' + this.host.domain + '\n' : '') + (this.host.dnsServers || []).map(d => 'nameserver ' + IP.str(d)).join('\n') + '\n'); } else io.print('cat: ' + (a[0] || '') + ': Aucun fichier ou dossier de ce type\n'); },
  dhclient(a, io) { const h = this.host; const i = h.mainIface; h.enableDhcp(i, true); const c = h.dhcpClients.get(i.name); c.unconfigure(); c.start(); this.waitDhcp(i, () => { io.done(); }); return 'async'; },
  systemctl(a, io) {
    const h = this.host; const act = a[0], svc = (a[1] || '').replace('.service', '');
    const map = { apache2: h.httpd, nginx: h.httpd, bind9: h.dnsd, named: h.dnsd, 'isc-dhcp-server': h.dhcpd, dhcpd: h.dhcpd };
    const s = map[svc]; if (!s) { io.print('Unit ' + svc + '.service could not be found.\n'); return; }
    if (act === 'start' || act === 'restart') { if (s.stop && s.enabled && act === 'restart') s.stop(); if (s.start) s.start(); else s.enabled = true; }
    else if (act === 'stop') { if (s.stop) s.stop(); else s.enabled = false; }
    else if (act === 'status') io.print('● ' + svc + '.service\n     Active: ' + (s.enabled ? 'active (running)' : 'inactive (dead)') + '\n');
  },
  help(a, io) { io.print('Commandes réseau : ip a|r|neigh, ifconfig, ping, traceroute, arp, nslookup, dig, curl, telnet, ssh, ss, dhclient, systemctl, hostname\n'); },
  ls(a, io) { io.print('Bureau  Documents  Téléchargements\n'); }, pwd(a, io) { io.print('/home/etudiant\n'); },
};
NS.HostShell = HostShell;
NS.Host.prototype.newSession = function () { return new HostShell(this); };
})(typeof window !== 'undefined' ? window : globalThis);
