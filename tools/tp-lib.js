/* Aides communes pour écrire les TP de cours (départ, correction) — utilisées par gen-tp-cours.js */
const { NS, Sim } = require('../tests/helpers');
const IP = NS.IP;
function mk(sim) {
  const dev = (model, name, x, y) => NS.createDevice(sim, model, { name, x, y });
  const get = n => Array.from(sim.devices.values()).find(d => d.name === n);
  const link = (a, pa, b, pb, type) => { const A = get(a), B = get(b); const l = sim.connect(A.findPort(pa), B.findPort(pb), type || 'auto'); if (!l) throw new Error('câble impossible ' + a + ':' + pa + ' – ' + b + ':' + pb); return l; };
  return { dev, get, link };
}
function cliRun(sim, dev, text) {
  const s = dev.newSession();
  text.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => { let d = false; s.exec(l, { print() { }, done() { d = true; }, clear() { } }); sim.runUntil(() => d, 60000); });
}
function hostIp(h, ip, mask, gw, dns) {
  h.applyIp(h.ifaceList()[0].name, { ip, mask: mask || '24' }); if (gw !== undefined) h.setGateway(gw); if (dns) { h.dnsServers = [].concat(dns).map(IP.parse); h.dhcpDns = false; }
}
function hostDhcp(h) { const i = h.ifaceList()[0]; h.enableDhcp(i, false); h.applyIp(i.name, { dhcp: true }); }
module.exports = { NS, Sim, IP, mk, cliRun, hostIp, hostDhcp };
