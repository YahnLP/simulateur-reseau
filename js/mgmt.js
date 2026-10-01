/* mgmt.js — supervision : agent SNMP (MIB-II, IF-MIB, BRIDGE-MIB…), traps, gestionnaire (get/walk/set), syslog (client + serveur) */
/* Copyright © 2026 Yahn LE PRETTRE – Formaxion Landes. Licensed under the EUPL-1.2. */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { IP, MAC, Codec, IPNode } = NS; const BER = Codec.BER;

/* ---------------------------------------------------------------- utilitaires OID */
const oa = s => Array.isArray(s) ? s : String(s).replace(/^\./, '').split('.').map(Number);
const os = a => a.join('.');
function cmpO(a, b) { const n = Math.min(a.length, b.length); for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; return a.length - b.length; }
const isPre = (root, o) => o.length >= root.length && root.every((x, i) => o[i] === x);
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const BASE_T = Date.UTC(2026, 8, 30, 8, 0, 0);
const p2 = n => String(n).padStart(2, '0');
function stamp(ms, withMs, star) { const d = new Date(BASE_T + ms); return (star ? '*' : '') + MON[d.getUTCMonth()] + ' ' + String(d.getUTCDate()).padStart(2, ' ') + ' ' + p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds()) + (withMs ? '.' + String(Math.floor(d.getUTCMilliseconds())).padStart(3, '0') : ''); }
const SEVN = ['emergencies', 'alerts', 'critical', 'errors', 'warnings', 'notifications', 'informational', 'debugging'];
const FACN = Codec.SYSLOG_FAC;

/* ---------------------------------------------------------------- noms MIB (affichage type net-snmp) */
const NAMES = [
  ['SNMPv2-MIB', 'system', '1.3.6.1.2.1.1'], ['SNMPv2-MIB', 'sysDescr', '1.3.6.1.2.1.1.1'], ['SNMPv2-MIB', 'sysObjectID', '1.3.6.1.2.1.1.2'], ['SNMPv2-MIB', 'sysUpTime', '1.3.6.1.2.1.1.3'], ['SNMPv2-MIB', 'sysContact', '1.3.6.1.2.1.1.4'], ['SNMPv2-MIB', 'sysName', '1.3.6.1.2.1.1.5'], ['SNMPv2-MIB', 'sysLocation', '1.3.6.1.2.1.1.6'], ['SNMPv2-MIB', 'sysServices', '1.3.6.1.2.1.1.7'],
  ['IF-MIB', 'interfaces', '1.3.6.1.2.1.2'], ['IF-MIB', 'ifNumber', '1.3.6.1.2.1.2.1'], ['IF-MIB', 'ifTable', '1.3.6.1.2.1.2.2'], ['IF-MIB', 'ifEntry', '1.3.6.1.2.1.2.2.1'],
  ['IF-MIB', 'ifIndex', '1.3.6.1.2.1.2.2.1.1'], ['IF-MIB', 'ifDescr', '1.3.6.1.2.1.2.2.1.2'], ['IF-MIB', 'ifType', '1.3.6.1.2.1.2.2.1.3'], ['IF-MIB', 'ifMtu', '1.3.6.1.2.1.2.2.1.4'], ['IF-MIB', 'ifSpeed', '1.3.6.1.2.1.2.2.1.5'], ['IF-MIB', 'ifPhysAddress', '1.3.6.1.2.1.2.2.1.6'], ['IF-MIB', 'ifAdminStatus', '1.3.6.1.2.1.2.2.1.7'], ['IF-MIB', 'ifOperStatus', '1.3.6.1.2.1.2.2.1.8'], ['IF-MIB', 'ifLastChange', '1.3.6.1.2.1.2.2.1.9'],
  ['IF-MIB', 'ifInOctets', '1.3.6.1.2.1.2.2.1.10'], ['IF-MIB', 'ifInUcastPkts', '1.3.6.1.2.1.2.2.1.11'], ['IF-MIB', 'ifInDiscards', '1.3.6.1.2.1.2.2.1.13'], ['IF-MIB', 'ifInErrors', '1.3.6.1.2.1.2.2.1.14'], ['IF-MIB', 'ifOutOctets', '1.3.6.1.2.1.2.2.1.16'], ['IF-MIB', 'ifOutUcastPkts', '1.3.6.1.2.1.2.2.1.17'], ['IF-MIB', 'ifOutDiscards', '1.3.6.1.2.1.2.2.1.19'], ['IF-MIB', 'ifOutErrors', '1.3.6.1.2.1.2.2.1.20'],
  ['IF-MIB', 'ifXTable', '1.3.6.1.2.1.31.1.1'], ['IF-MIB', 'ifName', '1.3.6.1.2.1.31.1.1.1.1'], ['IF-MIB', 'ifHCInOctets', '1.3.6.1.2.1.31.1.1.1.6'], ['IF-MIB', 'ifHCOutOctets', '1.3.6.1.2.1.31.1.1.1.10'], ['IF-MIB', 'ifHighSpeed', '1.3.6.1.2.1.31.1.1.1.15'], ['IF-MIB', 'ifAlias', '1.3.6.1.2.1.31.1.1.1.18'],
  ['IP-MIB', 'ip', '1.3.6.1.2.1.4'], ['IP-MIB', 'ipForwarding', '1.3.6.1.2.1.4.1'], ['IP-MIB', 'ipDefaultTTL', '1.3.6.1.2.1.4.2'],
  ['IP-MIB', 'ipAdEntAddr', '1.3.6.1.2.1.4.20.1.1'], ['IP-MIB', 'ipAdEntIfIndex', '1.3.6.1.2.1.4.20.1.2'], ['IP-MIB', 'ipAdEntNetMask', '1.3.6.1.2.1.4.20.1.3'],
  ['RFC1213-MIB', 'ipRouteDest', '1.3.6.1.2.1.4.21.1.1'], ['RFC1213-MIB', 'ipRouteIfIndex', '1.3.6.1.2.1.4.21.1.2'], ['RFC1213-MIB', 'ipRouteMetric1', '1.3.6.1.2.1.4.21.1.3'], ['RFC1213-MIB', 'ipRouteNextHop', '1.3.6.1.2.1.4.21.1.7'], ['RFC1213-MIB', 'ipRouteType', '1.3.6.1.2.1.4.21.1.8'], ['RFC1213-MIB', 'ipRouteProto', '1.3.6.1.2.1.4.21.1.9'], ['RFC1213-MIB', 'ipRouteMask', '1.3.6.1.2.1.4.21.1.11'],
  ['IP-MIB', 'ipNetToMediaIfIndex', '1.3.6.1.2.1.4.22.1.1'], ['IP-MIB', 'ipNetToMediaPhysAddress', '1.3.6.1.2.1.4.22.1.2'], ['IP-MIB', 'ipNetToMediaNetAddress', '1.3.6.1.2.1.4.22.1.3'], ['IP-MIB', 'ipNetToMediaType', '1.3.6.1.2.1.4.22.1.4'],
  ['SNMPv2-MIB', 'snmpInPkts', '1.3.6.1.2.1.11.1'], ['SNMPv2-MIB', 'snmpOutPkts', '1.3.6.1.2.1.11.2'], ['SNMPv2-MIB', 'snmpInBadCommunityNames', '1.3.6.1.2.1.11.4'], ['SNMPv2-MIB', 'snmpInGetRequests', '1.3.6.1.2.1.11.15'], ['SNMPv2-MIB', 'snmpInGetNexts', '1.3.6.1.2.1.11.16'], ['SNMPv2-MIB', 'snmpInSetRequests', '1.3.6.1.2.1.11.17'], ['SNMPv2-MIB', 'snmpOutTraps', '1.3.6.1.2.1.11.29'],
  ['BRIDGE-MIB', 'dot1dBaseBridgeAddress', '1.3.6.1.2.1.17.1.1'], ['BRIDGE-MIB', 'dot1dTpFdbAddress', '1.3.6.1.2.1.17.4.3.1.1'], ['BRIDGE-MIB', 'dot1dTpFdbPort', '1.3.6.1.2.1.17.4.3.1.2'], ['BRIDGE-MIB', 'dot1dTpFdbStatus', '1.3.6.1.2.1.17.4.3.1.3'],
  ['HOST-RESOURCES-MIB', 'hrSystemUptime', '1.3.6.1.2.1.25.1.1'], ['HOST-RESOURCES-MIB', 'hrMemorySize', '1.3.6.1.2.1.25.2.2'],
  ['UCD-SNMP-MIB', 'memTotalReal', '1.3.6.1.4.1.2021.4.5'], ['UCD-SNMP-MIB', 'memAvailReal', '1.3.6.1.4.1.2021.4.6'], ['UCD-SNMP-MIB', 'laLoad', '1.3.6.1.4.1.2021.10.1.3'], ['UCD-SNMP-MIB', 'ssCpuUser', '1.3.6.1.4.1.2021.11.9'], ['UCD-SNMP-MIB', 'ssCpuSystem', '1.3.6.1.4.1.2021.11.10'], ['UCD-SNMP-MIB', 'ssCpuIdle', '1.3.6.1.4.1.2021.11.11'],
  ['OLD-CISCO-CPU-MIB', 'avgBusy1', '1.3.6.1.4.1.9.2.1.57'], ['OLD-CISCO-CPU-MIB', 'avgBusy5', '1.3.6.1.4.1.9.2.1.58'], ['CISCO-PROCESS-MIB', 'cpmCPUTotal5minRev', '1.3.6.1.4.1.9.9.109.1.1.1.1.8'], ['CISCO-MEMORY-POOL-MIB', 'ciscoMemoryPoolUsed', '1.3.6.1.4.1.9.9.48.1.1.1.5'], ['CISCO-MEMORY-POOL-MIB', 'ciscoMemoryPoolFree', '1.3.6.1.4.1.9.9.48.1.1.1.6'],
  ['SNMPv2-MIB', 'snmpTrapOID', '1.3.6.1.6.3.1.1.4.1'], ['SNMPv2-MIB', 'snmpTraps', '1.3.6.1.6.3.1.1.5'], ['SNMPv2-MIB', 'coldStart', '1.3.6.1.6.3.1.1.5.1'], ['SNMPv2-MIB', 'linkDown', '1.3.6.1.6.3.1.1.5.3'], ['SNMPv2-MIB', 'linkUp', '1.3.6.1.6.3.1.1.5.4'], ['SNMPv2-MIB', 'authenticationFailure', '1.3.6.1.6.3.1.1.5.5'],
].map(x => ({ mod: x[0], name: x[1], oid: oa(x[2]) })).sort((a, b) => b.oid.length - a.oid.length);
const BYNAME = new Map(); NAMES.forEach(n => { BYNAME.set(n.name.toLowerCase(), n); BYNAME.set((n.mod + '::' + n.name).toLowerCase(), n); });
function nameOf(oid) {
  const o = oa(oid); for (const n of NAMES) if (isPre(n.oid, o)) { const rest = o.slice(n.oid.length); return n.mod + '::' + n.name + (rest.length ? '.' + rest.join('.') : ''); }
  if (isPre([1, 3, 6, 1, 4, 1], o) && o.length > 6) return 'SNMPv2-SMI::enterprises.' + o.slice(6).join('.');
  if (isPre([1, 3, 6, 1, 2, 1], o)) return 'SNMPv2-SMI::mib-2.' + o.slice(6).join('.');
  return 'iso.' + o.slice(1).join('.');
}
/* saisie utilisateur : nom, MIB::nom.inst, numérique, iso.… */
function parseOid(s) {
  s = String(s).trim(); if (/^\.?\d+(\.\d+)*$/.test(s)) return oa(s); if (/^iso\./i.test(s)) return oa('1.' + s.slice(4));
  const m = /^([A-Za-z0-9\-]+::)?([A-Za-z][A-Za-z0-9\-]*)((?:\.\d+)*)$/.exec(s); if (!m) return null;
  const n = BYNAME.get(((m[1] || '') + m[2]).toLowerCase()) || BYNAME.get(m[2].toLowerCase()); if (!n) return null;
  return n.oid.concat(m[3] ? m[3].slice(1).split('.').map(Number) : []);
}
const ENUM = {
  ifType: { 6: 'ethernetCsmacd', 24: 'softwareLoopback', 53: 'propVirtual', 135: 'l2vlan', 161: 'ieee8023adLag', 71: 'ieee80211' },
  ifAdminStatus: { 1: 'up', 2: 'down', 3: 'testing' }, ifOperStatus: { 1: 'up', 2: 'down', 3: 'testing', 5: 'dormant', 7: 'lowerLayerDown' },
  ipForwarding: { 1: 'forwarding', 2: 'notForwarding' }, ipRouteType: { 1: 'other', 3: 'direct', 4: 'indirect' }, ipNetToMediaType: { 1: 'other', 2: 'invalid', 3: 'dynamic', 4: 'static' }, dot1dTpFdbStatus: { 1: 'other', 3: 'learned', 5: 'mgmt' },
  ipRouteProto: { 1: 'other', 2: 'local', 3: 'netmgmt', 8: 'rip', 13: 'ospf' },
};
function tt2s(t) { const cs = t % 100, s = Math.floor(t / 100), d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60; return '(' + t + ') ' + (d ? d + ' day' + (d > 1 ? 's' : '') + ', ' : '') + h + ':' + p2(m) + ':' + p2(sec) + '.' + p2(cs); }
/* rendu d'un varbind comme net-snmp : "IF-MIB::ifDescr.1 = STRING: Gi0/1" */
function fmtVb(vb, o) {
  o = o || {}; const nm = o.numeric ? '.' + vb.oid : (vb.oid === '1.3.6.1.2.1.1.3.0' ? 'DISMAN-EVENT-MIB::sysUpTimeInstance' : nameOf(vb.oid));
  const base = NAMES.find(n => isPre(n.oid, oa(vb.oid))); const bn = base ? base.name : '';
  let ty, val;
  switch (vb.t) {
    case 'oct': { const u = vb.v; let pr = true; for (const b of u) if ((b < 32 || b > 126) && b !== 10 && b !== 13 && b !== 9) pr = false;
      if (bn === 'ifPhysAddress' || bn === 'ipNetToMediaPhysAddress' || bn === 'dot1dTpFdbAddress' || bn === 'dot1dBaseBridgeAddress') { ty = 'STRING'; val = Array.from(u).map(b => b.toString(16)).join(':'); }
      else if (pr) { ty = 'STRING'; val = '"' + String.fromCharCode.apply(null, Array.from(u)) + '"'; } else { ty = 'Hex-STRING'; val = Array.from(u).map(b => p2(b.toString(16).toUpperCase())).join(' ') + ' '; } break; }
    case 'int': ty = 'INTEGER'; val = ENUM[bn] && ENUM[bn][vb.v] ? ENUM[bn][vb.v] + '(' + vb.v + ')' : String(vb.v); break;
    case 'c32': ty = 'Counter32'; val = vb.v; break; case 'g32': ty = 'Gauge32'; val = vb.v; break; case 'c64': ty = 'Counter64'; val = vb.v; break;
    case 'tt': ty = 'Timeticks'; val = tt2s(vb.v); break; case 'ip': ty = 'IpAddress'; val = IP.str(vb.v); break;
    case 'oid': ty = 'OID'; val = o.numeric ? '.' + vb.v : nameOf(vb.v); break;
    case 'nso': return nm + ' = No Such Object available on this agent at this OID';
    case 'nsi': return nm + ' = No Such Instance currently exists at this OID';
    case 'eom': return nm + ' = No more variables left in this MIB View (It is past the end of the MIB tree)';
    default: ty = 'NULL'; val = '';
  }
  if (o.q) return nm + ' ' + String(val).replace(/^"|"$/g, ''); if (o.v) return String(val).replace(/^"|"$/g, '');
  return nm + ' = ' + ty + ': ' + val;
}

/* ================================================================== Mgmt (SNMP + syslog d'un équipement) */
class Mgmt {
  constructor(node) {
    this.node = node; this.sim = node.sim;
    this.snmp = { comms: new Map(), location: '', contact: '', hosts: [], traps: false, authTrap: false, on: false, bound: false };
    this.cnt = { inPkts: 0, outPkts: 0, badComm: 0, badVer: 0, gets: 0, nexts: 0, sets: 0, vars: 0, altered: 0, traps: 0, outResp: 0, tooBig: 0, noSuch: 0, genErr: 0 };
    this.lg = { hosts: [], trap: 6, bufLevel: 7, bufSize: 4096, facility: 23, seq: false, on: true, src: null, console: 7, counter: 0, buf: [], sent: new Map(), count: 0 };
    this.lastUp = new Map(); this.lastChange = new Map(); this.cpu = { t: 0, pk: 0, v: 3, a5: 3 };
    this.syslogd = { enabled: false, entries: [], max: 500 }; this.trapd = { enabled: false, entries: [], max: 200, bound: false };
    this._c = null;
    const orig = node.portStateChanged.bind(node);
    node.portStateChanged = p => { orig(p); this.portEvent(p); };
  }
  get isNet() { const t = this.node.type; return t !== 'pc' && t !== 'server' && t !== 'peripheral'; }
  get isLinux() { return this.node.os === 'linux'; }
  reset() { const s = this.snmp; s.comms.clear(); s.location = ''; s.contact = ''; s.hosts = []; s.traps = false; s.authTrap = false; this.sync(); Object.assign(this.lg, { hosts: [], trap: 6, bufLevel: 7, bufSize: 4096, facility: 23, seq: false, on: true, src: null, console: 7 }); }
  /* ---------- configuration SNMP ---------- */
  setCommunity(name, mode) { this.snmp.comms.set(name, mode === 'rw' ? 'rw' : 'ro'); this.sync(); }
  delCommunity(name) { this.snmp.comms.delete(name); this.sync(); }
  sync() {
    const n = this.node, s = this.snmp; const want = s.comms.size > 0;
    if (want && !s.bound) { n.udpBind(161, (p, i) => this.input(p, i)); s.bound = true; }
    if (!want && s.bound) { n.udpUnbind(161); s.bound = false; }
  }
  addHost(ip, ver, community, inform) { const s = this.snmp; s.hosts = s.hosts.filter(h => !(h.ip === ip)); s.hosts.push({ ip, ver: ver === 1 ? 1 : 0, community, inform: !!inform, sent: 0 }); }
  delHost(ip) { this.snmp.hosts = this.snmp.hosts.filter(h => h.ip !== ip); }
  /* ---------- MIB ---------- */
  ifList() {
    if (this._c && this._c.t === this.sim.now && this._ifl) return this._ifl;
    const n = this.node, L = []; const sw = n instanceof NS.Switch, host = n instanceof NS.Host;
    if (host) L.push({ idx: 1, name: 'lo', short: 'lo', type: 24, port: null, ifc: null, speed: 10, mtu: 65536 });
    n.ports.forEach(p => { const ifc = n.ifaces ? n.ifaces.get(p.name) || null : null; L.push({ idx: sw ? 10001 + p.idx : p.idx + (host ? 2 : 1), name: p.name, short: p.short, type: p.kind === 'wifi' ? 71 : 6, port: p, ifc: sw ? null : ifc, speed: p.speed, mtu: 1500 }); });
    let k = 0; n.ifaces && n.ifaces.forEach(i => {
      if (i.port && !i.sub) return; k++;
      if (i.svi !== null) L.push({ idx: i.svi, name: 'Vlan' + i.svi, short: 'Vl' + i.svi, type: 53, port: null, ifc: i, speed: 1000, mtu: 1500 });
      else if (i.loop) L.push({ idx: 1000 + k, name: i.name, short: i.name.replace(/^Loopback/, 'Lo'), type: 24, port: null, ifc: i, speed: 8000, mtu: 1514 });
      else if (i.sub) L.push({ idx: 2000 + k, name: i.name, short: i.name, type: 135, port: i.port, ifc: i, speed: i.port ? i.port.speed : 1000, mtu: 1500 });
    });
    if (n.chans) n.chans.forEach(c => L.push({ idx: 5000 + c.id, name: 'Port-channel' + c.id, short: 'Po' + c.id, type: 161, port: c.lp, chan: c, ifc: null, speed: c.lp.speedSum(), mtu: 1500 }));
    L.sort((a, b) => a.idx - b.idx); this._ifl = L; this._c = { t: this.sim.now }; return L;
  }
  ifCounters(e) {
    if (e.chan) { let a = { rxB: 0, txB: 0, rxPk: 0, txPk: 0 }; e.chan.members.forEach(m => { a.rxB += m.rxB || 0; a.txB += m.txB || 0; a.rxPk += m.rxPk || 0; a.txPk += m.txPk || 0; }); return a; }
    const p = e.port; return { rxB: p ? p.rxB || 0 : 0, txB: p ? p.txB || 0 : 0, rxPk: p ? p.rxPk || 0 : 0, txPk: p ? p.txPk || 0 : 0 };
  }
  ifAdmin(e) { if (!e.port && !e.ifc) return true; if (e.chan) return e.port.adminUp; if (e.ifc && !e.port) return e.ifc.adminUp; return !!(e.port.adminUp && (!e.ifc || e.ifc.adminUp)); }
  ifOper(e) { if (!e.port && !e.ifc) return true; if (e.chan) return e.port.up; if (e.ifc && !e.port) return e.ifc.isUp(); if (e.ifc) return e.ifc.sub ? e.ifc.isUp() : !!(e.ifc.isUp()); return !!e.port.up; }
  setAdmin(e, up) {
    const n = this.node, ifc = e.ifc, pt = e.port;
    if (e.chan) { pt.adminUp = up; e.chan.members.forEach(m => { m.adminUp = up; this.sim.portChanged(m); if (m.peer) this.sim.portChanged(m.peer); }); return; }
    if (ifc) ifc.adminUp = up;
    if (pt && !(ifc && ifc.sub)) { pt.adminUp = up; if (up) pt.errdis = false; this.sim.portChanged(pt); if (pt.peer) this.sim.portChanged(pt.peer); }
    if (ifc) n.ifaceStateChanged(ifc);
  }
  load() {
    const n = this.node, t = this.sim.now; let pk = 0; n.ports.forEach(p => pk += (p.rxPk || 0) + (p.txPk || 0));
    if (t > this.cpu.t) { const dt = (t - this.cpu.t) / 1000; const rate = (pk - this.cpu.pk) / dt; if (this.cpu.t > 0 || pk) { this.cpu.v = Math.max(1, Math.min(99, Math.round(2 + rate / 25 + (n.forwarding ? 1 : 0)))); this.cpu.a5 = Math.round(this.cpu.a5 * 0.8 + this.cpu.v * 0.2); } this.cpu.t = t; this.cpu.pk = pk; }
    return this.cpu;
  }
  sysDescr() {
    const n = this.node, m = NS.CATALOG[n.model] || {}; const v = (m.vendor || '');
    if (n.os === 'linux') return 'Linux ' + n.name.toLowerCase() + ' 6.1.0-13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.55-1 (2023-09-29) x86_64';
    if (n.os === 'windows') return 'Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 20348 Multiprocessor Free)';
    if (v === 'Cisco') return 'Cisco IOS Software, ' + (m.label || n.model) + ' Software, Version 15.2(4)E10, RELEASE SOFTWARE (fc2)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2020 by Cisco Systems, Inc.';
    return (m.vendor ? m.vendor + ' ' : '') + (m.label || n.model);
  }
  objectId() {
    const n = this.node, m = NS.CATALOG[n.model] || {}, v = m.vendor || '';
    if (n.os === 'linux') return '1.3.6.1.4.1.8072.3.2.10'; if (n.os === 'windows') return '1.3.6.1.4.1.311.1.1.3.1.3';
    const E = { Cisco: '1.3.6.1.4.1.9.1.1208', Fortinet: '1.3.6.1.4.1.12356.101.1.1', Stormshield: '1.3.6.1.4.1.11256.1.1', Netgate: '1.3.6.1.4.1.8072.3.2.8', Ubiquiti: '1.3.6.1.4.1.41112.1.6', 'Alcatel-Lucent': '1.3.6.1.4.1.6486.800.1.1.2.1.6.1.1' };
    return E[v] || '1.3.6.1.4.1.8072.3.2.255';
  }
  /* construit toutes les lignes de la MIB, triées */
  mib() {
    const n = this.node, sn = this.snmp, R = []; const t = this.sim.now;
    const add = (o, ty, v, set) => R.push({ o: oa(o), t: ty, v, set });
    const sysW = k => v => { if (v.t !== 'oct') return 'wrongType'; sn[k] = String.fromCharCode.apply(null, Array.from(v.v)); return null; };
    add('1.3.6.1.2.1.1.1.0', 'oct', this.sysDescr()); add('1.3.6.1.2.1.1.2.0', 'oid', this.objectId()); add('1.3.6.1.2.1.1.3.0', 'tt', Math.floor(t / 10));
    add('1.3.6.1.2.1.1.4.0', 'oct', sn.contact, sysW('contact')); add('1.3.6.1.2.1.1.5.0', 'oct', n.name, v => { if (v.t !== 'oct') return 'wrongType'; n.name = String.fromCharCode.apply(null, Array.from(v.v)); return null; });
    add('1.3.6.1.2.1.1.6.0', 'oct', sn.location, sysW('location')); add('1.3.6.1.2.1.1.7.0', 'int', n.forwarding ? (n instanceof NS.Switch && !n.forwarding ? 2 : 78) : 72);
    const L = this.ifList(); add('1.3.6.1.2.1.2.1.0', 'int', L.length);
    L.forEach(e => {
      const i = e.idx, c = this.ifCounters(e), adm = this.ifAdmin(e), op = this.ifOper(e), lc = this.lastChange.get(e.port || e.ifc || e) || 0;
      const b = '1.3.6.1.2.1.2.2.1.'; const macb = e.port ? e.port.mac : n.baseMac;
      add(b + '1.' + i, 'int', i); add(b + '2.' + i, 'oct', e.name); add(b + '3.' + i, 'int', e.type); add(b + '4.' + i, 'int', e.mtu); add(b + '5.' + i, 'g32', Math.min(4294967295, e.speed * 1e6));
      add(b + '6.' + i, 'oct', e.type === 24 ? new Uint8Array(0) : Uint8Array.from(macb.split(':').map(x => parseInt(x, 16))));
      add(b + '7.' + i, 'int', adm ? 1 : 2, v => { if (v.t !== 'int') return 'wrongType'; if (v.v !== 1 && v.v !== 2) return 'wrongValue'; return () => this.setAdmin(e, v.v === 1); });
      add(b + '8.' + i, 'int', op ? 1 : 2); add(b + '9.' + i, 'tt', Math.floor(lc / 10));
      add(b + '10.' + i, 'c32', c.rxB >>> 0); add(b + '11.' + i, 'c32', c.rxPk >>> 0); add(b + '13.' + i, 'c32', 0); add(b + '14.' + i, 'c32', 0);
      add(b + '16.' + i, 'c32', c.txB >>> 0); add(b + '17.' + i, 'c32', c.txPk >>> 0); add(b + '19.' + i, 'c32', 0); add(b + '20.' + i, 'c32', 0);
      const x = '1.3.6.1.2.1.31.1.1.1.'; add(x + '1.' + i, 'oct', e.short); add(x + '6.' + i, 'c64', c.rxB); add(x + '10.' + i, 'c64', c.txB); add(x + '15.' + i, 'g32', e.speed);
      add(x + '18.' + i, 'oct', (e.port && e.port.desc) || (e.ifc && e.ifc.desc) || '', v => { if (v.t !== 'oct') return 'wrongType'; const s = String.fromCharCode.apply(null, Array.from(v.v)); return () => { if (e.ifc) e.ifc.desc = s; if (e.port) e.port.desc = s; }; });
    });
    if (n.ifaces) {
      add('1.3.6.1.2.1.4.1.0', 'int', n.forwarding ? 1 : 2); add('1.3.6.1.2.1.4.2.0', 'int', n.ttl);
      const byIf = new Map(); n.ifaces.forEach(f => { const e = L.find(x => x.ifc === f) || L.find(x => x.port && f.port === x.port && !x.ifc); byIf.set(f, e ? e.idx : 0); });
      n.ifaces.forEach(f => { if (!f.ip || !f.isUp()) return; const a = IP.str(f.ip); add('1.3.6.1.2.1.4.20.1.1.' + a, 'ip', f.ip); add('1.3.6.1.2.1.4.20.1.2.' + a, 'int', byIf.get(f)); add('1.3.6.1.2.1.4.20.1.3.' + a, 'ip', f.mask); });
      const PR = { C: 2, S: 3, R: 8, O: 13, 'O IA': 13, 'O E2': 13 };
      n.allRoutes().forEach(r => { const d = IP.str(r.net); const dir = r.proto === 'C' || !r.nh; add('1.3.6.1.2.1.4.21.1.1.' + d, 'ip', r.net); add('1.3.6.1.2.1.4.21.1.2.' + d, 'int', byIf.get(r.iface) || 0); add('1.3.6.1.2.1.4.21.1.3.' + d, 'int', r.metric || 0); add('1.3.6.1.2.1.4.21.1.7.' + d, 'ip', r.nh || 0); add('1.3.6.1.2.1.4.21.1.8.' + d, 'int', dir ? 3 : 4); add('1.3.6.1.2.1.4.21.1.9.' + d, 'int', PR[r.proto] || 1); add('1.3.6.1.2.1.4.21.1.11.' + d, 'ip', r.mask); });
      n.arpTable.forEach((e, ip) => { if (!e.iface) return; const ix = byIf.get(e.iface) || 0; const k = ix + '.' + IP.str(ip); add('1.3.6.1.2.1.4.22.1.1.' + k, 'int', ix); add('1.3.6.1.2.1.4.22.1.2.' + k, 'oct', Uint8Array.from(e.mac.split(':').map(x => parseInt(x, 16)))); add('1.3.6.1.2.1.4.22.1.3.' + k, 'ip', ip); add('1.3.6.1.2.1.4.22.1.4.' + k, 'int', e.static ? 4 : 3); });
    }
    const c = this.cnt; add('1.3.6.1.2.1.11.1.0', 'c32', c.inPkts); add('1.3.6.1.2.1.11.2.0', 'c32', c.outPkts); add('1.3.6.1.2.1.11.4.0', 'c32', c.badComm); add('1.3.6.1.2.1.11.15.0', 'c32', c.gets); add('1.3.6.1.2.1.11.16.0', 'c32', c.nexts); add('1.3.6.1.2.1.11.17.0', 'c32', c.sets); add('1.3.6.1.2.1.11.29.0', 'c32', c.traps);
    if (n instanceof NS.Switch && n.macTable) {
      add('1.3.6.1.2.1.17.1.1.0', 'oct', Uint8Array.from(n.baseMac.split(':').map(x => parseInt(x, 16))));
      const seenM = new Set(); n.macTable.forEach((e, key) => { const m = String(key).split('|').pop().split(':'); if (seenM.has(m.join(':'))) return; seenM.add(m.join(':')); if (m.length !== 6 || !e.port) return; const k = m.map(x => parseInt(x, 16)).join('.'); const pn = e.port.isChannel ? 5000 + e.port.id : e.port.idx + 1; add('1.3.6.1.2.1.17.4.3.1.1.' + k, 'oct', Uint8Array.from(m.map(x => parseInt(x, 16)))); add('1.3.6.1.2.1.17.4.3.1.2.' + k, 'int', pn); add('1.3.6.1.2.1.17.4.3.1.3.' + k, 'int', 3); });
    }
    const ld = this.load();
    if (n instanceof NS.Host) {
      add('1.3.6.1.2.1.25.1.1.0', 'tt', Math.floor(t / 10)); add('1.3.6.1.2.1.25.2.2.0', 'int', 2097152);
      add('1.3.6.1.4.1.2021.4.5.0', 'int', 2097152); add('1.3.6.1.4.1.2021.4.6.0', 'int', 1310720 - ld.v * 100);
      [1, 2, 3].forEach(k => add('1.3.6.1.4.1.2021.10.1.3.' + k, 'oct', (ld.v / 100 * (1 + (3 - k) * 0.1)).toFixed(2)));
      add('1.3.6.1.4.1.2021.11.9.0', 'int', Math.round(ld.v * 0.7)); add('1.3.6.1.4.1.2021.11.10.0', 'int', Math.round(ld.v * 0.3)); add('1.3.6.1.4.1.2021.11.11.0', 'int', 100 - ld.v);
    } else if ((NS.CATALOG[n.model] || {}).vendor === 'Cisco') {
      add('1.3.6.1.4.1.9.2.1.57.0', 'int', ld.v); add('1.3.6.1.4.1.9.2.1.58.0', 'int', ld.a5); add('1.3.6.1.4.1.9.9.109.1.1.1.1.8.1', 'g32', ld.a5);
      add('1.3.6.1.4.1.9.9.48.1.1.1.5.1', 'g32', 21000000 + ld.v * 1000); add('1.3.6.1.4.1.9.9.48.1.1.1.6.1', 'g32', 87000000 - ld.v * 1000);
    }
    R.sort((a, b) => cmpO(a.o, b.o)); return R;
  }
  /* ---------- traitement des requêtes ---------- */
  input(p, iface) {
    const m = p.snmp; if (!m) return; const c = this.cnt, s = this.snmp; const P = m.pdu; c.inPkts++;
    if (m.ver > 1) { c.badVer++; return; }
    if (P.type === 'get-response' || P.type === 'trap' || P.type === 'snmpV2-trap' || P.type === 'report') return;
    if (!s.comms.has(m.community)) { c.badComm++; if (s.authTrap) this.trap('auth'); return; }
    const rw = s.comms.get(m.community) === 'rw'; const rows = this.mib(); const v1 = m.ver === 0;
    const find = o => { let lo = 0, hi = rows.length - 1; while (lo <= hi) { const mid = (lo + hi) >> 1, d = cmpO(rows[mid].o, o); if (!d) return mid; if (d < 0) lo = mid + 1; else hi = mid - 1; } return -1; };
    const next = o => { let lo = 0, hi = rows.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (cmpO(rows[mid].o, o) <= 0) lo = mid + 1; else hi = mid; } return lo < rows.length ? rows[lo] : null; };
    const vb = r => ({ oid: os(r.o), t: r.t, v: r.v });
    let out = [], es = 0, ei = 0; const req = P.varbinds.map(x => oa(x.oid)); c.vars += req.length;
    if (P.type === 'get-request') {
      c.gets++;
      req.forEach((o, i) => { const k = find(o); if (k >= 0) out.push(vb(rows[k])); else if (v1) { if (!es) { es = 2; ei = i + 1; } out.push({ oid: os(o), t: 'null' }); } else { const obj = rows.some(r => r.o.length === o.length && r.o.slice(0, -1).every((x, j) => x === o[j])); out.push({ oid: os(o), t: obj ? 'nsi' : 'nso' }); } });
    } else if (P.type === 'get-next-request') {
      c.nexts++;
      req.forEach((o, i) => { const r = next(o); if (r) out.push(vb(r)); else if (v1) { if (!es) { es = 2; ei = i + 1; } out.push({ oid: os(o), t: 'null' }); } else out.push({ oid: os(o), t: 'eom' }); });
    } else if (P.type === 'getBulkRequest' && !v1) {
      c.gets++; const nr = Math.max(0, Math.min(P.errStatus, req.length)), mr = Math.max(0, Math.min(P.errIdx, 60)); let est = 0;
      for (let i = 0; i < nr; i++) { const r = next(req[i]); out.push(r ? vb(r) : { oid: os(req[i]), t: 'eom' }); }
      let cur = req.slice(nr); let stop = false;
      for (let k = 0; k < mr && !stop && cur.length; k++) {
        let allEnd = true; const nx = [];
        for (let j = 0; j < cur.length; j++) { const r = next(cur[j]); if (r) { allEnd = false; out.push(vb(r)); nx.push(r.o); est += 14 + os(r.o).length + (typeof r.v === 'string' ? r.v.length : 6); } else { out.push({ oid: os(cur[j]), t: 'eom' }); nx.push(cur[j]); } }
        cur = nx; if (allEnd || est > 1100) stop = true;
      }
    } else if (P.type === 'set-request') {
      c.sets++; const acts = [];
      if (!rw) { es = v1 ? 2 : 6; ei = 1; out = P.varbinds.slice(); }
      else {
        for (let i = 0; i < P.varbinds.length; i++) {
          const k = find(req[i]); const row = k >= 0 ? rows[k] : null;
          if (!row) { es = v1 ? 2 : 6; ei = i + 1; break; } if (!row.set) { es = v1 ? 2 : 17; ei = i + 1; break; }
          const r = row.set(P.varbinds[i]); if (typeof r === 'string') { es = v1 ? 3 : (r === 'wrongType' ? 7 : 10); ei = i + 1; break; }
          if (typeof r === 'function') acts.push(r);
        }
        if (!es) { acts.forEach(f => f()); c.altered += P.varbinds.length; this._c = null; this._ifl = null; }
        out = P.varbinds.slice();
      }
    } else return;
    if (es) { c.noSuch++; }
    c.outPkts++; c.outResp++;
    const bytes = Codec.snmp({ ver: m.ver, community: m.community, pdu: { type: 'response', reqId: P.reqId, errStatus: es, errIdx: ei, varbinds: out } });
    this.node.udpSend(p.ip.src, p.udp.sport, 161, bytes, { src: p.ip.dst });
  }
  /* ---------- traps ---------- */
  trap(kind, e) {
    const s = this.snmp; if (!s.hosts.length) return; const n = this.node;
    const oid = { link_down: '1.3.6.1.6.3.1.1.5.3', link_up: '1.3.6.1.6.3.1.1.5.4', cold: '1.3.6.1.6.3.1.1.5.1', auth: '1.3.6.1.6.3.1.1.5.5' }[kind === 'auth' ? 'auth' : kind]; if (!oid) return;
    const tt = Math.floor(this.sim.now / 10);
    s.hosts.forEach(h => {
      const sport = n.nextPort(); const vbs = [];
      if (e) { vbs.push({ oid: '1.3.6.1.2.1.2.2.1.1.' + e.idx, t: 'int', v: e.idx }, { oid: '1.3.6.1.2.1.2.2.1.7.' + e.idx, t: 'int', v: this.ifAdmin(e) ? 1 : 2 }, { oid: '1.3.6.1.2.1.2.2.1.8.' + e.idx, t: 'int', v: this.ifOper(e) ? 1 : 2 }); if (this.isNet) vbs.push({ oid: '1.3.6.1.2.1.2.2.1.2.' + e.idx, t: 'oct', v: e.name }); }
      let pdu;
      if (h.ver === 0) { const src = (n.lookup(h.ip) || {}).iface; pdu = { type: 'trap1', enterprise: this.objectId(), agent: src ? src.ip : 0, generic: { link_down: 2, link_up: 3, cold: 0, auth: 4 }[kind], specific: 0, time: tt, varbinds: vbs }; }
      else pdu = { type: h.inform ? 'inform' : 'trap2', reqId: 1 + this.sim.rng.int(2e9), varbinds: [{ oid: '1.3.6.1.2.1.1.3.0', t: 'tt', v: tt }, { oid: '1.3.6.1.6.3.1.1.4.1.0', t: 'oid', v: oid }].concat(vbs) };
      const bytes = Codec.snmp({ ver: h.ver, community: h.community, pdu });
      h.sent++; this.cnt.traps++; this.cnt.outPkts++; n.udpSend(h.ip, 162, sport, bytes, {});
    });
  }
  /* ---------- événements de lien ---------- */
  portEvent(p) {
    const up = !!p.up; const prev = this.lastUp.get(p) || false; if (up === prev) return; this.lastUp.set(p, up); this.lastChange.set(p, this.sim.now);
    if (!this.isNet) return; const n = this.node;
    if (n.stp && n.stp.enabled === false && false) return;
    const nm = p.name; const adm = p.adminUp && !p.errdis;
    this.slog('LINK', 3, 'UPDOWN', 'Interface ' + nm + ', changed state to ' + (up ? 'up' : adm ? 'down' : 'administratively down'));
    this.slog('LINEPROTO', 5, 'UPDOWN', 'Line protocol on Interface ' + nm + ', changed state to ' + (up ? 'up' : 'down'));
    if (this.snmp.traps) { const e = this.ifList().find(x => x.port === p && !x.ifc || (x.port === p && !x.ifc && true)) || this.ifList().find(x => x.port === p); if (e) this.trap(up ? 'link_up' : 'link_down', e); }
  }
  /* ---------- syslog émetteur ---------- */
  fromLog(m) { const r = /^%([A-Z0-9_]+)-(\d)-([A-Z0-9_]+): ([\s\S]*)$/.exec(m); if (r && this.isNet) this.slog(r[1], +r[2], r[3], r[4]); }
  slog(fac, sev, mnem, text) {
    const L = this.lg; if (!L.on && !L.hosts.length) return; const n = this.node; L.count++;
    const msg = '%' + fac + '-' + sev + '-' + mnem + ': ' + text; const ts = stamp(this.sim.now, true, true);
    if (sev <= L.bufLevel) { L.buf.push((L.seq ? String(L.count).padStart(6, '0') + ': ' : '') + ts + ': ' + msg); let sz = 0; for (let i = L.buf.length - 1; i >= 0; i--) { sz += L.buf[i].length + 1; if (sz > L.bufSize) { L.buf.splice(0, i + 1); break; } } }
    if (sev > L.trap) return;
    L.hosts.forEach(h => {
      const seq = ++L.counter; const body = (L.seq ? String(seq).padStart(6, '0') : seq) + ': ' + ts + ': ' + msg; const pri = L.facility * 8 + sev;
      L.sent.set(h, (L.sent.get(h) || 0) + 1);
      const src = L.src ? n.ifaceByName(L.src) : null; const o = src && src.ip ? { src: src.ip } : {};
      n.udpSend(h, 514, 514, Codec.syslog(pri, body), o);
    });
  }
  /* ---------- client Linux : logger ---------- */
  logger(host, text, o) {
    o = o || {}; const n = this.node; const fac = o.fac === undefined ? 1 : o.fac, sev = o.sev === undefined ? 5 : o.sev; const tag = o.tag || 'etudiant';
    const body = stamp(this.sim.now, false, false) + ' ' + n.name.toLowerCase() + ' ' + tag + ': ' + text;
    if (host) return n.udpSend(host, o.port || 514, n.nextPort(), Codec.syslog(fac * 8 + sev, body), {});
    this.syslogd.entries.push({ t: this.sim.now, src: n.name.toLowerCase(), pri: fac * 8 + sev, msg: body, local: true }); return { ok: true };
  }
  /* ---------- serveur syslog (rsyslog) ---------- */
  startSyslogd() { const n = this.node, d = this.syslogd; if (d.enabled) return; d.enabled = true; n.udpBind(514, p => { const s = p.syslog; if (!s) return; d.entries.push({ t: this.sim.now, src: IP.str(p.ip.src), pri: s.pri, msg: s.msg }); if (d.entries.length > d.max) d.entries.shift(); }); }
  stopSyslogd() { const d = this.syslogd; if (!d.enabled) return; d.enabled = false; this.node.udpUnbind(514); }
  fileSyslog() { return this.syslogd.entries.map(e => e.local ? e.msg : stamp(e.t, false, false) + ' ' + e.src + ' ' + e.msg).join('\n') + (this.syslogd.entries.length ? '\n' : ''); }
  /* ---------- récepteur de traps (snmptrapd) ---------- */
  startTrapd() {
    const n = this.node, d = this.trapd; if (d.enabled) return; d.enabled = true; d.bound = true;
    n.udpBind(162, p => {
      const s = p.snmp; if (!s) return; const P = s.pdu; if (P.type !== 'snmpV2-trap' && P.type !== 'trap' && P.type !== 'informRequest') return;
      const e = { t: this.sim.now, src: IP.str(p.ip.src), ver: s.ver, community: s.community, type: P.type, varbinds: P.varbinds, generic: P.generic, enterprise: P.enterprise };
      let oid = ''; if (P.type === 'trap') oid = { 0: '1.3.6.1.6.3.1.1.5.1', 2: '1.3.6.1.6.3.1.1.5.3', 3: '1.3.6.1.6.3.1.1.5.4', 4: '1.3.6.1.6.3.1.1.5.5' }[P.generic] || ''; else { const v = P.varbinds.find(x => x.oid === '1.3.6.1.6.3.1.1.4.1.0'); oid = v ? v.v : ''; }
      e.trapOid = oid; d.entries.push(e); if (d.entries.length > d.max) d.entries.shift();
      if (P.type === 'informRequest') { const b = Codec.snmp({ ver: s.ver, community: s.community, pdu: { type: 'response', reqId: P.reqId, errStatus: 0, errIdx: 0, varbinds: P.varbinds } }); n.udpSend(p.ip.src, p.udp.sport, 162, b, { src: p.ip.dst }); }
    });
  }
  stopTrapd() { const d = this.trapd; if (!d.enabled) return; d.enabled = false; this.node.udpUnbind(162); }
  trapLine(e) { const nm = e.trapOid ? nameOf(e.trapOid) : '?'; return stamp(e.t, false, false) + ' ' + e.src + ' [' + e.type + ' ' + (e.ver === 0 ? 'v1' : 'v2c') + ' ' + e.community + '] ' + nm + (e.varbinds.length ? ' : ' + e.varbinds.filter(v => v.oid !== '1.3.6.1.2.1.1.3.0' && v.oid !== '1.3.6.1.6.3.1.1.4.1.0').map(v => fmtVb(v).replace(/^.*?::/, '')).join(', ') : ''); }
  /* ---------- gestionnaire SNMP (client) ---------- */
  query(dst, o, cb) {
    const n = this.node, sim = this.sim; const sport = n.nextPort(); const id = 1 + sim.rng.int(2147483000);
    const bytes = Codec.snmp({ ver: o.ver === 0 ? 0 : 1, community: o.community || 'public', pdu: { type: o.op, reqId: id, errStatus: o.nonRep || 0, errIdx: o.maxRep || 0, varbinds: o.vbs } });
    let tries = 0, done = false, tm = null; const retries = o.retries === undefined ? 1 : o.retries, to = o.timeout || 1000;
    const fin = (err, res) => { if (done) return; done = true; sim.cancel(tm); n.udpUnbind(sport); cb(err, res); };
    n.udpBind(sport, p => { const s = p.snmp; if (s && s.pdu.reqId === id && s.pdu.type === 'get-response') fin(null, s); });
    const send = () => { tries++; const r = n.udpSend(dst, o.port || 161, sport, bytes, { onFail: () => fin('unreachable') }); if (!r.ok) return fin('unreachable'); tm = sim.at(to, () => { if (tries > retries) fin('timeout'); else send(); }); };
    send();
  }
  walk(dst, o, root, onVb, done) {
    let cur = root.slice(); let last = null; const bulk = o.ver === 1 && !o.noBulk;
    const step = () => {
      if (o.abort && o.abort()) return done('aborted');
      this.query(dst, Object.assign({}, o, { op: bulk ? 'getbulk' : 'getnext', vbs: [{ oid: os(cur), t: 'null' }], nonRep: 0, maxRep: 10 }), (err, res) => {
        if (err) return done(err); const P = res.pdu; if (P.errStatus) { if (P.errStatus === 2) return done(null, 'end'); return done('err', P); }
        let end = false; for (const vb of P.varbinds) { const oo = oa(vb.oid); if (vb.t === 'eom' || !isPre(root, oo)) { end = true; break; } if (last && cmpO(oo, last) <= 0) return done('loop'); onVb(vb); last = oo; cur = oo; }
        if (end || !P.varbinds.length) return done(null); step();
      });
    };
    step();
  }
}

/* -------- patch IPNode : création de l'objet Mgmt et routage des journaux %FAC-SEV-MNEM vers syslog -------- */
const origLog = IPNode.prototype.log;
IPNode.prototype.log = function (m, l) { origLog.call(this, m, l); if (this.mgmt) this.mgmt.fromLog(m); };
NS.Mgmt = Mgmt; NS.mib = { oa, os, cmpO, nameOf, parseOid, fmtVb, stamp, SEVN, FACN, NAMES, tt2s };
})(typeof window !== 'undefined' ? window : globalThis);
