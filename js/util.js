/* util.js — adresses IP/MAC, octets, checksums */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};

/* ---------- IPv4 (entiers non signés) ---------- */
const IP = {
  parse(s) {
    if (typeof s === 'number') return s >>> 0;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || '').trim());
    if (!m) return null;
    let n = 0;
    for (let i = 1; i <= 4; i++) { const b = +m[i]; if (b > 255) return null; n = n * 256 + b; }
    return n >>> 0;
  },
  str(n) { n >>>= 0; return ((n >>> 24) & 255) + '.' + ((n >>> 16) & 255) + '.' + ((n >>> 8) & 255) + '.' + (n & 255); },
  maskFromPrefix(p) { return p <= 0 ? 0 : ((0xFFFFFFFF << (32 - p)) >>> 0); },
  prefixFromMask(m) { m >>>= 0; let p = 0; while (p < 32 && (m & (0x80000000 >>> p))) p++; return p; },
  isMask(m) { m >>>= 0; const inv = (~m) >>> 0; return (((inv + 1) >>> 0) & inv) === 0; },
  /* accepte 255.255.255.0, /24, 24 */
  parseMask(s) {
    s = String(s).trim();
    if (/^\/?\d{1,2}$/.test(s)) { const p = +s.replace('/', ''); return p <= 32 ? IP.maskFromPrefix(p) : null; }
    const m = IP.parse(s);
    return (m !== null && IP.isMask(m)) ? m : null;
  },
  net(ip, mask) { return (ip & mask) >>> 0; },
  bcast(ip, mask) { return ((ip & mask) | (~mask)) >>> 0; },
  isMulticast(ip) { return (ip >>> 28) === 0xE; },
  isBroadcast(ip) { return (ip >>> 0) === 0xFFFFFFFF; },
  inNet(ip, net, mask) { return ((ip & mask) >>> 0) === ((net & mask) >>> 0); },
  classMask(ip) { const b = ip >>> 24; return b < 128 ? 0xFF000000 : b < 192 ? 0xFFFF0000 : 0xFFFFFF00; },
  cidr(ip, mask) { return IP.str(ip) + '/' + IP.prefixFromMask(mask); },
  parseCidr(s) {
    const m = /^([\d.]+)\/(\d{1,2})$/.exec(String(s).trim()); if (!m) return null;
    const ip = IP.parse(m[1]); if (ip === null || +m[2] > 32) return null;
    return { ip, mask: IP.maskFromPrefix(+m[2]) };
  },
  isPrivate(ip) {
    return IP.inNet(ip, IP.parse('10.0.0.0'), IP.maskFromPrefix(8)) ||
           IP.inNet(ip, IP.parse('172.16.0.0'), IP.maskFromPrefix(12)) ||
           IP.inNet(ip, IP.parse('192.168.0.0'), IP.maskFromPrefix(16));
  },
  multicastMac(ip) { return '01:00:5e:' + [(ip >>> 16) & 0x7f, (ip >>> 8) & 255, ip & 255].map(hx2).join(':'); },
};
function hx2(n) { return (n < 16 ? '0' : '') + n.toString(16); }

/* ---------- MAC ---------- */
const MAC = {
  BCAST: 'ff:ff:ff:ff:ff:ff',
  _n: 0,
  make(oui) { const n = ++MAC._n; return (oui + ':' + hx2((n >> 16) & 255) + ':' + hx2((n >> 8) & 255) + ':' + hx2(n & 255)).toLowerCase(); },
  toBytes(s) { return s.split(':').map(x => parseInt(x, 16)); },
  fromBytes(u8, o) { let r = []; for (let i = 0; i < 6; i++) r.push(hx2(u8[o + i])); return r.join(':'); },
  isBroadcast(m) { return m === 'ff:ff:ff:ff:ff:ff'; },
  isMulticast(m) { return (parseInt(m.slice(0, 2), 16) & 1) === 1; },
  valid(s) { return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s); },
  /* format Cisco 0000.0c12.3456 */
  cisco(m) { const h = m.replace(/:/g, ''); return h.slice(0, 4) + '.' + h.slice(4, 8) + '.' + h.slice(8, 12); },
  parseAny(s) {
    s = String(s).trim().toLowerCase().replace(/[-.]/g, ':');
    if (/^[0-9a-f]{12}$/.test(s.replace(/:/g, ''))) { const h = s.replace(/:/g, ''); return h.match(/../g).join(':'); }
    return null;
  },
};
/* Constructeurs (OUI) utilisés par le simulateur */
const OUI = {
  cisco: '00:00:0c', dell: '00:14:22', hp: '3c:d9:2b', vmware: '00:50:56', fortinet: '00:09:0f',
  stormshield: '00:0d:b4', ubiquiti: '24:5a:4c', synology: '00:11:32', yealink: '80:5e:c0', netgear: '00:14:6c',
  netgate: '90:ec:77', generic: '02:00:5e', lenovo: '54:ee:75', apple: 'a4:83:e7', raspberry: 'b8:27:eb', canon: '00:1e:8f',
  orange: '00:07:cb', alcatel: '00:d0:95',
};
const OUI_NAMES = {}; // rempli ci-dessous
Object.keys(OUI).forEach(k => OUI_NAMES[OUI[k]] = k.charAt(0).toUpperCase() + k.slice(1));
NS.OUI = OUI; NS.OUI_NAMES = OUI_NAMES;

/* ---------- Octets ---------- */
class Writer {
  constructor() { this.a = []; }
  u8(v) { this.a.push(v & 255); return this; }
  u16(v) { this.a.push((v >>> 8) & 255, v & 255); return this; }
  u32(v) { this.a.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); return this; }
  bytes(b) { for (let i = 0; i < b.length; i++) this.a.push(b[i] & 255); return this; }
  str(s) { for (let i = 0; i < s.length; i++) this.a.push(s.charCodeAt(i) & 255); return this; }
  mac(m) { return this.bytes(MAC.toBytes(m)); }
  ip(v) { return this.u32(v); }
  zeros(n) { for (let i = 0; i < n; i++) this.a.push(0); return this; }
  get length() { return this.a.length; }
  toU8() { return Uint8Array.from(this.a); }
}
function u16(u, o) { return (u[o] << 8) | u[o + 1]; }
function u32(u, o) { return ((u[o] * 16777216) + (u[o + 1] << 16) + (u[o + 2] << 8) + u[o + 3]) >>> 0; }
function setU16(u, o, v) { u[o] = (v >>> 8) & 255; u[o + 1] = v & 255; }
function concat(...arr) {
  let n = 0; arr.forEach(a => n += a.length);
  const r = new Uint8Array(n); let o = 0; arr.forEach(a => { r.set(a, o); o += a.length; }); return r;
}
function checksum(u, off, len, initial) {
  let s = initial || 0;
  const end = off + len;
  for (let i = off; i + 1 < end; i += 2) s += (u[i] << 8) | u[i + 1];
  if (len & 1) s += u[end - 1] << 8;
  while (s >>> 16) s = (s & 0xFFFF) + (s >>> 16);
  return (~s) & 0xFFFF;
}
function strBytes(s) { const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) & 255; return u; }
function bytesStr(u, o, l) { let s = ''; const e = l === undefined ? u.length : o + l; for (let i = o || 0; i < e; i++) s += String.fromCharCode(u[i]); return s; }
/* Chaînes UTF-8 <-> octets (pour le contenu HTTP) */
function utf8Bytes(s) { return new TextEncoder().encode(s); }
function utf8Str(u) { try { return new TextDecoder('utf-8').decode(u); } catch (e) { return bytesStr(u); } }
function hex(n, w) { let s = n.toString(16); while (s.length < (w || 0)) s = '0' + s; return s; }

/* ---------- Emetteur d'événements ---------- */
class Emitter {
  constructor() { this._l = {}; }
  on(ev, fn) { (this._l[ev] = this._l[ev] || []).push(fn); return () => this.off(ev, fn); }
  off(ev, fn) { this._l[ev] = (this._l[ev] || []).filter(f => f !== fn); }
  emit(ev, ...a) { (this._l[ev] || []).slice().forEach(f => { try { f(...a); } catch (e) { console.error(e); } }); }
}

/* Générateur pseudo-aléatoire déterministe (reproductibilité des TP) */
class Rng {
  constructor(seed) { this.s = (seed || 1234567) >>> 0; }
  next() { this.s = (Math.imul(this.s, 1664525) + 1013904223) >>> 0; return this.s / 4294967296; }
  int(n) { return Math.floor(this.next() * n); }
  bytes(n) { const u = new Uint8Array(n); for (let i = 0; i < n; i++) u[i] = this.int(256); return u; }
}

NS.IP = IP; NS.MAC = MAC; NS.Writer = Writer; NS.Emitter = Emitter; NS.Rng = Rng;
NS.B = { u16, u32, setU16, concat, checksum, strBytes, bytesStr, utf8Bytes, utf8Str, hex, hx2 };
})(typeof window !== 'undefined' ? window : globalThis);
