/* qos.js — moteur QoS : classification (DSCP/CoS/ACL/protocole), marquage, policer, file prioritaire (LLQ), débit limité (shape),
   confiance CoS/DSCP des switchs (mls qos). S'appuie sur des crochets de Sim.transmit : port.qos (émission) et port.qosIn (réception). */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {}; const { Codec } = NS;
const DSCP_NAMES = { default: 0, cs1: 8, cs2: 16, cs3: 24, cs4: 32, cs5: 40, cs6: 48, cs7: 56, af11: 10, af12: 12, af13: 14, af21: 18, af22: 20, af23: 22, af31: 26, af32: 28, af33: 30, af41: 34, af42: 36, af43: 38, ef: 46 };
const dscpName = v => { for (const k in DSCP_NAMES) if (DSCP_NAMES[k] === v && k !== 'default') return k; return v === 0 ? 'default' : String(v); };
const parseDscp = s => { s = String(s).toLowerCase(); if (s in DSCP_NAMES) return DSCP_NAMES[s]; const n = +s; return Number.isInteger(n) && n >= 0 && n < 64 ? n : null; };
const COS_DSCP = [0, 8, 16, 24, 32, 40, 48, 56];   // table par défaut des Catalyst
const PROTO_PORTS = { http: ['tcp', 80], https: ['tcp', 443], ssh: ['tcp', 22], telnet: ['tcp', 23], dns: ['udp', 53], ftp: ['tcp', 21], smtp: ['tcp', 25], snmp: ['udp', 161], syslog: ['udp', 514], sip: ['udp', 5060] };
const ipOff = b => { let o = 12, cos = null; if (b[12] === 0x81 && b[13] === 0) { cos = b[14] >> 5; o = 16; } return (b[o] === 8 && b[o + 1] === 0) ? { ip: o + 2, cos } : { ip: -1, cos }; };
function setDscp(b, dscp) {
  const { ip } = ipOff(b); if (ip < 0) return b; const r = b.slice(); r[ip + 1] = (dscp << 2) | (r[ip + 1] & 3);
  r[ip + 10] = 0; r[ip + 11] = 0; const ihl = (r[ip] & 15) * 4; let s = 0; for (let i = 0; i < ihl; i += 2) s += (r[ip + i] << 8) | r[ip + i + 1]; while (s >> 16) s = (s & 0xffff) + (s >> 16); s = ~s & 0xffff; r[ip + 10] = s >> 8; r[ip + 11] = s & 255; return r;
}
function setCos(b, cos) { if (!(b[12] === 0x81 && b[13] === 0)) return b; const r = b.slice(); r[14] = (r[14] & 0x1f) | (cos << 5); return r; }

const Qos = {
  DSCP_NAMES, dscpName, parseDscp, COS_DSCP, setDscp, ipOff,
  ensure(dev) { if (!dev.qos) dev.qos = { cmaps: new Map(), pmaps: new Map(), mls: false }; return dev.qos; },
  reset(dev) { dev.qos = null; dev.ports.forEach(p => { p.svcIn = p.svcOut = null; p.trust = null; p.prioQ = false; p.qos = null; p.qosIn = null; }); },
  /* ---- correspondance d'une classe ---- */
  matchClass(dev, cm, p, meta) {
    if (!cm) return true; const res = m => {
      switch (m.t) {
        case 'any': return true;
        case 'dscp': return !!p.ip && m.v.includes(p.ip.tos >> 2);
        case 'cos': return meta.cos !== null && m.v.includes(meta.cos);
        case 'acl': return !!p.ip && !!dev.aclPermit && dev.aclPermit(m.v, p);
        case 'rtp': return !!p.rtp;
        case 'proto': { if (m.v === 'rtp') return !!p.rtp; if (m.v === 'icmp') return !!p.icmp; if (m.v === 'sip') return !!p.sip; const pp = PROTO_PORTS[m.v]; if (!pp) return false; const l = p[pp[0]]; return !!l && (l.dport === pp[1] || l.sport === pp[1]); }
        case 'vlan': return false;
      } return false;
    };
    if (!cm.matches.length) return false;
    return cm.any ? cm.matches.some(res) : cm.matches.every(res);
  },
  classify(dev, pol, bytes, meta) {
    const p = Codec.parse(bytes, false); if (!p.ip) return { cls: pol.classes.find(c => c.cm === 'class-default') || null, p };
    for (const c of pol.classes) { if (c.cm === 'class-default') continue; if (this.matchClass(dev, dev.qos.cmaps.get(c.cm), p, meta)) return { cls: c, p }; }
    return { cls: pol.classes.find(c => c.cm === 'class-default') || null, p };
  },
  /* ---- (re)compilation des crochets d'un équipement ---- */
  apply(dev) {
    dev.ports.forEach(pt => {
      pt.qos = null; pt.qosIn = null; const Q = dev.qos;
      if (!Q && !pt.trust && !pt.prioQ) return;
      const svcOut = Q && pt.svcOut && Q.pmaps.get(pt.svcOut), svcIn = Q && pt.svcIn && Q.pmaps.get(pt.svcIn);
      const mls = Q && Q.mls;
      if (svcIn || mls) pt.qosIn = this.mkIn(dev, pt, svcIn, mls);
      if (svcOut || (mls && pt.prioQ)) pt.qos = this.mkOut(dev, pt, svcOut, mls);
    });
  },
  cstats(c) { return c.st || (c.st = { pk: 0, by: 0, drop: 0, marked: 0 }); },
  policer(rateBps) { return { rate: rateBps, burst: Math.max(1600, rateBps / 8 / 8), tok: Math.max(1600, rateBps / 8 / 8), t: 0 }; },
  polOk(pl, now, len) { pl.tok = Math.min(pl.burst, pl.tok + (now - pl.t) * pl.rate / 8000); pl.t = now; if (pl.tok >= len) { pl.tok -= len; return true; } return false; },
  /* réception : confiance (mls qos) puis politique d'entrée */
  mkIn(dev, pt, pol, mls) {
    const self = this;
    return function (bytes, now) {
      let b = bytes; const o = ipOff(b);
      if (mls) {
        let trust = pt.trust; if (trust === 'phone') trust = (pt.link && pt.link.other(pt).dev && pt.link.other(pt).dev.phone) ? 'cos' : null;
        if (o.ip >= 0) {
          if (trust === 'dscp') { } else if (trust === 'cos') { if (o.cos !== null) b = setDscp(b, COS_DSCP[o.cos]); else b = setDscp(b, 0); } else { b = setDscp(b, 0); b = setCos(b, 0); }
        }
      }
      if (pol) {
        const meta = { cos: ipOff(b).cos }; const r = self.classify(dev, pol, b, meta); const c = r.cls;
        if (c) {
          const st = self.cstats(c); st.pk++; st.by += b.length;
          if (c.act.police) { c.pl = c.pl || self.policer(c.act.police); if (!self.polOk(c.pl, now, b.length)) { st.drop++; return null; } }
          if (c.act.dscp !== undefined && c.act.dscp !== null) { b = setDscp(b, c.act.dscp); st.marked++; }
        }
      }
      return b;
    };
  },
  /* émission : classification, marquage, file prioritaire, débit */
  mkOut(dev, pt, pol, mls) {
    const self = this; const q = { fh: 0, fl: 0, pol, hiDrops: 0, loDrops: 0, hiPk: 0, loPk: 0, maxDelay: 0 };
    let shape = null; if (pol) pol.classes.forEach(c => { if (c.act.shape) shape = c.act.shape; });
    q.rateKbps = shape ? shape / 1000 : null;
    q.tx = function (bytes, now, linkMbps) {
      let b = bytes, hi = false, cls = null;
      if (pol) {
        const meta = { cos: ipOff(b).cos }; const r = self.classify(dev, pol, b, meta); cls = r.cls;
        if (cls) { const st = self.cstats(cls); st.pk++; st.by += b.length; if (cls.act.priority) hi = true; if (cls.act.dscp !== undefined && cls.act.dscp !== null) { b = setDscp(b, cls.act.dscp); st.marked++; } if (cls.act.police) { cls.pl = cls.pl || self.policer(cls.act.police); if (!self.polOk(cls.pl, now, b.length)) { st.drop++; return null; } } }
      } else if (mls && pt.prioQ) { const o = ipOff(b); hi = (o.ip >= 0 && (b[o.ip + 1] >> 2) >= 40 && (b[o.ip + 1] >> 2) <= 47) || o.cos === 5; }
      const mbps = q.rateKbps ? Math.min(linkMbps, q.rateKbps / 1000) : linkMbps; const ser = (b.length + 24) * 8 / (mbps * 1000);
      const limit = 768000 / (mbps * 1000); let t0;
      if (hi) {
        const congested = q.fl > now;
        if (congested && cls && cls.act.priority > 1) { cls.pl = cls.pl || self.policer(cls.act.priority); if (!self.polOk(cls.pl, now, b.length)) { self.cstats(cls).drop++; q.hiDrops++; return null; } }
        t0 = Math.max(now, q.fh); if (q.fl > now) t0 += Math.min(q.fl - now, 12000 / (mbps * 1000)) / 2;
        if (t0 - now > limit / 4) { if (cls) self.cstats(cls).drop++; q.hiDrops++; return null; }
        q.fh = t0 + ser; q.fl = Math.max(q.fl, now) + ser; q.hiPk++;
      } else {
        t0 = Math.max(now, q.fl, q.fh);
        if (t0 - now > limit) { if (cls) self.cstats(cls).drop++; q.loDrops++; return null; }
        q.fl = t0 + ser; q.loPk++;
      }
      if (t0 - now > q.maxDelay) q.maxDelay = t0 - now; return { bytes: b, t0, ser };
    };
    return q;
  }
};
NS.Qos = Qos;
})(typeof window !== 'undefined' ? window : globalThis);
