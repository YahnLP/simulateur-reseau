const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const {IP6,Codec,tools}=NS;
let bad=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
const A6=s=>IP6.parse(s);
function ping6(sim,n,dst,o){ let r=[],done=false; tools.pingSeries(n,dst,Object.assign({count:2},o||{}),x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,30000); return r.join(' '); }
{ // 1) deux hôtes sur le même lien : LL + statique
  const sim=new Sim(); const S=createDevice(sim,'sw-2960',{name:'SW'}), A=createDevice(sim,'pc-linux',{name:'A'}), B=createDevice(sim,'pc-win',{name:'B'});
  sim.connect(A.ports[0],S.findPort('fa0/1')); sim.connect(B.ports[0],S.findPort('fa0/2')); sim.runFor(2500);
  const ia=A.mainIface, ib=B.mainIface;
  ok(ia.v6&&ia.v6.addrs.some(a=>a.kind==='ll'&&a.state==='preferred'),'A a une adresse link-local preferred');
  ok(IP6.str(ia.v6.addrs[0].addr)===IP6.str(IP6.linkLocal(ia.mac)),'LL = EUI-64 du MAC');
  A.ip6.addAddr(ia,A6('2001:db8:1::a'),64,'manual'); B.ip6.addAddr(ib,A6('2001:db8:1::b'),64,'manual'); sim.runFor(1500);
  ok(ping6(sim,A,A6('2001:db8:1::b'))==='reply reply','ping6 GUA A→B');
  const nb=A.ip6.getNbr(ia,A6('2001:db8:1::b')); ok(nb&&nb.mac===ib.mac&&nb.state==='REACHABLE','voisin B REACHABLE dans A');
  ok(ping6(sim,B,A6('fe80::'+IP6.str(IP6.linkLocal(ia.mac)).slice(6)),{zone:ib})==='reply reply','ping6 LL B→A');
  // NS/NA visibles dans les captures
  const kinds=new Set(); sim.captures.forEach(c=>{const p=Codec.parse(c.bytes,false); if(p.icmp6) kinds.add(p.icmp6.type)}); ok(kinds.has(135)&&kinds.has(136)&&kinds.has(128)&&kinds.has(129),'NS/NA/echo capturés '+Array.from(kinds));
  // vieillissement : STALE après 30 s
  sim.runFor(31000); ok(A.ip6.nstate(nb)==='STALE','REACHABLE → STALE après 30 s');
  ok(ping6(sim,A,A6('2001:db8:1::b'))==='reply reply','ping en STALE OK'); sim.runFor(6000); console.log('état après DELAY/PROBE:',A.ip6.nstate(nb));
  ok(['REACHABLE','PROBE','STALE'].includes(A.ip6.nstate(nb)),'état valide');
  // adresse inexistante -> échec ND
  const r=ping6(sim,A,A6('2001:db8:1::99')); ok(/arpfail/.test(r),'voisin inexistant : '+r);
  // DAD : doublon
  const C=createDevice(sim,'pc-linux',{name:'C'}); sim.connect(C.ports[0],S.findPort('fa0/3')); sim.runFor(2000); C.ip6.addAddr(C.mainIface,A6('2001:db8:1::a'),64,'manual'); sim.runFor(2500);
  ok(C.mainIface.v6.addrs.find(a=>a.addr===A6('2001:db8:1::a')).state==='duplicate','DAD détecte l\'adresse dupliquée');
}
{ // 2) routeur, SLAAC, routage, traceroute
  const sim=new Sim(); const R1=createDevice(sim,'r-2911',{name:'R1'}), R2=createDevice(sim,'r-2911',{name:'R2'}), S1=createDevice(sim,'sw-2960',{name:'S1'}), S2=createDevice(sim,'sw-2960',{name:'S2'});
  const H1=createDevice(sim,'pc-linux',{name:'H1'}), H2=createDevice(sim,'pc-win',{name:'H2'});
  sim.connect(H1.ports[0],S1.findPort('fa0/1')); sim.connect(R1.findPort('gi0/0'),S1.findPort('fa0/2')); sim.connect(R1.findPort('gi0/1'),R2.findPort('gi0/1')); sim.connect(R2.findPort('gi0/0'),S2.findPort('fa0/2')); sim.connect(H2.ports[0],S2.findPort('fa0/1'));
  const up=(r,ifn,addr,plen)=>{ const i=r.ifaceByName(ifn); i.adminUp=true; i.port.adminUp=true; sim.portChanged(i.port); if(i.port.peer) sim.portChanged(i.port.peer); r.ip6.enable(i); r.ip6.addAddr(i,A6(addr),plen,'manual'); return i; };
  up(R1,'gi0/0','2001:db8:1::1',64); up(R1,'gi0/1','2001:db8:12::1',64); up(R2,'gi0/1','2001:db8:12::2',64); up(R2,'gi0/0','2001:db8:2::1',64);
  R1.ip6.setRouting(true); R2.ip6.setRouting(true); sim.runFor(3000);
  const h1=H1.mainIface, h2=H2.mainIface;
  const g1=h1.v6.addrs.find(a=>a.kind==='slaac'); ok(g1&&IP6.str(g1.addr)===IP6.str(IP6.withIid(A6('2001:db8:1::'),h1.mac)),'H1 : adresse SLAAC '+(g1&&IP6.str(g1.addr)));
  ok(H1.ip6.raDefaults.length===1&&H1.ip6.raDefaults[0].nh===IP6.linkLocal(R1.ifaceByName('gi0/0').mac),'H1 : route par défaut via LL du routeur (RA)');
  const g2=h2.v6.addrs.find(a=>a.kind==='slaac'); ok(!!g2,'H2 : SLAAC');
  // pas de route entre les LANs -> unreachable
  R1.ip6.statics.push({net:A6('2001:db8:2::'),plen:64,nh:A6('2001:db8:12::2'),iface:null,ad:1}); 
  let r=ping6(sim,H1,g2.addr); console.log('avant retour:',r);
  R2.ip6.statics.push({net:A6('2001:db8:1::'),plen:64,nh:A6('2001:db8:12::1'),iface:null,ad:1});
  r=ping6(sim,H1,g2.addr); ok(r==='reply reply','ping6 H1→H2 à travers 2 routeurs : '+r);
  // hop limit / traceroute
  const hops=[]; let d=false; tools.trace(H1,g2.addr,{maxHops:6,probes:1},(ttl,rs)=>hops.push(ttl+':'+IP6.str(rs[0].from||0n)+':'+rs[0].type),ok2=>d=true); sim.runUntil(()=>d,60000); console.log(hops.join(' | '));
  ok(hops.length===3&&/ttl/.test(hops[0])&&/ttl/.test(hops[1])&&/reply/.test(hops[2]),'traceroute6 : 3 sauts');
  // routing off sur R1 -> plus de transit
  R1.ip6.setRouting(false); r=ping6(sim,H1,g2.addr,{timeout:800}); ok(!/reply/.test(r),'sans ipv6 unicast-routing : pas de transit ('+r+')');
  R1.ip6.setRouting(true);
  // destination sans route -> dest unreachable
  r=ping6(sim,H1,A6('2001:db8:99::1')); ok(/unreach/.test(r),'pas de route : unreachable ('+r+')');
  // PTB
  r=ping6(sim,H1,g2.addr,{size:1600,count:1}); console.log('gros paquet:',r); ok(/ptb/.test(r),'Packet Too Big');
}
console.log('bad',bad); process.exit(bad?1:0);
