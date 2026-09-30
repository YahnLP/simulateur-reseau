const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const A=NS.Analyzer; const {Codec}=NS; let bad=0;
const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
const cfg=(sim,d,lines)=>cli(sim,d,['enable','conf t'].concat(lines,['end']));
function ping(sim,n,dst,count){ let r=[],done=false; NS.tools.pingSeries(n,IP.parse(dst),{count:count||3},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,60000); return r.join(' '); }
const sim=new Sim(); sim.opts.stpFast=false;
const R1=createDevice(sim,'r-2911',{name:'R1'}),R2=createDevice(sim,'r-2911',{name:'R2'}); const p1=createDevice(sim,'pc-win',{name:'PC1'}),p2=createDevice(sim,'pc-win',{name:'PC2'});
sim.connect(R1.findPort('gi0/1'),R2.findPort('gi0/1')); sim.connect(p1.ports[0],R1.findPort('gi0/0')); sim.connect(p2.ports[0],R2.findPort('gi0/0'));
p1.applyIp('Ethernet0',{ip:'192.168.1.10',mask:'24'}); p1.setGateway('192.168.1.1'); p2.applyIp('Ethernet0',{ip:'192.168.2.10',mask:'24'}); p2.setGateway('192.168.2.1');
const base=(lan,wan)=>['interface gi0/0','ip address '+lan+' 255.255.255.0','no shutdown','interface gi0/1','ip address '+wan+' 255.255.255.252','no shutdown','exit'];
cfg(sim,R1,base('192.168.1.1','203.0.113.1')); cfg(sim,R2,base('192.168.2.1','203.0.113.2'));
const gre=(t,d,ip)=>['interface tunnel0','ip address '+ip+' 255.255.255.252','tunnel source gi0/1','tunnel destination '+d,'exit','ip route 192.168.'+(ip.endsWith('1')?'2':'1')+'.0 255.255.255.0 tunnel0'];
cfg(sim,R1,gre(0,'203.0.113.2','10.9.9.1')); cfg(sim,R2,gre(0,'203.0.113.1','10.9.9.2')); sim.runFor(3000);
ok(/reply/.test(ping(sim,p1,'192.168.2.10')),'ping via GRE'); 
const ctx=A.newCtx(); const rec=sim.captures.find(r=>{const q=Codec.parse(r.bytes);return q.gre&&q.gre.inner&&q.gre.inner.icmp&&q.gre.inner.icmp.type===8});
ok(!!rec,'trame GRE avec ICMP interne'); const s=A.summarize(ctx,rec); console.log(s.proto,'|',s.src,'→',s.dst,'|',s.info,'|',s.protos.join(':'));
ok(s.proto==='ICMP'&&s.src==='203.0.113.1'&&/Echo/.test(s.info),'colonnes : protocole interne, adresses externes');
const f=q=>{const fn=A.compile(q);return fn(s)};
ok(f('gre')&&f('icmp')&&f('ip.addr == 192.168.2.10')&&f('ip.src == 203.0.113.1')&&f('icmp.type == 8')&&!f('tcp')&&!f('esp'),'filtres gre/icmp/ip.addr voient le paquet interne');
const d=A.detail(ctx,rec); const names=d.map(n=>n.t.slice(0,32)); console.log(names.join(' | ')); ok(d.filter(n=>/Internet Protocol Version 4/.test(n.t)).length===2&&d.some(n=>/Generic Routing/.test(n.t)),'arbre : IP externe, GRE, IP interne, ICMP');
// IPsec
console.log(bad?'ECHECS':'OK'); process.exit(bad?1:0);
