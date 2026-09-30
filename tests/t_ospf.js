const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {tools}=NS; let bad=0;
const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
function ping(sim,n,dst){ let r=[],done=false; tools.pingSeries(n,IP.parse(dst),{count:3},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,30000); return r.join(' '); }
const R=(sim,name,model)=>createDevice(sim,model||'r-2911',{name});
const cfg=(sim,d,lines)=>cli(sim,d,['enable','conf t'].concat(lines,['end']));
// ---- 1. triangle de 3 routeurs, chacun avec un LAN
{
  const sim=new Sim(); sim.opts.stpFast=false;
  const A=R(sim,'A'),B=R(sim,'B'),C=R(sim,'C'); const pa=createDevice(sim,'pc-win',{name:'PA'}),pc=createDevice(sim,'pc-win',{name:'PC'});
  sim.connect(A.findPort('gi0/0'),B.findPort('gi0/0')); sim.connect(B.findPort('gi0/1'),C.findPort('gi0/0')); sim.connect(C.findPort('gi0/1'),A.findPort('gi0/1'));
  sim.connect(pa.ports[0],A.findPort('gi0/2')); sim.connect(pc.ports[0],C.findPort('gi0/2'));
  pa.applyIp('Ethernet0',{ip:'192.168.1.10',mask:'24'}); pa.setGateway('192.168.1.1'); pc.applyIp('Ethernet0',{ip:'192.168.3.10',mask:'24'}); pc.setGateway('192.168.3.1');
  const ipc=(d,i,ip)=>['interface '+i,'ip address '+ip+' 255.255.255.0','no shutdown','exit'];
  cfg(sim,A,[].concat(ipc(A,'gi0/0','10.0.12.1'),ipc(A,'gi0/1','10.0.13.1'),ipc(A,'gi0/2','192.168.1.1'),['interface loopback0','ip address 1.1.1.1 255.255.255.255','exit','router ospf 1','network 10.0.12.0 0.0.0.255 area 0','network 10.0.13.0 0.0.0.255 area 0','network 192.168.1.0 0.0.0.255 area 0','network 1.1.1.1 0.0.0.0 area 0','passive-interface gi0/2']));
  cfg(sim,B,[].concat(ipc(B,'gi0/0','10.0.12.2'),ipc(B,'gi0/1','10.0.23.2'),['router ospf 1','network 10.0.0.0 0.255.255.255 area 0']));
  cfg(sim,C,[].concat(ipc(C,'gi0/0','10.0.23.3'),ipc(C,'gi0/1','10.0.13.3'),ipc(C,'gi0/2','192.168.3.1'),['router ospf 1','network 10.0.0.0 0.255.255.255 area 0','network 192.168.3.0 0.0.0.255 area 0','passive-interface gi0/2']));
  sim.runFor(60000);
  const nb=cli(sim,A,['enable','show ip ospf neighbor']); console.log(nb);
  ok((nb.match(/FULL/g)||[]).length===2,'A : 2 voisins FULL');
  console.log(cli(sim,A,['show ip route']));
  ok(/O\s+192\.168\.3\.0\/24 \[110\/2\] via 10\.0\.13\.3/.test(cli(sim,A,['show ip route ospf'])),'A route OSPF vers 192.168.3.0/24 via C (coût 2)');
  ok(/reply/.test(ping(sim,pa,'192.168.3.10')),'PA -> PC (via OSPF)');
  console.log(cli(sim,A,['show ip ospf database']));
  console.log(cli(sim,A,['show ip ospf interface brief']));
  // panne du lien A-C : reroutage par B
  const lac=A.findPort('gi0/1').link; sim.disconnect(lac); sim.runFor(50000);
  console.log(cli(sim,A,['show ip route ospf']));
  ok(/192\.168\.3\.0\/24 \[110\/3\] via 10\.0\.12\.2/.test(cli(sim,A,['show ip route ospf'])),'reroutage via B après panne A–C (coût 3)');
  ok(/reply/.test(ping(sim,pa,'192.168.3.10')),'PA -> PC après panne');
  // analyseur : trames OSPF capturées
  const types=new Set(); sim.captures.forEach(c=>{ const p=NS.Codec.parse(c.bytes,false); if(p.ospf) types.add(p.ospf.type); });
  ok([1,2,3,4,5].every(t=>types.has(t)),'Hello, DBD, LSR, LSU, LSAck vus dans les captures ('+[...types]+')');
  const cap=sim.captures.find(c=>{const p=NS.Codec.parse(c.bytes,false); return p.ospf&&p.ospf.type===4;}); const pk=NS.Codec.parse(cap.bytes,true);
  console.log(JSON.stringify(pk.tree.slice(-1)[0].ch.slice(-3).map(n=>n.t)).slice(0,300));
}
// ---- 2. LAN partagé : élection DR/BDR
{
  const sim=new Sim(); sim.opts.stpFast=false;
  const sw=createDevice(sim,'sw-2960',{name:'SW'}); const Rs=[1,2,3].map(i=>R(sim,'R'+i));
  Rs.forEach((r,i)=>{ sim.connect(r.findPort('gi0/0'),sw.findPort('fa0/'+(i+1))); cfg(sim,r,['interface loopback0','ip address '+(i+1)+'.'+(i+1)+'.'+(i+1)+'.'+(i+1)+' 255.255.255.255','exit','interface gi0/0','ip address 10.0.0.'+(i+1)+' 255.255.255.0','no shutdown','exit','router ospf 1','network 10.0.0.0 0.0.0.255 area 0','network '+(i+1)+'.'+(i+1)+'.'+(i+1)+'.'+(i+1)+' 0.0.0.0 area 0']); });
  sim.runFor(100000);
  console.log(cli(sim,Rs[0],['enable','show ip ospf neighbor']));
  const st=Rs.map(r=>cli(sim,r,['enable','show ip ospf interface gi0/0']).match(/State (\w+)/)[1]);
  ok(st[2]==='DR'&&st[1]==='BDR'&&st[0]==='DROTHER','élection : R3 DR (RID le plus haut), R2 BDR, R1 DROTHER ('+st+')');
  ok(/1\.1\.1\.1\/32|O\s+3\.3\.3\.3/.test(cli(sim,Rs[0],['show ip route ospf'])),'R1 apprend la loopback de R3');
  // priorité 0 sur R3 + clear : R2 devient DR
  cfg(sim,Rs[2],['interface gi0/0','ip ospf priority 0']); Rs.forEach(r=>cli(sim,r,['enable','clear ip ospf process'])); sim.runFor(100000);
  const st2=Rs.map(r=>cli(sim,r,['enable','show ip ospf interface gi0/0']).match(/State (\w+)/)[1]);
  ok(st2[2]==='DROTHER'&&st2[1]==='DR','priorité 0 sur R3 : R3 DROTHER, R2 DR ('+st2+')');
}
// ---- 3. multi-aires + redistribution
{
  const sim=new Sim(); sim.opts.stpFast=false;
  const A=R(sim,'A'),B=R(sim,'B'),C=R(sim,'C');
  sim.connect(A.findPort('gi0/0'),B.findPort('gi0/0')); sim.connect(B.findPort('gi0/1'),C.findPort('gi0/0'));
  const ipc=(i,ip)=>['interface '+i,'ip address '+ip+' 255.255.255.0','no shutdown','exit'];
  cfg(sim,A,[].concat(ipc('gi0/0','10.1.1.1'),ipc('gi0/2','172.16.1.1'),['router ospf 1','network 10.1.1.0 0.0.0.255 area 1','network 172.16.1.0 0.0.0.255 area 1']));
  cfg(sim,B,[].concat(ipc('gi0/0','10.1.1.2'),ipc('gi0/1','10.0.0.2'),['router ospf 1','network 10.1.1.0 0.0.0.255 area 1','network 10.0.0.0 0.0.0.255 area 0']));
  cfg(sim,C,[].concat(ipc('gi0/0','10.0.0.3'),ipc('gi0/2','192.168.9.1'),['ip route 203.0.113.0 255.255.255.0 null0','router ospf 1','network 10.0.0.0 0.0.0.255 area 0','redistribute static subnets','default-information originate always']));
  sim.runFor(120000);
  console.log(cli(sim,A,['enable','show ip route']));
  ok(/O IA\s+10\.0\.0\.0\/24/.test(cli(sim,A,['show ip route'])),'A apprend 10.0.0.0/24 en inter-aire (O IA)');
  ok(/O\*?E2/.test(cli(sim,A,['show ip route']))||/E2/.test(cli(sim,A,['show ip route'])),'A a une route externe E2');
  console.log(cli(sim,B,['show ip ospf database']));
  console.log(cli(sim,B,['show ip ospf']));
  ok(/area border/.test(cli(sim,B,['show ip ospf'])),'B est ABR');
}
console.log(bad?'ECHECS '+bad:'OSPF OK');
