const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {tools}=NS; let bad=0;
const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
function build(mode){
  const sim=new Sim(); sim.opts.stpFast=true;
  const A=createDevice(sim,'sw-2960',{name:'A'}),B=createDevice(sim,'sw-2960',{name:'B'}),C=createDevice(sim,'sw-2960',{name:'C'});
  const p1=createDevice(sim,'pc-win',{name:'P1'}),p2=createDevice(sim,'pc-win',{name:'P2'});
  sim.connect(A.findPort('fa0/1'),B.findPort('fa0/1')); sim.connect(B.findPort('fa0/2'),C.findPort('fa0/2')); sim.connect(C.findPort('fa0/1'),A.findPort('fa0/2'));
  sim.connect(p1.ports[0],B.findPort('fa0/10')); sim.connect(p2.ports[0],C.findPort('fa0/10'));
  p1.applyIp('Ethernet0',{ip:'10.0.0.1',mask:'24'}); p2.applyIp('Ethernet0',{ip:'10.0.0.2',mask:'24'});
  [A,B,C].forEach(s=>cli(sim,s,['enable','conf t','spanning-tree mode '+mode,'end']));
  return {sim,A,B,C,p1,p2};
}
function ping(sim,n,dst){ let r=[],done=false; tools.pingSeries(n,IP.parse(dst),{count:2},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,20000); return r.join(' '); }
const blocked=(...sw)=>{let n=0;sw.forEach(s=>s.ports.forEach(p=>{ if(p.up&&p.stp.state==='blocking') n++; }));return n;};
for(const mode of ['pvst','rapid-pvst']){
  const T=build(mode); const {sim,A,B,C,p1}=T;
  sim.runFor(mode==='pvst'?12000:3000);
  ok(blocked(A,B,C)===1,mode+' : un seul port bloqué (='+blocked(A,B,C)+')');
  ok(/reply/.test(ping(sim,p1,'10.0.0.2')),mode+' : ping P1->P2');
  const out=cli(sim,A,['show spanning-tree']);
  if(mode==='rapid-pvst') console.log(out.split('\n').slice(0,20).join('\n'));
  ok(out.includes(mode==='pvst'?'protocol ieee':'protocol rstp'),mode+' : show indique le protocole');
  // panne du lien racine: trouver le port racine de B ou C
  const root=[A,B,C].find(s=>s.stp.isRoot);
  const nonroot=[A,B,C].filter(s=>s!==root);
  const rp=nonroot[0].stp.rootPort; const t0=sim.now;
  sim.setPortAdmin ? 0 : 0;
  const l=rp.link; sim.disconnect ? sim.disconnect(l) : 0;
  let t=0; const okc=()=>/reply/.test(ping(sim,p1,'10.0.0.2'));
  sim.runFor(mode==='pvst'?12000:1500);
  ok(blocked(A,B,C)===0,mode+' : après panne aucun port bloqué (='+blocked(A,B,C)+')');
  ok(okc(),mode+' : connectivité rétablie après panne');
}
console.log(bad?'ECHECS '+bad:'STP OK');
