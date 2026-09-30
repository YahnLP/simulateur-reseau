const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {tools}=NS; let bad=0;
const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
function ping(sim,n,dst){ let r=[],done=false; tools.pingSeries(n,IP.parse(dst),{count:2},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,20000); return r.join(' '); }
function tri(mode,fast){
  const sim=new Sim(); sim.opts.stpFast=fast;
  const A=createDevice(sim,'sw-2960',{name:'A'}),B=createDevice(sim,'sw-2960',{name:'B'}),C=createDevice(sim,'sw-2960',{name:'C'});
  const l1=sim.connect(A.findPort('fa0/1'),B.findPort('fa0/1')), l2=sim.connect(B.findPort('fa0/2'),C.findPort('fa0/2')), l3=sim.connect(C.findPort('fa0/1'),A.findPort('fa0/2'));
  [A,B,C].forEach(s=>cli(sim,s,['enable','conf t','spanning-tree mode '+mode,'end']));
  return {sim,A,B,C,l1,l2,l3};
}
// convergence : temps jusqu'à état stable et temps de reprise (mesures en temps simulé)
for(const [mode,fast] of [['pvst',false],['rapid-pvst',false]]){
  const {sim,A,B,C,l1,l2,l3}=tri(mode,fast);
  let t0=sim.now, stable=null; const fw=()=>sim.now>t0+100&&[A,B,C].every(s=>s.ports.filter(p=>p.up).every(p=>p.stp.role!=='disabled'&&(p.stp.state==='forwarding'||(p.stp.state==='blocking'&&p.stp.role==='alternate'))));
  sim.runUntil(fw,120000); const tconv=sim.now-t0; sim.runFor(60000);
  // force root = A ; casse le lien du port racine de B
  const root=[A,B,C].find(s=>s.stp.isRoot); const nr=[A,B,C].filter(s=>s!==root)[0]; const rp=nr.stp.rootPort;
  const cnt=()=>[A,B,C].reduce((n,s)=>n+s.ports.filter(p=>p.up&&p.stp.state!=='forwarding'&&p.stp.state!=='blocking').length,0);
  const t1=sim.now; sim.disconnect(rp.link); 
  // reprise = plus de port en transition et le port alternate est passé en root/forwarding
  let recov=null; sim.runUntil(()=>[A,B,C].every(s=>s.ports.filter(p=>p.up).every(p=>p.stp.state==='forwarding')),120000); recov=sim.now-t1;
  console.log(mode+' (délais 15 s) : convergence initiale '+(tconv/1000).toFixed(1)+' s ; reprise après panne du lien racine '+(recov/1000).toFixed(2)+' s');
  if(mode==='rapid-pvst') ok(recov<1500,'rapid : reprise < 1,5 s'); else ok(recov>=25000&&recov<=52000,'pvst : reprise ~30 s (802.1D) ='+recov);
  if(mode==='rapid-pvst') ok(tconv<4000,'rapid : convergence initiale < 4 s (='+tconv+')');
}
// équilibrage par VLAN : A root VLAN10, B root VLAN20 ; C doit bloquer un port différent par VLAN
{
  const {sim,A,B,C}=tri('rapid-pvst',true);
  [A,B,C].forEach(s=>cli(sim,s,['enable','conf t','vlan 10','vlan 20','exit','interface range fa0/1-2','switchport mode trunk','end']));
  cli(sim,A,['enable','conf t','spanning-tree vlan 10 priority 4096','spanning-tree vlan 20 priority 8192','end']);
  cli(sim,B,['enable','conf t','spanning-tree vlan 20 priority 4096','spanning-tree vlan 10 priority 8192','end']);
  sim.runFor(8000);
  const st=(s,v,p)=>s.stp.ps(s.findPort(p),v)&&s.stp.ps(s.findPort(p),v).state;
  console.log(cli(sim,C,['show spanning-tree vlan 10','show spanning-tree vlan 20']).split('\n').filter(l=>/^(Fa|VLAN|Interface)|Root ID|Priority/.test(l)).join('\n'));
  const b10=['fa0/1','fa0/2'].filter(p=>st(C,10,p)==='blocking'), b20=['fa0/1','fa0/2'].filter(p=>st(C,20,p)==='blocking');
  ok(A.stp.insts.get(10).rootPort===null && B.stp.insts.get(20).rootPort===null,'A racine VLAN10, B racine VLAN20');
  ok(b10.length===1&&b20.length===1&&b10[0]!==b20[0],'C bloque un port différent par VLAN ('+b10+' / '+b20+')');
}
// root guard & bpdu guard
{
  const {sim,A,B,C}=tri('rapid-pvst',true);
  sim.runFor(4000);
  cli(sim,A,['enable','conf t','spanning-tree vlan 1 priority 4096','end']); sim.runFor(3000);
  ok(A.stp.isRoot,'A devient racine');
  cli(sim,C,['enable','conf t','interface fa0/2','spanning-tree guard root','end']);
  cli(sim,A,['enable','conf t','interface fa0/1','spanning-tree guard root','end']);
  cli(sim,B,['enable','conf t','spanning-tree vlan 1 priority 0','end']); sim.runFor(5000);
  const x=C.stp.ps(C.findPort('fa0/2'),1), y=A.stp.ps(A.findPort('fa0/1'),1);
  ok(x.rootInc&&x.state==='blocking'&&y.rootInc,'root guard : ports vers le B « pirate » en root-inconsistent');
  ok(A.stp.isRoot,'A reste racine malgré B priorité 0');
  cli(sim,B,['enable','conf t','spanning-tree vlan 1 priority 61440','end']); sim.runFor(9000);
  ok(!C.stp.ps(C.findPort('fa0/2'),1).rootInc,'root guard : débloqué quand B cesse d\'annoncer une racine supérieure');
  console.log(cli(sim,C,['show spanning-tree']).split('\n').filter(l=>/Fa0|ROOT/.test(l)).join('\n'));
}
{
  const sim=new Sim(); sim.opts.stpFast=true;
  const A=createDevice(sim,'sw-2960',{name:'A'}),B=createDevice(sim,'sw-2960',{name:'B'});
  cli(sim,A,['enable','conf t','interface fa0/5','spanning-tree portfast','spanning-tree bpduguard enable','end']);
  sim.connect(A.findPort('fa0/5'),B.findPort('fa0/5')); sim.runFor(8000);
  ok(A.findPort('fa0/5').errdis===true,'bpduguard : port fa0/5 err-disabled');
  console.log(cli(sim,A,['show interfaces status']).split('\n').filter(l=>/Fa0\/5 /.test(l)).join('\n'));
}
console.log(bad?'ECHECS '+bad:'STP2 OK');
