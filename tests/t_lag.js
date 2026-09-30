const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {tools}=NS; let bad=0;
const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
function ping(sim,n,dst){ let r=[],done=false; tools.pingSeries(n,IP.parse(dst),{count:2},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,20000); return r.join(' '); }
function mk(m1,m2,mode){
  const sim=new Sim(); sim.opts.stpFast=true;
  const A=createDevice(sim,'sw-2960',{name:'A'}),B=createDevice(sim,'sw-2960',{name:'B'});
  const pcs=[]; for(let i=0;i<4;i++){ const p=createDevice(sim,'pc-win',{name:'P'+i}); p.applyIp('Ethernet0',{ip:'10.0.0.'+(i+1),mask:'24'}); sim.connect(p.ports[0],(i<2?A:B).findPort('fa0/'+(10+i))); pcs.push(p); }
  const l1=sim.connect(A.findPort('fa0/1'),B.findPort('fa0/1')), l2=sim.connect(A.findPort('fa0/2'),B.findPort('fa0/2'));
  const cfg=(sw,m)=>cli(sim,sw,['enable','conf t','spanning-tree mode '+(mode||'rapid-pvst'),'interface range fa0/1-2','channel-group 1 mode '+m,'exit','interface port-channel 1','switchport mode trunk','end']);
  if(m1){cfg(A,m1);} if(m2){cfg(B,m2);}
  return {sim,A,B,pcs,l1,l2};
}
const bundled=s=>s.chans.size?s.chans.get(1).bundled().length:0;
for(const [m1,m2,exp,label] of [['active','active',2,'LACP active/active'],['active','passive',2,'LACP active/passive'],['passive','passive',0,'LACP passive/passive : pas d\'agrégat'],['on','on',2,'mode on/on'],['desirable','auto',2,'PAgP desirable/auto'],['desirable','desirable',2,'PAgP desirable/desirable'],['auto','auto',0,'PAgP auto/auto : pas d\'agrégat'],['active','on',0,'LACP actif face à on : pas d\'agrégat']]){
  const {sim,A,B,pcs}=mk(m1,m2); sim.runFor(8000);
  ok(bundled(A)===exp&&(m2==='on'&&m1!=='on'?true:bundled(B)===exp),label+' (A='+bundled(A)+', B='+bundled(B)+')');
  if(exp===2){ ok(/reply/.test(ping(sim,pcs[0],'10.0.0.3')),label+' : ping A→B via Po1'); }
}
{
  const {sim,A,B,pcs,l1}=mk('active','active'); sim.runFor(8000);
  console.log(cli(sim,A,['enable','show etherchannel summary','show spanning-tree','show lacp neighbor']));
  ok(A.chans.get(1).lp.stp.v.get(1).state==='forwarding','Po1 forwarding en STP');
  ok(A.ports.filter(p=>p.up&&p.stp.state==='blocking').length===0,'aucun membre bloqué par STP');
  // répartition : 2 hôtes sources différents -> les deux liens servent
  pcs.forEach(p=>ping(sim,p,'10.0.0.4'));
  const used=[A.findPort('fa0/1'),A.findPort('fa0/2')].map(p=>{const l=p.link; return sim.captures.filter(c=>c.link===l).length;});
  console.log('trames par lien A:',used);
  // panne d'un membre
  sim.disconnect(l1); sim.runFor(4000);
  ok(bundled(A)===1&&bundled(B)===1,'après panne d\'un lien : 1 membre agrégé');
  ok(/reply/.test(ping(sim,pcs[0],'10.0.0.3')),'ping OK après panne d\'un membre');
  const cfg=cli(sim,A,['enable','show running-config']);
  ok(/interface Port-channel1/.test(cfg)&&/channel-group 1 mode active/.test(cfg),'running-config contient Port-channel1 et channel-group');
}
{ // sans channel : STP bloque un des deux liens
  const sim=new Sim(); sim.opts.stpFast=true;
  const A=createDevice(sim,'sw-2960',{name:'A'}),B=createDevice(sim,'sw-2960',{name:'B'});
  sim.connect(A.findPort('fa0/1'),B.findPort('fa0/1')); sim.connect(A.findPort('fa0/2'),B.findPort('fa0/2')); sim.runFor(8000);
  const n=[A,B].reduce((k,s)=>k+s.ports.filter(p=>p.up&&p.stp.state==='blocking').length,0);
  ok(n===1,'liens parallèles sans EtherChannel : 1 port bloqué');
}
// trame LACP décodée
{
  const {sim,A}=mk('active','active'); sim.runFor(3000);
  const cap=sim.captures.find(c=>{const p=NS.Codec.parse(c.bytes,false); return p.lacp;}); ok(!!cap,'LACPDU capturée');
  if(cap){ const pk=NS.Codec.parse(cap.bytes,true); console.log(NS.Analyzer.summarize? '':'',JSON.stringify(pk.tree.map(n=>n.t).slice(0,3))); }
}
console.log(bad?'ECHECS '+bad:'LAG OK');
