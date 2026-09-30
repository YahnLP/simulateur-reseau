const {NS,Sim,createDevice,IP,cli}=require('./helpers'); let bad=0; const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++;};
const cfg=(sim,d,lines)=>cli(sim,d,['enable','conf t'].concat(lines,['end']));
function run(withQos){
  const sim=new Sim(); sim.opts.stpFast=true;
  const R=createDevice(sim,'r-2911',{name:'R1'}), S1=createDevice(sim,'sw-2960',{name:'S1'}), S2=createDevice(sim,'sw-2960',{name:'S2'});
  const PBX=createDevice(sim,'srv-linux',{name:'PBX'}), T1=createDevice(sim,'ipphone',{name:'T1'}), T2=createDevice(sim,'ipphone',{name:'T2'}), F1=createDevice(sim,'pc-linux',{name:'F1'}), F2=createDevice(sim,'pc-linux',{name:'F2'});
  sim.connect(R.findPort('gi0/0'),S1.findPort('fa0/24')); sim.connect(R.findPort('gi0/1'),S2.findPort('fa0/24'));
  sim.connect(PBX.ports[0],S1.findPort('fa0/1')); sim.connect(T1.findPort('Internet'),S1.findPort('fa0/2')); sim.connect(F1.ports[0],S1.findPort('fa0/3')); sim.connect(T2.findPort('Internet'),S2.findPort('fa0/2')); sim.connect(F2.ports[0],S2.findPort('fa0/3'));
  cfg(sim,R,['interface gi0/0','ip address 10.1.0.1 255.255.255.0','no shutdown','exit','interface gi0/1','ip address 10.2.0.1 255.255.255.0','no shutdown','exit'].concat(withQos?['class-map match-any VOIX','match ip dscp ef','exit','class-map match-any SIGNAL','match ip dscp cs3','exit','policy-map WAN','class VOIX','priority 128','class SIGNAL','bandwidth 32','exit','interface gi0/1','service-policy output WAN','exit']:[]));
  cfg(sim,R,['interface gi0/1','bandwidth 512','exit']); 
  // liaison limitée : shape 512 kb/s via policy (sans QoS : policy sans priorité)
  if(!withQos) cfg(sim,R,['policy-map LIM','class class-default','shape average 512000','exit','exit','interface gi0/1','service-policy output LIM','exit']); else cfg(sim,R,['policy-map WAN','class class-default','shape average 512000','exit','exit']);
  PBX.applyIp(PBX.ifaceList()[0].name,{ip:'10.1.0.5',mask:'24'}); PBX.setGateway('10.1.0.1'); T1.applyIp('Internet',{ip:'10.1.0.11',mask:'24'}); T1.setGateway('10.1.0.1'); F1.applyIp(F1.ifaceList()[0].name,{ip:'10.1.0.50',mask:'24'}); F1.setGateway('10.1.0.1');
  T2.applyIp('Internet',{ip:'10.2.0.12',mask:'24'}); T2.setGateway('10.2.0.1'); F2.applyIp(F2.ifaceList()[0].name,{ip:'10.2.0.50',mask:'24'}); F2.setGateway('10.2.0.1');
  const P=PBX.pbx; P.addPeer('1001','a'); P.addPeer('1002','b'); P.addRoute('_10XX','SIP/${EXTEN}'); P.start();
  T1.voip.configure({ext:'1001',secret:'a',server:'10.1.0.5'}); T2.voip.configure({ext:'1002',secret:'b',server:'10.1.0.5'}); sim.runFor(3000);
  T1.voip.register(); T2.voip.register(); sim.runFor(8000);
  // flux de fond F1 -> F2 : 1400 o toutes les 8 ms (~1,4 Mb/s) pendant 20 s
  let n=0; const flood=()=>{ if(n++>2500) return; F1.udpSend(IP.parse('10.2.0.50'),9,40000,new Uint8Array(1400),{}); sim.at(8,flood); }; 
  T1.voip.call('1002'); sim.runFor(6000); flood(); sim.runFor(15000);
  return {T1,T2,R,st:T2.voip.stats(),st1:T1.voip.stats(),reg:[T1.voip.reg.state,T2.voip.reg.state],cur:T1.voip.cur&&T1.voip.cur.state,R};
}
const a=run(false); console.log('sans QoS',a.reg,a.cur,JSON.stringify(a.st));
const b=run(true); console.log('avec LLQ',b.reg,b.cur,JSON.stringify(b.st)); console.log(cli(b.R.sim,b.R,['enable','show policy-map interface gi0/1']));
ok(a.st&&a.st.mos<3.6,'sans QoS : voix dégradée (MOS '+(a.st&&a.st.mos)+')'); ok(b.st&&b.st.mos>4.0&&b.st.lossPct<1,'avec LLQ : voix propre (MOS '+(b.st&&b.st.mos)+')');
process.exit(bad?1:0);
