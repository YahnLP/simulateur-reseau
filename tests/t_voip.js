const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const A=NS.Analyzer; let bad=0; const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++;};
const cfg=(sim,d,lines)=>cli(sim,d,['enable','conf t'].concat(lines,['end']));
const sim=new Sim(); sim.opts.stpFast=false;
const SW=createDevice(sim,'sw-2960',{name:'SW1'}), PBX=createDevice(sim,'srv-linux',{name:'PBX'}), T1=createDevice(sim,'ipphone',{name:'T1'}), T2=createDevice(sim,'ipphone',{name:'T2'}), PC=createDevice(sim,'pc-win',{name:'PC1'});
sim.connect(PBX.ports[0],SW.findPort('fa0/24')); sim.connect(T1.findPort('Internet'),SW.findPort('fa0/1')); sim.connect(T2.findPort('Internet'),SW.findPort('fa0/2')); sim.connect(PC.ports[0],T1.findPort('PC'));
cfg(sim,SW,['vlan 10','name DATA','vlan 20','name VOIX','exit','interface vlan 20','ip address 192.168.20.1 255.255.255.0','no shutdown','exit','interface range fa0/1-2','switchport mode access','switchport access vlan 10','switchport voice vlan 20','exit','interface fa0/24','switchport mode access','switchport access vlan 20','exit']);
PBX.applyIp(PBX.ifaceList()[0].name,{ip:'192.168.20.5',mask:'24'});
T1.applyIp('Internet',{ip:'192.168.20.11',mask:'24'}); T2.applyIp('Internet',{ip:'192.168.20.12',mask:'24'}); PC.applyIp(PC.ifaceList()[0].name,{ip:'192.168.10.50',mask:'24'});
const P=PBX.pbx; P.addPeer('1001','pass1',{callerid:'Alice'}); P.addPeer('1002','pass2',{callerid:'Bob'}); P.addRoute('_10XX','SIP/${EXTEN}'); P.start();
sim.runFor(70000);
ok(T1.phone.voiceVlan===20&&T2.phone.voiceVlan===20,'VLAN voix 20 appris par CDP'); ok(T1.ifaceList()[0].vid===20,'iface téléphone étiquetée VLAN 20');
T1.voip.configure({ext:'1001',secret:'pass1',server:'192.168.20.5',name:'Alice'}); T2.voip.configure({ext:'1002',secret:'pass2',server:'192.168.20.5',name:'Bob'});
T1.voip.register(); T2.voip.register(); sim.runFor(5000);
ok(T1.voip.reg.state==='registered'&&T2.voip.reg.state==='registered','enregistrement digest 1001/1002 : '+T1.voip.reg.state+' '+T2.voip.reg.reason);
ok(!!P.peers.get('1001').reg,'PBX voit 1001 enregistré');
// mauvais mot de passe
const T3=createDevice(sim,'ipphone',{name:'T3'}); sim.connect(T3.findPort('Internet'),SW.findPort('fa0/3')); cfg(sim,SW,['interface fa0/3','switchport mode access','switchport access vlan 10','switchport voice vlan 20','exit']); T3.applyIp('Internet',{ip:'192.168.20.13',mask:'24'}); sim.runFor(40000);
P.addPeer('1003','good'); T3.voip.configure({ext:'1003',secret:'bad',server:'192.168.20.5'}); T3.voip.register(); sim.runFor(5000); ok(T3.voip.reg.state==='failed'&&/403/.test(T3.voip.reg.reason),'mauvais mot de passe : 403');
console.log(T3.voip.reg, P.log.slice(-4));
// appel
sim.opts.capture=true; T1.voip.call('1002'); sim.runFor(2500); console.log(T1.voip.cur&&T1.voip.cur.state,T2.voip.cur&&T2.voip.cur.state,T1.voip.log.slice(-3),T2.voip.log.slice(-3)); ok(T1.voip.cur&&T1.voip.cur.state==='ringing'&&T2.voip.cur&&T2.voip.cur.state==='ringing','ça sonne des deux côtés'); sim.runFor(5000);
ok(T1.voip.cur&&T1.voip.cur.state==='talking'&&T2.voip.cur&&T2.voip.cur.state==='talking','communication établie'); sim.runFor(10000);
console.log(T1.voip.cur&&T1.voip.cur.state,T2.voip.cur&&T2.voip.cur.state,P.log.slice(-6),T1.voip.log.slice(-4),T1.voip.debug);
const s1=T1.voip.stats(),s2=T2.voip.stats(); console.log(JSON.stringify(s1)); ok(s1&&s1.rx>400&&s2.rx>400&&s1.lossPct===0&&s1.mos>4.2,'RTP bidirectionnel, MOS>4.2');
const rtp=sim.captures.filter(r=>{const p=NS.Codec.parse(r.bytes,false); return p.rtp;}); ok(rtp.length>500,'trames RTP capturées'); const pr=NS.Codec.parse(rtp[0].bytes,false); ok(pr.eth.vlan&&pr.eth.vlan.vid===20&&pr.eth.vlan.pcp===5&&pr.ip.tos===0xb8,'RTP : VLAN 20, CoS 5, DSCP EF');
const sip=sim.captures.filter(r=>NS.Codec.parse(r.bytes,false).sip); ok(sip.length>8,'SIP capturé'); const sp=NS.Codec.parse(sip[0].bytes,false); ok(sp.eth.vlan.pcp===3&&sp.ip.tos===0x60,'SIP : CoS 3, DSCP CS3');
T1.voip.hangup(); sim.runFor(2000); ok(!T1.voip.cur&&!T2.voip.cur,'raccroché des deux côtés'); console.log(P.cdr,P.log.slice(-3)); ok(P.cdr.length===1&&P.cdr[0].disp==='ANSWERED','CDR PBX');
// PC derrière le téléphone dans VLAN data
PC.applyIp(PC.ifaceList()[0].name,{ip:'192.168.10.50',mask:'24'}); const PC2=createDevice(sim,'pc-win',{name:'PC2'}); sim.connect(PC2.ports[0],SW.findPort('fa0/5')); cfg(sim,SW,['interface fa0/5','switchport mode access','switchport access vlan 10','exit']); PC2.applyIp(PC2.ifaceList()[0].name,{ip:'192.168.10.51',mask:'24'}); sim.runFor(35000);
let r=[],d=false; NS.tools.pingSeries(PC,IP.parse('192.168.10.51'),{count:3},x=>r.push(x.type),()=>{d=true}); sim.runUntil(()=>d,60000); ok(/reply/.test(r.join(' ')),'PC derrière le téléphone joint PC2 (VLAN data) : '+r.join(' '));
// occupé / injoignable
T2.voip.call('1001'); sim.runFor(8000); T1.voip.call('1002'); sim.runFor(1000); T3.voip.configure({ext:'1003',secret:'good'}); 
process.exit(bad?1:0);
