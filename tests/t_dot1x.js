const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const A=NS.Analyzer; const {Codec}=NS;
let bad=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
function ping(sim,n,dst,count){ let r=[],done=false; NS.tools.pingSeries(n,IP.parse(dst),{count:count||3},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,60000); return r.join(' '); }
const cfg=(sim,d,lines)=>cli(sim,d,['enable','conf t'].concat(lines,['end']));
function build(o){
  o=o||{}; const sim=new Sim(); sim.opts.stpFast=false;
  const SW=createDevice(sim,'sw-2960',{name:'SW1'}), SRV=createDevice(sim,'srv-linux',{name:'RADIUS'}), P1=createDevice(sim,'pc-win',{name:'PC1'}), P2=createDevice(sim,'pc-linux',{name:'PC2'}), P3=createDevice(sim,'pc-win',{name:'PC3'});
  sim.connect(P1.ports[0],SW.findPort('fa0/1')); sim.connect(P2.ports[0],SW.findPort('fa0/2')); sim.connect(P3.ports[0],SW.findPort('fa0/3')); sim.connect(SRV.ports[0],SW.findPort('fa0/24'));
  SRV.applyIp(SRV.ifaceList()[0].name,{ip:'192.168.1.5',mask:'24'}); P1.applyIp('Ethernet0',{ip:'192.168.1.10',mask:'24'}); P2.applyIp(P2.ifaceList()[0].name,{ip:'192.168.1.11',mask:'24'}); P3.applyIp('Ethernet0',{ip:'192.168.10.30',mask:'24'});
  cfg(sim,SW,['vlan 10','name EMPLOYES','vlan 20','name INVITES','exit','interface vlan 1','ip address 192.168.1.2 255.255.255.0','no shutdown','exit','interface fa0/3','switchport mode access','switchport access vlan 10','exit',
    'aaa new-model','radius server RAD','address ipv4 192.168.1.5 auth-port 1812 acct-port 1813','key '+(o.key||'SECRET'),'exit','aaa authentication dot1x default group radius','aaa authorization network default group radius','dot1x system-auth-control',
    'interface fa0/1','switchport mode access','authentication port-control auto','dot1x pae authenticator','dot1x timeout tx-period 5','exit']);
  const R=SRV.radius; R.startSrv(); R.addClient(IP.parse('192.168.1.2'),0xFFFFFFFF,'SECRET','SW1'); R.addUser('alice','Passw0rd',{vlan:10}); R.addUser('bob','B0bpass'); R.addUser('aa:bb:cc:00:00:01'.replace(/:/g,''),'aabbcc000001',{vlan:10});
  sim.runFor(60000); return {sim,SW,SRV,P1,P2,P3,R};
}
// ---- A. test aaa (PAP)
{ const {sim,SW,R}=build();
  let o=cli(sim,SW,['enable','test aaa group radius alice Passw0rd new-code']); ok(/successfully authenticated/.test(o),'test aaa : bon mot de passe accepté');
  o=cli(sim,SW,['enable','test aaa group radius alice mauvais new-code']); ok(/rejected/.test(o),'test aaa : mauvais mot de passe rejeté');
  console.log(R.authLog()); console.log(cli(sim,SW,['enable','show aaa servers']));
  const b=build({key:'AUTRE'}); o=cli(b.sim,b.SW,['enable','test aaa group radius alice Passw0rd new-code']); ok(/not responding/.test(o),'clé partagée différente : pas de réponse'); console.log(b.R.authLog());
}
// ---- B. EAP-MD5 / PEAP
for (const meth of ['md5','peap']) {
  const {sim,SW,P1,R}=build(); ok(!/reply/.test(ping(sim,P1,'192.168.1.5',2)),'['+meth+'] avant authentification : port bloqué');
  P1.dot1x.supSet({user:'bob',pass:'B0bpass',method:meth}); P1.dot1x.supEnable(true); sim.runFor(15000);
  console.log(cli(sim,SW,['enable','show authentication sessions']));
  ok(P1.dot1x.sup.state==='authenticated','['+meth+'] supplicant : authentifié');
  ok(/reply/.test(ping(sim,P1,'192.168.1.5',3)),'['+meth+'] après authentification : le trafic passe');
  ok(/Auth/.test(cli(sim,SW,['enable','show authentication sessions'])),'['+meth+'] show authentication sessions');
  const P2=build(); P2.P1.dot1x.supSet({user:'bob',pass:'FAUX',method:meth}); P2.P1.dot1x.supEnable(true); P2.sim.runFor(15000);
  ok(P2.P1.dot1x.sup.state==='failed'&&!/reply/.test(ping(P2.sim,P2.P1,'192.168.1.5',2)),'['+meth+'] mauvais mot de passe : refus');
  const f=q=>{const fn=A.compile(q);const ctx=A.newCtx();return sim.captures.filter(x=>fn(A.summarize(ctx,x))).length};
  console.log(meth,'eapol',f('eapol'),'radius',f('radius'),'eap',f('eap'));
  if(meth==='peap'){ ok(f('eap')>=10,'PEAP : ≥10 échanges EAP'); }
  console.log(cli(sim,SW,['enable','show logging']).split('\n').filter(l=>/DOT1X|AUTHMGR/.test(l)).join('\n'));
}
// ---- C. VLAN dynamique
{ const {sim,SW,P1,P3}=build(); P1.applyIp('Ethernet0',{ip:'192.168.10.10',mask:'24'});
  P1.dot1x.supSet({user:'alice',pass:'Passw0rd',method:'peap'}); P1.dot1x.supEnable(true); sim.runFor(15000);
  ok(P1.dot1x.sup.state==='authenticated','alice authentifiée'); ok(SW.findPort('fa0/1').dynVlan===10,'VLAN 10 attribué dynamiquement');
  ok(/reply/.test(ping(sim,P1,'192.168.10.30',3)),'alice (VLAN 10 dynamique) joint PC3 (VLAN 10 statique)');
  ok(!/dynVlan|access vlan 10/.test(cli(sim,SW,['enable','show running-config']).split('interface FastEthernet0/1')[1].split('!')[0]),'la config n\'est pas modifiée par le VLAN dynamique');
}
// ---- D. VLAN invité + MAB
{ const {sim,SW,P2,P1}=build(); cfg(sim,SW,['interface fa0/2','switchport mode access','authentication port-control auto','authentication event no-response action authorize vlan 20','dot1x timeout tx-period 3']);
  sim.runFor(20000); ok(SW.findPort('fa0/2').dynVlan===20,'machine sans supplicant -> VLAN invité 20');
  ok(!/reply/.test(ping(sim,P2,'192.168.1.5',2)),'VLAN invité : le serveur (VLAN 1) est inaccessible');
}
{ const {sim,SW,P1,R}=build(); P1.ifaceList()[0].mac; const mac=P1.ifaceList()[0].mac; R.addUser(mac.replace(/:/g,'').toLowerCase(),mac.replace(/:/g,'').toLowerCase(),{vlan:null});
  cfg(sim,SW,['interface fa0/1','authentication order dot1x mab','mab','dot1x timeout tx-period 3']); sim.runFor(1000); SW.findPort('fa0/1').up; 
  const pt=SW.findPort('fa0/1'); SW.dot1x.startPort(pt); ping(sim,P1,'192.168.1.5',1); sim.runFor(30000);
  console.log(cli(sim,SW,['enable','show authentication sessions'])); ok(/mab\s+DATA\s+Auth/.test(cli(sim,SW,['enable','show authentication sessions'])),'MAB : imprimante sans supplicant authentifiée par son adresse MAC');
  ok(/reply/.test(ping(sim,P1,'192.168.1.5',3)),'MAB : trafic autorisé');
}
// ---- E. config aller-retour
{ const {sim,SW}=build(); const c=cli(sim,SW,['enable','show running-config']); console.log(c.split('\n').filter(l=>/aaa|radius|dot1x|authentication|address ipv4|key /.test(l)).join('\n'));
  ok(/aaa new-model/.test(c)&&/radius server RAD/.test(c)&&/authentication port-control auto/.test(c)&&/dot1x system-auth-control/.test(c),'running-config AAA/802.1X');
  SW.cliReset(); ok(!/aaa/.test(cli(sim,SW,['enable','show running-config'])),'reset'); SW.cliRestore(c.split('Current configuration')[1].split('\n').slice(1).join('\n'),true);
  const c2=cli(sim,SW,['enable','show running-config']); ok(c2.replace(/Current configuration : \d+ bytes/,'')===c.replace(/Current configuration : \d+ bytes/,''),'aller-retour config'); }
console.log(bad?'ECHECS '+bad:'OK'); process.exit(bad?1:0);
