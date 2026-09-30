const {NS,Sim,createDevice,IP,cli}=require('./helpers'); let bad=0; const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++;};
function ping(sim,n,dst,count){ let r=[],done=false; NS.tools.pingSeries(n,IP.parse(dst),{count:count||3},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,60000); return r.join(' '); }
function aos(sim,d,lines){ const s=d.newSession(); let out=''; lines.forEach(l=>{ let done=false; s.exec(l,{print:t=>out+=t,done:()=>done=true,clear(){}}); sim.runUntil(()=>done,60000); }); return out; }
const sim=new Sim(); sim.opts.stpFast=true;
const OS=createDevice(sim,'sw-os6400',{name:'OS6400'}), A=createDevice(sim,'pc-win',{name:'PC10'}), B=createDevice(sim,'pc-linux',{name:'PC20'}), T=createDevice(sim,'ipphone',{name:'TEL'});
ok(OS.ports.length===48&&OS.ports[0].name==='1/1','48 ports 1/1..1/48'); ok(NS.CATALOG['sw-os6400'].ok===true,'fiche marquée vérifiée');
sim.connect(A.ports[0],OS.findPort('1/1')); sim.connect(B.ports[0],OS.findPort('1/2')); sim.connect(T.findPort('Internet'),OS.findPort('1/3'));
let o=aos(sim,OS,['vlan 10 name "COMPTA"','vlan 20 name "LABO"','vlan 10 port default 1/1','vlan 20 port default 1/2','ip interface "v10" address 192.168.10.1 mask 255.255.255.0 vlan 10','ip interface "v20" address 192.168.20.1 mask 255.255.255.0 vlan 20','show vlan','show ip interface']);
console.log(o); ok(/COMPTA/.test(o)&&/v10\s+192\.168\.10\.1/.test(o),'vlan + ip interface');
A.applyIp(A.ifaceList()[0].name,{ip:'192.168.10.10',mask:'24',gw:'192.168.10.1'}); A.setGateway('192.168.10.1'); B.applyIp(B.ifaceList()[0].name,{ip:'192.168.20.10',mask:'24'}); B.setGateway('192.168.20.1'); sim.runFor(40000);
ok(/reply/.test(ping(sim,A,'192.168.20.10',3)),'routage inter-VLAN 10 -> 20');
o=aos(sim,OS,['show ip routes','show mac-learning','show spantree','show interfaces status']); console.log(o.split('\n').slice(0,40).join('\n'));
ok(/192\.168\.10\.0/.test(o)&&/LOCAL/.test(o),'show ip routes'); ok(/learned/.test(o),'show mac-learning');
o=aos(sim,OS,['vlan 30 name "VOIX"','vlan 30 802.1q 1/48','show 802.1q 1/48','show vlan 30 port','spantree vlan 1 priority 4096','spantree protocol rstp','show spantree','lacp linkagg 1 size 2 admin state enable','lacp agg 1/10 actor admin key 1','lacp agg 1/11 actor admin key 1','show linkagg','lanpower start 1','show lanpower 1','system name CORE','show system']);
console.log(o); ok(/tagged/.test(o),'802.1q tagged'); ok(/RSTP/.test(o),'spantree RSTP'); ok(/ENABLED/.test(o),'linkagg'); ok(/Powered On/.test(o),'PoE alimente le téléphone'); 
// sauvegarde/restauration
const j=JSON.parse(JSON.stringify(OS.serialize())); const sim2=new Sim(); const O2=createDevice(sim2,'sw-os6400',{name:'X'}); O2.restore(j);
const txt=O2.cliText(); ok(/vlan 10 port default 1\/1/.test(txt)&&/vlan 30 802.1q 1\/48/.test(txt)&&/ip interface v10 address 192.168.10.1/.test(txt)&&/spantree protocol rstp/.test(txt),'aller-retour configuration AOS'); console.log(txt);
aos(sim,OS,['lanpower stop 1/3']); sim.runFor(1000); ok(!T.findPort('Internet').up,'lanpower stop : le téléphone perd son alimentation (lien coupé)'); aos(sim,OS,['lanpower start 1/3']); sim.runFor(1000); ok(T.findPort('Internet').up,'lanpower start : retour du lien');
process.exit(bad?1:0);
