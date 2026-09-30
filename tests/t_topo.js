const {NS,Sim,createDevice,IP,cli}=require('./helpers');
function build(){
 const sim=new Sim();const c=(n,m)=>createDevice(sim,m,{name:n,x:10,y:20});
 const r=c('R1','r-1941'),pc=c('PC1','pc-win'),pc2=c('PC2','pc-win'),sw=c('SW1','sw-2960'),srv=c('SRV','srv-linux');
 sim.connect(pc.ports[0],sw.findPort('fa0/1'));sim.connect(pc2.ports[0],sw.findPort('fa0/2'));sim.connect(srv.ports[0],sw.findPort('fa0/3'));sim.connect(sw.findPort('gi0/1'),r.findPort('gi0/0'));
 cli(sim,r,'enable\nconf t\ninterface gi0/0\nip address 10.0.0.1 255.255.255.0\nno shutdown\nend\nwr'.split('\n'));
 cli(sim,sw,'enable\nconf t\nvlan 10\nname X\ninterface fa0/1\nswitchport access vlan 10\nend'.split('\n'));
 pc.applyIp('Ethernet0',{ip:'10.0.0.2',mask:'24'});pc.setGateway('10.0.0.1');pc2.applyIp('Ethernet0',{dhcp:false,ip:'10.0.0.3',mask:'24'});
 srv.applyIp('ens33',{ip:'10.0.0.10',mask:'24'});srv.httpd.start();srv.dnsd.enabled=true;srv.dnsd.records.push({name:'www.test.fr',type:'A',data:'10.0.0.10'});srv.dnsd.start();
 return sim;}
const sim=build();sim.runFor(3000);
const j=JSON.parse(JSON.stringify(NS.saveTopology(sim)));
const sim2=new Sim();NS.loadTopology(sim2,j);sim2.runFor(3000);
const g=(s,n)=>Array.from(s.devices.values()).find(d=>d.name===n);
console.log('devices',sim2.devices.size,'links',sim2.links.length);
const pc=g(sim2,'PC2');let out='',dn=false;const s=pc.newSession();
s.exec('ping 10.0.0.10',{print:t=>out+=t,done:()=>dn=true});sim2.runUntil(()=>dn,20000);console.log(/perdus = 0/.test(out)?'PASS ping après reload':'FAIL '+out);
const r2=cli(sim2,g(sim2,'R1'),'enable\nshow ip interface brief'.split('\n'));console.log(/10.0.0.1/.test(r2)?'PASS routeur':'FAIL '+r2);
const sw2=cli(sim2,g(sim2,'SW1'),'enable\nshow vlan brief'.split('\n'));console.log(/VLAN0010|10 +X/.test(sw2)?'PASS vlan':'FAIL '+sw2);
out='';dn=false;s.exec('nslookup www.test.fr 10.0.0.10',{print:t=>out+=t,done:()=>dn=true});sim2.runUntil(()=>dn,20000);console.log(/10\.0\.0\.10/.test(out)&&/www/.test(out)?'PASS dns':'FAIL '+out);
