const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const A=NS.Analyzer;
let bad=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
const sim=new Sim(); const R=createDevice(sim,'r-2911',{name:'R1'}), S=createDevice(sim,'sw-2960',{name:'SW1'}), M=createDevice(sim,'srv-linux',{name:'NMS'}), P=createDevice(sim,'pc-linux',{name:'LX'});
sim.connect(M.ports[0],S.findPort('fa0/2')); sim.connect(R.findPort('gi0/0'),S.findPort('fa0/1')); sim.connect(P.ports[0],S.findPort('fa0/3'));
M.applyIp('ens33',{ip:'10.0.0.50',mask:'24'}); P.applyIp('ens33',{ip:'10.0.0.60',mask:'24'});
cli(sim,R,['enable','conf t','interface gi0/0','ip address 10.0.0.1 255.255.255.0','no shutdown','exit','snmp-server community public RO','snmp-server community private RW','snmp-server location Salle B12','end']); sim.runFor(3000);
const sh=M.newSession(); let out=''; let dn;
const run=l=>{out='';dn=false;sh.exec(l,{print:t=>out+=t,done:()=>dn=true});sim.runUntil(()=>dn,60000);return out;};
console.log(run('snmpget -v2c -c public 10.0.0.1 sysName.0 sysLocation.0 sysUpTime.0'));
console.log(run('snmpget -v2c -c public -On 10.0.0.1 1.3.6.1.2.1.1.5.0'));
console.log(run('snmpwalk -v2c -c public 10.0.0.1 ifDescr'));
console.log(run('snmpwalk -v1 -c public 10.0.0.1 ifOperStatus'));
console.log(run('snmpget -v2c -c faux 10.0.0.1 sysName.0'));
console.log(run('snmpset -v2c -c public 10.0.0.1 sysLocation.0 s "X"'));
console.log(run('snmpset -v2c -c private 10.0.0.1 sysLocation.0 s "Salle C3"'));
ok(R.mgmt.snmp.location==='Salle C3','snmpset applique');
console.log(run('snmpwalk -v2c -c public 10.0.0.1 ipAdEntAddr'));
console.log(run('snmpwalk -v2c -c public 10.0.0.1 ipRouteDest'));
console.log(run('snmpwalk -v2c -c public 10.0.0.1 system').split('\n').slice(0,3).join('\n'));
// serveur syslog + logger
console.log(run('sudo systemctl start rsyslog')); console.log(run('sudo systemctl start snmpd'));
const s2=P.newSession(); out=''; dn=false; s2.exec('logger -n 10.0.0.50 -p local0.warning -t app "Test depuis LX"',{print:t=>out+=t,done:()=>dn=true}); sim.runUntil(()=>dn,5000); sim.runFor(500);
console.log(run('tail -n 3 /var/log/syslog')); ok(/Test depuis LX/.test(out),'logger -> rsyslog');
console.log(run('snmpwalk -v2c -c public 10.0.0.50 ifDescr'));
// mac table via BRIDGE-MIB sur le switch
S.mgmt.setCommunity('public','ro'); cli(sim,S,['enable','conf t','interface vlan 1','ip address 10.0.0.2 255.255.255.0','no shutdown','end']); sim.runFor(2000);
sim.captures.length=sim.captures.length; run('ping -c 1 10.0.0.60');
console.log(run('snmpwalk -v2c -c public 10.0.0.2 dot1dTpFdbPort'));
// analyseur
const ctx=A.newCtx(); const f=q=>{const fn=A.compile(q);return sim.captures.filter(r=>fn(A.summarize(ctx,r))).length};
console.log('snmp:',f('snmp'),'syslog:',f('syslog'),'get-bulk:',f('snmp.name == "1.3.6.1.2.1.2.2.1.2"'),'community:',f('snmp.community == "faux"'));
ok(f('snmp')>10&&f('syslog')>=1,'filtres analyseur');
sim.captures.filter(r=>/snmp|syslog/.test(A.summarize(ctx,r).proto.toLowerCase())).slice(0,6).forEach(r=>{const x=A.summarize(ctx,r);console.log(x.no,x.proto,x.src,x.dst,x.info.slice(0,90))});
const rec=sim.captures.find(r=>A.summarize(ctx,r).proto==='SNMP'); const tree=NS.Codec.parse(rec.bytes,true).tree; console.log(JSON.stringify(tree.map(n=>n.text||n.label||n.name)).slice(0,300));
console.log('bad',bad); process.exit(bad?1:0);
