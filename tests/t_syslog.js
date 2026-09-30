const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {mib,Codec}=NS; let bad=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
const sim=new Sim(); const cap=[]; sim.on&&0;
const R=createDevice(sim,'r-2911',{name:'R1'}), S=createDevice(sim,'sw-2960',{name:'SW1'}), M=createDevice(sim,'srv-linux',{name:'NMS'}), P=createDevice(sim,'pc-win',{name:'PC1'});
sim.connect(M.ports[0],S.findPort('fa0/2')); sim.connect(R.findPort('gi0/0'),S.findPort('fa0/1')); const lp=sim.connect(P.ports[0],S.findPort('fa0/3'));
M.applyIp('ens33',{ip:'10.0.0.50',mask:'24'}); M.mgmt.startSyslogd(); M.mgmt.startTrapd();
let out=cli(sim,R,['enable','conf t','interface gi0/0','ip address 10.0.0.1 255.255.255.0','no shutdown','exit',
 'snmp-server community public RO','snmp-server community private RW','snmp-server location Salle B12','snmp-server contact admin@lycee.fr',
 'snmp-server host 10.0.0.50 version 2c public','snmp-server enable traps','logging host 10.0.0.50','logging trap informational','logging source-interface gi0/0','service sequence-numbers','end','show snmp','show snmp community','show snmp host']);
console.log(out.slice(-1200));
ok(R.mgmt.snmp.comms.size===2&&R.mgmt.lg.hosts.length===1&&R.mgmt.snmp.hosts.length===1,'config appliquée');
sim.runFor(3000);
// S: syslog & trap sur SW1
cli(sim,S,['enable','conf t','interface vlan 1','ip address 10.0.0.2 255.255.255.0','no shutdown','exit','snmp-server community public RO','snmp-server host 10.0.0.50 version 1 public','snmp-server enable traps','logging host 10.0.0.50','end']); sim.runFor(3000);
const n0=M.mgmt.syslogd.entries.length, t0=M.mgmt.trapd.entries.length;
sim.disconnect(lp); sim.runFor(2000);
console.log(M.mgmt.fileSyslog()); console.log(M.mgmt.trapd.entries.map(e=>M.mgmt.trapLine(e)).join('\n'));
ok(M.mgmt.syslogd.entries.length>n0,'syslog reçu ('+(M.mgmt.syslogd.entries.length-n0)+')');
ok(M.mgmt.syslogd.entries.some(e=>/%LINK-3-UPDOWN: Interface FastEthernet0\/3, changed state to down/.test(e.msg)),'message LINK-3-UPDOWN');
ok(M.mgmt.trapd.entries.length>t0&&M.mgmt.trapd.entries.some(e=>e.ver===0&&/5\.3$/.test(e.trapOid)),'trap v1 linkDown reçue');
// v2c trap from R : shut gi0/1 ne fait rien ; test avec no shutdown / shutdown sur gi0/1 connecté à PC
const P2=createDevice(sim,'pc-win',{name:'PC2'}); sim.connect(P2.ports[0],R.findPort('gi0/1')); cli(sim,R,['enable','conf t','interface gi0/1','no shutdown','end']); sim.runFor(1500);
cli(sim,R,['enable','conf t','interface gi0/1','shutdown','end']); sim.runFor(1500);
ok(M.mgmt.trapd.entries.some(e=>e.ver===1&&e.type==='snmpV2-trap'&&/5\.3$/.test(e.trapOid)),'trap v2c linkDown reçue');
console.log(M.mgmt.fileSyslog().split('\n').slice(-6).join('\n'));
ok(M.mgmt.syslogd.entries.some(e=>/%SYS-5-CONFIG_I/.test(e.msg)),'%SYS-5-CONFIG_I');
console.log(cli(sim,R,['enable','show logging']).slice(-900));
// running-config aller-retour
const cfg=R.cliText(true); console.log(cfg.split('\n').filter(l=>/snmp|logging|service seq/.test(l)).join('\n'));
R.cliReset(); ok(R.mgmt.snmp.comms.size===0,'reset'); R.cliRestore(cfg); ok(R.mgmt.snmp.comms.size===2&&R.mgmt.lg.hosts.length===1&&R.mgmt.lg.seq&&R.mgmt.snmp.hosts[0].ver===1&&R.mgmt.snmp.location==='Salle B12','restauration');
// analyseur : trames décodées
const caps=sim.captures.filter(c=>{try{const p=Codec.parse(c.bytes||c.data,false);return p.syslog||p.snmp}catch(e){return false}});
console.log('captures snmp/syslog',caps.length, Object.keys(sim.captures[0]||{}));
console.log('bad',bad); process.exit(bad?1:0);
