const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const {IP6,Codec,tools}=NS;
let bad=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
const sim=new Sim(); const R1=createDevice(sim,'r-2911',{name:'R1'}), R2=createDevice(sim,'r-2911',{name:'R2'}), S1=createDevice(sim,'sw-2960',{name:'S1'}), S2=createDevice(sim,'sw-2960',{name:'S2'});
const H1=createDevice(sim,'pc-linux',{name:'H1'}), H2=createDevice(sim,'pc-win',{name:'H2'});
sim.connect(H1.ports[0],S1.findPort('fa0/1')); sim.connect(R1.findPort('gi0/0'),S1.findPort('fa0/2')); sim.connect(R1.findPort('gi0/1'),R2.findPort('gi0/1')); sim.connect(R2.findPort('gi0/0'),S2.findPort('fa0/2')); sim.connect(H2.ports[0],S2.findPort('fa0/1'));
cli(sim,R1,['enable','conf t','hostname R1','ipv6 unicast-routing','interface gi0/0','ipv6 address 2001:db8:1::1/64','no shutdown','exit','interface gi0/1','ipv6 address 2001:db8:12::1/64','no shutdown','exit','ipv6 route 2001:db8:2::/64 2001:db8:12::2','end']);
cli(sim,R2,['enable','conf t','ipv6 unicast-routing','interface gi0/1','ipv6 address 2001:db8:12::2/64','no shutdown','exit','interface gi0/0','ipv6 address 2001:db8:2::/64 eui-64','no shutdown','exit','ipv6 route ::/0 GigabitEthernet0/1 FE80::1','ipv6 route 2001:db8:1::/64 2001:db8:12::1','end']);
sim.runFor(4000);
let o=cli(sim,R1,['enable','show ipv6 interface brief','show ipv6 route','show ipv6 interface gi0/0']); console.log(o);
ok(/FE80::/.test(o)&&/2001:DB8:1::1/.test(o)&&/S {3}2001:DB8:2::\/64 \[1\/0\]/.test(o)&&/via 2001:DB8:12::2/.test(o)&&/L {3}FF00::\/8/.test(o),'show ipv6 interface brief / route');
const h1=H1.mainIface.v6.addrs.find(a=>a.kind==='slaac'); const h2=H2.mainIface.v6.addrs.find(a=>a.kind==='slaac');
ok(h1&&h2,'SLAAC sur les deux hôtes');
o=cli(sim,R1,['enable','ping ipv6 '+IP6.str(h1.addr)]); console.log(o); ok(/!!!!!/.test(o),'ping ipv6 R1→H1');
o=cli(sim,R1,['enable','ping '+IP6.str(h2.addr)+' repeat 3','traceroute ipv6 '+IP6.str(h2.addr)]); console.log(o); ok(/Success rate is 100 percent \(3\/3\)/.test(o),'ping R1→H2 via R2');
o=cli(sim,R1,['enable','show ipv6 neighbors']); console.log(o); ok(/REACH|STALE/.test(o),'show ipv6 neighbors');
// config aller-retour
const cfg=R2.cliText(true); console.log(cfg.split('\n').filter(l=>/ipv6/.test(l)).join('\n'));
ok(/ipv6 unicast-routing/.test(cfg)&&/ipv6 address 2001:DB8:2::\/64 eui-64/.test(cfg)&&/ipv6 route ::\/0 GigabitEthernet0\/1 FE80::1/.test(cfg),'running-config IPv6');
R2.cliReset(); ok(!R2.ip6.routing&&R2.ip6.statics.length===0,'reset'); R2.cliRestore(cfg); sim.runFor(3000);
ok(R2.ip6.routing&&R2.ip6.statics.length===2&&R2.ifaceByName('gi0/0').v6.addrs.some(a=>a.eui&&a.kind==='manual'),'restauration');
o=cli(sim,R1,['enable','ping ipv6 '+IP6.str(h2.addr)]); ok(/!!!!!/.test(o),'ping OK après restauration');
// DAD off + ra suppress
cli(sim,R1,['enable','conf t','interface gi0/0','ipv6 nd ra suppress all','ipv6 nd managed-config-flag','end']); console.log(cli(sim,R1,['enable','show running-config']).split('\n').filter(l=>/nd/.test(l)).join('\n'));
console.log('bad',bad); process.exit(bad?1:0);
