const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {tools}=NS;
function pingOK(sim,n,dst,count=2){ let ok=0,done=false; tools.pingSeries(n,IP.parse(dst),{count,interval:200},(r)=>{ if(r.type==='reply') ok++; },()=>{done=true}); sim.runUntil(()=>done,30000); return ok+'/'+count; }
let fails=0; const T=(name,got,exp)=>{ const ok=got===exp; if(!ok) fails++; console.log((ok?'PASS ':'FAIL ')+name+' -> '+got+(ok?'':' (attendu '+exp+')')); };

/* A. VLAN + trunk + router-on-a-stick */
{
 const sim=new Sim(); const c=(n,m)=>createDevice(sim,m,{name:n});
 const sw1=c('SW1','sw-2960'), sw2=c('SW2','sw-2960'), r=c('R1','r-1941');
 const p1=c('PC1','pc-win'),p2=c('PC2','pc-win'),p3=c('PC3','pc-win'),p4=c('PC4','pc-win');
 sim.connect(p1.ports[0],sw1.findPort('fa0/1'));sim.connect(p2.ports[0],sw1.findPort('fa0/2'));
 sim.connect(p3.ports[0],sw2.findPort('fa0/1'));sim.connect(p4.ports[0],sw2.findPort('fa0/2'));
 sim.connect(sw1.findPort('gi0/1'),sw2.findPort('gi0/1')); sim.connect(r.findPort('gi0/0'),sw1.findPort('fa0/24'));
 const swcfg=(isFirst)=>`enable
conf t
vlan 10
name COMPTA
vlan 20
name RH
interface range fa0/1 - 2
switchport mode access
switchport access vlan ${isFirst?10:20}
exit
interface gi0/1
switchport mode trunk
exit
end`;
 cli(sim,sw1,swcfg(true).split('\n')); 
 cli(sim,sw1,['enable','conf t','interface fa0/2','switchport access vlan 20','interface fa0/24','switchport mode trunk','end']);
 cli(sim,sw2,swcfg(true).split('\n')); cli(sim,sw2,['enable','conf t','interface fa0/2','switchport access vlan 20','end']);
 cli(sim,r,`enable
conf t
interface gi0/0
no shutdown
interface gi0/0.10
encapsulation dot1Q 10
ip address 192.168.10.1 255.255.255.0
interface gi0/0.20
encapsulation dot1Q 20
ip address 192.168.20.1 255.255.255.0
end`.split('\n'));
 p1.applyIp('Ethernet0',{ip:'192.168.10.11',mask:'24'});p1.setGateway('192.168.10.1');
 p3.applyIp('Ethernet0',{ip:'192.168.10.13',mask:'24'});p3.setGateway('192.168.10.1');
 p2.applyIp('Ethernet0',{ip:'192.168.20.12',mask:'24'});p2.setGateway('192.168.20.1');
 p4.applyIp('Ethernet0',{ip:'192.168.20.14',mask:'24'});p4.setGateway('192.168.20.1');
 sim.runFor(15000);
 T('VLAN10 PC1->PC3 (trunk)',pingOK(sim,p1,'192.168.10.13'),'2/2');
 T('VLAN20 PC2->PC4',pingOK(sim,p2,'192.168.20.14'),'2/2');
 T('inter-VLAN PC1->PC2 (routeur)',pingOK(sim,p1,'192.168.20.12'),'2/2');
 // isolation: retire routeur gw
 p1.setGateway(''); T('sans passerelle PC1->PC2',pingOK(sim,p1,'192.168.20.12',1),'0/1');
 console.log(cli(sim,sw1,['enable','show vlan brief','show interfaces trunk']));
 console.log(cli(sim,r,['enable','show ip interface brief','show running-config']).slice(-1400));
}
/* B. NAT/PAT + serveur public + HTTP/DNS */
{
 const sim=new Sim(); const c=(n,m)=>createDevice(sim,m,{name:n});
 const sw=c('SW1','sw-2960'), r1=c('R1','r-1941'), isp=c('ISP','inet'), web=c('WEB','srv-linux'), pc=c('PC1','pc-win'), pc2=c('PC2','pc-linux');
 sim.connect(pc.ports[0],sw.findPort('fa0/1'));sim.connect(pc2.ports[0],sw.findPort('fa0/2'));sim.connect(r1.findPort('gi0/0'),sw.findPort('fa0/24'));
 sim.connect(r1.findPort('gi0/1'),isp.findPort('gi0/0')); sim.connect(isp.findPort('gi0/1'),web.ports[0]);
 cli(sim,r1,`enable
conf t
interface gi0/0
ip address 192.168.1.1 255.255.255.0
ip nat inside
no shutdown
interface gi0/1
ip address 203.0.113.2 255.255.255.252
ip nat outside
no shutdown
exit
access-list 1 permit 192.168.1.0 0.0.0.255
ip nat inside source list 1 interface gi0/1 overload
ip route 0.0.0.0 0.0.0.0 203.0.113.1
end`.split('\n'));
 cli(sim,isp,`enable
conf t
interface gi0/0
ip address 203.0.113.1 255.255.255.252
no shutdown
interface gi0/1
ip address 198.51.100.1 255.255.255.0
no shutdown
end`.split('\n'));
 web.applyIp('ens33',{ip:'198.51.100.10',mask:'24'}); web.setGateway('198.51.100.1'); web.httpd.start();
 web.dnsd.records.push({name:'www.exemple.fr',type:'A',data:'198.51.100.10'}); web.dnsd.start();
 pc.applyIp('Ethernet0',{ip:'192.168.1.10',mask:'24'}); pc.setGateway('192.168.1.1'); pc.dnsServers=[IP.parse('198.51.100.10')];
 pc2.applyIp('ens33',{ip:'192.168.1.11',mask:'24'}); pc2.setGateway('192.168.1.1');
 sim.runFor(5000);
 T('PAT ping PC1->WEB',pingOK(sim,pc,'198.51.100.10'),'2/2');
 console.log(cli(sim,pc,['nslookup www.exemple.fr','curl http://www.exemple.fr']));
 console.log(cli(sim,pc2,['curl http://198.51.100.10']));
 console.log(cli(sim,r1,['enable','show ip nat translations','show ip nat statistics']));
 // retour: ISP ne peut pas joindre 192.168.1.10
 T('ISP->192.168.1.10 (privée) impossible',pingOK(sim,isp,'192.168.1.10',1),'0/1');
 // ACL: interdit PC2 (192.168.1.11) vers WEB
 cli(sim,r1,`enable
conf t
ip access-list extended BLOQUE
deny ip host 192.168.1.11 any
permit ip any any
exit
interface gi0/0
ip access-group BLOQUE in
end`.split('\n'));
 T('ACL PC2 bloqué',pingOK(sim,pc2,'198.51.100.10',1),'0/1');
 T('ACL PC1 ok',pingOK(sim,pc,'198.51.100.10',1),'1/1');
 console.log(cli(sim,r1,['enable','show access-lists']));
 console.log(cli(sim,pc2,['ping -c 1 198.51.100.10']));
}
/* C. RIP 3 routeurs */
{
 const sim=new Sim(); const c=(n,m)=>createDevice(sim,m,{name:n});
 const r1=c('R1','r-2911'),r2=c('R2','r-2911'),r3=c('R3','r-2911'); const pa=c('PCA','pc-win'),pb=c('PCB','pc-win');
 sim.connect(pa.ports[0],r1.findPort('gi0/0'));sim.connect(r1.findPort('gi0/1'),r2.findPort('gi0/0'));sim.connect(r2.findPort('gi0/1'),r3.findPort('gi0/0'));sim.connect(r3.findPort('gi0/1'),pb.ports[0]);
 const conf=(r,a)=>cli(sim,r,`enable
conf t
${a.map(([i,ip])=>`interface ${i}\nip address ${ip} 255.255.255.0\nno shutdown\nexit`).join('\n')}
router rip
version 2
no auto-summary
${a.map(([i,ip])=>'network '+ip.replace(/\.\d+$/,'.0')).join('\n')}
end`.split('\n'));
 conf(r1,[['gi0/0','10.1.1.1'],['gi0/1','10.1.2.1']]); conf(r2,[['gi0/0','10.1.2.2'],['gi0/1','10.1.3.2']]); conf(r3,[['gi0/0','10.1.3.3'],['gi0/1','10.1.4.3']]);
 pa.applyIp('Ethernet0',{ip:'10.1.1.10',mask:'24'});pa.setGateway('10.1.1.1');pb.applyIp('Ethernet0',{ip:'10.1.4.10',mask:'24'});pb.setGateway('10.1.4.3');
 sim.runFor(100000);
 T('RIP PCA->PCB',pingOK(sim,pa,'10.1.4.10'),'2/2');
 console.log(cli(sim,r1,['enable','show ip route','show ip protocols']));
}
/* D. STP triangle */
{
 const sim=new Sim(); const c=(n,m)=>createDevice(sim,m,{name:n});
 const a=c('SWA','sw-2960'),b=c('SWB','sw-2960'),d=c('SWC','sw-2960'); const p1=c('PC1','pc-win'),p2=c('PC2','pc-win');
 sim.connect(a.findPort('fa0/1'),b.findPort('fa0/1'));sim.connect(b.findPort('fa0/2'),d.findPort('fa0/2'));sim.connect(d.findPort('fa0/1'),a.findPort('fa0/2'));
 sim.connect(p1.ports[0],a.findPort('fa0/10'));sim.connect(p2.ports[0],d.findPort('fa0/10'));
 p1.applyIp('Ethernet0',{ip:'10.0.0.1',mask:'24'});p2.applyIp('Ethernet0',{ip:'10.0.0.2',mask:'24'});
 sim.runFor(60000);
 const blk=[a,b,d].reduce((n,s)=>n+s.ports.filter(p=>p.stp.state==='blocking').length,0);
 T('STP un port bloqué dans le triangle',String(blk),'1');
 T('STP ping après convergence',pingOK(sim,p1,'10.0.0.2'),'2/2');
 T('pas de tempête',String(sim.halted),'null');
 console.log(cli(sim,a,['enable','show spanning-tree']));
 // sans STP (switch non manageable) -> tempête
 const sim2=new Sim(); const c2=(n,m)=>createDevice(sim2,m,{name:n});
 const x=c2('X','sw-8p'),y=c2('Y','sw-8p'),z=c2('Z','sw-8p'),q1=c2('Q1','pc-win'),q2=c2('Q2','pc-win');
 sim2.connect(x.findPort('p1'),y.findPort('p1'));sim2.connect(y.findPort('p2'),z.findPort('p2'));sim2.connect(z.findPort('p1'),x.findPort('p2'));sim2.connect(q1.ports[0],x.findPort('p5'));sim2.connect(q2.ports[0],z.findPort('p5'));
 q1.applyIp('Ethernet0',{ip:'10.0.0.1',mask:'24'});q2.applyIp('Ethernet0',{ip:'10.0.0.2',mask:'24'});
 tools.pingSeries(q1,IP.parse('10.0.0.2'),{count:1},()=>{},()=>{}); sim2.runFor(2000);
 T('boucle sans STP => tempête détectée',sim2.halted?'oui':'non','oui');
}
/* H. telnet / ssh vers routeur */
{
 const sim=new Sim(); const c=(n,m)=>createDevice(sim,m,{name:n});
 const r=c('R1','r-1941'),pc=c('PC1','pc-win');
 sim.connect(pc.ports[0],r.findPort('gi0/0'));
 cli(sim,r,`enable
conf t
interface gi0/0
ip address 10.0.0.1 255.255.255.0
no shutdown
enable secret cisco
line vty 0 4
password vty123
login
end`.split('\n'));
 pc.applyIp('Ethernet0',{ip:'10.0.0.2',mask:'24'});
 sim.runFor(2000);
 const s=pc.newSession(); let out=''; let dn=false;
 const run=(l)=>{ dn=false; s.exec(l,{print:t=>out+=t,done:()=>dn=true}); sim.runUntil(()=>dn,20000); };
 run('telnet 10.0.0.1'); run('vty123'); run('enable'); run('cisco'); run('show ip interface brief'); run('exit');
 console.log(out);
 const cap=sim.captures.filter(r=>{const p=NS.Codec.parse(r.bytes);return p.telnet}).map(r=>NS.Codec.parse(r.bytes).telnet.data.replace(/\r\n/g,'|')).join(' ');
 T('mot de passe telnet visible en clair',/vty123/.test(cap)?'oui':'non','oui');
 const s2=pc.newSession(); out=''; let dn2=false; const run2=(l)=>{ dn2=false; s2.exec(l,{print:t=>out+=t,done:()=>dn2=true}); sim.runUntil(()=>dn2,20000); sim.runFor(50); };
 run2('ssh 10.0.0.1'); run2('vty123'); run2('show clock'); 
 console.log(JSON.stringify(out.slice(0,300)));
 console.log('p22',sim.captures.filter(r=>{const p=NS.Codec.parse(r.bytes);return p.tcp&&(p.tcp.dport==22||p.tcp.sport==22)}).length, sim.halted, sim.now);
 const cap2=sim.captures.filter(r=>{const p=NS.Codec.parse(r.bytes);return p.ssh&&p.ssh.encrypted}).length;
 T('ssh chiffré',cap2>0?'oui':'non','oui');
}
console.log(fails?('ECHECS: '+fails):'TOUS OK');
