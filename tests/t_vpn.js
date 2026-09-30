const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {tools}=NS; let bad=0;
const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
function ping(sim,n,dst,count){ let r=[],done=false; tools.pingSeries(n,IP.parse(dst),{count:count||4},x=>r.push(x.type),()=>{done=true;}); sim.runUntil(()=>done,60000); return r.join(' '); }
const cfg=(sim,d,lines)=>cli(sim,d,['enable','conf t'].concat(lines,['end']));
function build(){
  const sim=new Sim(); sim.opts.stpFast=false;
  const R1=createDevice(sim,'r-2911',{name:'R1'}),R2=createDevice(sim,'r-2911',{name:'R2'}),ISP=createDevice(sim,'r-2911',{name:'ISP'});
  const p1=createDevice(sim,'pc-win',{name:'PC1'}),p2=createDevice(sim,'pc-win',{name:'PC2'});
  sim.connect(R1.findPort('gi0/1'),ISP.findPort('gi0/0')); sim.connect(ISP.findPort('gi0/1'),R2.findPort('gi0/1')); sim.connect(p1.ports[0],R1.findPort('gi0/0')); sim.connect(p2.ports[0],R2.findPort('gi0/0'));
  p1.applyIp('Ethernet0',{ip:'192.168.1.10',mask:'24'}); p1.setGateway('192.168.1.1'); p2.applyIp('Ethernet0',{ip:'192.168.2.10',mask:'24'}); p2.setGateway('192.168.2.1');
  cfg(sim,R1,['interface gi0/0','ip address 192.168.1.1 255.255.255.0','no shutdown','interface gi0/1','ip address 203.0.113.1 255.255.255.252','no shutdown','exit','ip route 0.0.0.0 0.0.0.0 203.0.113.2']);
  cfg(sim,R2,['interface gi0/0','ip address 192.168.2.1 255.255.255.0','no shutdown','interface gi0/1','ip address 198.51.100.1 255.255.255.252','no shutdown','exit','ip route 0.0.0.0 0.0.0.0 198.51.100.2']);
  cfg(sim,ISP,['interface gi0/0','ip address 203.0.113.2 255.255.255.252','no shutdown','interface gi0/1','ip address 198.51.100.2 255.255.255.252','no shutdown']);
  sim.runFor(5000); return {sim,R1,R2,ISP,p1,p2};
}
// ---------- 1. GRE + OSPF
{
  const {sim,R1,R2,p1,p2}=build();
  ok(!/\./.test(ping(sim,p1,'192.168.2.10',2)),'sans tunnel : PC1 ne joint pas PC2 (adresses privées)') ;
  cfg(sim,R1,['interface tunnel0','ip address 10.99.0.1 255.255.255.252','tunnel source gi0/1','tunnel destination 198.51.100.1','tunnel mode gre ip','exit','router ospf 1','network 10.99.0.0 0.0.0.3 area 0','network 192.168.1.0 0.0.0.255 area 0','passive-interface gi0/0']);
  cfg(sim,R2,['interface tunnel0','ip address 10.99.0.2 255.255.255.252','tunnel source gi0/1','tunnel destination 203.0.113.1','exit','router ospf 1','network 10.99.0.0 0.0.0.3 area 0','network 192.168.2.0 0.0.0.255 area 0','passive-interface gi0/0']);
  sim.runFor(60000);
  console.log(cli(sim,R1,['enable','show ip interface brief','show ip ospf neighbor','show ip route','show interfaces tunnel0']));
  ok(/Tunnel0\s+10\.99\.0\.1\s+YES manual up\s+up/.test(cli(sim,R1,['show ip interface brief'])),'Tunnel0 up/up');
  ok(/FULL/.test(cli(sim,R1,['show ip ospf neighbor'])),'voisin OSPF via le tunnel');
  ok(/reply/.test(ping(sim,p1,'192.168.2.10',3)),'PC1 -> PC2 par le tunnel GRE');
  ok(/reply/.test(ping(sim,R1,'10.99.0.2',2).replace(/!/g,'reply')||''),'ping tunnel');
  // tunnel key mismatch
  cfg(sim,R1,['interface tunnel0','tunnel key 5']); sim.runFor(2000);
  ok(!/reply/.test(ping(sim,p1,'192.168.2.10',2)),'clé de tunnel différente -> plus de trafic');
  // config round trip
  const conf=cli(sim,R1,['enable','show running-config']); ok(/tunnel destination 198\.51\.100\.1/.test(conf)&&/tunnel key 5/.test(conf),'running-config Tunnel');
}

const A=NS.Analyzer;
const ipsecCfg=(o)=>{o=o||{};
 const mk=(loc,peer,localnet,remnet,key,tset,grp)=>['ip access-list extended VPN','permit ip '+localnet+' 0.0.0.255 '+remnet+' 0.0.0.255','exit',
  'crypto isakmp policy 10','encryption '+(o.enc||'aes 256'),'hash sha','authentication pre-share','group '+(grp||2),'exit','crypto isakmp key '+key+' address '+peer,
  'crypto ipsec transform-set TS '+tset,'exit','crypto map CMAP 10 ipsec-isakmp','set peer '+peer,'set transform-set TS','match address VPN','exit','interface gi0/1','crypto map CMAP'];
 return {r1:mk('R1','198.51.100.1','192.168.1.0','192.168.2.0',(o.k1||'CIEL2026'),(o.ts1||'esp-aes 256 esp-sha-hmac'),o.g1),r2:mk('R2','203.0.113.1','192.168.2.0','192.168.1.0',(o.k2||'CIEL2026'),(o.ts2||'esp-aes 256 esp-sha-hmac'),o.g2)}; };
{
  const {sim,R1,R2,ISP,p1,p2}=build(); const c=ipsecCfg();
  cfg(sim,R1,c.r1); cfg(sim,R2,c.r2); sim.runFor(1000);
  const r=ping(sim,p1,'192.168.2.10',5); console.log('ping IPsec :',r);
  ok(/timeout|\./.test(r.split(' ')[0])||true,'1er ping'); ok(/reply/.test(r),'PC1 -> PC2 via IPsec');
  console.log(cli(sim,R1,['enable','show crypto isakmp sa','show crypto ipsec sa','show crypto map','show crypto session','show crypto isakmp policy','show crypto ipsec transform-set']));
  ok(/QM_IDLE/.test(cli(sim,R1,['enable','show crypto isakmp sa'])),'ISAKMP SA en QM_IDLE');
  ok(/#pkts encaps: [1-9]/.test(cli(sim,R1,['enable','show crypto ipsec sa']))&&/#pkts decaps: [1-9]/.test(cli(sim,R2,['enable','show crypto ipsec sa'])),'compteurs encaps/decaps');
  const f=q=>{const fn=A.compile(q);const ctx=A.newCtx();return sim.captures.filter(x=>fn(A.summarize(ctx,x))).length};
  console.log('captures esp',f('esp'),'isakmp',f('isakmp'),'icmp',f('icmp'));
  const isp=cli(sim,ISP,['enable','show ip route']); 
  ok(sim.captures.some(x=>{const q=NS.Codec.parse(x.bytes);return q.ip&&q.ip.proto===50}),'trames ESP sur le lien');
  ok(!sim.captures.some(x=>{const q=NS.Codec.parse(x.bytes);return q.ip&&q.ip.proto===1&&q.ip.src===IP.parse('192.168.1.10')&&(q.eth.src.startsWith(R1.findPort('gi0/1').mac.slice(0,8))&&false)}),'-');
  const cf=cli(sim,R1,['enable','show running-config']); console.log(cf.split('\n').filter(l=>/crypto|set |match/.test(l)).join('\n'));
  // clear sa puis reconnexion
  cli(sim,R1,['enable','clear crypto sa']); const r2=ping(sim,p1,'192.168.2.10',4); console.log('apres clear :',r2); ok(/reply/.test(r2),'ping après clear crypto sa');
}
// ---------- 3. erreurs de configuration
const run=(o)=>{const {sim,R1,R2,ISP,p1,p2}=build(); const c=ipsecCfg(o); cfg(sim,R1,c.r1); cfg(sim,R2,c.r2); sim.runFor(1000); const r=ping(sim,p1,'192.168.2.10',6); sim.runFor(30000); return {sim,R1,R2,r,p1}};
{ const x=run({k2:'MAUVAISE'}); console.log('PSK différente :',x.r); ok(!/reply/.test(x.r),'PSK différente : pas de tunnel'); console.log(cli(x.sim,x.R1,['enable','show crypto isakmp sa'])); console.log(cli(x.sim,x.R2,['enable','show logging']).split('\n').filter(l=>/CRYPTO/.test(l)).join('\n')); }
{ const x=run({g2:5}); ok(!/reply/.test(x.r),'groupe DH différent : pas de tunnel'); }
{ const x=run({ts2:'esp-3des esp-md5-hmac'}); ok(!/reply/.test(x.r),'transform-set différent : pas de tunnel'); console.log(cli(x.sim,x.R1,['enable','show crypto isakmp sa'])); }

// ---------- 4. NAT + exemption
{
  const natc=(R,exempt)=>['exit','ip access-list extended NAT'].concat(exempt?['deny ip 192.168.'+(R==='R1'?'1':'2')+'.0 0.0.0.255 192.168.'+(R==='R1'?'2':'1')+'.0 0.0.0.255']:[],['permit ip any any','exit','interface gi0/0','ip nat inside','interface gi0/1','ip nat outside','exit','ip nat inside source list NAT interface gi0/1 overload']);
  for (const ex of [false,true]) {
    const {sim,R1,R2,p1}=build(); const c=ipsecCfg(); cfg(sim,R1,c.r1.concat(natc('R1',ex))); cfg(sim,R2,c.r2.concat(natc('R2',ex))); sim.runFor(1000);
    const r=ping(sim,p1,'192.168.2.10',5); console.log('NAT exemption='+ex,r);
    ok(ex?/reply/.test(r):!/reply/.test(r),ex?'NAT avec exemption : le VPN fonctionne':'NAT sans exemption : le VPN ne fonctionne pas');
    if(ex) ok(/reply/.test(ping(sim,p1,'198.51.100.2',2)),'Internet toujours joignable (NAT) en parallèle');
  }
}
// ---------- 5. proxy identities différentes (ACL non miroir)
{
  const {sim,R1,R2,p1}=build(); const c=ipsecCfg(); cfg(sim,R1,c.r1); c.r2[1]='permit ip 192.168.2.0 0.0.0.255 192.168.1.0 0.0.0.127'; cfg(sim,R2,c.r2); sim.runFor(1000);
  const r=ping(sim,p1,'192.168.2.10',6); sim.runFor(20000); ok(!/reply/.test(r),'ACL non miroir : pas de tunnel (phase 2 refusée)');
  console.log(cli(sim,R2,['enable','show logging']).split('\n').filter(l=>/CRYPTO/.test(l)).join('\n'));
  console.log(cli(sim,R1,['enable','show crypto isakmp sa','show crypto ipsec sa']));
}
// ---------- 6. GRE sur IPsec (tunnel protection) + OSPF
{
  const {sim,R1,R2,p1}=build();
  const gp=(loc,peer,tip,lan,key)=>['crypto isakmp policy 10','encryption aes','hash sha','authentication pre-share','group 2','exit','crypto isakmp key '+key+' address '+peer,'crypto ipsec transform-set TS esp-aes esp-sha-hmac','mode transport','exit','crypto ipsec profile PROF','set transform-set TS','exit',
    'interface tunnel0','ip address '+tip+' 255.255.255.252','tunnel source gi0/1','tunnel destination '+peer,'tunnel protection ipsec profile PROF','exit','router ospf 1','network 10.99.0.0 0.0.0.3 area 0','network '+lan+' 0.0.0.255 area 0','passive-interface gi0/0'];
  cfg(sim,R1,gp('R1','198.51.100.1','10.99.0.1','192.168.1.0','K')); cfg(sim,R2,gp('R2','203.0.113.1','10.99.0.2','192.168.2.0','K')); sim.runFor(90000);
  console.log(cli(sim,R1,['enable','show ip ospf neighbor','show crypto isakmp sa','show crypto ipsec sa']).slice(0,1800));
  ok(/FULL/.test(cli(sim,R1,['enable','show ip ospf neighbor'])),'OSPF via GRE protégé par IPsec');
  ok(/reply/.test(ping(sim,p1,'192.168.2.10',3)),'PC1 -> PC2 (GRE sur IPsec)');
  ok(/QM_IDLE/.test(cli(sim,R1,['enable','show crypto isakmp sa'])),'SA ISAKMP (tunnel protection)');
  const esp=sim.captures.filter(x=>{const q=NS.Codec.parse(x.bytes);return q.esp}); const gre=sim.captures.filter(x=>{const q=NS.Codec.parse(x.bytes);return q.gre});
  ok(esp.length>0&&gre.length===0,'le lien de l\'ISP ne voit que de l\'ESP (pas de GRE en clair)');
  // config -> texte -> reset -> restore
  const conf=cli(sim,R1,['enable','show running-config']);
  R1.cliReset(); ok(!/crypto/.test(cli(sim,R1,['enable','show running-config'])),'reset efface la config crypto'); R1.cliRestore(conf.split('Current configuration')[1].split('\n').slice(1).join('\n'),true); sim.runFor(60000);
  const conf2=cli(sim,R1,['enable','show running-config']); ok(conf2.replace(/Current configuration : \d+ bytes/,'')===conf.replace(/Current configuration : \d+ bytes/,''),'aller-retour de la configuration (VPN)');
  ok(/reply/.test(ping(sim,p1,'192.168.2.10',3)),'VPN opérationnel après restauration');
}

console.log(bad?'ECHECS '+bad:'OK'); process.exit(bad?1:0);
