const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const sim=new Sim();
const pc1=createDevice(sim,'pc-win',{name:'PC1'}), pc2=createDevice(sim,'pc-linux',{name:'PC2'}), srv=createDevice(sim,'srv-linux',{name:'SRV1'});
const sw=createDevice(sim,'sw-2960',{name:'SW1'}); const r=createDevice(sim,'r-1941',{name:'R1'});
sim.connect(pc1.ports[0],sw.findPort('fa0/1')); sim.connect(pc2.ports[0],sw.findPort('fa0/2')); sim.connect(r.findPort('gi0/0'),sw.findPort('fa0/24'));
sim.connect(r.findPort('gi0/1'),srv.ports[0]);
console.log(cli(sim,r,`enable
configure terminal
hostname R1
interface gi0/0
ip address 192.168.1.1 255.255.255.0
no shutdown
exit
interface gi0/1
ip address 10.0.0.1 255.255.255.0
no shutdown
exit
ip dhcp excluded-address 192.168.1.1 192.168.1.9
ip dhcp pool LAN
network 192.168.1.0 255.255.255.0
default-router 192.168.1.1
dns-server 10.0.0.53
exit
end
show ip interface brief
show ip route
`,{echo:false}));
srv.applyIp('ens33',{ip:'10.0.0.53',mask:'24'}); srv.setGateway('10.0.0.1');
pc1.applyIp('Ethernet0',{dhcp:true}); pc2.applyIp('ens33',{dhcp:true});
sim.runFor(30000);
console.log(cli(sim,pc1,['ipconfig','ping -n 2 10.0.0.53']));
console.log(cli(sim,pc2,['ip a','ping -c 2 10.0.0.53']));
console.log(cli(sim,r,['show ip dhcp binding','show arp','ping 192.168.1.10','traceroute 10.0.0.53']));
console.log(cli(sim,sw,['enable','show mac address-table','show vlan brief','show spanning-tree','show interfaces status']).slice(0,2500));
console.log(cli(sim,sw,['enable','sh run']).slice(0,1800));
