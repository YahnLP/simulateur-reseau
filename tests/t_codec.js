const NS=require('./load')(['util','codec']);
const {Codec,IP,MAC,B}=NS;
const eth=(dst,src,type,payload,vlan)=>Codec.frame({dst,src,type,payload,vlan});
// ARP
let arp=Codec.arp({op:1,sha:'00:00:0c:00:00:01',spa:IP.parse('192.168.1.10'),tha:'00:00:00:00:00:00',tpa:IP.parse('192.168.1.1')});
let f=eth('ff:ff:ff:ff:ff:ff','00:00:0c:00:00:01',0x0806,arp);
let p=Codec.parse(f,true); console.log(f.length,p.arp.op,IP.str(p.arp.tpa),p.tree.length);
// ICMP echo in IP in VLAN
let ic=Codec.icmp({type:8,code:0,id:1,seq:7,payload:new Uint8Array(32).fill(0x61)});
let ipk=Codec.ipPacket({ttl:128,proto:1,src:IP.parse('10.0.0.1'),dst:IP.parse('10.0.0.2'),id:5,df:1},ic);
f=eth('00:00:0c:00:00:02','00:00:0c:00:00:01',0x0800,ipk,{vid:10});
p=Codec.parse(f,true); console.log(p.eth.vlan.vid,p.ip.ttl,p.icmp.type,p.icmp.seq,p.ip.csumOk, JSON.stringify(p.tree.map(n=>n.t.slice(0,40))));
// UDP DHCP
let d=Codec.dhcp({op:1,xid:0x1234,flags:0x8000,chaddr:'00:00:0c:00:00:01',opts:{msgType:1,clientId:'00:00:0c:00:00:01',hostname:'PC1',paramList:[1,3,6,15]}});
let u=Codec.udp(0,0xffffffff,68,67,d);
ipk=Codec.ipPacket({ttl:64,proto:17,src:0,dst:0xffffffff,id:1},u);
f=eth('ff:ff:ff:ff:ff:ff','00:00:0c:00:00:01',0x0800,ipk);
p=Codec.parse(f,true); console.log(p.dhcp.msgType,p.dhcp.opts.hostname,p.tree.map(n=>n.layer));
// DNS
let dn=Codec.dns({id:0x99,qr:1,rd:1,ra:1,aa:1,questions:[{name:'www.lycee.fr',type:'A'}],answers:[{name:'www.lycee.fr',type:'A',data:'10.0.0.5',ttl:300}]});
u=Codec.udp(1,2,53,4000,dn); ipk=Codec.ipPacket({ttl:64,proto:17,src:1,dst:2,id:2},u);
p=Codec.parse(eth('00:00:0c:00:00:02','00:00:0c:00:00:01',0x0800,ipk),true); console.log(JSON.stringify(p.dns.answers));
// TCP + HTTP
let h=Codec.httpRequest('GET','www.lycee.fr','/');
let tcp=Codec.tcp(1,2,{sport:50000,dport:80,seq:100,ack:200,flags:0x18,payload:h});
ipk=Codec.ipPacket({ttl:64,proto:6,src:1,dst:2,id:3},tcp);
p=Codec.parse(eth('00:00:0c:00:00:02','00:00:0c:00:00:01',0x0800,ipk),true); console.log(p.http.method,p.http.uri,p.tcp.flags,p.ip.csumOk);
// rebuild NAT
let nb=Codec.rebuildIp(p,{ip:{src:IP.parse('1.2.3.4')},l4:{sport:1025}});
let p2=Codec.parse(eth('00:00:0c:00:00:02','00:00:0c:00:00:01',0x0800,nb),true); console.log(IP.str(p2.ip.src),p2.tcp.sport,p2.ip.csumOk, /correct\]/.test(JSON.stringify(p2.tree.map(n=>n.ch&&n.ch.map(c=>c.t)))));
// STP
let b=Codec.bpdu({rootPri:32769,rootMac:'00:00:0c:00:00:01',cost:19,brPri:32769,brMac:'00:00:0c:00:00:02',portId:0x8001});
f=Codec.frame8023({dst:'01:80:c2:00:00:00',src:'00:00:0c:00:00:02',payload:b});
p=Codec.parse(f,true); console.log(p.stp.rootPri,p.stp.cost,p.tree.map(n=>n.layer));
// RIP
let r=Codec.rip(2,[{net:IP.parse('10.0.0.0'),mask:IP.parse('255.255.255.0'),metric:1}]);
u=Codec.udp(1,IP.parse('224.0.0.9'),520,520,r); ipk=Codec.ipPacket({ttl:2,proto:17,src:1,dst:IP.parse('224.0.0.9'),id:4},u);
p=Codec.parse(eth('01:00:5e:00:00:09','00:00:0c:00:00:01',0x0800,ipk),true); console.log(p.rip.entries.length,p.rip.entries[0].metric);
