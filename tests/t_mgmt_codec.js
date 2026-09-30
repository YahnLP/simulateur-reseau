const NS=require('./load')(); const {Codec,IP}=NS; let ok=0,bad=0; const t=(c,m)=>{c?ok++:(bad++,console.log('FAIL',m))};
function wrap(sport,dport,payload){const udp=Codec.udp(IP.parse('10.0.0.1'),IP.parse('10.0.0.2'),sport,dport,payload);
 const ip=Codec.ipPacket({id:1,ttl:64,proto:17,src:IP.parse('10.0.0.1'),dst:IP.parse('10.0.0.2'),df:0},udp);
 return Codec.frame({dst:'00:11:22:33:44:55',src:'00:11:22:33:44:66',type:0x0800,payload:ip});}
const msg={ver:1,community:'public',pdu:{type:'get',reqId:1234,varbinds:[{oid:'1.3.6.1.2.1.1.1.0',t:'null'},{oid:'1.3.6.1.2.1.1.3.0',t:'null'}]}};
let p=Codec.parse(wrap(40000,161,Codec.snmp(msg)),true);
t(p.snmp&&p.snmp.pdu.type==='get-request','get parsed'); t(p.snmp.pdu.reqId===1234,'reqid'); t(p.snmp.pdu.varbinds[1].oid==='1.3.6.1.2.1.1.3.0','oid');
const resp={ver:1,community:'public',pdu:{type:'response',reqId:1234,varbinds:[{oid:'1.3.6.1.2.1.1.1.0',t:'oct',v:'Cisco IOS'},{oid:'1.3.6.1.2.1.1.3.0',t:'tt',v:123456},{oid:'1.3.6.1.2.1.2.2.1.10.1',t:'c32',v:4000000000},{oid:'1.3.6.1.2.1.2.2.1.5.1',t:'g32',v:1000000000},{oid:'1.3.6.1.2.1.4.20.1.1.10.0.0.1',t:'ip',v:IP.parse('10.0.0.1')},{oid:'1.3.6.1.2.1.1.2.0',t:'oid',v:'1.3.6.1.4.1.9.1.1208'},{oid:'1.3.6.1.2.1.1.7.0',t:'int',v:-5}]}};
p=Codec.parse(wrap(161,40000,Codec.snmp(resp)),true); const v=p.snmp.pdu.varbinds;
t(v[0].t==='oct'&&Codec.snmpValStr(v[0])==='Cisco IOS','oct'); t(v[1].v===123456,'tt'); t(v[2].v===4000000000,'c32'); t(v[4].v===IP.parse('10.0.0.1'),'ip'); t(v[5].v==='1.3.6.1.4.1.9.1.1208','oid val'); t(v[6].v===-5,'neg int');
t(p.tree.some(n=>n.layer==='snmp'),'tree'); 
const tr={ver:1,community:'public',pdu:{type:'trap2',reqId:7,varbinds:[{oid:'1.3.6.1.2.1.1.3.0',t:'tt',v:5},{oid:'1.3.6.1.6.3.1.1.4.1.0',t:'oid',v:'1.3.6.1.6.3.1.1.5.3'}]}};
p=Codec.parse(wrap(50000,162,Codec.snmp(tr)),true); t(p.snmp&&p.snmp.pdu.type==='snmpV2-trap','trap2');
const gb={ver:1,community:'public',pdu:{type:'getbulk',reqId:9,errStatus:0,errIdx:10,varbinds:[{oid:'1.3.6.1.2.1.2.2',t:'null'}]}}; p=Codec.parse(wrap(50000,161,Codec.snmp(gb)),true); t(p.snmp.pdu.errIdx===10,'bulk');
const sy=Codec.syslog(189,'12: *Sep 30 08:00:00.123: %LINK-3-UPDOWN: Interface Fa0/1, changed state to down');
p=Codec.parse(wrap(50000,514,sy),true); t(p.syslog&&p.syslog.facility===23&&p.syslog.severity===5,'syslog '+JSON.stringify(p.syslog));
console.log(ok+' ok, '+bad+' fail');
