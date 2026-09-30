const NS=require('./load')(); const {Codec,IP6,MAC}=NS; let ok=0,bad=0; const t=(c,m)=>{c?ok++:(bad++,console.log('FAIL',m))};
const S=['::','::1','2001:db8::1','fe80::1:2','2001:db8:0:0:1:0:0:1','ff02::1:ff00:1','1:2:3:4:5:6:7:8','2001:db8::','::ffff:1.2.3.4'];
t(IP6.str(IP6.parse('2001:0db8:0000:0000:0001:0000:0000:0001'))==='2001:db8::1:0:0:1','rfc5952 longest-first');
t(IP6.str(IP6.parse('2001:db8:0:0:0:0:0:1'))==='2001:db8::1','compress');
t(IP6.str(IP6.parse('::'))==='::'&&IP6.str(IP6.parse('::1'))==='::1','special');
S.forEach(s=>t(IP6.parse(s)!==null,'parse '+s)); t(IP6.parse('1::2::3')===null,'double ::'); t(IP6.parse('12345::')===null,'group too long'); t(IP6.parse('g::')===null,'bad hex');
const mac='00:1a:2b:3c:4d:5e'; t(IP6.str(IP6.linkLocal(mac))==='fe80::21a:2bff:fe3c:4d5e','eui64 '+IP6.str(IP6.linkLocal(mac)));
t(IP6.str(IP6.solicited(IP6.parse('2001:db8::21a:2bff:fe3c:4d5e')))==='ff02::1:ff3c:4d5e','solicited'); t(IP6.multicastMac(IP6.parse('ff02::1:ff3c:4d5e'))==='33:33:ff:3c:4d:5e','mcast mac');
t(IP6.inNet(IP6.parse('2001:db8:1::5'),IP6.parse('2001:db8:1::'),64)&&!IP6.inNet(IP6.parse('2001:db8:2::5'),IP6.parse('2001:db8:1::'),64),'inNet');
t(IP6.kind(IP6.parse('fe80::1'))==='link-local'&&IP6.kind(IP6.parse('fd00::1'))==='ULA'&&IP6.kind(IP6.parse('2001:db8::1'))==='global','kinds');
// echo + parse
const a=IP6.parse('2001:db8::1'),b=IP6.parse('2001:db8::2');
const ic=Codec.icmp6(a,b,128,0,Codec.echo6Body(0x1234,7,new Uint8Array(32)));
const pk=Codec.ip6Packet({next:58,hop:64,src:a,dst:b},ic); const fr=Codec.frame({dst:'00:11:22:33:44:55',src:mac,type:0x86dd,payload:pk});
let p=Codec.parse(fr,true); t(p.ip6&&p.icmp6&&p.icmp6.type===128&&p.icmp6.csumOk&&p.icmp6.seq===7,'echo request parse+checksum'); t(p.ip6.src===a&&p.ip6.hop===64,'src/hop');
console.log(JSON.stringify(p.tree.map(n=>n.t)));
// NS/NA/RA
const ns=Codec.icmp6(IP6.linkLocal(mac),IP6.solicited(b),135,0,Codec.nsBody(b,[{t:1,mac}]));
p=Codec.parse(Codec.frame({dst:IP6.multicastMac(IP6.solicited(b)),src:mac,type:0x86dd,payload:Codec.ip6Packet({next:58,hop:255,src:IP6.linkLocal(mac),dst:IP6.solicited(b)},ns)}),true);
t(p.icmp6.type===135&&p.icmp6.target===b&&p.icmp6.opts[0].mac===mac&&p.icmp6.csumOk,'NS');
const ra=Codec.icmp6(IP6.linkLocal(mac),IP6.ALL_NODES,134,0,Codec.raBody({hop:64,life:1800,opts:[{t:1,mac},{t:5,mtu:1500},{t:3,plen:64,l:1,a:1,vl:2592000,pl:604800,prefix:IP6.parse('2001:db8:1::')},{t:25,life:1800,addrs:[IP6.parse('2001:4860:4860::8888')]}]}));
p=Codec.parse(Codec.frame({dst:'33:33:00:00:00:01',src:mac,type:0x86dd,payload:Codec.ip6Packet({next:58,hop:255,src:IP6.linkLocal(mac),dst:IP6.ALL_NODES},ra)}),true);
t(p.icmp6.type===134&&p.icmp6.opts.length===4&&p.icmp6.opts[2].prefix===IP6.parse('2001:db8:1::')&&p.icmp6.opts[3].addrs[0]===IP6.parse('2001:4860:4860::8888')&&p.icmp6.csumOk,'RA');
const na=Codec.icmp6(a,b,136,0,Codec.naBody({r:1,s:1,o:1},a,[{t:2,mac}])); p=Codec.parse(Codec.frame({dst:mac,src:mac,type:0x86dd,payload:Codec.ip6Packet({next:58,hop:255,src:a,dst:b},na)}),true); t(p.icmp6.type===136&&p.icmp6.r&&p.icmp6.s&&p.icmp6.o,'NA flags');
console.log(ok+' ok, '+bad+' fail'); process.exit(bad?1:0);
