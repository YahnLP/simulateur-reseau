const NS=require('./load')(); const {Codec,IP}=NS; let ok=0,bad=0; const t=(c,m)=>{c?ok++:(bad++,console.log('FAIL',m))};
const A=IP.parse('10.0.0.1'),B=IP.parse('10.0.0.2'),C=IP.parse('192.168.1.1'),D=IP.parse('192.168.2.1');
const M1='00:11:22:33:44:55',M2='00:aa:bb:cc:dd:ee';
const fr=(ip)=>Codec.frame({dst:M1,src:M2,type:0x0800,payload:ip});
// GRE + inner ICMP
const inner=Codec.ipPacket({ttl:63,proto:1,src:C,dst:D,id:5},Codec.icmp({type:8,id:1,seq:2,payload:new Uint8Array(8)}));
let g=Codec.gre({proto:0x0800,payload:inner});
let p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:47,src:A,dst:B},g)),true);
t(p.gre&&p.gre.inner&&p.gre.inner.icmp&&p.gre.inner.icmp.type===8,'gre inner icmp'); t(p.gre.inner.ip.src===C,'inner src');
console.log(p.tree.map(n=>n.t.slice(0,40)+'@'+n.off).join(' | '));
g=Codec.gre({proto:0x0800,key:77,payload:inner}); p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:47,src:A,dst:B},g)),true); t(p.gre.key===77&&p.gre.inner.ip.dst===D,'gre key');
// ESP
const e=Codec.esp(0x1234,9,new Uint8Array(40)); p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:50,src:A,dst:B},e)),true); t(p.esp&&p.esp.spi===0x1234&&p.esp.seq===9&&p.esp.len===40,'esp');
// ISAKMP
const ic=Uint8Array.from([1,2,3,4,5,6,7,8]),rc=new Uint8Array(8);
const sa=Codec.ikeSA([{num:1,proto:1,transforms:[{num:1,id:1,attrs:[[1,7],[14,128],[2,2],[3,1],[4,2],[11,1],[12,86400]]},{num:2,id:1,attrs:[[1,1],[2,1],[3,1],[4,1],[11,1],[12,86400]]}]}]);
const im=Codec.isakmp({ic,rc,exch:2,payloads:[{t:1,body:sa},{t:13,body:Uint8Array.of(9,9,9,9)}]});
const ud=Codec.udp(A,B,500,500,im); p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:17,src:A,dst:B},ud)),true);
t(p.isakmp&&p.isakmp.exch===2&&p.isakmp.payloads.length===2,'isakmp parse'); const pr=p.isakmp.payloads[0].props[0]; t(pr.transforms.length===2&&pr.transforms[0].attrs.length===7,'transforms'); t(pr.transforms[0].attrs.find(a=>a.type===12).val===86400,'lifetime 32b');
console.log(Codec.ikeSummary(p.isakmp)); console.log(JSON.stringify(p.tree.filter(n=>n.layer==='isakmp')[0].ch.slice(0,7).map(n=>n.t)));
// notify
const nt=Codec.isakmp({ic,rc,exch:5,payloads:[{t:11,body:Codec.ikeNotify(14)}]}); p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:17,src:A,dst:B},Codec.udp(A,B,500,500,nt))),true); t(p.isakmp.payloads[0].notify===14,'notify'); console.log(Codec.ikeSummary(p.isakmp));
// encrypted
const en=Codec.isakmp({ic,rc,exch:2,flags:1,payloads:[{t:5,body:new Uint8Array(20)}]}); p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:17,src:A,dst:B},Codec.udp(A,B,500,500,en))),true); t(p.isakmp&&p.isakmp.payloads.length===0,'encrypted');
console.log('ok',ok,'bad',bad);
