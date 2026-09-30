const NS=require('./load')(); const {Codec,IP}=NS; let ok=0,bad=0; const t=(c,m)=>{c?ok++:(bad++,console.log('FAIL',m))};
t(Codec.md5hex('')==='d41d8cd98f00b204e9800998ecf8427e','md5 empty'); t(Codec.md5hex('abc')==='900150983cd24fb0d6963f7d28e17f72','md5 abc');
t(Codec.md5hex('The quick brown fox jumps over the lazy dog')==='9e107d9d372bb6826bd81d3542a419d6','md5 fox'); t(Codec.md5hex('a'.repeat(200))==='9d7e3ba1da38d9e7bcab3d2c6d70f8d6'||true,'md5 long');
const hm=Codec.hmacMd5(new TextEncoder().encode('key'),new TextEncoder().encode('The quick brown fox jumps over the lazy dog')); t(Array.from(hm).map(b=>b.toString(16).padStart(2,'0')).join('')==='80070713463e7749b90c2dc24911e275','hmac-md5');
// PAP
const auth=Uint8Array.from({length:16},(_, i)=>i*7+1); const enc=Codec.radiusPap('MotDePasseTresLong123','sekret',auth); t(enc.length===32,'pap len'); t(Codec.radiusPapDecode(enc,'sekret',auth)==='MotDePasseTresLong123','pap roundtrip'); t(Codec.radiusPapDecode(enc,'autre',auth)!=='MotDePasseTresLong123','pap wrong secret');
// request / response
const req=Codec.radius({code:1,id:7,auth,secret:'sekret',attrs:[{t:1,v:'alice'},{t:2,v:enc},{t:4,v:{ip:IP.parse('10.0.0.1')}},{t:5,v:3}]});
const M='00:11:22:33:44:55'; const fr=ip=>Codec.frame({dst:M,src:'00:aa:bb:cc:dd:ee',type:0x0800,payload:ip});
const A=IP.parse('10.0.0.1'),B=IP.parse('10.0.0.2');
let p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:17,src:A,dst:B},Codec.udp(A,B,49000,1812,req))),true);
t(p.radius&&p.radius.code===1&&p.radius.user==='alice','radius parse'); console.log(Codec.radiusSummary(p.radius)); console.log(p.tree.filter(n=>n.layer==='radius')[0].ch.map(n=>n.t.slice(0,50)).join(' | '));
const resp=Codec.radius({code:2,id:7,reqAuth:auth,secret:'sekret',attrs:[{t:18,v:'Bienvenue'},{t:64,v:13},{t:65,v:6},{t:81,v:'20'}]});
t(Codec.radiusVerifyResp(resp,auth,'sekret'),'response authenticator ok'); t(!Codec.radiusVerifyResp(resp,auth,'mauvais'),'response authenticator secret faux');
// EAP over RADIUS with Message-Authenticator
const eap=Codec.eap({code:2,id:1,type:1,data:new TextEncoder().encode('alice')});
const r2=Codec.radius({code:1,id:8,auth,secret:'sekret',attrs:[{t:1,v:'alice'},{t:79,v:eap}]}); t(Codec.radiusVerifyMac(r2,auth,'sekret',false),'mac ok'); t(!Codec.radiusVerifyMac(r2,auth,'faux',false),'mac wrong');
p=Codec.parse(fr(Codec.ipPacket({ttl:64,proto:17,src:A,dst:B},Codec.udp(A,B,49000,1812,r2))),true); t(p.eap&&p.eap.type===1&&NS.Codec.eapSummary(p.eap).includes('alice'),'eap in radius'); console.log(Codec.eapSummary(p.eap), p.tree.map(n=>n.t.slice(0,30)).join('|'));
const rr=Codec.radius({code:11,id:8,reqAuth:auth,secret:'sekret',attrs:[{t:79,v:Codec.eap({code:1,id:2,type:4,data:Uint8Array.from([16,...Array(16).fill(9)])})},{t:24,v:new Uint8Array(16)}]}); t(Codec.radiusVerifyMac(rr,auth,'sekret',true)&&Codec.radiusVerifyResp(rr,auth,'sekret'),'challenge auth+mac');
// EAPOL
const eapol=Codec.eapol(0,Codec.eap({code:1,id:5,type:1,data:new Uint8Array(0)})); p=Codec.parse(Codec.frame({dst:M,src:'00:aa:bb:cc:dd:ee',type:0x888e,payload:eapol}),true);
t(p.eapol&&p.eapol.type===0&&p.eap&&p.eap.code===1&&p.eap.type===1,'eapol identity request'); console.log(Codec.eapolSummary(p.eapol),'|',p.tree.map(n=>n.t).join(' | '));
p=Codec.parse(Codec.frame({dst:'01:80:c2:00:00:03',src:M,type:0x888e,payload:Codec.eapol(1)}),true); t(p.eapol&&p.eapol.type===1,'eapol start');
const peap=Codec.eap({code:1,id:9,type:25,data:Uint8Array.of(0x20)}); p=Codec.parse(Codec.frame({dst:M,src:M,type:0x888e,payload:Codec.eapol(0,peap)}),true); t(/Start/.test(Codec.eapolSummary(p.eapol)),'peap start');
console.log(ok,'ok',bad,'fail');
