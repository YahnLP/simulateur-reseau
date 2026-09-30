const {NS,Sim,createDevice,IP,cli}=require('./helpers');
const {mib}=NS; let bad=0; const ok=(c,m)=>{ console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++; };
const sim=new Sim(); 
const R=createDevice(sim,'r-2911',{name:'R1'}), S=createDevice(sim,'sw-2960',{name:'SW1'}), M=createDevice(sim,'srv-linux',{name:'NMS'});
console.log('models ok');
sim.connect(M.ports[0],S.findPort('fa0/2')); sim.connect(R.findPort('gi0/0'),S.findPort('fa0/1'));
cli(sim,R,['enable','conf t','interface gi0/0','ip address 10.0.0.1 255.255.255.0','no shutdown','end']);
M.applyIp('ens33',{ip:'10.0.0.50',mask:'24'}); sim.runFor(2000);
R.mgmt.setCommunity('public','ro'); R.mgmt.setCommunity('private','rw'); R.mgmt.snmp.location='Salle B12';
function q(op,oids,o){ let res; const vbs=oids.map(x=>({oid:mib.os(mib.parseOid(x)),t:'null'})); M.mgmt.query(IP.parse('10.0.0.1'),Object.assign({ver:1,community:'public',op,vbs},o||{}),(e,r)=>res={e,r}); sim.runUntil(()=>res,15000); return res; }
let r=q('get',['sysDescr.0','sysLocation.0','sysUpTime.0']);
ok(r&&!r.e&&r.r.pdu.varbinds.length===3,'get 3 varbinds '+JSON.stringify(r&&r.e));
console.log(r.r.pdu.varbinds.map(v=>mib.fmtVb(v)).join('\n'));
ok(/Salle B12/.test(mib.fmtVb(r.r.pdu.varbinds[1])),'sysLocation');
r=q('get',['sysDescr.0'],{community:'wrong',retries:0,timeout:500}); ok(r.e==='timeout','mauvaise communauté -> timeout'); ok(R.mgmt.cnt.badComm===1,'compteur badComm');
r=q('get',['1.3.6.1.2.1.99.1.0']); ok(r.r.pdu.varbinds[0].t==='nso','noSuchObject en v2c');
r=q('get',['1.3.6.1.2.1.99.1.0'],{ver:0}); ok(r.r.pdu.errStatus===2,'noSuchName en v1');
// walk ifDescr
const got=[]; let done=null; M.mgmt.walk(IP.parse('10.0.0.1'),{ver:1,community:'public'},mib.parseOid('ifDescr'),vb=>got.push(mib.fmtVb(vb)),e=>done=e||'ok'); sim.runUntil(()=>done,30000);
console.log(got.join('\n')); ok(done==='ok'&&got.length>=3&&/GigabitEthernet0\/0/.test(got[0]),'walk ifDescr ('+got.length+')');
// v1 walk
const g1=[]; done=null; M.mgmt.walk(IP.parse('10.0.0.1'),{ver:0,community:'public'},mib.parseOid('ifDescr'),vb=>g1.push(vb.oid),e=>done=e||'ok'); sim.runUntil(()=>done,30000); ok(done==='ok'&&g1.length===got.length,'walk v1 getnext = même nombre');
// set
r=q('set',['sysLocation.0'],{vbs:[{oid:'1.3.6.1.2.1.1.6.0',t:'oct',v:'Salle C3'}]}); ok(r.r.pdu.errStatus!==0,'set refusé avec communauté ro (errStatus '+r.r.pdu.errStatus+')');
r=q('set',[],{community:'private',vbs:[{oid:'1.3.6.1.2.1.1.6.0',t:'oct',v:'Salle C3'}]}); ok(r.r.pdu.errStatus===0&&R.mgmt.snmp.location==='Salle C3','set OK avec rw');
// shutdown via snmp
const ifidx=1; r=q('set',[],{community:'private',retries:0,timeout:500,vbs:[{oid:'1.3.6.1.2.1.2.2.1.7.'+ifidx,t:'int',v:2}]}); sim.runFor(1000);
console.log('reponse:',r.e||r.r.pdu.errStatus,'gi0/0 up?',R.findPort('gi0/0').up);
ok(!R.findPort('gi0/0').up,'ifAdminStatus=2 via SNMP coupe gi0/0');
// getbulk
R.mgmt.setCommunity('public','ro'); 
console.log(R.mgmt.mib().length+' lignes MIB');
console.log('bad',bad); process.exit(bad?1:0);
