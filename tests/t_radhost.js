const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const {HostShell}=NS; let bad=0; const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++;};
const sim=new Sim(); sim.opts.stpFast=true;
const SW=createDevice(sim,'sw-2960',{name:'SW'}),S=createDevice(sim,'srv-linux',{name:'RAD'}),C=createDevice(sim,'pc-linux',{name:'C'});
sim.connect(S.ports[0],SW.findPort('fa0/1')); sim.connect(C.ports[0],SW.findPort('fa0/2'));
S.applyIp(S.ifaceList()[0].name,{ip:'10.0.0.5',mask:'24'}); C.applyIp(C.ifaceList()[0].name,{ip:'10.0.0.9',mask:'24'}); sim.runFor(40000);
function sh(d,l){const s=d.shell||(d.shell=new HostShell(d));let out='',done=false;s.exec(l,{print:t=>out+=t,done:()=>done=true,clear(){}});sim.runUntil(()=>done,60000);return out;}
sh(S,"echo 'client lab { ipaddr = 10.0.0.0/24 secret = testing123 }' >> /etc/freeradius/3.0/clients.conf");
sh(S,'echo \'alice Cleartext-Password := "Pw1", Tunnel-Private-Group-Id = "30"\' >> /etc/freeradius/3.0/users');
ok(/alice[\s\S]*Group-Id = "30"/.test(sh(S,'cat /etc/freeradius/3.0/users')),'users écrit'); ok(/ipaddr = 10.0.0.0\/24/.test(sh(S,'cat /etc/freeradius/3.0/clients.conf')),'clients écrit');
ok(/inactive/.test(sh(S,'systemctl status freeradius')),'arrêté'); sh(S,'sudo systemctl start freeradius'); ok(/active \(running\)/.test(sh(S,'systemctl status freeradius')),'démarré');
let o=sh(C,'radtest alice Pw1 10.0.0.5 0 testing123'); console.log(o); ok(/Received Access-Accept/.test(o),'radtest accept');
o=sh(C,'radtest alice bad 10.0.0.5 0 testing123'); ok(/Access-Reject/.test(o),'radtest reject');
ok(/Login OK/.test(sh(S,'tail /var/log/freeradius/radius.log')),'log'); 
process.exit(bad?1:0);
