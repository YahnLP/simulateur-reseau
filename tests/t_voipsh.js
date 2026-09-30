const {NS,Sim,createDevice,IP,cli}=require('./helpers'); const {HostShell}=NS; let bad=0; const ok=(c,m)=>{console.log((c?'PASS ':'FAIL ')+m); if(!c) bad++;};
const sim=new Sim(); sim.opts.stpFast=true; const SW=createDevice(sim,'sw-2960',{name:'SW'}),S=createDevice(sim,'srv-linux',{name:'PBX'}),A=createDevice(sim,'pc-linux',{name:'A'}),B=createDevice(sim,'pc-win',{name:'B'});
sim.connect(S.ports[0],SW.findPort('fa0/1')); sim.connect(A.ports[0],SW.findPort('fa0/2')); sim.connect(B.ports[0],SW.findPort('fa0/3'));
S.applyIp(S.ifaceList()[0].name,{ip:'10.0.0.5',mask:'24'}); A.applyIp(A.ifaceList()[0].name,{ip:'10.0.0.11',mask:'24'}); B.applyIp(B.ifaceList()[0].name,{ip:'10.0.0.12',mask:'24'}); sim.runFor(40000);
function sh(d,l){const s=d.shell||(d.shell=new HostShell(d));let out='',done=false;s.exec(l,{print:t=>out+=t,done:()=>done=true,clear(){}});sim.runUntil(()=>done,60000);return out;}
sh(S,"echo '[2001]' >> /etc/asterisk/sip.conf"); sh(S,'echo secret=aaa >> /etc/asterisk/sip.conf'); sh(S,"echo '[2002]' >> /etc/asterisk/sip.conf"); sh(S,'echo secret=bbb >> /etc/asterisk/sip.conf'); sh(S,"echo 'exten => _200X,1,Dial(SIP/${EXTEN},20)' >> /etc/asterisk/extensions.conf");
ok(/\[2001\][\s\S]*secret=aaa/.test(sh(S,'cat /etc/asterisk/sip.conf')),'sip.conf'); ok(/_200X/.test(sh(S,'cat /etc/asterisk/extensions.conf')),'extensions.conf');
sh(S,'sudo systemctl start asterisk'); ok(/active \(running\)/.test(sh(S,'systemctl status asterisk')),'asterisk démarré');
sh(A,'sipphone register 2001 aaa 10.0.0.5 Alice'); sh(B,'sipphone register 2002 bbb 10.0.0.5 Bob'); sim.runFor(5000);
let o=sh(S,'asterisk -rx "sip show peers"'); console.log(o); ok(/2001\/2001\s+10\.0\.0\.11[\s\S]*OK/.test(o)&&/2002\/2002\s+10\.0\.0\.12/.test(o),'sip show peers');
sh(A,'sipphone call 2002'); sim.runFor(9000); o=sh(S,'asterisk -rx "core show channels"'); ok(/1 active calls/.test(o),'core show channels'); sim.runFor(5000);
o=sh(A,'sipphone status'); console.log(o); ok(/talking/.test(o)&&/MOS 4\./.test(o),'sipphone status (MOS)'); sh(B,'sipphone hangup'); sim.runFor(2000);
ok(/ANSWERED/.test(sh(S,'cat /var/log/asterisk/cdr-csv/Master.csv')),'CDR'); ok(/Registered SIP '2001'/.test(sh(S,'tail /var/log/asterisk/full')),'journal');
process.exit(bad?1:0);
