const {NS,Sim,createDevice,IP,cli}=require('./helpers');require('./load')(['analyzer']);
const A=NS.Analyzer;
const sim=new Sim();const c=(n,m)=>createDevice(sim,m,{name:n});
const pc=c('PC1','pc-win'),sw=c('SW','sw-2960'),srv=c('SRV','srv-linux');
sim.connect(pc.ports[0],sw.findPort('fa0/1'));sim.connect(srv.ports[0],sw.findPort('fa0/2'));
pc.applyIp('Ethernet0',{ip:'10.0.0.2',mask:'24'});srv.applyIp(srv.ifaceList?srv.ifaceList()[0].name:'eth0',{ip:'10.0.0.10',mask:'24'});
sim.runFor(3000);
let dn=false;const s=pc.newSession();let out='';
const run=l=>{dn=false;s.exec(l,{print:t=>out+=t,done:()=>dn=true});sim.runUntil(()=>dn,20000);};
srv.httpd.start();run('ping 10.0.0.10');run('curl http://10.0.0.10/');
const ctx=A.newCtx();
sim.captures.slice(0,40).forEach(r=>{const x=A.summarize(ctx,r);console.log(String(x.no).padStart(3),x.proto.padEnd(6),x.src.padEnd(18),x.dst.padEnd(18),x.info)});
const f=(q)=>{const fn=A.compile(q);return sim.captures.filter(r=>fn(A.summarize(ctx,r))).length};
for(const q of ['arp','icmp','ip.addr == 10.0.0.10','ip.addr==10.0.0.0/24 && tcp','tcp.flags.syn == 1 && tcp.flags.ack == 0','http.request.method == "GET"','http contains "Simu"','not arp and not stp','tcp.port in {80 443}','eth.addr == aa:bb','tcp.stream eq 0','icmp.type == 8','frame.len > 100'])console.log(q,'=>',f(q));
try{A.compile('ip.addr ==')}catch(e){console.log('err ok:',e.message)}
try{A.compile('foo.bar == 1')}catch(e){console.log('err ok:',e.message)}
const segs=A.followTcp(ctx,sim.captures,0);console.log(segs.length,A.streamText(segs).map(x=>x.dir+':'+x.text.slice(0,50).replace(/\r\n/g,'|')));
console.log(JSON.stringify(A.stats(ctx,sim.captures).proto));
const pc1=A.toPcap(sim.captures);console.log('pcap',pc1.length);require('fs').writeFileSync('/tmp/t.pcap',pc1);
const d=A.detail(ctx,sim.captures.find(r=>ctx.cache.get(r.no)&&ctx.cache.get(r.no).p.tcp));console.log(d.map(n=>n.t.slice(0,70)));
