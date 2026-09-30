const {open,scenario,dev}=require('./gen');
(async()=>{
 const {b,p,errs}=await open(1500,950);
 await p.evaluate(()=>{const s=__app.sim;const c=(m,n,x,y)=>NS.createDevice(s,m,{name:n,x,y});const a=c('sw-8p','A',500,150),b=c('sw-8p','B',350,350),d=c('sw-8p','C',650,350),p1=c('pc-win','P1',200,450);
  s.connect(a.findPort('port1'),b.findPort('port1'));s.connect(b.findPort('port2'),d.findPort('port2'));s.connect(d.findPort('port1'),a.findPort('port2'));s.connect(p1.ports[0],b.findPort('port3'));
  p1.applyIp('Ethernet0',{ip:'10.0.0.1',mask:'24'});__app.refresh();__app.fit();});
 await p.waitForTimeout(500);
 const c=await dev(p,'P1'); await p.mouse.dblclick(c.x,c.y); await p.waitForTimeout(300);
 await p.fill('.win .tin','ping 10.0.0.99'); await p.press('.win .tin','Enter'); await p.waitForTimeout(5000);
 console.log('halted',await p.evaluate(()=>__app.sim.halted), 'bar visible', await p.isVisible('#haltbar'));
 await p.click('.win .wclose');
 await p.screenshot({path:'/tmp/st1.png'});
 await p.click('#halt-ok'); console.log('after reset',await p.evaluate(()=>__app.sim.halted));
 await scenario(p,'Box, Wi-Fi'); await p.evaluate(()=>{__app.tpCurrent.solve(__app.sim);}); await p.waitForTimeout(25000);
 await p.screenshot({path:'/tmp/st2.png'});
 console.log(await p.evaluate(()=>[...__app.sim.devices.values()].filter(d=>d.ifaceList).map(d=>d.name+' '+d.ifaceList().map(i=>i.ip?NS.IP.str(i.ip):'-').join(',')).join(' | ')));
 console.log('errs',errs); await b.close();
})();
