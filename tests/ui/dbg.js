const {open,scenario}=require('./gen');
(async()=>{
 const {b,p,errs}=await open();
 await scenario(p,'Box, Wi-Fi'); await p.evaluate(()=>{__app.tpCurrent.solve(__app.sim);});
 for(let k=0;k<4;k++){ await p.waitForTimeout(3000);
 console.log(await p.evaluate(()=>{const s=__app.sim;const l=[...s.devices.values()].find(d=>d.name==='LAP1');const w=l.ifaceList().find(i=>i.port.media==='wifi');const c=l.dhcpClients.get(w.name);return JSON.stringify({now:s.now.toFixed(1),heap:s.heap.size,halted:s.halted,paused:s.paused,running:__app.running,state:c&&c.state,up:w.isUp(),dhcp:w.dhcp,next:s.heap.peek()&&(s.heap.peek().t-s.now).toFixed(1)});}));}
 await b.close();
})();
