const {open,dev}=require('./gen');
(async()=>{
 const {b,p,errs}=await open(1500,950);
 // placer 2 PC + switch via palette
 const place=async(model,x,y)=>{ await p.click(`.pal-item[data-model="${model}"]`); await p.mouse.click(x,y); await p.waitForTimeout(100); };
 await place('pc-win',450,250); await place('pc-linux',900,250); await place('sw-2960',700,400);
 console.log('devices',await p.evaluate(()=>[...__app.sim.devices.values()].map(d=>d.name).join(',')));
 // câble: outil
 await p.click('.tool[data-tool="cable"]');
 const cab=async(a,b2,portLabel)=>{ const A=await dev(p,a); await p.mouse.click(A.x,A.y); await p.waitForTimeout(100);
   const B=await dev(p,b2); await p.mouse.click(B.x,B.y); await p.waitForTimeout(150);
   if(await p.locator('.ctxmenu').count()){ await p.click(`.ctxmenu >> text=${portLabel}`); } await p.waitForTimeout(150); };
 // PC1 (1 port) -> switch : choix port fa0/1 dans le menu du switch
 await cab('PC1','SW1','FastEthernet0/1  ');
 await cab('LX1','SW1','FastEthernet0/2  ');
 console.log('links',await p.evaluate(()=>__app.sim.links.map(l=>l.a.dev.name+':'+l.a.name+'-'+l.b.dev.name+':'+l.b.name+' '+l.type+' ok='+l.ok).join(' | ')));
 await p.click('.tool[data-tool="select"]');
 await p.evaluate(()=>{const g=n=>[...__app.sim.devices.values()].find(d=>d.name===n);g('PC1').applyIp('Ethernet0',{ip:'10.0.0.1',mask:'24'});g('LX1').applyIp('ens33',{ip:'10.0.0.2',mask:'24'});});
 await p.waitForTimeout(500);
 // ping via terminal de PC1
 const c=await dev(p,'PC1'); await p.mouse.dblclick(c.x,c.y); await p.waitForTimeout(300);
 await p.fill('.win .tin','ping 10.0.0.2'); await p.press('.win .tin','Enter'); await p.waitForTimeout(7000);
 console.log((await p.evaluate(()=>document.querySelector('.win .tout').textContent)).slice(-260));
 await p.screenshot({path:'/tmp/c1.png'});
 // câbles stricts: PC-PC droit doit ne pas monter
 console.log('errs',errs); await b.close();
})();
