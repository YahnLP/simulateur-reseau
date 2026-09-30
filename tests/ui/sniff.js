const {open,scenario,dev}=require('./gen');
(async()=>{
 const {b,p,errs}=await open(1600,1000);
 await scenario(p,'Analyse de trames');
 const c=await dev(p,'PC1'); await p.mouse.dblclick(c.x,c.y); await p.waitForTimeout(300);
 const send=async(t,w=1500)=>{await p.fill('.win .tin',t);await p.press('.win .tin','Enter');await p.waitForTimeout(w);};
 await send('telnet 10.0.0.1',3000); await send('vty123'); await send('enable'); await send('cisco'); await send('show ip interface brief'); await send('exit');
 console.log((await p.evaluate(()=>document.querySelector('.win .tout').textContent)).slice(-500));
 // fermer la fenêtre
 await p.click('.win .wclose'); 
 // clic droit sur le câble PC2-HUB1
 const pos=await p.evaluate(()=>{const l=__app.sim.links.find(l=>[l.a.dev.name,l.b.dev.name].includes('PC2'));const g=__app.linkEls.get(l.id).querySelector('.hit');const r=g.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};});
 await p.mouse.click(pos.x,pos.y,{button:'right'}); await p.waitForTimeout(200); await p.click('.ctxmenu >> text=Analyser cette liaison'); await p.waitForTimeout(500);
 await p.fill('.filter','telnet'); await p.press('.filter','Enter'); await p.waitForTimeout(500);
 console.log('rows',await p.evaluate(()=>__app.analyzer.count));
 await p.evaluate(()=>__app.analyzer.selectFirst(s=>s.p.telnet)); await p.waitForTimeout(300);
 await p.screenshot({path:'/tmp/w1.png'});
 await p.click('text=Suivre le flux TCP'); await p.waitForTimeout(400);
 await p.screenshot({path:'/tmp/w2.png'});
 console.log((await p.evaluate(()=>document.querySelector('.follow').innerText)).slice(0,500));
 console.log('errs',errs); await b.close();
})();
