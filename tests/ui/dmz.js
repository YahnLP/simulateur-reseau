const {open,scenario,dev}=require('./gen');
(async()=>{
 const {b,p,errs}=await open();
 await scenario(p,'Pare-feu, DMZ');
 await p.evaluate(()=>{__app.tpCurrent.solve(__app.sim);__app.refresh();});
 // vérifier via le bouton
 await p.click('text=Vérifier mon travail'); await p.waitForTimeout(1500);
 console.log(await p.evaluate(()=>document.querySelector('.tpres').innerText));
 const c=await dev(p,'FW1'); await p.mouse.dblclick(c.x,c.y); await p.waitForTimeout(300);
 await p.click('.win .tab:has-text("Règles de filtrage")'); await p.waitForTimeout(300);
 await p.screenshot({path:'/tmp/d1.png'});
 await p.click('.win .tab:has-text("Journal")'); await p.waitForTimeout(300); await p.screenshot({path:'/tmp/d2.png'});
 console.log('errs',errs); await b.close();
})();
