const { chromium } = require('playwright');
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome',args:['--no-sandbox']});
 const p=await (await b.newContext({viewport:{width:1280,height:720}})).newPage(); const errs=[];
 p.on('pageerror',e=>errs.push('PAGEERR '+e.message+' '+(e.stack||'').split('\n')[1])); p.on('console',m=>{if(m.type()==='error')errs.push('CONSOLE '+m.text())});
 await p.goto('file:///home/claude/sim/dist/simulateur-reseau.html'); await p.waitForTimeout(300);
 const n=await p.evaluate(()=>NS.SCENARIOS.length);
 for(let i=0;i<n;i++){
   await p.click('#btn-scen'); const items=await p.locator('.ctxmenu .mitem').all(); await items[i].click(); await p.waitForTimeout(200);
   if(await p.locator('.modal >> text=Confirmer').count()) await p.click('.modal >> text=Confirmer'); await p.waitForTimeout(400);
   await p.evaluate(()=>{ if(__app.tpCurrent.solve) __app.tpCurrent.solve(__app.sim); __app.refresh(); });
   await p.click('#tppane >> text=Vérifier mon travail'); await p.waitForTimeout(3500);
   const t=await p.evaluate(()=>document.querySelector('.tpres p').innerText);
   console.log((await p.evaluate(()=>__app.tpCurrent.id)).padEnd(14),t);
   if(i===2) await p.screenshot({path:'/tmp/all_vlan.png'});
 }
 console.log('errs',errs); await b.close();
})();
