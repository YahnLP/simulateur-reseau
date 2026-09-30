const { chromium } = require('playwright');
(async()=>{
 const b=await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome',args:['--no-sandbox']});
 const p=await (await b.newContext({viewport:{width:1280,height:800}})).newPage(); const errs=[];
 p.on('pageerror',e=>errs.push('PAGEERR '+e.message+' '+(e.stack||'').split('\n')[1])); p.on('console',m=>{if(m.type()==='error')errs.push('CONSOLE '+m.text())});
 await p.goto('file:///home/claude/sim/index.html'); await p.waitForTimeout(300);
 const models=await p.evaluate(()=>Object.keys(NS.CATALOG));
 let x=100;
 for(const k of models){
   const r=await p.evaluate(async(k)=>{
     const d=__app.addDevice(k,100,100)||[...__app.sim.devices.values()].pop();
     __app.openDevice(d);
     const w=[...document.querySelectorAll('.win')].pop(); const out=[];
     const tabs=[...w.querySelectorAll('.tab')];
     for(const t of tabs){ try{ t.click(); await new Promise(r=>setTimeout(r,60)); out.push(t.innerText);}catch(e){out.push('ERR '+t.innerText+' '+e.message)} }
     await new Promise(r=>setTimeout(r,1000));
     w.querySelector('.wclose').click();
     return out.join('|');
   },k).catch(e=>'EVALERR '+e.message);
   console.log(k.padEnd(14),r);
 }
 console.log('errs',errs); await b.close();
})();
