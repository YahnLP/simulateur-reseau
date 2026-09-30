const {open,scenario,dev}=require('./gen');
const fs=require('fs');
(async()=>{
 const {b,p,errs}=await open(1500,950);
 await scenario(p,'VLAN, trunk');
 // console SW1
 const c=await dev(p,'SW1'); await p.mouse.dblclick(c.x,c.y); await p.waitForTimeout(300);
 const send=async(t,w=200)=>{await p.fill('.win .tin',t);await p.press('.win .tin','Enter');await p.waitForTimeout(w);};
 await p.press('.win .tin','Enter'); 
 await send('en'); await send('conf t'); await send('vlan 10'); await send('name COMPTA'); await send('exit'); await send('int fa0/1'); await send('switchport mode acc'); await send('switchport access vlan 10'); await send('end');
 // ? et tab
 await p.fill('.win .tin','sh vl'); await p.press('.win .tin','Tab'); console.log('tab ->',await p.inputValue('.win .tin'));
 await p.fill('.win .tin','show ?'); await p.press('.win .tin','?'); 
 await p.fill('.win .tin','show vlan brief'); await p.press('.win .tin','Enter'); await p.waitForTimeout(300);
 console.log((await p.evaluate(()=>document.querySelector('.win .tout').textContent)).slice(-700));
 // fiche technique
 await p.click('.win .tab:has-text("Fiche technique")'); await p.waitForTimeout(200); await p.screenshot({path:'/tmp/m1.png'});
 await p.click('.win .wclose');
 // sauvegarde
 const [dl]=await Promise.all([p.waitForEvent('download'),p.click('#btn-save')]); await dl.saveAs('/tmp/plan.json');
 const j=JSON.parse(fs.readFileSync('/tmp/plan.json','utf8')); console.log('saved devices',j.devices.length,'links',j.links.length,'tp',j.tp);
 // nouveau + recharge
 await p.click('#btn-new'); await p.click('.modal >> text=Confirmer'); await p.waitForTimeout(200); console.log('après nouveau',await p.evaluate(()=>__app.sim.devices.size));
 await p.setInputFiles('#filein','/tmp/plan.json'); await p.waitForTimeout(800); console.log('après ouvrir',await p.evaluate(()=>__app.sim.devices.size));
 // vlan conservé ?
 const ok=await p.evaluate(()=>{const s=[...__app.sim.devices.values()].find(d=>d.name==='SW1'); return s.vlans.has(10)&&s.ports.find(x=>x.name==='FastEthernet0/1').vlan===10;});
 console.log('vlan restauré',ok);
 // aide
 await p.click('#btn-help'); await p.click('.modal .tab:has-text("Couverture")'); await p.waitForTimeout(200); await p.screenshot({path:'/tmp/m2.png'}); await p.click('.modal >> text=Fermer');
 // vérifier TP
 await p.evaluate(()=>__app.tpCurrent.solve(__app.sim)); await p.click('#tppane >> text=Vérifier mon travail'); await p.waitForTimeout(2500);
 console.log(await p.evaluate(()=>document.querySelector('.tpres').innerText));
 console.log('errs',errs); await b.close();
})();
