const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox'] });
  const p = await b.newPage({ viewport: { width: 1500, height: 950 } });
  const errs = []; p.on('pageerror', e => errs.push('PAGEERR ' + e.message + '\n' + (e.stack||'').split('\n').slice(0,4).join('\n'))); p.on('console', m => { if (m.type() === 'error') errs.push('CONSOLE ' + m.text()); });
  await p.goto('file:///home/claude/sim/index.html'); await p.waitForTimeout(500);
  await p.click('#btn-scen'); await p.click('text=Réseau local'); await p.waitForTimeout(600);
  await p.screenshot({ path: '/tmp/s1.png' });
  // solution
  await p.evaluate(() => { __app.tpCurrent.solve(__app.sim); __app.refresh(); });
  // ouvrir PC1 par double-clic
  const box = await p.evaluate(() => { const n = document.querySelector('.node[data-id]'); const d = [...__app.sim.devices.values()].find(x => x.name === 'PC1'); const el = __app.nodes.get(d.id); const r = el.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; });
  await p.mouse.dblclick(box.x, box.y); await p.waitForTimeout(400);
  await p.screenshot({ path: '/tmp/s2.png' });
  await p.fill('.win .tin', 'ping 192.168.1.12'); await p.press('.win .tin', 'Enter');
  await p.waitForTimeout(6000);
  await p.screenshot({ path: '/tmp/s3.png' });
  console.log(await p.evaluate(() => document.querySelector('.win .tout').textContent.slice(-400)));
  console.log('captures', await p.evaluate(() => __app.sim.captures.length));
  console.log('errs:', errs);
  await b.close();
})();
