// utilitaire commun aux tests UI
const { chromium } = require('playwright');
exports.open = async (w=1500,h=950) => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox'] });
  const ctx = await b.newContext({ viewport: { width: w, height: h }, acceptDownloads: true });
  const p = await ctx.newPage(); const errs = [];
  p.on('pageerror', e => errs.push('PAGEERR ' + e.message + '\n' + (e.stack||'').split('\n').slice(0,4).join('\n'))); p.on('console', m => { if (m.type() === 'error') errs.push('CONSOLE ' + m.text()); });
  await p.goto('file:///home/claude/sim/index.html'); await p.waitForTimeout(400);
  return { b, p, errs };
};
exports.scenario = async (p, title) => { await p.click('#btn-scen'); await p.click('.ctxmenu >> text=' + title); await p.waitForTimeout(200); if (await p.locator('.modal >> text=Confirmer').count()) await p.click('.modal >> text=Confirmer'); await p.waitForTimeout(500); };
exports.dev = async (p, name) => p.evaluate(n => { const d = [...__app.sim.devices.values()].find(x => x.name === n); const r = __app.nodes.get(d.id).getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; }, name);
