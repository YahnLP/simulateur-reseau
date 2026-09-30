const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox'] }).catch(async () => chromium.launch({ args: ['--no-sandbox'] }));
  const p = await b.newPage({ viewport: { width: 1500, height: 900 } });
  const errs = []; p.on('pageerror', e => errs.push('PAGEERR ' + e.message + '\n' + (e.stack||'').split('\n').slice(0,3).join('\n'))); p.on('console', m => { if (m.type() === 'error') errs.push('CONSOLE ' + m.text()); });
  await p.goto('file:///home/claude/sim/index.html'); await p.waitForTimeout(800);
  await p.screenshot({ path: '/tmp/s0.png' });
  console.log('errs after load:', errs);
  await b.close();
})();
