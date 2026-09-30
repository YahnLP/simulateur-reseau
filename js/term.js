/* term.js — terminal (console) branché sur une session IOS ou shell hôte */
(function (g) {
'use strict';
const NS = g.NS = g.NS || {};
const { h, clear } = NS;

NS.Terminal = function (dev, opts) {
  opts = opts || {};
  const sess = dev._sess || (dev._sess = dev.newSession());
  const out = h('pre.tout', { tabindex: '-1' });
  const prompt = h('span.tprompt');
  const inp = h('input.tin', { type: 'text', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off', 'aria-label': 'Ligne de commande de ' + dev.name });
  const line = h('div.tline', prompt, inp);
  const root = h('div.term', { onclick: (e) => { if (!window.getSelection().toString()) inp.focus(); } }, out, line);
  let busy = false, hist = sess.history || [], hi = hist.length, buf = '';
  const isIos = typeof sess.complete === 'function';
  function print(t) { if (!t) return; out.appendChild(document.createTextNode(t)); if (out.childNodes.length > 800) { out.removeChild(out.firstChild); } scroll(); }
  function scroll() { root.scrollTop = root.scrollHeight; }
  function setPrompt() { const p = sess.prompt(); prompt.textContent = p; inp.type = sess.masking ? 'password' : 'text'; scroll(); }
  const io = {
    print, clear() { clear(out); },
    done() { busy = false; line.style.visibility = ''; setPrompt(); inp.focus({ preventScroll: true }); if (opts.onIdle) opts.onIdle(); },
  };
  function run(l) {
    const masked = sess.masking;
    print(sess.prompt() + (masked ? '' : l) + '\n');
    busy = true; hist = sess.history; hi = hist.length;
    if (sess.remote) { line.style.visibility = ''; }
    try { const r = sess.exec(l, io); } catch (e) { print('% Erreur interne : ' + e.message + '\n'); console.error(e); io.done(); }
    if (sess.closed) { print('\n[Session terminée — appuyez sur Entrée pour rouvrir]\n'); sess.closed = false; sess.mode = 'user'; sess.ctx = null; setPrompt(); }
  }
  inp.addEventListener('keydown', e => {
    if (e.ctrlKey && (e.key === 'c' || e.key === 'C')) { if (busy) { if (sess.abort) sess.abort(); print('^C\n'); } else { print(sess.prompt() + inp.value + '^C\n'); inp.value = ''; if (sess.mode !== 'user' && sess.mode !== 'priv' && isIos) { sess.mode = 'priv'; sess.ctx = null; setPrompt(); } } e.preventDefault(); return; }
    if (e.ctrlKey && (e.key === 'l' || e.key === 'L')) { clear(out); e.preventDefault(); return; }
    if (e.ctrlKey && (e.key === 'z' || e.key === 'Z') && isIos) { if (!busy) { sess.mode = 'priv'; sess.ctx = null; print('\n'); setPrompt(); } e.preventDefault(); return; }
    if (e.key === 'Enter') {
      if (busy && !sess.remote) { e.preventDefault(); return; }
      const l = inp.value; inp.value = ''; run(l); e.preventDefault(); return;
    }
    if (e.key === 'ArrowUp') { if (hi > 0) { if (hi === hist.length) buf = inp.value; hi--; inp.value = hist[hi]; } e.preventDefault(); return; }
    if (e.key === 'ArrowDown') { if (hi < hist.length) { hi++; inp.value = hi === hist.length ? buf : hist[hi]; } e.preventDefault(); return; }
    if (e.key === 'Tab' && isIos && !busy) {
      e.preventDefault(); const r = sess.complete(inp.value);
      if (typeof r === 'string') inp.value = r; else if (Array.isArray(r)) print(sess.prompt() + inp.value + '\n' + r.join('  ') + '\n');
      return;
    }
    if (e.key === '?' && isIos && !busy) {
      e.preventDefault(); const r = sess.help ? sess.help(inp.value) : []; print(sess.prompt() + inp.value + '?\n' + (Array.isArray(r) ? r.map(x => '  ' + String(x[0]).padEnd(20) + (x[1] || '')).join('\n') + (r.length ? '\n' : '') : String(r || '')));
      return;
    }
  });
  const api = {
    el: root, focus() { inp.focus(); },
    /* exécute des commandes comme si l'utilisateur les tapait */
    runLines(lines, then) {
      const arr = Array.isArray(lines) ? lines.slice() : [lines];
      const step = () => { if (!arr.length) { if (then) then(); return; } if (busy && !sess.remote) { setTimeout(step, 100); return; } run(arr.shift()); setTimeout(step, 30); };
      step();
    },
    session: sess,
  };
  if (!dev._termBanner) {
    dev._termBanner = true;
    if (sess.constructor && dev.newSession && isIos) print('\n' + dev.name + ' — console\nAppuyez sur Entrée pour commencer.  (Tab : compléter, ? : aide, Ctrl+C : interrompre)\n\n');
    else print('Simulateur — terminal de ' + dev.name + ' (' + (dev.os === 'windows' ? 'Windows' : 'Linux') + '). Tapez « help » pour la liste des commandes. Ctrl+C interrompt une commande.\n\n');
  }
  setPrompt();
  return api;
};
})(typeof window !== 'undefined' ? window : globalThis);
