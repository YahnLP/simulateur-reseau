const {NS,Sim}=require('./helpers');
let bad=0;
for(const sc of NS.SCENARIOS){
  const sim=new Sim(); sc.build(sim); sim.runFor(5000);
  const c0=NS.checker(sim); const before=sc.checks.map(k=>{try{return !!k.run(c0)}catch(e){return 'ERR '+e.message}});
  if(sc.solve){ sc.solve(sim); }
  sim.runFor(3000);
  const c=NS.checker(sim); const after=sc.checks.map(k=>{try{return !!k.run(c)}catch(e){return 'ERR '+e.stack.split('\n').slice(0,3).join('|')}});
  const ok=after.every(x=>x===true); if(!ok) bad++;
  console.log((ok?'PASS ':'FAIL ')+sc.id+'  avant='+JSON.stringify(before)+' après='+JSON.stringify(after)+(sim.halted?' HALT '+sim.halted:''));
}
console.log(bad?('ECHECS '+bad):'tous les TP OK');
