const NS=require('./load')();
const {Sim,createDevice,IP}=NS;
function cli(sim,dev,cmds,opts){
  const s=dev.newSession(); let out='';
  const lines=Array.isArray(cmds)?cmds:cmds.split('\n');
  for(const l of lines){
    let done=false; const line=l.replace(/^\s+/,'');
    const io={print:t=>{out+=t;},done:()=>{done=true;}, clear(){}};
    if(opts&&opts.echo) out+='\n'+s.prompt()+line+'\n';
    s.exec(line,io);
    sim.runUntil(()=>done,60000);
    if(!done) out+='\n[TIMEOUT sur: '+line+']\n';
  }
  return out;
}
function host(sim,dev,cmd){ return cli(sim,dev,[cmd]); }
module.exports={NS,Sim,createDevice,IP,cli,host};
