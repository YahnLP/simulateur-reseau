const {NS,Sim}=require('./helpers');
const {IP}=NS;
function mk(sim){const dev=(m,n,x,y)=>NS.createDevice(sim,m,{name:n,x,y});const get=n=>Array.from(sim.devices.values()).find(d=>d.name===n);const link=(a,pa,b,pb)=>sim.connect(get(a).findPort(pa),get(b).findPort(pb),'auto');return{dev,get,link};}
function run(dev,line){return new Promise((res)=>{const s=dev.newSession();let out='';s.exec(line,{print:t=>out+=t,done:()=>res(out),clear(){}});});}

async function main(){
  let bad=0;
  // --- nmap
  {
    const sim=new Sim(); const {dev,get,link}=mk(sim);
    dev('pc-linux','ATT',100,100); dev('srv-linux','SRV',300,100); dev('sw-8p','SW',200,200);
    link('ATT','ens33','SW','port1'); link('SRV','ens33','SW','port2');
    get('ATT').applyIp('ens33',{ip:'10.0.0.10',mask:'24'}); get('SRV').applyIp('ens33',{ip:'10.0.0.20',mask:'24'});
    get('SRV').httpd.start(); sim.runFor(2000);
    const p=run(get('ATT'),'nmap 10.0.0.20');
    sim.runFor(6000);
    const out=await p;
    console.log('--- nmap ---\n'+out);
    if(!/80\/tcp\s+open/.test(out)) { console.log('FAIL nmap: port 80 pas détecté ouvert'); bad++; }
    if(!/22\/tcp\s+closed|filtered/.test(out)) { /* informational */ }
  }
  // --- arpspoof
  {
    const sim=new Sim(); const {dev,get,link}=mk(sim);
    dev('pc-win','GW',100,100); dev('pc-linux','ATT',300,100); dev('pc-win','VICT',500,100); dev('sw-8p','SW',300,200);
    link('GW','eth0','SW','port1'); link('ATT','ens33','SW','port2'); link('VICT','eth0','SW','port3');
    get('GW').applyIp('eth0',{ip:'10.0.0.1',mask:'24'}); get('ATT').applyIp('ens33',{ip:'10.0.0.2',mask:'24'}); get('VICT').applyIp('eth0',{ip:'10.0.0.3',mask:'24'});
    sim.runFor(2000);
    // victim resolves gateway first, normally
    let ok=false; NS.tools.pingSeries(get('VICT'),IP.parse('10.0.0.1'),{count:1},r=>{if(r.type==='reply')ok=true;},()=>{});
    sim.runFor(3000);
    const before = get('VICT').arpGet(IP.parse('10.0.0.1'));
    console.log('avant spoof, mac appris pour la passerelle =', before && before.mac, 'devrait être celle de GW', get('GW').mainIface.mac);
    const p = run(get('ATT'), 'arpspoof 10.0.0.3 10.0.0.1');
    sim.runFor(4000);
    const after = get('VICT').arpGet(IP.parse('10.0.0.1'));
    console.log('après spoof, mac appris pour la passerelle =', after && after.mac, 'devrait être celle de ATT', get('ATT').mainIface.mac);
    if (!after || after.mac !== get('ATT').mainIface.mac) { console.log('FAIL arpspoof: cache non empoisonné'); bad++; }
    get('ATT')._shellAbort = true;
    const s2 = [...get('ATT').ports].length; // noop
  }
  // --- macflood + port-security countermeasure
  {
    const sim=new Sim(); const {dev,get,link}=mk(sim);
    dev('pc-linux','ATT',100,100); dev('sw-8p','SW',300,100);
    link('ATT','ens33','SW','port1');
    get('ATT').applyIp('ens33',{ip:'10.0.0.5',mask:'24'});
    sim.runFor(1000);
    const sw=get('SW'); const cap = sw.model_.macTableSize;
    console.log('capacité table MAC du switch =', cap);
    run(get('ATT'), 'macflood ' + (cap+500));
    sim.runFor(20000);
    console.log('taille table MAC après flood =', sw.macTable.size, '(<=', cap, '?)');
    if (sw.macTable.size > cap) { console.log('FAIL macflood: la table dépasse sa capacité déclarée'); bad++; }
    if (sw.macTable.size < cap*0.9) { console.log('FAIL macflood: la table ne s\'est pas remplie'); bad++; }
  }
  console.log(bad ? ('ECHECS '+bad) : 'tous les tests cyber OK');
  process.exit(bad?1:0);
}
main();
