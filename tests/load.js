// charge les fichiers du moteur dans un contexte node
const fs=require('fs'),vm=require('vm'),path=require('path');
module.exports=function(files){
  const root=path.join(__dirname,'..','js');
  const ctx=globalThis; ctx.window=undefined;
  (files||['util','catalog','codec','codec_mgmt','codec_ip6','codec_vpn','codec_aaa','codec_voip','sim','qos','stack','services','tools','mgmt','ip6','vpn','radius','voip','dot1x','stp','lag','ospf','devices','ioscli','ioscli_l2','ioscli_l3','ioscli_mgmt','ioscli_ip6','ioscli_vpn','ioscli_aaa','aos','ioscli_qos','host_persist','hostshell','hostshell_mgmt','hostshell_ip6','hostshell_aaa','hostshell_voip','cyber','analyzer','topology','scenarios']).forEach(f=>{
    const p=path.join(root,f+'.js'); if(!fs.existsSync(p)) return;
    vm.runInThisContext(fs.readFileSync(p,'utf8'),{filename:p});
  });
  return globalThis.NS;
};
