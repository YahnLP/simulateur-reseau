// Assemble index.html + css + js en un seul fichier autonome : dist/simulateur-reseau.html
const fs=require('fs'),path=require('path');
const root=path.join(__dirname,'..');
let html=fs.readFileSync(path.join(root,'index.html'),'utf8');
html=html.replace(/<link rel="stylesheet" href="([^"]+)">/g,(m,f)=>'<style>\n'+fs.readFileSync(path.join(root,f),'utf8')+'\n</style>');
html=html.replace(/<script src="([^"]+)"><\/script>/g,(m,f)=>'<script>\n'+fs.readFileSync(path.join(root,f),'utf8').replace(/<\/script>/gi,'<\\/script>')+'\n</script>');
fs.mkdirSync(path.join(root,'dist'),{recursive:true});
fs.writeFileSync(path.join(root,'dist','simulateur-reseau.html'),html);
console.log('dist/simulateur-reseau.html',(html.length/1024).toFixed(0)+' Ko');
