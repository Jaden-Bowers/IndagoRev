// Public documentation must not contain machine-specific home directories.
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');
const files=[];
function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,e.name);if(e.isDirectory())walk(p);else if(e.name.endsWith('.md'))files.push(p);}}
for(const dir of ['docs','kb'])walk(path.join(root,dir));
for(const e of fs.readdirSync(root,{withFileTypes:true}))if(e.isFile()&&e.name.endsWith('.md'))files.push(path.join(root,e.name));
const bad=[];
for(const file of files)fs.readFileSync(file,'utf8').split(/\r?\n/).forEach((line,i)=>{
 if(/[A-Z]:[\\/]Users[\\/]|(?:^|[\s(`])\/home\/[a-z0-9_.-]+\/|\/Users\/[^/]+\/|[A-Z]:[\\/]Documents and Settings[\\/]|[A-Za-z0-9._%+-]+@flare-on\.(?:com|net)/i.test(line))bad.push(`${path.relative(root,file)}:${i+1}`);
});
if(bad.length){console.error('Documentation privacy/portability failures:\n'+bad.join('\n'));process.exitCode=1;}
else console.log(`Public documentation portability passed (${files.length} files).`);
