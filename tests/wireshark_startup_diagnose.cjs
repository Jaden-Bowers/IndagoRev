// Bounded debugger diagnostic for the pinned analysis worker, never packet input.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [indago,directory,plugins]=process.argv.slice(2);
const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'indago-wireshark-debug-'));
const env={...process.env,WIRESHARK_CONFIG_DIR:scratch,WIRESHARK_PLUGIN_DIR:path.resolve(plugins),WIRESHARK_DATA_DIR:scratch,WIRESHARK_EXTCAP_DIR:path.join(scratch,'no-extcap')};
delete env.WIRESHARK_RUN_FROM_BUILD_DIRECTORY;
function call(args){const r=spawnSync(path.resolve(indago),['--workspace',scratch,...args],{env,encoding:'utf8',timeout:15000,maxBuffer:1048576});if(r.error)throw r.error;const result=JSON.parse(r.stdout);console.log(JSON.stringify({command:args.slice(0,2),exit:r.status,result}));return result;}
call(['project','create','--name','worker']);
const request=path.join(scratch,'launch.json');fs.writeFileSync(request,JSON.stringify({argv:['--version'],cwd:scratch,lifetime_ms:30000,timeout_ms:3000}));
let session;
try{
 session=call(['runtime','launch','--project','worker','--file',path.resolve(directory,'tshark.exe'),'--request',request]);
 if(!session.id)throw Error('No debugger session');
 const common=['--project','worker','--session',session.id];
 for(let i=0;i<3;i++){
  const stopped=call(['runtime','continue',...common,'--wait','true','--timeout-ms','3000']);
  if(stopped.state==='exited'||stopped.state==='failed')break;
  if(stopped.state==='stopped'){call(['runtime','crash',...common]);call(['runtime','stack',...common]);break;}
 }
}finally{if(session?.id)call(['runtime','terminate','--project','worker','--session',session.id]);}
console.log(JSON.stringify({workspace:scratch,scope:'pinned tshark --version startup only'}));
