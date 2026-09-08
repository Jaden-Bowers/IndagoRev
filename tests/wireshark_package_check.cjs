// No capture input yet: inspect the pinned offline worker with private config.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [directory,plugins]=process.argv.slice(2);
const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'indago-wireshark-preflight-'));
const emptyPlugins=path.join(scratch,'empty-plugins');fs.mkdirSync(emptyPlugins);
const env={...process.env,WIRESHARK_CONFIG_DIR:scratch,WIRESHARK_PLUGIN_DIR:plugins?path.resolve(plugins):emptyPlugins,WIRESHARK_DATA_DIR:scratch,WIRESHARK_EXTCAP_DIR:path.join(scratch,'no-extcap')};
delete env.WIRESHARK_RUN_FROM_BUILD_DIRECTORY;
for(const args of [['--version'],['-G','plugins']]){
 const result=spawnSync(path.resolve(directory,'tshark.exe'),args,{env,cwd:scratch,encoding:'utf8',timeout:20000,maxBuffer:65536});
 assert.ifError(result.error);assert.equal(result.status,0,result.stdout+result.stderr);
 if(args[0]==='--version'){assert.match(result.stdout,/TShark \(Wireshark\) 4\.6\.8/);console.log(result.stdout.trim());}
 else {assert.equal(result.stdout.trim(),'','Unexpected native/Lua plugin');console.log('No external native or Lua plugins loaded');}
}
console.log(JSON.stringify({status:'passed',scratch,traffic_captured:false,packet_input_read:false,system_installer_run:false}));
