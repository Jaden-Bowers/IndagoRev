import fs from 'node:fs';
import path from 'node:path';
import {Native} from './native.mjs';
import {ToolAdapters} from './tool-adapters.mjs';
// Read-only native capability audit. Writes only explicitly requested local report.
const args=Object.fromEntries(process.argv.slice(2).reduce((a,v,i,all)=>i%2?a:[...a,[v.replace(/^--/,''),all[i+1]]],[]));
if(!args.exe||!args.state)throw Error('Usage: node agent/tool-audit.mjs --exe INDAGO --state STATE [--output REPORT]');
const config={exe:path.resolve(args.exe),state:path.resolve(args.state),workspace:path.join(path.resolve(args.state),'native'),project:'tool_audit'};
const native=new Native(config),catalog=(await native.capabilities()).data,adapters=new ToolAdapters(native,{...config,toolCapabilities:catalog});
const rows=adapters.registry.coverage(catalog),unmapped=rows.filter(r=>r.status==='advanced-only');
const report={schema:'indago.agent-tool-coverage.v1',tool_count:adapters.registry.list().length,rows,unmapped,operator_only:['benchmark grading/freezing','evaluation administration','guest provisioning/reset profiles','project provisioning','builtin model inference','installing payloads'],limits:'Adapter presence does not certify engine availability, semantics or challenge coverage.'};
if(args.output)fs.writeFileSync(path.resolve(args.output),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({tool_count:report.tool_count,operations:rows.length,unmapped}));
if(unmapped.length)process.exitCode=1;
