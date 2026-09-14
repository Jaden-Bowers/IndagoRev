// Bounded byte operations, not target execution. No eval or shell interpolation.
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
export function pngTail(bytes) {
  if(bytes.length>33554432)throw Error('32 MiB input limit');
  if(!bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))throw Error('Not PNG framing');
  let offset=8,seenHeader=false;
  for(let count=0;count<100000;count++){
    if(offset+12>bytes.length)throw Error('Truncated PNG chunk or missing IEND');
    const length=bytes.readUInt32BE(offset),type=bytes.toString('ascii',offset+4,offset+8),end=offset+length+12;
    if(end>bytes.length)throw Error('Truncated PNG chunk');
    if(!seenHeader){if(type!=='IHDR'||length!==13)throw Error('Missing initial IHDR');seenHeader=true;}
    if(type==='IEND'){
      if(length!==0)throw Error('Invalid IEND length');
      return {offset:end,bytes:bytes.subarray(end),validation:'Chunk framing only; CRC and decoded pixels not verified'};
    }
    offset=end;
  }
  throw Error('Chunk count limit');
}
export function strings(bytes) {
  const rows=[];
  for(const [encoding,step] of [['ascii',1],['utf16le',2]]) for(let i=0;i<bytes.length && rows.length<2000;) {
    let j=i;
    while(j<bytes.length && bytes[j]>=32 && bytes[j]<=126 && (step===1 || bytes[j+1]===0))j+=step;
    if(j-i>=step*5)rows.push({offset:i,encoding,text:bytes.subarray(i,Math.min(j,i+step*300)).toString(encoding==='ascii'?'ascii':'utf16le')});
    i=j>i?j:i+1;
  }
  return rows;
}
export function phpLiteral(s,quote='"') {
  let out='';
  for(let i=0;i<s.length;i++){
    if(s[i]!=='\\'){out+=s[i];continue;}
    const n=s[i+1];
    if(n==='\\'||n===quote || (quote==='"'&&n==='$')){out+=n;i++;continue;}
    if(quote==='"'){
      const simple={n:'\n',r:'\r',t:'\t',v:'\v',e:'\x1b',f:'\f'};
      if(n in simple){out+=simple[n];i++;continue;}
      const hex=s.slice(i+1).match(/^x([0-9a-fA-F]{1,2})/);
      const oct=s.slice(i+1).match(/^([0-7]{1,3})/);
      if(hex){out+=String.fromCharCode(parseInt(hex[1],16));i+=hex[0].length;continue;}
      if(oct){out+=String.fromCharCode(parseInt(oct[1],8)&255);i+=oct[0].length;continue;}
    }
    out+='\\';
  }
  return out;
}
if(process.argv[1]===fileURLToPath(import.meta.url)) {
  const [op,file,output]=process.argv.slice(2);
  if(!['strings','png-tail'].includes(op)||!file)throw Error('Usage: node helper.mjs strings FILE | png-tail FILE NEW_OUTPUT');
  if(fs.statSync(file).size>32*1024*1024)throw Error('32 MiB input limit');
  const input=fs.readFileSync(file);
  if(op==='strings')console.log(JSON.stringify(strings(input)));
  else {
    if(!output||fs.existsSync(output)||fs.existsSync(output+'.lineage.json'))throw Error('Choose a new output and lineage filename');
    const tail=pngTail(input),sha=b=>createHash('sha256').update(b).digest('hex');
    const receipt={operation:'png-tail',parent_sha256:sha(input),offset:tail.offset,bytes:tail.bytes.length,sha256:sha(tail.bytes),validation:tail.validation};
    fs.writeFileSync(output,tail.bytes,{flag:'wx'});
    fs.writeFileSync(output+'.lineage.json',JSON.stringify(receipt,null,2),{flag:'wx'});
    console.log(JSON.stringify(receipt));
  }
}
