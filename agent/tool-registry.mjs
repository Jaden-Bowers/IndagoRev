// Model-facing contracts are deliberately separate from native transport envelopes.
export const string=(description='',maxLength=4096)=>({type:'string',minLength:1,maxLength,description});
export const integer=(minimum=0,maximum=100000)=>({type:'integer',minimum,maximum});
export const enumeration=(...values)=>({type:'string',enum:values});
export const array=(items,maxItems=32)=>({type:'array',items,maxItems});
export const object=(properties={},required=[])=>({type:'object',properties,required,additionalProperties:false});
export const boolean={type:'boolean'};
export const location=string('Hexadecimal virtual address, current function, or selection. Never a file offset.',64);

export function validate(schema,value,at='input'){
 if(schema.const!==undefined&&value!==schema.const)throw Error(`${at}: expected ${schema.const}`);
 if(schema.enum&&!schema.enum.includes(value))throw Error(`${at}: expected one of ${schema.enum.join(', ')}`);
 const types=Array.isArray(schema.type)?schema.type:[schema.type];
 const matches=t=>t===undefined||t==='null'&&value===null||t==='object'&&value!==null&&typeof value==='object'&&!Array.isArray(value)||t==='array'&&Array.isArray(value)||t==='integer'&&Number.isSafeInteger(value)||t==='number'&&typeof value==='number'&&Number.isFinite(value)||t==='string'&&typeof value==='string'||t==='boolean'&&typeof value==='boolean';
 if(!types.some(matches))throw Error(`${at}: expected ${types.join('/')}`);
 if(typeof value==='string'){
  if(value.length<(schema.minLength??0)||value.length>(schema.maxLength??Infinity)||schema.pattern&&!new RegExp(schema.pattern).test(value))throw Error(`${at}: invalid length or format`);
 }
 if(typeof value==='number'&&(value<(schema.minimum??-Infinity)||value>(schema.maximum??Infinity)))throw Error(`${at}: out of bounds`);
 if(Array.isArray(value)){if(value.length<(schema.minItems??0)||value.length>(schema.maxItems??Infinity))throw Error(`${at}: invalid item count`);value.forEach((v,i)=>validate(schema.items??{},v,`${at}[${i}]`));}
 else if(value&&typeof value==='object'){
  if(Object.keys(value).length>(schema.maxProperties??Infinity))throw Error(`${at}: too many properties`);
  for(const k of schema.required??[])if(!Object.hasOwn(value,k))throw Error(`${at}: missing ${k}`);
  for(const [k,v] of Object.entries(value)){
   if(Object.hasOwn(schema.properties??{},k))validate(schema.properties[k],v,`${at}.${k}`);
   else if(schema.additionalProperties===false)throw Error(`${at}: unknown field ${k}`);
   else if(typeof schema.additionalProperties==='object')validate(schema.additionalProperties,v,`${at}.${k}`);
  }
 }
}

export class ToolRegistry {
 constructor(){this.entries=new Map();}
 add(entry){
  if(this.entries.has(entry.name))throw Error(`Duplicate tool ${entry.name}`);
  if(!entry.schema||!entry.group||!entry.description||!entry.route||!entry.effect)throw Error(`Incomplete tool contract: ${entry.name}`);
  this.entries.set(entry.name,Object.freeze(entry));return this;
 }
 get(name){const e=this.entries.get(name);if(!e)throw Error(`Unknown tool: ${name}`);return e;}
 list(){return [...this.entries.values()];}
 coverage(catalog){
  const rows=[];
  for(const b of catalog.backends??[])for(const operation of b.operations??[]){
   const tools=this.list().filter(e=>e.route.kind==='analysis'&&e.route.backend===b.name&&e.route.operation===operation).map(e=>e.name);
   rows.push({family:b.name,operation,status:!b.available?'unavailable':tools.length?'direct':'advanced-only',tools});
  }
  for(const [family,operations] of Object.entries(catalog.workbench?.families??{}))for(const operation of operations){
   const tools=this.list().filter(e=>e.route.family===family&&e.route.operation===operation).map(e=>e.name);
   rows.push({family,operation,status:tools.length?'direct':'advanced-only',tools});
  }
  for(const operation of catalog.runtime?.operations??[]){const tools=this.list().filter(e=>e.route.kind==='runtime'&&e.route.operation===operation).map(e=>e.name);rows.push({family:'runtime',operation,status:tools.length?'direct':'advanced-only',tools});}
  for(const [family,operations] of Object.entries(catalog.harness?.read_families??{}))for(const operation of operations){
   const tools=this.list().filter(e=>e.route.kind==='workflow'&&e.route.family===family&&e.route.operation===operation).map(e=>e.name);
   const delegated={knowledge:['show','list'],graph:['search','packet','neighborhood'],coverage:['report'],evidence:['show'],artifact:['route'],investigation:['tools']}[family]?.includes(operation);
   rows.push({family:'harness.read/'+family,operation,status:tools.length?'direct':delegated?'shared-adapter':'advanced-only',tools,reason:delegated?'Existing project-bound adapter or preflight provides this surface':undefined});
  }
  for(const operation of catalog.harness?.operations??[])rows.push({family:'harness.controller',operation,status:['profile','explore','finish','transfer'].includes(operation)?'operator-only':'controller-managed',tools:[],reason:'External-owner lifecycle and proof/ownership grants are not arbitrary model arguments'});
  return rows;
 }
}
