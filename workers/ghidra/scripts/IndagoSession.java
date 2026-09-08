// Persistent, bounded JSON mailbox worker. One imported Program and DecompInterface per session.
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeManagerService;
import java.security.MessageDigest;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class IndagoSession extends HeadlessScript {
    private final Gson gson = new Gson();
    private DecompInterface decompiler;
    private int limit;
    private int textLimit;
    private boolean partial;
    private boolean analysisTimedOut;
    private TaskMonitorAdapter task;
    private JsonObject arguments;
    private JsonObject activeRequest;
    private int pageOffset, pageSize;
    private boolean closing;
    private String cursorBinding;
    private long revision() { return currentProgram.getOptions("Indago").getLong("revision",0); }
    private String digest(String text) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
    private String operationId(PcodeOp op) {return op==null?null:hex(op.getSeqnum().getTarget())+":"+op.getSeqnum().getTime();}
    private String varnodeId(Varnode v) {return v==null?null:v instanceof VarnodeAST?"vn_"+((VarnodeAST)v).getUniqueId():v.getAddress().getAddressSpace().getName()+":"+hex(v.getAddress())+":"+v.getSize()+":"+operationId(v.getDef());}
    private JsonObject varnode(Varnode v) {
        JsonArray uses=new JsonArray();Iterator<PcodeOp> it=v.getDescendants();while(it.hasNext()&&room(uses))uses.add(operationId(it.next()));
        return obj("id",varnodeId(v),"location",location(v.getAddress()),"size",v.getSize(),"constant",v.isConstant(),"register",v.isRegister(),"input",v.isInput(),"definition",operationId(v.getDef()),"uses",uses);
    }
    private JsonObject pcode(Function f,int seconds) {
        DecompileResults r=decompiler.decompileFunction(f,seconds,task);
        JsonArray ops=new JsonArray(),values=new JsonArray();Set<String> seen=new HashSet<>();
        if(r.getHighFunction()!=null){Iterator<PcodeOpAST> it=r.getHighFunction().getPcodeOps();while(it.hasNext()&&room(ops)){
            PcodeOp op=it.next();JsonArray inputs=new JsonArray();
            for(Varnode v:op.getInputs()){inputs.add(varnodeId(v));if(seen.add(varnodeId(v))&&room(values))values.add(varnode(v));}
            Varnode output=op.getOutput();if(output!=null&&seen.add(varnodeId(output))&&room(values))values.add(varnode(output));
            ops.add(obj("id",operationId(op),"location",location(op.getSeqnum().getTarget()),"opcode",op.getOpcode(),"mnemonic",op.getMnemonic(),"inputs",inputs,"output",varnodeId(output),"native_text",op.toString()));
        }}
        if(!r.decompileCompleted())partial=true;
        return obj("operations",ops,"varnodes",values,"native_verdict",r.decompileCompleted()?"completed":r.isTimedOut()?"timeout":r.isCancelled()?"cancelled":"failed","diagnostic",r.getErrorMessage(),"semantics","Ghidra HighFunction p-code; not XAIR IR; identifiers scoped to program revision and function");
    }
    private Address dataAddress(Data d) {
        Object value=d.getValue();if(value instanceof Address)return (Address)value;
        if(value instanceof ghidra.program.model.scalar.Scalar)return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(((ghidra.program.model.scalar.Scalar)value).getUnsignedValue());
        return null;
    }
    private Address pointerAt(Address at) throws Exception {
        int size=currentProgram.getDefaultPointerSize();if(size!=4&&size!=8)throw new IllegalArgumentException("pointer width unsupported");
        long value=size==8?currentProgram.getMemory().getLong(at):Integer.toUnsignedLong(currentProgram.getMemory().getInt(at));
        return value==0?null:at.getAddressSpace().getAddress(value);
    }
    private void pointerTable(Address table,String role,JsonArray out) {
        if(table==null)return;int width=currentProgram.getDefaultPointerSize();
        var region=currentProgram.getMemory().getBlock(table);if(region==null)return;
        for(int slot=0;slot<64&&room(out);++slot)try {
            Address cell=table.addNoWrap((long)slot*width);if(cell.addNoWrap(width-1).compareTo(region.getEnd())>0)break;Address target=pointerAt(cell);if(target==null)break;
            Function targetFunction=currentProgram.getFunctionManager().getFunctionAt(target);if(targetFunction==null)break;
            out.add(obj("location",location(cell),"from",hex(cell),"to",hex(target),"from_location",location(cell),"to_location",location(target),"table",location(table),"slot",slot,"role",role,"name",targetFunction.getName(),"native_verdict","mapped function pointer; execution not proven"));
            if(slot==63)partial=true;
        }catch(Exception error){partial=true;break;}
    }
    private void metadataRelations(Data d,Address owner,Function requested,JsonArray exceptions,JsonArray tls,Set<String> visited,int depth,int[] nodes) {
        if(d==null||depth>10||task.isCancelled()||++nodes[0]>4096){partial=true;return;}
        if(!visited.add(hex(d.getAddress())+":"+d.getLength()+":"+d.getDataType().getPathName()))return;
        int count=d.getNumComponents();if(count>256){count=256;partial=true;}
        for(int i=0;i<count;++i){Data child=d.getComponent(i);if(child!=null&&"BeginAddress".equals(child.getFieldName())){Address begin=dataAddress(child);if(begin!=null)owner=begin;}}
        String field=String.valueOf(d.getFieldName()).toLowerCase(Locale.ROOT);
        if(field.contains("addressofcallbacks"))pointerTable(dataAddress(d),"PE TLS callback",tls);
        if(field.contains("exceptionhandler")&&owner!=null&&requested.getEntryPoint().equals(owner)&&room(exceptions)){
            Address handler=dataAddress(d);if(handler!=null&&currentProgram.getMemory().contains(handler))exceptions.add(obj("from",hex(owner),"to",hex(handler),"from_location",location(owner),"to_location",location(handler),"location",location(d.getAddress()),"role","native unwind handler association","native_type",d.getDataType().getPathName(),"native_verdict","handler associated with protected function; exceptional execution not proven"));
        }
        if(field.contains("unwindinfo")&&owner!=null&&requested.getEntryPoint().equals(owner)){Address target=dataAddress(d);if(target!=null)metadataRelations(currentProgram.getListing().getDefinedDataAt(target),owner,requested,exceptions,tls,visited,depth+1,nodes);}
        for(int i=0;i<count;++i)metadataRelations(d.getComponent(i),owner,requested,exceptions,tls,visited,depth+1,nodes);
    }
    private Address constantPointer(Varnode value,int depth) {
        if(value==null||depth>8)return null;
        try {
            if(value.isConstant())return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.getOffset());
            PcodeOp def=value.getDef();if(def==null){if(value.getAddress().isMemoryAddress()&&value.getSize()==currentProgram.getDefaultPointerSize())return pointerAt(value.getAddress());return null;}
            if(def.getOpcode()==PcodeOp.COPY||def.getOpcode()==PcodeOp.CAST)return constantPointer(def.getInput(0),depth+1);
            if(def.getOpcode()==PcodeOp.LOAD){if(value.getSize()!=currentProgram.getDefaultPointerSize())return null;Address cell=constantPointer(def.getInput(1),depth+1);return cell==null?null:pointerAt(cell);}
            if(def.getOpcode()==PcodeOp.INT_ADD||def.getOpcode()==PcodeOp.PTRADD||def.getOpcode()==PcodeOp.PTRSUB){Address base=constantPointer(def.getInput(0),depth+1);Varnode offset=def.getInput(1);if(base==null||!offset.isConstant())return null;long displacement=offset.getOffset();if(def.getOpcode()==PcodeOp.PTRADD){if(!def.getInput(2).isConstant())return null;displacement=Math.multiplyExact(displacement,def.getInput(2).getOffset());}return base.addNoWrap(displacement);}
        }catch(Exception ignored){}return null;
    }
    private JsonObject controlFlow(Function f,int seconds) {
        JsonArray indirect=new JsonArray(),tables=new JsonArray();
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()&&room(indirect)){Instruction i=it.next();if(i.getFlowType().isComputed()){
            JsonArray targets=new JsonArray();for(Address a:i.getFlows())if(room(targets))targets.add(location(a));
            indirect.add(obj("location",location(i.getAddress()),"native_flow_type",i.getFlowType().toString(),"candidates",targets,"resolution",targets.isEmpty()?"unresolved":"backend candidates; not exhaustive proof"));
        }}
        DecompileResults r=decompiler.decompileFunction(f,seconds,task);
        if(r.getHighFunction()!=null)for(JumpTable table:r.getHighFunction().getJumpTables()){
            if(!room(tables))break;JsonArray cases=new JsonArray();for(Address a:table.getCases())if(room(cases))cases.add(location(a));
            tables.add(obj("location",location(table.getSwitchAddress()),"cases",cases,"labels",table.getLabelValues()));
        }
        if(!r.decompileCompleted())partial=true;
        JsonArray special=new JsonArray(),callbacks=new JsonArray(),exceptions=new JsonArray(),tls=new JsonArray(),dispatch=new JsonArray(),vtableSlots=new JsonArray();
        Set<String> visited=new HashSet<>();int[] nodes={0};
        DataIterator data=currentProgram.getListing().getDefinedData(true);int scanned=0;Address lsdaStart=null;long lsdaLength=0;
        while(data.hasNext()&&room(special)&&++scanned<=100000) {
            Data d=data.next();String name=d.getDataType().getPathName().toLowerCase(Locale.ROOT);
            String nativeComment=d.getComment(CodeUnit.EOL_COMMENT);
            if("(LSDA Call Site) IP Offset".equals(nativeComment)){lsdaStart=null;lsdaLength=0;for(Reference ref:d.getReferencesFrom())if(ref.getSource()==SourceType.ANALYSIS){lsdaStart=ref.getToAddress();break;}}
            else if("(LSDA Call Site) IP Range Length".equals(nativeComment)){Object value=d.getValue();lsdaLength=value instanceof ghidra.program.model.scalar.Scalar?((ghidra.program.model.scalar.Scalar)value).getUnsignedValue():value instanceof Number?((Number)value).longValue():0;}
            else if("(LSDA Call Site) Landing Pad Address".equals(nativeComment)){
                Object value=d.getValue();long offset=value instanceof ghidra.program.model.scalar.Scalar?((ghidra.program.model.scalar.Scalar)value).getUnsignedValue():value instanceof Number?((Number)value).longValue():0;
                if(offset!=0&&lsdaStart!=null&&lsdaLength>0&&f.getBody().contains(lsdaStart))for(Reference ref:d.getReferencesFrom())if(ref.getSource()==SourceType.ANALYSIS&&currentProgram.getMemory().contains(ref.getToAddress())&&room(exceptions))exceptions.add(obj("location",location(d.getAddress()),"from",hex(lsdaStart),"to",hex(ref.getToAddress()),"from_location",location(lsdaStart),"to_location",location(ref.getToAddress()),"protected_length",lsdaLength,"role","native GCC LSDA protected call-site to landing-pad association","native_verdict","Ghidra analyzer references; exception type/filter selection and actual execution unresolved"));
                lsdaStart=null;
            }else if(nativeComment==null||!nativeComment.startsWith("(LSDA Call Site)"))lsdaStart=null;
            var block=currentProgram.getMemory().getBlock(d.getAddress());String section=block==null?"":block.getName().toLowerCase(Locale.ROOT);
            boolean relevant=section.contains("tls")||section.equals(".pdata")||section.equals(".xdata")||section.contains("eh_frame")||section.contains("except")||name.contains("runtime_function")||name.contains("tls_directory");
            // Ghidra's PE TLSDirectory currently names its structure IMAGE_THUNK_DATA.
            // Identify its native callback field, not just the misleading type name.
            for(int component=0;component<Math.min(d.getNumComponents(),16);++component){Data field=d.getComponent(component);if(field!=null&&"AddressOfCallBacks".equalsIgnoreCase(field.getFieldName()))relevant=true;}
            if(relevant)special.add(obj("location",location(d.getAddress()),"size",d.getLength(),"type_path",d.getDataType().getPathName(),"section",section,"native_value",String.valueOf(d.getValue()),"interpretation","native defined metadata; section/type classification, not proof of an execution edge"));
            if(relevant&&nodes[0]<4096)metadataRelations(d,null,f,exceptions,tls,visited,0,nodes);
            if(section.contains("init_array")||section.contains("fini_array"))pointerTable(d.getAddress(),section.contains("fini")?"ELF finalizer":"ELF initializer",tls);
        }
        if(r.getHighFunction()!=null){Iterator<PcodeOpAST> ops=r.getHighFunction().getPcodeOps();int scannedOps=0;while(ops.hasNext()&&room(dispatch)&&++scannedOps<=100000){PcodeOp op=ops.next();if(op.getOpcode()!=PcodeOp.CALLIND)continue;Varnode input=op.getInput(0);Address target=constantPointer(input,0);Function resolved=target==null?null:currentProgram.getFunctionManager().getFunctionAt(target);dispatch.add(obj("location",location(op.getSeqnum().getTarget()),"operation_id",operationId(op),"target_value",varnodeId(input),"target_definition",operationId(input.getDef()),"target",resolved==null?null:location(target),"name",resolved==null?null:resolved.getName(),"native_verdict",resolved==null?"unresolved receiver/table or target":"constant p-code pointer chain resolves to mapped function","assumption","static program memory contents; writable tables may differ at runtime"));}if(scannedOps>=100000)partial=true;}
        SymbolIterator symbols=currentProgram.getSymbolTable().getSymbolIterator(true);int symbolBudget=0,tableBudget=0;while(symbols.hasNext()&&++symbolBudget<=100000&&tableBudget<32&&room(vtableSlots)){Symbol symbol=symbols.next();String name=symbol.getName().toLowerCase(Locale.ROOT);if(name.contains("vftable")||name.contains("vtable")||name.startsWith("_ztv")){++tableBudget;pointerTable(symbol.getAddress(),"named virtual table candidate; receiver compatibility not proven",vtableSlots);if(name.startsWith("_ztv"))try{pointerTable(symbol.getAddress().addNoWrap(2L*currentProgram.getDefaultPointerSize()),"Itanium primary address-point candidate",vtableSlots);}catch(Exception ignored){partial=true;}}}
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while(refs.hasNext()&&room(callbacks)){Reference ref=refs.next();if(!ref.getReferenceType().isCall()&&!ref.getReferenceType().isJump())callbacks.add(reference(ref,"incoming address-taken candidate; callback/virtual dispatch not proven"));}
        if(scanned>=100000)partial=true;
        return obj("indirect_flows",indirect,"jump_tables",tables,"special_metadata",special,"address_taken_candidates",callbacks,"exception_relations",exceptions,"initialization_callbacks",tls,"virtual_dispatch",dispatch,"virtual_table_slots",vtableSlots,"calling_convention",f.getCallingConventionName(),"signature_source",f.getSignatureSource().toString(),"no_return",f.hasNoReturn(),"diagnostic",r.getErrorMessage(),"native_verdict",r.decompileCompleted()?"completed":"partial","exception_tls_coverage","bounded native typed unwind associations, TLS/initializer pointer tables and p-code dispatch recovery; language-specific exception scopes and unknown receiver types may remain unresolved");
    }
    private JsonObject annotate(Function f) throws Exception {
        if(!arguments.has("expected_revision")||arguments.get("expected_revision").getAsLong()!=revision())throw new IllegalArgumentException("annotation requires current expected_revision");
        JsonObject change=arguments.getAsJsonObject("annotation");
        if(change==null||gson.toJson(change).length()>8192)throw new IllegalArgumentException("bounded annotation required");
        JsonArray history=JsonParser.parseString(currentProgram.getOptions("Indago").getString("annotations","[]")).getAsJsonArray();
        if(history.size()>=256)throw new IllegalArgumentException("annotation history budget reached");
        long before=revision();int tx=currentProgram.startTransaction("Indago annotation");boolean commit=false;
        try {
            switch(change.get("kind").getAsString()) {
                case "rename": f.setName(change.get("name").getAsString(),SourceType.USER_DEFINED);break;
                case "comment": f.setComment(change.get("text").getAsString());break;
                case "create_structure": {
                    String name=change.get("name").getAsString();int size=change.get("size").getAsInt();
                    if(size<1||size>65536)throw new IllegalArgumentException("structure size must be 1..65536");
                    CategoryPath category=new CategoryPath("/IndagoUser");
                    if(currentProgram.getDataTypeManager().getDataType(category,name)!=null)throw new IllegalArgumentException("type already exists");
                    StructureDataType structure=new StructureDataType(category,name,size,currentProgram.getDataTypeManager());
                    JsonArray fields=change.getAsJsonArray("fields");if(fields==null||fields.size()>256)throw new IllegalArgumentException("at most 256 fields required");
                    BitSet occupied=new BitSet(size);
                    for(JsonElement element:fields){JsonObject field=element.getAsJsonObject();int offset=field.get("offset").getAsInt();DataType type=currentProgram.getDataTypeManager().getDataType(field.get("type_path").getAsString());
                        if(type==null||type.getLength()<1||offset<0||offset>size-type.getLength())throw new IllegalArgumentException("invalid field extent/type");
                        int end=offset+type.getLength();if(occupied.nextSetBit(offset)>=0&&occupied.nextSetBit(offset)<end)throw new IllegalArgumentException("overlapping fields");occupied.set(offset,end);
                        structure.replaceAtOffset(offset,type,type.getLength(),field.get("name").getAsString(),null);
                    }
                    currentProgram.getDataTypeManager().addDataType(structure,DataTypeConflictHandler.DEFAULT_HANDLER);break;
                }
                case "signature": {
                    FunctionDefinitionDataType signature=CParserUtils.parseSignature((DataTypeManagerService)null,currentProgram,change.get("prototype").getAsString());
                    if(signature==null)throw new IllegalArgumentException("invalid signature");
                    ApplyFunctionSignatureCmd cmd=new ApplyFunctionSignatureCmd(f.getEntryPoint(),signature,SourceType.USER_DEFINED);
                    if(!cmd.applyTo(currentProgram,task))throw new IllegalArgumentException(cmd.getStatusMsg());break;
                }
                case "variable_type": {
                    DataType type=currentProgram.getDataTypeManager().getDataType(change.get("type_path").getAsString());
                    if(type==null)throw new IllegalArgumentException("unknown existing type_path");
                    DecompileResults r=decompiler.decompileFunction(f,Math.max(1,activeRequest.get("timeout_ms").getAsInt()/1000),task);
                    if(!r.decompileCompleted())throw new IllegalArgumentException("variable edit requires completed decompilation");
                    HighSymbol symbol=r.getHighFunction().getLocalSymbolMap().getSymbol(Long.parseUnsignedLong(change.get("symbol_id").getAsString()));
                    if(symbol==null)throw new IllegalArgumentException("unknown recovered symbol ID");
                    HighFunctionDBUtil.updateDBVariable(symbol,null,type,SourceType.USER_DEFINED);break;
                }
                default:throw new IllegalArgumentException("unknown annotation kind");
            }
            if(task.isCancelled())throw new IllegalStateException("cancelled before commit");
            history.add(obj("revision",before+1,"prior_revision",before,"function",hex(f.getEntryPoint()),"change",change,"authority","user annotation; not backend-inferred fact"));
            currentProgram.getOptions("Indago").setLong("revision",before+1);
            currentProgram.getOptions("Indago").setString("annotations",gson.toJson(history));commit=true;
        } finally {currentProgram.endTransaction(tx,commit);}
        decompiler.flushCache();currentProgram.save("Indago annotation",task);
        return obj("revision",revision(),"annotation",history.get(history.size()-1),"function",identity(f));
    }
    private String cursor(int offset) {return Base64.getUrlEncoder().withoutPadding().encodeToString(gson.toJson(obj("offset",offset,"binding",cursorBinding,"revision",revision())).getBytes(StandardCharsets.UTF_8));}
    private String collection(String op) {
        if(arguments.has("collection"))return arguments.get("collection").getAsString();
        switch(op){case "inspect":case "import":case "functions":return "functions";
          case "decompile":case "tokens":return "decompilation/tokens";case "assembly":return "instructions";
          case "analyze":return "functions";case "variables":return "recovered/variables";case "cfg":return "cfg/blocks";
          case "pcode":return "pcode/operations";case "control_flow":return "control_flow/indirect_flows";default:return op;}
    }
    private void paginate(JsonObject result) {
        String path=collection(activeRequest.get("operation").getAsString());JsonElement value=result;
        String[] parts=path.split("/");JsonObject parent=null;
        for(String part:parts){if(!value.isJsonObject()||!value.getAsJsonObject().has(part)){if(arguments.has("collection"))throw new IllegalArgumentException("unknown collection");return;}parent=value.getAsJsonObject();value=parent.get(part);}
        if(!value.isJsonArray()){if(arguments.has("collection"))throw new IllegalArgumentException("collection is not an array");return;}
        JsonArray all=value.getAsJsonArray(),page=new JsonArray();String search=arguments.has("search")?arguments.get("search").getAsString().toLowerCase(Locale.ROOT):"";
        int matched=0;boolean more=false;
        for(JsonElement item:all){if(!search.isEmpty()&&!gson.toJson(item).toLowerCase(Locale.ROOT).contains(search))continue;
            if(matched++<pageOffset)continue;if(page.size()>=pageSize){more=true;break;}page.add(item);}
        parent.add(parts[parts.length-1],page);
        result.add("pagination",obj("collection",path,"offset",pageOffset,"returned",page.size(),"next_cursor",more?cursor(pageOffset+page.size()):null,"program_revision",revision(),"scan_limit",limit,"scan_may_be_incomplete",all.size()>=limit));
        if(more){partial=true;result.addProperty("partial",true);result.addProperty("status","partial");}
    }
    private static String hex(Address a) { return a == null ? null : "0x" + Long.toUnsignedString(a.getOffset(), 16); }
    private JsonObject obj(Object... pairs) {
        JsonObject o = new JsonObject();
        for (int i=0;i<pairs.length;i+=2) o.add((String)pairs[i], gson.toJsonTree(pairs[i+1]));
        return o;
    }
    private boolean room(JsonArray a) { if (task.isCancelled()) { partial=true; return false; } if(a.size()>=limit){partial=true;return false;}return true; }
    private JsonObject location(Address a) { return obj("address",hex(a),"address_space", a == null ? null : a.getAddressSpace().getName()); }
    private Function function(String address) {
        Address a=currentProgram.getAddressFactory().getAddress(address);
        Function f=a==null?null:currentProgram.getFunctionManager().getFunctionContaining(a);
        if(f==null) throw new IllegalArgumentException("No function at " + address);
        return f;
    }
    private JsonObject identity(Function f) {
        JsonArray ranges=new JsonArray();AddressRangeIterator it=f.getBody().getAddressRanges();while(it.hasNext()&&room(ranges)){AddressRange r=it.next();ranges.add(obj("min",hex(r.getMinAddress()),"max",hex(r.getMaxAddress()),"max_inclusive",true));}
        return obj("entry",hex(f.getEntryPoint()),"name",f.getName(),"signature",f.getSignature().getPrototypeString(),"location",location(f.getEntryPoint()),"ranges",ranges,"calling_convention",f.getCallingConventionName(),"thunk",f.isThunk(),"external",f.isExternal());
    }
    private String bytes(Instruction i) {try{StringBuilder s=new StringBuilder();for(byte b:i.getBytes())s.append(String.format("%02x",b&255));return s.toString();}catch(Exception e){partial=true;return null;}}
    private JsonArray functions() {
        JsonArray a=new JsonArray(); FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext() && room(a)) a.add(identity(it.next())); return a;
    }
    private JsonArray assembly(Function f) {
        JsonArray a=new JsonArray(); InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()&&room(a)){Instruction i=it.next();a.add(obj("address",hex(i.getAddress()),"location",location(i.getAddress()),"text",i.toString(),"mnemonic",i.getMnemonicString(),"length",i.getLength(),"bytes",bytes(i)));}return a;
    }
    private JsonArray xrefs(Function f) {
        JsonArray a=new JsonArray();AddressIterator destinations=currentProgram.getReferenceManager().getReferenceDestinationIterator(f.getBody(),true);
        while(destinations.hasNext()&&room(a)){ReferenceIterator incoming=currentProgram.getReferenceManager().getReferencesTo(destinations.next());while(incoming.hasNext()&&room(a)){Reference r=incoming.next();a.add(reference(r,"incoming"));}}
        InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(it.hasNext()&&!task.isCancelled()) for(Reference r:it.next().getReferencesFrom()){if(!room(a))return a;a.add(reference(r,"outgoing"));} return a;
    }
    private JsonObject reference(Reference r,String direction){return obj("from",hex(r.getFromAddress()),"to",hex(r.getToAddress()),"from_location",location(r.getFromAddress()),"to_location",location(r.getToAddress()),"kind",r.getReferenceType().toString(),"direction",direction,"operand",r.getOperandIndex(),"call",r.getReferenceType().isCall());}
    private JsonArray calls(Function f){JsonArray a=new JsonArray();InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);while(it.hasNext()&&room(a))for(Reference r:it.next().getReferencesFrom())if(r.getReferenceType().isCall()){if(!room(a))return a;a.add(reference(r,"outgoing"));}return a;}
    private JsonArray strings(){JsonArray a=new JsonArray();DataIterator it=currentProgram.getListing().getDefinedData(true);while(it.hasNext()&&room(a)){Data d=it.next();if(d.hasStringValue()){String value=String.valueOf(d.getValue());boolean truncated=value.length()>textLimit;if(truncated){value=value.substring(0,textLimit);partial=true;}a.add(obj("location",location(d.getAddress()),"value",value,"length",d.getLength(),"type",d.getDataType().getPathName(),"text_truncated",truncated));}}return a;}
    private JsonArray symbols(boolean imports){JsonArray a=new JsonArray();SymbolIterator it=imports?currentProgram.getSymbolTable().getExternalSymbols():currentProgram.getSymbolTable().getSymbolIterator(true);while(it.hasNext()&&room(a)){Symbol s=it.next();if(imports||currentProgram.getSymbolTable().isExternalEntryPoint(s.getAddress()))a.add(obj("id",Long.toUnsignedString(s.getID()),"name",s.getName(),"namespace",s.getParentNamespace().getName(true),"location",location(s.getAddress()),"native_kind",s.getSymbolType().toString()));}return a;}
    private JsonArray variables(Function f) {
        JsonArray a=new JsonArray();for(Variable v:f.getAllVariables()){if(!room(a))break;a.add(obj("name",v.getName(),"type",v.getDataType().getPathName(),"storage",v.getVariableStorage().toString(),"first_use_offset",v.getFirstUseOffset(),"parameter",v instanceof Parameter,"source",v.getSource().toString()));}return a;
    }
    private JsonObject recoveredVariables(Function f,int seconds) {
        DecompileResults r=decompiler.decompileFunction(f,seconds,task);JsonArray a=new JsonArray();
        if(r.getHighFunction()!=null){Iterator<HighSymbol> it=r.getHighFunction().getLocalSymbolMap().getSymbols();while(it.hasNext()&&room(a)){HighSymbol s=it.next();a.add(obj("id",Long.toUnsignedString(s.getId()),"name",s.getName(),"type",s.getDataType().getPathName(),"storage",s.getStorage().toString(),"parameter",s.isParameter(),"location",location(s.getPCAddress()),"native_source","HighFunction.LocalSymbolMap"));}}
        if(!r.decompileCompleted())partial=true;
        return obj("variables",a,"database_variables",variables(f),"native_verdict",r.decompileCompleted()?"completed":r.isTimedOut()?"timeout":r.isCancelled()?"cancelled":"failed","diagnostic",r.getErrorMessage());
    }
    private JsonArray types() {
        JsonArray a=new JsonArray();Iterator<DataType> it=currentProgram.getDataTypeManager().getAllDataTypes();while(it.hasNext()&&room(a)){DataType t=it.next();JsonObject item=obj("name",t.getName(),"path",t.getPathName(),"length",t.getLength(),"description",t.getDescription(),"native_class",t.getClass().getSimpleName());if(t instanceof Composite){JsonArray fields=new JsonArray();for(DataTypeComponent c:((Composite)t).getComponents()){if(!room(fields))break;fields.add(obj("name",c.getFieldName(),"offset",c.getOffset(),"length",c.getLength(),"type",c.getDataType().getPathName()));}item.add("fields",fields);}a.add(item);}return a;
    }
    private JsonObject cfg(Function f) throws Exception {
        JsonArray blocks=new JsonArray(),edges=new JsonArray();BasicBlockModel model=new BasicBlockModel(currentProgram);
        CodeBlockIterator it=model.getCodeBlocksContaining(f.getBody(),task);
        while(it.hasNext()&&room(blocks)){CodeBlock b=it.next();blocks.add(obj("entry",hex(b.getFirstStartAddress()),"min",hex(b.getMinAddress()),"max",hex(b.getMaxAddress())));CodeBlockReferenceIterator refs=b.getDestinations(task);while(refs.hasNext()&&room(edges)){CodeBlockReference r=refs.next();edges.add(obj("from",hex(b.getFirstStartAddress()),"to",hex(r.getDestinationAddress()),"site",hex(r.getReferent()),"kind",r.getFlowType().toString()));}}
        return obj("blocks",blocks,"edges",edges);
    }
    private void tokens(ClangNode node,JsonArray out,int[] cursor) {
        if(node instanceof ClangToken){ClangToken t=(ClangToken)node;String text=t.getText();int start=cursor[0];cursor[0]+=text.length();if(room(out))out.add(obj("text",text,"token_index",out.size(),"token_stream_offset",start,"min_address",hex(t.getMinAddress()),"max_address",hex(t.getMaxAddress()),"location",location(t.getMinAddress()),"syntax_type",t.getSyntaxType(),"native_class",t.getClass().getSimpleName()));return;}
        for(int i=0;i<node.numChildren();i++){if(!room(out))break;tokens(node.Child(i),out,cursor);}
    }
    private JsonObject decompile(Function f,int seconds) {
        DecompileResults r=decompiler.decompileFunction(f,seconds,task);JsonObject o=identity(f);
        o.addProperty("native_verdict",r.decompileCompleted()?"completed":r.isTimedOut()?"timeout":r.isCancelled()?"cancelled":"failed");o.addProperty("diagnostic",r.getErrorMessage());
        if(!r.decompileCompleted())partial=true;
        if(r.getDecompiledFunction()!=null){String c=r.getDecompiledFunction().getC();if(c.length()>textLimit){c=c.substring(0,textLimit);partial=true;o.addProperty("text_truncated",true);}o.addProperty("decompiled_c",c);}
        JsonArray a=new JsonArray();StringBuilder rendered=new StringBuilder();
        if(r.getCCodeMarkup()!=null){PrettyPrinter printer=new PrettyPrinter(f,r.getCCodeMarkup(),null);
            for(ClangLine line:printer.getLines()) {
                if(task.isCancelled()||rendered.length()>textLimit){partial=true;break;}
                rendered.append(line.getIndentString());int column=line.getIndentString().length();
                for(ClangToken t:line.getAllTokens()) {
                    String text=t.getText();int start=rendered.length();rendered.append(text);
                    if(room(a)){JsonObject token=obj("text",text,"token_index",a.size(),"rendered_offset",start,"rendered_end",rendered.length(),"line",line.getLineNumber(),"column",column,"offset_unit","UTF-16 code units in rendered_c","location",location(t.getMinAddress()),"min_address",hex(t.getMinAddress()),"max_address",hex(t.getMaxAddress()),"syntax_type",t.getSyntaxType(),"native_class",t.getClass().getSimpleName(),"varnode_id",varnodeId(t.getVarnode()),"pcode_operation_id",operationId(t.getPcodeOp()));
                        HighVariable high=t.getHighVariable();if(high!=null){token.addProperty("type_path",high.getDataType().getPathName());if(high.getSymbol()!=null)token.addProperty("symbol_id",Long.toUnsignedString(high.getSymbol().getId()));}a.add(token);}
                    column+=text.length();
                }rendered.append('\n');
            }
        }
        o.addProperty("rendered_c",rendered.toString());o.add("tokens",a);return o;
    }
    private JsonObject handle(JsonObject request) throws Exception {
        activeRequest=request;arguments=request.has("arguments")?request.getAsJsonObject("arguments"):new JsonObject();
        String op=request.get("operation").getAsString();pageSize=Math.max(1,Math.min(100000,request.get("max_items").getAsInt()));pageOffset=0;
        cursorBinding=digest(request.get("session_key").getAsString()+currentProgram.getExecutableSHA256()+op+request.get("address").getAsString()+collection(op)+(arguments.has("search")?arguments.get("search").getAsString():""));
        if(arguments.has("cursor")){
            String c=arguments.get("cursor").getAsString();if(c.length()>2048)throw new IllegalArgumentException("cursor too long");
            JsonObject cursor=JsonParser.parseString(new String(Base64.getUrlDecoder().decode(c),StandardCharsets.UTF_8)).getAsJsonObject();
            if(!cursorBinding.equals(cursor.get("binding").getAsString())||cursor.get("revision").getAsLong()!=revision())throw new IllegalArgumentException("stale or mismatched cursor");pageOffset=cursor.get("offset").getAsInt();
        }
        if(pageOffset<0||pageOffset>=100000)throw new IllegalArgumentException("cursor scan budget exceeded");
        int scan=arguments.has("scan_limit")?arguments.get("scan_limit").getAsInt():100000;
        if(scan<1||scan>100000)throw new IllegalArgumentException("scan_limit must be 1..100000");
        limit=arguments.has("search")?scan:Math.min(scan,pageOffset+pageSize+1);
        textLimit=Math.max(128,request.get("max_output_bytes").getAsInt()/4);partial=analysisTimedOut;
        JsonObject out=obj("schema","indago.ghidra-result.v2","backend","ghidra","operation",op,"program",obj("format",currentProgram.getExecutableFormat(),"image_base",hex(currentProgram.getImageBase()),"language",currentProgram.getLanguageID().toString(),"executable_sha256",currentProgram.getExecutableSHA256()));
        out.addProperty("analysis_timed_out",analysisTimedOut);
        if(op.equals("session"))out.add("session",obj("revision",revision(),"idle_timeout_ms",300000,"profile",arguments.has("profile")?arguments.get("profile").getAsString():"standard","saved_program",currentProgram.getDomainFile().getPathname()));
        else if(op.equals("close")){currentProgram.save("Indago close",task);closing=true;out.addProperty("closing",true);}
        else if(op.equals("flush")){decompiler.flushCache();out.addProperty("cache_flushed",true);}
        else if(op.equals("annotations"))out.add("annotations",JsonParser.parseString(currentProgram.getOptions("Indago").getString("annotations","[]")));
        else if(op.equals("analyze")){
            if(!arguments.has("expected_revision")||arguments.get("expected_revision").getAsLong()!=revision())throw new IllegalArgumentException("analysis requires current expected_revision");
            long before=revision();int tx=currentProgram.startTransaction("Indago explicit analysis");
            try {
                String at=request.get("address").getAsString();
                AddressSetView scope=currentProgram.getMemory();
                if(!at.isEmpty()){
                    Address address=toAddr(at);
                    if(!new DisassembleCommand(address,null,true).applyTo(currentProgram,task))throw new IllegalArgumentException("disassembly failed");
                    if(getFunctionAt(address)==null&&!new CreateFunctionCmd(address).applyTo(currentProgram,task))throw new IllegalArgumentException("function creation failed");
                    scope=getFunctionAt(address).getBody();
                }
                AutoAnalysisManager manager=AutoAnalysisManager.getAnalysisManager(currentProgram);
                manager.reAnalyzeAll(scope);manager.startAnalysis(task);
            }finally{currentProgram.getOptions("Indago").setLong("revision",before+1);currentProgram.endTransaction(tx,true);decompiler.flushCache();currentProgram.save("Indago partial analysis",monitor);}
            decompiler.flushCache();currentProgram.save("Indago analysis",task);analysisTimedOut=task.isCancelled();partial=analysisTimedOut;
            out.addProperty("analysis_scope","pending native analysis; explicit function entry seed when address supplied");out.add("functions",functions());
        }
        else if(op.equals("import")||op.equals("inspect")||op.equals("functions"))out.add("functions",functions());
        else if(op.equals("types"))out.add("types",types());
        else if(op.equals("strings"))out.add("strings",strings());
        else if(op.equals("imports")||op.equals("exports"))out.add(op,symbols(op.equals("imports")));
        else {Function f=function(request.get("address").getAsString());out.add("function",identity(f));switch(op){
            case "decompile":case "tokens":out.add("decompilation",decompile(f,Math.max(1,request.get("timeout_ms").getAsInt()/1000)));break;
            case "assembly":out.add("instructions",assembly(f));break;
            case "xrefs":out.add("xrefs",xrefs(f));break;
            case "calls":out.add("calls",calls(f));break;
            case "variables":out.add("recovered",recoveredVariables(f,Math.max(1,request.get("timeout_ms").getAsInt()/1000)));break;
            case "cfg":out.add("cfg",cfg(f));break;
            case "pcode":out.add("pcode",pcode(f,Math.max(1,request.get("timeout_ms").getAsInt()/1000)));break;
            case "control_flow":out.add("control_flow",controlFlow(f,Math.max(1,request.get("timeout_ms").getAsInt()/1000)));break;
            case "annotate":out.add("edit",annotate(f));break;
            default:throw new IllegalArgumentException("Unsupported operation: "+op);
        }}out.addProperty("program_revision",revision());out.addProperty("status",task.isCancelled()?"cancelled":partial?"partial":"completed");out.addProperty("partial",partial);paginate(out);return out;
    }
    private void atomic(Path path,String value) throws Exception {Path tmp=path.resolveSibling(path.getFileName()+".tmp");Files.writeString(tmp,value,StandardCharsets.UTF_8);Files.move(tmp,path,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
    private JsonArray largestArray(JsonElement e,JsonArray best) {
        if(e.isJsonArray()){JsonArray a=e.getAsJsonArray();if(best==null||a.size()>best.size())best=a;for(JsonElement v:a)best=largestArray(v,best);}
        else if(e.isJsonObject())for(Map.Entry<String,JsonElement> p:e.getAsJsonObject().entrySet())best=largestArray(p.getValue(),best);
        return best;
    }
    private String bounded(JsonObject result,int bytes) {
        String encoded=gson.toJson(result);
        while(encoded.getBytes(StandardCharsets.UTF_8).length>bytes){
            result.addProperty("partial",true);result.addProperty("output_truncated",true);
            if("completed".equals(result.get("status").getAsString()))result.addProperty("status","partial");
            JsonArray a=largestArray(result,null);
            if(a==null||a.isEmpty())return gson.toJson(obj("schema","indago.ghidra-result.v2","backend","ghidra","status","partial","partial",true,"diagnostic","max_output_bytes exceeded; request smaller max_items","session_pid",ProcessHandle.current().pid()));
            int keep=a.size()/2;while(a.size()>keep)a.remove(a.size()-1);
            if(result.has("pagination")){
                JsonObject pagination=result.getAsJsonObject("pagination");JsonElement selected=result;
                for(String part:pagination.get("collection").getAsString().split("/"))selected=selected.getAsJsonObject().get(part);
                int count=selected.getAsJsonArray().size(),previous=pagination.get("returned").getAsInt();
                if(count<previous){pagination.addProperty("returned",count);pagination.add("next_cursor",count>0?gson.toJsonTree(cursor(pageOffset+count)):JsonNull.INSTANCE);
                    if(count==0)pagination.addProperty("continuation_blocked","increase output budget or narrow selection; no item fit");}
            }
            encoded=gson.toJson(result);
        }return encoded;
    }
    @Override protected void run() throws Exception {
        // Headless scripts start in a single transaction. Release it so each
        // request owns its transaction and can durably save before replying.
        end(true);
        Path dir=Paths.get(getScriptArgs()[0]);Files.createDirectories(dir);
        analysisTimedOut=analysisTimeoutOccurred();
        decompiler=new DecompInterface();decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(true);
        if(!decompiler.openProgram(currentProgram))throw new IllegalStateException(decompiler.getLastMessage());
        currentProgram.save("Indago initial import",monitor);
        atomic(dir.resolve("ready"),Long.toString(ProcessHandle.current().pid()));long last=System.currentTimeMillis();
        try {while(!closing&&System.currentTimeMillis()-last<300000&&!monitor.isCancelled()&&!Files.exists(dir.resolve("stop"))){
            try(DirectoryStream<Path> requests=Files.newDirectoryStream(dir,"*.request")){for(Path p:requests){last=System.currentTimeMillis();String id=p.getFileName().toString().replace(".request","");JsonObject q=JsonParser.parseString(Files.readString(p)).getAsJsonObject();task=new TaskMonitorAdapter(true);final TaskMonitorAdapter active=task;final long deadline=System.currentTimeMillis()+q.get("timeout_ms").getAsLong();Thread watcher=new Thread(()->{try{while(!Thread.currentThread().isInterrupted()){if(Files.exists(dir.resolve(id+".cancel"))||System.currentTimeMillis()>deadline){active.cancel();break;}Thread.sleep(25);}}catch(InterruptedException ignored){}});watcher.setDaemon(true);watcher.start();if(Files.exists(dir.resolve(id+".cancel")))task.cancel();JsonObject result;
                try{result=handle(q);}catch(Exception e){result=obj("schema","indago.ghidra-result.v2","backend","ghidra","status",task.isCancelled()?"cancelled":"failed","diagnostic",e.toString());}finally{watcher.interrupt();}
                result.addProperty("session_pid",ProcessHandle.current().pid());String encoded=bounded(result,q.get("max_output_bytes").getAsInt());atomic(dir.resolve(id+".response"),encoded);Files.deleteIfExists(p);Files.deleteIfExists(dir.resolve(id+".cancel"));
            }}Thread.sleep(25);
        }}finally{Files.deleteIfExists(dir.resolve("ready"));decompiler.dispose();}
    }
}
