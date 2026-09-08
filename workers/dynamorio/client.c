#include "dr_api.h"
#include <stdlib.h>
#include <string.h>

static file_t output = INVALID_FILE;
static void *lock;
static app_pc image_start, image_end;
static uint64 count, budget;
static bool capped;
static bool effects, all_code, application_code;
static ptr_uint_t written_pages[4096];
static uint64 write_sequences[4096];
static uint written_count;
static uint64 completed_sequences[4096];
static uint module_events;
typedef struct {app_pc pc,address;uint size;uint64 attempt;bool unconditional;} pending_write;
typedef struct {uint count;pending_write writes[8];app_pc source,target;uint64 transfer;} thread_writes;
static void thread_init(void *context){thread_writes *state=dr_thread_alloc(context,sizeof(*state));memset(state,0,sizeof(*state));dr_set_tls_field(context,state);}
static void thread_exit(void *context){void *state=dr_get_tls_field(context);if(state)dr_thread_free(context,state,sizeof(thread_writes));}
static void module_event(const module_data_t *module,bool loaded){
  dr_mutex_lock(lock);
  if(module_events++<256){
    dr_fprintf(output,"{\"kind\":\"module_%s\",\"base\":\"0x%llx\",\"end\":\"0x%llx\",\"path_hex\":\"",loaded?"loaded":"unloaded",(unsigned long long)(ptr_uint_t)module->start,(unsigned long long)(ptr_uint_t)module->end);
    const unsigned char *path=(const unsigned char*)(module->full_path?module->full_path:"");size_t n=0;for(;path[n]&&n<2048;++n)dr_fprintf(output,"%02x",path[n]);
    dr_fprintf(output,"\",\"path_truncated\":%s}\n",path[n]?"true":"false");
  }else capped=true;
  dr_mutex_unlock(lock);
}
static void module_load(void *context,const module_data_t *module,bool loaded){module_event(module,true);}
static void module_unload(void *context,const module_data_t *module){module_event(module,false);}
static void writes_completed(void){
  void *context=dr_get_current_drcontext();thread_writes *state=dr_get_tls_field(context);if(!state)return;
  dr_mutex_lock(lock);
  for(uint i=0;i<state->count;++i){pending_write *write=&state->writes[i];
    if(count>=budget){capped=true;break;}
    byte bytes[16];size_t copied=0;char hex[33];const char *digits="0123456789abcdef";
    dr_safe_read(write->address,write->size<16?write->size:16,bytes,&copied);for(size_t n=0;n<copied;++n){hex[n*2]=digits[bytes[n]>>4];hex[n*2+1]=digits[bytes[n]&15];}hex[copied*2]=0;
    uint64 sequence=++count;
    dr_fprintf(output,"{\"kind\":\"memory_effect_completed\",\"sequence\":%llu,\"attempt_sequence\":%llu,\"thread_id\":%u,\"pc\":\"0x%llx\",\"address\":\"0x%llx\",\"size\":%u,\"after_hex\":\"%s\",\"write_confirmed\":%s,\"completion\":\"post-instruction callback reached; snapshot may race with other threads; non-store conditional effects are not asserted committed\"}\n",(unsigned long long)sequence,(unsigned long long)write->attempt,dr_get_thread_id(context),(unsigned long long)(ptr_uint_t)write->pc,(unsigned long long)(ptr_uint_t)write->address,write->size,hex,write->unconditional?"true":"false");
    if(write->unconditional&&write->size&&write->size<=4096){ptr_uint_t first=(ptr_uint_t)write->address&~(ptr_uint_t)4095,last=((ptr_uint_t)write->address+write->size-1)&~(ptr_uint_t)4095;for(ptr_uint_t page=first;;page+=4096){uint n=0;while(n<written_count&&written_pages[n]!=page)++n;if(n<4096){if(n==written_count)++written_count;written_pages[n]=page;completed_sequences[n]=sequence;}else capped=true;if(page==last)break;}}
  }
  state->count=0;dr_mutex_unlock(lock);
}
static void transfer_kind(app_pc pc,app_pc target,const char *kind) {
  dr_mutex_lock(lock);
  if(count<budget)dr_fprintf(output,"{\"kind\":\"control_transfer\",\"transfer_kind\":\"%s\",\"sequence\":%llu,\"timestamp_us\":%llu,\"pid\":%u,\"thread_id\":%u,\"pc\":\"0x%llx\",\"target\":\"0x%llx\",\"phase\":\"before instruction\"}\n",kind,(unsigned long long)++count,(unsigned long long)dr_get_microseconds(),dr_get_process_id(),dr_get_thread_id(dr_get_current_drcontext()),(unsigned long long)(ptr_uint_t)pc,(unsigned long long)(ptr_uint_t)target);
  else capped=true;
  thread_writes *state=dr_get_tls_field(dr_get_current_drcontext());if(state&&count<budget){state->source=pc;state->target=target;state->transfer=count;}
  dr_mutex_unlock(lock);
}
static void call_transfer(app_pc pc,app_pc target){transfer_kind(pc,target,"call");}
static void return_transfer(app_pc pc,app_pc target){transfer_kind(pc,target,"return");}
static void indirect_transfer(app_pc pc,app_pc target){transfer_kind(pc,target,"indirect_jump");}
static void memory_effects(app_pc pc) {
  void *context=dr_get_current_drcontext();dr_mutex_lock(lock);
  thread_writes *pending=dr_get_tls_field(context);if(pending)pending->count=0;
  if(count>=budget){capped=true;dr_mutex_unlock(lock);return;}
  dr_mcontext_t mc={sizeof(mc),DR_MC_CONTROL|DR_MC_INTEGER};instr_t instruction;instr_init(context,&instruction);
  byte code[16]={0};size_t copied=0;
  if(dr_safe_read(pc,15,code,&copied)&&copied==15&&dr_get_mcontext(context,&mc)&&decode_from_copy(context,code,pc,&instruction)) {
    for(int write=0;write<2;++write) {
      int operands=write?instr_num_dsts(&instruction):instr_num_srcs(&instruction);
      for(int i=0;i<operands&&count<budget;++i) {
        opnd_t operand=write?instr_get_dst(&instruction,i):instr_get_src(&instruction,i);
        if(!opnd_is_memory_reference(operand))continue;
        app_pc address=opnd_compute_address(operand,&mc);uint size=opnd_size_in_bytes(opnd_get_size(operand));
        byte bytes[16];size_t read=0;char hex[33];const char *digits="0123456789abcdef";
        dr_safe_read(address,size<sizeof(bytes)?size:sizeof(bytes),bytes,&read);
        for(size_t n=0;n<read;++n){hex[n*2]=digits[bytes[n]>>4];hex[n*2+1]=digits[bytes[n]&15];}hex[read*2]=0;
        dr_fprintf(output,"{\"kind\":\"memory_effect\",\"sequence\":%llu,\"timestamp_us\":%llu,\"pid\":%u,\"thread_id\":%u,\"pc\":\"0x%llx\",\"address\":\"0x%llx\",\"size\":%u,\"access\":\"%s\",\"before_hex\":\"%s\",\"completion\":\"attempted; pre-instruction observation, not confirmed completion\"}\n",(unsigned long long)++count,(unsigned long long)dr_get_microseconds(),dr_get_process_id(),dr_get_thread_id(context),(unsigned long long)(ptr_uint_t)pc,(unsigned long long)(ptr_uint_t)address,size,write?"write":"read",hex);
        if(write){ptr_uint_t page=(ptr_uint_t)address&~(ptr_uint_t)4095;uint n=0;while(n<written_count&&written_pages[n]!=page)++n;if(n<4096){if(n==written_count)++written_count;written_pages[n]=page;write_sequences[n]=count;}else capped=true;}
        if(write&&pending&&pending->count<8){pending_write *entry=&pending->writes[pending->count++];entry->pc=pc;entry->address=address;entry->size=size;entry->attempt=count;entry->unconditional=instr_get_opcode(&instruction)==OP_mov_st;}
      }
    }
  }
  instr_free(context,&instruction);dr_mutex_unlock(lock);
}

static void record(app_pc pc, uint size) {
  void *context = dr_get_current_drcontext();
  dr_mutex_lock(lock);
  if (count < budget) {
    thread_writes *state=dr_get_tls_field(context);
    if(state&&state->transfer){if(state->target==pc){dr_fprintf(output,"{\"kind\":\"control_transfer_taken\",\"sequence\":%llu,\"attempt_sequence\":%llu,\"thread_id\":%u,\"pc\":\"0x%llx\",\"target\":\"0x%llx\",\"verdict\":\"computed transfer followed by matching target block entry on same thread\"}\n",(unsigned long long)++count,(unsigned long long)state->transfer,dr_get_thread_id(context),(unsigned long long)(ptr_uint_t)state->source,(unsigned long long)(ptr_uint_t)pc);}state->transfer=0;}
    if(count>=budget){capped=true;dr_mutex_unlock(lock);return;}
    char rva[40]="null",hex[65]="";byte code[32];size_t copied=0;uint64 prior_write=0,confirmed=0;
    for(uint i=0;i<written_count;++i)if(written_pages[i]==((ptr_uint_t)pc&~(ptr_uint_t)4095))confirmed=completed_sequences[i];
    if(pc>=image_start&&pc<image_end)dr_snprintf(rva,sizeof(rva),"\"0x%llx\"",(unsigned long long)(pc-image_start));
    if(effects){dr_safe_read(pc,size<32?size:32,code,&copied);const char* digits="0123456789abcdef";for(size_t i=0;i<copied;++i){hex[i*2]=digits[code[i]>>4];hex[i*2+1]=digits[code[i]&15];}hex[copied*2]=0;for(uint i=0;i<written_count;++i)if(written_pages[i]==((ptr_uint_t)pc&~(ptr_uint_t)4095))prior_write=write_sequences[i];}
    dr_fprintf(output,
               "{\"kind\":\"basic_block\",\"sequence\":%llu,\"thread_id\":%u,"
               "\"pc\":\"0x%llx\",\"rva\":%s,\"size\":%u,\"bytes_hex\":\"%s\",\"prior_page_write_attempt_sequence\":%llu,\"prior_confirmed_write_sequence\":%llu}\n",
               (unsigned long long)++count, dr_get_thread_id(context),
               (unsigned long long)(ptr_uint_t)pc,
               rva,size,hex,(unsigned long long)prior_write,(unsigned long long)confirmed);
  } else if (!capped) {
    capped = true;
    dr_fprintf(output, "{\"kind\":\"collection_limit\",\"partial\":true}\n");
  }
  dr_mutex_unlock(lock);
}
static dr_emit_flags_t instrument(void *context, void *tag, instrlist_t *bb,
                                  bool for_trace, bool translating) {
  app_pc pc = (app_pc)tag;
  bool selected=all_code||(pc>=image_start&&pc<image_end);
  if(!selected&&application_code){module_data_t *module=dr_lookup_module(pc);selected=module==NULL;if(module)dr_free_module_data(module);}
  if (!translating && selected) {
    instr_t *first = instrlist_first_app(bb), *last = instrlist_last_app(bb);
    if (first && last) {
      app_pc end = instr_get_app_pc(last) + instr_length(context, last);
      dr_insert_clean_call(context, bb, first, (void *)record, false, 2,
                           OPND_CREATE_INTPTR(pc),
                           OPND_CREATE_INT32((uint)(end - pc)));
    }
  }
  if(!translating&&effects&&selected)for(instr_t *i=instrlist_first_app(bb);i;i=instr_get_next_app(i)) {
    if(instr_reads_memory(i)||instr_writes_memory(i))dr_insert_clean_call_ex(context,bb,i,(void*)memory_effects,DR_CLEANCALL_READS_APP_CONTEXT,1,OPND_CREATE_INTPTR(instr_get_app_pc(i)));
    if(instr_writes_memory(i)&&!instr_is_cti(i)&&!instr_is_syscall(i)&&!instr_is_interrupt(i)&&instr_get_next(i))dr_insert_clean_call(context,bb,instr_get_next(i),(void*)writes_completed,false,0);
    if(instr_is_call_direct(i))dr_insert_call_instrumentation(context,bb,i,(void*)call_transfer);
    else if(instr_is_mbr(i))dr_insert_mbr_instrumentation(context,bb,i,instr_is_call_indirect(i)?(void*)call_transfer:instr_is_return(i)?(void*)return_transfer:(void*)indirect_transfer,SPILL_SLOT_1);
  }
  return DR_EMIT_DEFAULT;
}
static void finished(void) {
  dr_fprintf(output,
             "{\"kind\":\"collection_end\",\"events\":%llu,\"partial\":%s}\n",
             (unsigned long long)count, capped ? "true" : "false");
  dr_close_file(output);
  dr_mutex_destroy(lock);
}
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
  dr_set_client_name("IndagoRev bounded basic-block collector",
                     "https://dynamorio.org/");
  if (argc != 5)
    dr_abort();
  effects=strcmp(argv[3],"effects")==0;
  all_code=strcmp(argv[4],"all")==0;
  application_code=strcmp(argv[4],"application")==0;
  budget = (uint64)strtoul(argv[2], NULL, 10);
  if (!budget || budget > 10000)
    dr_abort();
  output = dr_open_file(argv[1], DR_FILE_WRITE_REQUIRE_NEW);
  if (output == INVALID_FILE)
    dr_abort();
  lock = dr_mutex_create();
  module_data_t *main = dr_get_main_module();
  if (!main)
    dr_abort();
  image_start = main->start;
  image_end = main->end;
  dr_fprintf(output,
             "{\"kind\":\"main_module\",\"base\":\"0x%llx\",\"end\":\"0x%llx\","
             "\"pid\":%u}\n",
             (unsigned long long)(ptr_uint_t)image_start,
             (unsigned long long)(ptr_uint_t)image_end, dr_get_process_id());
  dr_free_module_data(main);
  dr_register_thread_init_event(thread_init);dr_register_thread_exit_event(thread_exit);
  dr_register_module_load_event(module_load);dr_register_module_unload_event(module_unload);
  dr_register_bb_event(instrument);
  dr_register_exit_event(finished);
}
