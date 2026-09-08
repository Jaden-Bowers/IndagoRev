#include "indago/service.hpp"
#include "indago/contracts.hpp"
#include <sqlite3.h>
#include <iostream>
#include <thread>
using namespace indago;
using Json=nlohmann::json;
void check(bool v,const char* message){if(!v)throw std::runtime_error(message);}
template<class F>void rejects(F f,const char* message){bool rejected=false;try{f();}catch(const std::exception&){rejected=true;}check(rejected,message);}
int main(){
    auto dir=fs::temp_directory_path()/make_id("static-model-test");
    try{
        StaticService service(dir);auto& store=service.store();store.create_project("demo");atomic_write(dir/"fixture","bytes");auto target=store.import_target("demo",dir/"fixture");
        Json request{{"project","demo"},{"backend","xair"},{"operation","semantic"},{"idempotency_key","first"}};
        auto job=service.prepare(request);check(service.prepare(request)["id"]==job["id"],"idempotent submit");
        auto bad=request;bad["operation"]="cfg";rejects([&]{service.prepare(bad);},"key conflict");
        bad=request;bad["bogus"]=true;rejects([&]{service.prepare(bad);},"schema rejects extra fields");
        bad=request;bad["budget"]={{"wall_ms",true}};rejects([&]{service.prepare(bad);},"boolean budget rejected");
        bad=request;bad["operation"]="missing";rejects([&]{service.prepare(bad);},"operation validation");
        Json loc{{"address","0xfffffffffffffff0"},{"address_space","virtual"}};
        Json native{{"status","partial"},{"program",{{"image_base","0xfffffffffffff000"},{"segments",Json::array({{{"va","0xfffffffffffff000"},{"file_offset","0x100"},{"file_size",4096}}})}}},
            {"functions",Json::array({{{"id",0},{"name","native_name"},{"location",loc},{"blocks",{0}}}})},
            {"blocks",Json::array({{{"id",0},{"location",loc},{"end","0xffffffffffffffff"}}})},
            {"operations",Json::array({{{"ir_op",1},{"source_locations",Json::array({loc})},{"definitions",{7}},{"uses",{8}},{"constants",{{"low","0xffffffffffffffff"},{"high","0x0"}}},{"memory_effects",{{"read",true}}}}})},
            {"ssa_values",Json::array({{{"id",7},{"name","v7"}},{{"id",8},{"name","v8"}}})},
            {"calls",Json::array({{{"node",0},{"target","0x0"}}})},
            {"strings",Json::array({{{"location",loc},{"value","configuration"}}})}};
        auto result=store.publish_result(target,job,"xair",{3,"partial",native.dump()});validate_contract("result",result);
        check(store.publish_result(target,job,"xair",{3,"partial",native.dump()})==result,"idempotent publication");
        check(service.execute(job)==result,"completed job reused");
        auto entities=store.index_query("demo",{{"kind","function"}})["records"];check(entities.size()==1,"function indexed");
        auto entity=entities[0];check(entity["location"]["rva"]=="0xff0","64 bit RVA exact");check(entity["location"]["file_offset"]=="0x10f0","checked mapping");
        check(native.at(Json::json_pointer(entity["json_pointer"]))==entity["native"],"native evidence pointer resolves");
        auto anchor=entity["location"]["anchor_id"];
        auto rels=store.index_query("demo",{{"category","relations"},{"kind","definitions"}})["records"];check(rels.size()==1&&!rels[0]["target_entity"].is_null(),"SSA relation resolution");
        auto calls=store.index_query("demo",{{"category","relations"},{"kind","call"}})["records"];check(calls.size()==1&&calls[0]["target_location"].is_null(),"unknown call target preserved");
        check(store.index_query("demo",{{"search","configuration"}})["records"].size()==1,"strings indexed");
        check(store.index_query("demo",{{"kind","constant"}})["records"].size()==1,"constants indexed");
        auto claims=store.index_query("demo",{{"category","claims"},{"subject",entity["id"]}})["records"];check(claims.size()==1&&claims[0]["validation"]=="unvalidated","native claim not promoted");
        request.erase("idempotency_key");auto next=service.prepare(request);native["functions"][0]["name"]="new_name";store.publish_result(target,next,"xair",{3,"partial",native.dump()});
        check(store.index_query("demo",{{"kind","function"}})["records"][0]["name"]=="new_name","new head selected");
        auto historic=store.index_query("demo",{{"kind","function"},{"history",true}})["records"];check(historic.size()==2&&historic[0]["freshness"]=="superseded","old discovery retained but invalidated");
        request["backend"]="ghidra";request["operation"]="functions";auto ghidra=service.prepare(request);
        Json gn{{"status","completed"},{"functions",Json::array({{{"entry","0xfffffffffffffff0"},{"name","ghidra_name"},{"location",{{"address","0xfffffffffffffff0"},{"address_space","ram"}}}}})}};
        store.publish_result(target,ghidra,"ghidra",{0,"completed",gn.dump()});
        auto views=store.index_query("demo",{{"kind","function"},{"anchor",anchor}})["records"];check(views.size()==2&&views[0]["id"]!=views[1]["id"],"same-location independent discoveries");
        check(store.index_query("demo",{{"category","compare"},{"anchor",anchor}})["disagreements"].size()==1,"backend disagreement query");
        const auto before=store.index_query("demo",{{"history",true}});store.reindex("demo");check(store.index_query("demo",{{"history",true}})==before,"deterministic reindex");
        auto queued=service.prepare(request);auto owned=store.claim_job("demo",queued["id"]);rejects([&]{store.claim_job("demo",queued["id"]);},"exclusive ownership");
        rejects([&]{store.publish_result(target,queued,"ghidra",{0,"completed",gn.dump()});},"publication ownership");
        store.heartbeat(owned["id"].get<std::string>(),owned["lease_token"].get<std::string>());check(store.recover_jobs("demo")["interrupted_jobs"].empty(),"live leases not reclaimed");
        sqlite3* db{};check(sqlite3_open((dir/"indago-native.sqlite3").string().c_str(),&db)==SQLITE_OK,"test database");sqlite3_exec(db,"UPDATE job_leases SET deadline=0",nullptr,nullptr,nullptr);sqlite3_close(db);
        check(store.recover_jobs("demo")["interrupted_jobs"].size()==1,"expired lease recovered");rejects([&]{store.publish_result(target,owned,"ghidra",{0,"completed",gn.dump()});},"late worker fenced");
        check(store.job_events("demo",owned["id"])["events"].back()["kind"]=="interrupted","durable history");
        StaticService reopened(dir);check(!reopened.store().index_query("demo",{{"kind","function"}})["records"].empty(),"migration reopen");
        check(sqlite3_open((dir/"indago-native.sqlite3").string().c_str(),&db)==SQLITE_OK,"legacy fixture open");
        check(sqlite3_exec(db,"DROP TABLE static_claims; DROP TABLE static_relations; DROP TABLE static_entities; DROP TABLE analysis_heads; DROP TABLE indexed_revisions; DROP TABLE job_events; DROP TABLE job_leases; DROP TABLE idempotency; PRAGMA user_version=1",nullptr,nullptr,nullptr)==SQLITE_OK,"legacy fixture setup");sqlite3_close(db);
        StaticService migrated(dir);check(migrated.store().reindex("demo")["evidence_records"]==3,"legacy evidence backfill");check(migrated.store().index_query("demo",{{"kind","function"}})["records"].size()==2,"legacy migration indexes preserved views");
        check(sqlite3_open((dir/"indago-native.sqlite3").string().c_str(),&db)==SQLITE_OK,"future fixture open");sqlite3_exec(db,"PRAGMA user_version=99",nullptr,nullptr,nullptr);sqlite3_close(db);rejects([&]{StaticService future(dir);},"future schema rejected");
        fs::remove_all(dir);std::cout<<"static identity, contracts, indexing and job recovery passed\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<" (retained "<<dir<<")\n";return 1;}
}
