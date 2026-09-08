#include "indago/service.hpp"
#include <fstream>
#include <iostream>
using namespace indago;
using Json=nlohmann::json;
void require(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
int main(){
    const auto root=fs::temp_directory_path()/make_id("indago-test");
    try {
        StaticService service(root);auto& store=service.store();store.create_project("demo");
        atomic_write(root/"abc.bin","abc");
        require(sha256_file(root/"abc.bin")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 vector");
        atomic_write(root/"empty.bin","");require(sha256_file(root/"empty.bin")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","empty SHA vector");
        auto target=store.import_target("demo",root/"abc.bin");auto again=store.import_target("demo",root/"abc.bin");require(target.id==again.id,"dedup");require(store.latest_target("demo").id==target.id,"latest target");
        Json request{{"schema","indago.action.v1"},{"project","demo"},{"backend","airece"},{"operation","functions"}};
        auto job=service.prepare(request);require(store.job_info("demo",job["id"])["jobs"][0]["status"]=="queued","durable job");
        Json native{{"functions",Json::array({{{"address","0xffffffffffffffff"},{"name","xair_name"}}})}};
        auto result=store.publish_result(target,job,"airece",{3,"partial",native.dump()});
        require(result["completeness"]=="partial","partial preserved");
        auto ev=result["evidence_ids"][0].get<std::string>();require(store.evidence("demo",ev)["evidence"][0]["native_result"]==native,"evidence roundtrip");
        request["backend"]="ghidra";job=service.prepare(request);native["functions"][0]={{"entry","0xffffffffffffffff"},{"name","ghidra_name"}};
        store.publish_result(target,job,"ghidra",{0,"completed",native.dump()});
        auto fn=store.functions("demo");require(fn["functions"].size()==1,"common function identity");
        auto views=store.function_views("demo",fn["functions"][0]["id"]);require(views["views"].size()==2,"independent backend views retained");
        require(views["views"][0]["native"]["name"]!=views["views"][1]["native"]["name"],"backend disagreement retained");
        request["artifact_sha256"]="bad";bool rejected=false;try{service.prepare(request);}catch(...){rejected=true;}require(rejected,"stale artifact rejection");
        request.erase("artifact_sha256");request["backend"]="airece";job=service.prepare(request);store.cancel_job("demo",job["id"]);result=service.execute(job);require(result["status"]=="cancelled","cancel before launch");
        StaticService reopened(root);require(reopened.store().functions("demo")["functions"].size()==1,"persistence after reopen");
        std::ofstream(target.object_path,std::ios::binary|std::ios::trunc)<<"tampered";rejected=false;try{store.latest_target("demo");}catch(...){rejected=true;}require(rejected,"tamper detection");
        fs::remove_all(root);std::cout<<"core contracts passed\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<"; fixture retained at "<<root<<'\n';return 1;}
}
