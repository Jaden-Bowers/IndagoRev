#pragma once
#include "../src/harness_validation.hpp"
#include "indago/service.hpp"
inline void claim_validation_checks(const indago::fs::path &root) {
    using namespace indago;using J=nlohmann::json;
    StaticService svc(root);auto &store=svc.store();store.create_project("checks");
    atomic_write(root/"fixture.bin","source-backed arithmetic fixture");
    auto target=store.import_target("checks",root/"fixture.bin");
    auto job=svc.prepare({{"project","checks"},{"backend","xair"},{"operation","inventory"}});
    const J data{{"format","PE"},{"architecture","x86"},{"base","0x401000"},{"size",6144},
        {"inside","0x4024c0"},{"end","0x402800"},{"permissions",5},{"max","0xffffffffffffffff"},{"one",1}};
    auto published=store.publish_result(target,job,"xair",{0,"completed",data.dump()});
    J inv{{"project","checks"},{"target_id",target.id},{"artifact_sha256",target.sha256}};
    auto ref=[&](const char *pointer){return J{{"evidence_id",published["evidence_ids"][0]},
        {"raw_sha256",published["raw_sha256"]},{"pointer",pointer}};};
    J checks=J::array({{{"operation","equal"},{"operands",J::array({ref("/format")})},{"expected","PE"}},
        {{"operation","sum"},{"operands",J::array({ref("/base"),ref("/size")})},{"expected","0x402800"}},
        {{"operation","contains"},{"operands",J::array({ref("/base"),ref("/size"),ref("/inside")})},{"expected",true}},
        {{"operation","contains"},{"operands",J::array({ref("/base"),ref("/size"),ref("/end")})},{"expected",false}},
        {{"operation","bits"},{"operands",J::array({ref("/permissions")})},{"mask",5},{"expected",true}}});
    auto ensure=[](bool b){if(!b)throw std::runtime_error("claim validation regression");};
    ensure(harness_validate(store,inv,checks)["status"]=="passed");
    checks[0]["expected"]="Mach-O";checks[1]["expected"]="0x401800";
    auto contradicted=harness_validate(store,inv,checks);
    ensure(contradicted["status"]=="contradicted"&&contradicted["checks"][1]["actual"]==0x402800);
    auto rejects=[&](auto fn){bool failed=false;try{fn();}catch(const std::exception&){failed=true;}ensure(failed);};
    auto overflow=J::array({{{"operation","sum"},{"operands",J::array({ref("/max"),ref("/one")})},{"expected",0}}});
    rejects([&]{harness_validate(store,inv,overflow);});
    for(const J bad:{J(-1),J(1.2),J("0x"),J("1junk"),J("18446744073709551616"),J(true)})
        rejects([&]{harness_unsigned(bad);});
    rejects([&]{harness_validate(store,inv,checks,J::array({"ev_other"}));});
    auto stale=checks;stale[0]["operands"][0]["raw_sha256"]=std::string(64,'0');
    rejects([&]{harness_validate(store,inv,stale);});
    auto outside=inv;outside["artifact_sha256"]=std::string(64,'0');
    rejects([&]{harness_validate(store,outside,checks);});
    atomic_write(wb::object(store,published["raw_sha256"].get<std::string>()),"{}");
    rejects([&]{harness_validate(store,inv,checks);});
}
