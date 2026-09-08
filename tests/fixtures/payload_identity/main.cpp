#include "payload_identity.hpp"
#include <array>
#include <iostream>
struct Entry {const char* name;const char* sha;};
void check(bool value){if(!value)throw std::runtime_error("payload identity regression");}
int main(){
    using indago::payload::group_identity;
    std::array<Entry,4> a{{{"frida/worker","aaa"},{"ghidra/java/runtime","bbb"},{"ilspy/worker","ccc"},{"enrichment/capa","ddd"}}};
    const auto runtime=group_identity(a,"runtime"),ghidra=group_identity(a,"ghidra");
    auto b=a;b[3].sha="changed";
    check(runtime==group_identity(b,"runtime"));check(ghidra==group_identity(b,"ghidra"));
    check(group_identity(a,"enrichment")!=group_identity(b,"enrichment"));
    b=a;std::swap(b[0],b[3]);check(runtime==group_identity(b,"runtime"));
    b=a;b[0].sha="changed";check(runtime!=group_identity(b,"runtime"));
    b=a;b[0].name="frida/renamed";check(runtime!=group_identity(b,"runtime"));
    bool rejected=false;try{(void)group_identity(a,"../bad");}catch(...){rejected=true;}check(rejected);
    b=a;b[1]=b[0];rejected=false;try{(void)group_identity(b,"runtime");}catch(...){rejected=true;}check(rejected);
    b=a;b[0].name=nullptr;rejected=false;try{(void)group_identity(b,"runtime");}catch(...){rejected=true;}check(rejected);
    std::cout<<"payload group identity checks passed\n";
}
