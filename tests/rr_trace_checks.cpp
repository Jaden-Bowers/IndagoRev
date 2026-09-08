#include "../src/rr_trace.hpp"
#include <fstream>
#include <iostream>
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    const auto root=indago::fs::absolute(argv[1]);
    if(indago::fs::exists(root))return 2;
    indago::fs::create_directories(root);
    for(const auto* name:{"version","events","data","mmaps","tasks"})std::ofstream(root/name)<<name;
    auto check=[&](bool success){if(!success)throw std::runtime_error("rr trace assertion failed");};
    const auto first=indago::replay::trace_manifest(root,1048576,true);
    check(first==indago::replay::trace_manifest(root,1048576,true));
    std::ofstream(root/"data",std::ios::app)<<"changed";
    check(first!=indago::replay::trace_manifest(root,1048576,true));
    auto rejects=[&](auto action){bool rejected=false;try{action();}catch(const std::exception&){rejected=true;}check(rejected);};
    rejects([&]{indago::replay::trace_manifest(root,1,true);});
    indago::fs::create_symlink(root/"data",root/"external-link");
    rejects([&]{indago::replay::trace_manifest(root,1048576,true);});
    indago::fs::remove(root/"external-link");
    indago::fs::create_hard_link(root/"data",root/"hard-link");
    rejects([&]{indago::replay::trace_manifest(root,1048576,true);});
    indago::fs::remove(root/"hard-link");
    indago::fs::create_directory(root/"unexpected-directory");
    rejects([&]{indago::replay::trace_manifest(root,1048576,true);});
    std::cout<<"rr trace manifest: stable identities, mutation, size, symlink, hard-link and directory refusal passed\n";
}
