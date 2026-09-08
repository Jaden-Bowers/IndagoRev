#include "indago/lief.hpp"
#include <iostream>
int main(int argc,char** argv){
    if(argc!=2)return 2;
    try { const auto result=indago::lief_worker(nlohmann::json::parse(argv[1]));std::cout<<result.dump();return result.at("status")=="failed"?1:0; }
    catch(const std::exception& error){std::cerr<<error.what();return 2;}
}
