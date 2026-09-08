#include "indago/contracts.hpp"
#include "contracts_data.hpp"
#include <regex>
#include <stdexcept>
namespace indago {
using Json=nlohmann::json;
Json contract_schema(const std::string& name) {
    if(name=="action")return Json::parse(action_schema);
    if(name=="result")return Json::parse(result_schema);
    if(name=="evidence")return Json::parse(evidence_schema);
    if(name=="runtime-action")return Json::parse(runtime_action_schema);
    if(name=="workbench")return Json::parse(workbench_schema);
    throw std::runtime_error("unknown contract: "+name);
}
namespace {
bool type(const Json& v,const std::string& t) {
    return t=="object"?v.is_object():t=="array"?v.is_array():t=="string"?v.is_string():t=="integer"?v.is_number_integer():t=="number"?v.is_number():t=="boolean"?v.is_boolean():t=="null"?v.is_null():false;
}
// Implements exactly the vocabulary used by the bundled schemas, not an
// arbitrary external JSON Schema interpreter. Contracts are embedded at build.
void validate(const Json& s,const Json& v,const std::string& path) {
    auto fail=[&](const std::string& why){throw std::runtime_error("contract "+path+": "+why);};
    if(s.contains("type")){bool ok=false; if(s["type"].is_array()){for(const auto& t:s["type"])ok|=type(v,t);}else ok=type(v,s["type"]);if(!ok)fail("wrong type");}
    if(s.contains("const")&&s["const"]!=v)fail("wrong constant");
    if(s.contains("enum")&&std::find(s["enum"].begin(),s["enum"].end(),v)==s["enum"].end())fail("unsupported value");
    if(v.is_object()){
        if(s.contains("required"))for(const auto& key:s["required"])if(!v.contains(key.get<std::string>()))fail("missing "+key.get<std::string>());
        const auto properties=s.value("properties",Json::object());
        for(auto it=v.begin();it!=v.end();++it){if(properties.contains(it.key()))validate(properties[it.key()],it.value(),path+"/"+it.key());else if(s.value("additionalProperties",true)==false)fail("unknown field "+it.key());}
    }
    if(v.is_array()){
        if(s.contains("maxItems")&&v.size()>s["maxItems"].get<std::size_t>())fail("too many items");
        if(s.contains("minItems")&&v.size()<s["minItems"].get<std::size_t>())fail("too few items");
        if(s.contains("items"))for(std::size_t i=0;i<v.size();++i)validate(s["items"],v[i],path+"/"+std::to_string(i));
    }
    if(v.is_string()){
        const auto& text=v.get_ref<const std::string&>();
        if(s.contains("minLength")&&text.size()<s["minLength"].get<std::size_t>())fail("too short");
        if(s.contains("maxLength")&&text.size()>s["maxLength"].get<std::size_t>())fail("too long");
        if(s.contains("pattern")&&!std::regex_search(text,std::regex(s["pattern"].get<std::string>())))fail("invalid format");
    }
    if(v.is_number()){
        if(s.contains("minimum")&&v<s["minimum"])fail("below minimum");
        if(s.contains("maximum")&&v>s["maximum"])fail("above maximum");
    }
}
}
void validate_contract(const std::string& name,const Json& value){validate(contract_schema(name),value,name);}
}
