#pragma once
#include "harness_evidence_read.hpp"
#include <charconv>
#include <limits>

namespace indago {
// Deliberately small: native operands stay attached to their backend snapshot.
// This checks explicit assertions, never infers the meaning of report prose.
inline std::uint64_t harness_unsigned(const wb::J &value) {
    if (value.is_number_unsigned()) return value.get<std::uint64_t>();
    if (value.is_number_integer() && value.get<std::int64_t>() >= 0)
        return static_cast<std::uint64_t>(value.get<std::int64_t>());
    if (!value.is_string()) throw std::runtime_error("Expected unsigned integer or hexadecimal address");
    auto text=value.get<std::string>();
    int base=10;std::size_t offset=0;
    if(text.starts_with("0x")||text.starts_with("0X")){base=16;offset=2;}
    std::uint64_t result=0;
    const auto parsed=std::from_chars(text.data()+offset,text.data()+text.size(),result,base);
    if(offset==text.size()||parsed.ec!=std::errc()||parsed.ptr!=text.data()+text.size())
        throw std::runtime_error("Invalid or overflowing unsigned integer");
    return result;
}
inline wb::J harness_validate(const ProjectStore &store,const wb::J &inv,
                              const wb::J &checks,const wb::J &allowed_ids=nullptr) {
    using namespace wb;
    if(!checks.is_array()||checks.empty()||checks.size()>8)
        throw std::runtime_error("Validation requires 1 to 8 explicit checks");
    J result{{"schema","indago.claim-checks.v1"},{"status","passed"},
             {"checks",J::array()},{"semantic_entailment_checked",false},
             {"scope","Exact snapshot operands only; prose, completeness and backend semantic equivalence are not proven"}};
    for(const auto &check:checks){
        keys(check,{"operation","operands","expected","mask"});
        const auto op=check.at("operation").get<std::string>();
        const auto count=op=="equal"||op=="bits"?1u:op=="sum"?2u:op=="contains"?3u:0u;
        const auto &operands=check.at("operands");
        if(!count||!operands.is_array()||operands.size()!=count)
            throw std::runtime_error("Invalid check operation or operand count");
        if(check.contains("mask")!=(op=="bits"))throw std::runtime_error("Only bits requires mask");
        J values=J::array(),sources=J::array();
        for(const auto &ref:operands){
            keys(ref,{"evidence_id","pointer","raw_sha256"});
            const auto id=ref.at("evidence_id");
            if(!allowed_ids.is_null()&&std::find(allowed_ids.begin(),allowed_ids.end(),id)==allowed_ids.end())
                throw std::runtime_error("Check operand must be cited by its claim");
            // Require a pin even on the first check; obtain it from evidence/read.
            auto page=harness_evidence_page(store,inv,{{"id",id},{"pointer",ref.at("pointer")},
                {"raw_sha256",ref.at("raw_sha256")},{"max_bytes",512}});
            if(!page.value("source_verified",false)||page.value("partial",true))
                throw std::runtime_error("Check requires a complete verified scalar page");
            J value=page.contains("text")?page.at("text"):page.at("value");
            if(!value.is_primitive()||value.dump().size()>512)
                throw std::runtime_error("Check operand is not a bounded scalar");
            values.push_back(value);
            sources.push_back({{"evidence_id",id},{"pointer",ref.at("pointer")},
                {"raw_sha256",page.at("raw_sha256")},{"revision",page.at("revision")},
                {"native_status",page.at("native_status")}});
        }
        J actual;const auto &expected=check.at("expected");
        if(expected.dump().size()>512)throw std::runtime_error("Expected value too large");
        bool matches=false;
        if(op=="equal") {actual=values[0];matches=actual==expected;}
        else if(op=="bits") {
            if(!expected.is_boolean())throw std::runtime_error("bits expected must be boolean");
            const auto mask=harness_unsigned(check.at("mask"));
            if(!mask)throw std::runtime_error("bits mask must be nonzero");
            actual=(harness_unsigned(values[0])&mask)==mask;matches=actual==expected;
        } else {
            const auto base=harness_unsigned(values[0]),size=harness_unsigned(values[1]);
            if(size>std::numeric_limits<std::uint64_t>::max()-base)
                throw std::runtime_error("Unsigned range/addition overflow; no wrapped result accepted");
            if(op=="sum"){actual=base+size;matches=actual.get<std::uint64_t>()==harness_unsigned(expected);}
            else {
                if(!expected.is_boolean())throw std::runtime_error("contains expected must be boolean");
                const auto address=harness_unsigned(values[2]);
                actual=address>=base&&address<base+size;matches=actual==expected;
            }
        }
        result["checks"].push_back({{"operation",op},{"status",matches?"passed":"contradicted"},
            {"actual",actual},{"expected",expected},{"sources",sources}});
        if(!matches)result["status"]="contradicted";
    }
    if(result.dump().size()>12288)throw std::runtime_error("Claim check result exceeds byte budget");
    return result;
}
}
