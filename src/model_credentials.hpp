#pragma once
#include <string>
#include <sstream>
#include <stdexcept>
namespace indago {
inline std::string parse_model_credential(std::string input, const std::string &format, const std::string &variable="OPENROUTER_API_KEY") {
  auto trim=[](std::string s) {
    const auto first=s.find_first_not_of(" \t\r\n");
    return first==s.npos?std::string{}:s.substr(first,s.find_last_not_of(" \t\r\n")-first+1);
  };
  std::string secret;
  if(format=="raw")secret=trim(input);
  else if(format=="dotenv") {
    if(input.starts_with("\xef\xbb\xbf"))input.erase(0,3);
    std::istringstream lines(input);std::string line;bool found=false;
    while(std::getline(lines,line)) {
      line=trim(line);if(line.starts_with("export "))line=trim(line.substr(7));
      auto equal=line.find('=');
      if(equal==line.npos||trim(line.substr(0,equal))!=variable)continue;
      if(found)throw std::runtime_error("duplicate OpenRouter credential assignment");
      found=true;secret=trim(line.substr(equal+1));
      if(secret.size()>=2&&(secret.front()=='\''||secret.front()=='\"')) {
        const auto end=secret.find(secret.front(),1);
        if(end==secret.npos)throw std::runtime_error("invalid quoted OpenRouter credential");
        const auto tail=trim(secret.substr(end+1));
        if(!tail.empty()&&!tail.starts_with('#'))throw std::runtime_error("invalid credential suffix");
        secret=secret.substr(1,end-1);
      } else {auto comment=secret.find(" #");if(comment!=secret.npos)secret=trim(secret.substr(0,comment));}
    }
  } else throw std::runtime_error("unsupported credential format");
  if(secret.empty()||secret.size()>4096||secret.find_first_not_of(
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")!=secret.npos)
    throw std::runtime_error("invalid or missing OpenRouter credential");
  return secret;
}
}
