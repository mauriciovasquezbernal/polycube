/**
* firewall API
* Firewall Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

#include "JsonObjectBase.h"

namespace io {
namespace swagger {
namespace server {
namespace model {

bool JsonObjectBase::iequals(const std::string &a, const std::string &b) {
  if(a.size() != b.size())
    return false;
  for (unsigned int i = 0; i < a.size(); i++){
    if(tolower(a[i]) != tolower(b[i]))
      return false;
  }
  return true;
}

std::string JsonObjectBase::toJson(const std::string& value) {
  return value;
}

std::string JsonObjectBase::toJson(const std::time_t& value) {
  char buf[sizeof "2011-10-08T07:07:09Z"];
  strftime(buf, sizeof buf, "%FT%TZ", gmtime(&value));
  return buf;
}

int32_t JsonObjectBase::toJson(int32_t value) {
  return value;
}

int64_t JsonObjectBase::toJson(int64_t value) {
  return value;
}

double JsonObjectBase::toJson(double value) {
  return value;
}

bool JsonObjectBase::toJson(bool value) {
  return value;
}

nlohmann::json JsonObjectBase::toJson(const JsonObjectBase &content) {
  return content.toJson();
}

}
}
}
}
