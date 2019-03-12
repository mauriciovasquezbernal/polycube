/**
* iptables API
* iptables API generated from iptables.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "ChainResetCountersOutputJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

ChainResetCountersOutputJsonObject::ChainResetCountersOutputJsonObject() {
  m_resultIsSet = false;
}

ChainResetCountersOutputJsonObject::ChainResetCountersOutputJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_resultIsSet = false;


  if (val.count("result")) {
    setResult(val.at("result").get<bool>());
  }
}

nlohmann::json ChainResetCountersOutputJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_resultIsSet) {
    val["result"] = m_result;
  }

  return val;
}

bool ChainResetCountersOutputJsonObject::getResult() const {
  return m_result;
}

void ChainResetCountersOutputJsonObject::setResult(bool value) {
  m_result = value;
  m_resultIsSet = true;
}

bool ChainResetCountersOutputJsonObject::resultIsSet() const {
  return m_resultIsSet;
}

void ChainResetCountersOutputJsonObject::unsetResult() {
  m_resultIsSet = false;
}


nlohmann::json ChainResetCountersOutputJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json ChainResetCountersOutputJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["result"]["name"] = "result";
  val["result"]["type"] = "leaf"; // Suppose that type is leaf
  val["result"]["simpletype"] = "boolean";
  val["result"]["description"] = R"POLYCUBE(True if the operation is successful)POLYCUBE";
  val["result"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json ChainResetCountersOutputJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["result"]["name"] = "result";
  val["result"]["simpletype"] = "boolean";
  val["result"]["description"] = R"POLYCUBE(True if the operation is successful)POLYCUBE";
  val["result"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json ChainResetCountersOutputJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> ChainResetCountersOutputJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

}
}
}
}

