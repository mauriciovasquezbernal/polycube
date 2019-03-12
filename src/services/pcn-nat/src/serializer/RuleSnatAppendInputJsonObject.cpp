/**
* nat API
* nat API generated from nat.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "RuleSnatAppendInputJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

RuleSnatAppendInputJsonObject::RuleSnatAppendInputJsonObject() {
  m_internalNetIsSet = false;
  m_externalIpIsSet = false;
}

RuleSnatAppendInputJsonObject::RuleSnatAppendInputJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_internalNetIsSet = false;
  m_externalIpIsSet = false;


  if (val.count("internal-net")) {
    setInternalNet(val.at("internal-net").get<std::string>());
  }

  if (val.count("external-ip")) {
    setExternalIp(val.at("external-ip").get<std::string>());
  }
}

nlohmann::json RuleSnatAppendInputJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_internalNetIsSet) {
    val["internal-net"] = m_internalNet;
  }

  if (m_externalIpIsSet) {
    val["external-ip"] = m_externalIp;
  }

  return val;
}

std::string RuleSnatAppendInputJsonObject::getInternalNet() const {
  return m_internalNet;
}

void RuleSnatAppendInputJsonObject::setInternalNet(std::string value) {
  m_internalNet = value;
  m_internalNetIsSet = true;
}

bool RuleSnatAppendInputJsonObject::internalNetIsSet() const {
  return m_internalNetIsSet;
}



std::string RuleSnatAppendInputJsonObject::getExternalIp() const {
  return m_externalIp;
}

void RuleSnatAppendInputJsonObject::setExternalIp(std::string value) {
  m_externalIp = value;
  m_externalIpIsSet = true;
}

bool RuleSnatAppendInputJsonObject::externalIpIsSet() const {
  return m_externalIpIsSet;
}




nlohmann::json RuleSnatAppendInputJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json RuleSnatAppendInputJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["internal-net"]["name"] = "internal-net";
  val["internal-net"]["type"] = "leaf"; // Suppose that type is leaf
  val["internal-net"]["simpletype"] = "string";
  val["internal-net"]["description"] = R"POLYCUBE(Internal IP address (or subnet))POLYCUBE";
  val["internal-net"]["example"] = R"POLYCUBE(10.0.0.0/24 or 10.0.0.1/32)POLYCUBE";
  val["external-ip"]["name"] = "external-ip";
  val["external-ip"]["type"] = "leaf"; // Suppose that type is leaf
  val["external-ip"]["simpletype"] = "string";
  val["external-ip"]["description"] = R"POLYCUBE(Natted source IP address)POLYCUBE";
  val["external-ip"]["example"] = R"POLYCUBE(8.8.8.8)POLYCUBE";

  return val;
}

nlohmann::json RuleSnatAppendInputJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["internal-net"]["name"] = "internal-net";
  val["internal-net"]["simpletype"] = "string";
  val["internal-net"]["description"] = R"POLYCUBE(Internal IP address (or subnet))POLYCUBE";
  val["internal-net"]["example"] = R"POLYCUBE(10.0.0.0/24 or 10.0.0.1/32)POLYCUBE";
  val["external-ip"]["name"] = "external-ip";
  val["external-ip"]["simpletype"] = "string";
  val["external-ip"]["description"] = R"POLYCUBE(Natted source IP address)POLYCUBE";
  val["external-ip"]["example"] = R"POLYCUBE(8.8.8.8)POLYCUBE";

  return val;
}

nlohmann::json RuleSnatAppendInputJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> RuleSnatAppendInputJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

}
}
}
}

