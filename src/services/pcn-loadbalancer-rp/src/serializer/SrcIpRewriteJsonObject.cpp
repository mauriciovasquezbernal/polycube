/**
* lbrp API
* LoadBalancer Reverse-Proxy Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "SrcIpRewriteJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

SrcIpRewriteJsonObject::SrcIpRewriteJsonObject() : 
  m_ipRangeIsSet (false),
  m_newIpRangeIsSet (false) { }

SrcIpRewriteJsonObject::SrcIpRewriteJsonObject(nlohmann::json& val) : 
  m_ipRangeIsSet (false),
  m_newIpRangeIsSet (false) { 
  if (val.count("ip-range") != 0) {
    setIpRange(val.at("ip-range").get<std::string>());
  }

  if (val.count("new_ip_range") != 0) {
    setNewIpRange(val.at("new_ip_range").get<std::string>());
  }
}

nlohmann::json SrcIpRewriteJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_ipRangeIsSet) {
    val["ip-range"] = m_ipRange;
  }

  if (m_newIpRangeIsSet) {
    val["new_ip_range"] = m_newIpRange;
  }


  return val;
}

nlohmann::json SrcIpRewriteJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json SrcIpRewriteJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["ip-range"]["name"] = "ip-range";
  val["ip-range"]["type"] = "leaf"; // Suppose that type is leaf
  val["ip-range"]["simpletype"] = "string";
  val["ip-range"]["description"] = R"POLYCUBE(Range of IP addresses of the clients that must be replaced)POLYCUBE";
  val["ip-range"]["example"] = R"POLYCUBE(10.2.0.0/24)POLYCUBE";
  val["new_ip_range"]["name"] = "new_ip_range";
  val["new_ip_range"]["type"] = "leaf"; // Suppose that type is leaf
  val["new_ip_range"]["simpletype"] = "string";
  val["new_ip_range"]["description"] = R"POLYCUBE(Range of IP addresses of the that must be used to replace client addresses)POLYCUBE";
  val["new_ip_range"]["example"] = R"POLYCUBE(10.3.0.0/24)POLYCUBE";

  return val;
}

nlohmann::json SrcIpRewriteJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["ip-range"]["name"] = "ip-range";
  val["ip-range"]["simpletype"] = "string";
  val["ip-range"]["description"] = R"POLYCUBE(Range of IP addresses of the clients that must be replaced)POLYCUBE";
  val["ip-range"]["example"] = R"POLYCUBE(10.2.0.0/24)POLYCUBE";
  val["new_ip_range"]["name"] = "new_ip_range";
  val["new_ip_range"]["simpletype"] = "string";
  val["new_ip_range"]["description"] = R"POLYCUBE(Range of IP addresses of the that must be used to replace client addresses)POLYCUBE";
  val["new_ip_range"]["example"] = R"POLYCUBE(10.3.0.0/24)POLYCUBE";

  return val;
}

nlohmann::json SrcIpRewriteJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> SrcIpRewriteJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string SrcIpRewriteJsonObject::getIpRange() const {
  return m_ipRange;
}

void SrcIpRewriteJsonObject::setIpRange(std::string value) {
  m_ipRange = value;
  m_ipRangeIsSet = true;
}

bool SrcIpRewriteJsonObject::ipRangeIsSet() const {
  return m_ipRangeIsSet;
}

void SrcIpRewriteJsonObject::unsetIpRange() {
  m_ipRangeIsSet = false;
}



std::string SrcIpRewriteJsonObject::getNewIpRange() const {
  return m_newIpRange;
}

void SrcIpRewriteJsonObject::setNewIpRange(std::string value) {
  m_newIpRange = value;
  m_newIpRangeIsSet = true;
}

bool SrcIpRewriteJsonObject::newIpRangeIsSet() const {
  return m_newIpRangeIsSet;
}

void SrcIpRewriteJsonObject::unsetNewIpRange() {
  m_newIpRangeIsSet = false;
}




}
}
}
}


