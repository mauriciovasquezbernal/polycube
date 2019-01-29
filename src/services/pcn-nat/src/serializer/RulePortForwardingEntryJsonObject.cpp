/**
* nat API
* NAT Service
*
* OpenAPI spec version: 1.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "RulePortForwardingEntryJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

RulePortForwardingEntryJsonObject::RulePortForwardingEntryJsonObject() : 
  m_idIsSet (false),
  m_externalIpIsSet (false),
  m_externalPortIsSet (false),
  m_protoIsSet (false),
  m_internalIpIsSet (false),
  m_internalPortIsSet (false) { }

RulePortForwardingEntryJsonObject::RulePortForwardingEntryJsonObject(nlohmann::json& val) : 
  m_idIsSet (false),
  // Mandatory item
  m_externalIp (val.at("external-ip").get<std::string>()),
  m_externalIpIsSet (true),
  // Mandatory item
  m_externalPort (val.at("external-port").get<uint16_t>()),
  m_externalPortIsSet (true),
  m_protoIsSet (false),
  // Mandatory item
  m_internalIp (val.at("internal-ip").get<std::string>()),
  m_internalIpIsSet (true),
  // Mandatory item
  m_internalPort (val.at("internal-port").get<uint16_t>()),
  m_internalPortIsSet (true) { 



  if (val.count("proto") != 0) {
    setProto(val.at("proto").get<std::string>());
  }


}

nlohmann::json RulePortForwardingEntryJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["id"] = m_id;
  val["external-ip"] = m_externalIp;
  val["external-port"] = m_externalPort;
  if (m_protoIsSet) {
    val["proto"] = m_proto;
  }

  val["internal-ip"] = m_internalIp;
  val["internal-port"] = m_internalPort;

  return val;
}

nlohmann::json RulePortForwardingEntryJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["id"]["name"] = "id";
  val["id"]["type"] = "key";
  val["id"]["simpletype"] = "integer";
  val["id"]["description"] = R"POLYCUBE(Rule identifier)POLYCUBE";
  val["id"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json RulePortForwardingEntryJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["external-ip"]["name"] = "external-ip";
  val["external-ip"]["type"] = "leaf"; // Suppose that type is leaf
  val["external-ip"]["simpletype"] = "string";
  val["external-ip"]["description"] = R"POLYCUBE(External destination IP address)POLYCUBE";
  val["external-ip"]["example"] = R"POLYCUBE(8.8.8.8)POLYCUBE";
  val["external-port"]["name"] = "external-port";
  val["external-port"]["type"] = "leaf"; // Suppose that type is leaf
  val["external-port"]["simpletype"] = "integer";
  val["external-port"]["description"] = R"POLYCUBE(External destination L4 port)POLYCUBE";
  val["external-port"]["example"] = R"POLYCUBE()POLYCUBE";
  val["proto"]["name"] = "proto";
  val["proto"]["type"] = "leaf"; // Suppose that type is leaf
  val["proto"]["simpletype"] = "string";
  val["proto"]["description"] = R"POLYCUBE(L4 protocol (TCP, UDP, ALL))POLYCUBE";
  val["proto"]["example"] = R"POLYCUBE()POLYCUBE";
  val["internal-ip"]["name"] = "internal-ip";
  val["internal-ip"]["type"] = "leaf"; // Suppose that type is leaf
  val["internal-ip"]["simpletype"] = "string";
  val["internal-ip"]["description"] = R"POLYCUBE(Internal destination IP address)POLYCUBE";
  val["internal-ip"]["example"] = R"POLYCUBE(10.0.0.1)POLYCUBE";
  val["internal-port"]["name"] = "internal-port";
  val["internal-port"]["type"] = "leaf"; // Suppose that type is leaf
  val["internal-port"]["simpletype"] = "integer";
  val["internal-port"]["description"] = R"POLYCUBE(Internal destination L4 port)POLYCUBE";
  val["internal-port"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json RulePortForwardingEntryJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["external-ip"]["name"] = "external-ip";
  val["external-ip"]["simpletype"] = "string";
  val["external-ip"]["description"] = R"POLYCUBE(External destination IP address)POLYCUBE";
  val["external-ip"]["example"] = R"POLYCUBE(8.8.8.8)POLYCUBE";
  val["external-port"]["name"] = "external-port";
  val["external-port"]["simpletype"] = "integer";
  val["external-port"]["description"] = R"POLYCUBE(External destination L4 port)POLYCUBE";
  val["external-port"]["example"] = R"POLYCUBE()POLYCUBE";
  val["proto"]["name"] = "proto";
  val["proto"]["simpletype"] = "string";
  val["proto"]["description"] = R"POLYCUBE(L4 protocol (TCP, UDP, ALL))POLYCUBE";
  val["proto"]["example"] = R"POLYCUBE()POLYCUBE";
  val["internal-ip"]["name"] = "internal-ip";
  val["internal-ip"]["simpletype"] = "string";
  val["internal-ip"]["description"] = R"POLYCUBE(Internal destination IP address)POLYCUBE";
  val["internal-ip"]["example"] = R"POLYCUBE(10.0.0.1)POLYCUBE";
  val["internal-port"]["name"] = "internal-port";
  val["internal-port"]["simpletype"] = "integer";
  val["internal-port"]["description"] = R"POLYCUBE(Internal destination L4 port)POLYCUBE";
  val["internal-port"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json RulePortForwardingEntryJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> RulePortForwardingEntryJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

uint32_t RulePortForwardingEntryJsonObject::getId() const {
  return m_id;
}

void RulePortForwardingEntryJsonObject::setId(uint32_t value) {
  m_id = value;
  m_idIsSet = true;
}

bool RulePortForwardingEntryJsonObject::idIsSet() const {
  return m_idIsSet;
}





std::string RulePortForwardingEntryJsonObject::getExternalIp() const {
  return m_externalIp;
}

void RulePortForwardingEntryJsonObject::setExternalIp(std::string value) {
  m_externalIp = value;
  m_externalIpIsSet = true;
}

bool RulePortForwardingEntryJsonObject::externalIpIsSet() const {
  return m_externalIpIsSet;
}





uint16_t RulePortForwardingEntryJsonObject::getExternalPort() const {
  return m_externalPort;
}

void RulePortForwardingEntryJsonObject::setExternalPort(uint16_t value) {
  m_externalPort = value;
  m_externalPortIsSet = true;
}

bool RulePortForwardingEntryJsonObject::externalPortIsSet() const {
  return m_externalPortIsSet;
}





std::string RulePortForwardingEntryJsonObject::getProto() const {
  return m_proto;
}

void RulePortForwardingEntryJsonObject::setProto(std::string value) {
  m_proto = value;
  m_protoIsSet = true;
}

bool RulePortForwardingEntryJsonObject::protoIsSet() const {
  return m_protoIsSet;
}

void RulePortForwardingEntryJsonObject::unsetProto() {
  m_protoIsSet = false;
}



std::string RulePortForwardingEntryJsonObject::getInternalIp() const {
  return m_internalIp;
}

void RulePortForwardingEntryJsonObject::setInternalIp(std::string value) {
  m_internalIp = value;
  m_internalIpIsSet = true;
}

bool RulePortForwardingEntryJsonObject::internalIpIsSet() const {
  return m_internalIpIsSet;
}





uint16_t RulePortForwardingEntryJsonObject::getInternalPort() const {
  return m_internalPort;
}

void RulePortForwardingEntryJsonObject::setInternalPort(uint16_t value) {
  m_internalPort = value;
  m_internalPortIsSet = true;
}

bool RulePortForwardingEntryJsonObject::internalPortIsSet() const {
  return m_internalPortIsSet;
}






}
}
}
}


