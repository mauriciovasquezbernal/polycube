/**
* k8switch API
* Kubernetes HyperSwitch Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "PortsJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

PortsJsonObject::PortsJsonObject() :
  m_nameIsSet (false),
  m_uuidIsSet (false),
  m_statusIsSet (false),
  m_peerIsSet (false),
  m_type (PortsTypeEnum::DEFAULT),
  m_typeIsSet (true) { }

PortsJsonObject::PortsJsonObject(nlohmann::json& val) :
  m_nameIsSet (false),
  m_uuidIsSet (false),
  m_statusIsSet (false),
  m_peerIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_type (string_to_PortsTypeEnum(val.at("type").get<std::string>())),
  m_typeIsSet (true) {

  if (val.count("uuid") != 0) {
    setUuid(val.at("uuid").get<std::string>());
  }

  if (val.count("status") != 0) {
    setStatus(string_to_PortsStatusEnum(val.at("status").get<std::string>()));
  }

  if (val.count("peer") != 0) {
    setPeer(val.at("peer").get<std::string>());
  }

}

nlohmann::json PortsJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["name"] = m_name;
  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_statusIsSet) {
    val["status"] = PortsStatusEnum_to_string(m_status);
  }

  if (m_peerIsSet) {
    val["peer"] = m_peer;
  }

  if (m_typeIsSet) {
    val["type"] = PortsTypeEnum_to_string(m_type);
  }


  return val;
}

nlohmann::json PortsJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Port Name)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(port1)POLYCUBE";

  return val;
}

nlohmann::json PortsJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["uuid"]["name"] = "uuid";
  val["uuid"]["type"] = "leaf"; // Suppose that type is leaf
  val["uuid"]["simpletype"] = "string";
  val["uuid"]["description"] = R"POLYCUBE(UUID of the port)POLYCUBE";
  val["uuid"]["example"] = R"POLYCUBE()POLYCUBE";
  val["status"]["name"] = "status";
  val["status"]["type"] = "leaf"; // Suppose that type is leaf
  val["status"]["simpletype"] = "string";
  val["status"]["description"] = R"POLYCUBE(Status of the port (UP or DOWN))POLYCUBE";
  val["status"]["example"] = R"POLYCUBE()POLYCUBE";
  val["peer"]["name"] = "peer";
  val["peer"]["type"] = "leaf"; // Suppose that type is leaf
  val["peer"]["simpletype"] = "string";
  val["peer"]["description"] = R"POLYCUBE(Peer name, such as a network interfaces (e.g., 'veth0') or another cube (e.g., 'br1:port2'))POLYCUBE";
  val["peer"]["example"] = R"POLYCUBE(r0:port1)POLYCUBE";
  val["type"]["name"] = "type";
  val["type"]["type"] = "leaf"; // Suppose that type is leaf
  val["type"]["simpletype"] = "string";
  val["type"]["description"] = R"POLYCUBE(Type of the LB port (e.g. NODEPORT or DEFAULT))POLYCUBE";
  val["type"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json PortsJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["peer"]["name"] = "peer";
  val["peer"]["simpletype"] = "string";
  val["peer"]["description"] = R"POLYCUBE(Peer name, such as a network interfaces (e.g., 'veth0') or another cube (e.g., 'br1:port2'))POLYCUBE";
  val["peer"]["example"] = R"POLYCUBE(r0:port1)POLYCUBE";
  val["type"]["name"] = "type";
  val["type"]["simpletype"] = "string";
  val["type"]["description"] = R"POLYCUBE(Type of the LB port (e.g. NODEPORT or DEFAULT))POLYCUBE";
  val["type"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json PortsJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> PortsJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string PortsJsonObject::getName() const {
  return m_name;
}

void PortsJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool PortsJsonObject::nameIsSet() const {
  return m_nameIsSet;
}





std::string PortsJsonObject::getUuid() const {
  return m_uuid;
}

void PortsJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool PortsJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void PortsJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



PortsStatusEnum PortsJsonObject::getStatus() const {
  return m_status;
}

void PortsJsonObject::setStatus(PortsStatusEnum value) {
  m_status = value;
  m_statusIsSet = true;
}

bool PortsJsonObject::statusIsSet() const {
  return m_statusIsSet;
}

void PortsJsonObject::unsetStatus() {
  m_statusIsSet = false;
}

std::string PortsJsonObject::PortsStatusEnum_to_string(const PortsStatusEnum &value){
  switch(value){
    case PortsStatusEnum::UP:
      return std::string("up");
    case PortsStatusEnum::DOWN:
      return std::string("down");
    default:
      throw std::runtime_error("Bad Ports status");
  }
}

PortsStatusEnum PortsJsonObject::string_to_PortsStatusEnum(const std::string &str){
  if (JsonObjectBase::iequals("up", str))
    return PortsStatusEnum::UP;
  if (JsonObjectBase::iequals("down", str))
    return PortsStatusEnum::DOWN;
  throw std::runtime_error("Ports status is invalid");
}


std::string PortsJsonObject::getPeer() const {
  return m_peer;
}

void PortsJsonObject::setPeer(std::string value) {
  m_peer = value;
  m_peerIsSet = true;
}

bool PortsJsonObject::peerIsSet() const {
  return m_peerIsSet;
}

void PortsJsonObject::unsetPeer() {
  m_peerIsSet = false;
}



PortsTypeEnum PortsJsonObject::getType() const {
  return m_type;
}

void PortsJsonObject::setType(PortsTypeEnum value) {
  m_type = value;
  m_typeIsSet = true;
}

bool PortsJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void PortsJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string PortsJsonObject::PortsTypeEnum_to_string(const PortsTypeEnum &value){
  switch(value){
    case PortsTypeEnum::DEFAULT:
      return std::string("default");
    case PortsTypeEnum::NODEPORT:
      return std::string("nodeport");
    default:
      throw std::runtime_error("Bad Ports type");
  }
}

PortsTypeEnum PortsJsonObject::string_to_PortsTypeEnum(const std::string &str){
  if (JsonObjectBase::iequals("default", str))
    return PortsTypeEnum::DEFAULT;
  if (JsonObjectBase::iequals("nodeport", str))
    return PortsTypeEnum::NODEPORT;
  throw std::runtime_error("Ports type is invalid");
}



}
}
}
}


