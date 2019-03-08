/**
* simplebridge API
* simplebridge API generated from simplebridge.yang
*
* OpenAPI spec version: 1.0.0
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

PortsJsonObject::PortsJsonObject() {
  m_nameIsSet = false;
  m_macIsSet = false;
}

PortsJsonObject::PortsJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_nameIsSet = false;
  m_macIsSet = false;


  if (val.count("name")) {
    setName(val.at("name").get<std::string>());
  }

  if (val.count("mac")) {
    setMac(val.at("mac").get<std::string>());
  }
}

nlohmann::json PortsJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  val.update(getBase());

  if (m_nameIsSet) {
    val["name"] = m_name;
  }

  if (m_macIsSet) {
    val["mac"] = m_mac;
  }

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



std::string PortsJsonObject::getMac() const {
  return m_mac;
}

void PortsJsonObject::setMac(std::string value) {
  m_mac = value;
  m_macIsSet = true;
}

bool PortsJsonObject::macIsSet() const {
  return m_macIsSet;
}

void PortsJsonObject::unsetMac() {
  m_macIsSet = false;
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
  val["mac"]["name"] = "mac";
  val["mac"]["type"] = "leaf"; // Suppose that type is leaf
  val["mac"]["simpletype"] = "string";
  val["mac"]["description"] = R"POLYCUBE(MAC address of the port)POLYCUBE";
  val["mac"]["example"] = R"POLYCUBE(C5:13:2D:36:27:9B)POLYCUBE";

  return val;
}

nlohmann::json PortsJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["peer"]["name"] = "peer";
  val["peer"]["simpletype"] = "string";
  val["peer"]["description"] = R"POLYCUBE(Peer name, such as a network interfaces (e.g., 'veth0') or another cube (e.g., 'br1:port2'))POLYCUBE";
  val["peer"]["example"] = R"POLYCUBE(r0:port1)POLYCUBE";

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

}
}
}
}

