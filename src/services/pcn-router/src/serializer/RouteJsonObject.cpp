/**
* router API
* Router Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "RouteJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

RouteJsonObject::RouteJsonObject() : 
  m_networkIsSet (false),
  m_netmaskIsSet (false),
  m_nexthopIsSet (false),
  m_interfaceIsSet (false),
  m_pathcost (1),
  m_pathcostIsSet (true) { }

RouteJsonObject::RouteJsonObject(nlohmann::json& val) : 
  m_networkIsSet (false),
  m_netmaskIsSet (false),
  m_nexthopIsSet (false),
  m_interfaceIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_pathcost (val.at("pathcost").get<int32_t>()),
  m_pathcostIsSet (true) { 



  if (val.count("interface") != 0) {
    setInterface(val.at("interface").get<std::string>());
  }

}

nlohmann::json RouteJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["network"] = m_network;
  val["netmask"] = m_netmask;
  val["nexthop"] = m_nexthop;
  if (m_interfaceIsSet) {
    val["interface"] = m_interface;
  }

  if (m_pathcostIsSet) {
    val["pathcost"] = m_pathcost;
  }


  return val;
}

nlohmann::json RouteJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["network"]["name"] = "network";
  val["network"]["type"] = "key";
  val["network"]["simpletype"] = "string";
  val["network"]["description"] = R"POLYCUBE(Destination network IP)POLYCUBE";
  val["network"]["example"] = R"POLYCUBE(123.13.34.0)POLYCUBE";
  val["netmask"]["name"] = "netmask";
  val["netmask"]["type"] = "key";
  val["netmask"]["simpletype"] = "string";
  val["netmask"]["description"] = R"POLYCUBE(Destination network netmask)POLYCUBE";
  val["netmask"]["example"] = R"POLYCUBE(255.255.255.0)POLYCUBE";
  val["nexthop"]["name"] = "nexthop";
  val["nexthop"]["type"] = "key";
  val["nexthop"]["simpletype"] = "string";
  val["nexthop"]["description"] = R"POLYCUBE(Next hop; if destination is local will be shown 'local' instead of the ip address)POLYCUBE";
  val["nexthop"]["example"] = R"POLYCUBE(123.14.23.3)POLYCUBE";

  return val;
}

nlohmann::json RouteJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["interface"]["name"] = "interface";
  val["interface"]["type"] = "leaf"; // Suppose that type is leaf
  val["interface"]["simpletype"] = "string";
  val["interface"]["description"] = R"POLYCUBE(Outgoing interface)POLYCUBE";
  val["interface"]["example"] = R"POLYCUBE(port2)POLYCUBE";
  val["pathcost"]["name"] = "pathcost";
  val["pathcost"]["type"] = "leaf"; // Suppose that type is leaf
  val["pathcost"]["simpletype"] = "integer";
  val["pathcost"]["description"] = R"POLYCUBE(Cost of this route)POLYCUBE";
  val["pathcost"]["example"] = R"POLYCUBE(10)POLYCUBE";

  return val;
}

nlohmann::json RouteJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["pathcost"]["name"] = "pathcost";
  val["pathcost"]["simpletype"] = "integer";
  val["pathcost"]["description"] = R"POLYCUBE(Cost of this route)POLYCUBE";
  val["pathcost"]["example"] = R"POLYCUBE(10)POLYCUBE";

  return val;
}

nlohmann::json RouteJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> RouteJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string RouteJsonObject::getNetwork() const {
  return m_network;
}

void RouteJsonObject::setNetwork(std::string value) {
  m_network = value;
  m_networkIsSet = true;
}

bool RouteJsonObject::networkIsSet() const {
  return m_networkIsSet;
}





std::string RouteJsonObject::getNetmask() const {
  return m_netmask;
}

void RouteJsonObject::setNetmask(std::string value) {
  m_netmask = value;
  m_netmaskIsSet = true;
}

bool RouteJsonObject::netmaskIsSet() const {
  return m_netmaskIsSet;
}





std::string RouteJsonObject::getNexthop() const {
  return m_nexthop;
}

void RouteJsonObject::setNexthop(std::string value) {
  m_nexthop = value;
  m_nexthopIsSet = true;
}

bool RouteJsonObject::nexthopIsSet() const {
  return m_nexthopIsSet;
}





std::string RouteJsonObject::getInterface() const {
  return m_interface;
}

void RouteJsonObject::setInterface(std::string value) {
  m_interface = value;
  m_interfaceIsSet = true;
}

bool RouteJsonObject::interfaceIsSet() const {
  return m_interfaceIsSet;
}

void RouteJsonObject::unsetInterface() {
  m_interfaceIsSet = false;
}



int32_t RouteJsonObject::getPathcost() const {
  return m_pathcost;
}

void RouteJsonObject::setPathcost(int32_t value) {
  m_pathcost = value;
  m_pathcostIsSet = true;
}

bool RouteJsonObject::pathcostIsSet() const {
  return m_pathcostIsSet;
}

void RouteJsonObject::unsetPathcost() {
  m_pathcostIsSet = false;
}




}
}
}
}


