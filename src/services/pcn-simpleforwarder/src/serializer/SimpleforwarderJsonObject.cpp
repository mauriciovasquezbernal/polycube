/**
* simpleforwarder API
* Simple Forwarder Base Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "SimpleforwarderJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

SimpleforwarderJsonObject::SimpleforwarderJsonObject() : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  m_type (CubeType::TC),
  m_typeIsSet (true),
  m_loglevel (SimpleforwarderLoglevelEnum::INFO),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_actionsIsSet (false) { }

SimpleforwarderJsonObject::SimpleforwarderJsonObject(nlohmann::json& val) : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_type (string_to_CubeType(val.at("type").get<std::string>())),
  m_typeIsSet (true),
  // Item with a default value, granted to be part of the request body
  m_loglevel (string_to_SimpleforwarderLoglevelEnum(val.at("loglevel").get<std::string>())),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_actionsIsSet (false) { 

  if (val.count("uuid") != 0) {
    setUuid(val.at("uuid").get<std::string>());
  }



  m_ports.clear();
  for (auto& item : val["ports"]) { 
    PortsJsonObject newItem { item };
    m_ports.push_back(newItem);
  }
  m_portsIsSet = !m_ports.empty();
  

  m_actions.clear();
  for (auto& item : val["actions"]) { 
    ActionsJsonObject newItem { item };
    m_actions.push_back(newItem);
  }
  m_actionsIsSet = !m_actions.empty();
  
}

nlohmann::json SimpleforwarderJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["name"] = m_name;
  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_typeIsSet) {
    val["type"] = CubeType_to_string(m_type);
  }

  if (m_loglevelIsSet) {
    val["loglevel"] = SimpleforwarderLoglevelEnum_to_string(m_loglevel);
  }

  {
    nlohmann::json jsonArray;
    for (auto& item : m_ports) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["ports"] = jsonArray;
    }
  }
  {
    nlohmann::json jsonArray;
    for (auto& item : m_actions) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["actions"] = jsonArray;
    }
  }

  return val;
}

nlohmann::json SimpleforwarderJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Name of the simpleforwarder service)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(simpleforwarder1)POLYCUBE";

  return val;
}

nlohmann::json SimpleforwarderJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["uuid"]["name"] = "uuid";
  val["uuid"]["type"] = "leaf"; // Suppose that type is leaf
  val["uuid"]["simpletype"] = "string";
  val["uuid"]["description"] = R"POLYCUBE(UUID of the Cube)POLYCUBE";
  val["uuid"]["example"] = R"POLYCUBE()POLYCUBE";
  val["type"]["name"] = "type";
  val["type"]["type"] = "leaf"; // Suppose that type is leaf
  val["type"]["simpletype"] = "string";
  val["type"]["description"] = R"POLYCUBE(Type of the Cube (TC, XDP_SKB, XDP_DRV))POLYCUBE";
  val["type"]["example"] = R"POLYCUBE(TC)POLYCUBE";
  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["type"] = "leaf"; // Suppose that type is leaf
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";
  val["ports"]["name"] = "ports";
  val["ports"]["type"] = "leaf"; // Suppose that type is leaf
  val["ports"]["type"] = "list";
  val["ports"]["description"] = R"POLYCUBE(Entry of the ports table)POLYCUBE";
  val["ports"]["example"] = R"POLYCUBE()POLYCUBE";
  val["actions"]["name"] = "actions";
  val["actions"]["type"] = "leaf"; // Suppose that type is leaf
  val["actions"]["type"] = "list";
  val["actions"]["description"] = R"POLYCUBE(Entry of the Actions table)POLYCUBE";
  val["actions"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json SimpleforwarderJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";

  return val;
}

nlohmann::json SimpleforwarderJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["ports"]["name"] = "ports";
  val["ports"]["type"] = "list";
  val["ports"]["description"] = R"POLYCUBE(Entry of the ports table)POLYCUBE";
  val["ports"]["example"] = R"POLYCUBE()POLYCUBE";
  val["actions"]["name"] = "actions";
  val["actions"]["type"] = "list";
  val["actions"]["description"] = R"POLYCUBE(Entry of the Actions table)POLYCUBE";
  val["actions"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> SimpleforwarderJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string SimpleforwarderJsonObject::getName() const {
  return m_name;
}

void SimpleforwarderJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool SimpleforwarderJsonObject::nameIsSet() const {
  return m_nameIsSet;
}





std::string SimpleforwarderJsonObject::getUuid() const {
  return m_uuid;
}

void SimpleforwarderJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool SimpleforwarderJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void SimpleforwarderJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



CubeType SimpleforwarderJsonObject::getType() const {
  return m_type;
}

void SimpleforwarderJsonObject::setType(CubeType value) {
  m_type = value;
  m_typeIsSet = true;
}

bool SimpleforwarderJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void SimpleforwarderJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string SimpleforwarderJsonObject::CubeType_to_string(const CubeType &value){
  switch(value){
    case CubeType::TC:
      return std::string("tc");
    case CubeType::XDP_SKB:
      return std::string("xdp_skb");
    case CubeType::XDP_DRV:
      return std::string("xdp_drv");
    default:
      throw std::runtime_error("Bad Simpleforwarder type");
  }
}

CubeType SimpleforwarderJsonObject::string_to_CubeType(const std::string &str){
  if (JsonObjectBase::iequals("tc", str))
    return CubeType::TC;
  if (JsonObjectBase::iequals("xdp_skb", str))
    return CubeType::XDP_SKB;
  if (JsonObjectBase::iequals("xdp_drv", str))
    return CubeType::XDP_DRV;
  throw std::runtime_error("Simpleforwarder type is invalid");
}


SimpleforwarderLoglevelEnum SimpleforwarderJsonObject::getLoglevel() const {
  return m_loglevel;
}

void SimpleforwarderJsonObject::setLoglevel(SimpleforwarderLoglevelEnum value) {
  m_loglevel = value;
  m_loglevelIsSet = true;
}

bool SimpleforwarderJsonObject::loglevelIsSet() const {
  return m_loglevelIsSet;
}

void SimpleforwarderJsonObject::unsetLoglevel() {
  m_loglevelIsSet = false;
}

std::string SimpleforwarderJsonObject::SimpleforwarderLoglevelEnum_to_string(const SimpleforwarderLoglevelEnum &value){
  switch(value){
    case SimpleforwarderLoglevelEnum::TRACE:
      return std::string("trace");
    case SimpleforwarderLoglevelEnum::DEBUG:
      return std::string("debug");
    case SimpleforwarderLoglevelEnum::INFO:
      return std::string("info");
    case SimpleforwarderLoglevelEnum::WARN:
      return std::string("warn");
    case SimpleforwarderLoglevelEnum::ERR:
      return std::string("err");
    case SimpleforwarderLoglevelEnum::CRITICAL:
      return std::string("critical");
    case SimpleforwarderLoglevelEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Simpleforwarder loglevel");
  }
}

SimpleforwarderLoglevelEnum SimpleforwarderJsonObject::string_to_SimpleforwarderLoglevelEnum(const std::string &str){
  if (JsonObjectBase::iequals("trace", str))
    return SimpleforwarderLoglevelEnum::TRACE;
  if (JsonObjectBase::iequals("debug", str))
    return SimpleforwarderLoglevelEnum::DEBUG;
  if (JsonObjectBase::iequals("info", str))
    return SimpleforwarderLoglevelEnum::INFO;
  if (JsonObjectBase::iequals("warn", str))
    return SimpleforwarderLoglevelEnum::WARN;
  if (JsonObjectBase::iequals("err", str))
    return SimpleforwarderLoglevelEnum::ERR;
  if (JsonObjectBase::iequals("critical", str))
    return SimpleforwarderLoglevelEnum::CRITICAL;
  if (JsonObjectBase::iequals("off", str))
    return SimpleforwarderLoglevelEnum::OFF;
  throw std::runtime_error("Simpleforwarder loglevel is invalid");
}

  polycube::LogLevel SimpleforwarderJsonObject::getPolycubeLoglevel() const {
    switch(m_loglevel) {
      case SimpleforwarderLoglevelEnum::TRACE:
        return polycube::LogLevel::TRACE;
      case SimpleforwarderLoglevelEnum::DEBUG:
        return polycube::LogLevel::DEBUG;
      case SimpleforwarderLoglevelEnum::INFO:
        return polycube::LogLevel::INFO;
      case SimpleforwarderLoglevelEnum::WARN:
        return polycube::LogLevel::WARN;
      case SimpleforwarderLoglevelEnum::ERR:
        return polycube::LogLevel::ERR;
      case SimpleforwarderLoglevelEnum::CRITICAL:
        return polycube::LogLevel::CRITICAL;
      case SimpleforwarderLoglevelEnum::OFF:
        return polycube::LogLevel::OFF;
    }
  }
const std::vector<PortsJsonObject>& SimpleforwarderJsonObject::getPorts() const{
  return m_ports;
}

void SimpleforwarderJsonObject::addPorts(PortsJsonObject value) {
  m_ports.push_back(value);
}


bool SimpleforwarderJsonObject::portsIsSet() const {
  return m_portsIsSet;
}

void SimpleforwarderJsonObject::unsetPorts() {
  m_portsIsSet = false;
}



const std::vector<ActionsJsonObject>& SimpleforwarderJsonObject::getActions() const{
  return m_actions;
}

void SimpleforwarderJsonObject::addActions(ActionsJsonObject value) {
  m_actions.push_back(value);
}


bool SimpleforwarderJsonObject::actionsIsSet() const {
  return m_actionsIsSet;
}

void SimpleforwarderJsonObject::unsetActions() {
  m_actionsIsSet = false;
}




}
}
}
}


