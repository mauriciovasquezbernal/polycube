/**
* lbdsr API
* LoadBalancer Direct Server Return Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "LbdsrJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

LbdsrJsonObject::LbdsrJsonObject() : 
  m_nameIsSet(false),
  m_uuidIsSet(false),
  m_type(CubeType::TC),
  m_typeIsSet(true),
  m_loglevel(LbdsrLoglevelEnum::INFO),
  m_loglevelIsSet(true),
  m_portsIsSet(false),
  m_algorithmIsSet(false),
  m_frontendIsSet(false),
  m_backendIsSet(false) { }

LbdsrJsonObject::LbdsrJsonObject(nlohmann::json &val) : 
  m_nameIsSet(false),
  m_uuidIsSet(false),
  m_typeIsSet(false),
  m_loglevelIsSet(false),
  m_portsIsSet(false),
  m_algorithmIsSet(false),
  m_frontendIsSet(false),
  m_backendIsSet(false) { 
  if (val.count("name")) {
    setName(val.at("name").get<std::string>());
  }

  if (val.count("uuid")) {
    setUuid(val.at("uuid").get<std::string>());
  }

  if (val.count("type")) {
    setType(string_to_CubeType(val.at("type").get<std::string>()));
  }

  if (val.count("loglevel")) {
    setLoglevel(string_to_LbdsrLoglevelEnum(val.at("loglevel").get<std::string>()));
  }

  m_ports.clear();
  for (auto& item : val["ports"]) { 
    PortsJsonObject newItem { item };
    m_ports.push_back(newItem);
  }
  m_portsIsSet = !m_ports.empty();
  

  if (val.count("algorithm")) {
    setAlgorithm(val.at("algorithm").get<std::string>());
  }

  if (val.count("frontend")) {
  
  
    if (!val["frontend"].is_null()) {
      FrontendJsonObject newItem { val["frontend"] };
      setFrontend(newItem);
    }
  }

  if (val.count("backend")) {
  
  
    if (!val["backend"].is_null()) {
      BackendJsonObject newItem { val["backend"] };
      setBackend(newItem);
    }
  }
}

nlohmann::json LbdsrJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_nameIsSet) {
    val["name"] = m_name;
  }

  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_typeIsSet) {
    val["type"] = CubeType_to_string(m_type);
  }

  if (m_loglevelIsSet) {
    val["loglevel"] = LbdsrLoglevelEnum_to_string(m_loglevel);
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
  if (m_algorithmIsSet) {
    val["algorithm"] = m_algorithm;
  }

  if (m_frontendIsSet) {
    val["frontend"] = JsonObjectBase::toJson(m_frontend);
  }
  if (m_backendIsSet) {
    val["backend"] = JsonObjectBase::toJson(m_backend);
  }

  return val;
}

nlohmann::json LbdsrJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Name of the lbdsr service)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(lbdsr1)POLYCUBE";

  return val;
}

nlohmann::json LbdsrJsonObject::helpElements() {
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
  val["algorithm"]["name"] = "algorithm";
  val["algorithm"]["type"] = "leaf"; // Suppose that type is leaf
  val["algorithm"]["simpletype"] = "string";
  val["algorithm"]["description"] = R"POLYCUBE(Defines the algorithm which LB use to direct requests to the node of the pool (Random, RoundRobin, ..))POLYCUBE";
  val["algorithm"]["example"] = R"POLYCUBE(Random)POLYCUBE";
  val["frontend"]["name"] = "frontend";
  val["frontend"]["type"] = "leaf"; // Suppose that type is leaf
  val["frontend"]["description"] = R"POLYCUBE()POLYCUBE";
  val["frontend"]["example"] = R"POLYCUBE()POLYCUBE";
  val["backend"]["name"] = "backend";
  val["backend"]["type"] = "leaf"; // Suppose that type is leaf
  val["backend"]["description"] = R"POLYCUBE()POLYCUBE";
  val["backend"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json LbdsrJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";
  val["algorithm"]["name"] = "algorithm";
  val["algorithm"]["simpletype"] = "string";
  val["algorithm"]["description"] = R"POLYCUBE(Defines the algorithm which LB use to direct requests to the node of the pool (Random, RoundRobin, ..))POLYCUBE";
  val["algorithm"]["example"] = R"POLYCUBE(Random)POLYCUBE";

  return val;
}

nlohmann::json LbdsrJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["ports"]["name"] = "ports";
  val["ports"]["type"] = "list";
  val["ports"]["description"] = R"POLYCUBE(Entry of the ports table)POLYCUBE";
  val["ports"]["example"] = R"POLYCUBE()POLYCUBE";
  val["frontend"]["name"] = "frontend";
  val["frontend"]["type"] = "complex";
  val["frontend"]["description"] = R"POLYCUBE()POLYCUBE";
  val["frontend"]["example"] = R"POLYCUBE()POLYCUBE";
  val["backend"]["name"] = "backend";
  val["backend"]["type"] = "complex";
  val["backend"]["description"] = R"POLYCUBE()POLYCUBE";
  val["backend"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> LbdsrJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string LbdsrJsonObject::getName() const {
  return m_name;
}

void LbdsrJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool LbdsrJsonObject::nameIsSet() const {
  return m_nameIsSet;
}





std::string LbdsrJsonObject::getUuid() const {
  return m_uuid;
}

void LbdsrJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool LbdsrJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void LbdsrJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



CubeType LbdsrJsonObject::getType() const {
  return m_type;
}

void LbdsrJsonObject::setType(CubeType value) {
  m_type = value;
  m_typeIsSet = true;
}

bool LbdsrJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void LbdsrJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string LbdsrJsonObject::CubeType_to_string(const CubeType &value){
  switch(value){
    case CubeType::TC:
      return std::string("tc");
    case CubeType::XDP_SKB:
      return std::string("xdp_skb");
    case CubeType::XDP_DRV:
      return std::string("xdp_drv");
    default:
      throw std::runtime_error("Bad Lbdsr type");
  }
}

CubeType LbdsrJsonObject::string_to_CubeType(const std::string &str){
  if (JsonObjectBase::iequals("tc", str))
    return CubeType::TC;
  if (JsonObjectBase::iequals("xdp_skb", str))
    return CubeType::XDP_SKB;
  if (JsonObjectBase::iequals("xdp_drv", str))
    return CubeType::XDP_DRV;
  throw std::runtime_error("Lbdsr type is invalid");
}


LbdsrLoglevelEnum LbdsrJsonObject::getLoglevel() const {
  return m_loglevel;
}

void LbdsrJsonObject::setLoglevel(LbdsrLoglevelEnum value) {
  m_loglevel = value;
  m_loglevelIsSet = true;
}

bool LbdsrJsonObject::loglevelIsSet() const {
  return m_loglevelIsSet;
}

void LbdsrJsonObject::unsetLoglevel() {
  m_loglevelIsSet = false;
}

std::string LbdsrJsonObject::LbdsrLoglevelEnum_to_string(const LbdsrLoglevelEnum &value){
  switch(value){
    case LbdsrLoglevelEnum::TRACE:
      return std::string("trace");
    case LbdsrLoglevelEnum::DEBUG:
      return std::string("debug");
    case LbdsrLoglevelEnum::INFO:
      return std::string("info");
    case LbdsrLoglevelEnum::WARN:
      return std::string("warn");
    case LbdsrLoglevelEnum::ERR:
      return std::string("err");
    case LbdsrLoglevelEnum::CRITICAL:
      return std::string("critical");
    case LbdsrLoglevelEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Lbdsr loglevel");
  }
}

LbdsrLoglevelEnum LbdsrJsonObject::string_to_LbdsrLoglevelEnum(const std::string &str){
  if (JsonObjectBase::iequals("trace", str))
    return LbdsrLoglevelEnum::TRACE;
  if (JsonObjectBase::iequals("debug", str))
    return LbdsrLoglevelEnum::DEBUG;
  if (JsonObjectBase::iequals("info", str))
    return LbdsrLoglevelEnum::INFO;
  if (JsonObjectBase::iequals("warn", str))
    return LbdsrLoglevelEnum::WARN;
  if (JsonObjectBase::iequals("err", str))
    return LbdsrLoglevelEnum::ERR;
  if (JsonObjectBase::iequals("critical", str))
    return LbdsrLoglevelEnum::CRITICAL;
  if (JsonObjectBase::iequals("off", str))
    return LbdsrLoglevelEnum::OFF;
  throw std::runtime_error("Lbdsr loglevel is invalid");
}

  polycube::LogLevel LbdsrJsonObject::getPolycubeLoglevel() const {
    switch(m_loglevel) {
      case LbdsrLoglevelEnum::TRACE:
        return polycube::LogLevel::TRACE;
      case LbdsrLoglevelEnum::DEBUG:
        return polycube::LogLevel::DEBUG;
      case LbdsrLoglevelEnum::INFO:
        return polycube::LogLevel::INFO;
      case LbdsrLoglevelEnum::WARN:
        return polycube::LogLevel::WARN;
      case LbdsrLoglevelEnum::ERR:
        return polycube::LogLevel::ERR;
      case LbdsrLoglevelEnum::CRITICAL:
        return polycube::LogLevel::CRITICAL;
      case LbdsrLoglevelEnum::OFF:
        return polycube::LogLevel::OFF;
    }
  }
const std::vector<PortsJsonObject>& LbdsrJsonObject::getPorts() const{
  return m_ports;
}

void LbdsrJsonObject::addPorts(PortsJsonObject value) {
  m_ports.push_back(value);
}


bool LbdsrJsonObject::portsIsSet() const {
  return m_portsIsSet;
}

void LbdsrJsonObject::unsetPorts() {
  m_portsIsSet = false;
}



std::string LbdsrJsonObject::getAlgorithm() const {
  return m_algorithm;
}

void LbdsrJsonObject::setAlgorithm(std::string value) {
  m_algorithm = value;
  m_algorithmIsSet = true;
}

bool LbdsrJsonObject::algorithmIsSet() const {
  return m_algorithmIsSet;
}

void LbdsrJsonObject::unsetAlgorithm() {
  m_algorithmIsSet = false;
}



FrontendJsonObject LbdsrJsonObject::getFrontend() const {
  return m_frontend;
}

void LbdsrJsonObject::setFrontend(FrontendJsonObject value) {
  m_frontend = value;
  m_frontendIsSet = true;
}

bool LbdsrJsonObject::frontendIsSet() const {
  return m_frontendIsSet;
}

void LbdsrJsonObject::unsetFrontend() {
  m_frontendIsSet = false;
}



BackendJsonObject LbdsrJsonObject::getBackend() const {
  return m_backend;
}

void LbdsrJsonObject::setBackend(BackendJsonObject value) {
  m_backend = value;
  m_backendIsSet = true;
}

bool LbdsrJsonObject::backendIsSet() const {
  return m_backendIsSet;
}

void LbdsrJsonObject::unsetBackend() {
  m_backendIsSet = false;
}




}
}
}
}

