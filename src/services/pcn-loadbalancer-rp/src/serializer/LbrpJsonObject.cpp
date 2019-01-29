/**
* lbrp API
* LoadBalancer Reverse-Proxy Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "LbrpJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

LbrpJsonObject::LbrpJsonObject() : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  m_type (CubeType::TC),
  m_typeIsSet (true),
  m_loglevel (LbrpLoglevelEnum::INFO),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_srcIpRewriteIsSet (false),
  m_serviceIsSet (false) { }

LbrpJsonObject::LbrpJsonObject(nlohmann::json& val) : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_type (string_to_CubeType(val.at("type").get<std::string>())),
  m_typeIsSet (true),
  // Item with a default value, granted to be part of the request body
  m_loglevel (string_to_LbrpLoglevelEnum(val.at("loglevel").get<std::string>())),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_srcIpRewriteIsSet (false),
  m_serviceIsSet (false) { 

  if (val.count("uuid") != 0) {
    setUuid(val.at("uuid").get<std::string>());
  }



  m_ports.clear();
  for (auto& item : val["ports"]) { 
    PortsJsonObject newItem { item };
    m_ports.push_back(newItem);
  }
  m_portsIsSet = !m_ports.empty();
  

  if (val.count("src-ip-rewrite") != 0) {
  
  
    if (!val["src-ip-rewrite"].is_null()) {
      SrcIpRewriteJsonObject newItem { val["src-ip-rewrite"] };
      setSrcIpRewrite(newItem);
    }
  }

  m_service.clear();
  for (auto& item : val["service"]) { 
    ServiceJsonObject newItem { item };
    m_service.push_back(newItem);
  }
  m_serviceIsSet = !m_service.empty();
  
}

nlohmann::json LbrpJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["name"] = m_name;
  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_typeIsSet) {
    val["type"] = CubeType_to_string(m_type);
  }

  if (m_loglevelIsSet) {
    val["loglevel"] = LbrpLoglevelEnum_to_string(m_loglevel);
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
  if (m_srcIpRewriteIsSet) {
    val["src-ip-rewrite"] = JsonObjectBase::toJson(m_srcIpRewrite);
  }
  {
    nlohmann::json jsonArray;
    for (auto& item : m_service) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["service"] = jsonArray;
    }
  }

  return val;
}

nlohmann::json LbrpJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Name of the lbrp service)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(lbrp1)POLYCUBE";

  return val;
}

nlohmann::json LbrpJsonObject::helpElements() {
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
  val["src-ip-rewrite"]["name"] = "src-ip-rewrite";
  val["src-ip-rewrite"]["type"] = "leaf"; // Suppose that type is leaf
  val["src-ip-rewrite"]["description"] = R"POLYCUBE()POLYCUBE";
  val["src-ip-rewrite"]["example"] = R"POLYCUBE()POLYCUBE";
  val["service"]["name"] = "service";
  val["service"]["type"] = "leaf"; // Suppose that type is leaf
  val["service"]["type"] = "list";
  val["service"]["description"] = R"POLYCUBE(Services (i.e., virtual ip:protocol:port) exported to the client)POLYCUBE";
  val["service"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json LbrpJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";

  return val;
}

nlohmann::json LbrpJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["ports"]["name"] = "ports";
  val["ports"]["type"] = "list";
  val["ports"]["description"] = R"POLYCUBE(Entry of the ports table)POLYCUBE";
  val["ports"]["example"] = R"POLYCUBE()POLYCUBE";
  val["src-ip-rewrite"]["name"] = "src-ip-rewrite";
  val["src-ip-rewrite"]["type"] = "complex";
  val["src-ip-rewrite"]["description"] = R"POLYCUBE()POLYCUBE";
  val["src-ip-rewrite"]["example"] = R"POLYCUBE()POLYCUBE";
  val["service"]["name"] = "service";
  val["service"]["type"] = "list";
  val["service"]["description"] = R"POLYCUBE(Services (i.e., virtual ip:protocol:port) exported to the client)POLYCUBE";
  val["service"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> LbrpJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string LbrpJsonObject::getName() const {
  return m_name;
}

void LbrpJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool LbrpJsonObject::nameIsSet() const {
  return m_nameIsSet;
}





std::string LbrpJsonObject::getUuid() const {
  return m_uuid;
}

void LbrpJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool LbrpJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void LbrpJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



CubeType LbrpJsonObject::getType() const {
  return m_type;
}

void LbrpJsonObject::setType(CubeType value) {
  m_type = value;
  m_typeIsSet = true;
}

bool LbrpJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void LbrpJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string LbrpJsonObject::CubeType_to_string(const CubeType &value){
  switch(value){
    case CubeType::TC:
      return std::string("tc");
    case CubeType::XDP_SKB:
      return std::string("xdp_skb");
    case CubeType::XDP_DRV:
      return std::string("xdp_drv");
    default:
      throw std::runtime_error("Bad Lbrp type");
  }
}

CubeType LbrpJsonObject::string_to_CubeType(const std::string &str){
  if (JsonObjectBase::iequals("tc", str))
    return CubeType::TC;
  if (JsonObjectBase::iequals("xdp_skb", str))
    return CubeType::XDP_SKB;
  if (JsonObjectBase::iequals("xdp_drv", str))
    return CubeType::XDP_DRV;
  throw std::runtime_error("Lbrp type is invalid");
}


LbrpLoglevelEnum LbrpJsonObject::getLoglevel() const {
  return m_loglevel;
}

void LbrpJsonObject::setLoglevel(LbrpLoglevelEnum value) {
  m_loglevel = value;
  m_loglevelIsSet = true;
}

bool LbrpJsonObject::loglevelIsSet() const {
  return m_loglevelIsSet;
}

void LbrpJsonObject::unsetLoglevel() {
  m_loglevelIsSet = false;
}

std::string LbrpJsonObject::LbrpLoglevelEnum_to_string(const LbrpLoglevelEnum &value){
  switch(value){
    case LbrpLoglevelEnum::TRACE:
      return std::string("trace");
    case LbrpLoglevelEnum::DEBUG:
      return std::string("debug");
    case LbrpLoglevelEnum::INFO:
      return std::string("info");
    case LbrpLoglevelEnum::WARN:
      return std::string("warn");
    case LbrpLoglevelEnum::ERR:
      return std::string("err");
    case LbrpLoglevelEnum::CRITICAL:
      return std::string("critical");
    case LbrpLoglevelEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Lbrp loglevel");
  }
}

LbrpLoglevelEnum LbrpJsonObject::string_to_LbrpLoglevelEnum(const std::string &str){
  if (JsonObjectBase::iequals("trace", str))
    return LbrpLoglevelEnum::TRACE;
  if (JsonObjectBase::iequals("debug", str))
    return LbrpLoglevelEnum::DEBUG;
  if (JsonObjectBase::iequals("info", str))
    return LbrpLoglevelEnum::INFO;
  if (JsonObjectBase::iequals("warn", str))
    return LbrpLoglevelEnum::WARN;
  if (JsonObjectBase::iequals("err", str))
    return LbrpLoglevelEnum::ERR;
  if (JsonObjectBase::iequals("critical", str))
    return LbrpLoglevelEnum::CRITICAL;
  if (JsonObjectBase::iequals("off", str))
    return LbrpLoglevelEnum::OFF;
  throw std::runtime_error("Lbrp loglevel is invalid");
}

  polycube::LogLevel LbrpJsonObject::getPolycubeLoglevel() const {
    switch(m_loglevel) {
      case LbrpLoglevelEnum::TRACE:
        return polycube::LogLevel::TRACE;
      case LbrpLoglevelEnum::DEBUG:
        return polycube::LogLevel::DEBUG;
      case LbrpLoglevelEnum::INFO:
        return polycube::LogLevel::INFO;
      case LbrpLoglevelEnum::WARN:
        return polycube::LogLevel::WARN;
      case LbrpLoglevelEnum::ERR:
        return polycube::LogLevel::ERR;
      case LbrpLoglevelEnum::CRITICAL:
        return polycube::LogLevel::CRITICAL;
      case LbrpLoglevelEnum::OFF:
        return polycube::LogLevel::OFF;
    }
  }
const std::vector<PortsJsonObject>& LbrpJsonObject::getPorts() const{
  return m_ports;
}

void LbrpJsonObject::addPorts(PortsJsonObject value) {
  m_ports.push_back(value);
}


bool LbrpJsonObject::portsIsSet() const {
  return m_portsIsSet;
}

void LbrpJsonObject::unsetPorts() {
  m_portsIsSet = false;
}



SrcIpRewriteJsonObject LbrpJsonObject::getSrcIpRewrite() const {
  return m_srcIpRewrite;
}

void LbrpJsonObject::setSrcIpRewrite(SrcIpRewriteJsonObject value) {
  m_srcIpRewrite = value;
  m_srcIpRewriteIsSet = true;
}

bool LbrpJsonObject::srcIpRewriteIsSet() const {
  return m_srcIpRewriteIsSet;
}

void LbrpJsonObject::unsetSrcIpRewrite() {
  m_srcIpRewriteIsSet = false;
}



const std::vector<ServiceJsonObject>& LbrpJsonObject::getService() const{
  return m_service;
}

void LbrpJsonObject::addService(ServiceJsonObject value) {
  m_service.push_back(value);
}


bool LbrpJsonObject::serviceIsSet() const {
  return m_serviceIsSet;
}

void LbrpJsonObject::unsetService() {
  m_serviceIsSet = false;
}




}
}
}
}


