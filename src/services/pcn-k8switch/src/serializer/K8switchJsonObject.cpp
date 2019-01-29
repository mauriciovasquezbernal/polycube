/**
* k8switch API
* Kubernetes HyperSwitch Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "K8switchJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

K8switchJsonObject::K8switchJsonObject() : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  m_type (CubeType::TC),
  m_typeIsSet (true),
  m_loglevel (K8switchLoglevelEnum::INFO),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_clusterIpSubnetIsSet (false),
  m_clientSubnetIsSet (false),
  m_virtualClientSubnetIsSet (false),
  m_serviceIsSet (false),
  m_fwdTableIsSet (false) { }

K8switchJsonObject::K8switchJsonObject(nlohmann::json& val) : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_type (string_to_CubeType(val.at("type").get<std::string>())),
  m_typeIsSet (true),
  // Item with a default value, granted to be part of the request body
  m_loglevel (string_to_K8switchLoglevelEnum(val.at("loglevel").get<std::string>())),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  // Mandatory item
  m_clusterIpSubnet (val.at("cluster-ip-subnet").get<std::string>()),
  m_clusterIpSubnetIsSet (true),
  // Mandatory item
  m_clientSubnet (val.at("client-subnet").get<std::string>()),
  m_clientSubnetIsSet (true),
  // Mandatory item
  m_virtualClientSubnet (val.at("virtual-client-subnet").get<std::string>()),
  m_virtualClientSubnetIsSet (true),
  m_serviceIsSet (false),
  m_fwdTableIsSet (false) { 

  if (val.count("uuid") != 0) {
    setUuid(val.at("uuid").get<std::string>());
  }



  m_ports.clear();
  for (auto& item : val["ports"]) { 
    PortsJsonObject newItem { item };
    m_ports.push_back(newItem);
  }
  m_portsIsSet = !m_ports.empty();
  




  m_service.clear();
  for (auto& item : val["service"]) { 
    ServiceJsonObject newItem { item };
    m_service.push_back(newItem);
  }
  m_serviceIsSet = !m_service.empty();
  

  m_fwdTable.clear();
  for (auto& item : val["fwd-table"]) { 
    FwdTableJsonObject newItem { item };
    m_fwdTable.push_back(newItem);
  }
  m_fwdTableIsSet = !m_fwdTable.empty();
  
}

nlohmann::json K8switchJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["name"] = m_name;
  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_typeIsSet) {
    val["type"] = CubeType_to_string(m_type);
  }

  if (m_loglevelIsSet) {
    val["loglevel"] = K8switchLoglevelEnum_to_string(m_loglevel);
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
  val["cluster-ip-subnet"] = m_clusterIpSubnet;
  val["client-subnet"] = m_clientSubnet;
  val["virtual-client-subnet"] = m_virtualClientSubnet;
  {
    nlohmann::json jsonArray;
    for (auto& item : m_service) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["service"] = jsonArray;
    }
  }
  {
    nlohmann::json jsonArray;
    for (auto& item : m_fwdTable) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["fwd-table"] = jsonArray;
    }
  }

  return val;
}

nlohmann::json K8switchJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Name of the k8switch service)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(k8switch1)POLYCUBE";

  return val;
}

nlohmann::json K8switchJsonObject::helpElements() {
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
  val["cluster-ip-subnet"]["name"] = "cluster-ip-subnet";
  val["cluster-ip-subnet"]["type"] = "leaf"; // Suppose that type is leaf
  val["cluster-ip-subnet"]["simpletype"] = "string";
  val["cluster-ip-subnet"]["description"] = R"POLYCUBE(Range of VIPs where clusterIP services are exposed)POLYCUBE";
  val["cluster-ip-subnet"]["example"] = R"POLYCUBE(10.96.0.0/12)POLYCUBE";
  val["client-subnet"]["name"] = "client-subnet";
  val["client-subnet"]["type"] = "leaf"; // Suppose that type is leaf
  val["client-subnet"]["simpletype"] = "string";
  val["client-subnet"]["description"] = R"POLYCUBE(Range of IPs of pods in this node)POLYCUBE";
  val["client-subnet"]["example"] = R"POLYCUBE(192.168.1.0/24)POLYCUBE";
  val["virtual-client-subnet"]["name"] = "virtual-client-subnet";
  val["virtual-client-subnet"]["type"] = "leaf"; // Suppose that type is leaf
  val["virtual-client-subnet"]["simpletype"] = "string";
  val["virtual-client-subnet"]["description"] = R"POLYCUBE(Range where client's IPs are mapped into)POLYCUBE";
  val["virtual-client-subnet"]["example"] = R"POLYCUBE(10.10.1.0/24)POLYCUBE";
  val["service"]["name"] = "service";
  val["service"]["type"] = "leaf"; // Suppose that type is leaf
  val["service"]["type"] = "list";
  val["service"]["description"] = R"POLYCUBE(Services (i.e., virtual ip:protocol:port) exported to the client)POLYCUBE";
  val["service"]["example"] = R"POLYCUBE()POLYCUBE";
  val["fwd-table"]["name"] = "fwd-table";
  val["fwd-table"]["type"] = "leaf"; // Suppose that type is leaf
  val["fwd-table"]["type"] = "list";
  val["fwd-table"]["description"] = R"POLYCUBE(Entry associated with the forwarding table)POLYCUBE";
  val["fwd-table"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json K8switchJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";
  val["cluster-ip-subnet"]["name"] = "cluster-ip-subnet";
  val["cluster-ip-subnet"]["simpletype"] = "string";
  val["cluster-ip-subnet"]["description"] = R"POLYCUBE(Range of VIPs where clusterIP services are exposed)POLYCUBE";
  val["cluster-ip-subnet"]["example"] = R"POLYCUBE(10.96.0.0/12)POLYCUBE";
  val["client-subnet"]["name"] = "client-subnet";
  val["client-subnet"]["simpletype"] = "string";
  val["client-subnet"]["description"] = R"POLYCUBE(Range of IPs of pods in this node)POLYCUBE";
  val["client-subnet"]["example"] = R"POLYCUBE(192.168.1.0/24)POLYCUBE";
  val["virtual-client-subnet"]["name"] = "virtual-client-subnet";
  val["virtual-client-subnet"]["simpletype"] = "string";
  val["virtual-client-subnet"]["description"] = R"POLYCUBE(Range where client's IPs are mapped into)POLYCUBE";
  val["virtual-client-subnet"]["example"] = R"POLYCUBE(10.10.1.0/24)POLYCUBE";

  return val;
}

nlohmann::json K8switchJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["ports"]["name"] = "ports";
  val["ports"]["type"] = "list";
  val["ports"]["description"] = R"POLYCUBE(Entry of the ports table)POLYCUBE";
  val["ports"]["example"] = R"POLYCUBE()POLYCUBE";
  val["service"]["name"] = "service";
  val["service"]["type"] = "list";
  val["service"]["description"] = R"POLYCUBE(Services (i.e., virtual ip:protocol:port) exported to the client)POLYCUBE";
  val["service"]["example"] = R"POLYCUBE()POLYCUBE";
  val["fwd-table"]["name"] = "fwd-table";
  val["fwd-table"]["type"] = "list";
  val["fwd-table"]["description"] = R"POLYCUBE(Entry associated with the forwarding table)POLYCUBE";
  val["fwd-table"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> K8switchJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string K8switchJsonObject::getName() const {
  return m_name;
}

void K8switchJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool K8switchJsonObject::nameIsSet() const {
  return m_nameIsSet;
}





std::string K8switchJsonObject::getUuid() const {
  return m_uuid;
}

void K8switchJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool K8switchJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void K8switchJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



CubeType K8switchJsonObject::getType() const {
  return m_type;
}

void K8switchJsonObject::setType(CubeType value) {
  m_type = value;
  m_typeIsSet = true;
}

bool K8switchJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void K8switchJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string K8switchJsonObject::CubeType_to_string(const CubeType &value){
  switch(value){
    case CubeType::TC:
      return std::string("tc");
    case CubeType::XDP_SKB:
      return std::string("xdp_skb");
    case CubeType::XDP_DRV:
      return std::string("xdp_drv");
    default:
      throw std::runtime_error("Bad K8switch type");
  }
}

CubeType K8switchJsonObject::string_to_CubeType(const std::string &str){
  if (JsonObjectBase::iequals("tc", str))
    return CubeType::TC;
  if (JsonObjectBase::iequals("xdp_skb", str))
    return CubeType::XDP_SKB;
  if (JsonObjectBase::iequals("xdp_drv", str))
    return CubeType::XDP_DRV;
  throw std::runtime_error("K8switch type is invalid");
}


K8switchLoglevelEnum K8switchJsonObject::getLoglevel() const {
  return m_loglevel;
}

void K8switchJsonObject::setLoglevel(K8switchLoglevelEnum value) {
  m_loglevel = value;
  m_loglevelIsSet = true;
}

bool K8switchJsonObject::loglevelIsSet() const {
  return m_loglevelIsSet;
}

void K8switchJsonObject::unsetLoglevel() {
  m_loglevelIsSet = false;
}

std::string K8switchJsonObject::K8switchLoglevelEnum_to_string(const K8switchLoglevelEnum &value){
  switch(value){
    case K8switchLoglevelEnum::TRACE:
      return std::string("trace");
    case K8switchLoglevelEnum::DEBUG:
      return std::string("debug");
    case K8switchLoglevelEnum::INFO:
      return std::string("info");
    case K8switchLoglevelEnum::WARN:
      return std::string("warn");
    case K8switchLoglevelEnum::ERR:
      return std::string("err");
    case K8switchLoglevelEnum::CRITICAL:
      return std::string("critical");
    case K8switchLoglevelEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad K8switch loglevel");
  }
}

K8switchLoglevelEnum K8switchJsonObject::string_to_K8switchLoglevelEnum(const std::string &str){
  if (JsonObjectBase::iequals("trace", str))
    return K8switchLoglevelEnum::TRACE;
  if (JsonObjectBase::iequals("debug", str))
    return K8switchLoglevelEnum::DEBUG;
  if (JsonObjectBase::iequals("info", str))
    return K8switchLoglevelEnum::INFO;
  if (JsonObjectBase::iequals("warn", str))
    return K8switchLoglevelEnum::WARN;
  if (JsonObjectBase::iequals("err", str))
    return K8switchLoglevelEnum::ERR;
  if (JsonObjectBase::iequals("critical", str))
    return K8switchLoglevelEnum::CRITICAL;
  if (JsonObjectBase::iequals("off", str))
    return K8switchLoglevelEnum::OFF;
  throw std::runtime_error("K8switch loglevel is invalid");
}

  polycube::LogLevel K8switchJsonObject::getPolycubeLoglevel() const {
    switch(m_loglevel) {
      case K8switchLoglevelEnum::TRACE:
        return polycube::LogLevel::TRACE;
      case K8switchLoglevelEnum::DEBUG:
        return polycube::LogLevel::DEBUG;
      case K8switchLoglevelEnum::INFO:
        return polycube::LogLevel::INFO;
      case K8switchLoglevelEnum::WARN:
        return polycube::LogLevel::WARN;
      case K8switchLoglevelEnum::ERR:
        return polycube::LogLevel::ERR;
      case K8switchLoglevelEnum::CRITICAL:
        return polycube::LogLevel::CRITICAL;
      case K8switchLoglevelEnum::OFF:
        return polycube::LogLevel::OFF;
    }
  }
const std::vector<PortsJsonObject>& K8switchJsonObject::getPorts() const{
  return m_ports;
}

void K8switchJsonObject::addPorts(PortsJsonObject value) {
  m_ports.push_back(value);
}


bool K8switchJsonObject::portsIsSet() const {
  return m_portsIsSet;
}

void K8switchJsonObject::unsetPorts() {
  m_portsIsSet = false;
}



std::string K8switchJsonObject::getClusterIpSubnet() const {
  return m_clusterIpSubnet;
}

void K8switchJsonObject::setClusterIpSubnet(std::string value) {
  m_clusterIpSubnet = value;
  m_clusterIpSubnetIsSet = true;
}

bool K8switchJsonObject::clusterIpSubnetIsSet() const {
  return m_clusterIpSubnetIsSet;
}





std::string K8switchJsonObject::getClientSubnet() const {
  return m_clientSubnet;
}

void K8switchJsonObject::setClientSubnet(std::string value) {
  m_clientSubnet = value;
  m_clientSubnetIsSet = true;
}

bool K8switchJsonObject::clientSubnetIsSet() const {
  return m_clientSubnetIsSet;
}





std::string K8switchJsonObject::getVirtualClientSubnet() const {
  return m_virtualClientSubnet;
}

void K8switchJsonObject::setVirtualClientSubnet(std::string value) {
  m_virtualClientSubnet = value;
  m_virtualClientSubnetIsSet = true;
}

bool K8switchJsonObject::virtualClientSubnetIsSet() const {
  return m_virtualClientSubnetIsSet;
}





const std::vector<ServiceJsonObject>& K8switchJsonObject::getService() const{
  return m_service;
}

void K8switchJsonObject::addService(ServiceJsonObject value) {
  m_service.push_back(value);
}


bool K8switchJsonObject::serviceIsSet() const {
  return m_serviceIsSet;
}

void K8switchJsonObject::unsetService() {
  m_serviceIsSet = false;
}



const std::vector<FwdTableJsonObject>& K8switchJsonObject::getFwdTable() const{
  return m_fwdTable;
}

void K8switchJsonObject::addFwdTable(FwdTableJsonObject value) {
  m_fwdTable.push_back(value);
}


bool K8switchJsonObject::fwdTableIsSet() const {
  return m_fwdTableIsSet;
}

void K8switchJsonObject::unsetFwdTable() {
  m_fwdTableIsSet = false;
}




}
}
}
}


