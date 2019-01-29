/**
* firewall API
* Firewall Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "FirewallJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

FirewallJsonObject::FirewallJsonObject() : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  m_type (CubeType::TC),
  m_typeIsSet (true),
  m_loglevel (FirewallLoglevelEnum::INFO),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_ingressPortIsSet (false),
  m_egressPortIsSet (false),
  m_conntrackIsSet (false),
  m_acceptEstablishedIsSet (false),
  m_interactive (true),
  m_interactiveIsSet (true),
  m_sessionTableIsSet (false),
  m_chainIsSet (false) { }

FirewallJsonObject::FirewallJsonObject(nlohmann::json& val) : 
  m_nameIsSet (false),
  m_uuidIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_type (string_to_CubeType(val.at("type").get<std::string>())),
  m_typeIsSet (true),
  // Item with a default value, granted to be part of the request body
  m_loglevel (string_to_FirewallLoglevelEnum(val.at("loglevel").get<std::string>())),
  m_loglevelIsSet (true),
  m_portsIsSet (false),
  m_ingressPortIsSet (false),
  m_egressPortIsSet (false),
  m_conntrackIsSet (false),
  m_acceptEstablishedIsSet (false),
  // Item with a default value, granted to be part of the request body
  m_interactive (val.at("interactive").get<bool>()),
  m_interactiveIsSet (true),
  m_sessionTableIsSet (false),
  m_chainIsSet (false) { 

  if (val.count("uuid") != 0) {
    setUuid(val.at("uuid").get<std::string>());
  }



  m_ports.clear();
  for (auto& item : val["ports"]) { 
    PortsJsonObject newItem { item };
    m_ports.push_back(newItem);
  }
  m_portsIsSet = !m_ports.empty();
  

  if (val.count("ingress-port") != 0) {
    setIngressPort(val.at("ingress-port").get<std::string>());
  }

  if (val.count("egress-port") != 0) {
    setEgressPort(val.at("egress-port").get<std::string>());
  }

  if (val.count("conntrack") != 0) {
    setConntrack(string_to_FirewallConntrackEnum(val.at("conntrack").get<std::string>()));
  }

  if (val.count("accept-established") != 0) {
    setAcceptEstablished(string_to_FirewallAcceptEstablishedEnum(val.at("accept-established").get<std::string>()));
  }


  m_sessionTable.clear();
  for (auto& item : val["session-table"]) { 
    SessionTableJsonObject newItem { item };
    m_sessionTable.push_back(newItem);
  }
  m_sessionTableIsSet = !m_sessionTable.empty();
  

  m_chain.clear();
  for (auto& item : val["chain"]) { 
    ChainJsonObject newItem { item };
    m_chain.push_back(newItem);
  }
  m_chainIsSet = !m_chain.empty();
  
}

nlohmann::json FirewallJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["name"] = m_name;
  if (m_uuidIsSet) {
    val["uuid"] = m_uuid;
  }

  if (m_typeIsSet) {
    val["type"] = CubeType_to_string(m_type);
  }

  if (m_loglevelIsSet) {
    val["loglevel"] = FirewallLoglevelEnum_to_string(m_loglevel);
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
  if (m_ingressPortIsSet) {
    val["ingress-port"] = m_ingressPort;
  }

  if (m_egressPortIsSet) {
    val["egress-port"] = m_egressPort;
  }

  if (m_conntrackIsSet) {
    val["conntrack"] = FirewallConntrackEnum_to_string(m_conntrack);
  }

  if (m_acceptEstablishedIsSet) {
    val["accept-established"] = FirewallAcceptEstablishedEnum_to_string(m_acceptEstablished);
  }

  if (m_interactiveIsSet) {
    val["interactive"] = m_interactive;
  }

  {
    nlohmann::json jsonArray;
    for (auto& item : m_sessionTable) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["session-table"] = jsonArray;
    }
  }
  {
    nlohmann::json jsonArray;
    for (auto& item : m_chain) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["chain"] = jsonArray;
    }
  }

  return val;
}

nlohmann::json FirewallJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Name of the firewall service)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(firewall1)POLYCUBE";

  return val;
}

nlohmann::json FirewallJsonObject::helpElements() {
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
  val["ingress-port"]["name"] = "ingress-port";
  val["ingress-port"]["type"] = "leaf"; // Suppose that type is leaf
  val["ingress-port"]["simpletype"] = "string";
  val["ingress-port"]["description"] = R"POLYCUBE(Name for the ingress port, from which arrives traffic processed by INGRESS chain (by default it's the first port of the cube))POLYCUBE";
  val["ingress-port"]["example"] = R"POLYCUBE()POLYCUBE";
  val["egress-port"]["name"] = "egress-port";
  val["egress-port"]["type"] = "leaf"; // Suppose that type is leaf
  val["egress-port"]["simpletype"] = "string";
  val["egress-port"]["description"] = R"POLYCUBE(Name for the egress port, from which arrives traffic processed by EGRESS chain (by default it's the second port of the cube))POLYCUBE";
  val["egress-port"]["example"] = R"POLYCUBE()POLYCUBE";
  val["conntrack"]["name"] = "conntrack";
  val["conntrack"]["type"] = "leaf"; // Suppose that type is leaf
  val["conntrack"]["simpletype"] = "string";
  val["conntrack"]["description"] = R"POLYCUBE(Enables the Connection Tracking module. Mandatory if connection tracking rules are needed. Default is ON.)POLYCUBE";
  val["conntrack"]["example"] = R"POLYCUBE()POLYCUBE";
  val["accept-established"]["name"] = "accept-established";
  val["accept-established"]["type"] = "leaf"; // Suppose that type is leaf
  val["accept-established"]["simpletype"] = "string";
  val["accept-established"]["description"] = R"POLYCUBE(If Connection Tracking is enabled, all packets belonging to ESTABLISHED connections will be forwarded automatically. Default is ON.)POLYCUBE";
  val["accept-established"]["example"] = R"POLYCUBE()POLYCUBE";
  val["interactive"]["name"] = "interactive";
  val["interactive"]["type"] = "leaf"; // Suppose that type is leaf
  val["interactive"]["simpletype"] = "boolean";
  val["interactive"]["description"] = R"POLYCUBE(Interactive mode applies new rules immediately; if 'false', the command 'apply-rules' has to be used to apply all the rules at once. Default is TRUE.)POLYCUBE";
  val["interactive"]["example"] = R"POLYCUBE()POLYCUBE";
  val["session-table"]["name"] = "session-table";
  val["session-table"]["type"] = "leaf"; // Suppose that type is leaf
  val["session-table"]["type"] = "list";
  val["session-table"]["description"] = R"POLYCUBE()POLYCUBE";
  val["session-table"]["example"] = R"POLYCUBE()POLYCUBE";
  val["chain"]["name"] = "chain";
  val["chain"]["type"] = "leaf"; // Suppose that type is leaf
  val["chain"]["type"] = "list";
  val["chain"]["description"] = R"POLYCUBE()POLYCUBE";
  val["chain"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json FirewallJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["loglevel"]["name"] = "loglevel";
  val["loglevel"]["simpletype"] = "string";
  val["loglevel"]["description"] = R"POLYCUBE(Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE))POLYCUBE";
  val["loglevel"]["example"] = R"POLYCUBE(INFO)POLYCUBE";
  val["ingress-port"]["name"] = "ingress-port";
  val["ingress-port"]["simpletype"] = "string";
  val["ingress-port"]["description"] = R"POLYCUBE(Name for the ingress port, from which arrives traffic processed by INGRESS chain (by default it's the first port of the cube))POLYCUBE";
  val["ingress-port"]["example"] = R"POLYCUBE()POLYCUBE";
  val["egress-port"]["name"] = "egress-port";
  val["egress-port"]["simpletype"] = "string";
  val["egress-port"]["description"] = R"POLYCUBE(Name for the egress port, from which arrives traffic processed by EGRESS chain (by default it's the second port of the cube))POLYCUBE";
  val["egress-port"]["example"] = R"POLYCUBE()POLYCUBE";
  val["conntrack"]["name"] = "conntrack";
  val["conntrack"]["simpletype"] = "string";
  val["conntrack"]["description"] = R"POLYCUBE(Enables the Connection Tracking module. Mandatory if connection tracking rules are needed. Default is ON.)POLYCUBE";
  val["conntrack"]["example"] = R"POLYCUBE()POLYCUBE";
  val["accept-established"]["name"] = "accept-established";
  val["accept-established"]["simpletype"] = "string";
  val["accept-established"]["description"] = R"POLYCUBE(If Connection Tracking is enabled, all packets belonging to ESTABLISHED connections will be forwarded automatically. Default is ON.)POLYCUBE";
  val["accept-established"]["example"] = R"POLYCUBE()POLYCUBE";
  val["interactive"]["name"] = "interactive";
  val["interactive"]["simpletype"] = "boolean";
  val["interactive"]["description"] = R"POLYCUBE(Interactive mode applies new rules immediately; if 'false', the command 'apply-rules' has to be used to apply all the rules at once. Default is TRUE.)POLYCUBE";
  val["interactive"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json FirewallJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["ports"]["name"] = "ports";
  val["ports"]["type"] = "list";
  val["ports"]["description"] = R"POLYCUBE(Entry of the ports table)POLYCUBE";
  val["ports"]["example"] = R"POLYCUBE()POLYCUBE";
  val["session-table"]["name"] = "session-table";
  val["session-table"]["type"] = "list";
  val["session-table"]["description"] = R"POLYCUBE()POLYCUBE";
  val["session-table"]["example"] = R"POLYCUBE()POLYCUBE";
  val["chain"]["name"] = "chain";
  val["chain"]["type"] = "list";
  val["chain"]["description"] = R"POLYCUBE()POLYCUBE";
  val["chain"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> FirewallJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string FirewallJsonObject::getName() const {
  return m_name;
}

void FirewallJsonObject::setName(std::string value) {
  m_name = value;
  m_nameIsSet = true;
}

bool FirewallJsonObject::nameIsSet() const {
  return m_nameIsSet;
}





std::string FirewallJsonObject::getUuid() const {
  return m_uuid;
}

void FirewallJsonObject::setUuid(std::string value) {
  m_uuid = value;
  m_uuidIsSet = true;
}

bool FirewallJsonObject::uuidIsSet() const {
  return m_uuidIsSet;
}

void FirewallJsonObject::unsetUuid() {
  m_uuidIsSet = false;
}



CubeType FirewallJsonObject::getType() const {
  return m_type;
}

void FirewallJsonObject::setType(CubeType value) {
  m_type = value;
  m_typeIsSet = true;
}

bool FirewallJsonObject::typeIsSet() const {
  return m_typeIsSet;
}

void FirewallJsonObject::unsetType() {
  m_typeIsSet = false;
}

std::string FirewallJsonObject::CubeType_to_string(const CubeType &value){
  switch(value){
    case CubeType::TC:
      return std::string("tc");
    case CubeType::XDP_SKB:
      return std::string("xdp_skb");
    case CubeType::XDP_DRV:
      return std::string("xdp_drv");
    default:
      throw std::runtime_error("Bad Firewall type");
  }
}

CubeType FirewallJsonObject::string_to_CubeType(const std::string &str){
  if (JsonObjectBase::iequals("tc", str))
    return CubeType::TC;
  if (JsonObjectBase::iequals("xdp_skb", str))
    return CubeType::XDP_SKB;
  if (JsonObjectBase::iequals("xdp_drv", str))
    return CubeType::XDP_DRV;
  throw std::runtime_error("Firewall type is invalid");
}


FirewallLoglevelEnum FirewallJsonObject::getLoglevel() const {
  return m_loglevel;
}

void FirewallJsonObject::setLoglevel(FirewallLoglevelEnum value) {
  m_loglevel = value;
  m_loglevelIsSet = true;
}

bool FirewallJsonObject::loglevelIsSet() const {
  return m_loglevelIsSet;
}

void FirewallJsonObject::unsetLoglevel() {
  m_loglevelIsSet = false;
}

std::string FirewallJsonObject::FirewallLoglevelEnum_to_string(const FirewallLoglevelEnum &value){
  switch(value){
    case FirewallLoglevelEnum::TRACE:
      return std::string("trace");
    case FirewallLoglevelEnum::DEBUG:
      return std::string("debug");
    case FirewallLoglevelEnum::INFO:
      return std::string("info");
    case FirewallLoglevelEnum::WARN:
      return std::string("warn");
    case FirewallLoglevelEnum::ERR:
      return std::string("err");
    case FirewallLoglevelEnum::CRITICAL:
      return std::string("critical");
    case FirewallLoglevelEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Firewall loglevel");
  }
}

FirewallLoglevelEnum FirewallJsonObject::string_to_FirewallLoglevelEnum(const std::string &str){
  if (JsonObjectBase::iequals("trace", str))
    return FirewallLoglevelEnum::TRACE;
  if (JsonObjectBase::iequals("debug", str))
    return FirewallLoglevelEnum::DEBUG;
  if (JsonObjectBase::iequals("info", str))
    return FirewallLoglevelEnum::INFO;
  if (JsonObjectBase::iequals("warn", str))
    return FirewallLoglevelEnum::WARN;
  if (JsonObjectBase::iequals("err", str))
    return FirewallLoglevelEnum::ERR;
  if (JsonObjectBase::iequals("critical", str))
    return FirewallLoglevelEnum::CRITICAL;
  if (JsonObjectBase::iequals("off", str))
    return FirewallLoglevelEnum::OFF;
  throw std::runtime_error("Firewall loglevel is invalid");
}

  polycube::LogLevel FirewallJsonObject::getPolycubeLoglevel() const {
    switch(m_loglevel) {
      case FirewallLoglevelEnum::TRACE:
        return polycube::LogLevel::TRACE;
      case FirewallLoglevelEnum::DEBUG:
        return polycube::LogLevel::DEBUG;
      case FirewallLoglevelEnum::INFO:
        return polycube::LogLevel::INFO;
      case FirewallLoglevelEnum::WARN:
        return polycube::LogLevel::WARN;
      case FirewallLoglevelEnum::ERR:
        return polycube::LogLevel::ERR;
      case FirewallLoglevelEnum::CRITICAL:
        return polycube::LogLevel::CRITICAL;
      case FirewallLoglevelEnum::OFF:
        return polycube::LogLevel::OFF;
    }
  }
const std::vector<PortsJsonObject>& FirewallJsonObject::getPorts() const{
  return m_ports;
}

void FirewallJsonObject::addPorts(PortsJsonObject value) {
  m_ports.push_back(value);
}


bool FirewallJsonObject::portsIsSet() const {
  return m_portsIsSet;
}

void FirewallJsonObject::unsetPorts() {
  m_portsIsSet = false;
}



std::string FirewallJsonObject::getIngressPort() const {
  return m_ingressPort;
}

void FirewallJsonObject::setIngressPort(std::string value) {
  m_ingressPort = value;
  m_ingressPortIsSet = true;
}

bool FirewallJsonObject::ingressPortIsSet() const {
  return m_ingressPortIsSet;
}

void FirewallJsonObject::unsetIngressPort() {
  m_ingressPortIsSet = false;
}



std::string FirewallJsonObject::getEgressPort() const {
  return m_egressPort;
}

void FirewallJsonObject::setEgressPort(std::string value) {
  m_egressPort = value;
  m_egressPortIsSet = true;
}

bool FirewallJsonObject::egressPortIsSet() const {
  return m_egressPortIsSet;
}

void FirewallJsonObject::unsetEgressPort() {
  m_egressPortIsSet = false;
}



FirewallConntrackEnum FirewallJsonObject::getConntrack() const {
  return m_conntrack;
}

void FirewallJsonObject::setConntrack(FirewallConntrackEnum value) {
  m_conntrack = value;
  m_conntrackIsSet = true;
}

bool FirewallJsonObject::conntrackIsSet() const {
  return m_conntrackIsSet;
}

void FirewallJsonObject::unsetConntrack() {
  m_conntrackIsSet = false;
}

std::string FirewallJsonObject::FirewallConntrackEnum_to_string(const FirewallConntrackEnum &value){
  switch(value){
    case FirewallConntrackEnum::ON:
      return std::string("on");
    case FirewallConntrackEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Firewall conntrack");
  }
}

FirewallConntrackEnum FirewallJsonObject::string_to_FirewallConntrackEnum(const std::string &str){
  if (JsonObjectBase::iequals("on", str))
    return FirewallConntrackEnum::ON;
  if (JsonObjectBase::iequals("off", str))
    return FirewallConntrackEnum::OFF;
  throw std::runtime_error("Firewall conntrack is invalid");
}


FirewallAcceptEstablishedEnum FirewallJsonObject::getAcceptEstablished() const {
  return m_acceptEstablished;
}

void FirewallJsonObject::setAcceptEstablished(FirewallAcceptEstablishedEnum value) {
  m_acceptEstablished = value;
  m_acceptEstablishedIsSet = true;
}

bool FirewallJsonObject::acceptEstablishedIsSet() const {
  return m_acceptEstablishedIsSet;
}

void FirewallJsonObject::unsetAcceptEstablished() {
  m_acceptEstablishedIsSet = false;
}

std::string FirewallJsonObject::FirewallAcceptEstablishedEnum_to_string(const FirewallAcceptEstablishedEnum &value){
  switch(value){
    case FirewallAcceptEstablishedEnum::ON:
      return std::string("on");
    case FirewallAcceptEstablishedEnum::OFF:
      return std::string("off");
    default:
      throw std::runtime_error("Bad Firewall acceptEstablished");
  }
}

FirewallAcceptEstablishedEnum FirewallJsonObject::string_to_FirewallAcceptEstablishedEnum(const std::string &str){
  if (JsonObjectBase::iequals("on", str))
    return FirewallAcceptEstablishedEnum::ON;
  if (JsonObjectBase::iequals("off", str))
    return FirewallAcceptEstablishedEnum::OFF;
  throw std::runtime_error("Firewall acceptEstablished is invalid");
}


bool FirewallJsonObject::getInteractive() const {
  return m_interactive;
}

void FirewallJsonObject::setInteractive(bool value) {
  m_interactive = value;
  m_interactiveIsSet = true;
}

bool FirewallJsonObject::interactiveIsSet() const {
  return m_interactiveIsSet;
}

void FirewallJsonObject::unsetInteractive() {
  m_interactiveIsSet = false;
}



const std::vector<SessionTableJsonObject>& FirewallJsonObject::getSessionTable() const{
  return m_sessionTable;
}

void FirewallJsonObject::addSessionTable(SessionTableJsonObject value) {
  m_sessionTable.push_back(value);
}


bool FirewallJsonObject::sessionTableIsSet() const {
  return m_sessionTableIsSet;
}

void FirewallJsonObject::unsetSessionTable() {
  m_sessionTableIsSet = false;
}



const std::vector<ChainJsonObject>& FirewallJsonObject::getChain() const{
  return m_chain;
}

void FirewallJsonObject::addChain(ChainJsonObject value) {
  m_chain.push_back(value);
}


bool FirewallJsonObject::chainIsSet() const {
  return m_chainIsSet;
}

void FirewallJsonObject::unsetChain() {
  m_chainIsSet = false;
}




}
}
}
}


