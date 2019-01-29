/**
* iptables API
* iptables API generated from iptables.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "ChainAppendInputJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

ChainAppendInputJsonObject::ChainAppendInputJsonObject() : 
  m_inIfaceIsSet (false),
  m_outIfaceIsSet (false),
  m_srcIsSet (false),
  m_dstIsSet (false),
  m_l4protoIsSet (false),
  m_sportIsSet (false),
  m_dportIsSet (false),
  m_tcpflagsIsSet (false),
  m_conntrackIsSet (false),
  m_actionIsSet (false) { }

ChainAppendInputJsonObject::ChainAppendInputJsonObject(nlohmann::json& val) : 
  m_inIfaceIsSet (false),
  m_outIfaceIsSet (false),
  m_srcIsSet (false),
  m_dstIsSet (false),
  m_l4protoIsSet (false),
  m_sportIsSet (false),
  m_dportIsSet (false),
  m_tcpflagsIsSet (false),
  m_conntrackIsSet (false),
  m_actionIsSet (false) { 
  if (val.count("in-iface") != 0) {
    setInIface(val.at("in-iface").get<std::string>());
  }

  if (val.count("out-iface") != 0) {
    setOutIface(val.at("out-iface").get<std::string>());
  }

  if (val.count("src") != 0) {
    setSrc(val.at("src").get<std::string>());
  }

  if (val.count("dst") != 0) {
    setDst(val.at("dst").get<std::string>());
  }

  if (val.count("l4proto") != 0) {
    setL4proto(val.at("l4proto").get<std::string>());
  }

  if (val.count("sport") != 0) {
    setSport(val.at("sport").get<uint16_t>());
  }

  if (val.count("dport") != 0) {
    setDport(val.at("dport").get<uint16_t>());
  }

  if (val.count("tcpflags") != 0) {
    setTcpflags(val.at("tcpflags").get<std::string>());
  }

  if (val.count("conntrack") != 0) {
    setConntrack(string_to_ConntrackstatusEnum(val.at("conntrack").get<std::string>()));
  }

  if (val.count("action") != 0) {
    setAction(string_to_ActionEnum(val.at("action").get<std::string>()));
  }
}

nlohmann::json ChainAppendInputJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_inIfaceIsSet) {
    val["in-iface"] = m_inIface;
  }

  if (m_outIfaceIsSet) {
    val["out-iface"] = m_outIface;
  }

  if (m_srcIsSet) {
    val["src"] = m_src;
  }

  if (m_dstIsSet) {
    val["dst"] = m_dst;
  }

  if (m_l4protoIsSet) {
    val["l4proto"] = m_l4proto;
  }

  if (m_sportIsSet) {
    val["sport"] = m_sport;
  }

  if (m_dportIsSet) {
    val["dport"] = m_dport;
  }

  if (m_tcpflagsIsSet) {
    val["tcpflags"] = m_tcpflags;
  }

  if (m_conntrackIsSet) {
    val["conntrack"] = ConntrackstatusEnum_to_string(m_conntrack);
  }

  if (m_actionIsSet) {
    val["action"] = ActionEnum_to_string(m_action);
  }


  return val;
}

nlohmann::json ChainAppendInputJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json ChainAppendInputJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["in-iface"]["name"] = "in-iface";
  val["in-iface"]["type"] = "leaf"; // Suppose that type is leaf
  val["in-iface"]["simpletype"] = "string";
  val["in-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is received)POLYCUBE";
  val["in-iface"]["example"] = R"POLYCUBE(eth0)POLYCUBE";
  val["out-iface"]["name"] = "out-iface";
  val["out-iface"]["type"] = "leaf"; // Suppose that type is leaf
  val["out-iface"]["simpletype"] = "string";
  val["out-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is going to be sent)POLYCUBE";
  val["out-iface"]["example"] = R"POLYCUBE(eth1)POLYCUBE";
  val["src"]["name"] = "src";
  val["src"]["type"] = "leaf"; // Suppose that type is leaf
  val["src"]["simpletype"] = "string";
  val["src"]["description"] = R"POLYCUBE(Source IP Address.)POLYCUBE";
  val["src"]["example"] = R"POLYCUBE(10.0.0.1/24)POLYCUBE";
  val["dst"]["name"] = "dst";
  val["dst"]["type"] = "leaf"; // Suppose that type is leaf
  val["dst"]["simpletype"] = "string";
  val["dst"]["description"] = R"POLYCUBE(Destination IP Address.)POLYCUBE";
  val["dst"]["example"] = R"POLYCUBE(10.0.0.2/24)POLYCUBE";
  val["l4proto"]["name"] = "l4proto";
  val["l4proto"]["type"] = "leaf"; // Suppose that type is leaf
  val["l4proto"]["simpletype"] = "string";
  val["l4proto"]["description"] = R"POLYCUBE(Level 4 Protocol.)POLYCUBE";
  val["l4proto"]["example"] = R"POLYCUBE()POLYCUBE";
  val["sport"]["name"] = "sport";
  val["sport"]["type"] = "leaf"; // Suppose that type is leaf
  val["sport"]["simpletype"] = "integer";
  val["sport"]["description"] = R"POLYCUBE(Source L4 Port)POLYCUBE";
  val["sport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["dport"]["name"] = "dport";
  val["dport"]["type"] = "leaf"; // Suppose that type is leaf
  val["dport"]["simpletype"] = "integer";
  val["dport"]["description"] = R"POLYCUBE(Destination L4 Port)POLYCUBE";
  val["dport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["tcpflags"]["name"] = "tcpflags";
  val["tcpflags"]["type"] = "leaf"; // Suppose that type is leaf
  val["tcpflags"]["simpletype"] = "string";
  val["tcpflags"]["description"] = R"POLYCUBE(TCP flags. Allowed values: SYN, FIN, ACK, RST, PSH, URG, CWR, ECE. ! means set to 0.)POLYCUBE";
  val["tcpflags"]["example"] = R"POLYCUBE(!FIN,SYN,!RST,!ACK)POLYCUBE";
  val["conntrack"]["name"] = "conntrack";
  val["conntrack"]["type"] = "leaf"; // Suppose that type is leaf
  val["conntrack"]["simpletype"] = "string";
  val["conntrack"]["description"] = R"POLYCUBE(Connection status (NEW, ESTABLISHED, RELATED, INVALID))POLYCUBE";
  val["conntrack"]["example"] = R"POLYCUBE()POLYCUBE";
  val["action"]["name"] = "action";
  val["action"]["type"] = "leaf"; // Suppose that type is leaf
  val["action"]["simpletype"] = "string";
  val["action"]["description"] = R"POLYCUBE(Action if the rule matches. Default is DROP.)POLYCUBE";
  val["action"]["example"] = R"POLYCUBE(DROP, ACCEPT, LOG)POLYCUBE";

  return val;
}

nlohmann::json ChainAppendInputJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["in-iface"]["name"] = "in-iface";
  val["in-iface"]["simpletype"] = "string";
  val["in-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is received)POLYCUBE";
  val["in-iface"]["example"] = R"POLYCUBE(eth0)POLYCUBE";
  val["out-iface"]["name"] = "out-iface";
  val["out-iface"]["simpletype"] = "string";
  val["out-iface"]["description"] = R"POLYCUBE(Name of the interface via which the packet is going to be sent)POLYCUBE";
  val["out-iface"]["example"] = R"POLYCUBE(eth1)POLYCUBE";
  val["src"]["name"] = "src";
  val["src"]["simpletype"] = "string";
  val["src"]["description"] = R"POLYCUBE(Source IP Address.)POLYCUBE";
  val["src"]["example"] = R"POLYCUBE(10.0.0.1/24)POLYCUBE";
  val["dst"]["name"] = "dst";
  val["dst"]["simpletype"] = "string";
  val["dst"]["description"] = R"POLYCUBE(Destination IP Address.)POLYCUBE";
  val["dst"]["example"] = R"POLYCUBE(10.0.0.2/24)POLYCUBE";
  val["l4proto"]["name"] = "l4proto";
  val["l4proto"]["simpletype"] = "string";
  val["l4proto"]["description"] = R"POLYCUBE(Level 4 Protocol.)POLYCUBE";
  val["l4proto"]["example"] = R"POLYCUBE()POLYCUBE";
  val["sport"]["name"] = "sport";
  val["sport"]["simpletype"] = "integer";
  val["sport"]["description"] = R"POLYCUBE(Source L4 Port)POLYCUBE";
  val["sport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["dport"]["name"] = "dport";
  val["dport"]["simpletype"] = "integer";
  val["dport"]["description"] = R"POLYCUBE(Destination L4 Port)POLYCUBE";
  val["dport"]["example"] = R"POLYCUBE()POLYCUBE";
  val["tcpflags"]["name"] = "tcpflags";
  val["tcpflags"]["simpletype"] = "string";
  val["tcpflags"]["description"] = R"POLYCUBE(TCP flags. Allowed values: SYN, FIN, ACK, RST, PSH, URG, CWR, ECE. ! means set to 0.)POLYCUBE";
  val["tcpflags"]["example"] = R"POLYCUBE(!FIN,SYN,!RST,!ACK)POLYCUBE";
  val["conntrack"]["name"] = "conntrack";
  val["conntrack"]["simpletype"] = "string";
  val["conntrack"]["description"] = R"POLYCUBE(Connection status (NEW, ESTABLISHED, RELATED, INVALID))POLYCUBE";
  val["conntrack"]["example"] = R"POLYCUBE()POLYCUBE";
  val["action"]["name"] = "action";
  val["action"]["simpletype"] = "string";
  val["action"]["description"] = R"POLYCUBE(Action if the rule matches. Default is DROP.)POLYCUBE";
  val["action"]["example"] = R"POLYCUBE(DROP, ACCEPT, LOG)POLYCUBE";

  return val;
}

nlohmann::json ChainAppendInputJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> ChainAppendInputJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string ChainAppendInputJsonObject::getInIface() const {
  return m_inIface;
}

void ChainAppendInputJsonObject::setInIface(std::string value) {
  m_inIface = value;
  m_inIfaceIsSet = true;
}

bool ChainAppendInputJsonObject::inIfaceIsSet() const {
  return m_inIfaceIsSet;
}

void ChainAppendInputJsonObject::unsetInIface() {
  m_inIfaceIsSet = false;
}



std::string ChainAppendInputJsonObject::getOutIface() const {
  return m_outIface;
}

void ChainAppendInputJsonObject::setOutIface(std::string value) {
  m_outIface = value;
  m_outIfaceIsSet = true;
}

bool ChainAppendInputJsonObject::outIfaceIsSet() const {
  return m_outIfaceIsSet;
}

void ChainAppendInputJsonObject::unsetOutIface() {
  m_outIfaceIsSet = false;
}



std::string ChainAppendInputJsonObject::getSrc() const {
  return m_src;
}

void ChainAppendInputJsonObject::setSrc(std::string value) {
  m_src = value;
  m_srcIsSet = true;
}

bool ChainAppendInputJsonObject::srcIsSet() const {
  return m_srcIsSet;
}

void ChainAppendInputJsonObject::unsetSrc() {
  m_srcIsSet = false;
}



std::string ChainAppendInputJsonObject::getDst() const {
  return m_dst;
}

void ChainAppendInputJsonObject::setDst(std::string value) {
  m_dst = value;
  m_dstIsSet = true;
}

bool ChainAppendInputJsonObject::dstIsSet() const {
  return m_dstIsSet;
}

void ChainAppendInputJsonObject::unsetDst() {
  m_dstIsSet = false;
}



std::string ChainAppendInputJsonObject::getL4proto() const {
  return m_l4proto;
}

void ChainAppendInputJsonObject::setL4proto(std::string value) {
  m_l4proto = value;
  m_l4protoIsSet = true;
}

bool ChainAppendInputJsonObject::l4protoIsSet() const {
  return m_l4protoIsSet;
}

void ChainAppendInputJsonObject::unsetL4proto() {
  m_l4protoIsSet = false;
}



uint16_t ChainAppendInputJsonObject::getSport() const {
  return m_sport;
}

void ChainAppendInputJsonObject::setSport(uint16_t value) {
  m_sport = value;
  m_sportIsSet = true;
}

bool ChainAppendInputJsonObject::sportIsSet() const {
  return m_sportIsSet;
}

void ChainAppendInputJsonObject::unsetSport() {
  m_sportIsSet = false;
}



uint16_t ChainAppendInputJsonObject::getDport() const {
  return m_dport;
}

void ChainAppendInputJsonObject::setDport(uint16_t value) {
  m_dport = value;
  m_dportIsSet = true;
}

bool ChainAppendInputJsonObject::dportIsSet() const {
  return m_dportIsSet;
}

void ChainAppendInputJsonObject::unsetDport() {
  m_dportIsSet = false;
}



std::string ChainAppendInputJsonObject::getTcpflags() const {
  return m_tcpflags;
}

void ChainAppendInputJsonObject::setTcpflags(std::string value) {
  m_tcpflags = value;
  m_tcpflagsIsSet = true;
}

bool ChainAppendInputJsonObject::tcpflagsIsSet() const {
  return m_tcpflagsIsSet;
}

void ChainAppendInputJsonObject::unsetTcpflags() {
  m_tcpflagsIsSet = false;
}



ConntrackstatusEnum ChainAppendInputJsonObject::getConntrack() const {
  return m_conntrack;
}

void ChainAppendInputJsonObject::setConntrack(ConntrackstatusEnum value) {
  m_conntrack = value;
  m_conntrackIsSet = true;
}

bool ChainAppendInputJsonObject::conntrackIsSet() const {
  return m_conntrackIsSet;
}

void ChainAppendInputJsonObject::unsetConntrack() {
  m_conntrackIsSet = false;
}

std::string ChainAppendInputJsonObject::ConntrackstatusEnum_to_string(const ConntrackstatusEnum &value){
  switch(value){
    case ConntrackstatusEnum::NEW:
      return std::string("new");
    case ConntrackstatusEnum::ESTABLISHED:
      return std::string("established");
    case ConntrackstatusEnum::RELATED:
      return std::string("related");
    case ConntrackstatusEnum::INVALID:
      return std::string("invalid");
    default:
      throw std::runtime_error("Bad ChainAppendInput conntrack");
  }
}

ConntrackstatusEnum ChainAppendInputJsonObject::string_to_ConntrackstatusEnum(const std::string &str){
  if (JsonObjectBase::iequals("new", str))
    return ConntrackstatusEnum::NEW;
  if (JsonObjectBase::iequals("established", str))
    return ConntrackstatusEnum::ESTABLISHED;
  if (JsonObjectBase::iequals("related", str))
    return ConntrackstatusEnum::RELATED;
  if (JsonObjectBase::iequals("invalid", str))
    return ConntrackstatusEnum::INVALID;
  throw std::runtime_error("ChainAppendInput conntrack is invalid");
}


ActionEnum ChainAppendInputJsonObject::getAction() const {
  return m_action;
}

void ChainAppendInputJsonObject::setAction(ActionEnum value) {
  m_action = value;
  m_actionIsSet = true;
}

bool ChainAppendInputJsonObject::actionIsSet() const {
  return m_actionIsSet;
}

void ChainAppendInputJsonObject::unsetAction() {
  m_actionIsSet = false;
}

std::string ChainAppendInputJsonObject::ActionEnum_to_string(const ActionEnum &value){
  switch(value){
    case ActionEnum::DROP:
      return std::string("drop");
    case ActionEnum::LOG:
      return std::string("log");
    case ActionEnum::ACCEPT:
      return std::string("accept");
    default:
      throw std::runtime_error("Bad ChainAppendInput action");
  }
}

ActionEnum ChainAppendInputJsonObject::string_to_ActionEnum(const std::string &str){
  if (JsonObjectBase::iequals("drop", str))
    return ActionEnum::DROP;
  if (JsonObjectBase::iequals("log", str))
    return ActionEnum::LOG;
  if (JsonObjectBase::iequals("accept", str))
    return ActionEnum::ACCEPT;
  throw std::runtime_error("ChainAppendInput action is invalid");
}



}
}
}
}


