/**
* firewall API
* Firewall Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */



#include "ChainJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

ChainJsonObject::ChainJsonObject() : 
  m_nameIsSet (false),
  m_defaultIsSet (false),
  m_statsIsSet (false),
  m_ruleIsSet (false) { }

ChainJsonObject::ChainJsonObject(nlohmann::json& val) : 
  m_nameIsSet (false),
  m_defaultIsSet (false),
  m_statsIsSet (false),
  m_ruleIsSet (false) { 

  if (val.count("default") != 0) {
    setDefault(string_to_ActionEnum(val.at("default").get<std::string>()));
  }

  m_stats.clear();
  for (auto& item : val["stats"]) { 
    ChainStatsJsonObject newItem { item };
    m_stats.push_back(newItem);
  }
  m_statsIsSet = !m_stats.empty();
  

  m_rule.clear();
  for (auto& item : val["rule"]) { 
    ChainRuleJsonObject newItem { item };
    m_rule.push_back(newItem);
  }
  m_ruleIsSet = !m_rule.empty();
  
}

nlohmann::json ChainJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  val["name"] = ChainNameEnum_to_string(m_name);
  if (m_defaultIsSet) {
    val["default"] = ActionEnum_to_string(m_default);
  }

  {
    nlohmann::json jsonArray;
    for (auto& item : m_stats) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["stats"] = jsonArray;
    }
  }
  {
    nlohmann::json jsonArray;
    for (auto& item : m_rule) {
      jsonArray.push_back(JsonObjectBase::toJson(item));
    }

    if (jsonArray.size() > 0) {
      val["rule"] = jsonArray;
    }
  }

  return val;
}

nlohmann::json ChainJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();

  val["name"]["name"] = "name";
  val["name"]["type"] = "key";
  val["name"]["simpletype"] = "string";
  val["name"]["description"] = R"POLYCUBE(Chain in which the rule will be inserted. Default: INGRESS.)POLYCUBE";
  val["name"]["example"] = R"POLYCUBE(INGRESS, EGRESS.)POLYCUBE";

  return val;
}

nlohmann::json ChainJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["default"]["name"] = "default";
  val["default"]["type"] = "leaf"; // Suppose that type is leaf
  val["default"]["simpletype"] = "string";
  val["default"]["description"] = R"POLYCUBE(Default action if no rule matches in the ingress chain. Default is DROP.)POLYCUBE";
  val["default"]["example"] = R"POLYCUBE(DROP, FORWARD, LOG)POLYCUBE";
  val["stats"]["name"] = "stats";
  val["stats"]["type"] = "leaf"; // Suppose that type is leaf
  val["stats"]["type"] = "list";
  val["stats"]["description"] = R"POLYCUBE()POLYCUBE";
  val["stats"]["example"] = R"POLYCUBE()POLYCUBE";
  val["rule"]["name"] = "rule";
  val["rule"]["type"] = "leaf"; // Suppose that type is leaf
  val["rule"]["type"] = "list";
  val["rule"]["description"] = R"POLYCUBE()POLYCUBE";
  val["rule"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json ChainJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["default"]["name"] = "default";
  val["default"]["simpletype"] = "string";
  val["default"]["description"] = R"POLYCUBE(Default action if no rule matches in the ingress chain. Default is DROP.)POLYCUBE";
  val["default"]["example"] = R"POLYCUBE(DROP, FORWARD, LOG)POLYCUBE";

  return val;
}

nlohmann::json ChainJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();

  val["stats"]["name"] = "stats";
  val["stats"]["type"] = "list";
  val["stats"]["description"] = R"POLYCUBE()POLYCUBE";
  val["stats"]["example"] = R"POLYCUBE()POLYCUBE";
  val["rule"]["name"] = "rule";
  val["rule"]["type"] = "list";
  val["rule"]["description"] = R"POLYCUBE()POLYCUBE";
  val["rule"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

std::vector<std::string> ChainJsonObject::helpActions() {
  std::vector<std::string> val;
  val.push_back("append");
  val.push_back("reset-counters");
  val.push_back("apply-rules");
  return val;
}

ChainNameEnum ChainJsonObject::getName() const {
  return m_name;
}

void ChainJsonObject::setName(ChainNameEnum value) {
  m_name = value;
  m_nameIsSet = true;
}

bool ChainJsonObject::nameIsSet() const {
  return m_nameIsSet;
}



std::string ChainJsonObject::ChainNameEnum_to_string(const ChainNameEnum &value){
  switch(value){
    case ChainNameEnum::INGRESS:
      return std::string("ingress");
    case ChainNameEnum::EGRESS:
      return std::string("egress");
    case ChainNameEnum::INVALID:
      return std::string("invalid");
    default:
      throw std::runtime_error("Bad Chain name");
  }
}

ChainNameEnum ChainJsonObject::string_to_ChainNameEnum(const std::string &str){
  if (JsonObjectBase::iequals("ingress", str))
    return ChainNameEnum::INGRESS;
  if (JsonObjectBase::iequals("egress", str))
    return ChainNameEnum::EGRESS;
  if (JsonObjectBase::iequals("invalid", str))
    return ChainNameEnum::INVALID;
  throw std::runtime_error("Chain name is invalid");
}


ActionEnum ChainJsonObject::getDefault() const {
  return m_default;
}

void ChainJsonObject::setDefault(ActionEnum value) {
  m_default = value;
  m_defaultIsSet = true;
}

bool ChainJsonObject::defaultIsSet() const {
  return m_defaultIsSet;
}

void ChainJsonObject::unsetDefault() {
  m_defaultIsSet = false;
}

std::string ChainJsonObject::ActionEnum_to_string(const ActionEnum &value){
  switch(value){
    case ActionEnum::DROP:
      return std::string("drop");
    case ActionEnum::LOG:
      return std::string("log");
    case ActionEnum::FORWARD:
      return std::string("forward");
    default:
      throw std::runtime_error("Bad Chain default");
  }
}

ActionEnum ChainJsonObject::string_to_ActionEnum(const std::string &str){
  if (JsonObjectBase::iequals("drop", str))
    return ActionEnum::DROP;
  if (JsonObjectBase::iequals("log", str))
    return ActionEnum::LOG;
  if (JsonObjectBase::iequals("forward", str))
    return ActionEnum::FORWARD;
  throw std::runtime_error("Chain default is invalid");
}


const std::vector<ChainStatsJsonObject>& ChainJsonObject::getStats() const{
  return m_stats;
}

void ChainJsonObject::addChainStats(ChainStatsJsonObject value) {
  m_stats.push_back(value);
}


bool ChainJsonObject::statsIsSet() const {
  return m_statsIsSet;
}

void ChainJsonObject::unsetStats() {
  m_statsIsSet = false;
}



const std::vector<ChainRuleJsonObject>& ChainJsonObject::getRule() const{
  return m_rule;
}

void ChainJsonObject::addChainRule(ChainRuleJsonObject value) {
  m_rule.push_back(value);
}


bool ChainJsonObject::ruleIsSet() const {
  return m_ruleIsSet;
}

void ChainJsonObject::unsetRule() {
  m_ruleIsSet = false;
}




}
}
}
}


