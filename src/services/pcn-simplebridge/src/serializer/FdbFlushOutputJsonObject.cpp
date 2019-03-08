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



#include "FdbFlushOutputJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

FdbFlushOutputJsonObject::FdbFlushOutputJsonObject() {
  m_flushedIsSet = false;
}

FdbFlushOutputJsonObject::FdbFlushOutputJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_flushedIsSet = false;


  if (val.count("flushed")) {
    setFlushed(val.at("flushed").get<bool>());
  }
}

nlohmann::json FdbFlushOutputJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_flushedIsSet) {
    val["flushed"] = m_flushed;
  }

  return val;
}

bool FdbFlushOutputJsonObject::getFlushed() const {
  return m_flushed;
}

void FdbFlushOutputJsonObject::setFlushed(bool value) {
  m_flushed = value;
  m_flushedIsSet = true;
}

bool FdbFlushOutputJsonObject::flushedIsSet() const {
  return m_flushedIsSet;
}




nlohmann::json FdbFlushOutputJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json FdbFlushOutputJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["flushed"]["name"] = "flushed";
  val["flushed"]["type"] = "leaf"; // Suppose that type is leaf
  val["flushed"]["simpletype"] = "boolean";
  val["flushed"]["description"] = R"POLYCUBE(Returns true if the Filtering database has been flushed. False otherwise)POLYCUBE";
  val["flushed"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json FdbFlushOutputJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["flushed"]["name"] = "flushed";
  val["flushed"]["simpletype"] = "boolean";
  val["flushed"]["description"] = R"POLYCUBE(Returns true if the Filtering database has been flushed. False otherwise)POLYCUBE";
  val["flushed"]["example"] = R"POLYCUBE()POLYCUBE";

  return val;
}

nlohmann::json FdbFlushOutputJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> FdbFlushOutputJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

}
}
}
}

