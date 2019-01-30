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



#include "FrontendJsonObject.h"
#include <regex>

namespace io {
namespace swagger {
namespace server {
namespace model {

FrontendJsonObject::FrontendJsonObject() : 
  m_vipIsSet (false),
  m_macIsSet (false) { }

FrontendJsonObject::FrontendJsonObject(nlohmann::json& val) : 
  m_vipIsSet (false),
  m_macIsSet (false) { 
  if (val.count("vip") != 0) {
    setVip(val.at("vip").get<std::string>());
  }

  if (val.count("mac") != 0) {
    setMac(val.at("mac").get<std::string>());
  }
}

nlohmann::json FrontendJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();

  if (m_vipIsSet) {
    val["vip"] = m_vip;
  }

  if (m_macIsSet) {
    val["mac"] = m_mac;
  }


  return val;
}

nlohmann::json FrontendJsonObject::helpKeys() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

nlohmann::json FrontendJsonObject::helpElements() {
  nlohmann::json val = nlohmann::json::object();

  val["vip"]["name"] = "vip";
  val["vip"]["type"] = "leaf"; // Suppose that type is leaf
  val["vip"]["simpletype"] = "string";
  val["vip"]["description"] = R"POLYCUBE(IP address of the loadbalancer frontend)POLYCUBE";
  val["vip"]["example"] = R"POLYCUBE(130.192.100.1)POLYCUBE";
  val["mac"]["name"] = "mac";
  val["mac"]["type"] = "leaf"; // Suppose that type is leaf
  val["mac"]["simpletype"] = "string";
  val["mac"]["description"] = R"POLYCUBE(MAC address of the port)POLYCUBE";
  val["mac"]["example"] = R"POLYCUBE(aa:bb:cc:dd:ee:ff)POLYCUBE";

  return val;
}

nlohmann::json FrontendJsonObject::helpWritableLeafs() {
  nlohmann::json val = nlohmann::json::object();

  val["vip"]["name"] = "vip";
  val["vip"]["simpletype"] = "string";
  val["vip"]["description"] = R"POLYCUBE(IP address of the loadbalancer frontend)POLYCUBE";
  val["vip"]["example"] = R"POLYCUBE(130.192.100.1)POLYCUBE";
  val["mac"]["name"] = "mac";
  val["mac"]["simpletype"] = "string";
  val["mac"]["description"] = R"POLYCUBE(MAC address of the port)POLYCUBE";
  val["mac"]["example"] = R"POLYCUBE(aa:bb:cc:dd:ee:ff)POLYCUBE";

  return val;
}

nlohmann::json FrontendJsonObject::helpComplexElements() {
  nlohmann::json val = nlohmann::json::object();


  return val;
}

std::vector<std::string> FrontendJsonObject::helpActions() {
  std::vector<std::string> val;
  return val;
}

std::string FrontendJsonObject::getVip() const {
  return m_vip;
}

void FrontendJsonObject::setVip(std::string value) {
  m_vip = value;
  m_vipIsSet = true;
}

bool FrontendJsonObject::vipIsSet() const {
  return m_vipIsSet;
}

void FrontendJsonObject::unsetVip() {
  m_vipIsSet = false;
}



std::string FrontendJsonObject::getMac() const {
  return m_mac;
}

void FrontendJsonObject::setMac(std::string value) {
  m_mac = value;
  m_macIsSet = true;
}

bool FrontendJsonObject::macIsSet() const {
  return m_macIsSet;
}

void FrontendJsonObject::unsetMac() {
  m_macIsSet = false;
}




}
}
}
}


