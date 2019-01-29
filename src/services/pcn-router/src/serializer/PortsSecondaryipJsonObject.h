/**
* router API
* Router Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* PortsSecondaryipJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  PortsSecondaryipJsonObject : public JsonObjectBase {
public:
  PortsSecondaryipJsonObject();
  PortsSecondaryipJsonObject(nlohmann::json& json);
  ~PortsSecondaryipJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// PortsSecondaryipJsonObject members

  /// <summary>
  /// Seconadary IP address of the port
  /// </summary>
  std::string getIp() const;
  void setIp(std::string value);
  bool ipIsSet() const;
  void unsetIp();

  /// <summary>
  /// Secondary netmask of the port
  /// </summary>
  std::string getNetmask() const;
  void setNetmask(std::string value);
  bool netmaskIsSet() const;
  void unsetNetmask();


private:
  std::string m_ip;
  bool m_ipIsSet;
  std::string m_netmask;
  bool m_netmaskIsSet;
};

}
}
}
}

