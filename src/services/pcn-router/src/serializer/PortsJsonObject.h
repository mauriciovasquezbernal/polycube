/**
* router API
* router API generated from router.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* PortsJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "PortsSecondaryipJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  PortsJsonObject : public JsonObjectBase {
public:
  PortsJsonObject();
  PortsJsonObject(const nlohmann::json &json);
  ~PortsJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// PortsJsonObject members

  /// <summary>
  /// Port Name
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;

  /// <summary>
  /// IP address of the port
  /// </summary>
  std::string getIp() const;
  void setIp(std::string value);
  bool ipIsSet() const;

  /// <summary>
  /// Netmask of the port
  /// </summary>
  std::string getNetmask() const;
  void setNetmask(std::string value);
  bool netmaskIsSet() const;

  /// <summary>
  /// Secondary IP address for the port
  /// </summary>
  const std::vector<PortsSecondaryipJsonObject>& getSecondaryip() const;
  void addPortsSecondaryip(PortsSecondaryipJsonObject value);
  bool secondaryipIsSet() const;
  void unsetSecondaryip();

  /// <summary>
  /// MAC address of the port
  /// </summary>
  std::string getMac() const;
  void setMac(std::string value);
  bool macIsSet() const;
  void unsetMac();

private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_ip;
  bool m_ipIsSet;
  std::string m_netmask;
  bool m_netmaskIsSet;
  std::vector<PortsSecondaryipJsonObject> m_secondaryip;
  bool m_secondaryipIsSet;
  std::string m_mac;
  bool m_macIsSet;
};

}
}
}
}

