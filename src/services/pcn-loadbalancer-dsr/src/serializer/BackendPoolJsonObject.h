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

/*
* BackendPoolJsonObject.h
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
class  BackendPoolJsonObject : public JsonObjectBase {
public:
  BackendPoolJsonObject();
  BackendPoolJsonObject(nlohmann::json& json);
  ~BackendPoolJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// BackendPoolJsonObject members

  /// <summary>
  /// id
  /// </summary>
  uint32_t getId() const;
  void setId(uint32_t value);
  bool idIsSet() const;
  void unsetId();

  /// <summary>
  /// MAC address of the backend server of the pool
  /// </summary>
  std::string getMac() const;
  void setMac(std::string value);
  bool macIsSet() const;
  void unsetMac();


private:
  uint32_t m_id;
  bool m_idIsSet;
  std::string m_mac;
  bool m_macIsSet;
};

}
}
}
}

