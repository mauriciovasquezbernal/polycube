/**
* nat API
* NAT Service
*
* OpenAPI spec version: 1.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* RuleDnatAppendInputJsonObject.h
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
class  RuleDnatAppendInputJsonObject : public JsonObjectBase {
public:
  RuleDnatAppendInputJsonObject();
  RuleDnatAppendInputJsonObject(nlohmann::json& json);
  ~RuleDnatAppendInputJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// RuleDnatAppendInputJsonObject members

  /// <summary>
  /// External destination IP address
  /// </summary>
  std::string getExternalIp() const;
  void setExternalIp(std::string value);
  bool externalIpIsSet() const;
  void unsetExternalIp();

  /// <summary>
  /// Internal destination IP address
  /// </summary>
  std::string getInternalIp() const;
  void setInternalIp(std::string value);
  bool internalIpIsSet() const;
  void unsetInternalIp();


private:
  std::string m_externalIp;
  bool m_externalIpIsSet;
  std::string m_internalIp;
  bool m_internalIpIsSet;
};

}
}
}
}

