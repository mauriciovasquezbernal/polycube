/**
* iptables API
* iptables API generated from iptables.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* ChainAppendOutputJsonObject.h
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
class  ChainAppendOutputJsonObject : public JsonObjectBase {
public:
  ChainAppendOutputJsonObject();
  ChainAppendOutputJsonObject(nlohmann::json& json);
  ~ChainAppendOutputJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// ChainAppendOutputJsonObject members

  /// <summary>
  ///
  /// </summary>
  uint32_t getId() const;
  void setId(uint32_t value);
  bool idIsSet() const;
  void unsetId();


private:
  uint32_t m_id;
  bool m_idIsSet;
};

}
}
}
}

