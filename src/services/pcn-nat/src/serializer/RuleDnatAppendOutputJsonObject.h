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
* RuleDnatAppendOutputJsonObject.h
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
class  RuleDnatAppendOutputJsonObject : public JsonObjectBase {
public:
  RuleDnatAppendOutputJsonObject();
  RuleDnatAppendOutputJsonObject(nlohmann::json& json);
  ~RuleDnatAppendOutputJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// RuleDnatAppendOutputJsonObject members

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

