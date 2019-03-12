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
* ChainApplyRulesOutputJsonObject.h
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
class  ChainApplyRulesOutputJsonObject : public JsonObjectBase {
public:
  ChainApplyRulesOutputJsonObject();
  ChainApplyRulesOutputJsonObject(const nlohmann::json &json);
  ~ChainApplyRulesOutputJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// ChainApplyRulesOutputJsonObject members

  /// <summary>
  /// True if the operation is successful
  /// </summary>
  bool getResult() const;
  void setResult(bool value);
  bool resultIsSet() const;
  void unsetResult();

private:
  bool m_result;
  bool m_resultIsSet;
};

}
}
}
}

