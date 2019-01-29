/**
* ddosmitigator API
* DDoS Mitigator Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* BlacklistSrcJsonObject.h
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
class  BlacklistSrcJsonObject : public JsonObjectBase {
public:
  BlacklistSrcJsonObject();
  BlacklistSrcJsonObject(nlohmann::json& json);
  ~BlacklistSrcJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// BlacklistSrcJsonObject members

  /// <summary>
  /// Source IP Address
  /// </summary>
  std::string getIp() const;
  void setIp(std::string value);
  bool ipIsSet() const;
  void unsetIp();

  /// <summary>
  /// Dropped Packets
  /// </summary>
  uint64_t getDropPkts() const;
  void setDropPkts(uint64_t value);
  bool dropPktsIsSet() const;
  void unsetDropPkts();


private:
  std::string m_ip;
  bool m_ipIsSet;
  uint64_t m_dropPkts;
  bool m_dropPktsIsSet;
};

}
}
}
}

