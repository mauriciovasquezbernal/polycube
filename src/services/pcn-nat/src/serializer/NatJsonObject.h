/**
* nat API
* NAT Service
*
* OpenAPI spec version: 1.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* NatJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "RuleJsonObject.h"
#include <vector>
#include "NattingTableJsonObject.h"
#include "polycube/services/cube.h"

using polycube::service::CubeType;

namespace io {
namespace swagger {
namespace server {
namespace model {

enum class NatLoglevelEnum {
  TRACE, DEBUG, INFO, WARN, ERR, CRITICAL, OFF
};

/// <summary>
///
/// </summary>
class  NatJsonObject : public JsonObjectBase {
public:
  NatJsonObject();
  NatJsonObject(nlohmann::json& json);
  ~NatJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// NatJsonObject members

  /// <summary>
  /// Name of the nat service
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;
  void unsetName();

  /// <summary>
  /// UUID of the Cube
  /// </summary>
  std::string getUuid() const;
  void setUuid(std::string value);
  bool uuidIsSet() const;
  void unsetUuid();

  /// <summary>
  /// Type of the Cube (TC, XDP_SKB, XDP_DRV)
  /// </summary>
  CubeType getType() const;
  void setType(CubeType value);
  bool typeIsSet() const;
  void unsetType();
  static std::string CubeType_to_string(const CubeType &value);
  static CubeType string_to_CubeType(const std::string &str);

  /// <summary>
  /// Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE)
  /// </summary>
  NatLoglevelEnum getLoglevel() const;
  void setLoglevel(NatLoglevelEnum value);
  bool loglevelIsSet() const;
  void unsetLoglevel();
  static std::string NatLoglevelEnum_to_string(const NatLoglevelEnum &value);
  static NatLoglevelEnum string_to_NatLoglevelEnum(const std::string &str);
  polycube::LogLevel getPolycubeLoglevel() const;

  /// <summary>
  ///
  /// </summary>
  RuleJsonObject getRule() const;
  void setRule(RuleJsonObject value);
  bool ruleIsSet() const;
  void unsetRule();

  /// <summary>
  ///
  /// </summary>
  const std::vector<NattingTableJsonObject>& getNattingTable() const;
  void addNattingTable(NattingTableJsonObject value);
  bool nattingTableIsSet() const;
  void unsetNattingTable();


private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_uuid;
  bool m_uuidIsSet;
  CubeType m_type;
  bool m_typeIsSet;
  NatLoglevelEnum m_loglevel;
  bool m_loglevelIsSet;
  RuleJsonObject m_rule;
  bool m_ruleIsSet;
  std::vector<NattingTableJsonObject> m_nattingTable;
  bool m_nattingTableIsSet;
};

}
}
}
}

