/**
* pbforwarder API
* Policy-Based Forwarder Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* PbforwarderJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "PortsJsonObject.h"
#include <vector>
#include "RulesJsonObject.h"
#include "polycube/services/cube.h"

using polycube::service::CubeType;

namespace io {
namespace swagger {
namespace server {
namespace model {

enum class PbforwarderLoglevelEnum {
  TRACE, DEBUG, INFO, WARN, ERR, CRITICAL, OFF
};

/// <summary>
///
/// </summary>
class  PbforwarderJsonObject : public JsonObjectBase {
public:
  PbforwarderJsonObject();
  PbforwarderJsonObject(nlohmann::json& json);
  ~PbforwarderJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// PbforwarderJsonObject members

  /// <summary>
  /// Name of the pbforwarder service
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
  PbforwarderLoglevelEnum getLoglevel() const;
  void setLoglevel(PbforwarderLoglevelEnum value);
  bool loglevelIsSet() const;
  void unsetLoglevel();
  static std::string PbforwarderLoglevelEnum_to_string(const PbforwarderLoglevelEnum &value);
  static PbforwarderLoglevelEnum string_to_PbforwarderLoglevelEnum(const std::string &str);
  polycube::LogLevel getPolycubeLoglevel() const;
  /// <summary>
  /// Entry of the ports table
  /// </summary>
  const std::vector<PortsJsonObject>& getPorts() const;
  void addPorts(PortsJsonObject value);
  bool portsIsSet() const;
  void unsetPorts();

  /// <summary>
  /// Rule that contains all possible matches and the action for a packet
  /// </summary>
  const std::vector<RulesJsonObject>& getRules() const;
  void addRules(RulesJsonObject value);
  bool rulesIsSet() const;
  void unsetRules();


private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_uuid;
  bool m_uuidIsSet;
  CubeType m_type;
  bool m_typeIsSet;
  PbforwarderLoglevelEnum m_loglevel;
  bool m_loglevelIsSet;
  std::vector<PortsJsonObject> m_ports;
  bool m_portsIsSet;
  std::vector<RulesJsonObject> m_rules;
  bool m_rulesIsSet;
};

}
}
}
}

