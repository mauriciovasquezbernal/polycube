/**
* k8switch API
* Kubernetes HyperSwitch Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
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


namespace io {
namespace swagger {
namespace server {
namespace model {

enum class PortsStatusEnum {
  UP, DOWN
};
enum class PortsTypeEnum {
  DEFAULT, NODEPORT
};

/// <summary>
///
/// </summary>
class  PortsJsonObject : public JsonObjectBase {
public:
  PortsJsonObject();
  PortsJsonObject(nlohmann::json& json);
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
  void unsetName();

  /// <summary>
  /// UUID of the port
  /// </summary>
  std::string getUuid() const;
  void setUuid(std::string value);
  bool uuidIsSet() const;
  void unsetUuid();

  /// <summary>
  /// Status of the port (UP or DOWN)
  /// </summary>
  PortsStatusEnum getStatus() const;
  void setStatus(PortsStatusEnum value);
  bool statusIsSet() const;
  void unsetStatus();
  static std::string PortsStatusEnum_to_string(const PortsStatusEnum &value);
  static PortsStatusEnum string_to_PortsStatusEnum(const std::string &str);

  /// <summary>
  /// Peer name, such as a network interfaces (e.g., &#39;veth0&#39;) or another cube (e.g., &#39;br1:port2&#39;)
  /// </summary>
  std::string getPeer() const;
  void setPeer(std::string value);
  bool peerIsSet() const;
  void unsetPeer();

  /// <summary>
  /// Type of the LB port (e.g. NODEPORT or DEFAULT)
  /// </summary>
  PortsTypeEnum getType() const;
  void setType(PortsTypeEnum value);
  bool typeIsSet() const;
  void unsetType();
  static std::string PortsTypeEnum_to_string(const PortsTypeEnum &value);
  static PortsTypeEnum string_to_PortsTypeEnum(const std::string &str);


private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_uuid;
  bool m_uuidIsSet;
  PortsStatusEnum m_status;
  bool m_statusIsSet;
  std::string m_peer;
  bool m_peerIsSet;
  PortsTypeEnum m_type;
  bool m_typeIsSet;
};

}
}
}
}

