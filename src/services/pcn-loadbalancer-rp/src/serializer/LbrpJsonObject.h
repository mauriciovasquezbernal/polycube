/**
* lbrp API
* LoadBalancer Reverse-Proxy Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* LbrpJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "ServiceJsonObject.h"
#include "SrcIpRewriteJsonObject.h"
#include "PortsJsonObject.h"
#include <vector>
#include "polycube/services/cube.h"

using polycube::service::CubeType;

namespace io {
namespace swagger {
namespace server {
namespace model {

enum class LbrpLoglevelEnum {
  TRACE, DEBUG, INFO, WARN, ERR, CRITICAL, OFF
};

/// <summary>
///
/// </summary>
class  LbrpJsonObject : public JsonObjectBase {
public:
  LbrpJsonObject();
  LbrpJsonObject(nlohmann::json& json);
  ~LbrpJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// LbrpJsonObject members

  /// <summary>
  /// Name of the lbrp service
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
  LbrpLoglevelEnum getLoglevel() const;
  void setLoglevel(LbrpLoglevelEnum value);
  bool loglevelIsSet() const;
  void unsetLoglevel();
  static std::string LbrpLoglevelEnum_to_string(const LbrpLoglevelEnum &value);
  static LbrpLoglevelEnum string_to_LbrpLoglevelEnum(const std::string &str);
  polycube::LogLevel getPolycubeLoglevel() const;
  /// <summary>
  /// Entry of the ports table
  /// </summary>
  const std::vector<PortsJsonObject>& getPorts() const;
  void addPorts(PortsJsonObject value);
  bool portsIsSet() const;
  void unsetPorts();

  /// <summary>
  ///
  /// </summary>
  SrcIpRewriteJsonObject getSrcIpRewrite() const;
  void setSrcIpRewrite(SrcIpRewriteJsonObject value);
  bool srcIpRewriteIsSet() const;
  void unsetSrcIpRewrite();

  /// <summary>
  /// Services (i.e., virtual ip:protocol:port) exported to the client
  /// </summary>
  const std::vector<ServiceJsonObject>& getService() const;
  void addService(ServiceJsonObject value);
  bool serviceIsSet() const;
  void unsetService();


private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_uuid;
  bool m_uuidIsSet;
  CubeType m_type;
  bool m_typeIsSet;
  LbrpLoglevelEnum m_loglevel;
  bool m_loglevelIsSet;
  std::vector<PortsJsonObject> m_ports;
  bool m_portsIsSet;
  SrcIpRewriteJsonObject m_srcIpRewrite;
  bool m_srcIpRewriteIsSet;
  std::vector<ServiceJsonObject> m_service;
  bool m_serviceIsSet;
};

}
}
}
}

