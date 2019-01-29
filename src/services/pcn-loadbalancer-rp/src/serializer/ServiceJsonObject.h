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
* ServiceJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "ServiceBackendJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace model {

enum class ServiceProtoEnum {
  ICMP, TCP, UDP, ALL
};

/// <summary>
///
/// </summary>
class  ServiceJsonObject : public JsonObjectBase {
public:
  ServiceJsonObject();
  ServiceJsonObject(nlohmann::json& json);
  ~ServiceJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// ServiceJsonObject members

  /// <summary>
  /// Service name related to the backend server of the pool is connected to
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;
  void unsetName();

  /// <summary>
  /// Virtual IP (vip) of the service where clients connect to
  /// </summary>
  std::string getVip() const;
  void setVip(std::string value);
  bool vipIsSet() const;
  void unsetVip();

  /// <summary>
  /// Port of the virtual server where clients connect to (this value is ignored in case of ICMP)
  /// </summary>
  uint16_t getVport() const;
  void setVport(uint16_t value);
  bool vportIsSet() const;
  void unsetVport();

  /// <summary>
  /// Upper-layer protocol associated with a loadbalancing service instance. &#39;ALL&#39; creates an entry for all the supported protocols
  /// </summary>
  ServiceProtoEnum getProto() const;
  void setProto(ServiceProtoEnum value);
  bool protoIsSet() const;
  void unsetProto();
  static std::string ServiceProtoEnum_to_string(const ServiceProtoEnum &value);
  static ServiceProtoEnum string_to_ServiceProtoEnum(const std::string &str);

  /// <summary>
  /// Pool of backend servers that actually serve requests
  /// </summary>
  const std::vector<ServiceBackendJsonObject>& getBackend() const;
  void addServiceBackend(ServiceBackendJsonObject value);
  bool backendIsSet() const;
  void unsetBackend();


private:
  std::string m_name;
  bool m_nameIsSet;
  std::string m_vip;
  bool m_vipIsSet;
  uint16_t m_vport;
  bool m_vportIsSet;
  ServiceProtoEnum m_proto;
  bool m_protoIsSet;
  std::vector<ServiceBackendJsonObject> m_backend;
  bool m_backendIsSet;
};

}
}
}
}

