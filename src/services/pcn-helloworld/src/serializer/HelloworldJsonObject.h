/**
* helloworld API
* Helloworld Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* HelloworldJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "PortsJsonObject.h"
#include <vector>
#include "polycube/services/cube.h"

using polycube::service::CubeType;

namespace io {
namespace swagger {
namespace server {
namespace model {

enum class HelloworldLoglevelEnum {
  TRACE, DEBUG, INFO, WARN, ERR, CRITICAL, OFF
};

enum class HelloworldActionEnum {
  DROP, SLOWPATH, FORWARD
};

/// <summary>
///
/// </summary>
class  HelloworldJsonObject : public JsonObjectBase {
public:
  HelloworldJsonObject();
  HelloworldJsonObject(nlohmann::json& json);
  ~HelloworldJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// HelloworldJsonObject members

  /// <summary>
  /// Name of the helloworld service
  /// </summary>
  std::string getName() const;
  void setName(std::string value);
  bool nameIsSet() const;

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  const std::vector<PortsJsonObject>& getPorts() const;
  void addPorts(PortsJsonObject value);
  bool portsIsSet() const;
  void unsetPorts();

  /// <summary>
  /// Action performed on the received packet (i.e., DROP, SLOWPATH, or FORWARD; default: DROP)
  /// </summary>
  HelloworldActionEnum getAction() const;
  void setAction(HelloworldActionEnum value);
  bool actionIsSet() const;
  void unsetAction();
  static std::string HelloworldActionEnum_to_string(const HelloworldActionEnum &value);
  static HelloworldActionEnum string_to_HelloworldActionEnum(const std::string &str);

private:
  std::string m_name;
  bool m_nameIsSet;
  std::vector<PortsJsonObject> m_ports;
  bool m_portsIsSet;
  HelloworldActionEnum m_action;
  bool m_actionIsSet;
};

}
}
}
}

