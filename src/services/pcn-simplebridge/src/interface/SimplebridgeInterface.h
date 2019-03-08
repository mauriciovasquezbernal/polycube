/**
* simplebridge API
* simplebridge API generated from simplebridge.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* SimplebridgeInterface.h
*
*
*/

#pragma once

#include "../serializer/SimplebridgeJsonObject.h"

#include "../Fdb.h"
#include "../Ports.h"

using namespace io::swagger::server::model;

class SimplebridgeInterface {
public:

  virtual void update(const SimplebridgeJsonObject &conf) = 0;
  virtual SimplebridgeJsonObject toJsonObject() = 0;

  /// <summary>
  /// Name of the simplebridge service
  /// </summary>
  //virtual std::string getName() = 0;

  /// <summary>
  /// Entry of the ports table
  /// </summary>
  virtual std::shared_ptr<Ports> getPorts(const std::string &name) = 0;
  virtual std::vector<std::shared_ptr<Ports>> getPortsList() = 0;
  virtual void addPorts(const std::string &name, const PortsJsonObject &conf) = 0;
  virtual void addPortsList(const std::vector<PortsJsonObject> &conf) = 0;
  virtual void replacePorts(const std::string &name, const PortsJsonObject &conf) = 0;
  virtual void delPorts(const std::string &name) = 0;
  virtual void delPortsList() = 0;

  /// <summary>
  ///
  /// </summary>
  virtual std::shared_ptr<Fdb> getFdb() = 0;
  virtual void addFdb(const FdbJsonObject &value) = 0;
  virtual void replaceFdb(const FdbJsonObject &conf) = 0;
  virtual void delFdb() = 0;
};

