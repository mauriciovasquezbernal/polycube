/**
 * bridge API generated from bridge.yang
 *
 * NOTE: This file is auto generated by polycube-codegen
 * https://github.com/polycube-network/polycube-codegen
 */

/* Do not edit this file manually */

/*
 * PortsStpBase.h
 *
 *
 */

#pragma once

#include "../serializer/PortsStpJsonObject.h"

#include <spdlog/spdlog.h>

using namespace polycube::service::model;

class Ports;

class PortsStpBase {
 public:
  PortsStpBase(Ports &parent);

  virtual ~PortsStpBase();
  virtual void update(const PortsStpJsonObject &conf);
  virtual PortsStpJsonObject toJsonObject();

  /// <summary>
  /// VLAN identifier for this entry
  /// </summary>
  virtual uint16_t getVlan() = 0;

  /// <summary>
  /// STP port state
  /// </summary>
  virtual PortsStpStateEnum getState() = 0;

  /// <summary>
  /// STP cost associated with this interface
  /// </summary>
  virtual uint32_t getPathCost() = 0;
  virtual void setPathCost(const uint32_t &value) = 0;

  /// <summary>
  /// Port priority of this interface
  /// </summary>
  virtual uint8_t getPortPriority() = 0;
  virtual void setPortPriority(const uint8_t &value) = 0;

  std::shared_ptr<spdlog::logger> logger();

 protected:
  Ports &parent_;
};
