/**
 * bridge API generated from bridge.yang
 *
 * NOTE: This file is auto generated by polycube-codegen
 * https://github.com/polycube-network/polycube-codegen
 */

/* Do not edit this file manually */

/*
 * PortsTrunkBase.h
 *
 *
 */

#pragma once

#include "../serializer/PortsTrunkJsonObject.h"

#include "../PortsTrunkAllowed.h"

#include <spdlog/spdlog.h>

using namespace polycube::service::model;

class Ports;

class PortsTrunkBase {
 public:
  PortsTrunkBase(Ports &parent);

  virtual ~PortsTrunkBase();
  virtual void update(const PortsTrunkJsonObject &conf);
  virtual PortsTrunkJsonObject toJsonObject();

  /// <summary>
  /// Allowed vlans
  /// </summary>
  virtual std::shared_ptr<PortsTrunkAllowed> getAllowed(
      const uint16_t &vlanid) = 0;
  virtual std::vector<std::shared_ptr<PortsTrunkAllowed>> getAllowedList() = 0;
  virtual void addAllowed(const uint16_t &vlanid,
                          const PortsTrunkAllowedJsonObject &conf) = 0;
  virtual void addAllowedList(
      const std::vector<PortsTrunkAllowedJsonObject> &conf);
  virtual void replaceAllowed(const uint16_t &vlanid,
                              const PortsTrunkAllowedJsonObject &conf);
  virtual void delAllowed(const uint16_t &vlanid) = 0;
  virtual void delAllowedList();

  /// <summary>
  /// Enable/Disable the native vlan feature in this trunk port
  /// </summary>
  virtual bool getNativeVlanEnabled() = 0;
  virtual void setNativeVlanEnabled(const bool &value) = 0;

  /// <summary>
  /// VLAN that is not tagged in this trunk port
  /// </summary>
  virtual uint16_t getNativeVlan() = 0;
  virtual void setNativeVlan(const uint16_t &value) = 0;

  std::shared_ptr<spdlog::logger> logger();

 protected:
  Ports &parent_;
};
