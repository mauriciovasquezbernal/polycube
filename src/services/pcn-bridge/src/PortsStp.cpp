/**
 * bridge API generated from bridge.yang
 *
 * NOTE: This file is auto generated by polycube-codegen
 * https://github.com/polycube-network/polycube-codegen
 */

// TODO: Modify these methods with your own implementation

#include "PortsStp.h"
#include "Bridge.h"

PortsStp::PortsStp(Ports &parent, const PortsStpJsonObject &conf)
    : PortsStpBase(parent) {}

PortsStp::~PortsStp() {}

uint16_t PortsStp::getVlan() {
  throw std::runtime_error("PortsStp::getVlan: Method not implemented");
}

PortsStpStateEnum PortsStp::getState() {
  throw std::runtime_error("PortsStp::getState: Method not implemented");
}

uint32_t PortsStp::getPathCost() {
  throw std::runtime_error("PortsStp::getPathCost: Method not implemented");
}

void PortsStp::setPathCost(const uint32_t &value) {
  throw std::runtime_error("PortsStp::setPathCost: Method not implemented");
}

uint8_t PortsStp::getPortPriority() {
  throw std::runtime_error("PortsStp::getPortPriority: Method not implemented");
}

void PortsStp::setPortPriority(const uint8_t &value) {
  throw std::runtime_error("PortsStp::setPortPriority: Method not implemented");
}
