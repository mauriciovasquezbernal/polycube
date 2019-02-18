/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "transparent_cube.h"
#include "controller.h"
#include "port.h"

#include <iostream>

namespace polycube {
namespace polycubed {

TransparentCube::TransparentCube(const std::string &name,
                                 const std::string &service_name,
                                 PatchPanel &patch_panel_ingress_,
                                 PatchPanel &patch_panel_egress_,
                                 LogLevel level, CubeType type,
                                 const service::attach_cb &attach)
    : BaseCube(name, service_name, "", patch_panel_ingress_,
               patch_panel_egress_, level, type),
      ingress_next_(0),
      egress_next_(0),
      attach_(attach),
      parent_(nullptr) {}

TransparentCube::~TransparentCube() {}

void TransparentCube::uninit() {
  if (parent_) {
    parent_->remove_cube(get_name());
  }
  BaseCube::uninit();
}

std::string TransparentCube::get_wrapper_code() {
  return BaseCube::get_wrapper_code();
}

void TransparentCube::set_next(uint16_t next, ProgramType type) {
  switch (type) {
  case ProgramType::INGRESS:
    if (ingress_next_ == next)
      return;
    ingress_next_ = next;
    break;

  case ProgramType::EGRESS:
    if (egress_next_ == next)
      return;
    egress_next_ = next;
  }

  reload_all();
}

void TransparentCube::set_parent(PortIface *parent) {
  parent_ = parent;
  if (parent) {
    attach_();
  }
}

PortIface *TransparentCube::get_parent() {
  return parent_;
}

void TransparentCube::send_packet_out(const std::vector<uint8_t> &packet,
                                      service::Sense sense, bool recirculate) {
  Controller &c = (get_type() == CubeType::TC) ? Controller::get_tc_instance()
                                               : Controller::get_xdp_instance();

  uint16_t port = 0;
  uint16_t module;

  Port *parent = dynamic_cast<Port *>(parent_);

  // calculate port
  switch (sense) {
  case service::Sense::INGRESS:
    // packet is comming in, port is ours
    port = parent->index();
    break;
  case service::Sense::EGRESS:
    // packet is going, set port to next one
    if (parent->peer_port_) {
      port = parent->peer_port_->get_port_id();
    }
    break;
  }

  // calculate module index
  switch (sense) {
  case service::Sense::INGRESS:
    if (recirculate) {
      module = ingress_index_;  // myself in ingress
    } else {
      module = ingress_next_;
    }
    break;
  case service::Sense::EGRESS:
    if (recirculate) {
      module = egress_index_;  // myself in egress
    } else {
      module = egress_next_;
    }
    break;
  }

  c.send_packet_to_cube(module, port, packet);
}

}  // namespace polycubed
}  // namespace polycube
