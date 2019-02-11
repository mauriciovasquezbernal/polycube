/*
 * Copyright 2017 The Polycube Authors
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

#include "cube_factory_impl.h"
#include "cube_tc.h"
#include "cube_xdp.h"
#include "service_controller.h"

#include <iostream>
#include <sstream>
#include <string>

namespace polycube {
namespace polycubed {

CubeFactoryImpl::CubeFactoryImpl(const std::string &service_name)
    : service_name_(service_name),
      controller_tc_(Controller::get_tc_instance()),
      controller_xdp_(Controller::get_xdp_instance()),
      datapathlog_(DatapathLog::get_instance()) {}

std::shared_ptr<CubeIface> CubeFactoryImpl::create_cube(const std::string &name,
                                        const std::vector<std::string> &ingress_code,
                                        const std::vector<std::string> &egress_code,
                                        const log_msg_cb &log_msg,
                                        const CubeType type,
                                        const packet_in_cb &cb,
                                        LogLevel level) {
  std::shared_ptr<CubeIface> cube;
  typename std::unordered_map<std::string, std::shared_ptr<CubeIface>>::iterator
      iter;
  bool inserted;

  switch (type) {
  case CubeType::XDP_SKB:
  case CubeType::XDP_DRV:
    cube = std::make_shared<CubeXDP>(name, service_name_, ingress_code,
                                     egress_code, level, type);
    break;
  case CubeType::TC:
    cube = std::make_shared<CubeTC>(name, service_name_, ingress_code,
                                    egress_code, level);
    break;
  default:
    throw std::runtime_error("invalid cube type");
  }

  std::tie(iter, inserted) = cubes_.emplace(name, std::move(cube));
  if (!inserted) {
    return nullptr;
  }

  auto &m = iter->second;
  ServiceController::register_cube(m, service_name_);
  datapathlog_.register_cb(m->get_id(), log_msg);
  if (cb) {
    switch (type) {
    case CubeType::XDP_SKB:
    case CubeType::XDP_DRV:
      controller_xdp_.register_cb(m->get_id(), cb);
      break;
    case CubeType::TC:
      controller_tc_.register_cb(m->get_id(), cb);
      break;
    }
  }
  return m;
}

void CubeFactoryImpl::destroy_cube(const std::string &name) {
  auto cube = cubes_.find(name);
  if (cube == cubes_.end()) {
    return;
  }

  uint32_t id = cube->second->get_id();

  switch (cube->second->get_type()) {
  case CubeType::XDP_SKB:
  case CubeType::XDP_DRV:
    controller_xdp_.unregister_cb(id);
    break;
  case CubeType::TC:
    controller_tc_.unregister_cb(id);
    break;
  }

  datapathlog_.unregister_cb(id);
  ServiceController::unregister_cube(name);
  cubes_.erase(name);
}

std::vector<std::shared_ptr<CubeIface>> CubeFactoryImpl::get_cubes() {
  std::vector<std::shared_ptr<CubeIface>> r;
  r.reserve(cubes_.size());

  for (auto &&i : cubes_) {
    r.push_back(i.second);
  }

  return r;
}

}  // namespace polycubed
}  // namespace polycube
