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

#pragma once

#include <memory>
#include <mutex>
#include <vector>
#include <string>
#include <spdlog/spdlog.h>

#include "polycube/services/port_iface.h"

using polycube::service::PortIface;
using polycube::service::PortType;

#include "polycube/services/guid.h"
#include "polycube/services/json-3.5.hpp"
#include "management_interface.h"
#include "cube_factory_impl.h"
#include "cube_tc.h"
#include "cube_xdp.h"
#include "extiface_tc.h"
#include "extiface_xdp.h"
#include "port_host.h"
#include "port_tc.h"
#include "port_xdp.h"
#include "utils.h"

namespace polycube {
namespace polycubed {

using json = nlohmann::json;

using service::ManagementInterface;
using service::ServiceMetadata;

enum class ServiceControllerType {LIBRARY, DAEMON};

class ServiceController {
 public:
  ServiceController(const std::string &name, const std::string &path);
  ~ServiceController();

  json to_json() const;
  std::string to_json_string() const;
  json to_json_datamodel() const;
  std::string to_json_string_datamodel() const;

  std::string get_name() const;
  std::string get_description() const;
  std::string get_version() const;
  std::string get_pyang_git_repo_id() const;
  std::string get_swagger_codegen_git_repo_id() const;
  std::string get_servicecontroller() const;
  std::string get_datamodel() const;
  std::vector<std::shared_ptr<CubeIface>> get_cubes();

  // Instantiate the managementGrpc Object, using the endpoint url
  void connect(std::string PolycubeEndpoint);
  ServiceControllerType get_type() const;

  static std::shared_ptr<CubeIface> get_cube(const std::string &name);
  static std::vector<std::shared_ptr<CubeIface>> get_all_cubes();

  static void register_cube(std::shared_ptr<CubeIface> cube,
                            const std::string &service);
  static void unregister_cube(const std::string &name);

  static std::string get_cube_service(const std::string &name);

  static void set_port_peer(Port &p, const std::string &peer_name);

 private:
  std::shared_ptr<spdlog::logger> l;
  std::shared_ptr<ManagementInterface> management_interface_;
  std::string name_;
  std::string servicecontroller_;
  std::string datamodel_;
  ServiceMetadata service_md_;
  ServiceControllerType type_;  // daemon|library
  CubeFactoryImpl factory_;

  // returns true if peer is in the cube:port format
  static bool parse_peer_name(const std::string &peer, std::string &cube,
                              std::string &port);

  // these objects save all the common objects accross different services
  static std::unordered_map<std::string, std::shared_ptr<CubeIface>> cubes;
  static std::unordered_map<Guid, std::unique_ptr<Node>> ports_to_ifaces;
  static std::unordered_map<std::string, std::string> ports_to_ports;

  static std::unordered_map<std::string, std::string> cubes_x_service;

  static std::mutex service_ctrl_mutex_;
};

}  // namespace polycubed
}  // namespace polycube
