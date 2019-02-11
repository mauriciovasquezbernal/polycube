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

#include "polycubed_core.h"

#include <regex>

namespace polycube {
namespace polycubed {

PolycubedCore::PolycubedCore() : logger(spdlog::get("polycubed")) {}

void PolycubedCore::set_polycubeendpoint(std::string &polycube) {
  polycubeendpoint_ = polycube;
}

std::string PolycubedCore::get_polycubeendpoint() {
  return polycubeendpoint_;
}

void PolycubedCore::add_servicectrl(const std::string &name,
                                    const std::string &path) {
  // logger->debug("PolycubedCore: post servicectrl {0}", name);
  if (servicectrls_map_.count(name) != 0) {
    throw std::runtime_error("Service Controller already exists");
  }

  std::unordered_map<std::string, ServiceController>::iterator iter;
  bool inserted;
  std::tie(iter, inserted) = servicectrls_map_.emplace(
      std::piecewise_construct, std::forward_as_tuple(name),
      std::forward_as_tuple(name, path));
  if (!inserted) {
    throw std::runtime_error("error creating service controller");
  }

  ServiceController &s = iter->second;
  try {
    s.connect(get_polycubeendpoint());
    logger->info("service {0} loaded using {1}", s.get_name(),
                 s.get_servicecontroller());
  } catch (const std::exception &e) {
    // logger->error("cannot load service: {0}", e.what());
    servicectrls_map_.erase(name);
    throw;
  }
}

std::string PolycubedCore::get_servicectrl(const std::string &name) {
  logger->debug("PolycubedCore: get service {0}", name);
  auto iter = servicectrls_map_.find(name);
  if (iter == servicectrls_map_.end()) {
    // logger->warn("no service present with name {0}", name);
    throw std::runtime_error("Service Controller does not exist");
  }

  ServiceController &s = iter->second;
  json j = json::array();
  j += s.to_json_datamodel();
  return j.dump(4);
}

std::list<std::string> PolycubedCore::get_servicectrls_names() {
  std::list<std::string> list;
  for (auto &it : servicectrls_map_) {
    list.push_back(it.first);
  }

  return list;
}

std::list<ServiceController const *> PolycubedCore::get_servicectrls_list()
    const {
  std::list<ServiceController const *> list;
  for (auto &it : servicectrls_map_) {
    list.push_back(&it.second);
  }

  return list;
}

std::string PolycubedCore::get_servicectrls() {
  logger->debug("PolycubedCore: get services");
  json j = json::array();
  for (auto &it : servicectrls_map_) {
    j += it.second.to_json();
  }
  return j.dump(4);
}

void PolycubedCore::delete_servicectrl(const std::string &name) {
  logger->debug("PolycubedCore: delete service {0}", name);
  if (servicectrls_map_.count(name) == 0) {
    logger->warn("no service present with name {0}", name);
    throw std::runtime_error("Service Controller does not exist");
  }

  // automatically destroy management grpc client instance and disconnect
  // TODO Check consistency of currently deployed cubes,
  // is necessary to undeploy them?
  servicectrls_map_.erase(name);
  logger->info("delete service {0}", name);
}

std::string PolycubedCore::get_cube(const std::string &name) {
  logger->debug("PolycubedCore: get cube {0}", name);
  auto cube = ServiceController::get_cube(name);
  if (cube == nullptr) {
    logger->warn("no cube present with name {0}", name);
    throw std::runtime_error("Cube does not exist");
  }

  return cube->toJson().dump(4);
}

std::string PolycubedCore::get_cubes() {
  logger->debug("PolycubedCore: get cubes");

  json j = json::object();
  for (auto &it : servicectrls_map_) {
    json j2 = json::array();
    for (auto &it2 : it.second.get_cubes()) {
      j2 += it2->toJson();
    }
    if (j2.size()) {
      j[it.first] = j2;
    }
  }
  return j.dump(4);
}

std::string PolycubedCore::get_netdev(const std::string &name) {
  logger->debug("PolycubedCore: get netdev {0}", name);
  json j = json::array();
  auto ifaces = Netlink::getInstance().get_available_ifaces();
  if (ifaces.count(name) != 0) {
    j += ifaces.at(name).toJson();
    return j.dump(4);
  }

  throw std::runtime_error("netdev " + name + "does not exist");
}

std::string PolycubedCore::get_netdevs() {
  logger->debug("PolycubedCore: get netdevs");
  json j = json::array();
  auto ifaces = Netlink::getInstance().get_available_ifaces();
  for (auto &it : ifaces) {
    j += it.second.toJson();
  }
  return j.dump(4);
}

std::string PolycubedCore::topology() {
  json j = json::array();
  auto cubes = ServiceController::get_all_cubes();

  for (auto &it : cubes) {
    j += it->toJson(true);
  }

  return j.dump(4);
}

std::string get_port_peer(const std::string &port) {
  std::smatch match;
  std::regex rule("(\\S+):(\\S+)");

  if (std::regex_match(port, match, rule)) {
    auto cube = ServiceController::get_cube(match[1]);
    if (cube == nullptr) {
      throw std::runtime_error("Cube does not exist");
    }

    auto port = cube->get_port(match[2]);
    return port->peer();
  }

  return std::string();
}

bool PolycubedCore::try_to_set_peer(const std::string &peer1,
                                    const std::string &peer2) {
  std::smatch match;
  std::regex rule("(\\S+):(\\S+)");

  if (std::regex_match(peer1, match, rule)) {
    auto cube = ServiceController::get_cube(match[1]);
    if (cube == nullptr) {
      throw std::runtime_error("Cube does not exist");
    }

    auto port = cube->get_port(match[2]);
    port->set_peer(peer2);
    return true;
  }

  return false;
}

void PolycubedCore::connect(const std::string &peer1,
                            const std::string &peer2) {
  int count = 0;
  std::string ret;

  ret = get_port_peer(peer1);
  if (!ret.empty()) {
    throw std::runtime_error(peer1 + " already has a peer " + ret);
  }

  ret = get_port_peer(peer2);
  if (!ret.empty()) {
    throw std::runtime_error(peer2 + " already has a peer " + ret);
  }

  if (try_to_set_peer(peer1, peer2)) {
    count++;
  }

  if (try_to_set_peer(peer2, peer1)) {
    count++;
  }

  if (count == 0) {
    throw std::runtime_error("Error setting peer");
  }
}

void PolycubedCore::disconnect(const std::string &peer1,
                               const std::string &peer2) {
  std::string ret1, ret2;
  ret1 = get_port_peer(peer1);
  ret2 = get_port_peer(peer2);

  if (ret1.empty() && ret2.empty()) {
    throw std::runtime_error(peer1 + " is not connected to " + peer2);
  }

  if (!ret1.empty() && ret1 != peer2) {
    throw std::runtime_error(peer1 + " is not connected to " + peer2);
  }

  if (!ret2.empty() && ret2 != peer1) {
    throw std::runtime_error(peer1 + " is not connected to " + peer2);
  }

  try_to_set_peer(peer1, "");
  try_to_set_peer(peer2, "");
}

}  // namespace polycubed
}  // namespace polycube
