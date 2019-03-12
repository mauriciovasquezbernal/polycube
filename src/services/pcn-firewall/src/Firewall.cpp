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

#include "Firewall.h"
#include "Firewall_dp.h"

Firewall::Firewall(const std::string name, const FirewallJsonObject &conf)
    : Cube(conf.getBase(), {generate_code()}, {}) {
  logger()->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [Firewall] [%n] [%l] %v");
  logger()->info("Creating Firewall instance");

  update(conf);

  /*Creating default INGRESS and EGRESS chains.*/
  ChainJsonObject chain;
  addChain(ChainNameEnum::INGRESS, chain);
  addChain(ChainNameEnum::EGRESS, chain);
  logger()->debug("Ingress and Egress chain added");

  /*Initialize programs*/
  programs.insert(
      std::pair<std::pair<uint8_t, ChainNameEnum>, Firewall::Program *>(
          std::make_pair(ModulesConstants::PARSER, ChainNameEnum::INVALID),
          new Firewall::Parser(0, *this)));
  programs.insert(
      std::pair<std::pair<uint8_t, ChainNameEnum>, Firewall::Program *>(
          std::make_pair(ModulesConstants::CONNTRACKLABEL,
                         ChainNameEnum::INVALID),
          new Firewall::ConntrackLabel(1, *this)));
  programs.insert(
      std::pair<std::pair<uint8_t, ChainNameEnum>, Firewall::Program *>(
          std::make_pair(ModulesConstants::CHAINFORWARDER,
                         ChainNameEnum::INVALID),
          new Firewall::ChainForwarder(2, *this)));

  /*
   * 3 modules in the beginning
   * NR_MODULES ingress chain
   * NR_MODULES egress chain
   * NR_MODULES second ingress chain
   * NR_MODULES second egress chain
   * Default Action
   * Conntrack Label
   */

  programs.insert(
      std::pair<std::pair<uint8_t, ChainNameEnum>, Firewall::Program *>(
          std::make_pair(ModulesConstants::DEFAULTACTION,
                         ChainNameEnum::INVALID),
          new Firewall::DefaultAction(3 + ModulesConstants::NR_MODULES * 4,
                                      *this)));

  programs.insert(
      std::pair<std::pair<uint8_t, ChainNameEnum>, Firewall::Program *>(
          std::make_pair(ModulesConstants::CONNTRACKTABLEUPDATE,
                         ChainNameEnum::INVALID),
          new Firewall::ConntrackTableUpdate(
              3 + ModulesConstants::NR_MODULES * 4 + 1, *this)));
}

Firewall::~Firewall() {
  logger()->info("[{0}] Destroying firewall...", get_name());
  chains_.clear();

  // Delete all eBPF programs
  for (auto it = programs.begin(); it != programs.end(); ++it) {
    delete it->second;
  }
}

void Firewall::update(const FirewallJsonObject &conf) {
  // This method updates all the object/parameter in Firewall object specified
  // in the conf JsonObject.
  Cube::set_conf(conf.getBase());

  if (conf.chainIsSet()) {
    for (auto &i : conf.getChain()) {
      auto name = i.getName();
      auto m = getChain(name);
      m->update(i);
    }
  }

  if (conf.ingressPortIsSet()) {
    setIngressPort(conf.getIngressPort());
  }

  if (conf.egressPortIsSet()) {
    setEgressPort(conf.getEgressPort());
  }

  if (conf.acceptEstablishedIsSet()) {
    setAcceptEstablished(conf.getAcceptEstablished());
  }

  if (conf.conntrackIsSet()) {
    setConntrack(conf.getConntrack());
  }

  if (conf.portsIsSet()) {
    for (auto &i : conf.getPorts()) {
      auto name = i.getName();
      auto m = getPorts(name);
      m->update(i);
    }
  }

  if (conf.interactiveIsSet()) {
    setInteractive(conf.getInteractive());
  }
}

FirewallJsonObject Firewall::toJsonObject() {
  FirewallJsonObject conf;
  conf.setBase(Cube::to_json());

  // Remove comments when you implement all sub-methods
  for (auto &i : getChainList()) {
    conf.addChain(i->toJsonObject());
  }

  conf.setIngressPort(getIngressPort());

  conf.setEgressPort(getEgressPort());

  conf.setConntrack(getConntrack());

  conf.setAcceptEstablished(getAcceptEstablished());

  for (auto &i : getPortsList()) {
    conf.addPorts(i->toJsonObject());
  }

  conf.setInteractive(getInteractive());

  return conf;
}

std::string Firewall::generate_code() {
  return firewall_code;
}

std::vector<std::string> Firewall::generate_code_vector() {
  throw std::runtime_error("Method not implemented");
}

void Firewall::packet_in(Ports &port, polycube::service::PacketInMetadata &md,
                         const std::vector<uint8_t> &packet) {
  logger()->info("Packet received from port {0}", port.name());
}

std::string Firewall::getIngressPort() {
  // This method retrieves the ingressPort value.
  return ingressPort;
}

void Firewall::setIngressPort(const std::string &value) {
  // This method sets the ingressPort value.
  auto port = getPorts(value);
  ingressPort = port->getName();
  reload_all();
}

std::string Firewall::getEgressPort() {
  // This method retrieves the egressPort value.
  return egressPort;
}

void Firewall::setEgressPort(const std::string &value) {
  // This method sets the egressPort value.
  auto port = getPorts(value);
//  if (!port->getPeer().empty() && port->getPeer() == ":host" && transparent) {
//    logger()->info(
//        "Switching to Host mode. The EGRESS chain will be disabled.");
//    transparent = false;
//  }
//  if (!port->getPeer().empty() && port->getPeer() == ":host" && !transparent) {
//    logger()->info(
//        "Switching to Transparent mode. The EGRESS chain will be enabled.");
//    transparent = true;
//  }

  egressPort = port->getName();
  reload_all();
}

bool Firewall::getInteractive() {
  return interactive_;
}

void Firewall::setInteractive(const bool &value) {
  interactive_ = value;
}

FirewallAcceptEstablishedEnum Firewall::getAcceptEstablished() {
  if (this->conntrackMode == ConntrackModes::AUTOMATIC) {
    return FirewallAcceptEstablishedEnum::ON;
  }
  return FirewallAcceptEstablishedEnum::OFF;
}

void Firewall::setAcceptEstablished(
    const FirewallAcceptEstablishedEnum &value) {
  if (conntrackMode == ConntrackModes::DISABLED) {
    throw new std::runtime_error("Please enable conntrack first.");
  }

  if (value == FirewallAcceptEstablishedEnum::ON &&
      conntrackMode != ConntrackModes::AUTOMATIC) {
    conntrackMode = ConntrackModes::AUTOMATIC;

    dynamic_cast<Firewall::ConntrackLabel *>(
        programs[std::make_pair(ModulesConstants::CONNTRACKLABEL,
                                ChainNameEnum::INVALID)])
        ->reload();
    return;
  }

  if (value == FirewallAcceptEstablishedEnum::OFF &&
      conntrackMode != ConntrackModes::MANUAL) {
    conntrackMode = ConntrackModes::MANUAL;

    dynamic_cast<Firewall::ConntrackLabel *>(
        programs[std::make_pair(ModulesConstants::CONNTRACKLABEL,
                                ChainNameEnum::INVALID)])
        ->reload();
    return;
  }
}

FirewallConntrackEnum Firewall::getConntrack() {
  if (this->conntrackMode == ConntrackModes::DISABLED) {
    return FirewallConntrackEnum::OFF;
  }
  return FirewallConntrackEnum::ON;
}

void Firewall::setConntrack(const FirewallConntrackEnum &value) {
  if (value == FirewallConntrackEnum::OFF &&
      this->conntrackMode != ConntrackModes::DISABLED) {
    this->conntrackMode = ConntrackModes::DISABLED;

    // The parser has to be reloaded to skip the conntrack
    programs[std::make_pair(ModulesConstants::CONNTRACKTABLEUPDATE,
                            ChainNameEnum::INVALID)]
        ->reload();
    programs[std::make_pair(ModulesConstants::PARSER, ChainNameEnum::INVALID)]
        ->reload();

    auto it = programs.find(std::make_pair(ModulesConstants::CONNTRACKLABEL,
                                           ChainNameEnum::INVALID));
    if (it != programs.end()) {
      programs.erase(it);
    }
    return;
  }

  if (value == FirewallConntrackEnum::ON &&
      this->conntrackMode == ConntrackModes::DISABLED) {
    this->conntrackMode = ConntrackModes::MANUAL;

    programs.insert(
        std::pair<std::pair<uint8_t, ChainNameEnum>, Firewall::Program *>(
            std::make_pair(ModulesConstants::CONNTRACKLABEL,
                           ChainNameEnum::INVALID),
            new Firewall::ConntrackLabel(1, *this)));

    // The parser has to be reloaded to skip the conntrack
    programs[std::make_pair(ModulesConstants::CONNTRACKTABLEUPDATE,
                            ChainNameEnum::INVALID)]
        ->reload();
    programs[std::make_pair(ModulesConstants::PARSER, ChainNameEnum::INVALID)]
        ->reload();
    return;
  }
}

int Firewall::getIngressPortIndex() {
  if (ingressPort.empty()) {
    // No port set.
    return 0;
  }
  return get_port(ingressPort)->index();
}
int Firewall::getEgressPortIndex() {
  if (egressPort.empty()) {
    // No port set.
    return 0;
  }
  return get_port(egressPort)->index();
}

void Firewall::reload_chain(ChainNameEnum chain) {
  for (auto it = programs.begin(); it != programs.end(); ++it) {
    if (it->first.second == chain) {
      it->second->reload();
    }
  }
}

void Firewall::reload_all() {
  for (auto it = programs.begin(); it != programs.end(); ++it) {
    it->second->reload();
  }
}

bool Firewall::isContrackActive() {
  return (conntrackMode == ConntrackModes::AUTOMATIC ||
          conntrackMode == ConntrackModes::MANUAL);
}
