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

#include "polycube/services/base_cube.h"

namespace polycube {
namespace service {

BaseCube::BaseCube(const std::string &name,
                   const std::vector<std::string> &ingress_code,
                   const std::vector<std::string> &egress_code,
                   const CubeType type, LogLevel level)
    : type_(type),
      dismounted_(false),
      logger_(std::make_shared<spdlog::logger>(
          name, (spdlog::sinks_init_list){
                    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                        logfile_, 1048576 * 5, 3),
                    std::make_shared<spdlog::sinks::stdout_sink_mt>()})) {
  logger()->set_level(logLevelToSPDLog(level));
  // TODO: move to function
  /*
  handle_packet_in = [&](const PacketIn *md,
                         const std::vector<uint8_t> &packet) -> void {
    // This lock guarantees:
    // - port is not deleted while processing it
    // - service implementation is not deleted wile processing it
    std::lock_guard<std::mutex> guard(cube_mutex);
    if (dismounted_)
      return;

    auto &p = *ports_by_id_.at(md->port_id);
    PacketInMetadata md_;
    md_.reason = md->reason;
    md_.metadata[0] = md->metadata[0];
    md_.metadata[1] = md->metadata[1];
    md_.metadata[2] = md->metadata[2];
    packet_in(p, md_, packet);
  };
  */

  handle_log_msg = [&](const LogMsg *msg) -> void { datapath_log_msg(msg); };

  // TODO: where to create cube?, here or in derived classes?
  // cube_ = factory_->create_cube(name, ingress_code, egress_code,
  //                              handle_log_msg, type, handle_packet_in,
  //                              level);
}

BaseCube::~BaseCube() {
  // just in case
  dismount();

  // factory_->destroy_cube(get_name());
}

int BaseCube::get_table_fd(const std::string &table_name, int index,
                           ProgramType type) {
  return cube_->get_table_fd(table_name, index, type);
}

void BaseCube::reload(const std::string &code, int index, ProgramType type) {
  cube_->reload(code, index, type);
}

int BaseCube::add_program(const std::string &code, int index,
                          ProgramType type) {
  return cube_->add_program(code, index, type);
}

void BaseCube::del_program(int index, ProgramType type) {
  cube_->del_program(index, type);
}

RawTable BaseCube::get_raw_table(const std::string &table_name, int index,
                                 ProgramType type) {
  int fd = get_table_fd(table_name, index, type);
  RawTable t(&fd);
  return std::move(t);
}

void BaseCube::datapath_log_msg(const LogMsg *msg) {
  spdlog::level::level_enum level_ =
      logLevelToSPDLog((polycube::LogLevel)msg->level);
  std::string print;

  switch (msg->type) {
  case 0:
    print = utils::format_debug_string(msg->msg, msg->args);
    logger()->log(level_, print.c_str());
    break;

  case 1:
#ifdef HAVE_POLYCUBE_TOOLS
    logger()->log(level_, "packet received for debug:");
    utils::print_packet((const uint8_t *)msg->msg, msg->len);
#else
    logger()->warn(
        "Received packet for debugging. polycube-tools is not available");
#endif
    break;

  default:
    logger()->warn("Received bad message type in datapath_log_msg");
    return;
  }
}

void BaseCube::set_log_level(LogLevel level) {
  logger()->set_level(logLevelToSPDLog(level));
  return cube_->set_log_level(level);
}

LogLevel BaseCube::get_log_level() const {
  return cube_->get_log_level();
}

const Guid &BaseCube::get_uuid() const {
  return cube_->uuid();
}

const std::string BaseCube::get_name() const {
  return cube_->get_name();
}

CubeType BaseCube::get_type() const {
  return type_;
}

std::shared_ptr<spdlog::logger> BaseCube::logger() {
  return logger_;
}

void BaseCube::dismount() {
  std::lock_guard<std::mutex> guard(cube_mutex);

  if (dismounted_)
    return;

  dismounted_ = true;
  // invalidate handlers
  // handle_packet_in = nullptr;
  handle_log_msg = nullptr;

  // TODO: remove from controller and datapathlog?
}

}  // namespace service
}  // namespace polycube
