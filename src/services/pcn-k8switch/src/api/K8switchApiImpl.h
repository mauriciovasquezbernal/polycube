/**
* k8switch API
* Kubernetes HyperSwitch Service
*
* OpenAPI spec version: 2.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* K8switchApiImpl.h
*
*
*/

#pragma once


#include <memory>
#include <map>
#include <mutex>
#include "../K8switch.h"

#include "FwdTableJsonObject.h"
#include "K8switchJsonObject.h"
#include "PortsJsonObject.h"
#include "ServiceJsonObject.h"
#include "ServiceBackendJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;

namespace K8switchApiImpl {
  void create_k8switch_by_id(const std::string &name, const K8switchJsonObject &value);
  void create_k8switch_fwd_table_by_id(const std::string &name, const std::string &address, const FwdTableJsonObject &value);
  void create_k8switch_fwd_table_list_by_id(const std::string &name, const std::vector<FwdTableJsonObject> &value);
  void create_k8switch_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void create_k8switch_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void create_k8switch_service_backend_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port, const ServiceBackendJsonObject &value);
  void create_k8switch_service_backend_list_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::vector<ServiceBackendJsonObject> &value);
  void create_k8switch_service_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const ServiceJsonObject &value);
  void create_k8switch_service_list_by_id(const std::string &name, const std::vector<ServiceJsonObject> &value);
  void delete_k8switch_by_id(const std::string &name);
  void delete_k8switch_fwd_table_by_id(const std::string &name, const std::string &address);
  void delete_k8switch_fwd_table_list_by_id(const std::string &name);
  void delete_k8switch_ports_by_id(const std::string &name, const std::string &portsName);
  void delete_k8switch_ports_list_by_id(const std::string &name);
  void delete_k8switch_service_backend_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port);
  void delete_k8switch_service_backend_list_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto);
  void delete_k8switch_service_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto);
  void delete_k8switch_service_list_by_id(const std::string &name);
  K8switchJsonObject read_k8switch_by_id(const std::string &name);
  std::string read_k8switch_client_subnet_by_id(const std::string &name);
  std::string read_k8switch_cluster_ip_subnet_by_id(const std::string &name);
  FwdTableJsonObject read_k8switch_fwd_table_by_id(const std::string &name, const std::string &address);
  std::vector<FwdTableJsonObject> read_k8switch_fwd_table_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_k8switch_fwd_table_list_by_id_get_list(const std::string &name);
  std::string read_k8switch_fwd_table_mac_by_id(const std::string &name, const std::string &address);
  std::string read_k8switch_fwd_table_port_by_id(const std::string &name, const std::string &address);
  std::vector<K8switchJsonObject> read_k8switch_list_by_id();
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_k8switch_list_by_id_get_list();
  K8switchLoglevelEnum read_k8switch_loglevel_by_id(const std::string &name);
  PortsJsonObject read_k8switch_ports_by_id(const std::string &name, const std::string &portsName);
  std::vector<PortsJsonObject> read_k8switch_ports_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_k8switch_ports_list_by_id_get_list(const std::string &name);
  std::string read_k8switch_ports_peer_by_id(const std::string &name, const std::string &portsName);
  PortsStatusEnum read_k8switch_ports_status_by_id(const std::string &name, const std::string &portsName);
  PortsTypeEnum read_k8switch_ports_type_by_id(const std::string &name, const std::string &portsName);
  std::string read_k8switch_ports_uuid_by_id(const std::string &name, const std::string &portsName);
  ServiceBackendJsonObject read_k8switch_service_backend_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port);
  std::vector<ServiceBackendJsonObject> read_k8switch_service_backend_list_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_k8switch_service_backend_list_by_id_get_list(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto);
  std::string read_k8switch_service_backend_name_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port);
  uint16_t read_k8switch_service_backend_weight_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port);
  ServiceJsonObject read_k8switch_service_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto);
  std::vector<ServiceJsonObject> read_k8switch_service_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_k8switch_service_list_by_id_get_list(const std::string &name);
  std::string read_k8switch_service_name_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto);
  CubeType read_k8switch_type_by_id(const std::string &name);
  std::string read_k8switch_uuid_by_id(const std::string &name);
  std::string read_k8switch_virtual_client_subnet_by_id(const std::string &name);
  void replace_k8switch_by_id(const std::string &name, const K8switchJsonObject &value);
  void replace_k8switch_fwd_table_by_id(const std::string &name, const std::string &address, const FwdTableJsonObject &value);
  void replace_k8switch_fwd_table_list_by_id(const std::string &name, const std::vector<FwdTableJsonObject> &value);
  void replace_k8switch_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void replace_k8switch_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void replace_k8switch_service_backend_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port, const ServiceBackendJsonObject &value);
  void replace_k8switch_service_backend_list_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::vector<ServiceBackendJsonObject> &value);
  void replace_k8switch_service_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const ServiceJsonObject &value);
  void replace_k8switch_service_list_by_id(const std::string &name, const std::vector<ServiceJsonObject> &value);
  void update_k8switch_by_id(const std::string &name, const K8switchJsonObject &value);
  void update_k8switch_client_subnet_by_id(const std::string &name, const std::string &value);
  void update_k8switch_cluster_ip_subnet_by_id(const std::string &name, const std::string &value);
  void update_k8switch_fwd_table_by_id(const std::string &name, const std::string &address, const FwdTableJsonObject &value);
  void update_k8switch_fwd_table_list_by_id(const std::string &name, const std::vector<FwdTableJsonObject> &value);
  void update_k8switch_fwd_table_mac_by_id(const std::string &name, const std::string &address, const std::string &value);
  void update_k8switch_fwd_table_port_by_id(const std::string &name, const std::string &address, const std::string &value);
  void update_k8switch_list_by_id(const std::vector<K8switchJsonObject> &value);
  void update_k8switch_loglevel_by_id(const std::string &name, const K8switchLoglevelEnum &value);
  void update_k8switch_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void update_k8switch_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void update_k8switch_ports_peer_by_id(const std::string &name, const std::string &portsName, const std::string &value);
  void update_k8switch_ports_type_by_id(const std::string &name, const std::string &portsName, const PortsTypeEnum &value);
  void update_k8switch_service_backend_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port, const ServiceBackendJsonObject &value);
  void update_k8switch_service_backend_list_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::vector<ServiceBackendJsonObject> &value);
  void update_k8switch_service_backend_name_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port, const std::string &value);
  void update_k8switch_service_backend_weight_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &ip, const uint16_t &port, const uint16_t &value);
  void update_k8switch_service_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const ServiceJsonObject &value);
  void update_k8switch_service_list_by_id(const std::string &name, const std::vector<ServiceJsonObject> &value);
  void update_k8switch_service_name_by_id(const std::string &name, const std::string &vip, const uint16_t &vport, const ServiceProtoEnum &proto, const std::string &value);
  void update_k8switch_virtual_client_subnet_by_id(const std::string &name, const std::string &value);
}
}
}
}
}

