/**
* nat API
* NAT Service
*
* OpenAPI spec version: 1.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* NatApiImpl.h
*
*
*/

#pragma once


#include <memory>
#include <map>
#include <mutex>
#include "../Nat.h"

#include "NatJsonObject.h"
#include "NattingTableJsonObject.h"
#include "RuleJsonObject.h"
#include "RuleDnatJsonObject.h"
#include "RuleDnatAppendInputJsonObject.h"
#include "RuleDnatAppendOutputJsonObject.h"
#include "RuleDnatEntryJsonObject.h"
#include "RuleMasqueradeJsonObject.h"
#include "RuleMasqueradeDisableOutputJsonObject.h"
#include "RuleMasqueradeEnableOutputJsonObject.h"
#include "RulePortForwardingJsonObject.h"
#include "RulePortForwardingAppendInputJsonObject.h"
#include "RulePortForwardingAppendOutputJsonObject.h"
#include "RulePortForwardingEntryJsonObject.h"
#include "RuleSnatJsonObject.h"
#include "RuleSnatAppendInputJsonObject.h"
#include "RuleSnatAppendOutputJsonObject.h"
#include "RuleSnatEntryJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;

namespace NatApiImpl {
  void create_nat_by_id(const std::string &name, const NatJsonObject &value);
  void create_nat_natting_table_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const NattingTableJsonObject &value);
  void create_nat_natting_table_list_by_id(const std::string &name, const std::vector<NattingTableJsonObject> &value);
  void create_nat_rule_by_id(const std::string &name, const RuleJsonObject &value);
  RuleDnatAppendOutputJsonObject create_nat_rule_dnat_append_by_id(const std::string &name, const RuleDnatAppendInputJsonObject &value);
  void create_nat_rule_dnat_by_id(const std::string &name, const RuleDnatJsonObject &value);
  void create_nat_rule_dnat_entry_by_id(const std::string &name, const uint32_t &id, const RuleDnatEntryJsonObject &value);
  void create_nat_rule_dnat_entry_list_by_id(const std::string &name, const std::vector<RuleDnatEntryJsonObject> &value);
  void create_nat_rule_masquerade_by_id(const std::string &name, const RuleMasqueradeJsonObject &value);
  RuleMasqueradeDisableOutputJsonObject create_nat_rule_masquerade_disable_by_id(const std::string &name);
  RuleMasqueradeEnableOutputJsonObject create_nat_rule_masquerade_enable_by_id(const std::string &name);
  RulePortForwardingAppendOutputJsonObject create_nat_rule_port_forwarding_append_by_id(const std::string &name, const RulePortForwardingAppendInputJsonObject &value);
  void create_nat_rule_port_forwarding_by_id(const std::string &name, const RulePortForwardingJsonObject &value);
  void create_nat_rule_port_forwarding_entry_by_id(const std::string &name, const uint32_t &id, const RulePortForwardingEntryJsonObject &value);
  void create_nat_rule_port_forwarding_entry_list_by_id(const std::string &name, const std::vector<RulePortForwardingEntryJsonObject> &value);
  RuleSnatAppendOutputJsonObject create_nat_rule_snat_append_by_id(const std::string &name, const RuleSnatAppendInputJsonObject &value);
  void create_nat_rule_snat_by_id(const std::string &name, const RuleSnatJsonObject &value);
  void create_nat_rule_snat_entry_by_id(const std::string &name, const uint32_t &id, const RuleSnatEntryJsonObject &value);
  void create_nat_rule_snat_entry_list_by_id(const std::string &name, const std::vector<RuleSnatEntryJsonObject> &value);
  void delete_nat_by_id(const std::string &name);
  void delete_nat_natting_table_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto);
  void delete_nat_natting_table_list_by_id(const std::string &name);
  void delete_nat_rule_by_id(const std::string &name);
  void delete_nat_rule_dnat_by_id(const std::string &name);
  void delete_nat_rule_dnat_entry_by_id(const std::string &name, const uint32_t &id);
  void delete_nat_rule_dnat_entry_list_by_id(const std::string &name);
  void delete_nat_rule_masquerade_by_id(const std::string &name);
  void delete_nat_rule_port_forwarding_by_id(const std::string &name);
  void delete_nat_rule_port_forwarding_entry_by_id(const std::string &name, const uint32_t &id);
  void delete_nat_rule_port_forwarding_entry_list_by_id(const std::string &name);
  void delete_nat_rule_snat_by_id(const std::string &name);
  void delete_nat_rule_snat_entry_by_id(const std::string &name, const uint32_t &id);
  void delete_nat_rule_snat_entry_list_by_id(const std::string &name);
  NatJsonObject read_nat_by_id(const std::string &name);
  std::vector<NatJsonObject> read_nat_list_by_id();
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_nat_list_by_id_get_list();
  NatLoglevelEnum read_nat_loglevel_by_id(const std::string &name);
  NattingTableJsonObject read_nat_natting_table_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto);
  std::string read_nat_natting_table_external_ip_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto);
  uint16_t read_nat_natting_table_external_port_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto);
  std::vector<NattingTableJsonObject> read_nat_natting_table_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_nat_natting_table_list_by_id_get_list(const std::string &name);
  NattingTableOriginatingRuleEnum read_nat_natting_table_originating_rule_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto);
  RuleJsonObject read_nat_rule_by_id(const std::string &name);
  RuleDnatJsonObject read_nat_rule_dnat_by_id(const std::string &name);
  RuleDnatEntryJsonObject read_nat_rule_dnat_entry_by_id(const std::string &name, const uint32_t &id);
  std::string read_nat_rule_dnat_entry_external_ip_by_id(const std::string &name, const uint32_t &id);
  std::string read_nat_rule_dnat_entry_internal_ip_by_id(const std::string &name, const uint32_t &id);
  std::vector<RuleDnatEntryJsonObject> read_nat_rule_dnat_entry_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_nat_rule_dnat_entry_list_by_id_get_list(const std::string &name);
  RuleMasqueradeJsonObject read_nat_rule_masquerade_by_id(const std::string &name);
  bool read_nat_rule_masquerade_enabled_by_id(const std::string &name);
  RulePortForwardingJsonObject read_nat_rule_port_forwarding_by_id(const std::string &name);
  RulePortForwardingEntryJsonObject read_nat_rule_port_forwarding_entry_by_id(const std::string &name, const uint32_t &id);
  std::string read_nat_rule_port_forwarding_entry_external_ip_by_id(const std::string &name, const uint32_t &id);
  uint16_t read_nat_rule_port_forwarding_entry_external_port_by_id(const std::string &name, const uint32_t &id);
  std::string read_nat_rule_port_forwarding_entry_internal_ip_by_id(const std::string &name, const uint32_t &id);
  uint16_t read_nat_rule_port_forwarding_entry_internal_port_by_id(const std::string &name, const uint32_t &id);
  std::vector<RulePortForwardingEntryJsonObject> read_nat_rule_port_forwarding_entry_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_nat_rule_port_forwarding_entry_list_by_id_get_list(const std::string &name);
  std::string read_nat_rule_port_forwarding_entry_proto_by_id(const std::string &name, const uint32_t &id);
  RuleSnatJsonObject read_nat_rule_snat_by_id(const std::string &name);
  RuleSnatEntryJsonObject read_nat_rule_snat_entry_by_id(const std::string &name, const uint32_t &id);
  std::string read_nat_rule_snat_entry_external_ip_by_id(const std::string &name, const uint32_t &id);
  std::string read_nat_rule_snat_entry_internal_net_by_id(const std::string &name, const uint32_t &id);
  std::vector<RuleSnatEntryJsonObject> read_nat_rule_snat_entry_list_by_id(const std::string &name);
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_nat_rule_snat_entry_list_by_id_get_list(const std::string &name);
  CubeType read_nat_type_by_id(const std::string &name);
  std::string read_nat_uuid_by_id(const std::string &name);
  void replace_nat_by_id(const std::string &name, const NatJsonObject &value);
  void replace_nat_natting_table_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const NattingTableJsonObject &value);
  void replace_nat_natting_table_list_by_id(const std::string &name, const std::vector<NattingTableJsonObject> &value);
  void replace_nat_rule_by_id(const std::string &name, const RuleJsonObject &value);
  void replace_nat_rule_dnat_by_id(const std::string &name, const RuleDnatJsonObject &value);
  void replace_nat_rule_dnat_entry_by_id(const std::string &name, const uint32_t &id, const RuleDnatEntryJsonObject &value);
  void replace_nat_rule_dnat_entry_list_by_id(const std::string &name, const std::vector<RuleDnatEntryJsonObject> &value);
  void replace_nat_rule_masquerade_by_id(const std::string &name, const RuleMasqueradeJsonObject &value);
  void replace_nat_rule_port_forwarding_by_id(const std::string &name, const RulePortForwardingJsonObject &value);
  void replace_nat_rule_port_forwarding_entry_by_id(const std::string &name, const uint32_t &id, const RulePortForwardingEntryJsonObject &value);
  void replace_nat_rule_port_forwarding_entry_list_by_id(const std::string &name, const std::vector<RulePortForwardingEntryJsonObject> &value);
  void replace_nat_rule_snat_by_id(const std::string &name, const RuleSnatJsonObject &value);
  void replace_nat_rule_snat_entry_by_id(const std::string &name, const uint32_t &id, const RuleSnatEntryJsonObject &value);
  void replace_nat_rule_snat_entry_list_by_id(const std::string &name, const std::vector<RuleSnatEntryJsonObject> &value);
  void update_nat_by_id(const std::string &name, const NatJsonObject &value);
  void update_nat_list_by_id(const std::vector<NatJsonObject> &value);
  void update_nat_loglevel_by_id(const std::string &name, const NatLoglevelEnum &value);
  void update_nat_natting_table_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const NattingTableJsonObject &value);
  void update_nat_natting_table_external_ip_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const std::string &value);
  void update_nat_natting_table_external_port_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const uint16_t &value);
  void update_nat_natting_table_list_by_id(const std::string &name, const std::vector<NattingTableJsonObject> &value);
  void update_nat_natting_table_originating_rule_by_id(const std::string &name, const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const NattingTableOriginatingRuleEnum &value);
  void update_nat_rule_by_id(const std::string &name, const RuleJsonObject &value);
  void update_nat_rule_dnat_by_id(const std::string &name, const RuleDnatJsonObject &value);
  void update_nat_rule_dnat_entry_by_id(const std::string &name, const uint32_t &id, const RuleDnatEntryJsonObject &value);
  void update_nat_rule_dnat_entry_external_ip_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_dnat_entry_internal_ip_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_dnat_entry_list_by_id(const std::string &name, const std::vector<RuleDnatEntryJsonObject> &value);
  void update_nat_rule_masquerade_by_id(const std::string &name, const RuleMasqueradeJsonObject &value);
  void update_nat_rule_masquerade_enabled_by_id(const std::string &name, const bool &value);
  void update_nat_rule_port_forwarding_by_id(const std::string &name, const RulePortForwardingJsonObject &value);
  void update_nat_rule_port_forwarding_entry_by_id(const std::string &name, const uint32_t &id, const RulePortForwardingEntryJsonObject &value);
  void update_nat_rule_port_forwarding_entry_external_ip_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_port_forwarding_entry_external_port_by_id(const std::string &name, const uint32_t &id, const uint16_t &value);
  void update_nat_rule_port_forwarding_entry_internal_ip_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_port_forwarding_entry_internal_port_by_id(const std::string &name, const uint32_t &id, const uint16_t &value);
  void update_nat_rule_port_forwarding_entry_list_by_id(const std::string &name, const std::vector<RulePortForwardingEntryJsonObject> &value);
  void update_nat_rule_port_forwarding_entry_proto_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_snat_by_id(const std::string &name, const RuleSnatJsonObject &value);
  void update_nat_rule_snat_entry_by_id(const std::string &name, const uint32_t &id, const RuleSnatEntryJsonObject &value);
  void update_nat_rule_snat_entry_external_ip_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_snat_entry_internal_net_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_nat_rule_snat_entry_list_by_id(const std::string &name, const std::vector<RuleSnatEntryJsonObject> &value);
}
}
}
}
}

