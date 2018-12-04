/**
* ddosmitigator API
* DDoS Mitigator Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* DdosmitigatorApi.h
*
*/

#pragma once

#define POLYCUBE_SERVICE_NAME "ddosmitigator"


#include <polycube/services/http_router.h>
#include <polycube/services/management_interface.h>
#include <vector>

#include "BlacklistDstJsonObject.h"
#include "BlacklistSrcJsonObject.h"
#include "DdosmitigatorJsonObject.h"
#include "StatsJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;
using namespace polycube::service;

class  DdosmitigatorApi : public ManagementInterface {
 public:
  DdosmitigatorApi();
  virtual ~DdosmitigatorApi() {};

  const std::string base = "/" + std::string(POLYCUBE_SERVICE_NAME) + "/";

 protected:
  void setup_routes();
  void control_handler(const HttpHandleRequest &request, HttpHandleResponse &response) override;

  void create_ddosmitigator_blacklist_dst_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void create_ddosmitigator_blacklist_dst_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void create_ddosmitigator_blacklist_src_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void create_ddosmitigator_blacklist_src_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void create_ddosmitigator_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void delete_ddosmitigator_blacklist_dst_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void delete_ddosmitigator_blacklist_dst_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void delete_ddosmitigator_blacklist_src_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void delete_ddosmitigator_blacklist_src_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void delete_ddosmitigator_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_dst_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_dst_drop_pkts_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_dst_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_src_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_src_drop_pkts_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_src_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_loglevel_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_stats_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_stats_pkts_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_stats_pps_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_type_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_uuid_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void replace_ddosmitigator_blacklist_dst_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void replace_ddosmitigator_blacklist_dst_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void replace_ddosmitigator_blacklist_src_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void replace_ddosmitigator_blacklist_src_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void replace_ddosmitigator_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_blacklist_dst_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_blacklist_dst_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_blacklist_src_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_blacklist_src_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_list_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void update_ddosmitigator_loglevel_by_id_handler(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);

  void read_ddosmitigator_blacklist_dst_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_dst_list_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_src_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_blacklist_src_list_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_list_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);
  void read_ddosmitigator_stats_by_id_help(const polycube::service::Rest::Request &request, polycube::service::HttpHandleResponse &response);


  polycube::service::Rest::Router router;

  /// <summary>
  /// Create blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Create operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  /// <param name="value">blacklist-dstbody object</param>
  virtual void create_ddosmitigator_blacklist_dst_by_id(const std::string &name, const std::string &ip, const BlacklistDstJsonObject &value) = 0;
  /// <summary>
  /// Create blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Create operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">blacklist-dstbody object</param>
  virtual void create_ddosmitigator_blacklist_dst_list_by_id(const std::string &name, const std::vector<BlacklistDstJsonObject> &value) = 0;
  /// <summary>
  /// Create blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Create operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  /// <param name="value">blacklist-srcbody object</param>
  virtual void create_ddosmitigator_blacklist_src_by_id(const std::string &name, const std::string &ip, const BlacklistSrcJsonObject &value) = 0;
  /// <summary>
  /// Create blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Create operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">blacklist-srcbody object</param>
  virtual void create_ddosmitigator_blacklist_src_list_by_id(const std::string &name, const std::vector<BlacklistSrcJsonObject> &value) = 0;
  /// <summary>
  /// Create ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Create operation of resource: ddosmitigator
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">ddosmitigatorbody object</param>
  virtual void create_ddosmitigator_by_id(const std::string &name, const DdosmitigatorJsonObject &value) = 0;
  /// <summary>
  /// Delete blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Delete operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  virtual void delete_ddosmitigator_blacklist_dst_by_id(const std::string &name, const std::string &ip) = 0;
  /// <summary>
  /// Delete blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Delete operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual void delete_ddosmitigator_blacklist_dst_list_by_id(const std::string &name) = 0;
  /// <summary>
  /// Delete blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Delete operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  virtual void delete_ddosmitigator_blacklist_src_by_id(const std::string &name, const std::string &ip) = 0;
  /// <summary>
  /// Delete blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Delete operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual void delete_ddosmitigator_blacklist_src_list_by_id(const std::string &name) = 0;
  /// <summary>
  /// Delete ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Delete operation of resource: ddosmitigator
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual void delete_ddosmitigator_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  virtual BlacklistDstJsonObject read_ddosmitigator_blacklist_dst_by_id(const std::string &name, const std::string &ip) = 0;
  /// <summary>
  /// Read drop-pkts by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: drop-pkts
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  virtual uint64_t read_ddosmitigator_blacklist_dst_drop_pkts_by_id(const std::string &name, const std::string &ip) = 0;
  /// <summary>
  /// Read blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual std::vector<BlacklistDstJsonObject> read_ddosmitigator_blacklist_dst_list_by_id(const std::string &name) = 0;
  virtual std::vector<nlohmann::fifo_map<std::string, std::string>> read_ddosmitigator_blacklist_dst_list_by_id_get_list(const std::string &name) = 0;
  /// <summary>
  /// Read blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  virtual BlacklistSrcJsonObject read_ddosmitigator_blacklist_src_by_id(const std::string &name, const std::string &ip) = 0;
  /// <summary>
  /// Read drop-pkts by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: drop-pkts
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  virtual uint64_t read_ddosmitigator_blacklist_src_drop_pkts_by_id(const std::string &name, const std::string &ip) = 0;
  /// <summary>
  /// Read blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual std::vector<BlacklistSrcJsonObject> read_ddosmitigator_blacklist_src_list_by_id(const std::string &name) = 0;
  virtual std::vector<nlohmann::fifo_map<std::string, std::string>> read_ddosmitigator_blacklist_src_list_by_id_get_list(const std::string &name) = 0;
  /// <summary>
  /// Read ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: ddosmitigator
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual DdosmitigatorJsonObject read_ddosmitigator_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: ddosmitigator
  /// </remarks>
  virtual std::vector<DdosmitigatorJsonObject> read_ddosmitigator_list_by_id() = 0;
  virtual std::vector<nlohmann::fifo_map<std::string, std::string>> read_ddosmitigator_list_by_id_get_list() = 0;
  /// <summary>
  /// Read loglevel by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: loglevel
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual DdosmitigatorLoglevelEnum read_ddosmitigator_loglevel_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read stats by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: stats
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual StatsJsonObject read_ddosmitigator_stats_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read pkts by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: pkts
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual uint64_t read_ddosmitigator_stats_pkts_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read pps by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: pps
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual uint64_t read_ddosmitigator_stats_pps_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read type by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: type
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual CubeType read_ddosmitigator_type_by_id(const std::string &name) = 0;
  /// <summary>
  /// Read uuid by ID
  /// </summary>
  /// <remarks>
  /// Read operation of resource: uuid
  /// </remarks>
  /// <param name="name">ID of name</param>
  virtual std::string read_ddosmitigator_uuid_by_id(const std::string &name) = 0;
  /// <summary>
  /// Replace blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Replace operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  /// <param name="value">blacklist-dstbody object</param>
  virtual void replace_ddosmitigator_blacklist_dst_by_id(const std::string &name, const std::string &ip, const BlacklistDstJsonObject &value) = 0;
  /// <summary>
  /// Replace blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Replace operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">blacklist-dstbody object</param>
  virtual void replace_ddosmitigator_blacklist_dst_list_by_id(const std::string &name, const std::vector<BlacklistDstJsonObject> &value) = 0;
  /// <summary>
  /// Replace blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Replace operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  /// <param name="value">blacklist-srcbody object</param>
  virtual void replace_ddosmitigator_blacklist_src_by_id(const std::string &name, const std::string &ip, const BlacklistSrcJsonObject &value) = 0;
  /// <summary>
  /// Replace blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Replace operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">blacklist-srcbody object</param>
  virtual void replace_ddosmitigator_blacklist_src_list_by_id(const std::string &name, const std::vector<BlacklistSrcJsonObject> &value) = 0;
  /// <summary>
  /// Replace ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Replace operation of resource: ddosmitigator
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">ddosmitigatorbody object</param>
  virtual void replace_ddosmitigator_by_id(const std::string &name, const DdosmitigatorJsonObject &value) = 0;
  /// <summary>
  /// Update blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  /// <param name="value">blacklist-dstbody object</param>
  virtual void update_ddosmitigator_blacklist_dst_by_id(const std::string &name, const std::string &ip, const BlacklistDstJsonObject &value) = 0;
  /// <summary>
  /// Update blacklist-dst by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: blacklist-dst
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">blacklist-dstbody object</param>
  virtual void update_ddosmitigator_blacklist_dst_list_by_id(const std::string &name, const std::vector<BlacklistDstJsonObject> &value) = 0;
  /// <summary>
  /// Update blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="ip">ID of ip</param>
  /// <param name="value">blacklist-srcbody object</param>
  virtual void update_ddosmitigator_blacklist_src_by_id(const std::string &name, const std::string &ip, const BlacklistSrcJsonObject &value) = 0;
  /// <summary>
  /// Update blacklist-src by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: blacklist-src
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">blacklist-srcbody object</param>
  virtual void update_ddosmitigator_blacklist_src_list_by_id(const std::string &name, const std::vector<BlacklistSrcJsonObject> &value) = 0;
  /// <summary>
  /// Update ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: ddosmitigator
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">ddosmitigatorbody object</param>
  virtual void update_ddosmitigator_by_id(const std::string &name, const DdosmitigatorJsonObject &value) = 0;
  /// <summary>
  /// Update ddosmitigator by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: ddosmitigator
  /// </remarks>
  /// <param name="value">ddosmitigatorbody object</param>
  virtual void update_ddosmitigator_list_by_id(const std::vector<DdosmitigatorJsonObject> &value) = 0;
  /// <summary>
  /// Update loglevel by ID
  /// </summary>
  /// <remarks>
  /// Update operation of resource: loglevel
  /// </remarks>
  /// <param name="name">ID of name</param>
  /// <param name="value">Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE)</param>
  virtual void update_ddosmitigator_loglevel_by_id(const std::string &name, const DdosmitigatorLoglevelEnum &value) = 0;
};

}
}
}
}

