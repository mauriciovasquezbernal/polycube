/**
* helloworld API
* Helloworld Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* HelloworldApi.h
*
*/

#pragma once

#define POLYCUBE_SERVICE_NAME "helloworld"


#include "polycube/services/response.h"
#include "polycube/services/shared_lib_elements.h"

#include "HelloworldJsonObject.h"
#include "PortsJsonObject.h"
#include <vector>


#ifdef __cplusplus
extern "C" {
#endif

Response create_helloworld_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_helloworld_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_helloworld_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response delete_helloworld_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_helloworld_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_helloworld_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_action_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_loglevel_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_ports_peer_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_ports_status_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_ports_uuid_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_type_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_helloworld_uuid_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response replace_helloworld_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_helloworld_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_helloworld_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_action_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_loglevel_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_helloworld_ports_peer_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);

Response helloworld_by_id_help(HelpType type, const char *name, const Key *keys, size_t num_keys);
Response helloworld_list_by_id_help(HelpType type, const char *name, const Key *keys, size_t num_keys);
Response helloworld_ports_by_id_help(HelpType type, const char *name, const Key *keys, size_t num_keys);
Response helloworld_ports_list_by_id_help(HelpType type, const char *name, const Key *keys, size_t num_keys);



#ifdef __cplusplus
}
#endif

