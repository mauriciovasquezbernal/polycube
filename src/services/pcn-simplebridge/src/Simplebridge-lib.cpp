/**
* simplebridge API
* Simple L2 Bridge Service
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

#include "api/SimplebridgeApiImpl.h"
#define MANAGER_TYPE io::swagger::server::api::SimplebridgeApiImpl
#define SERVICE_DESCRIPTION "Simple L2 Bridge Service"
#define SERVICE_VERSION "1.0.0"
#define SERVICE_PYANG_GIT ""
#define SERVICE_SWAGGER_CODEGEN_GIT "c757d44b71d48df9e381fc8d35ea69bd12268127/c757d44"
#define SERVICE_REQUIRED_KERNEL_VERSION "4.11.0"

const std::string SERVICE_DATA_MODEL = R"POLYCUBE_DM(
module simplebridge {
  yang-version 1.1;
  namespace "http://polycube.network/simplebridge";
  prefix "simplebridge";

  import polycube-base { prefix "polycube-base"; }
  import polycube-standard-base { prefix "polycube-standard-base"; }

  import ietf-yang-types { prefix "yang"; }

  organization "Polycube open source project";
  description "YANG data model for the Polycube simple L2 bridge";

  polycube-base:service-description "Simple L2 Bridge Service";
  polycube-base:service-version "1.0.0";
  polycube-base:service-name "simplebridge";
  polycube-base:service-min-kernel-version "4.11.0";

  uses "polycube-standard-base:standard-base-yang-module" {
    augment ports {
      leaf mac {
        type yang:mac-address;
        description "MAC address of the port";
        config true;
        polycube-base:init-only-config;
        polycube-base:cli-example "C5:13:2D:36:27:9B";
      }
    }
  }

  container fdb {
    leaf aging-time {
      type uint32;
      units seconds;
      default 300;
      description "Aging time of the filtering database (in seconds)";
      polycube-base:cli-example "300";
    }

    list entry {
      key "address";
      description "Entry associated with the filtering database";
      leaf address {
        type yang:mac-address;
        mandatory true;
        description "Address of the filtering database entry";
        polycube-base:cli-example "C5:13:2D:36:27:9B";
      }

      leaf port {
        type string;
        mandatory true;
        description "Output port name";
        polycube-base:cli-example "port2";
      }

      leaf age {
        type uint32;
        units seconds;
        description "Age of the current filtering database entry";
        config false;
      }
    }

    action flush {
      description "Flushes the filtering database of the bridge";
      output {
        leaf flushed {
          type boolean;
          description "Returns true if the Filtering database has been flushed. False otherwise";
          mandatory true;
        }
      }
    }
  }
}

)POLYCUBE_DM";

extern "C" const char *data_model() {
  return SERVICE_DATA_MODEL.c_str();
}


#include <polycube/services/shared_library.h>
