/**
* simpleforwarder API
* Simple Forwarder Base Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

#include "api/SimpleforwarderApiImpl.h"
#define SERVICE_PYANG_GIT ""
#define SERVICE_SWAGGER_CODEGEN_GIT "c757d44b71d48df9e381fc8d35ea69bd12268127/c757d44"

const std::string SERVICE_DATA_MODEL = R"POLYCUBE_DM(
module simpleforwarder {
  yang-version 1.1;
  namespace "http://polycube.network/simpleforwarder";
  prefix "simpleforwarder";

  import polycube-base { prefix "polycube-base"; }
  import polycube-standard-base { prefix "polycube-standard-base"; }

  organization "Polycube open source project";
  description "YANG data model for the Polycube Simple Forwarder service";

  polycube-base:service-description "Simple Forwarder Base Service";
  polycube-base:service-version "2.0";
  polycube-base:service-name "simpleforwarder";
  polycube-base:service-min-kernel-version "4.14.0";

  uses "polycube-standard-base:standard-base-yang-module";

  list actions {
    key "inport";
    description "Entry of the Actions table";
    leaf inport {
      type string;
      mandatory true;
      description "Ingress port";
    }

    leaf action {
      type enumeration {
        enum DROP;
        enum SLOWPATH;
        enum FORWARD;
      }
      mandatory true;
      description "Action associated to the current table entry (i.e., DROP, SLOWPATH, or FORWARD; default: DROP)";
    }

    leaf outport {
      type string;
      description "Output port (used only when action is FORWARD)";
    }
  }
}


)POLYCUBE_DM";

extern "C" const char *data_model() {
  return SERVICE_DATA_MODEL.c_str();
}


#include <polycube/services/shared_library.h>
