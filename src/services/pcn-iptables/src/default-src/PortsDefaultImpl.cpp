/**
* iptables API
* iptables API generated from iptables.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


// These methods have a default implementation. Your are free to keep it or add your own


#include "../Ports.h"


nlohmann::fifo_map<std::string, std::string>  Ports::getKeys() {
  nlohmann::fifo_map<std::string, std::string>  r;

  r["name"] = getName();

  return r;
}




