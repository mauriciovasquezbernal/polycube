/**
* pbforwarder API
* Policy-Based Forwarder Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* JsonObjectBase.h
*
* This is the base class for all model classes
*/

#pragma once


#include "polycube/services/json.hpp"
#include "polycube/services/fifo_map.hpp"
#include <ctime>
#include <string>

namespace io {
namespace swagger {
namespace server {
namespace model {

class  JsonObjectBase
{
public:
  virtual ~JsonObjectBase() = default;

  virtual nlohmann::json toJson() const = 0;

  static bool iequals(const std::string &a, const std::string &b);
  static std::string toJson(const std::string& value);
  static std::string toJson(const std::time_t& value);
  static int32_t toJson(int32_t value);
  static int64_t toJson(int64_t value);
  static double toJson(double value);
  static bool toJson(bool value);
  static nlohmann::json toJson(const JsonObjectBase &content);

};

}
}
}
}
