#include <string>

#include "polycube/services/response.h"
#include "polycube/services/json.hpp"

namespace polycube::polycubed {

class BaseModel {
 public:
  BaseModel() = default;
  ~BaseModel() = default;
  // polycube-base module
  Response get_type(const std::string &cube_name) const;
  Response get_uuid(const std::string &cube_name) const;
  Response get_loglevel(const std::string &cube_name) const;
  Response set_loglevel(const std::string &cube_name,
                        const nlohmann::json &json);

  // polycube-standard-base module
  Response get_port_uuid(const std::string &cube_name,
                         const std::string &port_name) const;
  Response get_port_status(const std::string &cube_name,
                          const std::string &port_name) const;
  Response get_port_peer(const std::string &cube_name,
                         const std::string &port_name) const;
  Response set_port_peer(const std::string &cube_name,
                         const std::string &port_name,
                         const nlohmann::json &json);
};


} // namespace polycube::polycubed