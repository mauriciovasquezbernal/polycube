#include <string>

#include "polycube/services/response.h"
#include "polycube/services/json.hpp"

namespace polycube::polycubed {

class BaseModel {
 public:
  BaseModel() = default;
  ~BaseModel() = default;
  Response get_uuid(const std::string &cube_name) const;
  Response get_loglevel(const std::string &cube_name) const;
  Response set_loglevel(const std::string &cube_name,
                        const nlohmann::json &json);
};


} // namespace polycube::polycubed