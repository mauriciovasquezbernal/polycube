#include "base_model.h"

#include "service_controller.h"

namespace polycube::polycubed {

Response BaseModel::get_uuid(const std::string &cube_name) const {
  auto cube = ServiceController::get_cube(cube_name);
  if (cube == nullptr) {
    return Response {
      .error_tag = kNoContent,
      .message = strdup("Cube does not exist"),
    };
  }

  auto uuid = "\"" + cube->uuid().str() + "\"";

  return Response {
    .error_tag = kOk,
    .message = strdup(uuid.data()),
  };
}

Response BaseModel::get_loglevel(const std::string &cube_name) const {
  auto cube = ServiceController::get_cube(cube_name);
  if (cube == nullptr) {
    return Response {
      .error_tag = kNoContent,
      .message = strdup("Cube does not exist"),
    };
  }

  auto loglevel = "\"" + logLevelString(cube->get_log_level()) + "\"";
  return Response {
    .error_tag = kOk,
    .message = strdup(loglevel.data()),
  };
}

Response BaseModel::set_loglevel(const std::string &cube_name,
                                 const nlohmann::json &json) {
  auto cube = ServiceController::get_cube(cube_name);
  if (cube == nullptr) {
    return Response {
      .error_tag = kNoContent,
      .message = strdup("Cube does not exist"),
    };
  }

  auto loglevel_str = json.get<std::string>();
  std::transform(loglevel_str.begin(), loglevel_str.end(),
                 loglevel_str.begin(), ::toupper);
  auto loglevel = stringLogLevel(loglevel_str);
  cube->set_log_level(loglevel);

  return Response {
    .error_tag = kOk,
    .message = strdup(""),
  };
}

} // namespace polycube::polycubed