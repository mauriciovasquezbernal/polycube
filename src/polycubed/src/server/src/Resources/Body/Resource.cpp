/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "server/include/Resources/Body/Resource.h"

#include "server/include/Resources/Body/JsonNodeField.h"
#include "server/include/Resources/Body/ListResource.h"
#include "server/include/Resources/Body/ParentResource.h"
#include "server/include/Resources/Body/Service.h"

#include "polycubed_core.h"

namespace polycube::polycubed::Rest::Resources::Body {
Resource::Resource(const std::string &name, const std::string &description,
                   const std::string &cli_example, const ParentResource *const parent,
                   const PolycubedCore *core, bool configuration, bool init_only_config,
                   const std::vector<JsonNodeField> &node_fields)
    : name_{name},
      parent_(parent),
      description_{description},
      cli_example_{cli_example},
      configuration_(configuration),
      init_only_config_(init_only_config),
      core_(core),
      node_fields_{node_fields} {}

const std::shared_ptr<Service> Resource::GetService(
    const std::string &service_name) const {
  return std::dynamic_pointer_cast<Service>(
      core_->get_service_controller(service_name)
          .get_management_interface()
          ->get_service());
}

const Response Resource::ReadValue(const std::string &cube_name,
                                   const ListKeyValues &keys) const {
  auto response = parent_->ReadValue(cube_name, keys);
  auto body = nlohmann::json::parse(response.message)[name_].dump();
  ::free(response.message);
  return {response.error_tag, ::strdup(body.data())};
}
}  // namespace polycube::polycubed::Rest::Resources::Body
