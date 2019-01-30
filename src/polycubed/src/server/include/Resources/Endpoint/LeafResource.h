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
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "ParentResource.h"
#include "server/include/Resources/Body/JsonValueField.h"
#include "server/include/Resources/Body/LeafResource.h"

namespace polycube::polycubed::Rest::Resources::Endpoint {
using Pistache::Http::ResponseWriter;
using Pistache::Rest::Request;
class LeafResource : public Resource, public virtual Body::LeafResource {
 public:
  LeafResource(const std::string &name, const std::string &description,
               const std::string &cli_example, const std::string &rest_endpoint,
               const Body::ParentResource *parent,
               const PolycubedCore *core,
               std::unique_ptr<Body::JsonValueField> &&value_field,
               const std::vector<Body::JsonNodeField> &node_fields,
               bool configuration, bool init_only_config, bool mandatory,
               Types::Scalar type,
               std::unique_ptr<const std::string> &&default_value);

  ~LeafResource() override;

  std::vector<Response> RequestValidate(
      const Request &request, const std::string &caller_name) const override;

  void Keys(const Pistache::Rest::Request &request,
            ListKeyValues &parsed) const final;

  Response Help(const std::string &cube_name, HelpType type,
                const ListKeyValues &keys) override;

 private:
  void get(const Request &request, ResponseWriter response);

  void CreateReplaceUpdate(const Pistache::Rest::Request &request,
                           Pistache::Http::ResponseWriter response, bool update,
                           bool initialization) final;

  void patch(const Request &request, ResponseWriter response);

  void options(const Request &request, ResponseWriter response);
};
}  // namespace polycube::polycubed::Rest::Resources::Endpoint
