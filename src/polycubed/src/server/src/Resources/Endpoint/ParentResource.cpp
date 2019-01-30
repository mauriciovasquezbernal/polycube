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
#include "server/include/Resources/Endpoint/ParentResource.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "rest_server.h"

#include "server/include/Resources/Body/JsonNodeField.h"
#include "server/include/Resources/Body/ListKey.h"
#include "server/include/Resources/Endpoint/Service.h"
#include "server/include/Server/ResponseGenerator.h"

namespace polycube::polycubed::Rest::Resources::Endpoint {
ParentResource::ParentResource(
    const std::string &name, const std::string &description,
    const std::string &cli_example, const std::string &rest_endpoint,
    const Body::ParentResource *parent, const PolycubedCore *core,
    const std::vector<Body::JsonNodeField> &node_fields, bool configuration,
    bool init_only_config, bool container_presence, bool rpc_action)
    : Body::ParentResource(name, description, cli_example, parent, core,
                           node_fields, configuration, init_only_config,
                           container_presence),
      Endpoint::Resource(rest_endpoint),
      has_endpoints_(true),
      rpc_action_(rpc_action) {
  using Pistache::Rest::Routes::bind;
  auto router = RestServer::Router();
  router->options(rest_endpoint_, bind(&ParentResource::options, this));
  if (rpc_action_) {
    router->post(rest_endpoint_, bind(&ParentResource::post, this));
  } else {
    router->get(rest_endpoint_, bind(&ParentResource::get, this));
    if (configuration_ && !init_only_config_) {
      router->post(rest_endpoint_, bind(&ParentResource::post, this));
      router->put(rest_endpoint_, bind(&ParentResource::put, this));
      router->patch(rest_endpoint_, bind(&ParentResource::patch, this));
      router->del(rest_endpoint_, bind(&ParentResource::del, this));
    }
  }
}

ParentResource::~ParentResource() {
  if (has_endpoints_) {
    using Pistache::Http::Method;
    auto router = RestServer::Router();
    router->removeRoute(Method::Options, rest_endpoint_);
    if (rpc_action_) {
      router->removeRoute(Method::Post, rest_endpoint_);
    } else {
      router->removeRoute(Method::Get, rest_endpoint_);
      if (configuration_ && !init_only_config_) {
        router->removeRoute(Method::Post, rest_endpoint_);
        router->removeRoute(Method::Put, rest_endpoint_);
        router->removeRoute(Method::Patch, rest_endpoint_);
        router->removeRoute(Method::Delete, rest_endpoint_);
      }
    }
  }
}

void ParentResource::CreateReplaceUpdate(
    const Pistache::Rest::Request &request,
    Pistache::Http::ResponseWriter response, bool update, bool initialization) {
  std::vector<Response> errors;
  if (parent_ != nullptr) {
    auto rerrors =
        dynamic_cast<const ParentResource *const>(parent_)->RequestValidate(
            request, name_);
    errors.reserve(rerrors.size());
    std::move(std::begin(rerrors), std::end(rerrors),
              std::back_inserter(errors));
  }

  nlohmann::json jbody;
  if (request.body().empty()) {
    jbody = nlohmann::json::parse("{}");
  } else {
    jbody = nlohmann::json::parse(request.body());
  }

  // Mandatory value is checked only during POST and PUT, both
  // considered as initialization operations.
  SetDefaultIfMissing(jbody, initialization);

  const auto &cube_name = Service::Cube(request);
  ListKeyValues keys{};
  Keys(request, keys);
  auto body_errors = BodyValidate(cube_name, keys, jbody, initialization);
  errors.reserve(errors.size() + body_errors.size());
  std::move(std::begin(body_errors), std::end(body_errors),
            std::back_inserter(errors));

  if (errors.empty()) {
    auto op = OperationType(update, initialization);
    auto resp = WriteValue(cube_name, jbody, keys, op);
    if (resp.error_tag == ErrorTag::kOk) {
      errors.push_back({ErrorTag::kCreated, nullptr});
    } else {
      errors.push_back(resp);
    }
  }
  Server::ResponseGenerator::Generate(std::move(errors), std::move(response));
}

std::vector<Response> ParentResource::RequestValidate(
    const Pistache::Rest::Request &request,
    [[maybe_unused]] const std::string &caller_name) const {
  std::vector<Response> errors;
  if (parent_ != nullptr) {
    auto rerrors =
        dynamic_cast<const ParentResource *const>(parent_)->RequestValidate(
            request, name_);
    errors.reserve(rerrors.size());
    std::move(std::begin(rerrors), std::end(rerrors),
              std::back_inserter(errors));
  }
  return errors;
}

void ParentResource::Keys(const Pistache::Rest::Request &request,
                          ListKeyValues &parsed) const {
  if (parent_ != nullptr) {
    // Do not call Keys on Service
    if (dynamic_cast<const Service *const>(parent_) == nullptr) {
      dynamic_cast<const ParentResource *const>(parent_)->Keys(request, parsed);
    }
  }
}

void ParentResource::get(const Request &request, ResponseWriter response) {
  std::vector<Response> errors;
  if (parent_ != nullptr) {
    auto rerrors =
        dynamic_cast<const ParentResource *const>(parent_)->RequestValidate(
            request, name_);
    errors.reserve(rerrors.size());
    std::move(std::begin(rerrors), std::end(rerrors),
              std::back_inserter(errors));
  }
  if (errors.empty()) {
    const auto &cube_name = Service::Cube(request);
    ListKeyValues keys{};
    if (parent_ != nullptr) {
      Keys(request, keys);
    }
    errors.push_back(ReadValue(cube_name, keys));
  }
  Server::ResponseGenerator::Generate(std::move(errors), std::move(response));
}

void ParentResource::post(const Request &request, ResponseWriter response) {
  CreateReplaceUpdate(request, std::move(response), false, true);
}

void ParentResource::put(const Request &request, ResponseWriter response) {
  CreateReplaceUpdate(request, std::move(response), true, true);
}

void ParentResource::patch(const Request &request, ResponseWriter response) {
  CreateReplaceUpdate(request, std::move(response), true, false);
}

void ParentResource::del(const Request &request, ResponseWriter response) {
  auto errors = RequestValidate(request, name_);
  if (!errors.empty()) {
    Server::ResponseGenerator::Generate(std::move(errors), std::move(response));
    return;
  }
  const auto &cube_name = Service::Cube(request);
  ListKeyValues keys{};
  Keys(request, keys);
  if (ReadValue(cube_name, keys).error_tag != ErrorTag::kOk) {
    Server::ResponseGenerator::Generate(
        std::vector<Response>{{ErrorTag::kDataMissing, nullptr}},
        std::move(response));
    return;
  }
  auto resp = DeleteValue(cube_name, keys);
  if (resp.error_tag == ErrorTag::kOk) {
    Server::ResponseGenerator::Generate(
        std::vector<Response>{{ErrorTag::kNoContent, nullptr}},
        std::move(response));
    errors.push_back({ErrorTag::kCreated, nullptr});
  } else {
    Server::ResponseGenerator::Generate(std::vector<Response>{resp},
                                        std::move(response));
  }
}

void ParentResource::options(const Request &request, ResponseWriter response) {
  const auto &query_param = request.query();
  if (!query_param.has("help")) {
    Server::ResponseGenerator::Generate({{kBadRequest, nullptr}},
                                        std::move(response));
    return;
  }

  auto help = query_param.get("help").get();
  if (help == "NO_HELP") {
    Server::ResponseGenerator::Generate({{kOk, nullptr}}, std::move(response));
  }

  HelpType type;
  if (help == "SHOW") {
    type = SHOW;
  } else if (help == "SET") {
    type = SET;
  } else if (help == "NONE") {
    type = NONE;
  } else {
    Server::ResponseGenerator::Generate({{kBadRequest, nullptr}},
                                        std::move(response));
    return;
  }
  ListKeyValues keys{};
  Keys(request, keys);

  Server::ResponseGenerator::Generate(
      {Help(Service::Cube(request), type, keys)}, std::move(response));
}

ParentResource::ParentResource(
    const std::string &name, const std::string &description,
    const std::string &cli_example, const Body::ParentResource *parent,
    const PolycubedCore *core,
    const std::vector<Body::JsonNodeField> &node_fields)
    : Body::ParentResource(name, description, cli_example, nullptr, nullptr,
                           node_fields, false, false, false),
      Endpoint::Resource(""),
      has_endpoints_(false),
      rpc_action_(false) {}
}  // namespace polycube::polycubed::Rest::Resources::Endpoint
