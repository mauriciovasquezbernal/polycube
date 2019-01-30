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
#include "server/include/Resources/Endpoint/ListResource.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "rest_server.h"
#include "server/include/Resources/Body/JsonNodeField.h"
#include "server/include/Resources/Body/ListKey.h"
#include "server/include/Resources/Endpoint/PathParamField.h"
#include "server/include/Resources/Endpoint/Service.h"
#include "server/include/Server/ResponseGenerator.h"

namespace polycube::polycubed::Rest::Resources::Endpoint {
ListResource::ListResource(const std::string &name,
                           const std::string &description,
                           const std::string &cli_example,
                           const Body::ParentResource *parent,
                           const PolycubedCore *core, const std::string &rest_endpoint,
                           const std::string &rest_endpoint_multiple,
                           std::vector<Body::ListKey> &&keys,
                           const std::vector<Body::JsonNodeField> &node_fields,
                           bool configuration, bool init_only_config)
    : Body::ParentResource(name, description, cli_example, parent, core,
                           node_fields, configuration, init_only_config, false),
      ParentResource(name, description, cli_example, rest_endpoint,
                     parent, core, node_fields, configuration, init_only_config,
                     false, false),
      Body::ListResource(name, description, cli_example, parent, core,
                         std::move(keys), node_fields, configuration,
                         init_only_config),
      key_params_{},
      multiple_endpoint_(rest_endpoint_multiple) {
  using Pistache::Rest::Routes::bind;
  for (const auto &key : keys_) {
    key_params_.emplace_back(key.Name(), key.Validators());
  }
  auto router = RestServer::Router();
  router->get(multiple_endpoint_, bind(&ListResource::get_multiple, this));
  if (configuration_ && !init_only_config) {
    router->post(multiple_endpoint_, bind(&ListResource::post_multiple, this));
    router->put(multiple_endpoint_, bind(&ListResource::put_multiple, this));
    router->patch(multiple_endpoint_,
                  bind(&ListResource::patch_multiple, this));
    router->del(multiple_endpoint_, bind(&ListResource::del_multiple, this));
  }
}

ListResource::~ListResource() {
  using Pistache::Http::Method;
  auto router = RestServer::Router();
  router->removeRoute(Method::Get, multiple_endpoint_);
  if (configuration_ && !init_only_config_) {
    router->removeRoute(Method::Post, multiple_endpoint_);
    router->removeRoute(Method::Put, multiple_endpoint_);
    router->removeRoute(Method::Patch, multiple_endpoint_);
    router->removeRoute(Method::Delete, multiple_endpoint_);
  }
}

std::vector<Response> ListResource::RequestValidate(
    const Pistache::Rest::Request &request,
    const std::string &caller_name) const {
  auto errors = ParentResource::RequestValidate(request, caller_name);
  for (const auto &key_param : key_params_) {
    auto error = key_param.Validate(request);
    if (error != ErrorTag::kOk) {
      errors.push_back({error, ::strdup(key_param.Name().data())});
    }
  }
  return errors;
}

void ListResource::Keys(const Pistache::Rest::Request &request,
                        ListKeyValues &parsed) const {
  for (const auto &k : keys_) {
    parsed.push_back(
        {k.Name(), k.Type(), request.param(':' + k.Name()).as<std::string>()});
  }
  dynamic_cast<const ParentResource *const>(parent_)->Keys(request, parsed);
}

void ListResource::CreateReplaceUpdateWhole(
    const Pistache::Rest::Request &request, ResponseWriter response,
    bool update, bool initialization) {
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
    jbody = nlohmann::json::parse("[]");
  } else {
    jbody = nlohmann::json::parse(request.body());
  }

  if (jbody.type() != nlohmann::detail::value_t::array) {
    Server::ResponseGenerator::Generate(
        std::vector<Response>{{ErrorTag::kInvalidValue, nullptr}},
        std::move(response));
    return;
  }

  const auto cube_name = Service::Cube(request);
  ListKeyValues keys{};
  dynamic_cast<const ParentResource *const>(parent_)->Keys(request, keys);
  for (auto &elem : jbody) {
    SetDefaultIfMissing(elem, initialization);
    auto body = BodyValidate(cube_name, keys, elem, initialization);
    errors.reserve(errors.size() + body.size());
    std::copy(std::begin(body), std::end(body), std::back_inserter(errors));
  }
  if (errors.empty()) {
    auto op = OperationType(update, initialization);
    auto resp = WriteWhole(cube_name, jbody, keys, op);
    if (resp.error_tag == ErrorTag::kOk) {
      errors.push_back({ErrorTag::kCreated, nullptr});
    } else {
      errors.push_back(resp);
    }
  }
  Server::ResponseGenerator::Generate(std::move(errors), std::move(response));
}

void ListResource::get_multiple(const Request &request,
                                ResponseWriter response) {
  std::vector<Response> errors;
  if (parent_ != nullptr) {
    auto rerrors =
        dynamic_cast<const ParentResource *const>(parent_)->RequestValidate(
            request, name_);
    errors.reserve(rerrors.size());
    std::copy(std::begin(rerrors), std::end(rerrors),
              std::back_inserter(errors));
  }
  if (errors.empty()) {
    const auto &cube_name = Service::Cube(request);
    ListKeyValues keys{};
    dynamic_cast<const ParentResource *const>(parent_)->Keys(request, keys);
    errors.push_back(ReadWhole(cube_name, keys));
  }
  Server::ResponseGenerator::Generate(std::move(errors), std::move(response));
}

void ListResource::post_multiple(const Request &request,
                                 ResponseWriter response) {
  CreateReplaceUpdateWhole(request, std::move(response), false, true);
}

void ListResource::put_multiple(const Request &request,
                                ResponseWriter response) {
  CreateReplaceUpdateWhole(request, std::move(response), true, true);
}

void ListResource::patch_multiple(const Request &request,
                                  ResponseWriter response) {
  CreateReplaceUpdateWhole(request, std::move(response), true, false);
}

void ListResource::del_multiple(const Request &request,
                                ResponseWriter response) {
  std::vector<Response> errors;
  if (parent_ != nullptr) {
    auto rerrors =
        dynamic_cast<const ParentResource *const>(parent_)->RequestValidate(
            request, name_);
    errors.reserve(rerrors.size());
    std::copy(std::begin(rerrors), std::end(rerrors),
              std::back_inserter(errors));
  }
  if (errors.empty()) {
    const auto &cube_name = Service::Cube(request);
    ListKeyValues keys{};
    dynamic_cast<const ParentResource *const>(parent_)->Keys(request, keys);
    errors.push_back(DeleteWhole(cube_name, keys));
  }
  Server::ResponseGenerator::Generate(std::move(errors), std::move(response));
}

void ListResource::options(const Request &request, ResponseWriter response) {
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
  } else if (help == "ADD") {
    type = ADD;
  } else if (help == "DEL") {
    type = DEL;
  } else if (help == "NONE") {
    type = NONE;
  } else {
    Server::ResponseGenerator::Generate({{kBadRequest, nullptr}},
                                        std::move(response));
    return;
  }
  ListKeyValues keys{};
  dynamic_cast<const ParentResource *const>(parent_)->Keys(request, keys);

  auto helpresp = Help(Service::Cube(request), type, keys);
  Server::ResponseGenerator::Generate({helpresp}, std::move(response));
}
}  // namespace polycube::polycubed::Rest::Resources::Endpoint
