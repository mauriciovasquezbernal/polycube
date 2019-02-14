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
#include "ConcreteFactory.h"

#include <memory>
#include <string>
#include <vector>

#include "../../Body/JsonNodeField.h"

#include "../../Endpoint/LeafResource.h"
#include "../../Endpoint/ListResource.h"
#include "../../Endpoint/ParentResource.h"
#include "../../Endpoint/Service.h"

//#include "EntryPoint.h"
#include "LeafResource.h"
//#include "ListResource.h"
//#include "ParentResource.h"
//#include "Service.h"

#include "polycube/services/service_metadata.h"

#include "polycubed_core.h"

namespace polycube::polycubed::Rest::Resources::Data::BaseModel {

ConcreteFactory::ConcreteFactory(const std::string &file_name,
                                 PolycubedCore *core)
    : AbstractFactory(core), core_(core) {
        std::cout << "ConcreteFactory::ConcreteFactory core : " << core_ << std::endl;
    }

const std::string ConcreteFactory::Yang() const {
  return "";
}

std::unique_ptr<Endpoint::CaseResource> ConcreteFactory::RestCase(
    const std::queue<std::string> &tree_names, const std::string &name,
    const std::string &description, const std::string &cli_example,
    const Body::ParentResource *parent) const {
  throw std::invalid_argument(
      "Yang case node not supported with shared object protocol.");
}

std::unique_ptr<Endpoint::ChoiceResource> ConcreteFactory::RestChoice(
    const std::queue<std::string> &tree_names, const std::string &name,
    const std::string &description, const std::string &cli_example,
    const Body::ParentResource *parent, bool mandatory,
    std::unique_ptr<const std::string> &&default_case) const {
  throw std::invalid_argument(
      "Yang choice node not supported with shared object protocol.");
}

std::unique_ptr<Endpoint::LeafResource> ConcreteFactory::RestLeaf(
    const std::queue<std::string> &tree_names, const std::string &name,
    const std::string &description, const std::string &cli_example,
    const std::string &rest_endpoint, const Body::ParentResource *parent,
    std::unique_ptr<Body::JsonValueField> &&value_field,
    const std::vector<Body::JsonNodeField> &node_fields, bool configuration,
    bool init_only_config, bool mandatory, Types::Scalar type,
    std::unique_ptr<const std::string> &&default_value) const {

//  if (!configuration || init_only_config) {
//    return std::make_unique<LeafResource>(
//        std::move(read_handler), name, description, cli_example,
//        rest_endpoint, parent, configuration, init_only_config,
//        core_, std::move(value_field), node_fields, mandatory, type,
//        std::move(default_value));
//  }
//  auto replace_handler =
//      LoadHandler<Response(const char *, const Key *, size_t, const char *)>(
//          GenerateHandlerName(tree_names, Operation::kUpdate));

  // TODO: what to check  here? we don't need
  auto tree_names_ = tree_names;
  tree_names_.pop();

  std::function<Response(const std::string &,const ListKeyValues &keys)> read_handler_;
  std::function<Response(const std::string &, const nlohmann::json &,
                         const ListKeyValues &, Endpoint::Operation)> replace_handler_;

  // TODO: I need to capture this variable inside the lambda functions,
  // capturing "this" for me is not working
  auto local_core = this->core_;

  if (tree_names_.size() == 1) {
    auto leaf = tree_names_.front();
    if (leaf == "uuid") {
      read_handler_ = [local_core]
        (const std::string &cube_name, const ListKeyValues &keys) -> Response {
        return local_core->base_model()->get_uuid(cube_name);
      };
    } else if (leaf == "loglevel") {
      read_handler_ = [local_core]
        (const std::string &cube_name, const ListKeyValues &keys) -> Response {
        return local_core->base_model()->get_loglevel(cube_name);
      };

      replace_handler_ = [local_core]
        (const std::string &cube_name, const nlohmann::json &json,
        const ListKeyValues &keys, Endpoint::Operation op) -> Response {
        return local_core->base_model()->set_loglevel(cube_name, json);
      };
    }
  }

  return std::make_unique<LeafResource>(
        std::move(read_handler_), std::move(replace_handler_),
        name, description, cli_example,
        rest_endpoint, parent, configuration, init_only_config,
        core_, std::move(value_field), node_fields, mandatory, type,
        std::move(default_value));
}

std::unique_ptr<Endpoint::LeafListResource> ConcreteFactory::RestLeafList(
    const std::queue<std::string> &tree_names, const std::string &name,
    const std::string &description, const std::string &cli_example,
    const std::string &rest_endpoint, const Body::ParentResource *parent,
    std::unique_ptr<Body::JsonValueField> &&value_field,
    const std::vector<Body::JsonNodeField> &node_fields, bool configuration,
    bool init_only_config, bool mandatory, Types::Scalar type,
    std::vector<std::string> &&default_value) const {
  throw std::invalid_argument(
      "Yang case leaf-list not supported with shared object protocol.");
}

std::unique_ptr<Endpoint::ListResource> ConcreteFactory::RestList(
    const std::queue<std::string> &tree_names, const std::string &name,
    const std::string &description, const std::string &cli_example,
    const std::string &rest_endpoint, const std::string &rest_endpoint_whole_list,
    const Body::ParentResource *parent, bool configuration,
    bool init_only_config, std::vector<Resources::Body::ListKey> &&keys,
    const std::vector<Body::JsonNodeField> &node_fields) const {
  throw std::invalid_argument(
      "Yang case rest-list not supported with shared object protocol.");
}

std::unique_ptr<Endpoint::ParentResource> ConcreteFactory::RestGeneric(
    const std::queue<std::string> &tree_names, const std::string &name,
    const std::string &description, const std::string &cli_example,
    const std::string &rest_endpoint, const Body::ParentResource *parent,
    const std::vector<Body::JsonNodeField> &node_fields, bool configuration,
    bool init_only_config, bool container_presence, bool rpc_action) const {
  throw std::invalid_argument(
      "Yang case rest-generic not supported with shared object protocol.");
}

std::unique_ptr<Endpoint::Service> ConcreteFactory::RestService(
    [[maybe_unused]] const std::queue<std::string> &tree_names,
    const std::string &name, const std::string &description,
    const std::string &cli_example, std::string base_endpoint,
    std::string version) const {
  throw std::invalid_argument(
      "Yang case rest-service not supported with shared object protocol.");
}
}  // namespace polycube::polycubed::Rest::Resources::Data::BaseModel
