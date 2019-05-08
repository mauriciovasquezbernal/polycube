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

#include <string>
#include <polycube/services/json.hpp>
#include <server/Resources/Body/ListKey.h>
#include <server/Resources/Endpoint/Resource.h>

namespace polycube::polycubed {

class cubes_dump {
private:

    // mutex on the access to cubesConfig
    static std::mutex cubesConfigMutex;
    // cubes configuration <name, configuration>
    static std::map<std::string, nlohmann::json> cubesConfig;
    //how many updates have been made while thread saving to file
    static std::atomic<int> toSave;

    cubes_dump();

    static void UpdateCubesConfigCreateReplace(const std::vector<std::string> &resItem,
                                               const nlohmann::json &body,
                                               const ListKeyValues &keys,
                                               polycube::polycubed::Rest::Resources::Endpoint::ResourceType resType);

    static void UpdateCubesConfigUpdate(const std::vector<std::string> &resItem,
                                        const nlohmann::json body,
                                        const ListKeyValues &keys,
                                        polycube::polycubed::Rest::Resources::Endpoint::ResourceType resType);

    static void UpdateCubesConfigDelete(const std::vector<std::string> &resItem,
                                        const nlohmann::json &body,
                                        const ListKeyValues &keys,
                                        polycube::polycubed::Rest::Resources::Endpoint::ResourceType resType);

    static bool checkPresence(const std::vector<std::string> &resItem,
                              const int &resItemIndex,
                              const std::map<std::string, std::vector<polycube::polycubed::Rest::Resources::Body::ListKeyValue>> &keyValues,
                              const nlohmann::json &elem);

public:

    // wait until an update occurs
    static std::condition_variable waitForUpdate;
    // the saving thread ends if the daemon is shutting down (kill=true)
    static bool kill;

    static void UpdateCubesConfig(const std::string &resource,
                                  const nlohmann::json &body,
                                  const ListKeyValues &keys,
                                  polycube::polycubed::Rest::Resources::Endpoint::Operation opType,
                                  polycube::polycubed::Rest::Resources::Endpoint::ResourceType resType);

    static void SaveToFile(const std::string &path);
};
} // namespace polycube::polycubed