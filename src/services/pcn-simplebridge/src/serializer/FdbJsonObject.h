/**
* simplebridge API
* Simple L2 Bridge Service
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/netgroup-polito/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */

/*
* FdbJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"

#include "FdbEntryJsonObject.h"
#include <vector>

namespace io {
namespace swagger {
namespace server {
namespace model {


/// <summary>
///
/// </summary>
class  FdbJsonObject : public JsonObjectBase {
public:
  FdbJsonObject();
  FdbJsonObject(nlohmann::json& json);
  ~FdbJsonObject() final = default;

  /////////////////////////////////////////////
  /// JsonObjectBase overrides

  nlohmann::json toJson() const final;

  static nlohmann::json helpKeys();
  static nlohmann::json helpElements();
  static nlohmann::json helpWritableLeafs();
  static nlohmann::json helpComplexElements();
  static std::vector<std::string> helpActions();
  /////////////////////////////////////////////
  /// FdbJsonObject members

  /// <summary>
  /// Aging time of the filtering database (in seconds)
  /// </summary>
  uint32_t getAgingTime() const;
  void setAgingTime(uint32_t value);
  bool agingTimeIsSet() const;
  void unsetAgingTime();

  /// <summary>
  /// Entry associated with the filtering database
  /// </summary>
  const std::vector<FdbEntryJsonObject>& getEntry() const;
  void addFdbEntry(FdbEntryJsonObject value);
  bool entryIsSet() const;
  void unsetEntry();


private:
  uint32_t m_agingTime;
  bool m_agingTimeIsSet;
  std::vector<FdbEntryJsonObject> m_entry;
  bool m_entryIsSet;
};

}
}
}
}

