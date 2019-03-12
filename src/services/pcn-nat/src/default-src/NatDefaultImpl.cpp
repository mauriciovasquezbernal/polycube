/**
* nat API
* nat API generated from nat.yang
*
* OpenAPI spec version: 1.0.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


// These methods have a default implementation. Your are free to keep it or add your own


#include "../Nat.h"



std::shared_ptr<Rule> Nat::getRule(){
  return Rule::getEntry(*this);
}

void Nat::addRule(const RuleJsonObject &value){
  Rule::create(*this, value);
}

void Nat::replaceRule(const RuleJsonObject &conf){
  Rule::removeEntry(*this);
  Rule::create(*this, conf);
}

void Nat::delRule(){
  Rule::removeEntry(*this);
}


std::shared_ptr<NattingTable> Nat::getNattingTable(const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto){
  return NattingTable::getEntry(*this, internalSrc, internalDst, internalSport, internalDport, proto);
}

std::vector<std::shared_ptr<NattingTable>> Nat::getNattingTableList(){
  return NattingTable::get(*this);
}

void Nat::addNattingTable(const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const NattingTableJsonObject &conf){
  NattingTable::create(*this, internalSrc, internalDst, internalSport, internalDport, proto, conf);
}

void Nat::addNattingTableList(const std::vector<NattingTableJsonObject> &conf){
  for(auto &i : conf){
    std::string internalSrc_ = i.getInternalSrc();
    std::string internalDst_ = i.getInternalDst();
    uint16_t internalSport_ = i.getInternalSport();
    uint16_t internalDport_ = i.getInternalDport();
    std::string proto_ = i.getProto();
    NattingTable::create(*this, internalSrc_, internalDst_, internalSport_, internalDport_, proto_,  i);
  }
}

void Nat::replaceNattingTable(const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto, const NattingTableJsonObject &conf){
  NattingTable::removeEntry(*this, internalSrc, internalDst, internalSport, internalDport, proto);
  std::string internalSrc_ = conf.getInternalSrc();
  std::string internalDst_ = conf.getInternalDst();
  uint16_t internalSport_ = conf.getInternalSport();
  uint16_t internalDport_ = conf.getInternalDport();
  std::string proto_ = conf.getProto();
  NattingTable::create(*this, internalSrc_, internalDst_, internalSport_, internalDport_, proto_, conf);

}

void Nat::delNattingTable(const std::string &internalSrc, const std::string &internalDst, const uint16_t &internalSport, const uint16_t &internalDport, const std::string &proto){
  NattingTable::removeEntry(*this, internalSrc, internalDst, internalSport, internalDport, proto);
}

void Nat::delNattingTableList(){
  NattingTable::remove(*this);
}



