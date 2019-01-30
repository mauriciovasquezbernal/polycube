/**
* router API
* Router Service
*
* OpenAPI spec version: 2.0
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/polycube-network/swagger-codegen.git
* branch polycube
*/


/* Do not edit this file manually */


#include "RouterApiImpl.h"

namespace io {
namespace swagger {
namespace server {
namespace api {

using namespace io::swagger::server::model;

namespace RouterApiImpl {
namespace {
std::unordered_map<std::string, std::shared_ptr<Router>> cubes;
std::mutex cubes_mutex;

std::shared_ptr<Router> get_cube(const std::string &name) {
  std::lock_guard<std::mutex> guard(cubes_mutex);
  auto iter = cubes.find(name);
  if (iter == cubes.end()) {
    throw std::runtime_error("Cube " + name + " does not exist");
  }

  return iter->second;
}

}

/*
* These functions include a default basic implementation.  The user could
* extend adapt this implementation to his needs.
*/
void create_router_by_id(const std::string &name, const RouterJsonObject &jsonObject) {
  {
    // check if name is valid before creating it
    std::lock_guard<std::mutex> guard(cubes_mutex);
    if (cubes.count(name) != 0) {
      throw std::runtime_error("There is already an Cube with name " + name);
    }
  }
  auto ptr = std::make_shared<Router>(name, jsonObject, jsonObject.getType());
  std::unordered_map<std::string, std::shared_ptr<Router>>::iterator iter;
  bool inserted;

  std::lock_guard<std::mutex> guard(cubes_mutex);
  std::tie(iter, inserted) = cubes.emplace(name, std::move(ptr));

  if (!inserted) {
    throw std::runtime_error("There is already an Cube with name " + name);
  }
}

void replace_router_by_id(const std::string &name, const RouterJsonObject &bridge){
  throw std::runtime_error("Method not supported!");
}

void delete_router_by_id(const std::string &name) {
  std::lock_guard<std::mutex> guard(cubes_mutex);
  if (cubes.count(name) == 0) {
    throw std::runtime_error("Cube " + name + " does not exist");
  }
  cubes.erase(name);
}

std::string read_router_uuid_by_id(const std::string &name) {
  auto m = get_cube(name);
  return m->getUuid();
}

std::vector<RouterJsonObject> read_router_list_by_id() {
  std::vector<RouterJsonObject> jsonObject_vect;
  for(auto &i : cubes) {
    auto m = get_cube(i.first);
    jsonObject_vect.push_back(m->toJsonObject());
  }
  return jsonObject_vect;
}

std::vector<nlohmann::fifo_map<std::string, std::string>> read_router_list_by_id_get_list() {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  for (auto &x : cubes) {
    nlohmann::fifo_map<std::string, std::string> m;
    m["name"] = x.first;
    r.push_back(std::move(m));
  }
  return r;
}

/*
* Ports list related functions
*/
void create_router_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &ports) {
  auto m = get_cube(name);
  m->addPortsList(ports);
}

std::vector<PortsJsonObject> read_router_ports_list_by_id(const std::string &name) {
  std::vector<PortsJsonObject> vect;
  auto m = get_cube(name);
  for (auto &i : m->getPortsList()) {
    vect.push_back(i->toJsonObject());
  }
  return vect;
}

void replace_router_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &ports) {
  throw std::runtime_error("Method not supported");
}

void delete_router_ports_list_by_id(const std::string &name) {
  auto m = get_cube(name);
  m->delPortsList();
}

std::vector<nlohmann::fifo_map<std::string, std::string>> read_router_ports_list_by_id_get_list(const std::string &name) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto m = get_cube(name);
  for(auto &i : m->getPortsList()){
    nlohmann::fifo_map<std::string, std::string> m;
    m["name"] = i->getName();
    r.push_back(std::move(m));
  }
  return r;
}

/*
* Ports related functions
*/
void create_router_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &ports) {
  auto m = get_cube(name);
  return m->addPorts(portsName, ports);
}

PortsJsonObject read_router_ports_by_id(const std::string &name, const std::string &portsName) {
  auto m = get_cube(name);
  return m->getPorts(portsName)->toJsonObject();
}

void replace_router_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &ports) {
  auto m = get_cube(name);
  m->replacePorts(portsName, ports);
}

void delete_router_ports_by_id(const std::string &name, const std::string &portsName) {
  auto m = get_cube(name);
  m->delPorts(portsName);
}

std::string read_router_ports_peer_by_id(const std::string &name, const std::string &portsName) {
  auto m = get_cube(name);
  auto p = m->getPorts(portsName);
  return p->getPeer();
}

PortsStatusEnum read_router_ports_status_by_id(const std::string &name, const std::string &portsName) {
  auto m = get_cube(name);
  auto p = m->getPorts(portsName);
  return p->getStatus();
}

std::string read_router_ports_uuid_by_id(const std::string &name, const std::string &portsName) {
  auto m = get_cube(name);
  auto p = m->getPorts(portsName);
  return p->getUuid();
}

void update_router_ports_peer_by_id(const std::string &name, const std::string &portsName, const std::string &peer) {
  auto m = get_cube(name);
  auto p = m->getPorts(portsName);
  p->setPeer(peer);
}


/**
* @brief   Create arp-entry by ID
*
* Create operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] address ID of address
* @param[in] value arp-entrybody object
*
* Responses:
*
*/
void
create_router_arp_entry_by_id(const std::string &name, const std::string &address, const ArpEntryJsonObject &value) {
  auto router = get_cube(name);

  router->addArpEntry(address, value);
}




/**
* @brief   Create arp-entry by ID
*
* Create operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] value arp-entrybody object
*
* Responses:
*
*/
void
create_router_arp_entry_list_by_id(const std::string &name, const std::vector<ArpEntryJsonObject> &value) {
  auto router = get_cube(name);
  router->addArpEntryList(value);
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> create_router_arp_entry_list_by_id_get_list(const std::string &name, const std::vector<ArpEntryJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);

  auto &&arpEntry = router->addArpEntryList(value);
  for(auto &i : arpEntry) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif


/**
* @brief   Create secondaryip by ID
*
* Create operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] ip ID of ip
* @param[in] netmask ID of netmask
* @param[in] value secondaryipbody object
*
* Responses:
*
*/
void
create_router_ports_secondaryip_by_id(const std::string &name, const std::string &portsName, const std::string &ip, const std::string &netmask, const PortsSecondaryipJsonObject &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->addSecondaryip(ip, netmask, value);
}




/**
* @brief   Create secondaryip by ID
*
* Create operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value secondaryipbody object
*
* Responses:
*
*/
void
create_router_ports_secondaryip_list_by_id(const std::string &name, const std::string &portsName, const std::vector<PortsSecondaryipJsonObject> &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  ports->addSecondaryipList(value);
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> create_router_ports_secondaryip_list_by_id_get_list(const std::string &name, const std::string &portsName, const std::vector<PortsSecondaryipJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);
  auto &&ports = router->getPorts(portsName);

  auto &&secondaryip = ports->addSecondaryipList(value);
  for(auto &i : secondaryip) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif


/**
* @brief   Create route by ID
*
* Create operation of resource: route*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
* @param[in] value routebody object
*
* Responses:
*
*/
void
create_router_route_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop, const RouteJsonObject &value) {
  auto router = get_cube(name);

  router->addRoute(network, netmask, nexthop, value);
}




/**
* @brief   Create route by ID
*
* Create operation of resource: route*
*
* @param[in] name ID of name
* @param[in] value routebody object
*
* Responses:
*
*/
void
create_router_route_list_by_id(const std::string &name, const std::vector<RouteJsonObject> &value) {
  auto router = get_cube(name);
  router->addRouteList(value);
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> create_router_route_list_by_id_get_list(const std::string &name, const std::vector<RouteJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);

  auto &&route = router->addRouteList(value);
  for(auto &i : route) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif


/**
* @brief   Delete arp-entry by ID
*
* Delete operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] address ID of address
*
* Responses:
*
*/
void
delete_router_arp_entry_by_id(const std::string &name, const std::string &address) {
  auto router = get_cube(name);

  router->delArpEntry(address);
}




/**
* @brief   Delete arp-entry by ID
*
* Delete operation of resource: arp-entry*
*
* @param[in] name ID of name
*
* Responses:
*
*/
void
delete_router_arp_entry_list_by_id(const std::string &name) {
  auto router = get_cube(name);
  router->delArpEntryList();
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> delete_router_arp_entry_list_by_id_get_list(const std::string &name) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);

  auto &&arpEntry = router->delArpEntryList();
  for(auto &i : arpEntry) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif


/**
* @brief   Delete secondaryip by ID
*
* Delete operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] ip ID of ip
* @param[in] netmask ID of netmask
*
* Responses:
*
*/
void
delete_router_ports_secondaryip_by_id(const std::string &name, const std::string &portsName, const std::string &ip, const std::string &netmask) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->delSecondaryip(ip, netmask);
}




/**
* @brief   Delete secondaryip by ID
*
* Delete operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
*
*/
void
delete_router_ports_secondaryip_list_by_id(const std::string &name, const std::string &portsName) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  ports->delSecondaryipList();
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> delete_router_ports_secondaryip_list_by_id_get_list(const std::string &name, const std::string &portsName) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);
  auto &&ports = router->getPorts(portsName);

  auto &&secondaryip = ports->delSecondaryipList();
  for(auto &i : secondaryip) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif


/**
* @brief   Delete route by ID
*
* Delete operation of resource: route*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
*
* Responses:
*
*/
void
delete_router_route_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop) {
  auto router = get_cube(name);

  router->delRoute(network, netmask, nexthop);
}




/**
* @brief   Delete route by ID
*
* Delete operation of resource: route*
*
* @param[in] name ID of name
*
* Responses:
*
*/
void
delete_router_route_list_by_id(const std::string &name) {
  auto router = get_cube(name);
  router->delRouteList();
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> delete_router_route_list_by_id_get_list(const std::string &name) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);

  auto &&route = router->delRouteList();
  for(auto &i : route) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif


/**
* @brief   Read arp-entry by ID
*
* Read operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] address ID of address
*
* Responses:
* ArpEntryJsonObject
*/
ArpEntryJsonObject
read_router_arp_entry_by_id(const std::string &name, const std::string &address) {
  auto router = get_cube(name);
  return router->getArpEntry(address)->toJsonObject();

}




/**
* @brief   Read interface by ID
*
* Read operation of resource: interface*
*
* @param[in] name ID of name
* @param[in] address ID of address
*
* Responses:
* std::string
*/
std::string
read_router_arp_entry_interface_by_id(const std::string &name, const std::string &address) {
  auto router = get_cube(name);
  auto arpEntry = router->getArpEntry(address);
  return arpEntry->getInterface();

}




/**
* @brief   Read arp-entry by ID
*
* Read operation of resource: arp-entry*
*
* @param[in] name ID of name
*
* Responses:
* std::vector<ArpEntryJsonObject>
*/
std::vector<ArpEntryJsonObject>
read_router_arp_entry_list_by_id(const std::string &name) {
  auto router = get_cube(name);
  auto &&arpEntry = router->getArpEntryList();
  std::vector<ArpEntryJsonObject> m;
  for(auto &i : arpEntry)
    m.push_back(i->toJsonObject());
  return m;
}

#define IMPLEMENT_POLYCUBE_GET_LIST

#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> read_router_arp_entry_list_by_id_get_list(const std::string &name) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);

  auto &&arpEntry = router->getArpEntryList();
  for(auto &i : arpEntry) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif

#undef IMPLEMENT_POLYCUBE_GET_LIST

/**
* @brief   Read mac by ID
*
* Read operation of resource: mac*
*
* @param[in] name ID of name
* @param[in] address ID of address
*
* Responses:
* std::string
*/
std::string
read_router_arp_entry_mac_by_id(const std::string &name, const std::string &address) {
  auto router = get_cube(name);
  auto arpEntry = router->getArpEntry(address);
  return arpEntry->getMac();

}




/**
* @brief   Read router by ID
*
* Read operation of resource: router*
*
* @param[in] name ID of name
*
* Responses:
* RouterJsonObject
*/
RouterJsonObject
read_router_by_id(const std::string &name) {
  return get_cube(name)->toJsonObject();

}




/**
* @brief   Read loglevel by ID
*
* Read operation of resource: loglevel*
*
* @param[in] name ID of name
*
* Responses:
* RouterLoglevelEnum
*/
RouterLoglevelEnum
read_router_loglevel_by_id(const std::string &name) {
  auto router = get_cube(name);
  return router->getLoglevel();

}




/**
* @brief   Read ip by ID
*
* Read operation of resource: ip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
* std::string
*/
std::string
read_router_ports_ip_by_id(const std::string &name, const std::string &portsName) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  return ports->getIp();

}




/**
* @brief   Read mac by ID
*
* Read operation of resource: mac*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
* std::string
*/
std::string
read_router_ports_mac_by_id(const std::string &name, const std::string &portsName) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  return ports->getMac();

}




/**
* @brief   Read netmask by ID
*
* Read operation of resource: netmask*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
* std::string
*/
std::string
read_router_ports_netmask_by_id(const std::string &name, const std::string &portsName) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  return ports->getNetmask();

}




/**
* @brief   Read secondaryip by ID
*
* Read operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] ip ID of ip
* @param[in] netmask ID of netmask
*
* Responses:
* PortsSecondaryipJsonObject
*/
PortsSecondaryipJsonObject
read_router_ports_secondaryip_by_id(const std::string &name, const std::string &portsName, const std::string &ip, const std::string &netmask) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  return ports->getSecondaryip(ip, netmask)->toJsonObject();

}




/**
* @brief   Read secondaryip by ID
*
* Read operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
* std::vector<PortsSecondaryipJsonObject>
*/
std::vector<PortsSecondaryipJsonObject>
read_router_ports_secondaryip_list_by_id(const std::string &name, const std::string &portsName) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  auto &&secondaryip = ports->getSecondaryipList();
  std::vector<PortsSecondaryipJsonObject> m;
  for(auto &i : secondaryip)
    m.push_back(i->toJsonObject());
  return m;
}

#define IMPLEMENT_POLYCUBE_GET_LIST

#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> read_router_ports_secondaryip_list_by_id_get_list(const std::string &name, const std::string &portsName) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);
  auto &&ports = router->getPorts(portsName);

  auto &&secondaryip = ports->getSecondaryipList();
  for(auto &i : secondaryip) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif

#undef IMPLEMENT_POLYCUBE_GET_LIST

/**
* @brief   Read route by ID
*
* Read operation of resource: route*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
*
* Responses:
* RouteJsonObject
*/
RouteJsonObject
read_router_route_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop) {
  auto router = get_cube(name);
  return router->getRoute(network, netmask, nexthop)->toJsonObject();

}




/**
* @brief   Read interface by ID
*
* Read operation of resource: interface*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
*
* Responses:
* std::string
*/
std::string
read_router_route_interface_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop) {
  auto router = get_cube(name);
  auto route = router->getRoute(network, netmask, nexthop);
  return route->getInterface();

}




/**
* @brief   Read route by ID
*
* Read operation of resource: route*
*
* @param[in] name ID of name
*
* Responses:
* std::vector<RouteJsonObject>
*/
std::vector<RouteJsonObject>
read_router_route_list_by_id(const std::string &name) {
  auto router = get_cube(name);
  auto &&route = router->getRouteList();
  std::vector<RouteJsonObject> m;
  for(auto &i : route)
    m.push_back(i->toJsonObject());
  return m;
}

#define IMPLEMENT_POLYCUBE_GET_LIST

#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> read_router_route_list_by_id_get_list(const std::string &name) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&router = get_cube(name);

  auto &&route = router->getRouteList();
  for(auto &i : route) {
    r.push_back(i->getKeys());
  }
  return r;
}
#endif

#undef IMPLEMENT_POLYCUBE_GET_LIST

/**
* @brief   Read pathcost by ID
*
* Read operation of resource: pathcost*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
*
* Responses:
* int32_t
*/
int32_t
read_router_route_pathcost_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop) {
  auto router = get_cube(name);
  auto route = router->getRoute(network, netmask, nexthop);
  return route->getPathcost();

}




/**
* @brief   Read type by ID
*
* Read operation of resource: type*
*
* @param[in] name ID of name
*
* Responses:
* CubeType
*/
CubeType
read_router_type_by_id(const std::string &name) {
  auto router = get_cube(name);
  return router->getType();

}




/**
* @brief   Replace arp-entry by ID
*
* Replace operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] address ID of address
* @param[in] value arp-entrybody object
*
* Responses:
*
*/
void
replace_router_arp_entry_by_id(const std::string &name, const std::string &address, const ArpEntryJsonObject &value) {
  auto router = get_cube(name);

  router->replaceArpEntry(address, value);
}




/**
* @brief   Replace arp-entry by ID
*
* Replace operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] value arp-entrybody object
*
* Responses:
*
*/
void
replace_router_arp_entry_list_by_id(const std::string &name, const std::vector<ArpEntryJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> replace_router_arp_entry_list_by_id_get_list(const std::string &name, const std::vector<ArpEntryJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Replace secondaryip by ID
*
* Replace operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] ip ID of ip
* @param[in] netmask ID of netmask
* @param[in] value secondaryipbody object
*
* Responses:
*
*/
void
replace_router_ports_secondaryip_by_id(const std::string &name, const std::string &portsName, const std::string &ip, const std::string &netmask, const PortsSecondaryipJsonObject &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->replaceSecondaryip(ip, netmask, value);
}




/**
* @brief   Replace secondaryip by ID
*
* Replace operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value secondaryipbody object
*
* Responses:
*
*/
void
replace_router_ports_secondaryip_list_by_id(const std::string &name, const std::string &portsName, const std::vector<PortsSecondaryipJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> replace_router_ports_secondaryip_list_by_id_get_list(const std::string &name, const std::string &portsName, const std::vector<PortsSecondaryipJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Replace route by ID
*
* Replace operation of resource: route*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
* @param[in] value routebody object
*
* Responses:
*
*/
void
replace_router_route_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop, const RouteJsonObject &value) {
  auto router = get_cube(name);

  router->replaceRoute(network, netmask, nexthop, value);
}




/**
* @brief   Replace route by ID
*
* Replace operation of resource: route*
*
* @param[in] name ID of name
* @param[in] value routebody object
*
* Responses:
*
*/
void
replace_router_route_list_by_id(const std::string &name, const std::vector<RouteJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> replace_router_route_list_by_id_get_list(const std::string &name, const std::vector<RouteJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Update arp-entry by ID
*
* Update operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] address ID of address
* @param[in] value arp-entrybody object
*
* Responses:
*
*/
void
update_router_arp_entry_by_id(const std::string &name, const std::string &address, const ArpEntryJsonObject &value) {
  auto router = get_cube(name);
  auto arpEntry = router->getArpEntry(address);

  arpEntry->update(value);
}




/**
* @brief   Update interface by ID
*
* Update operation of resource: interface*
*
* @param[in] name ID of name
* @param[in] address ID of address
* @param[in] value Outgoing interface
*
* Responses:
*
*/
void
update_router_arp_entry_interface_by_id(const std::string &name, const std::string &address, const std::string &value) {
  auto router = get_cube(name);
  auto arpEntry = router->getArpEntry(address);

  arpEntry->setInterface(value);
}




/**
* @brief   Update arp-entry by ID
*
* Update operation of resource: arp-entry*
*
* @param[in] name ID of name
* @param[in] value arp-entrybody object
*
* Responses:
*
*/
void
update_router_arp_entry_list_by_id(const std::string &name, const std::vector<ArpEntryJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> update_router_arp_entry_list_by_id_get_list(const std::string &name, const std::vector<ArpEntryJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Update mac by ID
*
* Update operation of resource: mac*
*
* @param[in] name ID of name
* @param[in] address ID of address
* @param[in] value Destination MAC address
*
* Responses:
*
*/
void
update_router_arp_entry_mac_by_id(const std::string &name, const std::string &address, const std::string &value) {
  auto router = get_cube(name);
  auto arpEntry = router->getArpEntry(address);

  arpEntry->setMac(value);
}




/**
* @brief   Update router by ID
*
* Update operation of resource: router*
*
* @param[in] name ID of name
* @param[in] value routerbody object
*
* Responses:
*
*/
void
update_router_by_id(const std::string &name, const RouterJsonObject &value) {
  auto router = get_cube(name);

  router->update(value);
}




/**
* @brief   Update router by ID
*
* Update operation of resource: router*
*
* @param[in] value routerbody object
*
* Responses:
*
*/
void
update_router_list_by_id(const std::vector<RouterJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> update_router_list_by_id_get_list(const std::vector<RouterJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Update loglevel by ID
*
* Update operation of resource: loglevel*
*
* @param[in] name ID of name
* @param[in] value Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE)
*
* Responses:
*
*/
void
update_router_loglevel_by_id(const std::string &name, const RouterLoglevelEnum &value) {
  auto router = get_cube(name);

  router->setLoglevel(value);
}




/**
* @brief   Update ports by ID
*
* Update operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
update_router_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->update(value);
}




/**
* @brief   Update ip by ID
*
* Update operation of resource: ip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value IP address of the port
*
* Responses:
*
*/
void
update_router_ports_ip_by_id(const std::string &name, const std::string &portsName, const std::string &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->setIp(value);
}




/**
* @brief   Update ports by ID
*
* Update operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
update_router_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> update_router_ports_list_by_id_get_list(const std::string &name, const std::vector<PortsJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Update mac by ID
*
* Update operation of resource: mac*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value MAC address of the port
*
* Responses:
*
*/
void
update_router_ports_mac_by_id(const std::string &name, const std::string &portsName, const std::string &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->setMac(value);
}




/**
* @brief   Update netmask by ID
*
* Update operation of resource: netmask*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value Netmask of the port
*
* Responses:
*
*/
void
update_router_ports_netmask_by_id(const std::string &name, const std::string &portsName, const std::string &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);

  ports->setNetmask(value);
}




/**
* @brief   Update secondaryip by ID
*
* Update operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] ip ID of ip
* @param[in] netmask ID of netmask
* @param[in] value secondaryipbody object
*
* Responses:
*
*/
void
update_router_ports_secondaryip_by_id(const std::string &name, const std::string &portsName, const std::string &ip, const std::string &netmask, const PortsSecondaryipJsonObject &value) {
  auto router = get_cube(name);
  auto ports = router->getPorts(portsName);
  auto secondaryip = ports->getSecondaryip(ip, netmask);

  secondaryip->update(value);
}




/**
* @brief   Update secondaryip by ID
*
* Update operation of resource: secondaryip*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value secondaryipbody object
*
* Responses:
*
*/
void
update_router_ports_secondaryip_list_by_id(const std::string &name, const std::string &portsName, const std::vector<PortsSecondaryipJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> update_router_ports_secondaryip_list_by_id_get_list(const std::string &name, const std::string &portsName, const std::vector<PortsSecondaryipJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Update route by ID
*
* Update operation of resource: route*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
* @param[in] value routebody object
*
* Responses:
*
*/
void
update_router_route_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop, const RouteJsonObject &value) {
  auto router = get_cube(name);
  auto route = router->getRoute(network, netmask, nexthop);

  route->update(value);
}




/**
* @brief   Update route by ID
*
* Update operation of resource: route*
*
* @param[in] name ID of name
* @param[in] value routebody object
*
* Responses:
*
*/
void
update_router_route_list_by_id(const std::string &name, const std::vector<RouteJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}


#ifdef IMPLEMENT_POLYCUBE_GET_LIST
std::vector<nlohmann::fifo_map<std::string, std::string>> update_router_route_list_by_id_get_list(const std::string &name, const std::vector<RouteJsonObject> &value) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
}
#endif


/**
* @brief   Update pathcost by ID
*
* Update operation of resource: pathcost*
*
* @param[in] name ID of name
* @param[in] network ID of network
* @param[in] netmask ID of netmask
* @param[in] nexthop ID of nexthop
* @param[in] value Cost of this route
*
* Responses:
*
*/
void
update_router_route_pathcost_by_id(const std::string &name, const std::string &network, const std::string &netmask, const std::string &nexthop, const int32_t &value) {
  auto router = get_cube(name);
  auto route = router->getRoute(network, netmask, nexthop);

  route->setPathcost(value);
}




}
}
}
}
}

