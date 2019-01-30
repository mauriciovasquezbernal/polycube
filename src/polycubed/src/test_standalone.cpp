#include "polycube/services/transparent_cube.h"
#include "cube_factory_impl.h"
#include "polycubed_core.h"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

// not actually needed, bug to be solved in pistache
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>

using namespace Pistache;
using namespace Pistache::Rest;

namespace polycube {
  namespace service {
  polycube::service::CubeFactory *factory_;
  std::string logfile_("/var/log/polycube/polycubecustom.log");
  }
}

const std::string CODE = R"(
BPF_PERCPU_ARRAY(rxcnt, uint64_t, 1);

static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  uint32_t key = 0;
  uint64_t *value;

  //pcn_log(ctx, LOG_DEBUG, "Packet received");
  value = rxcnt.lookup(&key);
  if (value)
    *value += 1;

  return RX_OK;
}
)";

class StandAloneCube : public polycube::service::TransparentCube {
 public:
  StandAloneCube(const std::string &name) :
    TransparentCube(name, {CODE}, {}, polycube::service::CubeType::TC,
      polycube::LogLevel::TRACE){};

  virtual ~StandAloneCube() {};

  void packet_in(polycube::service::Sense sense,
                 polycube::service::PacketInMetadata &md,
                 const std::vector<uint8_t> &packet) override {};

  uint64_t get_counter() {
    auto dropcnt = get_percpuarray_table<uint64_t>("rxcnt");
    auto values = dropcnt.get(0);
    return std::accumulate(values.begin(), values.end(), 0);
  };
};

int main(void) {
  // create logger, this is needed by some internal libraries
  auto logger = spdlog::stdout_color_mt("polycubed");
  logger->set_level(spdlog::level::from_str("trace"));

  // create an instance of the core
  polycube::polycubed::PolycubedCore core;

  // create an instance of a cube factory and save it to be used by the cube
  polycube::polycubed::CubeFactoryImpl factory("mycustomservice");
  polycube::service::factory_ = &factory;

  // create cube instance
  StandAloneCube cube0("packet_counter");

  // attach to a nic
  core.attach("packet_counter", "veth1", "first", "");

  // create mini rest server to get statistics
  Rest::Router router;
  std::shared_ptr<Http::Endpoint> httpEndpoint(
    std::make_shared<Http::Endpoint>("localhost:9001"));
  auto opts = Http::Endpoint::options().threads(1).flags(
      Tcp::Options::InstallSignalHandler | Tcp::Options::ReuseAddr);
  httpEndpoint->init(opts);

  // create an http endpoint for replying with statistics
  Routes::Get(router, std::string("/counters"),
    [&](const Rest::Request &request, Http::ResponseWriter response)
    -> Pistache::Rest::Route::Result {
    response.send(Http::Code::Ok, std::to_string(cube0.get_counter()));
  });

  httpEndpoint->setHandler(router.handler());
  httpEndpoint->serveThreaded();

  while(1) {
    logger->info("total packets: {}", cube0.get_counter());
    sleep(1);
  }
  getchar();
}