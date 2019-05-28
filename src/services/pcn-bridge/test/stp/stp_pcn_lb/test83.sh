#! /bin/bash

# 3 pcn-bridge; triangle topology;
# connect extra links between bridges
# test connectivity, after convergence

source "${BASH_SOURCE%/*}/../../helpers.bash"

function cleanup {
  set +e
  del_bridges 2
  del_bridges_lb 3 3
  delete_veth 3
  delete_link 6
}
trap cleanup EXIT

set -x

#setup
create_veth 3
create_link 6

set -e

add_bridges_stp 2
add_bridges_lb 3 3

# create ports
bridge_add_port br1 link11
set_br_priority br1 24576
bridge_add_port br1 link32
bridge_add_port br1 veth1

bridge_add_port br2 link12
set_br_priority br2 28672
bridge_add_port br2 link21
bridge_add_port br2 veth2

bridge_add_port_lb br3 link22
bridge_add_port_lb br3 link31
bridge_add_port_lb br3 veth3

bridge_add_port br1 link41
bridge_add_port br2 link42

bridge_add_port br2 link51
bridge_add_port_lb br3 link52

bridge_add_port_lb br3 link61
bridge_add_port br1 link62

#sleeping
sleep $CONVERGENCE_TIME

# testing ports state
test_forwarding_pcn br1 link11
test_forwarding_pcn br1 link32

test_forwarding_pcn br2 link12
test_forwarding_pcn br2 link21

test_forwarding_lb br3 link31
test_blocking_lb br3 link22

test_forwarding_pcn br1 link41
test_forwarding_pcn br1 link62

test_blocking_pcn br2 link42
test_forwarding_pcn br2 link51

test_blocking_lb br3 link52
test_blocking_lb br3 link61


# change topology
polycubectl bridge br1 ports del link11
polycubectl bridge br2 ports del link12

polycubectl bridge br2 ports del link21
sudo brctl delif br3 link22
# polycubectl bridge br3 ports del link22

# polycubectl bridge br3 ports del link31
sudo brctl delif br3 link31
polycubectl bridge br1 ports del link32

#sleeping
sleep $CONVERGENCE_TIME

# testing ports state
test_forwarding_pcn br1 link41
test_forwarding_pcn br1 link62

test_forwarding_pcn br2 link42
test_forwarding_pcn br2 link51

test_blocking_lb br3 link52
test_forwarding_lb br3 link61

#testing connectivity
ping_cycle 3
