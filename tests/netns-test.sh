#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# End-to-end test with network namespaces. Needs root, iproute2, nft, python3
# and a kernel with nf_tables, conntrack, NAT and veth.
#
#   sudo tests/netns-test.sh            (run from the source dir after make)
#
# Uses timeout=3 so the expiry checks run quickly. Expected result: every
# scenario reports status uploads #0..#3 OK and #4 FAILED (idle > timeout).
set -u
D=$(cd "$(dirname "$0")/.." && pwd)
P="python3 $D/tests/peer.py"
X() { ip netns exec "$@"; }
SCHED="1:1,2:1,0.5:12,0.2:1,5:1"

modprobe -a nf_conntrack nf_nat nf_tables nft_ct nft_nat veth
rmmod nf_nat_arinc615a nf_conntrack_arinc615a 2>/dev/null
insmod $D/nf_conntrack_arinc615a.ko timeout=3 || exit 1
insmod $D/nf_nat_arinc615a.ko || exit 1
T=$(mktemp -d); trap "rm -rf $T" EXIT
echo "timeout param: $(cat /sys/module/nf_conntrack_arinc615a/parameters/timeout)"

dump() { echo "--- conntrack ($1)"; X $1 cat /proc/net/nf_conntrack | grep -E "udp" | sed 's/ \[UNREPLIED\]//; s/ mark=0.*helper/ helper/; s/ mark=0.*//; s/^ipv4 *2 udp *17 //'; echo "--- expect ($1)"; X $1 cat /proc/net/nf_conntrack_expect; }

########## Scenario A: helper and firewall on the Target ##########
setupA() {
  for n in dl tgt; do ip netns add $n; X $n ip link set lo up; done
  ip link add d0 netns dl type veth peer name t0 netns tgt
  X dl ip addr add 10.0.0.1/24 dev d0; X dl ip link set d0 up
  X tgt ip addr add 10.0.0.2/24 dev t0; X tgt ip link set t0 up
  X dl ip addr add fd00::1/64 dev d0 nodad; X tgt ip addr add fd00::2/64 dev t0 nodad
  cat > $T/tgt.nft <<'NFT'
table inet fw {
  ct helper a615 { type "arinc615a" protocol udp; }
  chain pre { type filter hook prerouting priority filter; udp dport 59 ct helper set "a615"; }
  chain in  { type filter hook input  priority filter; policy drop;
              ct state established,related accept; udp dport 59 accept;
              icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept;
              counter log prefix "TGT-IN-DROP "; }
  chain out { type filter hook output priority filter; policy drop;
              ct state established,related accept;
              icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept;
              counter log prefix "TGT-OUT-DROP "; }
}
NFT
  X tgt nft -f $T/tgt.nft || echo NFT-LOAD-FAILED
}
teardown() { for n in dl tgt rtr; do ip netns del $n 2>/dev/null; done; sleep 1; }

runA() {
  echo; echo "########## Scenario A$1: Target-local firewall, DL opts: $2"
  setupA
  X tgt $P tgt --schedule $SCHED &
  sleep 0.5
  X dl $P dl --target 10.0.0.2 $2 --serve 21 &
  sleep 2.5; dump tgt
  wait
  echo "--- after operation (all idle > timeout)"; dump tgt
  teardown
}
runA 1 "--sport 50000"
runA6() {
  echo; echo "########## Scenario A6: IPv6, Target-local firewall, port option"
  setupA
  X tgt $P tgt --v6 --schedule $SCHED &
  sleep 0.5
  X dl $P dl --v6 --target fd00::2 --sport 50000 --opt 50059 --serve 21 &
  sleep 2.5; echo "--- conntrack (tgt)"; X tgt cat /proc/net/nf_conntrack | grep ipv6 | sed 's/ mark=0.*helper/ helper/; s/ mark=0.*//'; echo "--- expect (tgt)"; X tgt cat /proc/net/nf_conntrack_expect
  wait
  echo "--- after operation"; X tgt cat /proc/net/nf_conntrack | grep -c "ipv6.*udp"
  teardown
}
runA6
runA 2 "--sport 50000 --opt 50059"
runA 3 "--sport 59"

########## Scenario B: router in the middle doing SNAT with port remapping ##########
setupB() {
  for n in dl rtr tgt; do ip netns add $n; X $n ip link set lo up; done
  ip link add d0 netns dl type veth peer name rd netns rtr
  ip link add t0 netns tgt type veth peer name rt netns rtr
  X dl ip addr add 10.0.0.1/24 dev d0; X dl ip link set d0 up; X dl ip route add default via 10.0.0.254
  X rtr ip addr add 10.0.0.254/24 dev rd; X rtr ip link set rd up
  X rtr ip addr add 192.168.1.254/24 dev rt; X rtr ip link set rt up
  X tgt ip addr add 192.168.1.2/24 dev t0; X tgt ip link set t0 up
  X rtr sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
  cat > $T/rtr.nft <<'NFT'
table inet fw {
  ct helper a615 { type "arinc615a" protocol udp; }
  chain pre { type filter hook prerouting priority filter;
              iifname "rd" udp dport 59 ct helper set "a615"; }
  chain fw_fwd { type filter hook forward priority filter; policy drop;
              ct state established,related accept;
              iifname "rd" udp dport 59 accept;
              counter log prefix "RTR-FWD-DROP "; }
}
table ip nat {
  chain pre  { type nat hook prerouting priority dstnat; }
  chain post { type nat hook postrouting priority srcnat;
               oifname "rt" meta l4proto udp snat to 192.168.1.254:40000-40100; }
}
NFT
  X rtr nft -f $T/rtr.nft || echo NFT-LOAD-FAILED
}
runB() {
  echo; echo "########## Scenario B$1: SNAT router, DL opts: $2"
  setupB
  X tgt $P tgt --schedule $SCHED &
  sleep 0.5
  X dl $P dl --target 192.168.1.2 $2 --serve 21 &
  sleep 2.5; dump rtr
  wait
  echo "--- after operation"; dump rtr
  teardown
}
runB 1 "--sport 50000"
runB 2 "--sport 50000 --opt 50059"

echo; echo "########## runtime timeout change"
echo 14 > /sys/module/nf_conntrack_arinc615a/parameters/timeout; cat /sys/module/nf_conntrack_arinc615a/parameters/timeout
echo 0 > /sys/module/nf_conntrack_arinc615a/parameters/timeout 2>&1 || echo "timeout=0 rejected"
echo 3 > /sys/module/nf_conntrack_arinc615a/parameters/timeout
rmmod nf_nat_arinc615a && rmmod nf_conntrack_arinc615a && echo "unloaded cleanly"
