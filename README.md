# nf_conntrack_arinc615a

Netfilter connection tracking helper for ARINC 615A data loading, as an
out-of-tree kernel module, plus a companion NAT helper.

ARINC 615A uses TFTP, but `nf_conntrack_tftp` cannot track it because both
peers act as TFTP server during one operation:

1. The Data Loader (DL) sends a RRQ/WRQ to the Target's UDP port 59. The
   Target answers from a new port (normal TFTP).
2. The Target sends its own RRQ/WRQs (e.g. `.LUS` status files, data file
   reads) to the DL's TFTP server. That is port 59 as well, unless the DL's
   request carries a `port` option naming another one.
3. The DL answers those from a new port again.

## How it works

The helper is attached to the DL → Target:59 connection (the "root" of an
operation). On every RRQ/WRQ in the original direction it registers
expectations:

| Seen on             | Expectation (any source port) | Kind      |
|---------------------|-------------------------------|-----------|
| root connection     | Target → DL server port (59 or `port` option) | permanent |
| root, unless the DL sent from its server port | Target → DL request port (the reply) | one shot |
| any child connection with a RRQ/WRQ | responder → requester port | one shot |

Every expected connection inherits the helper, so all flows of an operation
form a tree. **Each packet anywhere in that tree restarts the timeout of every
connection up to the root and of their expectations.** A long file transfer
therefore keeps the operation alive, and the whole operation disappears once
nothing at all has been seen for `timeout` seconds (default 14).

Nothing depends on which host the module runs on, so it works on the Target,
on the Data Loader, and on routers/firewalls in between. Load
`nf_nat_arinc615a` too if that router does NAT (SNAT/masquerade with port
remapping is supported).

## Build

```sh
make                          # against the running kernel
make KDIR=/path/to/linux      # against another configured kernel tree
sudo make modules_install && sudo depmod -a
```

Or with DKMS: copy the directory to `/usr/src/nf_conntrack_arinc615a-1.0` and
run `dkms install nf_conntrack_arinc615a/1.0`.

`nf_nat_arinc615a.ko` is only built if the kernel has `CONFIG_NF_NAT`.
`nf_ct_refresh()` changed signature in Linux 6.14; Kbuild detects the variant
from the kernel headers, so vendor backports are handled.

## Module parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `timeout` | 14      | Seconds without any packet of an operation after which it is dropped. Writable at runtime via `/sys/module/nf_conntrack_arinc615a/parameters/timeout`; new values apply to subsequent refreshes. |
| `ports`   | 59      | Target port(s), up to 8, e.g. `ports=59,1059`. Helpers are named `arinc615a`, `arinc615a-1`, … |

```sh
modprobe nf_conntrack_arinc615a timeout=14
# or persistently, in /etc/modprobe.d/arinc615a.conf:
options nf_conntrack_arinc615a timeout=14
```

## Usage

Since Linux 4.7 helpers are not attached automatically; assign it with a rule.

nftables, on the Target:

```nft
table inet filter {
    ct helper arinc615a { type "arinc615a" protocol udp; }

    chain pre {
        type filter hook prerouting priority filter;
        udp dport 59 ct helper set "arinc615a"
    }
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        udp dport 59 accept
    }
    chain output {
        type filter hook output priority filter; policy drop;
        ct state established,related accept
    }
}
```

On a router, use the same `ct helper set` rule in prerouting and
`ct state established,related accept` in the forward chain.

iptables:

```sh
iptables -t raw -A PREROUTING -p udp --dport 59 -j CT --helper arinc615a
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp --dport 59 -j ACCEPT
```

Inspect state with `conntrack -L` / `conntrack -L expect`, or
`/proc/net/nf_conntrack_expect` if `CONFIG_NF_CONNTRACK_PROCFS` is set.
Expectations of this helper show up as `arinc615a/arinc615a`.

## Testing

`tests/netns-test.sh` (root, iproute2, nft, python3) sets up network
namespaces, runs a minimal ARINC 615A exchange with `tests/peer.py` and checks
that only helper-created flows pass a default-drop firewall:

- A1/A2/A6: firewall on the Target; IPv4 without and with `port` option, IPv6.
- B1/B2: firewall plus SNAT with port remapping on a router in between.

Each scenario: status uploads after 1 s and 2 s idle, a 12-block transfer
lasting longer than the timeout, an upload right after it (all must pass),
and an upload after an idle period longer than the timeout (must fail).

## Limitations

- Only the first 512 bytes of a request are parsed for the `port` option, as
  RFC 2347 limits requests to that size.
- An invalid `port` value (not 1–65535 decimal) is ignored and port 59 is
  used.
- The DL server port is used as is on the address the Target sees. Behind
  NAT, the DL must therefore be reachable on that same port of the
  translated address (the NAT helper maps it back to the DL).
- Requests are recognised by opcode only; a Target that answers from port 59
  itself (no new TID) is also covered since that is the root's reply direction.
