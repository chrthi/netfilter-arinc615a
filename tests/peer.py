#!/usr/bin/env python3
"""Minimal ARINC 615A-style TFTP peers for exercising the conntrack helper.

dl:  sends WRQ to target:59 (optionally with a "port" option), transfers one
     block, then serves the Target's WRQs on its server port.
tgt: answers the DL's WRQ from a new port, then sends its own WRQs (status
     uploads) to the DL's server port according to a schedule.
"""
import socket, struct, sys, time, argparse

RRQ, WRQ, DATA, ACK, ERR = 1, 2, 3, 4, 5
T = 2.0


def log(*a):
    print(f"[{time.monotonic():8.2f}]", *a, flush=True)


def req(op, name, opts=None):
    b = struct.pack("!H", op) + name.encode() + b"\0octet\0"
    for k, v in (opts or {}).items():
        b += k.encode() + b"\0" + str(v).encode() + b"\0"
    return b


def parse_req(b):
    parts = b[2:].split(b"\0")[:-1]
    opts = {parts[i].decode().lower(): parts[i + 1].decode()
            for i in range(2, len(parts) - 1, 2)}
    return parts[0].decode(), opts


V6 = "--v6" in sys.argv


def sock(port=0):
    s = socket.socket(socket.AF_INET6 if V6 else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("::" if V6 else "0.0.0.0", port))
    s.settimeout(T)
    return s


def send_file(s, peer, blocks, interval):
    """We are the writer, the WRQ was acked by peer: send blocks."""
    for n in range(1, blocks + 1):
        s.sendto(struct.pack("!HH", DATA, n) + b"x" * (512 if n < blocks else 10), peer)
        b, a = s.recvfrom(1024)
        assert a[:2] == peer[:2] and struct.unpack("!HH", b[:4]) == (ACK, n), (a, b)
        if n < blocks:
            time.sleep(interval)


def recv_file(s, first_peer_reply):
    s.sendto(struct.pack("!HH", ACK, 0), first_peer_reply)
    while True:
        b, a = s.recvfrom(1024)
        op, n = struct.unpack("!HH", b[:4])
        assert op == DATA, b
        s.sendto(struct.pack("!HH", ACK, n), a)
        if len(b) - 4 < 512:
            return n


def dl(args):
    s = sock(args.sport)
    srv = s
    opts = {}
    if args.opt:
        opts["port"] = args.opt
        if args.opt != args.sport:
            srv = sock(args.opt)
    s.sendto(req(WRQ, "TARGET.LUI", opts), (args.target, 59))
    b, tid = s.recvfrom(1024)
    assert struct.unpack("!HH", b[:4]) == (ACK, 0), b
    send_file(s, tid, 1, 0)
    log(f"DL: WRQ to Target ok (target TID {tid[1]})")

    srv.settimeout(0.5)
    end = time.monotonic() + args.serve
    while time.monotonic() < end:
        try:
            b, peer = srv.recvfrom(1024)
        except socket.timeout:
            continue
        if struct.unpack("!H", b[:2])[0] != WRQ:
            continue
        name, _ = parse_req(b)
        c = sock()
        n = recv_file(c, peer)
        log(f"DL: served Target WRQ {name} from {peer}, {n} blocks, server TID {c.getsockname()[1]}")
        c.close()


def tgt(args):
    l = sock(59)
    l.settimeout(10)
    b, dlpeer = l.recvfrom(1024)
    name, opts = parse_req(b)
    dlport = int(opts.get("port", dlpeer[1]))
    log(f"TGT: {name} from {dlpeer}, DL server port {dlport}")
    c = sock()
    recv_file(c, dlpeer)
    log(f"TGT: received {name} via TID {c.getsockname()[1]}")
    c.close()

    for i, step in enumerate(args.schedule.split(",")):
        delay, blocks = (float(x) for x in step.split(":"))
        time.sleep(delay)
        c = sock()
        try:
            c.sendto(req(WRQ, f"STATUS{i}.LUS"), (dlpeer[0], dlport))
            b, srvtid = c.recvfrom(1024)
            assert struct.unpack("!HH", b[:4]) == (ACK, 0)
            send_file(c, srvtid, int(blocks), 0.5)
            log(f"TGT: status upload #{i} after {delay}s idle: OK ({int(blocks)} blocks)")
        except (socket.timeout, PermissionError, OSError) as e:
            log(f"TGT: status upload #{i} after {delay}s idle: FAILED ({e.__class__.__name__})")
        c.close()


p = argparse.ArgumentParser()
p.add_argument("role", choices=["dl", "tgt"])
p.add_argument("--target")
p.add_argument("--sport", type=int, default=50000)
p.add_argument("--opt", type=int, default=0)
p.add_argument("--serve", type=float, default=20)
p.add_argument("--schedule", default="1:1")
p.add_argument("--v6", action="store_true")
a = p.parse_args()
dl(a) if a.role == "dl" else tgt(a)
