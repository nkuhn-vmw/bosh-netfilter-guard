#!/usr/bin/env python3
"""Watch a TCP port's reachability over time and log every state change.

Connects to HOST:PORT every 0.25 s and prints how long each state lasted: connected, refused (the kernel
answered with a reset: nothing listening and no rule dropping), no-answer (dropped, or the host is down),
unreachable. Run it while you deploy, restart or reboot a VM to measure how long a rule was absent.

    portwatch.py HOST PORT SECONDS [opts]

With `opts`, every SYN carries an IPv4 Record Route option (unprivileged, via IP_OPTIONS), which is what the
ipv4-options profile drops. Point a plain watcher at an unused port with a marker DROP rule and an `opts`
watcher at the same port to compare two mechanisms side by side; add a plain watcher on a listening port
(e.g. 22) to see when the host itself is up.
"""
import datetime
import errno
import socket
import sys
import time

RECORD_ROUTE = bytes([7, 7, 4, 0, 0, 0, 0, 0])


def probe(host, port, opts):
    s = socket.socket()
    s.settimeout(0.4)
    if opts:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, RECORD_ROUTE)
    try:
        s.connect((host, port))
        return "connected"
    except socket.timeout:
        return "no-answer"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        return "unreachable" if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else f"err-{e.errno}"
    finally:
        s.close()


def stamp(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]


def main():
    if len(sys.argv) < 4:
        sys.exit(f"usage: {sys.argv[0]} HOST PORT SECONDS [opts]")
    host, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    opts = len(sys.argv) > 4 and sys.argv[4] == "opts"
    end = time.time() + dur
    last, since, counts = None, time.time(), {}
    while time.time() < end:
        now = time.time()
        st = probe(host, port, opts)
        counts[st] = counts.get(st, 0) + 1
        if st != last:
            if last:
                print(stamp(since), f"{last:12} for {now - since:7.2f}s", flush=True)
            last, since = st, now
        time.sleep(max(0, 0.25 - (time.time() - now)))
    print(stamp(since), f"{last:12} for {time.time() - since:7.2f}s (end)")
    print("counts", counts)


if __name__ == "__main__":
    main()
