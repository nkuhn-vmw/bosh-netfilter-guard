#!/usr/bin/env python3
"""Check whether TCP SYNs carrying IPv4 options reach a listener.

Sends a plain SYN and a SYN with an IPv4 Record Route option (set unprivileged via IP_OPTIONS) to
host:port. With the ipv4-options profile enforced on the target, the first connects and the second times out.
"""
import socket
import sys

RECORD_ROUTE = bytes([7, 7, 4, 0, 0, 0, 0, 0])  # type 7, len 7, pointer 4, one empty slot, EOL pad


def attempt(host, port, with_options, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if with_options:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, RECORD_ROUTE)
    try:
        s.connect((host, port))
        return "connected"
    except socket.timeout:
        return "no answer (timeout)"
    except OSError as e:
        return f"failed ({e.strerror or type(e).__name__})"
    finally:
        s.close()


def main():
    if len(sys.argv) < 3:
        sys.exit(f"usage: {sys.argv[0]} HOST PORT [TIMEOUT_SECONDS]")
    host, port = sys.argv[1], int(sys.argv[2])
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0
    print(f"plain SYN          -> {attempt(host, port, False, timeout)}")
    print(f"SYN + IPv4 options -> {attempt(host, port, True, timeout)}")


if __name__ == "__main__":
    main()
