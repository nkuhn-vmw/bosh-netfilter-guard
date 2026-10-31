# What a host packet filter can and can't mitigate

netfilter-guard works on packet headers (IP, TCP, UDP) at the host's netfilter hooks. That makes it a strong
interim control for one class of bug, a useful containment layer for another, and the wrong tool for a third.
This page maps recent, widely reported vulnerability classes to the controls that actually help, so the guard
gets used where it works and nobody relies on it where it doesn't.

## At a glance

| Vulnerability class | Recent example | Can a host packet filter stop the exploit? | What it *can* do | Primary fix |
|---|---|---|---|---|
| Kernel network-stack bug reachable only through an unusual packet shape | Late-2026 Linux use-after-free in the IPv4 TCP handshake, triggered by a SYN carrying IPv4 options | **Yes**: the trigger is visible in the packet header | Drop the shape before the TCP stack (`profiles/ipv4-options.yml`) | Patched kernel / stemcell |
| Kernel bug triggered by abnormal TCP parameters | Historic small-MSS / SACK bugs | **Yes** | `profiles/tcp-small-mss.yml` | Patched kernel |
| Language-runtime RCE triggered by request content ("PHP2Shell"-style: request-memory use-after-free / out-of-memory handling in PHP) | Late-2026 PHP RCEs, fixed in the PHP point releases shipped in updated buildpacks | **No**: the trigger is inside the HTTP request, usually inside TLS | Contain what an attacker can reach afterwards (egress backstop below) | Update the buildpack and **restage** every app |
| Decompression bug reached through HTTP compression ("HTTP2Shell", also called Node2Shell / Python2Shell: Brotli decoder out-of-bounds write, Brotli 1.0.3–1.2.0) | Late 2026; reaches Node.js, Python HTTP clients, Bun, Envoy, and anything that auto-decodes `Content-Encoding: br` | **No**: the payload is a compressed body, not a packet shape | Contain what an attacker can reach afterwards | Brotli 1.2.1 / 1.1.1 / 1.0.10 (or the runtime releases that bundle it), then restage |

## Why packet filtering can't stop application-layer RCEs

- The malicious input is in the HTTP body or headers. On a platform it's usually TLS-encrypted until the router
  or load balancer, so the host sees ciphertext.
- Matching plaintext bytes with `-m string` is easy to evade (chunking, compression, HTTP/2 framing) and costly.
  It gives false confidence, so don't.
- The legitimate and malicious requests use the same ports, protocols and header shapes.

## Layered controls for the "…2Shell" class

1. **Patch and restage.** On Cloud Foundry, an app keeps the runtime from the buildpack that staged it. Updating
   the buildpack alone fixes nothing until each app is restaged.
2. **Layer 7 at the edge** (load balancer / WAF in full-proxy mode with TLS termination):
   - HTTP2Shell inbound path: reject or strip `Content-Encoding: br` on request bodies for apps that don't accept
     compressed uploads (very few do). A pure TCP/TLS pass-through load balancer can't see headers.
   - Gorouter can't do this: it can rewrite *response* headers (`router.http_rewrite.responses.*`) but has no
     request-header removal, so do it at the load balancer or with a route service.
   - `examples/avi-reject-brotli-request.json` is an NSX Advanced Load Balancer (Avi) HTTP policy set that answers
     403 to any request whose `Content-Encoding` contains `br`. It only works on an L7 virtual service that
     terminates TLS. Many platforms front the routers with L4 pass-through, and that can't see headers at all.
3. **Outbound path for decompression bugs:** apps that *fetch* attacker-controlled content (webhooks, URL previews,
   scrapers) decode `br` responses too. An egress proxy that strips `br` from `Accept-Encoding`, or restricted
   egress, covers that path. Inbound filtering doesn't.
4. **Contain post-exploitation:** "…2Shell" means the attacker gets a shell in the app container. What matters next
   is what that container can reach:
   - **Cloud Foundry ASGs are the primary control.** The stock `default_security_group` allows egress to everything
     except link-local, including the platform's own management networks. Replace it with explicit
     destinations per space.
   - **Host-level backstop:** `profiles/container-egress-backstop.yml` uses netfilter-guard on Diego cells to drop
     container traffic to platform management ports, regardless of ASGs. It's defense in depth, deliberately narrow,
     and ships in monitor mode. See the warnings in the file.
5. **Detect:** watch for app processes spawning shells, outbound connections to unusual destinations, and cell
   kernel traces (for kernel-class bugs).

## Choosing a delivery mechanism

| Need | netfilter-guard | os-conf `iptables` job | os-conf `pre-start-script` |
|---|---|---|---|
| Maintained under the Cloud Foundry org | no | **yes** | **yes** |
| Rules in place before networking at boot | **yes** (systemd, before `network-pre`); measured: no gap | no: measured **58 s** unprotected after the VM was reachable | no: not re-run on reboot at all |
| No unprotected window during deploys | **yes**; measured: no gap through `bosh restart` | no: measured **28 s** unprotected per deploy/restart (`stop` flushes the chain) | depends on the script |
| Jump placed first in the built-in chain | **yes**, enforced | no: appended at the end | script-defined |
| Drift detection and repair | **yes** (2-minute timer) | no: a rule inserted above its jump bypasses it indefinitely | no |
| Clean removal | **yes** (`enabled: false`) | no: empty chains and jumps stay until reboot | no |
| Monitor (count-only) mode, validation, dry-run | **yes** | no | no |
| Per-VM evidence tooling | **yes** | no | no |

`examples/os-conf-iptables.yml` shows the same IPv4-options rule delivered with os-conf, for teams that prefer an
upstream release. It's acceptable as long as the trade-offs above are understood: keep an upstream control in
place, because every deploy and every reboot opens a window.

### How the numbers were measured

One BOSH VM (Ubuntu Jammy stemcell) ran both add-ons at once. os-conf 23.0.4 dropped a marker rule (TCP to an
unused port) and netfilter-guard ran the `ipv4-options` profile. `tools/portwatch.py` connected every 0.25 s
from another host, once plainly to the marker port and once with an IPv4 option. "Refused" means the rule is
absent and the kernel answered. "No answer" means the rule dropped the packet.

| Event | os-conf marker rule | netfilter-guard rule |
|---|---|---|
| First deploy | live 2 s after "starting jobs" | (already deployed) |
| `bosh restart` | unprotected 28 s (job stop to job start) | no gap |
| Reboot | unprotected 58 s after the VM answered again | no gap |
| Rule inserted above both jumps | bypassed until manually removed | jump back at position 1 on the next 2-minute check |
| Job removed from the runtime config | empty `pfbr-custom-*` chains and jumps left behind | n/a |

Caveat: the options probe can't tell which netfilter-guard hook dropped a packet. Linux echoes received IP
options into its RST reply, so the `OUTPUT` rule drops the reply even when `PREROUTING` was bypassed. Read the
per-rule counters (`netfilter-guard status`) when you need to know which hook did it.
