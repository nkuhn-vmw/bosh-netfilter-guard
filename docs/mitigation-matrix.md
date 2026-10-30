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
| Rules in place before networking at boot | **yes** (systemd, before `network-pre`) | no (monit starts it after the agent) | no (only on deploy) |
| No unprotected window during deploys | **yes** (chain swapped atomically) | no: `stop` flushes the chains | depends on the script |
| Jump placed first in the built-in chain | **yes**, enforced | no: appended at the end | script-defined |
| Drift detection and repair | **yes** (2-minute timer) | no | no |
| Monitor (count-only) mode, validation, dry-run | **yes** | no | no |
| Per-VM evidence tooling | **yes** | no | no |

`examples/os-conf-iptables.yml` shows the same IPv4-options rule delivered with os-conf, for teams that prefer an
upstream release. It's acceptable as long as the trade-offs above are understood.
