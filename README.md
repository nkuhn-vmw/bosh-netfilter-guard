# netfilter-guard

A BOSH add-on that applies named netfilter rules (iptables / ip6tables) to every VM it's placed on,
and keeps them there across deploys, recreates and reboots.

It's built for **interim, packet-level mitigations**: a kernel or network-stack bug is reachable only
through some unusual packet shape, the fixed stemcell isn't out yet, and you need to drop that shape
everywhere *now*, in a way you can roll out gradually, observe, and cleanly remove later.

- Job-only release: no packages, no compiled code, nothing downloaded at deploy time.
- Rules are data (manifest properties), so one release covers many mitigations.
- Everything lives in chains it owns (`NFG-<hook>`), jumped to from the built-in chain. Re-apply and
  removal never touch rules from Garden, Silk, the agent or anything else.
- `monitor` mode counts matches without dropping, so you can prove a rule is quiet on real traffic first.

## How it works

```
pre-start (each deploy)                          boot / every 2 min
  render rules.v4 / rules.v6                       │
  dry-run them (iptables-restore --test)           ├─► netfilter-guard.service ─► netfilter-guard apply
  install to /usr/local/..., keep previous files   │    (Before=network-pre.target, retries on failure)
  reload unit; on failure restore previous files   └─► netfilter-guard-reconcile.timer ─► netfilter-guard reconcile
```

`netfilter-guard apply`, for each family:
1. creates any missing `NFG-<hook>` chains;
2. loads the rendered file with `iptables-restore --noflush`, which flushes and refills our chains. **This
   step is atomic per table**: the chain body is never seen empty. The steps around it (chain creation,
   jump placement, stale-chain cleanup) are separate commands;
3. makes sure each built-in hook jumps to our chain **exactly once, at position 1**. It inserts the new jump
   before deleting stray ones, so there is never a moment without a jump;
4. only then removes `NFG-*` chains the current rules no longer need.

`netfilter-guard status` verifies the jump position and that each chain holds exactly the expected rules
(comment and target), not just that the chain exists. `netfilter-guard reconcile` runs `status`, and only if
something drifted (a rule inserted above our jump, an emptied chain, a duplicate jump) it logs what and
re-applies. A systemd timer runs it every 2 minutes; when nothing drifted, counters are left alone.

The script, rule files and units are installed on the **root disk** (`/usr/local/sbin`,
`/usr/local/lib/netfilter-guard`, `/etc/systemd/system`). This matters: `/var/vcap/jobs` is rebuilt by the
BOSH agent only *after* boot, and pre-start doesn't run on a reboot. A unit that points into the job
directory fails at boot with `203/EXEC`, leaving the VM unprotected until the next deploy.

Stopping the unit, including at shutdown, leaves the rules in place. Removal is explicit, via
`enabled: false`, so the VM is never left unprotected while it's still up.

## Quick start

```bash
bosh create-release --force --version 0.1.2 --tarball netfilter-guard-0.1.2.tgz
bosh upload-release netfilter-guard-0.1.2.tgz
bosh update-config --type=runtime --name=netfilter-guard examples/runtime-config.yml
bosh -d my-canary-deployment deploy <(bosh -d my-canary-deployment manifest)
bosh -d my-canary-deployment ssh -c 'sudo /usr/local/sbin/netfilter-guard status'
```

Use a **named** runtime config (`--name=netfilter-guard`). It merges with the director's default config
instead of replacing it, including directors whose default config is managed by Ops Manager.

## Properties

| Property | Default | |
|---|---|---|
| `netfilter_guard.enabled` | `true` | `false` + deploy removes rules, script and unit |
| `netfilter_guard.mode` | `enforce` | `monitor` = match and count only |
| `netfilter_guard.rules` | `[]` | list of rules (below) |

Rule fields:

| Field | Default | |
|---|---|---|
| `name` | required | unique, `[a-z0-9-]`; shows up as the rule comment `nfg:<name>` |
| `match` | required | iptables match args, e.g. `-p tcp -m u32 --u32 "0>>24&0x0F=6:15"`; no `-j`/`-g` |
| `target` | `DROP` | any target: `REJECT`, `LOG --log-prefix "nfg: "`, … |
| `family` | `ipv4` | `ipv4`, `ipv6` or `both` |
| `table` | `raw` | `raw`, `mangle` or `filter` |
| `hook` | `PREROUTING` | must be valid for the table (raw: PREROUTING/OUTPUT; filter: INPUT/FORWARD/OUTPUT; mangle: all five) |
| `mode` | global mode | per-rule `enforce` / `monitor` |

Invalid rules fail **template rendering**, so a bad manifest stops the deploy before any VM changes. The
checks reject control characters and every form of jump or goto in `match` (`-j X`, `-jX`, `--jump`, and
abbreviations like `--ju`), and require `target` to start with a target name. Pre-start then dry-runs the
complete rendered files with `iptables-restore --test` on the VM, so syntax the templates can't judge
(unknown matches, bad arguments) also fails the deploy before anything is installed.

**Why `raw` / `PREROUTING` is the default:** the raw table runs before routing, DNAT, main conntrack and the
TCP stack. It runs just *after* IPv4 defragmentation (netfilter's defrag hook comes first), so options are
checked on the reassembled header. A drop there also covers traffic routed or DNAT'd to containers on the
host (e.g. a Diego cell), and the dropped packet never creates conntrack state. Packets the host itself
sends (including host → container on the same VM) never pass the host's PREROUTING; add the same rule on
raw `OUTPUT` for those, as the `ipv4-options` profile does.

## Profiles

`profiles/` holds ready-to-paste rule lists:

| Profile | Drops |
|---|---|
| `ipv4-options.yml` | TCP packets whose IPv4 header carries options (IHL > 5), inbound (PREROUTING) and host-generated (OUTPUT) |
| `ipv6-rh0.yml` | IPv6 packets with a type 0 routing header (deprecated, RFC 5095) |
| `tcp-small-mss.yml` | TCP SYNs advertising MSS ≤ 500 |
| `container-egress-backstop.yml` | Diego cells only: app-container traffic to BOSH director/agent and NATS ports (defense in depth behind ASGs; ships in monitor mode, needs your overlay CIDR) |

Combine several by listing their entries under one `netfilter_guard.rules`.

## What this can and can't mitigate

A packet filter stops bugs whose trigger is visible in packet headers, such as kernel network-stack bugs reached
through unusual packet shapes. It can't stop application-layer RCEs, where the payload sits inside HTTP or TLS
(language-runtime bugs, decompression bugs like the Brotli "HTTP2Shell" class). For those, it can only help
contain what a compromised container reaches afterwards. [docs/mitigation-matrix.md](docs/mitigation-matrix.md)
maps recent vulnerability classes to the controls that work. It also compares this release with os-conf's
`iptables` and `pre-start-script` jobs, with an os-conf example in `examples/os-conf-iptables.yml`.

## Rolling out a mitigation

1. **Canary in monitor mode.** One low-risk deployment, `mode: monitor`. Check
   `netfilter-guard status`: counters should stay at or near 0 under normal load.
2. **Prove it blocks.** Switch the canary to `enforce` and test from outside. For the IPv4-options profile,
   `tools/probe-ip-options.py HOST PORT` (unprivileged) sends a plain SYN and a SYN with a Record Route
   option; expect `connected`, then `no answer`. Run it from a few places (outside the edge, another VM,
   inside a container). Don't assume the network in between strips IP options: many don't.
3. **Widen** the runtime config's `include:` one deployment or environment at a time. VMs pick up changes
   on their next deploy; on-demand service instances pick them up on their next upgrade/redeploy.
4. **Retire** when the fix ships: set `enabled: false` and deploy, *then* remove the add-on. Removing the
   add-on first leaves the unit installed on existing VMs until they're recreated, because a job that's
   no longer present has no hook to clean up.

## Limits

- **Host network stack only.** The rules see packets that cross the host namespace's netfilter hooks:
  everything arriving at the VM (PREROUTING) and everything it sends (OUTPUT). They don't see:
  - **loopback inside a container's own namespace.** Code already running in a container can send the packet
    to itself; only the real fix closes that;
  - **bridged traffic, unless `br_netfilter` is enabled.** If containers on a host share a Linux bridge,
    container-to-container frames are switched without passing the host's IP hooks. Overlays that *route*
    through the host (each container on its own veth with host routes, VXLAN decapsulated by the host) do pass
    them. Check your container networking before claiming container-to-container coverage, and test it.
- **Fail-open gaps.** A new or recreated VM is unprotected from when its network comes up until BOSH runs
  pre-start, typically a few minutes. At boot the rules load before networking, but that is ordering, not a
  hard dependency: if apply fails, networking still starts, the unit retries every 10 s, and the reconcile
  timer re-checks every 2 minutes. Keep an upstream control (a full-proxy load balancer or an edge firewall
  rule) in place while you roll out and whenever VMs are being recreated.
- **Edge devices are separate.** Full-proxy load balancers already open fresh connections to backends, but
  pass-through / NAT / DSR load balancers forward the client's packet as is. Their own OS needs checking too.
- **IPv6 disabled = v6 rules skipped.** Standard BOSH stemcells boot with IPv6 disabled (no
  `/proc/net/if_inet6`), so there's no IPv6 traffic to filter. `apply` logs that it skipped the v6 rules,
  and `status` reports them as skipped rather than missing. `family: both` therefore works everywhere.
- **Re-applying resets counters.** Each deploy and each reboot refills the chains, so counters count from
  the last apply; a `reconcile` with no drift leaves them alone. Read them (`netfilter-guard status`, or
  `tools/evidence.sh`) before you redeploy.
- **Owns the `NFG-` prefix.** Every chain named `NFG-<hook>` in raw/mangle/filter is treated as ours. Don't
  create chains with that prefix by other means.
- **Cost:** one `u32` header test per packet in the chain's hook. That's small, but it hasn't been
  benchmarked at very high packet rates.
- Requires `iptables`/`ip6tables` ≥ 1.6.2 (for `-w` on restore); both the legacy and nf_tables backends work.

## Evidence

Proving a mitigation (or a patch) needs a record per VM, not a spot check. Two read-only tools:

- `tools/evidence.sh` runs on a VM as root and prints `key=value` lines: instance, deployment, stemcell, boot
  time, running kernel and package version, whether that kernel is at or above a fixed version, and the
  guard's unit state, jumps and per-rule counters.
  Pass the fixed version **once per kernel series and flavor** (`--fixed-deb 5.15.0-NNN.NNN`, `aws:5.15.0-NNNN.NNN`;
  the flavor defaults to `generic`), or `--fixed-uname X.Y.Z` for VMs without dpkg. A fix is only compared against
  a kernel of the same series and flavor; with no match the answer is `unknown`, never a cross-series or
  cross-flavor "yes". Duplicate or malformed thresholds are rejected.
- `tools/fleet-evidence.sh OUTDIR [--fixed-deb V]... [--probe 22] [deployment ...]` runs it across every instance
  of the targeted director (one `bosh ssh` per deployment, in parallel within it). With `--probe` it also probes
  each VM from where you run it. Output: raw records per deployment, `summary.tsv` (one row per **expected** VM,
  from `bosh instances`), and `SHA256SUMS`. A VM whose record couldn't be collected gets `record=MISSING`. The
  run then writes `INCOMPLETE` and exits 1, so a partial bundle is never mistaken for a complete one.

- `tools/portwatch.py HOST PORT SECONDS [opts]` connects every 0.25 s and logs each state change with its duration.
  Run it during a deploy, restart or reboot to measure how long a VM was unprotected (`opts` adds an IPv4 option to
  every SYN).

A workable evidence trail:
1. **Baseline:** `fleet-evidence.sh` before you change anything. It shows the affected kernels, and with `--probe`
   that crafted packets get through.
2. **Mitigated:** the same run after rollout. Every row should show `guard_unit=enabled/active`, the rule present
   with target `DROP`, and the options probe getting no answer.
3. **Patched:** the same run after the fixed stemcell is deployed. Every row should show `kernel_fixed=yes`. Then
   retire the guard (`enabled: false`), run it again, and archive all runs with their `SHA256SUMS`.

## Testing

```bash
tests/run.sh
```

Renders the templates with a stand-in for BOSH's `p()`, checks validation, then runs the real script inside
a throwaway user + network namespace (`unshare -rn`): apply twice (idempotent), drop real packets over
loopback, clean up stale chains, remove, and confirm a foreign rule survives. It never touches the host's
firewall. Needs `ruby`, `python3`, `iptables` and unprivileged user namespaces; the namespace part is
skipped if they're unavailable.

## License

Apache-2.0
