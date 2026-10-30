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
pre-start (each deploy)                       boot
  render rules.v4 / rules.v6  ──┐               │
  install to /usr/local/...     ├─► netfilter-guard.service ─► netfilter-guard apply
  enable + reload unit        ──┘  (Before=network-pre.target)
```

`netfilter-guard apply`, for each family:
1. removes `NFG-*` chains the current rules no longer need;
2. creates any missing `NFG-<hook>` chains;
3. loads the rendered file with `iptables-restore --noflush`, which flushes and refills our chains
   atomically per table;
4. makes sure the built-in hook jumps to our chain at position 1.

The script, rule files and unit are installed on the **root disk** (`/usr/local/sbin`,
`/usr/local/lib/netfilter-guard`, `/etc/systemd/system`). This matters: `/var/vcap/jobs` is rebuilt by the
BOSH agent only *after* boot, and pre-start doesn't run on a reboot. A unit that points into the job
directory fails at boot with `203/EXEC`, leaving the VM unprotected until the next deploy.

## Quick start

```bash
bosh create-release --force --version 0.1.0 --tarball netfilter-guard-0.1.0.tgz
bosh upload-release netfilter-guard-0.1.0.tgz
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

Invalid rules fail **template rendering**, so a bad manifest stops the deploy before any VM changes.

**Why `raw` / `PREROUTING` is the default:** the raw table runs before conntrack, routing and DNAT. A drop
there also covers traffic that's DNAT'd or forwarded to containers on the host (e.g. a Diego cell), and
the dropped packet never creates conntrack state.

## Profiles

`profiles/` holds ready-to-paste rule lists:

| Profile | Drops |
|---|---|
| `ipv4-options.yml` | TCP packets whose IPv4 header carries options (IHL > 5) |
| `ipv6-rh0.yml` | IPv6 packets with a type 0 routing header (deprecated, RFC 5095) |
| `tcp-small-mss.yml` | TCP SYNs advertising MSS ≤ 500 |

Combine several by listing their entries under one `netfilter_guard.rules`.

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

- **Host stack only.** Traffic that never crosses a host netfilter hook isn't seen. In particular, loopback
  traffic inside a container's own network namespace stays in that namespace. Code already running in a
  container can still send the packet to itself; only the real fix closes that.
- **Edge devices are separate.** Full-proxy load balancers already open fresh connections to backends, but
  pass-through / NAT / DSR load balancers forward the client's packet as is. Their own OS needs checking too.
- **IPv6 disabled = v6 rules skipped.** Standard BOSH stemcells boot with IPv6 disabled (no
  `/proc/net/if_inet6`), so there's no IPv6 traffic to filter. `apply` logs that it skipped the v6 rules,
  and `status` reports them as skipped rather than missing. `family: both` therefore works everywhere.
- **Re-applying resets counters.** Each deploy and each reboot refills the chains, so counters count from
  the last apply. Read them (`netfilter-guard status`, or `tools/evidence.sh`) before you redeploy.
- Requires `iptables`/`ip6tables` ≥ 1.6.2 (for `-w` on restore); both the legacy and nf_tables backends work.

## Evidence

Proving a mitigation (or a patch) needs a record per VM, not a spot check. Two read-only tools:

- `tools/evidence.sh` runs on a VM as root and prints `key=value` lines: instance, deployment, stemcell, boot
  time, running kernel and package version, whether that kernel is at or above a fixed version, and the
  guard's unit state, jumps and per-rule counters.
  Pass the fixed version **once per kernel series** (`--fixed-deb 5.15.0-NNN.NNN --fixed-deb 6.8.0-NNN.NNN`,
  or `--fixed-uname X.Y.Z` for VMs without dpkg). A fix is only compared against a kernel of the same series;
  with no match the answer is `unknown`, never a cross-series "yes".
- `tools/fleet-evidence.sh OUTDIR [--fixed-deb V]... [--probe 22] [deployment ...]` runs it across every instance
  of the targeted director (one `bosh ssh` per deployment, in parallel within it). With `--probe` it also probes
  each VM from where you run it. Output: raw records per deployment, `summary.tsv` (one row per VM) and `SHA256SUMS`.

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
