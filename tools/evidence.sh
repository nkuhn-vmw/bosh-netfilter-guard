#!/bin/bash
# Prints one VM's evidence record as key=value lines: identity, stemcell, running kernel, whether that
# kernel is at/above a fixed version, and the netfilter-guard state with per-rule counters.
# Run as root on the VM (e.g. via `bosh ssh -c`). Read-only.
#   evidence.sh [--fixed-deb VERSION]... [--fixed-uname VERSION]...
#     --fixed-deb    fixed linux-image package version (Debian/Ubuntu), e.g. 5.15.0-999.999; repeat once per
#                    kernel series (5.15.0, 6.8.0, ...). Only a fix for the VM's own series is compared;
#                    with none, kernel_fixed=unknown (never compare across series).
#     --fixed-uname  fixed upstream version for VMs without dpkg, e.g. 7.2.10; also per series (major.minor)
set -uo pipefail
FIXED_DEB=() FIXED_UNAME=()
while [ $# -gt 0 ]; do
  case $1 in
    --fixed-deb) FIXED_DEB+=("$2"); shift 2 ;;
    --fixed-uname) FIXED_UNAME+=("$2"); shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
kv() { printf '%s=%s\n' "$1" "$2"; }
first() { for f in "$@"; do [ -r "$f" ] && { tr -d '\n' < "$f"; return; }; done; echo -n unknown; }

kv collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
kv instance "$(first /var/vcap/instance/name)/$(first /var/vcap/instance/id)"
kv deployment "$(first /var/vcap/instance/deployment)"
kv stemcell "$(first /var/vcap/bosh/etc/operating_system)/$(first /var/vcap/bosh/etc/stemcell_version)"
kv booted_at "$(date -u -d "$(uptime -s)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
K=$(uname -r); kv kernel_running "$K"

fixed=unknown
if command -v dpkg-query >/dev/null; then
  pkg=$(dpkg-query -W -f='${Version}' "linux-image-$K" 2>/dev/null || true)
  kv kernel_package "linux-image-$K=${pkg:-unknown}"
  for f in "${FIXED_DEB[@]}"; do   # same series = same upstream version before the first '-'
    [ -n "$pkg" ] && [ "${f%%-*}" = "${pkg%%-*}" ] || continue
    dpkg --compare-versions "$pkg" ge "$f" && fixed=yes || fixed=no
    kv kernel_fixed_in "$f"
  done
fi
if [ "$fixed" = unknown ]; then
  up=${K%%-*}
  for f in "${FIXED_UNAME[@]}"; do  # same series = same major.minor
    [ "$(cut -d. -f1-2 <<<"$f")" = "$(cut -d. -f1-2 <<<"$up")" ] || continue
    [ "$(printf '%s\n%s\n' "$f" "$up" | sort -V | head -1)" = "$f" ] && fixed=yes || fixed=no
    kv kernel_fixed_in "$f"
  done
fi
kv kernel_fixed "$fixed"

if command -v systemctl >/dev/null && systemctl cat netfilter-guard.service >/dev/null 2>&1; then
  kv guard_unit "$(systemctl is-enabled netfilter-guard 2>/dev/null)/$(systemctl is-active netfilter-guard 2>/dev/null)"
  L=/usr/local/lib/netfilter-guard
  kv guard_rules_sha256 "$(cat $L/rules.v4 $L/rules.v6 2>/dev/null | sha256sum | cut -c1-16)"
  for fam in v4 v6; do
    cmd=iptables; [ $fam = v6 ] && cmd=ip6tables
    [ $fam = v6 ] && [ ! -e /proc/net/if_inet6 ] && { kv guard_v6 "skipped (IPv6 disabled)"; continue; }
    for t in raw mangle filter; do
      $cmd -w 5 -t $t -S 2>/dev/null | awk '$1=="-N" && $2 ~ /^NFG-/ {print $2}' | while read -r c; do
        h=${c#NFG-}
        $cmd -w 5 -t $t -C "$h" -m comment --comment netfilter-guard -j "$c" >/dev/null 2>&1 && j=present || j=MISSING
        kv "guard_jump_${fam}_${t}_${h}" "$j"
        $cmd -w 5 -t $t -L "$c" -v -n -x 2>/dev/null | awk -v f=$fam -v t=$t 'match($0, /\/\* nfg:[a-z0-9-]+ \*\//) {
            n=substr($0, RSTART+7, RLENGTH-10); tgt=($3 ~ /^[A-Z]/) ? $3 : "count-only";
            printf "guard_rule_%s_%s_%s=%s pkts, target %s\n", f, t, n, $1, tgt }'
      done
    done
  done
else
  kv guard_unit absent
fi
