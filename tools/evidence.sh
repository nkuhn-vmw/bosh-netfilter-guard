#!/bin/bash
# Prints one VM's evidence record as key=value lines: identity, stemcell, running kernel, whether that
# kernel is at/above a fixed version, and the netfilter-guard state with per-rule counters.
# Run as root on the VM (e.g. via `bosh ssh -c`). Read-only.
#   evidence.sh [--fixed-deb VERSION]... [--fixed-uname VERSION]...
#     --fixed-deb    [FLAVOR:]VERSION of the fixed linux-image package (Debian/Ubuntu), e.g. 5.15.0-999.999 or
#                    aws:5.15.0-1099.106. FLAVOR defaults to "generic". Repeat once per series and flavor. A fix is
#                    compared only against a kernel of the same series AND flavor; with no match the result is
#                    kernel_fixed=unknown (never a cross-series or cross-flavor yes). Duplicates are rejected.
#     --fixed-uname  fixed upstream version for VMs without dpkg, e.g. 7.2.10; also per series (major.minor)
set -uo pipefail
FIXED_DEB=() FIXED_UNAME=()
while [ $# -gt 0 ]; do
  case $1 in
    --fixed-deb) v=$2; [[ $v == *:* ]] || v="generic:$v"; FIXED_DEB+=("$v"); shift 2 ;;
    --fixed-uname) FIXED_UNAME+=("$2"); shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
kv() { printf '%s=%s\n' "$1" "$2"; }
# reject malformed or duplicate thresholds (a later, older threshold would otherwise override a "no")
seen=" "
for v in "${FIXED_DEB[@]}"; do
  [[ $v =~ ^[a-z0-9.+-]+:[0-9]+\.[0-9]+\.[0-9]+-[0-9][0-9A-Za-z.+~-]*$ ]] || { echo "bad --fixed-deb $v" >&2; exit 2; }
  key="${v%%:*}:${v#*:}"; key="${key%%-*}"
  [[ $seen == *" $key "* ]] && { echo "duplicate --fixed-deb for series/flavor ${key}" >&2; exit 2; }
  seen+="$key "
done
for v in "${FIXED_UNAME[@]}"; do
  [[ $v =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo "bad --fixed-uname $v" >&2; exit 2; }
  key=$(cut -d. -f1-2 <<<"$v"); [[ $seen == *" u$key "* ]] && { echo "duplicate --fixed-uname for $key" >&2; exit 2; }
  seen+="u$key "
done
first() { for f in "$@"; do [ -r "$f" ] && { tr -d '\n' < "$f"; return; }; done; echo -n unknown; }

kv collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
kv instance "$(first /var/vcap/instance/name)/$(first /var/vcap/instance/id)"
kv deployment "$(first /var/vcap/instance/deployment)"
kv stemcell "$(first /var/vcap/bosh/etc/operating_system)/$(first /var/vcap/bosh/etc/stemcell_version)"
kv booted_at "$(date -u -d "$(uptime -s)" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
K=$(uname -r); kv kernel_running "$K"
FLAVOR=${K##*-}; [[ $FLAVOR =~ ^[0-9] ]] && FLAVOR=generic   # 5.15.0-187-generic -> generic, 5.15.0-1099-aws -> aws

fixed=unknown
if command -v dpkg-query >/dev/null; then
  pkg=$(dpkg-query -W -f='${Version}' "linux-image-$K" 2>/dev/null || true)
  kv kernel_package "linux-image-$K=${pkg:-unknown}"
  kv kernel_flavor "$FLAVOR"
  for fv in "${FIXED_DEB[@]}"; do   # same series = same upstream version before the first '-', same flavor
    f=${fv#*:}
    [ "${fv%%:*}" = "$FLAVOR" ] || continue
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
