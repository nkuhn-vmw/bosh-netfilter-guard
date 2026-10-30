#!/bin/bash
# netfilter-guard apply|remove|status
#   apply   create/refresh the NFG-<hook> chains from $NFG_LIB/rules.v{4,6}, hook them in at position 1,
#           and remove NFG chains that are no longer wanted
#   remove  unhook and delete every NFG chain (both families)
#   status  print counters per chain; exit 1 if a wanted chain or its jump is missing
set -euo pipefail
LIB=${NFG_LIB:-/usr/local/lib/netfilter-guard}
PREFIX=NFG-
TAG=netfilter-guard
TABLES="raw mangle filter"

# note: iptables-nft 1.8.7 (Jammy) prints the matched rule on a successful -C, hence >/dev/null on checks
ipt()     { if [ "$1" = v4 ]; then shift; iptables -w 10 "$@"; else shift; ip6tables -w 10 "$@"; fi; }
restore() { if [ "$1" = v4 ]; then iptables-restore -w 10 --noflush; else ip6tables-restore -w 10 --noflush; fi; }
have()    { if [ "$1" = v4 ]; then command -v iptables >/dev/null; else command -v ip6tables >/dev/null && [ -e /proc/net/if_inet6 ]; fi; }

# "table hook" pairs the rendered file wants
wanted() {
  [ -f "$LIB/rules.$1" ] || return 0
  awk -v p="$PREFIX" '/^\*/ {t=substr($1,2)} $1=="-F" && index($2,p)==1 {print t, substr($2,length(p)+1)}' "$LIB/rules.$1"
}
# "table hook" pairs that exist on the host
existing() {
  local t
  for t in $TABLES; do
    ipt "$1" -t "$t" -S 2>/dev/null | awk -v t="$t" -v p="$PREFIX" '$1=="-N" && index($2,p)==1 {print t, substr($2,length(p)+1)}'
  done
}
jump() { echo -m comment --comment "$TAG" -j "$PREFIX$1"; }  # hook -> jump rule match/target

unhook() {  # family table hook
  local fam=$1 t=$2 h=$3
  # shellcheck disable=SC2046
  while ipt "$fam" -t "$t" -C "$h" $(jump "$h") >/dev/null 2>&1; do ipt "$fam" -t "$t" -D "$h" $(jump "$h"); done
  ipt "$fam" -t "$t" -F "$PREFIX$h" 2>/dev/null || true
  ipt "$fam" -t "$t" -X "$PREFIX$h" 2>/dev/null || true
}

apply_family() {
  local fam=$1 want t h
  want=$(wanted "$fam")
  if ! have "$fam"; then
    [ -z "$want" ] && return 0
    echo "netfilter-guard: rules.$fam has rules but $fam tooling/stack is unavailable" >&2; return 1
  fi
  existing "$fam" | while read -r t h; do
    grep -qxF "$t $h" <<<"$want" || { echo "netfilter-guard: removing stale $fam $t/$PREFIX$h"; unhook "$fam" "$t" "$h"; }
  done
  [ -n "$want" ] || return 0
  while read -r t h; do ipt "$fam" -t "$t" -N "$PREFIX$h" 2>/dev/null || true; done <<<"$want"
  restore "$fam" < "$LIB/rules.$fam"   # flush + refill of our chains, atomic per table
  # shellcheck disable=SC2046
  while read -r t h; do
    ipt "$fam" -t "$t" -C "$h" $(jump "$h") >/dev/null 2>&1 || ipt "$fam" -t "$t" -I "$h" 1 $(jump "$h")
  done <<<"$want"
}

remove_family() {
  have "$1" || return 0
  local t h
  existing "$1" | while read -r t h; do unhook "$1" "$t" "$h"; done
}

status_family() {
  local fam=$1 want t h rc=0
  want=$(wanted "$fam")
  [ -n "$want" ] || return 0
  while read -r t h; do
    echo "== $fam $t $PREFIX$h"
    # shellcheck disable=SC2046
    if ! ipt "$fam" -t "$t" -C "$h" $(jump "$h") >/dev/null 2>&1; then echo "   MISSING jump from $h"; rc=1; fi
    ipt "$fam" -t "$t" -L "$PREFIX$h" -v -n -x 2>/dev/null || { echo "   MISSING chain"; rc=1; }
  done <<<"$want"
  return $rc
}

case "${1:-status}" in
  apply)  apply_family v4; apply_family v6 ;;
  remove) remove_family v4; remove_family v6 ;;
  status) rc=0; status_family v4 || rc=1; status_family v6 || rc=1; exit $rc ;;
  *) echo "usage: $0 apply|remove|status" >&2; exit 2 ;;
esac
