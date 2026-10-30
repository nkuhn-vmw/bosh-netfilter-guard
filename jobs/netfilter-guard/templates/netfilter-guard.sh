#!/bin/bash
# netfilter-guard apply|reconcile|remove|status|test FILE...
#   apply      create/refresh the NFG-<hook> chains from $NFG_LIB/rules.v{4,6}, make sure each built-in
#              hook jumps to its chain exactly once at position 1, then remove NFG chains no longer wanted
#   reconcile  run status; only if it fails, log why and apply (keeps counters when nothing drifted)
#   remove     unhook and delete every NFG chain (both families); exits 1 if anything is left behind
#   status     verify every wanted chain: single jump at position 1, and exactly the expected rules
#              (comment + target); print counters; exit 1 on any mismatch
#   test F...  dry-run rules files through iptables-restore --test without changing anything
set -euo pipefail
LIB=${NFG_LIB:-/usr/local/lib/netfilter-guard}
PREFIX=NFG-
TAG=netfilter-guard
TABLES="raw mangle filter"
HOOKS="PREROUTING INPUT FORWARD OUTPUT POSTROUTING"

# note: iptables-nft 1.8.7 (Jammy) prints the matched rule on a successful -C, hence >/dev/null on checks
ipt()     { if [ "$1" = v4 ]; then shift; iptables -w 10 "$@"; else shift; ip6tables -w 10 "$@"; fi; }
restore() { local f=$1; shift; if [ "$f" = v4 ]; then iptables-restore -w 10 "$@"; else ip6tables-restore -w 10 "$@"; fi; }
have()    { if [ "$1" = v4 ]; then command -v iptables >/dev/null; else command -v ip6tables >/dev/null; fi; }
# BOSH stemcells boot with IPv6 disabled (no /proc/net/if_inet6): no IPv6 traffic exists to filter, so skip v6
v6_off()  { [ "$1" = v6 ] && [ ! -e "${NFG_IF_INET6:-/proc/net/if_inet6}" ]; }
log()     { echo "netfilter-guard: $*"; }
valid_hook() { case " $HOOKS " in *" $1 "*) return 0 ;; esac; return 1; }

# "table hook" pairs a rules file wants
wanted_in() {
  [ -f "$1" ] || return 0
  awk -v p="$PREFIX" '/^\*/ {t=substr($1,2)} $1=="-F" && index($2,p)==1 {print t, substr($2,length(p)+1)}' "$1"
}
wanted() { wanted_in "$LIB/rules.$1"; }
# "name target" pairs a rules file expects in table $2 chain NFG-$3 (target "-" = count only)
expected() {
  awk -v t="$2" -v c="$PREFIX$3" '/^\*/ {tab=substr($1,2)} tab==t && $1=="-A" && $2==c {
      n="-"; g="-"
      if (match($0, /--comment "nfg:[a-z0-9-]+"/)) n=substr($0, RSTART+15, RLENGTH-16)
      if (match($0, / -j [^ ]+/)) g=substr($0, RSTART+4, RLENGTH-4)
      print n, g }' "$LIB/rules.$1"
}
# same, read back from the kernel
actual() {
  ipt "$1" -t "$2" -S "$PREFIX$3" 2>/dev/null | awk '$1=="-A" {
      n="-"; g="-"
      if (match($0, /--comment "?nfg:[a-z0-9-]+/)) { s=substr($0, RSTART, RLENGTH); sub(/.*nfg:/, "", s); n=s }
      if (match($0, / -j [^ ]+/)) g=substr($0, RSTART+4, RLENGTH-4)
      print n, g }'
}
# NFG chains that exist on the host, restricted to real hook names
existing() {
  local t
  for t in $TABLES; do
    ipt "$1" -t "$t" -S 2>/dev/null | awk -v t="$t" -v p="$PREFIX" '$1=="-N" && index($2,p)==1 {print t, substr($2,length(p)+1)}' \
      | while read -r t2 h; do valid_hook "$h" && echo "$t2 $h"; done
  done
}
jump() { echo -m comment --comment "$TAG" -j "$PREFIX$1"; }  # hook -> jump rule match/target
# line numbers (1-based, rules only) of our jumps in a built-in hook
jump_lines() {
  ipt "$1" -t "$2" -S "$3" 2>/dev/null | awk -v j="$PREFIX$3" '$1=="-A" {n++; if ($0 ~ ("--comment \"?'"$TAG"'\"? -j " j "$")) print n}'
}

# exactly one jump, at position 1: insert first, then delete any others (highest line first),
# so there is never a moment without a jump
ensure_jump() {
  local fam=$1 t=$2 h=$3 lines
  lines=$(jump_lines "$fam" "$t" "$h" | tr '\n' ' ')
  [ "$lines" = "1 " ] && return 0
  # shellcheck disable=SC2046
  [ "${lines%% *}" = 1 ] || ipt "$fam" -t "$t" -I "$h" 1 $(jump "$h")
  for n in $(jump_lines "$fam" "$t" "$h" | sort -rn); do
    [ "$n" = 1 ] || ipt "$fam" -t "$t" -D "$h" "$n"
  done
}

unhook() {  # family table hook; returns 1 if the chain could not be removed
  local fam=$1 t=$2 h=$3 n
  for n in $(jump_lines "$fam" "$t" "$h" | sort -rn); do ipt "$fam" -t "$t" -D "$h" "$n"; done
  ipt "$fam" -t "$t" -F "$PREFIX$h" 2>/dev/null || true
  if ! ipt "$fam" -t "$t" -X "$PREFIX$h" 2>/dev/null; then
    log "could not delete $fam $t/$PREFIX$h (still referenced?)" >&2; return 1
  fi
}

# rules file + chain declarations, so --test can check it without the chains existing
test_file() {
  local fam=$1 f=$2
  awk -v p="$PREFIX" '/^\*/ {print; t=substr($1,2); next}
      $1=="-F" && index($2,p)==1 {print ":" $2 " - [0:0]"; next} {print}' "$f" | restore "$fam" --test --noflush
}

apply_family() {
  local fam=$1 want t h
  want=$(wanted "$fam")
  if v6_off "$fam"; then
    [ -n "$want" ] && log "IPv6 is disabled on this host; skipping $(grep -c '^-A' "$LIB/rules.v6") v6 rule(s)"
    remove_family v6; return 0
  fi
  if ! have "$fam"; then
    [ -z "$want" ] && return 0
    log "rules.$fam has rules but $fam tooling is unavailable" >&2; return 1
  fi
  if [ -n "$want" ]; then
    while read -r t h; do ipt "$fam" -t "$t" -N "$PREFIX$h" 2>/dev/null || true; done <<<"$want"
    restore "$fam" --noflush < "$LIB/rules.$fam"   # flush + refill of our chains, atomic per table
    while read -r t h; do ensure_jump "$fam" "$t" "$h"; done <<<"$want"
  fi
  # only after the wanted chains are in place: drop the ones no longer wanted
  local rc=0
  while read -r t h; do
    [ -n "$t" ] || continue
    grep -qxF "$t $h" <<<"$want" || { log "removing stale $fam $t/$PREFIX$h"; unhook "$fam" "$t" "$h" || rc=1; }
  done < <(existing "$fam")
  return $rc
}

remove_family() {
  have "$1" || return 0
  local t h rc=0
  while read -r t h; do [ -n "$t" ] && { unhook "$1" "$t" "$h" || rc=1; }; done < <(existing "$1")
  return $rc
}

status_family() {
  local fam=$1 want t h rc=0 lines exp act
  want=$(wanted "$fam")
  [ -n "$want" ] || return 0
  if v6_off "$fam"; then echo "== $fam skipped (IPv6 disabled on this host)"; return 0; fi
  while read -r t h; do
    echo "== $fam $t $PREFIX$h"
    lines=$(jump_lines "$fam" "$t" "$h" | tr '\n' ' ')
    case "$lines" in
      "1 ") ;;
      "") echo "   MISSING jump from $h"; rc=1 ;;
      *) echo "   jump from $h not exactly once at position 1 (rule lines: $lines)"; rc=1 ;;
    esac
    if ! ipt "$fam" -t "$t" -L "$PREFIX$h" -v -n -x 2>/dev/null; then echo "   MISSING chain"; rc=1; continue; fi
    exp=$(expected "$fam" "$t" "$h"); act=$(actual "$fam" "$t" "$h")
    if [ "$exp" != "$act" ]; then
      echo "   rules differ from $LIB/rules.$fam"
      diff <(echo "$exp") <(echo "$act") | sed -n 's/^</   expected:/p; s/^>/   found:   /p'
      rc=1
    fi
  done <<<"$want"
  return $rc
}

status_all() { local rc=0; status_family v4 || rc=1; status_family v6 || rc=1; return $rc; }

case "${1:-status}" in
  apply)     rc=0; apply_family v4 || rc=1; apply_family v6 || rc=1; exit $rc ;;
  reconcile) if out=$(status_all 2>&1); then exit 0; fi
             log "drift detected, re-applying:"; grep -E 'MISSING|differ|position|expected|found' <<<"$out" | sed 's/^/  /' || true
             exec "$0" apply ;;
  remove)    rc=0; remove_family v4 || rc=1; remove_family v6 || rc=1; exit $rc ;;
  status)    status_all ;;
  test)      shift; rc=0
             for f in "$@"; do
               case $f in *.v6) fam=v6 ;; *) fam=v4 ;; esac
               [ -n "$(wanted_in "$f")" ] || continue
               if v6_off "$fam" || ! have "$fam"; then continue; fi
               test_file "$fam" "$f" || { log "$f failed iptables-restore --test" >&2; rc=1; }
             done; exit $rc ;;
  *) echo "usage: $0 apply|reconcile|remove|status|test FILE..." >&2; exit 2 ;;
esac
