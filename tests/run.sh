#!/bin/bash
# Template rendering + validation tests, then (if possible) an end-to-end apply/remove test inside a
# throwaway user+network namespace, so the host's own firewall is never touched.
set -uo pipefail
cd "$(dirname "$0")/.."
T=jobs/netfilter-guard/templates
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok()  { echo "ok   $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
render() { ruby tests/render.rb "$T/$1" "$2"; }
props() { cat > "$W/props.yml"; }

# 1. profiles render into restore files with the expected rules
{ echo "netfilter_guard:"; echo "  rules:"; cat profiles/*.yml | grep -v '^#' | sed 's/^/  /'; } > "$W/all.yml"
render rules.v4.erb "$W/all.yml" > "$W/rules.v4" && render rules.v6.erb "$W/all.yml" > "$W/rules.v6" \
  && ok "profiles render" || bad "profiles render"
grep -q -- '-A NFG-PREROUTING -p tcp -m u32 --u32 "0>>24&0x0F=6:15" -m comment --comment "nfg:ipv4-options-tcp" -j DROP' "$W/rules.v4" \
  && ok "ipv4-options rule in v4" || bad "ipv4-options rule in v4"
grep -q 'nfg:ipv4-options-tcp' "$W/rules.v6" && bad "ipv4-only rule leaked into v6" || ok "ipv4-only rule absent from v6"
grep -q 'nfg:ipv6-rh0' "$W/rules.v6" && ! grep -q 'nfg:ipv6-rh0' "$W/rules.v4" && ok "ipv6-only rule in v6 only" || bad "ipv6-only rule placement"
[ "$(grep -c 'nfg:tcp-small-mss' "$W/rules.v4" "$W/rules.v6" | awk -F: '{s+=$2} END {print s}')" = 2 ] \
  && ok "family both -> v4 and v6" || bad "family both"

# 2. monitor mode drops the target
printf 'netfilter_guard:\n  mode: monitor\n  rules:\n  - {name: a, match: "-p tcp"}\n  - {name: b, match: "-p udp", mode: enforce, target: REJECT}\n' | props
out=$(render rules.v4.erb "$W/props.yml")
grep -q 'nfg:a"$' <<<"$out" && grep -q 'nfg:b" -j REJECT$' <<<"$out" && ok "monitor mode + per-rule override" || bad "monitor mode"

# 3. disabled -> empty rule files
printf 'netfilter_guard:\n  enabled: false\n  rules:\n  - {name: a, match: "-p tcp"}\n' | props
[ -z "$(render rules.v4.erb "$W/props.yml" | grep -v '^#')" ] && ok "disabled renders no rules" || bad "disabled"
render pre-start.erb "$W/props.yml" | grep -q 'netfilter-guard remove' && ok "disabled pre-start removes" || bad "disabled pre-start"

# 4. validation rejects bad input at render time (i.e. the deploy fails before touching VMs)
reject() {
  printf 'netfilter_guard:\n  rules:\n  - %s\n' "$2" | props
  render rules.v4.erb "$W/props.yml" >/dev/null 2>&1 && bad "rejects $1" || ok "rejects $1"
}
reject "bad name"            '{name: "Bad_Name", match: "-p tcp"}'
reject "missing match"       '{name: a}'
reject "target in match"     '{name: a, match: "-p tcp -j ACCEPT"}'
reject "invalid hook"        '{name: a, table: filter, match: "-p tcp"}'
reject "unknown table"       '{name: a, table: nat, match: "-p tcp"}'
reject "unknown family"      '{name: a, family: ipv5, match: "-p tcp"}'
printf 'netfilter_guard:\n  rules:\n  - {name: a, match: "-p tcp"}\n  - {name: a, match: "-p udp"}\n' | props
render rules.v4.erb "$W/props.yml" >/dev/null 2>&1 && bad "rejects duplicate names" || ok "rejects duplicate names"

# 5. end-to-end in a private namespace (needs unprivileged user namespaces + iptables)
e2e() {
  local L=$W/lib; mkdir -p "$L"; cp "$W/rules.v4" "$W/rules.v6" "$L/"
  NFG_LIB=$L unshare -rn bash -c '
    set -e; S=jobs/netfilter-guard/templates/netfilter-guard.sh
    iptables -t raw -A PREROUTING -p icmp -j ACCEPT          # a foreign rule that must survive
    bash $S apply; bash $S apply                             # idempotent
    [ "$(iptables -t raw -S PREROUTING | grep -c NFG-PREROUTING)" = 1 ] || { echo "jump not unique"; exit 1; }
    iptables -t raw -S PREROUTING | sed -n 2p | grep -q NFG-PREROUTING || { echo "jump not first"; exit 1; }
    bash $S status >/dev/null
    # real packets over loopback (lo also traverses raw PREROUTING)
    ip link set lo up
    python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"127.0.0.1\",18080));s.listen(8);time.sleep(30)" & L=$!
    sleep 0.5
    out=$(python3 tools/probe-ip-options.py 127.0.0.1 18080 2)
    kill $L
    grep -q "plain SYN *-> connected" <<<"$out" || { echo "plain SYN blocked: $out"; exit 1; }
    grep -q "options -> no answer" <<<"$out" || { echo "options SYN not dropped: $out"; exit 1; }
    iptables -t raw -L NFG-PREROUTING -v -n -x | grep "nfg:ipv4-options-tcp" | awk "{exit !(\$1>0)}" || { echo "counter did not move"; exit 1; }
    : > "$NFG_LIB/rules.v6"; bash $S apply                   # dropping v6 rules removes the stale v6 chain
    ! ip6tables -t raw -S | grep -q NFG- || { echo "stale v6 chain kept"; exit 1; }
    bash $S remove
    ! iptables -t raw -S | grep -q NFG- || { echo "remove left chains"; exit 1; }
    iptables -t raw -S PREROUTING | grep -q "icmp -j ACCEPT" || { echo "foreign rule lost"; exit 1; }
  '
}
if unshare -rn true 2>/dev/null && command -v iptables >/dev/null && unshare -rn iptables -t raw -S >/dev/null 2>&1; then
  e2e && ok "apply/idempotent/packet-drop/stale-cleanup/remove in netns" || bad "netns end-to-end"
else
  echo "skip netns end-to-end (no unprivileged user namespaces or iptables)"
fi

echo "$pass passed, $fail failed"; [ $fail = 0 ]
