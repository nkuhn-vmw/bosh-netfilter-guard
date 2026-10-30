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
grep -q -- '-A NFG-OUTPUT -p tcp -m u32 --u32 "0>>24&0x0F=6:15" -m comment --comment "nfg:ipv4-options-tcp-out" -j DROP' "$W/rules.v4" \
  && ok "ipv4-options OUTPUT rule in v4" || bad "ipv4-options OUTPUT rule"
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
reject "attached -jACCEPT"   '{name: a, match: "-p tcp -jACCEPT"}'
reject "abbreviated --jum"   '{name: a, match: "-p tcp --jum ACCEPT"}'
reject "goto"                '{name: a, match: "-p tcp -g OTHER"}'
reject "NUL in match"        '{name: a, match: "-p tcp\0x"}'
reject "lowercase target"    '{name: a, match: "-p tcp", target: "accept"}'
reject "control char target" '{name: a, match: "-p tcp", target: "DROP\tx"}'
printf 'netfilter_guard:\n  rules:\n  - {name: a, match: "-p tcp -m owner --gid-owner 0"}\n' | props
render rules.v4.erb "$W/props.yml" >/dev/null 2>&1 && ok "allows --gid-owner (not a goto)" || bad "allows --gid-owner"
printf 'netfilter_guard:\n  rules:\n  - {name: a, match: "-p tcp"}\n  - {name: a, match: "-p udp"}\n' | props
render rules.v4.erb "$W/props.yml" >/dev/null 2>&1 && bad "rejects duplicate names" || ok "rejects duplicate names"

# 5. end-to-end in a private namespace (needs unprivileged user namespaces + iptables)
e2e() {
  local L=$W/lib; mkdir -p "$L"; cp "$W/rules.v4" "$W/rules.v6" "$L/"
  # a PREROUTING-only ruleset, to prove the inbound hook on its own
  printf 'netfilter_guard:\n  rules:\n  - {name: in-only, match: "-p tcp -m u32 --u32 \\"0>>24&0x0F=6:15\\""}\n' > "$W/in.yml"
  ruby tests/render.rb "$T/rules.v4.erb" "$W/in.yml" > "$W/rules.in.v4"
  NFG_LIB=$L RIN=$W/rules.in.v4 unshare -rn bash -c '
    set -e; S=jobs/netfilter-guard/templates/netfilter-guard.sh
    fail() { echo "$*"; exit 1; }
    listen() { python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"127.0.0.1\",18080));s.listen(8);time.sleep(20)" & LP=$!; sleep 0.5; }
    probe() { python3 tools/probe-ip-options.py 127.0.0.1 18080 2; }
    cnt() { iptables -t raw -L "NFG-$1" -v -n -x | awk -v n="nfg:$2 " "index(\$0, n) {print \$1}"; }
    ip link set lo up
    iptables -t raw -A PREROUTING -p icmp -j ACCEPT                       # a foreign rule that must survive
    bash $S test "$NFG_LIB/rules.v4" "$NFG_LIB/rules.v6" || fail "valid rules failed --test"
    printf "*raw\n-F NFG-PREROUTING\n-A NFG-PREROUTING -m nosuchmatch -j DROP\nCOMMIT\n" > /tmp/nfg-bad.v4 2>/dev/null || true
    bash $S apply; bash $S apply                                          # idempotent
    [ "$(iptables -t raw -S PREROUTING | grep -c NFG-PREROUTING)" = 1 ] || fail "jump not unique"
    iptables -t raw -S PREROUTING | sed -n 2p | grep -q NFG-PREROUTING || fail "jump not first"
    bash $S status >/dev/null || fail "status failed after apply"

    # outbound hook: the host generating an options SYN is dropped at raw OUTPUT
    listen; out=$(probe); kill $LP; wait $LP 2>/dev/null || true
    grep -q "plain SYN *-> connected" <<<"$out" || fail "plain SYN blocked: $out"
    grep -q "options -> no answer" <<<"$out" || fail "options SYN not dropped: $out"
    [ "$(cnt OUTPUT ipv4-options-tcp-out)" -gt 0 ] || fail "OUTPUT counter did not move"

    # drift: a foreign rule inserted above our jump, a duplicate jump, and an emptied chain
    iptables -t raw -I PREROUTING 1 -p tcp -j ACCEPT
    iptables -t raw -A PREROUTING -m comment --comment netfilter-guard -j NFG-PREROUTING
    ! bash $S status >/dev/null || fail "status missed jump not at position 1"
    bash $S reconcile >/dev/null
    [ "$(iptables -t raw -S PREROUTING | grep -c NFG-PREROUTING)" = 1 ] || fail "reconcile left duplicate jumps"
    iptables -t raw -S PREROUTING | sed -n 2p | grep -q NFG-PREROUTING || fail "reconcile did not restore position 1"
    iptables -t raw -D PREROUTING -p tcp -j ACCEPT
    iptables -t raw -F NFG-OUTPUT
    ! bash $S status >/dev/null || fail "status missed an emptied chain"
    bash $S reconcile >/dev/null; bash $S status >/dev/null || fail "reconcile did not refill the chain"
    a=$(cnt PREROUTING ipv4-options-tcp); bash $S reconcile >/dev/null
    [ "$(cnt PREROUTING ipv4-options-tcp)" = "$a" ] || fail "reconcile re-applied without drift (counters reset)"

    # inbound hook on its own: options SYN dropped at raw PREROUTING
    cp "$NFG_LIB/rules.v4" /dev/null; cp "$RIN" "$NFG_LIB/rules.v4"; bash $S apply >/dev/null
    iptables -t raw -S | grep -q NFG-OUTPUT && fail "stale OUTPUT chain kept"
    listen; out=$(probe); kill $LP; wait $LP 2>/dev/null || true
    grep -q "options -> no answer" <<<"$out" || fail "PREROUTING did not drop: $out"
    [ "$(cnt PREROUTING in-only)" -gt 0 ] || fail "PREROUTING counter did not move"

    # IPv6-off handling, then removal
    NFG_IF_INET6=/nonexistent bash $S apply | grep -q "IPv6 is disabled" || true
    NFG_IF_INET6=/nonexistent bash $S status >/dev/null || fail "status fails with IPv6 off"
    bash $S remove || fail "remove reported failure"
    ! iptables -t raw -S | grep -q NFG- || fail "remove left chains"
    iptables -t raw -S PREROUTING | grep -q "icmp -j ACCEPT" || fail "foreign rule lost"
  '
}
if unshare -rn true 2>/dev/null && command -v iptables >/dev/null && unshare -rn iptables -t raw -S >/dev/null 2>&1; then
  e2e && ok "netns: --test, apply, OUTPUT+PREROUTING packet drops, drift repair, counters kept, remove" || bad "netns end-to-end"
  # iptables-restore --test rejects a syntactically bad ruleset
  printf '*raw\n-F NFG-PREROUTING\n-A NFG-PREROUTING -m nosuchmatch -j DROP\nCOMMIT\n' > "$W/bad.v4"
  unshare -rn bash jobs/netfilter-guard/templates/netfilter-guard.sh test "$W/bad.v4" >/dev/null 2>&1 \
    && bad "--test accepted a bad ruleset" || ok "--test rejects a bad ruleset"
else
  echo "skip netns end-to-end (no unprivileged user namespaces or iptables)"
fi

# 6. evidence.sh compares a fix only within the VM's own kernel series
if command -v dpkg-query >/dev/null && dpkg-query -W "linux-image-$(uname -r)" >/dev/null 2>&1; then
  pkg=$(dpkg-query -W -f='${Version}' "linux-image-$(uname -r)"); ser=${pkg%%-*}
  ev() { bash tools/evidence.sh "$@" 2>/dev/null | sed -n 's/^kernel_fixed=//p'; }
  [ "$(ev --fixed-deb 0.0.1-1.1)" = unknown ] && ok "evidence: other-series fix -> unknown" || bad "evidence: cross-series"
  [ "$(ev --fixed-deb "$ser-1.1")" = yes ] && ok "evidence: older fix in series -> yes" || bad "evidence: older fix"
  [ "$(ev --fixed-deb "$ser-99999.1")" = no ] && ok "evidence: newer fix in series -> no" || bad "evidence: newer fix"
  [ "$(ev --fixed-deb "nosuchflavor:$ser-1.1")" = unknown ] && ok "evidence: other-flavor fix -> unknown" || bad "evidence: cross-flavor"
  bash tools/evidence.sh --fixed-deb "$ser-99999.1" --fixed-deb "$ser-1.1" >/dev/null 2>&1 \
    && bad "evidence: accepted duplicate series" || ok "evidence: rejects duplicate series"
else
  echo "skip evidence.sh series tests (no dpkg kernel package)"
fi

# 7. fleet-evidence never reports an incomplete run as complete (fake bosh: one VM's record missing)
mkdir -p "$W/fb"; cat > "$W/fb/bosh" <<'FAKE'
#!/bin/bash
case "$*" in
  *"instances --json"*) echo '{"Tables":[{"Rows":[{"instance":"web/1","ips":"192.0.2.1"},{"instance":"web/2","ips":"192.0.2.2"},{"instance":"errand/1","ips":""}]}]}' ;;
  *ssh*) printf '{"Tables":[{"Rows":[{"instance":"web/1","stdout":"collected_at=2026-01-01T00:00:00Z\\nkernel_running=5.15.0-1-generic\\nkernel_fixed=no\\nguard_unit=absent\\n"}]}]}'; exit 1 ;;
esac
FAKE
chmod +x "$W/fb/bosh"
if PATH="$W/fb:$PATH" bash tools/fleet-evidence.sh "$W/fe" dep >/dev/null 2>&1; then bad "fleet: incomplete run exited 0"; else
  [ -f "$W/fe/INCOMPLETE" ] && [ "$(awk -F'\t' '$2=="web/2" {print $3}' "$W/fe/summary.tsv")" = MISSING ] \
    && [ "$(awk -F'\t' '$2=="web/1" {print $3"/"$6}' "$W/fe/summary.tsv")" = ok/no ] \
    && ! grep -q errand "$W/fe/summary.tsv" && ok "fleet: missing VM row, INCOMPLETE marker, exit 1" || bad "fleet: completeness"
fi

echo "$pass passed, $fail failed"; [ $fail = 0 ]
