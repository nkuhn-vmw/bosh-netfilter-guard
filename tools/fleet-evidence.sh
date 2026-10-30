#!/bin/bash
# Runs tools/evidence.sh on every instance of the given deployments (default: all) on the targeted BOSH
# director, and optionally probes each instance from here. Writes OUTDIR/<deployment>.txt (raw records),
# OUTDIR/summary.tsv (one row per VM) and OUTDIR/SHA256SUMS. Read-only on the VMs.
#   BOSH_ENVIRONMENT=... fleet-evidence.sh OUTDIR [--fixed-deb V]... [--fixed-uname V]... [--probe PORT] [deployment ...]
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?usage: $0 OUTDIR [--fixed-deb V]... [--fixed-uname V]... [--probe PORT] [deployment ...]}; shift
ARGS=() PROBE= DEPS=()
while [ $# -gt 0 ]; do
  case $1 in
    --fixed-deb|--fixed-uname) ARGS+=("$1" "$2"); shift 2 ;;
    --probe) PROBE=$2; shift 2 ;;
    *) DEPS+=("$1"); shift ;;
  esac
done
mkdir -p "$OUT"
[ ${#DEPS[@]} -gt 0 ] || mapfile -t DEPS < <(bosh deployments --json | jq -r '.Tables[0].Rows[].name')
SCRIPT=$(base64 -w0 "$HERE/evidence.sh")
printf 'deployment\tinstance\tstemcell\tkernel\tkernel_fixed\tguard_unit\tguard_rules\tprobe_plain\tprobe_options\tcollected_at\n' > "$OUT/summary.tsv"

for d in "${DEPS[@]}"; do
  echo "== $d" >&2
  bosh -d "$d" ssh -r --json -c "echo $SCRIPT | base64 -d | sudo bash -s -- ${ARGS[*]}" 2>/dev/null \
    | jq -r '.Tables[0].Rows[] | "### \(.instance)\n\(.stdout)"' > "$OUT/$d.txt"
  ips=$(bosh -d "$d" instances --json 2>/dev/null | jq -r '.Tables[0].Rows[] | "\(.instance)\t\(.ips|split("\n")[0])"')
  awk -v d="$d" '
    /^### / { if (inst) emit(); inst=substr($0,5); delete r; next }
    { i=index($0,"="); if (i) { k=substr($0,1,i-1); v=substr($0,i+1); gsub(/\r/,"",v); r[k]=v
        if (k ~ /^guard_rule_/) rules = rules (rules ? "; " : "") substr(k,12) ": " v } }
    function emit() { printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d, inst, r["stemcell"], r["kernel_running"], r["kernel_fixed"], r["guard_unit"], (rules ? rules : "-"), r["collected_at"] > "/dev/stdout"; rules="" }
    END { if (inst) emit() }' "$OUT/$d.txt" | while IFS=$'\t' read -r dep inst sc k fx gu gr at; do
      pp=- po=-
      if [ -n "$PROBE" ]; then
        ip=$(awk -F'\t' -v i="$inst" '$1==i {print $2}' <<<"$ips")
        if [ -n "$ip" ]; then
          res=$(python3 "$HERE/probe-ip-options.py" "$ip" "$PROBE" 3)
          pp=$(sed -n 's/^plain SYN *-> //p' <<<"$res"); po=$(sed -n 's/^SYN + IPv4 options -> //p' <<<"$res")
        fi
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$dep" "$inst" "$sc" "$k" "$fx" "$gu" "$gr" "$pp" "$po" "$at"
    done >> "$OUT/summary.tsv"
done
( cd "$OUT" && sha256sum -- *.txt summary.tsv > SHA256SUMS )
echo "wrote $OUT/summary.tsv ($(($(wc -l < "$OUT/summary.tsv")-1)) VMs)" >&2
