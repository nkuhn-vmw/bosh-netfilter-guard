#!/bin/bash
# Runs tools/evidence.sh on every instance of the given deployments (default: all) on the targeted BOSH
# director, and optionally probes each instance from here. Writes OUTDIR/<deployment>.txt (raw records),
# OUTDIR/summary.tsv (one row per expected VM, including ones that could not be read), OUTDIR/SHA256SUMS.
# Read-only on the VMs.
#
# Completeness: the expected VM list comes from `bosh instances`. Every expected VM gets a row; a VM whose
# record is missing gets record=MISSING. If anything is missing or a deployment can't be listed, the run
# writes OUTDIR/INCOMPLETE and exits 1, so a partial bundle is never mistaken for a complete one.
#
#   BOSH_ENVIRONMENT=... fleet-evidence.sh OUTDIR [--fixed-deb V]... [--fixed-uname V]... [--probe PORT] [deployment ...]
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?usage: $0 OUTDIR [--fixed-deb V]... [--fixed-uname V]... [--probe PORT] [deployment ...]}; shift
ARGS=() PROBE= DEPS=()
while [ $# -gt 0 ]; do
  case $1 in
    --fixed-deb|--fixed-uname) ARGS+=("$1" "$2"); shift 2 ;;
    --probe) PROBE=$2; [[ $PROBE =~ ^[0-9]+$ ]] || { echo "bad --probe $PROBE" >&2; exit 2; }; shift 2 ;;
    *) DEPS+=("$1"); shift ;;
  esac
done
# validate the evidence arguments locally (same checks evidence.sh applies), then quote them for the remote shell
bash "$HERE/evidence.sh" "${ARGS[@]}" >/dev/null || { echo "invalid --fixed-* arguments" >&2; exit 2; }
QARGS=$(printf '%q ' "${ARGS[@]}")
mkdir -p "$OUT"; rm -f "$OUT/INCOMPLETE"
if [ ${#DEPS[@]} -eq 0 ]; then
  if ! list=$(bosh deployments --json 2>&1); then echo "cannot list deployments: $list" >&2; exit 1; fi
  mapfile -t DEPS < <(jq -r '.Tables[0].Rows[].name' <<<"$list")
fi
SCRIPT=$(base64 -w0 "$HERE/evidence.sh")
COLS='deployment\tinstance\trecord\tstemcell\tkernel\tkernel_fixed\tguard_unit\tguard_rules\tprobe_plain\tprobe_options\tcollected_at\n'
printf "$COLS" > "$OUT/summary.tsv"
incomplete=0

for d in "${DEPS[@]}"; do
  echo "== $d" >&2
  if ! inst_json=$(bosh -d "$d" instances --json 2>&1); then
    echo "   cannot list instances: $(head -1 <<<"$inst_json")" >&2
    printf '%s\t-\tDEPLOYMENT-UNREADABLE\t-\t-\t-\t-\t-\t-\t-\t-\n' "$d" >> "$OUT/summary.tsv"; incomplete=1; continue
  fi
  # expected VMs: instances with an IP, i.e. with a VM (errand-only instance groups have none)
  expected=$(jq -r '.Tables[0].Rows[] | select((.ips // "") != "") | "\(.instance)\t\(.ips|split("\n")[0])"' <<<"$inst_json")
  [ -n "$expected" ] || { echo "   no VMs" >&2; continue; }
  if ! raw=$(bosh -d "$d" ssh -r --json -c "echo $SCRIPT | base64 -d | sudo -n bash -s -- $QARGS" 2>&1); then
    echo "   bosh ssh reported a failure; rows without records will be marked MISSING" >&2
  fi
  jq -r '.Tables[0].Rows[]? | "### \(.instance)\n\(.stdout)"' <<<"$raw" 2>/dev/null > "$OUT/$d.txt" || : > "$OUT/$d.txt"

  # parse records with awk only (no shell IFS parsing, so empty fields can't shift columns)
  while IFS= read -r line; do
    inst=${line%%$'\t'*}; ip=${line#*$'\t'}
    row=$(awk -v d="$d" -v want="$inst" '
      /^### / { cur=substr($0,5); next }
      cur==want { i=index($0,"="); if (i) { k=substr($0,1,i-1); v=substr($0,i+1); gsub(/[\r\t]/," ",v); r[k]=v
                  if (k ~ /^guard_rule_/) rules = rules (rules ? "; " : "") substr(k,12) ": " v } }
      END {
        if (r["collected_at"] == "") { printf "%s\t%s\tMISSING\t-\t-\t-\t-\t-", d, want; exit }
        printf "%s\t%s\tok\t%s\t%s\t%s\t%s\t%s", d, want, f(r["stemcell"]), f(r["kernel_running"]), f(r["kernel_fixed"]), f(r["guard_unit"]), (rules ? rules : "-")
        printf "\t@%s", r["collected_at"] }
      function f(x) { return (x == "" ? "-" : x) }' "$OUT/$d.txt")
    at=-; [[ $row == *$'\t@'* ]] && { at=${row##*$'\t@'}; row=${row%$'\t@'*}; }
    [[ $row == *$'\tMISSING\t'* ]] && incomplete=1
    pp=- po=-
    if [ -n "$PROBE" ] && [ -n "$ip" ] && [ "$ip" != null ]; then
      res=$(python3 "$HERE/probe-ip-options.py" "$ip" "$PROBE" 3 2>&1)
      pp=$(sed -n 's/^plain SYN *-> //p' <<<"$res"); po=$(sed -n 's/^SYN + IPv4 options -> //p' <<<"$res")
    fi
    printf '%s\t%s\t%s\t%s\n' "$row" "${pp:--}" "${po:--}" "$at" >> "$OUT/summary.tsv"
  done <<<"$expected"
done

n=$(($(wc -l < "$OUT/summary.tsv")-1)); miss=$(awk -F'\t' 'NR>1 && $3!="ok"' "$OUT/summary.tsv" | wc -l)
if [ "$incomplete" = 1 ] || [ "$miss" -gt 0 ]; then
  echo "$miss of $n expected VMs have no record (see summary.tsv column 'record')" > "$OUT/INCOMPLETE"
fi
( cd "$OUT" && sha256sum -- *.txt summary.tsv $( [ -f INCOMPLETE ] && echo INCOMPLETE ) > SHA256SUMS )
echo "wrote $OUT/summary.tsv ($n VMs, $miss without a record)" >&2
[ ! -f "$OUT/INCOMPLETE" ]
