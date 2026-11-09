#!/usr/bin/env bash
# Runs the throughput bench between two containers on a bridge network: a closer
# stand-in for two hosts than loopback, but still one machine. It compares the tunnel with
# plain TCP across record sizes and prints the median of each.
#
#   scripts/docker-bench.sh [repetitions]      # SIZES="1400 8192 61440" is the default
#
# Needs Docker and Go. Turn off VPN clients, antivirus and similar network filters first,
# and close other heavy applications. On Docker Desktop the containers share a Linux VM,
# so figures at 4 KB and above can swing by tens of percent between runs; use more
# repetitions and read the spread before trusting a difference.
set -euo pipefail

reps=${1:-3}
sizes=${SIZES:-"1400 8192 61440"}
case "$(docker info --format '{{.Architecture}}')" in
  aarch64 | arm64) goarch=arm64 ;;
  x86_64 | amd64) goarch=amd64 ;;
  *) echo "unsupported Docker architecture" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'docker rm -f qt-srv >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$work/qt" ./cmd/quantum-tunnel
printf 'FROM scratch\nCOPY qt /qt\nENTRYPOINT ["/qt"]\n' >"$work/Dockerfile"
docker build -q -t qt-bench "$work" >/dev/null
docker network create qt-bench-net >/dev/null 2>&1 || true

trial() { # size mode(tunnel|plain)
  local size=$1 mode=$2 extra=""
  [ "$mode" = plain ] && extra="--plain"
  docker rm -f qt-srv >/dev/null 2>&1 || true
  docker run -d --name qt-srv --network qt-bench-net qt-bench bench --serve :9000 $extra --duration 25s >/dev/null
  sleep 1
  docker run --rm --network qt-bench-net qt-bench bench --connect qt-srv:9000 --size 2GB --duration 10s --chunk "$size" $extra >/dev/null 2>&1
  sleep 1
  local log
  log=$(docker logs qt-srv 2>&1)
  printf '%s\t%s\t%s\t%s\n' "$size" "$mode" \
    "$(awk '/Throughput:/ {print $2; exit}' <<<"$log")" \
    "$(awk '/CPU on this host:/ {print $5; exit}' <<<"$log")" >>"$work/results.tsv"
}

: >"$work/results.tsv"
for rep in $(seq 1 "$reps"); do
  for size in $sizes; do
    trial "$size" tunnel
    trial "$size" plain
  done
done

median() { sort -n | awk '{a[NR]=$1} END {if (NR) print a[int((NR+1)/2)]}'; }
printf '\n%-8s %-8s %12s %10s %14s\n' "record" "mode" "median MB/s" "spread" "recv CPU-s/GiB"
for size in $sizes; do
  for mode in tunnel plain; do
    vals=$(awk -F'\t' -v s="$size" -v m="$mode" '$1==s && $2==m && $3!="" {print $3}' "$work/results.tsv")
    cpus=$(awk -F'\t' -v s="$size" -v m="$mode" '$1==s && $2==m && $4!="" {print $4}' "$work/results.tsv")
    [ -z "$vals" ] && continue
    lo=$(sort -n <<<"$vals" | head -1); hi=$(sort -n <<<"$vals" | tail -1)
    printf '%-8s %-8s %12s %9s%% %14s\n' "$size" "$mode" "$(median <<<"$vals")" \
      "$(awk -v l="$lo" -v h="$hi" 'BEGIN {printf "%.0f", 100*(h-l)/l}')" "$(median <<<"$cpus")"
  done
done
