#!/usr/bin/env bash
# Two-host benchmark of quantum-tunnel on AWS or Google Cloud.
#
#   scripts/cloud-bench.sh aws|gcp            dry run: checks and plan, creates nothing
#   scripts/cloud-bench.sh aws|gcp --yes      launch two VMs, run the matrix, tear down
#   scripts/cloud-bench.sh aws|gcp cleanup --yes   sweep leftovers from a crashed run
#
# Options: --duration SECONDS (default 10), --instance-type TYPE, --cross-zone,
#          --out DIR (default ./cloud-bench-results/<run id>)
# Region, profile and project come from your environment and CLI config. Nothing here
# creates a project, links billing or opens a port wider than your own address. See
# docs/usage/CLOUD_BENCH.md.
set -euo pipefail

TAG=quantum-go-bench
PORT=9000
SELF_DESTRUCT_MIN=90

log()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found in PATH"; }

PROVIDER=${1:-}; shift || true
case "$PROVIDER" in aws|gcp) ;; *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;; esac
ACTION=run; YES=0; DURATION=10; ITYPE=; CROSS=0; OUT=
while [ $# -gt 0 ]; do
	case "$1" in
	cleanup) ACTION=cleanup ;;
	--yes) YES=1 ;;
	--cross-zone) CROSS=1 ;;
	--duration) DURATION=${2:?--duration needs a value}; shift ;;
	--instance-type) ITYPE=${2:?--instance-type needs a value}; shift ;;
	--out) OUT=${2:?--out needs a value}; shift ;;
	*) die "unknown argument: $1" ;;
	esac
	shift
done
case "$OUT" in ""|/*) ;; *) OUT=$PWD/$OUT ;; esac   # resolve against the caller's directory before we cd
OUTDIR=${OUT:-$PWD/cloud-bench-results}
case "$DURATION" in ''|*[!0-9]*) die "--duration must be whole seconds" ;; esac

cd "$(dirname "$0")/.."
RUNID=qgb-$(date +%y%m%d%H%M%S)
WORK=$(mktemp -d); chmod 700 "$WORK"
KEY=$WORK/key; KNOWN=$WORK/known_hosts
LAUNCHED=0
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- providers

aws_() { aws --region "$REGION" "$@"; }

aws_context() { # what a sweep needs: credentials and a region
	need aws
	aws sts get-caller-identity --query Account --output text >/dev/null 2>&1 || die "no AWS credentials (try: aws login, or set AWS_PROFILE)"
	REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}
	[ -n "$REGION" ] || die "no AWS region: set AWS_REGION or run: aws configure set region <region>"
	ZONE_DESC="$REGION"
}

aws_preflight() {
	aws_context
	: "${ITYPE:=c7i-flex.large}"
	local plan elig
	plan=$(aws freetier get-account-plan-state --query accountPlanType --output text 2>/dev/null || true)
	elig=$(aws_ ec2 describe-instance-types --instance-types "$ITYPE" --query 'InstanceTypes[0].FreeTierEligible' --output text 2>/dev/null || echo unknown)
	[ "$elig" != unknown ] || die "$ITYPE is not a known instance type in $REGION"
	aws_ ec2 describe-instance-types --instance-types "$ITYPE" --query 'InstanceTypes[0].ProcessorInfo.SupportedArchitectures' --output text | grep -qw x86_64 || die "$ITYPE is not x86_64; the script builds linux/amd64 binaries"
	if [ "$plan" = FREE ] && [ "$elig" != True ]; then
		die "the AWS free plan refuses $ITYPE. Use the default (c7i-flex.large) or another free-tier-eligible type, or upgrade the plan."
	fi
	VPC=$(aws_ ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)
	{ [ -n "$VPC" ] && [ "$VPC" != None ]; } || die "no default VPC in $REGION; create one with: aws ec2 create-default-vpc"
	SUBNETS=$(aws_ ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC" Name=default-for-az,Values=true --query 'Subnets[].[AvailabilityZone,SubnetId]' --output text | sort)
	SUBNET_A=$(printf '%s\n' "$SUBNETS" | sed -n 1p | cut -f2)
	SUBNET_B=$SUBNET_A
	if [ "$CROSS" = 1 ]; then SUBNET_B=$(printf '%s\n' "$SUBNETS" | sed -n 2p | cut -f2); [ -n "$SUBNET_B" ] || die "--cross-zone needs two default subnets"; fi
	AMI=$(aws_ ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)
	SSHUSER=ec2-user
}

aws_launch() {
	aws_ ec2 create-key-pair --key-name "$RUNID" --tag-specifications "ResourceType=key-pair,Tags=[{Key=$TAG,Value=$RUNID}]" --query KeyMaterial --output text >"$KEY"; chmod 600 "$KEY"
	SG=$(aws_ ec2 create-security-group --group-name "$RUNID" --description "quantum-go bench $RUNID" --vpc-id "$VPC" \
		--tag-specifications "ResourceType=security-group,Tags=[{Key=$TAG,Value=$RUNID}]" --query GroupId --output text)
	aws_ ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr "$OPIP/32" >/dev/null
	local proto
	for proto in tcp udp; do
		aws_ ec2 authorize-security-group-ingress --group-id "$SG" --protocol "$proto" --port "$PORT" --source-group "$SG" >/dev/null
	done
	local ud; ud=$(printf '#!/bin/bash\nshutdown -P +%s\n' "$SELF_DESTRUCT_MIN")
	local n subnet ids=""
	for n in a b; do
		subnet=$SUBNET_A; [ "$n" = b ] && subnet=$SUBNET_B
		ids="$ids $(aws_ ec2 run-instances --image-id "$AMI" --instance-type "$ITYPE" --key-name "$RUNID" --security-group-ids "$SG" \
			--subnet-id "$subnet" --instance-initiated-shutdown-behavior terminate --user-data "$ud" \
			--tag-specifications "ResourceType=instance,Tags=[{Key=$TAG,Value=$RUNID},{Key=Name,Value=$RUNID-$n}]" \
			--query 'Instances[0].InstanceId' --output text)"
	done
	# shellcheck disable=SC2086
	aws_ ec2 wait instance-running --instance-ids $ids
	local id
	for id in $ids; do
		printf '%s\t%s\n' \
			"$(aws_ ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)" \
			"$(aws_ ec2 describe-instances --instance-ids "$id" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
	done
}

aws_instances() { # echo ids of live instances for $1 (a run id, or empty for all tagged)
	local f="Name=tag-key,Values=$TAG"; [ -n "${1:-}" ] && f="Name=tag:$TAG,Values=$1"
	aws_ ec2 describe-instances --filters "$f" Name=instance-state-name,Values=pending,running,stopping,stopped \
		--query 'Reservations[].Instances[].InstanceId' --output text
}

aws_teardown() { # $1 run id or empty for every tagged run
	local ids sg f="Name=tag-key,Values=$TAG"; [ -n "${1:-}" ] && f="Name=tag:$TAG,Values=$1"
	ids=$(aws_instances "${1:-}")
	# shellcheck disable=SC2086
	if [ -n "$ids" ]; then aws_ ec2 terminate-instances --instance-ids $ids >/dev/null && aws_ ec2 wait instance-terminated --instance-ids $ids || true; fi
	for sg in $(aws_ ec2 describe-security-groups --filters "$f" --query 'SecurityGroups[].GroupId' --output text); do
		local _n; for _n in 1 2 3 4 5 6; do aws_ ec2 delete-security-group --group-id "$sg" >/dev/null 2>&1 && break; sleep 5; done
	done
	local k; for k in $(aws_ ec2 describe-key-pairs --filters "Name=tag-key,Values=$TAG" --query 'KeyPairs[].KeyName' --output text 2>/dev/null) ${1:+$1}; do
		aws_ ec2 delete-key-pair --key-name "$k" >/dev/null 2>&1 || true
	done
}

aws_leftovers() {
	local f="Name=tag-key,Values=$TAG"; [ -n "${1:-}" ] && f="Name=tag:$TAG,Values=$1"
	{ aws_instances "${1:-}"
	  aws_ ec2 describe-security-groups --filters "$f" --query 'SecurityGroups[].GroupId' --output text
	} | tr -s ' \t\n' ' '
}

gcp_context() { # what a sweep needs: an account and a project
	need gcloud
	PROJECT=$(gcloud config get-value project 2>/dev/null || true)
	[ -n "$PROJECT" ] && [ "$PROJECT" != "(unset)" ] || die "no gcloud project: run gcloud config set project <project> (use a dedicated project with billing already linked; this script never links billing)"
	gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q . || die "no active gcloud account: run gcloud auth login"
	ZONE_DESC="$PROJECT"
}

gcp_preflight() {
	gcp_context
	local billing; billing=$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)' 2>/dev/null) || billing=unknown
	[ "$billing" != False ] || die "billing is not enabled on the active project; link it yourself first"
	[ "$billing" != unknown ] || warn "could not read the billing state (missing permission or API); continuing, instance creation will fail if billing is off"
	gcloud compute networks describe default --format='value(name)' >/dev/null 2>&1 || die "no 'default' VPC network in the project (enable the Compute API or create it)"
	ZONE_A=${GCP_ZONE:-$(gcloud config get-value compute/zone 2>/dev/null || true)}
	[ -n "$ZONE_A" ] && [ "$ZONE_A" != "(unset)" ] || die "no zone: set GCP_ZONE=<zone> or run gcloud config set compute/zone <zone>"
	: "${ITYPE:=c3-standard-8}"
	gcloud compute machine-types describe "$ITYPE" --zone "$ZONE_A" --format='value(name)' >/dev/null 2>&1 || die "$ITYPE is not offered in $ZONE_A (pick another zone or --instance-type)"
	[ "$(gcloud compute machine-types describe "$ITYPE" --zone "$ZONE_A" --format='value(architecture)' 2>/dev/null)" != ARM64 ] || die "$ITYPE is ARM64; the script builds linux/amd64 binaries"
	ZONE_B=$ZONE_A
	if [ "$CROSS" = 1 ]; then
		ZONE_B=$(gcloud compute zones list --filter="region:(${ZONE_A%-*}) AND name!=$ZONE_A" --format='value(name)' | head -1)
		[ -n "$ZONE_B" ] || die "--cross-zone needs a second zone in the region"
	fi
	ZONE_DESC="$ZONE_A"
	SSHUSER=bench
}

gcp_launch() {
	ssh-keygen -q -t ed25519 -N "" -f "$KEY"
	gcloud compute firewall-rules create "$RUNID-ssh" --network default --allow tcp:22 --source-ranges "$OPIP/32" --target-tags "$RUNID" --quiet >/dev/null
	gcloud compute firewall-rules create "$RUNID-int" --network default --allow "tcp:$PORT,udp:$PORT" --source-tags "$RUNID" --target-tags "$RUNID" --quiet >/dev/null
	local n zone
	for n in a b; do
		zone=$ZONE_A; [ "$n" = b ] && zone=$ZONE_B
		gcloud compute instances create "$RUNID-$n" --zone "$zone" --machine-type "$ITYPE" --image-family debian-12 --image-project debian-cloud \
			--boot-disk-size 20GB --boot-disk-type pd-balanced --tags "$RUNID" --labels "$TAG=$RUNID" \
			--max-run-duration "${SELF_DESTRUCT_MIN}m" --instance-termination-action DELETE \
			--metadata "ssh-keys=$SSHUSER:$(cat "$KEY.pub")" --quiet >/dev/null
	done
	for n in a b; do
		zone=$ZONE_A; [ "$n" = b ] && zone=$ZONE_B
		printf '%s\t%s\n' \
			"$(gcloud compute instances describe "$RUNID-$n" --zone "$zone" --format='value(networkInterfaces[0].accessConfigs[0].natIP)')" \
			"$(gcloud compute instances describe "$RUNID-$n" --zone "$zone" --format='value(networkInterfaces[0].networkIP)')"
	done
}

gcp_filter() { if [ -n "${1:-}" ]; then printf 'labels.%s=%s' "$TAG" "$1"; else printf 'labels.%s:*' "$TAG"; fi; }

gcp_teardown() {
	local line name zone
	gcloud compute instances list --filter="$(gcp_filter "${1:-}")" --format='value(name,zone.basename())' 2>/dev/null |
	while read -r name zone; do
		[ -n "$name" ] && gcloud compute instances delete "$name" --zone "$zone" --quiet >/dev/null 2>&1 || true
	done
	for line in $(gcloud compute firewall-rules list --filter="name~^${1:-qgb-}" --format='value(name)' 2>/dev/null); do
		gcloud compute firewall-rules delete "$line" --quiet >/dev/null 2>&1 || true
	done
}

gcp_leftovers() {
	{ gcloud compute instances list --filter="$(gcp_filter "${1:-}")" --format='value(name)'
	  gcloud compute firewall-rules list --filter="name~^${1:-qgb-}" --format='value(name)'
	} 2>/dev/null | tr -s ' \t\n' ' '
}

# ---------------------------------------------------------------- shared

finish() {
	local rc=$?
	trap '' INT TERM HUP   # a second Ctrl-C must not interrupt teardown
	trap - EXIT
	if [ "$LAUNCHED" = 1 ]; then
		log "tearing down $RUNID"
		"${PROVIDER}_teardown" "$RUNID" || true
		local left; left=$("${PROVIDER}_leftovers" "$RUNID" || true)
		if [ -n "${left// /}" ]; then
			warn "resources may remain for $RUNID ($left). Sweep them: $0 $PROVIDER cleanup --yes"
			rc=1
		else
			log "teardown verified: nothing left for $RUNID"
		fi
	fi
	rm -rf "$WORK"
	exit "$rc"
}

rssh() { local host=$1; shift; ssh -i "$KEY" -o IdentitiesOnly=yes -o UserKnownHostsFile="$KNOWN" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -o ConnectTimeout=8 -o ServerAliveInterval=10 "$SSHUSER@$host" "$@"; }
mask() { sed -E 's/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/<ip>/g'; }
field() { awk -v pat="$1" -v col="$2" '$0 ~ pat { gsub(/[()%]/, ""); print $col; exit }'; }

# cell LABEL SERVER_ARGS CLIENT_ARGS: one run, appends a table row.
cell() {
	local label=$1 sargs=$2 cargs=$3 srv cli gbps loss rxc txc
	rssh "$PUB_A" "pkill -x qt; sleep 1; rm -f srv.log; nohup ./qt bench --serve :$PORT $sargs > srv.log 2>&1 < /dev/null &" || true
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do rssh "$PUB_A" 'grep -q Listening srv.log' 2>/dev/null && break; sleep 1; done
	cli=$(rssh "$PUB_B" "./qt bench --connect $PRIV_A:$PORT $cargs" 2>&1) || warn "client for '$label' exited with an error"
	for _ in $(seq 1 $((DURATION + 25))); do rssh "$PUB_A" '! pgrep -x qt >/dev/null' 2>/dev/null && break; sleep 1; done
	srv=$(rssh "$PUB_A" 'cat srv.log' 2>&1 || true)
	{ printf '=== %s\n--- receiver\n%s\n--- sender\n%s\n' "$label" "$srv" "$cli"; } | mask >>"$OUT/raw.log"
	gbps=$(printf '%s\n' "$srv" | field 'Throughput:' 4)
	if [ -n "$gbps" ]; then gbps=$(awk -v m="$gbps" 'BEGIN { printf "%.2f", m / 1000 }'); else gbps=n/a; fi
	loss=$(printf '%s\n' "$srv" | field 'Loss:' 2); loss=${loss:--}
	rxc=$(printf '%s\n' "$srv" | field 'CPU on this host' 5); rxc=${rxc:--}
	txc=$(printf '%s\n' "$cli" | field 'CPU on this host' 5); txc=${txc:--}
	printf '| %s | %s | %s | %s | %s |\n' "$label" "$gbps" "$loss" "$rxc" "$txc" | tee -a "$OUT/results.md"
}

run_matrix() {
	local chunk flows mode f d="--duration ${DURATION}s"
	{
		printf '# quantum-tunnel two-host bench\n\n'
		printf -- '- provider: %s, zone: %s, instance type: %s (2 VMs)\n' "$PROVIDER" "$ZONE_DESC" "$ITYPE"
		printf -- '- commit: %s, date: %s, %ss per cell, single runs (indicative, not medians)\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" "$(date +%Y-%m-%d)" "$DURATION"
		printf -- '- datagram cells run with net.core.rmem_max raised to 4 MiB on both VMs\n\n'
		printf '| cell | Gbps (receiver) | loss | rx CPU-s/GiB | tx CPU-s/GiB |\n|---|---|---|---|---|\n'
	} | tee "$OUT/results.md"
	for chunk in 1400 8KB 60KB; do for flows in 1 4; do for mode in plain tunnel; do
		f=; [ "$mode" = plain ] && f=--plain
		cell "stream $mode, ${chunk} records, $flows flow(s)" "$f --flows $flows $d" "$f --flows $flows --chunk $chunk $d --size 400GB"
	done; done; done
	rssh "$PUB_A" 'sudo sh -c "echo 4194304 > /proc/sys/net/core/rmem_max"'
	rssh "$PUB_B" 'sudo sh -c "echo 4194304 > /proc/sys/net/core/rmem_max"'
	local what
	for rate in 1000 4000 0; do
		what="offered ${rate} Mbps"; [ "$rate" = 0 ] && what=unpaced
		cell "datagram, 1100 B, offload, batch 16, $what" "--datagram --offload $d" "--datagram --offload --batch 16 --chunk 1100 --rate $rate $d"
	done
}

# ---------------------------------------------------------------- main

if [ "$ACTION" = cleanup ]; then
	"${PROVIDER}_context"
	log "sweeping every $TAG resource for $PROVIDER ($ZONE_DESC)"
	[ "$YES" = 1 ] || die "add --yes to delete them"
	"${PROVIDER}_teardown" ""
	left=$("${PROVIDER}_leftovers" "" || true)
	[ -z "${left// /}" ] || die "still present: $left"
	log "nothing left"
	exit 0
fi

need ssh; need ssh-keygen; need curl; need go
"${PROVIDER}_preflight"
OPIP=$(curl -fsS --noproxy "*" --max-time 8 https://checkip.amazonaws.com | tr -d '[:space:]') || die "could not look up your public address"
CELLS=15; MIN=$(( (CELLS * (DURATION + 8)) / 60 + 3 ))
log "plan for $RUNID"
log "  provider      $PROVIDER ($ZONE_DESC)"
log "  instances     2 x $ITYPE$([ "$CROSS" = 1 ] && printf ', in two zones' || printf ', one zone')"
log "  ssh allowed   $OPIP/32 only (your current public address; a VPN reconnect mid-run drops it and aborts, teardown still runs)"
log "  run time      about $MIN minutes; VMs self-destruct after $SELF_DESTRUCT_MIN minutes even if this script dies"
log "  cost          the cloud bills two VMs for the run; check the hourly price of $ITYPE in your region"
log "  results       ${OUT:-$OUTDIR/$RUNID}"
[ "$YES" = 1 ] || { log; log "dry run only. Re-run with --yes to launch."; rm -rf "$WORK"; exit 0; }

OUT=${OUT:-$OUTDIR/$RUNID}; mkdir -p "$OUT"; : >"$OUT/raw.log"
log "building quantum-tunnel for linux/amd64"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/qt" ./cmd/quantum-tunnel
trap finish EXIT; trap 'exit 130' INT TERM HUP
LAUNCHED=1
"${PROVIDER}_launch" >"$WORK/hosts"   # not a command substitution: errexit must stay on
HOSTS=$(cat "$WORK/hosts")
[ "$(printf '%s\n' "$HOSTS" | awk -F'\t' 'NF == 2 && $1 != "" && $2 != ""' | wc -l | tr -d ' ')" = 2 ] || die "the launch did not return two VMs with addresses"
PUB_A=$(printf '%s\n' "$HOSTS" | sed -n 1p | cut -f1); PRIV_A=$(printf '%s\n' "$HOSTS" | sed -n 1p | cut -f2)
PUB_B=$(printf '%s\n' "$HOSTS" | sed -n 2p | cut -f1)
for h in "$PUB_A" "$PUB_B"; do
	ok=0; for _ in $(seq 1 24); do
		rssh "$h" 'cat > qt.new && chmod +x qt.new && mv qt.new qt && ./qt bench --help >/dev/null 2>&1' <"$WORK/qt" && { ok=1; break; }; sleep 5
	done
	[ "$ok" = 1 ] || die "could not deploy the binary to a VM"
done
run_matrix
log; log "results: $OUT/results.md (raw output, addresses masked: $OUT/raw.log)"
