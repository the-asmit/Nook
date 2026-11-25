#!/bin/sh
# Registry garbage collection for Nook.
#
# The registry's garbage collector deletes blobs that no manifest
# references. A push in progress has uploaded blobs that no manifest
# references yet, so collection must never overlap a push. Every interval
# this job asks the control plane for a maintenance window (granted once no
# build is running; no build starts while it is open), collects, and closes
# the window. If the control plane refuses (builds running), it tries again
# at the next interval.
set -eu

url="${NOOK_CONTROL_PLANE_URL:?}/api/v1/registry/gc-window"
interval="${NOOK_REGISTRY_GC_INTERVAL:-3600}"
auth="Authorization: Bearer ${NOOK_REGISTRY_GC_SECRET:?}"
json="Content-Type: application/json"

while true; do
	sleep "$interval"
	if ! wget -q -O /dev/null -T 120 --header "$auth" --header "$json" \
		--post-data '{"ttl_seconds":900}' "$url/open"; then
		echo "registry-gc: no maintenance window (builds running or control plane unreachable); retrying in ${interval}s" >&2
		continue
	fi
	echo "registry-gc: maintenance window open; collecting" >&2
	if ! registry garbage-collect --delete-untagged /etc/distribution/config.yml; then
		echo "registry-gc: garbage collection failed" >&2
	fi
	if ! wget -q -O /dev/null -T 30 --header "$auth" --header "$json" --post-data '{}' "$url/close"; then
		echo "registry-gc: could not close the window; it expires on its own" >&2
	fi
done
