#!/bin/bash
# nook-db: runs Nook's app database server inside the nook-postgres image.
# The agent starts the container with `nook-db run` and drives everything
# else with `docker exec` (or, for final-archive, a one-off container on
# the same volume). Settings arrive in the environment:
#
#   NOOK_DB_MODE              init (first start of the installation's server),
#                             restore (rebuild from the latest backup and WAL),
#                             existing (the volume must already hold data)
#   NOOK_DB_SUPERUSER         the role the control plane uses
#   NOOK_DB_SUPERUSER_PASSWORD  its password (used by init)
#   NOOK_DB_TLS_CERT/_KEY     server certificate and key (PEM)
#   NOOK_DB_ARCHIVE_TIMEOUT   seconds before a partly filled WAL segment is archived
#   NOOK_DB_MAX_CONNECTIONS, NOOK_DB_SHARED_BUFFERS_MB
#   WALG_* and AWS_*          WAL-G's storage, encryption and credentials
#
# Nothing here prints a secret.
set -euo pipefail

: "${PGDATA:?}"
run_dir=/var/run/postgresql
tls_dir=$run_dir/nook-tls
hba=$run_dir/nook-hba.conf

log() { printf 'nook-db: %s\n' "$*" >&2; }

write_tls() {
	umask 077
	mkdir -p "$tls_dir"
	printf '%s\n' "$1" >"$tls_dir/server.crt.new"
	printf '%s\n' "$2" >"$tls_dir/server.key.new"
	mv "$tls_dir/server.crt.new" "$tls_dir/server.crt"
	mv "$tls_dir/server.key.new" "$tls_dir/server.key"
}

# Only TLS connections with SCRAM passwords from the network; the local
# socket is reachable only from inside this container (the agent's execs).
write_hba() {
	umask 077
	cat >"$hba" <<-'EOF'
		local   all all                 trust
		hostssl all all 0.0.0.0/0       scram-sha-256
		hostssl all all ::/0            scram-sha-256
	EOF
}

prepare_data() {
	if [[ -s $PGDATA/PG_VERSION ]]; then
		return
	fi
	case ${NOOK_DB_MODE:?} in
	init)
		log "initializing a new database cluster"
		mkdir -p -m 0700 "$PGDATA"
		initdb --pgdata="$PGDATA" --username="${NOOK_DB_SUPERUSER:?}" \
			--pwfile=<(printf '%s' "${NOOK_DB_SUPERUSER_PASSWORD:?}") \
			--auth-local=trust --auth-host=scram-sha-256 --encoding=UTF8 --locale=C.UTF-8 >/dev/null
		;;
	restore)
		log "restoring the latest base backup"
		mkdir -p -m 0700 "$PGDATA"
		wal-g backup-fetch "$PGDATA" LATEST
		# Archive recovery: replay every archived WAL segment, then
		# promote on a new timeline.
		touch "$PGDATA/recovery.signal"
		;;
	existing)
		log "the data directory is empty but this server already holds data elsewhere; refusing to initialize"
		exit 1
		;;
	*)
		log "unknown NOOK_DB_MODE"
		exit 1
		;;
	esac
}

cmd_run() {
	write_tls "${NOOK_DB_TLS_CERT:?}" "${NOOK_DB_TLS_KEY:?}"
	write_hba
	prepare_data
	log "starting postgres"
	exec postgres -D "$PGDATA" \
		-c listen_addresses='*' -c port=5432 \
		-c hba_file="$hba" \
		-c ssl=on -c ssl_cert_file="$tls_dir/server.crt" -c ssl_key_file="$tls_dir/server.key" \
		-c ssl_min_protocol_version=TLSv1.2 \
		-c password_encryption=scram-sha-256 \
		-c max_connections="${NOOK_DB_MAX_CONNECTIONS:-200}" \
		-c shared_buffers="${NOOK_DB_SHARED_BUFFERS_MB:-128}MB" \
		-c wal_level=replica \
		-c archive_mode=on \
		-c archive_command='wal-g wal-push %p' \
		-c archive_timeout="${NOOK_DB_ARCHIVE_TIMEOUT:-60}" \
		-c restore_command='wal-g wal-fetch %f %p' \
		-c recovery_target_timeline=latest \
		-c hot_standby=off \
		-c log_destination=stderr -c logging_collector=off \
		-c log_line_prefix='%m [%p] ' \
		-c log_min_error_statement=panic
}

# ready: accepting connections and not recovering.
cmd_ready() {
	pg_isready -q -U "${NOOK_DB_SUPERUSER:?}" -d postgres
	[[ $(psql -U "${NOOK_DB_SUPERUSER:?}" -d postgres -XtAc 'select pg_is_in_recovery()') == f ]]
}

# backup: a full base backup, then retention (keep every full backup made
# after $1, at least one, and the WAL they need).
cmd_backup() {
	wal-g backup-push "$PGDATA"
	wal-g delete retain FULL 1 --after "${1:?retain-after time}" --confirm
}

# final-archive: after a clean shutdown, push the WAL the archiver has not
# sent yet, including the last, partly filled segment that holds the
# shutdown checkpoint, so a restore elsewhere loses nothing. Prints that
# segment's name.
cmd_final_archive() {
	local control state redo f name
	control=$(pg_controldata "$PGDATA")
	state=$(sed -n 's/^Database cluster state: *//p' <<<"$control")
	if [[ $state != "shut down" ]]; then
		log "the cluster was not shut down cleanly ($state)"
		exit 1
	fi
	redo=$(sed -n "s/^Latest checkpoint's REDO WAL file: *//p" <<<"$control")
	for f in "$PGDATA"/pg_wal/archive_status/*.ready; do
		[[ -e $f ]] || continue
		name=$(basename "$f" .ready)
		if [[ $name != "$redo" ]]; then
			wal-g wal-push "$PGDATA/pg_wal/$name"
		fi
	done
	wal-g wal-push "$PGDATA/pg_wal/$redo"
	printf '%s\n' "$redo"
}

# tls: replace the certificate (PEM certificate, then key, on stdin) and
# reload.
cmd_tls() {
	local pem cert key
	pem=$(cat)
	cert=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' <<<"$pem")
	key=$(sed -n '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/p' <<<"$pem")
	[[ -n $cert && -n $key ]] || { log "expected a certificate and a key"; exit 1; }
	write_tls "$cert" "$key"
	psql -U "${NOOK_DB_SUPERUSER:?}" -d postgres -XtAqc 'select pg_reload_conf()' >/dev/null
}

# dump: a plain-SQL dump of one database to stdout.
cmd_dump() {
	pg_dump -U "${NOOK_DB_SUPERUSER:?}" --no-owner --no-privileges --format=plain --dbname="${1:?database}"
}

case ${1:-run} in
run) cmd_run ;;
ready) cmd_ready ;;
backup) cmd_backup "${2:-}" ;;
final-archive) cmd_final_archive ;;
tls) cmd_tls ;;
dump) cmd_dump "${2:-}" ;;
*)
	log "usage: nook-db run|ready|backup TIME|final-archive|tls|dump DATABASE"
	exit 2
	;;
esac
