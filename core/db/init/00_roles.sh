#!/bin/bash
# Runs once, as the superuser, when the PostgreSQL data directory is first created
# (files in /docker-entrypoint-initdb.d run in name order: this one before 10_schema.sql).
#
# Roles (D-06: the two schemas are owned by different DB roles):
#   pv2_credential  NOLOGIN  owns schema `credential` (elections, roster, tokens, admin work, outbox)
#   pv2_ballot      NOLOGIN  owns schema `ballot` (credential hashes, sealed ballots, receipts)
#   pv2_core        LOGIN    the Core API connection; full DML on `credential`, read-only on `ballot`,
#                            and writes ballot rows only through two SECURITY DEFINER functions (10_schema.sql)
set -euo pipefail

if [ -z "${DB_CORE_PASSWORD:-}" ]; then
  echo "DB_CORE_PASSWORD is not set" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v core_pw="$DB_CORE_PASSWORD" <<-'EOSQL'
	CREATE ROLE pv2_credential NOLOGIN;
	CREATE ROLE pv2_ballot NOLOGIN;
	CREATE ROLE pv2_core LOGIN PASSWORD :'core_pw';
	REVOKE ALL ON DATABASE :"DBNAME" FROM PUBLIC;
	GRANT CONNECT ON DATABASE :"DBNAME" TO pv2_core;
	REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EOSQL
