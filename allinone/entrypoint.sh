#!/usr/bin/env bash
# =============================================================================
#  SOC Lab "Operation: Tainted Input" — entrypoint single-container.
#  Fokus: VISUALISASI DATA di OpenSearch Dashboards. Submit jawaban dilakukan
#  peserta di platform eksternal (https://hack.redlimit.id/soc-lab).
#  Jalankan: OpenSearch -> Dashboards -> seeder (data + dashboard siap-pakai).
#  Env:
#    PORT                 port publik Dashboards (default 5601; dihormati PaaS)
#    EVENT_COUNT          jumlah event noise (default 9000)
#    OPENSEARCH_JAVA_OPTS heap JVM (default -Xms512m -Xmx512m)
#    SCENARIO_DAY         tanggal insiden (default 2026-10-11)
# =============================================================================
set -uo pipefail
log() { echo "[labweb $(date +%H:%M:%S)] $*"; }

export PORT="${PORT:-5601}"
export OPENSEARCH_JAVA_OPTS="${OPENSEARCH_JAVA_OPTS:--Xms512m -Xmx512m}"

# --- Start OpenSearch ---
log "menjalankan OpenSearch ..."
/usr/share/opensearch/bin/opensearch > /tmp/opensearch.log 2>&1 &
OS_PID=$!

log "menunggu OpenSearch (security aktif, auth admin) ..."
up=0
for i in $(seq 1 120); do
  if curl -s -u admin:admin http://localhost:9200/_cluster/health >/dev/null 2>&1; then up=1; log "OpenSearch up."; break; fi
  if ! kill -0 "$OS_PID" 2>/dev/null; then log "ERROR: OpenSearch mati."; tail -n 40 /tmp/opensearch.log; exit 1; fi
  sleep 2
done
[ "$up" = 1 ] || { log "ERROR: OpenSearch timeout."; tail -n 40 /tmp/opensearch.log; exit 1; }

# --- Start Dashboards di $PORT ---
log "menjalankan OpenSearch Dashboards di port ${PORT} ..."
/opt/opensearch-dashboards/bin/opensearch-dashboards \
    --server.host 0.0.0.0 --server.port "${PORT}" > /tmp/dashboards.log 2>&1 &
OSD_PID=$!

# --- Seed data + buat index pattern, visualisasi, dan dashboard ---
log "seeding data (${EVENT_COUNT:-9000} event noise) + dashboard ..."
OPENSEARCH_URL="http://localhost:9200" \
DASHBOARDS_URL="http://localhost:${PORT}" \
BASIC_AUTH="admin:admin" \
EVENT_COUNT="${EVENT_COUNT:-9000}" \
SCENARIO_DAY="${SCENARIO_DAY:-2026-10-11}" \
  python3 /opt/seeder/seed.py || log "WARN: seeder error (lihat di atas)."

log "========================================================="
log " LAB SIAP — OpenSearch Dashboards di port ${PORT}"
log "   Dashboard investigasi tampil otomatis saat dibuka."
log "   Submit jawaban: https://hack.redlimit.id/soc-lab"
log " Tidak perlu login."
log "========================================================="

tail -n +1 -F /tmp/opensearch.log /tmp/dashboards.log 2>/dev/null &
wait -n "$OS_PID" "$OSD_PID"
log "salah satu proses inti berhenti — container keluar."
