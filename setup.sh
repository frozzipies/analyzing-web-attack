#!/usr/bin/env bash
# SOC Lab "Operation: Tainted Input" — build & jalankan lab secara lokal.
# Lab = OpenSearch Dashboards (visualisasi). Submit jawaban: hack.redlimit.id/soc-lab
# (Di PaaS ngelinx.com cukup arahkan ke repo ini; Dockerfile-nya dipakai langsung.)
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-5601}"
DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then DOCKER="sudo docker"; echo "[i] memakai sudo docker"; fi
fi

echo "=================================================="
echo " SOC Lab — Operation: Tainted Input (setup lokal)"
echo "=================================================="

MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$MAP" -lt 262144 ]; then
  echo "[*] menaikkan vm.max_map_count=262144 ..."
  sudo sysctl -w vm.max_map_count=262144 || echo "    WARN: gagal set; jika OpenSearch crash jalankan manual."
fi

echo "[*] build & start (pertama kali mengunduh ~1 GB, bisa beberapa menit) ..."
$DOCKER compose up -d --build

echo -n "[*] menunggu Dashboards siap di http://localhost:${PORT} "
ok=0
for _ in $(seq 1 120); do
  if curl -sf -u admin:admin "http://localhost:${PORT}/api/status" >/dev/null 2>&1; then ok=1; echo " OK"; break; fi
  printf '.'; sleep 5
done

if [ "$ok" != 1 ]; then
  echo; echo "[!] belum siap. Lihat log: $DOCKER compose logs -f"
  exit 1
fi

cat <<MSG

==================================================================
 LAB SIAP
==================================================================
 OpenSearch Dashboards : http://localhost:${PORT}/
   -> dashboard investigasi tampil otomatis saat dibuka
   -> atau buka Discover untuk query manual
 Tanpa login.

 Peserta SUBMIT jawaban 8 task di:  https://hack.redlimit.id/soc-lab
 Brief   : CHALLENGE.md      Kunci jawaban : SOLUTION.md (instruktur)
==================================================================
MSG
