#!/usr/bin/env bash
# Hentikan lab.  --purge juga menghapus image hasil build.
set -euo pipefail
cd "$(dirname "$0")"

DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then DOCKER="sudo docker"; fi
fi

if [[ "${1:-}" == "--purge" ]]; then
  echo "[*] menghentikan & menghapus image ..."
  $DOCKER compose down --rmi local -v
else
  echo "[*] menghentikan lab ..."
  $DOCKER compose down
fi
echo "[*] selesai."
