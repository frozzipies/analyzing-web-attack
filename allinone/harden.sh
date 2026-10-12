#!/usr/bin/env bash
# Dijalankan saat BUILD image:
#  1) generate sertifikat TLS transport (CA + node + admin) via openssl
#  2) aktifkan anonymous auth + tambah role read-only utk anonymous di securityconfig
# Semua perubahan "dibakar" ke image; dimuat OpenSearch saat init security index pertama.
set -euo pipefail
OS=/usr/share/opensearch
SEC="$OS/config/opensearch-security"
CERTS="$OS/config/certs"

echo "[harden] generate sertifikat TLS transport ..."
mkdir -p "$CERTS"; cd "$CERTS"

# Root CA
openssl genrsa -out root-ca-key.pem 2048
openssl req -new -x509 -sha256 -days 3650 -key root-ca-key.pem -subj "/CN=soc-lab-ca" -out root-ca.pem

# Node cert (PKCS#8 key, wajib utk plugin security)
openssl genrsa -out node-key-pkcs1.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in node-key-pkcs1.pem -out node-key.pem
openssl req -new -key node-key.pem -subj "/CN=node" -out node.csr
printf "extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:node,DNS:localhost,IP:127.0.0.1\n" > node.ext
openssl x509 -req -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -days 3650 -extfile node.ext -out node.pem

# Admin cert (utk superadmin/securityadmin)
openssl genrsa -out admin-key-pkcs1.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in admin-key-pkcs1.pem -out admin-key.pem
openssl req -new -key admin-key.pem -subj "/CN=admin" -out admin.csr
printf "extendedKeyUsage=clientAuth\n" > admin.ext
openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -days 3650 -extfile admin.ext -out admin.pem

rm -f ./*.csr ./*.ext ./*-pkcs1.pem root-ca.srl
chmod 600 ./*-key.pem

echo "[harden] aktifkan anonymous auth ..."
sed -i 's/anonymous_auth_enabled: false/anonymous_auth_enabled: true/' "$SEC/config.yml"
# Pemetaan role read-only untuk anonymous dilakukan seeder via Security REST API
# (lihat seed.py -> harden_security) agar andal & idempoten tiap start.

echo "[harden] selesai."
