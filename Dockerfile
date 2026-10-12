# =============================================================================
#  SOC Lab "Operation: Tainted Input" — single container untuk PaaS.
#  Fokus VISUALISASI: OpenSearch + OpenSearch Dashboards + seeder.
#  Akses peserta = ANONYMOUS READ-ONLY (security plugin aktif, tanpa login).
#  Submit jawaban di platform eksternal (hack.redlimit.id/soc-lab).
#  Base Debian 12 slim. Multi-arch (amd64 + arm64). Sediakan ~2 GB RAM.
#  Port publik: $PORT (default 5601, HTTP; ngelinx yang meng-HTTPS-kan).
# =============================================================================
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV OS_VERSION=2.19.1

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates python3 adduser procps openssl \
 && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
# ---- OpenSearch ----
RUN if [ "$TARGETARCH" = "arm64" ]; then ARCH="arm64"; else ARCH="x64"; fi && \
    echo "Mengunduh OpenSearch linux-${ARCH} ${OS_VERSION} ..." && \
    curl -sL "https://artifacts.opensearch.org/releases/bundle/opensearch/${OS_VERSION}/opensearch-${OS_VERSION}-linux-${ARCH}.tar.gz" \
      | tar -xz -C /opt/ && \
    ln -s /opt/opensearch-${OS_VERSION} /usr/share/opensearch

RUN adduser --disabled-password --gecos "" --no-create-home --home /opt/opensearch-${OS_VERSION} opensearch \
 && chown -R opensearch:opensearch /opt/opensearch-${OS_VERSION}

# ---- OpenSearch Dashboards ----
RUN if [ "$TARGETARCH" = "arm64" ]; then ARCH="arm64"; else ARCH="x64"; fi && \
    echo "Mengunduh OpenSearch Dashboards linux-${ARCH} ${OS_VERSION} ..." && \
    curl -sL "https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/${OS_VERSION}/opensearch-dashboards-${OS_VERSION}-linux-${ARCH}.tar.gz" \
      | tar -xz -C /opt/ && \
    ln -s /opt/opensearch-dashboards-${OS_VERSION} /opt/opensearch-dashboards && \
    chown -R opensearch:opensearch /opt/opensearch-dashboards-${OS_VERSION}

# ---- Konfigurasi ----
COPY config/opensearch.yml /usr/share/opensearch/config/opensearch.yml
COPY allinone/opensearch_dashboards.yml /opt/opensearch-dashboards/config/opensearch_dashboards.yml

# ---- Hardening: cert TLS transport + anonymous read-only ----
COPY allinone/harden.sh /tmp/harden.sh
RUN chmod +x /tmp/harden.sh && /tmp/harden.sh && rm -f /tmp/harden.sh

# ---- Seeder + entrypoint ----
COPY seeder/seed.py /opt/seeder/seed.py
COPY allinone/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ---- Izin ----
RUN chown -R opensearch:opensearch /usr/share/opensearch/config \
 && chown opensearch:opensearch /opt/opensearch-dashboards/config/opensearch_dashboards.yml \
 && chown -R opensearch:opensearch /opt/seeder \
 && mkdir -p /var/lib/opensearch && chown opensearch:opensearch /var/lib/opensearch

USER opensearch
WORKDIR /usr/share/opensearch

ENV PORT=5601
EXPOSE 5601
ENTRYPOINT ["/entrypoint.sh"]
