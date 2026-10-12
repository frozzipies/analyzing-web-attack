# SOC Lab — Operation: Tainted Input 🧪

Lab investigasi untuk melatih **SOC Analyst**. Peserta memakai **OpenSearch
Dashboards** (dashboard visualisasi siap-pakai + Discover) untuk membongkar
rantai **serangan injeksi web** — **XSS**, **SQL Injection**, **LFI/path
traversal**, **OS command injection**, plus percobaan SSTI/XXE/NoSQLi/CRLF/SSRF/
LDAP/XPath — lalu **submit jawaban 8 task di platform eksternal**:

> 📝 **Submit jawaban:** https://hack.redlimit.id/soc-lab

Lab ini **fokus pada visualisasi/investigasi data** — tidak ada form submit di
dalam lab. Satu kontainer berisi OpenSearch + OpenSearch Dashboards + data dummy
yang ter-seed otomatis, mengekspos **satu port**, jadi langsung cocok untuk PaaS
(ngelinx.com, dll).

```
┌──────────────── container (port $PORT, default 5601) ────────────────┐
│  OpenSearch Dashboards  ◀── visualisasi + Discover (yang dilihat user) │
│        │                                                               │
│   OpenSearch  ◀── seeder: data dummy + dashboard siap-pakai (otomatis) │
└──────────────────────────────────────────────────────────────────────┘
```

## Struktur

| Path | Keterangan |
|---|---|
| `Dockerfile` | image single-container untuk PaaS & lokal |
| `allinone/entrypoint.sh` | start OpenSearch → Dashboards → seeder |
| `allinone/opensearch_dashboards.yml` | OSD, `defaultRoute` → dashboard investigasi |
| `allinone/harden.sh` | cert TLS transport + anonymous auth (saat build) |
| `config/opensearch.yml` | OpenSearch single-node, security plugin aktif |
| `seeder/seed.py` | generator data + pembuat index pattern, 10 visualisasi, 1 dashboard (stdlib) |
| `docker-compose.yml` | menjalankan image yang sama secara lokal (port 5601) |
| `setup.sh` / `teardown.sh` | helper lokal |
| `CHALLENGE.md` | brief peserta + 8 task (untuk diunggah ke platform submit) |
| `SOLUTION.md` | **kunci jawaban** (khusus instruktur) |

## Rantai serangan yang disimulasikan
`recon` → **Reflected XSS** (`/search.php?q=`) → **SQLi manual** (`/product.php?id=`)
→ **otomasi sqlmap** → **dump `UNION SELECT` tabel `ns_users`** → **login dengan
kredensial curian** → **LFI** (`/view.php?page=`) → **percobaan injeksi lain**
(SSTI, XXE, NoSQLi, CRLF, SSRF, LDAP, XPath) → **OS command injection**
(`/admin/tools/ping.php?host=`) → **unduh & jalankan payload tahap-2 (C2)**.

Plus tiga **red herring** dan satu kelas **false positive**: IP yang menyemburkan
ratusan payload tapi selalu diblok WAF (403), IP yang nge-XSS endpoint tak ada
(404), scanner Nikto generik, pentest internal terjadwal (ZAP dari `10.10.5.x`),
dan pencarian pelanggan yang memang mengandung `'` atau `1=1`.

## Dashboard yang dibuat otomatis
Saat Dashboards dibuka, langsung tampil **"SOC Lab — Investigasi Serangan Injeksi
Web"**: panel brief (berisi tautan submit), total event, distribusi status code,
timeline event, Top Source IP, Top URL, asal negara IP, **tabel payload injeksi
yang BERHASIL (200)**, **user agent per source IP** (untuk memburu tool scanner),
dan **login panel admin per akun · IP · hasil**. Peserta juga bisa pakai
**Discover** untuk query manual (DQL/Lucene).

---

## Jalankan lokal

```bash
./setup.sh          # build + start, tunggu siap
# buka http://localhost:5601/
./teardown.sh       # stop   (--purge untuk hapus image)
```
Build pertama mengunduh ~1 GB (tarball OpenSearch+Dashboards), butuh beberapa
menit. Sediakan **±2 GB RAM**. `setup.sh` otomatis menaikkan `vm.max_map_count`
dan memakai `sudo docker` bila perlu. Peserta masuk tanpa login sebagai **anonymous read-only**.

---

## Deploy ke PaaS (ngelinx.com)

ngelinx mendukung deploy dari **GitHub / Docker / Nixpacks** dengan deteksi build
& port otomatis. Lab ini adalah **satu `Dockerfile`** yang mengekspos satu port
(Dashboards).

1. Push folder ini ke repo GitHub (lihat "Push ke GitHub").
2. ngelinx: **New App → from GitHub**, pilih repo (branch `main`). Build auto →
   memakai `Dockerfile` root.
3. **Environment variables** (opsional):
   | Var | Default | Fungsi |
   |---|---|---|
   | `PORT` | `5601` | port publik; di-inject PaaS → dihormati entrypoint |
   | `EVENT_COUNT` | `9000` | banyak noise → tingkat kesulitan |
   | `OPENSEARCH_JAVA_OPTS` | `-Xms512m -Xmx512m` | heap; naikkan bila RAM besar |
   | `SCENARIO_DAY` | `2026-10-11` | tanggal insiden |
4. **Resource**: beri **≥ 2 GB RAM**. Protokol **HTTP**.
5. Deploy → akses domain ngelinx → dashboard investigasi tampil otomatis.

> Data di-seed ulang setiap start (deterministik, jawaban selalu sama). Tidak
> perlu volume. Boot pertama ~1–2 menit sampai Dashboards + dashboard siap.

### Push ke GitHub
```bash
cd webattack-analyzing
git init -b main && git add . && git commit -m "SOC lab: Operation Tainted Input"
git remote add origin git@github.com:<user>/<repo>.git
git push -u origin main
```

---

## Task & submit jawaban
8 task (brief lengkap di `CHALLENGE.md`) **dikerjakan & disubmit di
https://hack.redlimit.id/soc-lab**, bukan di lab. Kunci jawaban + query
pembuktian + penjelasan red herring ada di `SOLUTION.md`.

## Akses & keamanan
- **Peserta = anonymous READ-ONLY.** Security plugin OpenSearch AKTIF. Pengunjung
  masuk tanpa login (anonymous), dipetakan ke role read-only (`soc_viewer` +
  Global tenant `kibana_all_read`). Mereka bisa melihat dashboard & query bebas di
  Discover, tapi **tidak bisa menulis/menghapus data, dashboard, maupun visualisasi**
  — via UI, API saved-object, maupun Dev Tools. Jadi satu peserta iseng tidak bisa
  merusak lab untuk yang lain.
- **Admin internal.** OpenSearch REST (`:9200`) memakai user `admin`/`admin` &
  `kibanaserver`/`kibanaserver` (kredensial demo) — **tidak diekspos ke publik**
  (hanya dipakai di dalam container; yang terekspos hanya Dashboards). Seeder
  memakai admin untuk memuat data & membuat dashboard.
- **REST tanpa TLS, transport TLS self-signed** (internal). HTTPS publik ditangani
  ngelinx. Lab ini untuk **latihan** — jangan untuk produksi/data nyata.
- Tidak ada aplikasi rentan sungguhan: hanya **jejak log** simulasi untuk latihan
  deteksi. Payload di log tidak pernah dieksekusi — hanya string di field `url.query`.
