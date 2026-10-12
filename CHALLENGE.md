# 🧪 Operation: Tainted Input — Brief Peserta

## Skenario
Kamu **SOC Analyst** di **Nusacommerce** (toko online). WAF mengirim lonjakan alert
kategori `injection` sepanjang hari, dan DBA melapor ada query `UNION SELECT` aneh
di slow-log database. Dugaan: **seseorang berhasil menembus aplikasi lewat parameter
yang tidak divalidasi** — mulai dari **XSS**, **SQL Injection**, **Local File
Inclusion (LFI)**, sampai **OS command injection**. Bongkar rantai serangannya.

## Lingkungan (lab)
- Buka **OpenSearch Dashboards** (URL lab dari instruktur). Tanpa login (akses **read-only**
  — kamu bisa melihat & query bebas, tapi tidak bisa mengubah apa pun).
- **Menu lengkap tersedia**: Discover, **Visualize**, Dashboards, sampai Query Workbench.
  Kamu bebas bikin visualisasi/agregasi sendiri untuk eksplorasi — hanya tombol **Save**
  yang ditolak (403), jadi dashboard & data lab aman dari perubahan peserta lain.
- Saat dibuka, dashboard **"SOC Lab — Investigasi Serangan Injeksi Web"** tampil
  otomatis (timeline, top IP, status code, tabel payload injeksi yang berhasil,
  user agent per IP, login panel admin, dst).
- Butuh query manual? Buka menu **Discover**.
- **Index:**
  - `nusacommerce-web-access*` — log akses web (siapa mengakses URL apa, dengan payload apa)
  - `nusacommerce-auth*` — log login panel admin/user
- ⏰ Insiden **11 Oktober 2026 (UTC)**. Time range sudah otomatis ke tanggal itu;
  jika kosong set manual `2026-10-11` → `2026-10-12`.

## 📝 Submit jawaban
Kerjakan 8 task di bawah, lalu **submit jawabannya di:**
**https://hack.redlimit.id/soc-lab**
(Lab hanya untuk investigasi — tidak ada form submit di dalam lab.)

## Field penting
| Field | Arti |
|---|---|
| `source.ip` | IP pengakses |
| `url.path` / `url.original` | URL (tanpa / dengan query) |
| `url.query` | **query string — di sini payload injeksinya** (mis. `id=1+UNION+SELECT...`) |
| `url.extension` | ekstensi (`php`, `jpg`, …) |
| `http.request.method` | GET / POST |
| `http.response.status_code` | **200 payload lolos · 403 diblok WAF · 404 endpoint tak ada · 500 error SQL** |
| `http.response.body.bytes` | ukuran respons (dump data = respons besar) |
| `user_agent.original` | identitas client — **tool otomatis menuliskan namanya di sini** |
| `user.name` | akun yang dipakai saat request/login |
| `event.action` (auth) | `login_failed` / `login_success` |

## 8 Task (total 150 poin)
| # | Fase | Pertanyaan | Poin |
|---|---|---|---|
| 1 | Reconnaissance | Dari IP mana rangkaian serangan injeksi yang **berhasil** berasal? | 10 |
| 2 | Discovery | Tool otomatis apa yang dipakai pelaku untuk eksploitasi SQL injection? (lihat user agent) | 10 |
| 3 | Exploitation | Endpoint (URL path) mana yang rentan **SQL injection**? | 15 |
| 4 | Collection | Nama tabel aplikasi apa yang isinya (username & password) berhasil di-dump via `UNION SELECT`? | 15 |
| 5 | Exploitation | Endpoint (URL path) mana yang rentan **Reflected XSS** (payload `<script>` dipantulkan, status 200)? | 20 |
| 6 | Discovery | File sistem apa yang berhasil dibaca lewat **Local File Inclusion**? (path lengkap) | 25 |
| 7 | Lateral Movement | Akun apa yang dipakai pelaku untuk login ke panel admin setelah kredensial dicuri? | 25 |
| 8 | Command & Control | URL mana yang dihubungi (lewat command injection) untuk mengunduh payload tahap-2? | 30 |

> Tips: jawaban sejati memenuhi **seluruh** rantai — payload berstatus **200**
> (bukan 403/404) → SQLi sampai `UNION SELECT ... FROM <tabel>` → login dengan
> kredensial curian → LFI → command injection → unduh payload tahap-2.
>
> **Jebakan:**
> - Ada IP yang menyemburkan **ratusan** payload SQLi/XSS/LFI tapi **semuanya 403**
>   (diblok WAF) — dia jadi Top Source IP, tapi tidak pernah berhasil.
> - Ada IP yang mengirim payload XSS ke endpoint yang **tidak ada** (404).
> - Ada **pentest internal terjadwal** dari IP kantor `10.10.5.x` (UA ZAP).
> - **False positive:** pencarian pelanggan yang memang berisi tanda kutip
>   (`q=O'Brien+coffee+table`, `q=d'Angelo+parfum`) atau `1=1`
>   (`q=promo+1=1+gratis+ongkir`) — itu belanja biasa, bukan injeksi.

Contoh query DQL/Lucene di Discover:
```
url.query : *UNION* and http.response.status_code : 200
url.query : *script* or url.query : *onerror*
url.query : *passwd*
user_agent.original : *sqlmap*
source.ip : "x.x.x.x" and http.response.status_code : 200
event.category : "authentication"
```
