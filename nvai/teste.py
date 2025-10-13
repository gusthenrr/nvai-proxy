# server_proxy.py
from flask import Flask, request, Response
from flask_cors import CORS
import os, time, random, itertools
import requests
from urllib.parse import urlparse, unquote
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Domínios permitidos (ML + API)
ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

# ====== ENV / Config ======
SP_USERNAME = os.getenv("SP_USERNAME", "")
SP_PASSWORD = os.getenv("SP_PASSWORD", "")

_raw_eps = (os.getenv("SP_ENDPOINTS") or os.getenv("SP_ENDPOINT") or "").replace("\n", "")
ENDPOINTS = [e.strip() for e in _raw_eps.split(",") if e.strip()]

CONNECT_TO = float(os.getenv("SP_CONNECT_TIMEOUT", "4"))   # seg
READ_TO    = float(os.getenv("SP_READ_TIMEOUT", "6"))      # seg
POOL_CONN  = int(os.getenv("SP_POOL_CONNECTIONS", "100"))
POOL_MAX   = int(os.getenv("SP_POOL_MAXSIZE", "200"))
DEBUG      = os.getenv("SP_DEBUG", "0") == "1"

# ====== Session HTTP (rápida e estável) ======
session = requests.Session()
retry = Retry(
    total=1,  # a gente controla retry se quiser; aqui é “rápido”
    backoff_factor=0.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"])
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=POOL_CONN, pool_maxsize=POOL_MAX)
session.mount("https://", adapter)
session.mount("http://", adapter)
session.trust_env = False

# Round-robin simples (ou porta única)
_cycle = itertools.cycle(ENDPOINTS) if ENDPOINTS else None
def pick_proxies():
    if _cycle:
        ep = next(_cycle)
    else:
        ep = _raw_eps.strip() if _raw_eps else ""
    if not ep:
        return None  # sem proxy (desaconselhado, mas não quebra o app)
    if DEBUG: print(f"[proxy] usando {ep}")
    return {
        "http":  f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
        "https": f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
    }

DEFAULT_OUT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

def is_allowed(target: str) -> bool:
    try:
        u = urlparse(target)
        if u.scheme not in ("http", "https"): return False
        host = (u.hostname or "").lower()
        if host in ALLOWED_EXACT: return True
        return any(host.endswith(suf) for suf in ALLOWED_SUFFIXES)
    except Exception:
        return False

def add_cors(resp: Response):
    origin = request.headers.get("Origin")
    resp.headers["Access-Control-Allow-Origin"] = origin or "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true" if origin else "false"
    req_method = request.headers.get("Access-Control-Request-Method")
    req_headers = request.headers.get("Access-Control-Request-Headers")
    resp.headers["Access-Control-Allow-Methods"] = req_method or "GET,HEAD,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = req_headers or (
        "Content-Type, Authorization, If-None-Match, If-Modified-Since, Range, Cache-Control, Pragma"
    )
    resp.headers["Access-Control-Expose-Headers"] = (
        "Content-Type, ETag, Cache-Control, Last-Modified, Location, Content-Range, "
        "Content-Length, X-Proxy-Final-Url, X-Proxy-Redirect-Count"
    )
    resp.headers["Access-Control-Max-Age"] = "86400"
    resp.headers["Vary"] = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"
    return resp

@app.route("/", defaults={"raw": ""}, methods=["OPTIONS"])
@app.route("/<path:raw>", methods=["OPTIONS"])
def _opts(raw):
    return add_cors(Response(status=204))

@app.route("/_health", methods=["GET"])
def _health():
    return "ok", 200

@app.route("/_proxy_check", methods=["GET"])
def _proxy_check():
    proxies = pick_proxies()
    r = session.get("https://ip.decodo.com/json", timeout=(CONNECT_TO, READ_TO), proxies=proxies)
    return (r.text, 200, {"Content-Type": "application/json"})

# Compatível com a extensão (GET/HEAD, follow)
@app.route("/", defaults={"raw": ""}, methods=["GET", "HEAD"])
@app.route("/<path:raw>", methods=["GET", "HEAD"])
def proxy(raw: str):
    if not raw:
        return add_cors(Response("OK - use /https://<url-destino>", status=200))

    target = unquote(raw)
    q = request.query_string.decode("utf-8")
    if q:
        target = f"{target}{'&' if '?' in target else '?'}{q}"

    if not is_allowed(target):
        return add_cors(Response("Host não permitido", status=400))

    # Sem Cookie/Referer; prioriza UA vindo da extensão
    forward_headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization","Content-Type","Accept","Accept-Language",
              "User-Agent","Range","If-None-Match","If-Modified-Since"):
        v = request.headers.get(k)
        if v: forward_headers[k] = v

    try:
        r = session.request(
            method=request.method,
            url=target,
            headers=forward_headers,
            allow_redirects=True,
            timeout=(CONNECT_TO, READ_TO),
            stream=False,
            verify=True,
            proxies=pick_proxies(),
        )
    except requests.RequestException as e:
        return add_cors(Response(f"Erro ao contatar destino: {e}", status=502))

    resp = Response(r.content if request.method == "GET" else b"", status=r.status_code)
    hop_by_hop = {"transfer-encoding","connection","keep-alive","proxy-authenticate",
                  "proxy-authorization","te","trailers","upgrade"}
    for k, v in r.headers.items():
        lk = k.lower()
        if lk in hop_by_hop: continue
        if lk in ("content-type","cache-control","etag","last-modified",
                  "content-range","accept-ranges","location","content-length"):
            resp.headers[k] = v

    resp.headers["X-Proxy-Final-Url"] = getattr(r, "url", target)
    resp.headers["X-Proxy-Redirect-Count"] = str(len(getattr(r, "history", [])))
    return add_cors(resp)
