# server_proxy.py
from flask import Flask, request, Response
from flask_cors import CORS
import os, time, random
import requests
from urllib.parse import urlparse, unquote
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

app = Flask(__name__)
CORS(app, supports_credentials=True)

# --- destinos permitidos (ML + API) ---
ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

# ===================== Config por ENV =====================
SP_USERNAME = os.getenv("SP_USERNAME", "")
SP_PASSWORD = os.getenv("SP_PASSWORD", "")

# Aceita uma lista em SP_ENDPOINTS OU SP_ENDPOINT (vírgula e/ou quebras de linha)
_raw_eps = (os.getenv("SP_ENDPOINTS") or os.getenv("SP_ENDPOINT") or "").replace("\n", "")
ENDPOINTS = [e.strip() for e in _raw_eps.split(",") if e.strip()]

# Performance / robustez
ATTEMPTS     = int(os.getenv("SP_ATTEMPTS", "1"))            # 1 = mais rápido; 2 = tenta outra porta se cair no gate
BURST_N      = int(os.getenv("SP_BURST_N", "3"))             # quantas requisições seguidas por porta antes de trocar
CONNECT_TO   = float(os.getenv("SP_CONNECT_TIMEOUT", "3.5")) # seg (connect)
READ_TO      = float(os.getenv("SP_READ_TIMEOUT", "5.0"))    # seg (read)
JIT_MIN      = float(os.getenv("SP_JITTER_MIN", "0.10"))     # seg
JIT_MAX      = float(os.getenv("SP_JITTER_MAX", "0.25"))     # seg
POOL_CONN    = int(os.getenv("SP_POOL_CONNECTIONS", "200"))
POOL_MAX     = int(os.getenv("SP_POOL_MAXSIZE", "400"))
ENABLE_BR    = os.getenv("SP_ACCEPT_BR", "0") == "1"
DEBUG        = os.getenv("SP_DEBUG", "0") == "1"

# ===================== Sessão HTTP base =====================
session = requests.Session()
retry = Retry(
    total=1,                              # retries internos do urllib3 = 1 (rápido)
    backoff_factor=0.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"]),
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=POOL_CONN, pool_maxsize=POOL_MAX)
session.mount("https://", adapter)
session.mount("http://", adapter)
session.trust_env = False

# ===================== Rotação com "burst" =====================
# Mantém a mesma porta por BURST_N requisições para reaproveitar a conexão,
# depois troca para a próxima porta (round-robin).
_current_idx = 0
_current_count = 0

def _next_endpoint():
    global _current_idx, _current_count
    if not ENDPOINTS:
        return None
    if _current_count < max(1, BURST_N):
        _current_count += 1
        ep = ENDPOINTS[_current_idx]
    else:
        _current_count = 1
        _current_idx = (_current_idx + 1) % len(ENDPOINTS)
        ep = ENDPOINTS[_current_idx]
    return ep

def pick_proxies(force_new=False):
    """force_new=True força a troca de porta imediatamente (usado no retry anti-gate)."""
    global _current_idx, _current_count
    if not ENDPOINTS:
        return None
    if force_new:
        _current_count = 0
        _current_idx = (_current_idx + 1) % len(ENDPOINTS)
    ep = _next_endpoint()
    if DEBUG: print(f"[proxy] porta {ep} (burst { _current_count }/{ max(1,BURST_N) })")
    return {
        "http":  f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
        "https": f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
    }

# ===================== Headers =====================
DEFAULT_OUT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate" + (", br" if ENABLE_BR else ""),
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ===================== Helpers =====================
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

def looks_like_gate(resp) -> bool:
    url = getattr(resp, "url", "") or ""
    if "account-verification" in url: return True
    if resp.status_code in (403, 429): return True
    ct = resp.headers.get("content-type", "")
    if "text/html" in ct:
        body = resp.content[:40000].lower()
        if b"account-verification" in body:
            return True
    return False

# ===================== Rotas =====================
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

# Suporta GET e HEAD (compatível com a extensão)
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

    # monta headers (nunca repassar Cookie/Referer)
    forward_headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization","Content-Type","Accept","Accept-Language",
              "User-Agent","Range","If-None-Match","If-Modified-Since"):
        v = request.headers.get(k)
        if v: forward_headers[k] = v

    last_exc = None
    for i in range(max(1, ATTEMPTS)):
        # 1ª tentativa: usa a porta atual; retry: força próxima porta
        proxies = pick_proxies(force_new=(i > 0))
        try:
            r = session.request(
                method=request.method,
                url=target,
                headers=forward_headers,
                allow_redirects=True,                  # a extensão espera follow
                timeout=(CONNECT_TO, READ_TO),
                stream=False,
                verify=True,
                proxies=proxies,
            )
            gated = looks_like_gate(r)
            if DEBUG: print(f"[proxy] {r.status_code} gate={gated} url={getattr(r,'url','')}")
            if gated and (i < ATTEMPTS - 1):
                time.sleep(random.uniform(JIT_MIN, JIT_MAX))
                continue

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

        except requests.RequestException as e:
            last_exc = e
            if i < ATTEMPTS - 1:
                time.sleep(random.uniform(JIT_MIN, JIT_MAX))
                continue
            return add_cors(Response(f"Erro ao contatar destino: {e}", status=502))

    return add_cors(Response(f"Erro: {last_exc}", status=502))
