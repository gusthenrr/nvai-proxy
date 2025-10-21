# server_proxy.py
from flask import Flask, request, Response, jsonify
from flask_cors import CORS
import os, re, itertools, threading, time, random
import requests
from urllib.parse import urlparse, unquote
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ===== Destinos permitidos (ML + API) =====
ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

# ===== ENV / Config =====
SP_USERNAME = os.getenv("SP_USERNAME", "").strip()
SP_PASSWORD = os.getenv("SP_PASSWORD", "").strip()

_raw_eps = (os.getenv("SP_ENDPOINTS") or os.getenv("SP_ENDPOINT") or "").strip()
ENDPOINTS = [e.strip() for e in re.split(r"[,\s]+", _raw_eps) if e.strip()]  # aceita vírgula/esp/linhas
ROTATING_MODE = any(ep.endswith(":10000") for ep in ENDPOINTS) or _raw_eps.endswith(":10000")

CONNECT_TO = float(os.getenv("SP_CONNECT_TIMEOUT", "4"))
READ_TO    = float(os.getenv("SP_READ_TIMEOUT", "6"))
POOL_CONN  = int(os.getenv("SP_POOL_CONNECTIONS", "100"))
POOL_MAX   = int(os.getenv("SP_POOL_MAXSIZE", "200"))

# anti-GAP
SP_GATE_RETRY = os.getenv("SP_GATE_RETRY", "1") == "1"   # tenta 1 retry ao detectar gate
JIT_MIN = float(os.getenv("SP_JITTER_MIN", "0.10"))
JIT_MAX = float(os.getenv("SP_JITTER_MAX", "0.30"))

# controle de concorrência (por processo)
MAX_CONCURRENCY = int(os.getenv("SP_MAX_CONCURRENCY", "8"))
_sem = threading.Semaphore(MAX_CONCURRENCY)

# opcional: referer coerente com o domínio
SP_REFERER = os.getenv("SP_REFERER", "").strip()

# ===== sessão HTTP (requests) =====
session = requests.Session()
retry = Retry(
    total=1,
    backoff_factor=0.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"])
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=POOL_CONN, pool_maxsize=POOL_MAX)
session.mount("https://", adapter)
session.mount("http://", adapter)
session.trust_env = False  # ignora proxies do SO

# ===== round-robin de endpoints =====
_cycle = itertools.cycle(ENDPOINTS) if ENDPOINTS else None
def pick_proxies():
    """
    Retorna (endpoint, proxies dict) para esta requisição.
    - Rotating (10000): sempre o mesmo host:porta -> IP troca por conexão.
    - Sticky (10001..): avança round-robin entre portas.
    """
    ep = next(_cycle) if _cycle else None
    if not ep and _raw_eps:
        ep = _raw_eps
    if not ep:
        return None, None
    proxy_str = f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}"
    return ep, {"http": proxy_str, "https": proxy_str}

# ===== headers tipo navegador =====
DEFAULT_OUT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",  # sem 'br'
    "Upgrade-Insecure-Requests": "1",
    # client hints / sec-fetch coerentes com CORS cross-site
    "sec-ch-ua": '"Chromium";v="120", "Google Chrome";v="120", "Not A(Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
}
# Conexão: para ROTATING é melhor fechar o túnel a cada request
DEFAULT_OUT_HEADERS["Connection"] = "close" if ROTATING_MODE else "keep-alive"
if SP_REFERER:
    DEFAULT_OUT_HEADERS["Referer"] = SP_REFERER
    DEFAULT_OUT_HEADERS["sec-fetch-site"] = "same-origin"

# ===== utils =====
def is_allowed(target: str) -> bool:
    try:
        u = urlparse(target)
        if u.scheme not in ("http", "https"):
            return False
        host = (u.hostname or "").lower()
        if host in ALLOWED_EXACT:
            return True
        return any(host.endswith(s) for s in ALLOWED_SUFFIXES)
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
        "Content-Length, X-Proxy-Final-Url, X-Proxy-Redirect-Count, X-Proxy-Endpoint, X-Proxy-Error"
    )
    resp.headers["Access-Control-Max-Age"] = "86400"
    resp.headers["Vary"] = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"
    return resp

def looks_like_gate(resp) -> bool:
    try:
        url = getattr(resp, "url", "") or ""
        if "account-verification" in url:
            return True
        if resp.status_code in (403, 429):
            return True
        ct = resp.headers.get("content-type", "")
        if "text/html" in ct:
            body = (resp.content or b"")[:40000].lower()
            if b"account-verification" in body or b"verify" in body and b"account" in body:
                return True
    except Exception:
        pass
    return False

# ===== rotas =====
@app.route("/", defaults={"raw": ""}, methods=["OPTIONS"])
@app.route("/<path:raw>", methods=["OPTIONS"])
def _opts(raw):
    return add_cors(Response(status=204))

@app.route("/_health", methods=["GET"])
def _health():
    return "ok", 200

@app.route("/_proxy_check", methods=["GET"])
def _proxy_check():
    try:
        ep, proxies = pick_proxies()
        r = session.get("https://ip.decodo.com/json", timeout=(CONNECT_TO, READ_TO), proxies=proxies)
        resp = Response(r.text, 200, {"Content-Type": "application/json"})
        if ep: resp.headers["X-Proxy-Endpoint"] = ep
        return resp
    except Exception as e:
        body = jsonify({"error": str(e)})
        return Response(body.get_data(as_text=True), status=502, mimetype="application/json")

# GET/HEAD – compatível com a extensão
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

    # monta headers sem Cookie/Referer do cliente
    headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization","Content-Type","Accept","Accept-Language","User-Agent",
              "Range","If-None-Match","If-Modified-Since"):
        v = request.headers.get(k)
        if v:
            headers[k] = v

    # espalhar um pouco (jitter sempre ajuda)
    if JIT_MAX > 0:
        time.sleep(random.uniform(JIT_MIN, JIT_MAX))

    # controla concorrência
    with _sem:
        ep1, proxies1 = pick_proxies()
        try:
            r = session.request(
                method=request.method,
                url=target,
                headers=headers,
                allow_redirects=True,
                timeout=(CONNECT_TO, READ_TO),
                verify=True,
                stream=False,
                proxies=proxies1,
            )
        except Exception as e:
            body = jsonify({"error": str(e), "endpoint": ep1 or ""})
            resp = Response(body.get_data(as_text=True), status=502, mimetype="application/json")
            if ep1: resp.headers["X-Proxy-Endpoint"] = ep1
            resp.headers["X-Proxy-Error"] = str(e)
            return add_cors(resp)

    # retry único se identificar GAP
    if SP_GATE_RETRY and looks_like_gate(r):
        time.sleep(random.uniform(JIT_MIN, JIT_MAX))
        with _sem:
            ep2, proxies2 = pick_proxies()
            try:
                r2 = session.request(
                    method=request.method,
                    url=target,
                    headers=headers,
                    allow_redirects=True,
                    timeout=(CONNECT_TO, READ_TO),
                    verify=True,
                    stream=False,
                    proxies=proxies2,
                )
                # só troca se o r2 não for gate
                if not looks_like_gate(r2):
                    r, ep1 = r2, (ep2 or ep1)
            except Exception as e:
                body = jsonify({"error": str(e), "endpoint": ep2 or ep1 or ""})
                resp = Response(body.get_data(as_text=True), status=502, mimetype="application/json")
                if ep2 or ep1: resp.headers["X-Proxy-Endpoint"] = (ep2 or ep1)
                resp.headers["X-Proxy-Error"] = str(e)
                return add_cors(resp)

    # devolve a resposta do destino
    resp = Response(r.content if request.method == "GET" else b"", status=r.status_code)
    hop_by_hop = {"transfer-encoding","connection","keep-alive","proxy-authenticate",
                  "proxy-authorization","te","trailers","upgrade"}
    for k, v in r.headers.items():
        lk = k.lower()
        if lk in hop_by_hop:
            continue
        if lk in ("content-type","cache-control","etag","last-modified",
                  "content-range","accept-ranges","location","content-length"):
            resp.headers[k] = v

    resp.headers["X-Proxy-Final-Url"] = getattr(r, "url", target)
    resp.headers["X-Proxy-Redirect-Count"] = str(len(getattr(r, "history", [])))
    if ep1: resp.headers["X-Proxy-Endpoint"] = ep1
    return add_cors(resp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
