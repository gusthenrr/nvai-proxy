# server_proxy.py
from flask import Flask, request, Response, jsonify
from flask_cors import CORS
import os, itertools, requests, re
from urllib.parse import urlparse, unquote
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ===== destinos permitidos (ML + API) =====
ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

# ===== ENV / Config =====
SP_USERNAME = os.getenv("SP_USERNAME", "").strip()
SP_PASSWORD = os.getenv("SP_PASSWORD", "").strip()

_raw_eps = (os.getenv("SP_ENDPOINTS") or os.getenv("SP_ENDPOINT") or "")
# aceita vírgula, espaço e quebras de linha
ENDPOINTS = [e.strip() for e in re.split(r"[,\s]+", _raw_eps) if e.strip()]

CONNECT_TO = float(os.getenv("SP_CONNECT_TIMEOUT", "4"))
READ_TO    = float(os.getenv("SP_READ_TIMEOUT", "6"))
POOL_CONN  = int(os.getenv("SP_POOL_CONNECTIONS", "100"))
POOL_MAX   = int(os.getenv("SP_POOL_MAXSIZE", "200"))
DEBUG      = os.getenv("SP_DEBUG", "0") == "1"
SP_REFERER = os.getenv("SP_REFERER", "").strip()  # opcional: ex. https://www.mercadolivre.com.br/

# ===== sessão HTTP =====
session = requests.Session()
retry = Retry(
    total=1, backoff_factor=0.0,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"])
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=POOL_CONN, pool_maxsize=POOL_MAX)
session.mount("https://", adapter)
session.mount("http://", adapter)
session.trust_env = False

# round-robin de portas (ou única porta)
_cycle = itertools.cycle(ENDPOINTS) if ENDPOINTS else None
def pick_proxies():
    ep = None
    if _cycle:
        ep = next(_cycle)
    elif _raw_eps.strip():
        ep = _raw_eps.strip()
    if not ep:
        return None, None
    proxies = {
        "http":  f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
        "https": f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
    }
    return ep, proxies

# ===== headers “de navegador” =====
DEFAULT_OUT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",      # sem 'br' p/ evitar dependência
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    # client hints + sec-fetch (ajuda em “catalog”)
    "sec-ch-ua": '"Chromium";v="120", "Google Chrome";v="120", "Not A(Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-site": "none",                # muda p/ same-origin se usar SP_REFERER
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
}
if SP_REFERER:
    DEFAULT_OUT_HEADERS["Referer"] = SP_REFERER
    DEFAULT_OUT_HEADERS["sec-fetch-site"] = "same-origin"

# ===== utils =====
def is_allowed(target: str) -> bool:
    try:
        u = urlparse(target)
        if u.scheme not in ("http", "https"): return False
        host = (u.hostname or "").lower()
        if host in ALLOWED_EXACT: return True
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
    url = getattr(resp, "url", "") or ""
    if "account-verification" in url: return True
    if resp.status_code in (403, 429): return True
    ct = resp.headers.get("content-type", "")
    if "text/html" in ct:
        body = resp.content[:40000].lower()
        if b"account-verification" in body:
            return True
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
    ep, proxies = pick_proxies()
    r = session.get("https://ip.decodo.com/json", timeout=(CONNECT_TO, READ_TO), proxies=proxies)
    resp = Response(r.text, 200, {"Content-Type": "application/json"})
    if ep: resp.headers["X-Proxy-Endpoint"] = ep
    return resp

@app.route("/_diag_endpoints", methods=["GET"])
def _diag_endpoints():
    """Testa todas as portas rapidamente e mostra quais falham (pega só status/IP)."""
    out = []
    for ep in ENDPOINTS or ([_raw_eps.strip()] if _raw_eps.strip() else []):
        proxies = {
            "http":  f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
            "https": f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
        }
        item = {"endpoint": ep}
        try:
            rr = session.get("https://ip.decodo.com/json", timeout=(2.5, 4.0), proxies=proxies)
            item["ok"] = True
            item["status"] = rr.status_code
        except Exception as e:
            item["ok"] = False
            item["error"] = str(e)
        out.append(item)
    return jsonify(out), 200

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

    # nunca repassar Cookie; prioriza UA do cliente se vier
    forward_headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization","Content-Type","Accept","Accept-Language",
              "User-Agent","Range","If-None-Match","If-Modified-Since"):
        v = request.headers.get(k)
        if v: forward_headers[k] = v

    ep, proxies = pick_proxies()
    try:
        r = session.request(
            method=request.method,
            url=target,
            headers=forward_headers,
            allow_redirects=True,
            timeout=(CONNECT_TO, READ_TO),
            stream=False,
            verify=True,
            proxies=proxies,
        )
    except requests.RequestException as e:
        # retorno 502 com detalhes – facilita achar porta/erro ruim
        body = jsonify({"error": str(e), "endpoint": ep or ""})
        resp = Response(body.get_data(as_text=True), status=502, mimetype="application/json")
        if ep: resp.headers["X-Proxy-Endpoint"] = ep
        resp.headers["X-Proxy-Error"] = str(e)
        return add_cors(resp)

    # sucesso (mesmo que 302/304/etc – a extensão sabe lidar)
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
    if ep: resp.headers["X-Proxy-Endpoint"] = ep
    return add_cors(resp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
