# server_proxy.py
from flask import Flask, request, Response
from flask_cors import CORS
import requests, os
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

app = Flask(__name__)
CORS(app, supports_credentials=True)

ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

# ---------- Sessão HTTP com Retry + Proxy ----------
session = requests.Session()
retry = Retry(
    total=3, backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
session.mount("https://", adapter)
session.mount("http://", adapter)

# Smartproxy (Decodo) via env
SP_ENDPOINT = os.getenv("SP_ENDPOINT")      # ex.: br.decodo.com:10001 (sticky 10min)
SP_USERNAME = os.getenv("SP_USERNAME")      # ex.: spv25y9c1j
SP_PASSWORD = os.getenv("SP_PASSWORD")      # sua senha
if SP_ENDPOINT and SP_USERNAME and SP_PASSWORD:
    PROXY_URL = f"http://{SP_USERNAME}:{SP_PASSWORD}@{SP_ENDPOINT}"
    session.proxies.update({"http": PROXY_URL, "https": PROXY_URL})
    session.trust_env = False  # ignora proxies do SO

DEFAULT_OUT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    # evita 'br' pra não precisar de brotli no servidor
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Connection": "keep-alive",
}

def is_allowed(target: str) -> bool:
    try:
        u = urlparse(target)
        if u.scheme not in ("http", "https"):
            return False
        host = (u.hostname or "").lower()
        if host in ALLOWED_EXACT:
            return True
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

@app.route("/", defaults={"raw": ""}, methods=["GET"])
@app.route("/<path:raw>", methods=["GET"])
def proxy(raw: str):
    if not raw:
        return add_cors(Response("Target URL ausente", status=400))

    target = raw
    q = request.query_string.decode("utf-8")
    if q:
        target = f"{target}{'&' if '?' in target else '?'}{q}"

    if not is_allowed(target):
        return add_cors(Response("Host não permitido", status=400))

    # NÃO forward de Cookie (evita conta real) — só cabeçalhos “seguros”
    forward_headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization","Content-Type","Accept","Accept-Language",
              "User-Agent","Range","If-None-Match","If-Modified-Since","Referer"):
        v = request.headers.get(k)
        if v:
            forward_headers[k] = v

    try:
        r = session.request(
            method="GET",
            url=target,
            headers=forward_headers,
            allow_redirects=True,
            timeout=(10, 60),  # connect, read
            stream=False,
            verify=True,
        )
    except requests.RequestException as e:
        return add_cors(Response(f"Erro ao contatar destino: {e}", status=502))

    resp = Response(r.content, status=r.status_code)
    hop_by_hop = {"transfer-encoding","connection","keep-alive","proxy-authenticate",
                  "proxy-authorization","te","trailers","upgrade"}
    for k, v in r.headers.items():
        lk = k.lower()
        if lk in hop_by_hop:
            continue
        if lk in ("content-type","cache-control","etag","last-modified",
                  "content-range","accept-ranges","location"):
            resp.headers[k] = v

    resp.headers["X-Proxy-Final-Url"] = getattr(r, "url", target)
    resp.headers["X-Proxy-Redirect-Count"] = str(len(getattr(r, "history", [])))
    return add_cors(resp)
    @app.route("/_proxy_check", methods=["GET"])
    
def _proxy_check():
    r = session.get("https://ip.decodo.com/json", timeout=(8, 30))
    return (r.text, 200, {"Content-Type": "application/json"})

