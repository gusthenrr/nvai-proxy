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

# --- destinos permitidos (ML + API) ---
ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

# ---------- sessão HTTP base (sem proxy fixo) ----------
session = requests.Session()
retry = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=frozenset(["HEAD", "GET", "OPTIONS"])
)
adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
session.mount("https://", adapter)
session.mount("http://", adapter)
session.trust_env = False

# ---------- proxies Decodo/Smartproxy ----------
SP_USERNAME = os.getenv("SP_USERNAME", "")
SP_PASSWORD = os.getenv("SP_PASSWORD", "")
_endpoints = os.getenv("SP_ENDPOINTS") or os.getenv("SP_ENDPOINT") or ""
ENDPOINTS = [e.strip() for e in _endpoints.split(",") if e.strip()]
# round-robin: gira 1 porta por requisição
_cycle = itertools.cycle(ENDPOINTS) if ENDPOINTS else None

def pick_proxies():
    if not _cycle:
        return None
    ep = next(_cycle)
    return {
        "http":  f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
        "https": f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}",
    }

# ---------- headers padrão (backend) ----------
DEFAULT_OUT_HEADERS = {
    # se a extensão mandar User-Agent, a gente substitui abaixo
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    # evitar 'br' para não exigir brotli no servidor
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
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

@app.route("/_health", methods=["GET"])
def _health():
    return "ok", 200

@app.route("/_proxy_check", methods=["GET"])
def _proxy_check():
    proxies = pick_proxies()
    r = session.get("https://ip.decodo.com/json", timeout=(5, 8), proxies=proxies)
    return (r.text, 200, {"Content-Type": "application/json"})

def looks_like_gate(resp) -> bool:
    # gate do ML: redireciona ou injeta 'account-verification'
    url = getattr(resp, "url", "") or ""
    if "account-verification" in url:
        return True
    if resp.status_code in (403, 429):
        return True
    ct = resp.headers.get("content-type", "")
    if "text/html" in ct:
        body = resp.content[:50000].lower()
        if b"account-verification" in body:
            return True
    return False

# --- GET/HEAD (compatível com tua extensão) ---
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
    # dá prioridade ao User-Agent enviado pela extensão
    for k in ("Authorization","Content-Type","Accept","Accept-Language",
              "User-Agent","Range","If-None-Match","If-Modified-Since"):
        v = request.headers.get(k)
        if v:
            forward_headers[k] = v

    # até 2 tentativas (portes diferentes) dentro do timeout de 30s da extensão
    attempts = 2
    last_exc = None
    for i in range(attempts):
        proxies = pick_proxies()
        try:
            r = session.request(
                method=request.method,
                url=target,
                headers=forward_headers,
                allow_redirects=True,      # extensão usa "follow" por padrão
                timeout=(5, 8),            # connect, read — cabe nos 30s totais
                stream=False,
                verify=True,
                proxies=proxies,
            )

            # se parecer gate e ainda tiver outra porta, tenta de novo
            if looks_like_gate(r) and i < attempts - 1:
                time.sleep(random.uniform(0.5, 1.2))   # jitter curto
                continue

            # monta resposta para o browser
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
            return add_cors(resp)

        except requests.RequestException as e:
            last_exc = e
            if i < attempts - 1:
                time.sleep(random.uniform(0.5, 1.2))
                continue
            return add_cors(Response(f"Erro ao contatar destino: {e}", status=502))

    return add_cors(Response(f"Erro: {last_exc}", status=502))
