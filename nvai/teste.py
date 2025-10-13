from flask import Flask, request, Response
from flask_cors import CORS
import requests, re
from urllib.parse import urlparse, urljoin
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

app = Flask(__name__)
# CORS bem permissivo (igual ao mfy-cors): usamos "*" sem credenciais
CORS(app, supports_credentials=False)

# ----- allowlist de hosts -----
ALLOWED_EXACT = {
    "api.mercadolibre.com",
}
ALLOWED_SUFFIXES = (
    ".mercadolivre.com.br",
    ".mercadolibre.com",
)

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

# ----- sessão requests com retry/pool -----
session = requests.Session()
retry = Retry(total=2, backoff_factor=0.2, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
session.mount("https://", adapter)
session.mount("http://", adapter)

DEFAULT_OUT_HEADERS = {
    "User-Agent":  ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control":   "no-cache",
    "Pragma":          "no-cache",
}

def add_cors(resp: Response):
    # Como supports_credentials=False, podemos soltar "*"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = request.headers.get("Access-Control-Request-Method") or "GET,HEAD,OPTIONS"
    allow_headers = request.headers.get("Access-Control-Request-Headers") or "Content-Type, Authorization, If-None-Match, If-Modified-Since, Range, Cache-Control, Pragma"
    resp.headers["Access-Control-Allow-Headers"] = allow_headers
    # headers expostos (inclui x-final-url igual o mfy-cors)
    resp.headers["Access-Control-Expose-Headers"] = (
        "content-type,transfer-encoding,connection,date,server,expect-ct,referrer-policy,strict-transport-security,"
        "x-content-type-options,x-dns-prefetch-control,x-download-options,x-permitted-cross-domain-policies,x-xss-protection,"
        "accept-ch,accept-ch-lifetime,content-security-policy,content-security-policy-report-only,reporting-endpoints,"
        "cache-control,x-navigation-version,etag,vary,content-encoding,x-envoy-upstream-service-time,x-request-id,"
        "x-final-url,access-control-allow-origin"
    )
    resp.headers["Access-Control-Max-Age"] = "86400"
    resp.headers["Vary"] = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"
    return resp

# ---------- OPTIONS (preflight) ----------
@app.route("/", defaults={"raw": ""}, methods=["OPTIONS"])
@app.route("/<path:raw>", methods=["OPTIONS"])
def _opts(raw):
    return add_cors(Response(status=204))

# ---------- Proxy estilo PREFIXO: https://SEU_RAILWAY/https://alvo... ----------
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

    # monta headers de saída
    forward_headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization", "Content-Type", "Accept", "Accept-Language",
              "User-Agent", "Range", "If-None-Match", "If-Modified-Since", "Referer"):
        v = request.headers.get(k)
        if v:
            forward_headers[k] = v

    try:
        r = session.request(
            method="GET",
            url=target,
            headers=forward_headers,
            allow_redirects=True,
            timeout=(5, 30),
            stream=False,
        )
    except requests.RequestException as e:
        return add_cors(Response(f"Erro ao contatar destino: {e}", status=502))

    # monta a resposta
    resp = Response(r.content, status=r.status_code)

    # propaga alguns headers úteis (evita hop-by-hop)
    hop_by_hop = {
        "transfer-encoding", "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers", "upgrade"
    }
    for k, v in r.headers.items():
        lk = k.lower()
        if lk in hop_by_hop:
            continue
        if lk in ("content-type", "cache-control", "etag", "last-modified",
                  "content-range", "accept-ranges", "location", "vary", "content-encoding"):
            resp.headers[k] = v

    # header diagnóstico (igual mfy-cors usa x-final-url)
    try:
        resp.headers["x-final-url"] = r.url
    except Exception:
        pass

    return add_cors(resp)
