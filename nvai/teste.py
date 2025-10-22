# server_proxy.py
from flask import Flask, request, Response, jsonify
from flask_cors import CORS
import os, re, itertools, threading, time, random
import requests
from urllib.parse import urlparse, unquote, parse_qs
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import http.cookiejar as cookielib

app = Flask(__name__)
CORS(app, supports_credentials=True)

ALLOWED_EXACT = {"api.mercadolibre.com"}
ALLOWED_SUFFIXES = (".mercadolivre.com.br", ".mercadolibre.com")

SP_USERNAME = os.getenv("SP_USERNAME","").strip()
SP_PASSWORD = os.getenv("SP_PASSWORD","").strip()
_raw_eps = (os.getenv("SP_ENDPOINTS") or os.getenv("SP_ENDPOINT") or "").strip()
ENDPOINTS = [e.strip() for e in re.split(r"[,\s]+", _raw_eps) if e.strip()]

CONNECT_TO = float(os.getenv("SP_CONNECT_TIMEOUT", "3.5"))
READ_TO    = float(os.getenv("SP_READ_TIMEOUT", "5.5"))
POOL_CONN  = int(os.getenv("SP_POOL_CONNECTIONS", "100"))
POOL_MAX   = int(os.getenv("SP_POOL_MAXSIZE", "200"))

SP_GATE_RETRY = os.getenv("SP_GATE_RETRY", "1") == "1"
JIT_MIN = float(os.getenv("SP_JITTER_MIN", "0.02"))
JIT_MAX = float(os.getenv("SP_JITTER_MAX", "0.12"))
SP_SECOND_CHANCE_5XX = os.getenv("SP_SECOND_CHANCE_5XX", "1") == "1"

MAX_CONCURRENCY = int(os.getenv("SP_MAX_CONCURRENCY", "16"))
_sem = threading.Semaphore(MAX_CONCURRENCY)

BATCH_MIN = int(os.getenv("SP_STICKY_BATCH_MIN", "3"))
BATCH_MAX = int(os.getenv("SP_STICKY_BATCH_MAX", "6"))
ASSIGN_JIT_MS_MIN = int(os.getenv("SP_ASSIGN_JITTER_MS_MIN", "20"))
ASSIGN_JIT_MS_MAX = int(os.getenv("SP_ASSIGN_JITTER_MS_MAX", "80"))
PER_IP_DELAY_MS_MIN = int(os.getenv("SP_PER_IP_DELAY_MS_MIN", "80"))
PER_IP_DELAY_MS_MAX = int(os.getenv("SP_PER_IP_DELAY_MS_MAX", "220"))

SP_CANONICALIZE_ITEM = os.getenv("SP_CANONICALIZE_ITEM", "1") == "1"
SP_REFERER = os.getenv("SP_REFERER","").strip()

session = requests.Session()
class _NoCookiesPolicy(cookielib.CookiePolicy):
    rfc2965 = hide_cookie2 = True
    def set_ok(self, *a, **kw): return False
    def return_ok(self, *a, **kw): return False
    def domain_return_ok(self, *a, **kw): return False
    def path_return_ok(self, *a, **kw): return False

# cria um jar vazio e bloqueia set/return
session.cookies = cookielib.CookieJar()
session.cookies.set_policy(_NoCookiesPolicy())
retry = Retry(total=1, backoff_factor=0.0,
              status_forcelist=[429,500,502,503,504],
              allowed_methods=frozenset(["HEAD","GET","OPTIONS"]))
adapter = HTTPAdapter(max_retries=retry, pool_connections=POOL_CONN, pool_maxsize=POOL_MAX)
session.mount("https://", adapter); session.mount("http://", adapter)
session.trust_env = False

# --- onde você define os headers padrão ---
DEFAULT_OUT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",  # aceita brotli como um navegador real
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "sec-ch-ua": '"Chromium";v="120", "Google Chrome";v="120", "Not A(Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
}

if SP_REFERER:
    DEFAULT_OUT_HEADERS["Referer"] = SP_REFERER
    DEFAULT_OUT_HEADERS["sec-fetch-site"] = "same-origin"

def is_allowed(target: str) -> bool:
    try:
        u = urlparse(target)
        if u.scheme not in ("http","https"): return False
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
        "Content-Length, X-Proxy-Final-Url, X-Proxy-Canonical-Url, X-Proxy-Redirect-Count, "
        "X-Proxy-Redirect-Chain, X-Proxy-Endpoint, X-Proxy-Error, X-Proxy-Action"
    )
    resp.headers["Access-Control-Max-Age"] = "86400"
    resp.headers["Vary"] = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method"
    return resp

def looks_like_gate(resp) -> bool:
    try:
        url = getattr(resp,"url","") or ""
        if "account-verification" in url: return True
        if resp.status_code in (403,429): return True
        ct = resp.headers.get("content-type","")
        if "text/html" in ct:
            body = (resp.content or b"")[:40000].lower()
            if b"account-verification" in body:
                return True
    except Exception:
        pass
    return False

def normalize_mlb(s: str|None) -> str|None:
    if not s: return None
    m = re.search(r"MLB-?(\d+)", s, re.I)
    return f"MLB-{m.group(1)}".upper() if m else None

def extract_mlb_from_url(url: str) -> str|None:
    m = re.search(r"(MLB-?\d+)", url or "", re.I)
    return normalize_mlb(m.group(1)) if m else None

def extract_mlb_from_pdp_filters(url: str) -> str|None:
    try:
        q = parse_qs(urlparse(url).query)
        for key, vals in q.items():
            if key.lower() == "pdp_filters":
                joined = ",".join(vals)
                m = re.search(r"item_id:(MLB-?\d+)", joined, re.I)
                if m: return normalize_mlb(m.group(1))
    except Exception: pass
    return None

def extract_mlb_from_html(html: bytes) -> str|None:
    # tenta canonical, og:url e fallback regex
    try:
        txt = html.decode("utf-8", errors="ignore")
    except Exception:
        try: txt = html.decode("latin-1", errors="ignore")
        except Exception: return None
    m = re.search(r'rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']', txt, re.I)
    if m:
        mlb = extract_mlb_from_url(m.group(1))
        if mlb: return mlb
    m = re.search(r'property=["\']og:url["\'][^>]*content=["\']([^"\']+)["\']', txt, re.I)
    if m:
        mlb = extract_mlb_from_url(m.group(1))
        if mlb: return mlb
    m = re.search(r'https?://produto\.mercadolivre\.com\.br/MLB-?\d+', txt, re.I)
    if m:
        mlb = extract_mlb_from_url(m.group(0))
        if mlb: return mlb
    m = re.search(r'\b(MLB-?\d+)\b', txt, re.I)
    if m:
        return normalize_mlb(m.group(1))
    return None

class EpState:
    __slots__=("endpoint","remaining","last_ts")
    def __init__(self, endpoint:str):
        self.endpoint=endpoint; self.remaining=0; self.last_ts=0.0

_states = [EpState(e) for e in ENDPOINTS] or []
_idx=0; _lock=threading.Lock()

def _new_batch(): return random.randint(max(1,BATCH_MIN), max(BATCH_MIN,BATCH_MAX))
def _ms(n): return n/1000.0

def pick_sticky_endpoint():
    global _idx
    if not _states: return None, None, 0.0
    with _lock:
        time.sleep(_ms(random.randint(ASSIGN_JIT_MS_MIN, ASSIGN_JIT_MS_MAX)))
        for _ in range(len(_states)):
            s=_states[_idx]; _idx=( _idx + 1 ) % len(_states)
            if s.remaining>0:
                s.remaining-=1; chosen=s; break
        else:
            s=_states[_idx]; _idx=( _idx + 1 ) % len(_states)
            s.remaining=_new_batch()-1; chosen=s
        now=time.time(); need_gap=random.randint(PER_IP_DELAY_MS_MIN, PER_IP_DELAY_MS_MAX)
        sleep_needed=0.0
        if chosen.last_ts>0:
            elapsed_ms=(now-chosen.last_ts)*1000.0
            if elapsed_ms<need_gap: sleep_needed=_ms(need_gap-int(elapsed_ms))
        chosen.last_ts=max(now, now+sleep_needed); ep=chosen.endpoint
    proxy=f"http://{SP_USERNAME}:{SP_PASSWORD}@{ep}"
    return ep, {"http":proxy,"https":proxy}, sleep_needed

def redirect_chain(r):
    chain=[]
    for h in (r.history or []):
        loc = h.headers.get("Location","")
        chain.append(f"{h.status_code}:{loc}")
    chain.append(f"{r.status_code}:{getattr(r,'url','')}")
    return " | ".join(chain[:12])

@app.route("/", defaults={"raw": ""}, methods=["OPTIONS"])
@app.route("/<path:raw>", methods=["OPTIONS"])
def _opts(raw): return add_cors(Response(status=204))

@app.route("/_health", methods=["GET"])
def _health(): return "ok", 200

@app.route("/_proxy_check", methods=["GET"])
def _proxy_check():
    try:
        ep, proxies, extra_sleep = pick_sticky_endpoint()
        if extra_sleep: time.sleep(extra_sleep)
        r = session.get("https://ip.decodo.com/json", timeout=(CONNECT_TO, READ_TO), proxies=proxies)
        resp = Response(r.text, 200, {"Content-Type":"application/json"})
        if ep: resp.headers["X-Proxy-Endpoint"]=ep
        return resp
    except Exception as e:
        body = jsonify({"error":str(e)})
        return Response(body.get_data(as_text=True), status=502, mimetype="application/json")

@app.route("/", defaults={"raw": ""}, methods=["GET","HEAD"])
@app.route("/<path:raw>", methods=["GET","HEAD"])
def proxy(raw: str):
    if not raw:
        return add_cors(Response("OK - use /https://<url-destino>", status=200))

    orig_target = unquote(raw)
    target = orig_target
    q = request.query_string.decode("utf-8")
    if q: target = f"{target}{'&' if '?' in target else '?'}{q}"
    if not is_allowed(target):
        return add_cors(Response("Host não permitido", status=400))

    headers = dict(DEFAULT_OUT_HEADERS)
    for k in ("Authorization","Content-Type","Accept","Accept-Language","User-Agent",
              "Range","If-None-Match","If-Modified-Since"):
        v = request.headers.get(k)
        if v: headers[k]=v
    if JIT_MAX>0: time.sleep(random.uniform(JIT_MIN,JIT_MAX))

    actions=[]; canonical_mlb=None; canon_from=""

    def do_request(ep, proxies, url_to_get, hdrs):
        return session.request(
            method=request.method,
            url=url_to_get,
            headers=hdrs,
            allow_redirects=True,
            timeout=(CONNECT_TO, READ_TO),
            verify=True,
            stream=False,
            proxies=proxies,
            cookies={}  # <- zera cookies por requisição
        )

    # 1ª chamada
    with _sem:
        ep1, proxies1, extra_sleep = pick_sticky_endpoint()
        if extra_sleep: time.sleep(extra_sleep)
        try:
            r = do_request(ep1, proxies1, target, headers)
        except Exception as e:
            body = jsonify({"error":str(e), "endpoint":ep1 or ""})
            resp = Response(body.get_data(as_text=True), status=502, mimetype="application/json")
            if ep1: resp.headers["X-Proxy-Endpoint"]=ep1
            resp.headers["X-Proxy-Error"]=str(e)
            return add_cors(resp)

    # anti-GAP retry
    if SP_GATE_RETRY and looks_like_gate(r):
        with _sem:
            ep2, proxies2, extra_sleep2 = pick_sticky_endpoint()
            if extra_sleep2: time.sleep(extra_sleep2)
            try:
                r2 = do_request(ep2, proxies2, target, headers)
                if not looks_like_gate(r2):
                    r, ep1 = r2, (ep2 or ep1); actions.append("gate-retry")
            except Exception as e:
                body = jsonify({"error":str(e), "endpoint":ep2 or ep1 or ""})
                resp = Response(body.get_data(as_text=True), status=502, mimetype="application/json")
                if ep2 or ep1: resp.headers["X-Proxy-Endpoint"]=(ep2 or ep1)
                resp.headers["X-Proxy-Error"]=str(e)
                return add_cors(resp)

    # 2nd-chance 5xx
    if SP_SECOND_CHANCE_5XX and r.status_code in (502,503,504):
        with _sem:
            ep3, proxies3, extra_sleep3 = pick_sticky_endpoint()
            if extra_sleep3: time.sleep(extra_sleep3)
            try:
                r3 = do_request(ep3, proxies3, target, headers)
                if r3.status_code < 500:
                    r, ep1 = r3, (ep3 or ep1); actions.append("retry-5xx")
            except Exception as e:
                actions.append(f"retry-5xx-error:{str(e)[:30]}")

    # ===== CANONIZAÇÃO =====
    if SP_CANONICALIZE_ITEM:
        final_url = getattr(r,"url","") or ""
        u = urlparse(final_url); host=(u.hostname or "").lower(); path=u.path or ""; query=u.query or ""
        needs_item = (
            host.endswith("mercadolivre.com.br") and (
                "/p/" in path or "/up/" in path or "/catalogo/" in path or "pdp_filters=" in query
            )
        )

        # também corrige produto sem hífen (ex.: /MLB123456)
        if host == "produto.mercadolivre.com.br":
            m = re.search(r"/MLB(\d+)$", path, re.I)
            if m:
                canonical_mlb = f"MLB-{m.group(1)}"; canon_from="fix-hyphen"
                actions.append("canon-fix-hyphen")
                final_url = f"https://produto.mercadolivre.com.br/{canonical_mlb}"
            # mesmo estando em produto, se houver pdp_filters, trate também
            needs_item = needs_item or ("pdp_filters=" in query)

        if needs_item:
            # ordem de extração
            canonical_mlb = (
                extract_mlb_from_pdp_filters(final_url) or
                extract_mlb_from_url(orig_target) or
                extract_mlb_from_url(final_url)
            )
            if not canonical_mlb and r.headers.get("content-type","").lower().startswith("text/html"):
                canonical_mlb = extract_mlb_from_html(r.content)
                if canonical_mlb: canon_from="html"
            else:
                if canonical_mlb and not canon_from: canon_from="url|query"

            canonical_mlb = normalize_mlb(canonical_mlb)

            if canonical_mlb:
                force_url = f"https://produto.mercadolivre.com.br/{canonical_mlb}"
                forced_headers = dict(headers)
                forced_headers["Referer"] = f"https://produto.mercadolivre.com.br/{canonical_mlb}"
                forced_headers["sec-fetch-site"] = "same-origin"
                with _sem:
                    ep4, proxies4, sleep4 = pick_sticky_endpoint()
                    if sleep4: time.sleep(sleep4)
                    try:
                        r4 = do_request(ep4, proxies4, force_url, forced_headers)
                        # se o ML redirecionar de volta para www, a gente aceita o conteúdo
                        # mas ainda assim marca o canonical nos headers (pra seu card).
                        if r4.status_code < 500 and not looks_like_gate(r4):
                            r, ep1 = r4, (ep4 or ep1)
                            actions.append(f"canon-item({canon_from or 'url'})")
                    except Exception as e:
                        actions.append(f"canon-error:{str(e)[:30]}")

    # ===== resposta =====
    resp = Response(r.content if request.method == "GET" else b"", status=r.status_code)
    hop_by_hop={"transfer-encoding","connection","keep-alive","proxy-authenticate",
                "proxy-authorization","te","trailers","upgrade"}
    for k,v in r.headers.items():
        lk=k.lower()
        if lk in hop_by_hop: continue
        if lk in ("content-type","cache-control","etag","last-modified","content-encoding","content-range","accept-ranges","location","vary"):
            resp.headers[k]=v

    # final/report
    chain = redirect_chain(r)
    actual_final = getattr(r,"url", target)
    # força o header para produto se soubermos o MLB (isso destrava seu card)
    canonical_url = f"https://produto.mercadolivre.com.br/{canonical_mlb}" if canonical_mlb else ""
    header_final = canonical_url or actual_final

    resp.headers["X-Proxy-Final-Url"] = header_final
    if canonical_url: resp.headers["X-Proxy-Canonical-Url"] = canonical_url
    resp.headers["X-Proxy-Redirect-Count"] = str(len(getattr(r,"history",[])))
    resp.headers["X-Proxy-Redirect-Chain"] = chain
    if ep1: resp.headers["X-Proxy-Endpoint"] = ep1
    if actions: resp.headers["X-Proxy-Action"] = ",".join(actions)
    return add_cors(resp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT","8080")))



