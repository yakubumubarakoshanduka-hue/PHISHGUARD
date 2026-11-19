"""PhishGuard server. Uses only Python's standard library: no pip install, works offline."""
import json, os, re, time, urllib.request, xml.etree.ElementTree as ET
import concurrent.futures as cf
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import database, detector, mining

ROOT = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static") + os.sep
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml"}
GN = "https://news.google.com/rss/search?hl=en-NG&gl=NG&ceid=NG:en&q="
FEEDS = [  # (name, url, needs keyword filter)
 ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/", True), ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", True),
 ("Sophos News", "https://nakedsecurity.sophos.com/feed/", True), ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", True),
 ("SecurityWeek", "https://feeds.feedburner.com/securityweek", True), ("Help Net Security", "https://www.helpnetsecurity.com/feed/", True),
 ("The Record", "https://therecord.media/feed", True), ("Dark Reading", "https://www.darkreading.com/rss.xml", True),
 ("TechCabal", "https://techcabal.com/feed/", True), ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", True),
 ("Google News", GN + "phishing+website", False), ("Google News", GN + "phishing+Nigeria", False),
 ("Google News", GN + "fake+website+scam+bank+Nigeria", False)]
KEYS = re.compile(r"phish|smish|vish|quishing|scam|fraud|spoof|impersonat|credential|fake (site|website|bank|app|login)|clone", re.I)
FALLBACK = [
 {"title": "Offline: never share your OTP, PIN or BVN with anyone", "link": "https://www.cbn.gov.ng", "source": "Safety tip", "date": ""},
 {"title": "Offline: verify .gov.ng and .edu.ng sites before paying any fee", "link": "https://www.nimc.gov.ng", "source": "Safety tip", "date": ""},
 {"title": "Offline: report phishing to your bank and to cert.gov.ng", "link": "https://cert.gov.ng", "source": "Safety tip", "date": ""},
]
last_try = 0
database.init()

def pull(src, url, filt):
    out = []
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "PhishGuard"}), timeout=4) as r:
            root = ET.fromstring(r.read())
        for i in root.iter("item"):
            t = i.findtext("title", "").strip()
            gn = src == "Google News"          # search feed is already about phishing; outlet name is in <source>
            if not gn and not KEYS.search(t + " " + (i.findtext("description", "") or "")[:400]): continue
            try: dt = parsedate_to_datetime(i.findtext("pubDate", ""))
            except Exception: dt = None
            out.append({"title": t, "link": i.findtext("link", "").strip(), "source": (i.findtext("source", "") or src).strip() if gn else src,
                        "ts": dt.timestamp() if dt else 0, "date": dt.strftime("%d %b %Y") if dt else ""})
    except Exception:
        pass
    return out

def fetch_news():
    global last_try
    items, ts = database.get_news()
    if (items and time.time() - ts < 1800) or time.time() - last_try < 300:
        return items or FALLBACK
    last_try = time.time()
    with cf.ThreadPoolExecutor(10) as ex:
        found = [x for chunk in ex.map(lambda f: pull(*f), FEEDS) for x in chunk]
    found.sort(key=lambda x: -x["ts"])
    seen, uniq = set(), []
    for x in found:
        if x["title"].lower() not in seen: seen.add(x["title"].lower()); uniq.append(x)
    if uniq:
        items = uniq[:40]; database.set_news(items)
    return items or FALLBACK

class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(data))),
                     ("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Headers", "Content-Type")):
            self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)

    def do_OPTIONS(self): self.reply(204, b"")

    def do_GET(self):
        p = urlparse(self.path).path
        api = {"/api/history": database.history, "/api/stats": database.stats, "/api/news": fetch_news,
           "/api/analysis": mining.analyze}
        if p in api: return self.reply(200, api[p]())
        full = os.path.realpath(os.path.join(ROOT, "index.html" if p == "/" else p.lstrip("/")))
        if (full == os.path.join(ROOT, "index.html") or full.startswith(STATIC)) and os.path.isfile(full):
            with open(full, "rb") as f:
                return self.reply(200, f.read(), TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))
        self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/scan": return self.reply(404, {"error": "Not found"})
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 10000)
            res = detector.analyze(json.loads(self.rfile.read(n) or b"{}").get("url", ""))
        except (ValueError, AttributeError) as e:
            return self.reply(400, {"error": str(e) if isinstance(e, ValueError) and "URL" in str(e) or "valid" in str(e) else "Enter a single valid URL."})
        database.save_scan(res); self.reply(200, res)

    def log_message(self, *a): pass

if __name__ == "__main__":
    print("PhishGuard running at http://127.0.0.1:5000  (press Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 5000), Handler).serve_forever()
