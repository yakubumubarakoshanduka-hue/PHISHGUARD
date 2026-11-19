import sqlite3, time, json, os
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")

def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    with conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT, host TEXT, score INTEGER, verdict TEXT, brand TEXT, ts INTEGER)""")
        c.execute("CREATE TABLE IF NOT EXISTS news(id INTEGER PRIMARY KEY CHECK(id=1), data TEXT, ts INTEGER)")

def save_scan(r):
    with conn() as c:
        c.execute("INSERT INTO scans(url,host,score,verdict,brand,ts) VALUES(?,?,?,?,?,?)",
                  (r["url"], r["host"], r["score"], r["verdict"], r["brand"], int(time.time())))

def history(n=15):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (n,))]

def stats():
    with conn() as c:
        rows = c.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict").fetchall()
    d = {"safe": 0, "suspicious": 0, "phishing": 0}
    d.update({r["verdict"]: r["n"] for r in rows}); d["total"] = sum(d.values()); return d

def get_news():
    with conn() as c:
        r = c.execute("SELECT data, ts FROM news WHERE id=1").fetchone()
    return (json.loads(r["data"]), r["ts"]) if r else (None, 0)

def set_news(items):
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO news VALUES(1,?,?)", (json.dumps(items), int(time.time())))
