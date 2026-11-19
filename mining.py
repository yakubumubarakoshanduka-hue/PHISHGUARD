"""Data mining on a labelled URL dataset: feature prevalence, information gain, association rules."""
import csv, math, os, re
from urllib.parse import urlparse
import detector

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "dataset.csv")

def host_of(url):
    return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()

def brand_fake(h):
    if any(detector.registered(h) in d for d in detector.BRANDS.values()):
        return False
    return any(detector.token_hit(t, h) for t in detector.TOKENS.values())

FEATURES = {
 "No HTTPS": lambda u, h: not u.startswith("https://"),
 "URL longer than 60 characters": lambda u, h: len(u) > 60,
 "2+ hyphens in domain": lambda u, h: h.count("-") >= 2,
 "3+ dots (many subdomains)": lambda u, h: h.count(".") >= 3,
 "Digits in domain": lambda u, h: any(c.isdigit() for c in h),
 "IP address as host": lambda u, h: bool(re.fullmatch(r"[\d.]+", h)),
 "'@' symbol in URL": lambda u, h: "@" in u,
 "High-risk domain extension": lambda u, h: h.split(".")[-1] in detector.BAD_TLDS,
 "Urgency / credential words": lambda u, h: any(w in u for w in detector.WORDS),
 "Brand name on unofficial domain": lambda u, h: brand_fake(h),
 "Fake .gov.ng/.edu.ng inside domain": lambda u, h: bool(re.search(r"\.(gov|edu)\.ng\.", h)),
}

def ent(p):
    return 0 if p in (0, 1) else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))

def analyze():
    with open(DATA, encoding="utf-8") as f:
        rows = [(r["url"].strip().lower(), r["label"].strip() == "phishing") for r in csv.DictReader(f)]
    vecs = [({k for k, fn in FEATURES.items() if fn(u, host_of(u))}, y) for u, y in rows]
    n = len(vecs); P = sum(y for _, y in vecs); L = n - P
    base, feats = ent(P / n), []
    for k in FEATURES:
        a = [y for s, y in vecs if k in s]; na, pa = len(a), sum(a)
        nb, pb = n - na, P - pa
        cond = na / n * ent(pa / na if na else 0) + nb / n * ent(pb / nb if nb else 0)
        feats.append({"name": k, "phish_pct": round(100 * pa / P, 1),
                      "legit_pct": round(100 * (na - pa) / L, 1), "gain": round(base - cond, 3)})
    feats.sort(key=lambda x: -x["gain"])
    names, pairs = list(FEATURES), []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            m = [y for s, y in vecs if names[i] in s and names[j] in s]
            if len(m) >= 0.05 * n:
                conf = sum(m) / len(m)
                pairs.append({"rule": f"{names[i]} + {names[j]}", "support": round(100 * len(m) / n, 1),
                              "confidence": round(100 * conf, 1), "lift": round(conf / (P / n), 2)})
    pairs.sort(key=lambda p: (-p["lift"], -p["support"]))
    return {"total": n, "phishing": P, "legit": L, "features": feats, "pairs": pairs[:6],
            "note": "Sample dataset for demonstration. Replace data/dataset.csv with real data (e.g. PhishTank) for research."}
