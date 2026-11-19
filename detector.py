import re, ipaddress
from difflib import SequenceMatcher
from urllib.parse import urlparse

# Official domains of Nigerian banks, fintechs, companies, government and schools
BRANDS = {
 "GTBank": ["gtbank.com", "gtco.com"], "Access Bank": ["accessbankplc.com"],
 "Zenith Bank": ["zenithbank.com"], "First Bank": ["firstbanknigeria.com"],
 "UBA": ["ubagroup.com"], "Opay": ["opay.com", "opayweb.com"],
 "Moniepoint": ["moniepoint.com"], "Paystack": ["paystack.com"],
 "Flutterwave": ["flutterwave.com"], "CBN": ["cbn.gov.ng"],
 "FIRS": ["firs.gov.ng"], "NIMC": ["nimc.gov.ng"], "JAMB": ["jamb.gov.ng"],
 "WAEC": ["waecdirect.org", "waecnigeria.org"], "MTN": ["mtn.ng", "mtnonline.com"],
 "Airtel": ["airtel.com.ng"], "DSTV": ["dstv.com"], "NNPC": ["nnpcgroup.com"],
 "UNILAG": ["unilag.edu.ng"], "University of Ibadan": ["ui.edu.ng"],
 "Nigeria Immigration": ["immigration.gov.ng"], "Nigeria Police": ["npf.gov.ng"],
}
TOKENS = {b: re.sub(r"[^a-z]", "", b.lower()) for b in BRANDS}
TOKENS.update({"University of Ibadan": "ibadan", "Nigeria Immigration": "immigration",
               "Nigeria Police": "policeng", "Zenith Bank": "zenith", "Access Bank": "accessbank",
               "First Bank": "firstbank", "MTN": "mtn"})
import json, os
_f = os.path.join(os.path.dirname(os.path.abspath(__file__)), "institutions.json")
try:  # extra organisations/institutions: edit institutions.json to add more
    for _i in json.load(open(_f, encoding="utf-8")):
        BRANDS[_i["name"]] = _i["domains"]
        TOKENS[_i["name"]] = _i.get("token", _i["domains"][0].split(".")[0])
except (OSError, ValueError, KeyError):
    pass

def token_hit(tok, host):
    # short tokens must equal a whole word in the host (so "abu" does not match "abuja")
    if len(tok) >= 5:
        return tok in host.replace("-", "").replace(".", "")
    return tok in re.split(r"[.\-]", host)

BAD_TLDS = {"xyz","top","tk","ml","ga","cf","gq","click","work","support","loan","icu","buzz","zip","cfd"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy","ow.ly"}
WORDS = ["login","verify","secure","update","account","confirm","bvn","nin","otp","token",
         "password","suspend","unlock","reactivate","bonus","claim","giveaway","scholarship",
         "tax-refund","portal","signin","wallet","alert"]
SLDS = {"com","gov","edu","org","net","co","sch"}

def registered(host):
    p = host.split(".")
    if len(p) >= 3 and p[-2] in SLDS and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])

def analyze(raw):
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048 or " " in raw:
        raise ValueError("Enter a single valid URL (max 2048 characters).")
    url = raw if re.match(r"^[a-zA-Z]+://", raw) else "http://" + raw
    u = urlparse(url)
    host = (u.hostname or "").lower().rstrip(".")
    if not host or "." not in host and not host.replace(".", "").isdigit():
        raise ValueError("That does not look like a valid web address.")
    reg = registered(host)
    for brand, doms in BRANDS.items():
        if reg in doms:
            return {"url": raw, "host": host, "score": 0, "verdict": "safe",
                    "brand": brand, "reasons": [f"Official {brand} domain ({reg})."]}
    score, why, brand = 0, [], None
    def add(n, msg): 
        nonlocal score; score += n; why.append(msg)
    try:
        ipaddress.ip_address(host); add(35, "Uses a raw IP address instead of a domain name.")
    except ValueError:
        pass
    if u.scheme != "https": add(12, "Connection is not encrypted (no HTTPS).")
    if "@" in u.netloc: add(25, "Contains '@' to hide the real destination.")
    if host.startswith("xn--") or ".xn--" in host: add(20, "Punycode (look-alike characters) in domain.")
    if host in SHORTENERS: add(20, "Shortened link hides the real destination.")
    if len(url) > 90: add(8, "Unusually long URL.")
    if host.count(".") >= 4: add(12, "Too many subdomains.")
    if host.count("-") >= 2: add(10, "Several hyphens in the domain.")
    if host.split(".")[-1] in BAD_TLDS: add(15, "Domain ends in a high-risk extension.")
    hits = [w for w in WORDS if w in url.lower()]
    if hits: add(min(5 * len(hits), 20), "Pressure/credential words: " + ", ".join(hits[:5]) + ".")
    label = reg.split(".")[0]
    for b, tok in TOKENS.items():
        if token_hit(tok, host):
            brand = b; add(45, f"Impersonates {b} but is not an official {b} domain."); break
    if not brand:
        for b, doms in BRANDS.items():
            for d in doms:
                if len(label) >= 5 and 0.8 <= SequenceMatcher(None, label, d.split(".")[0]).ratio() < 1:
                    brand = b; add(40, f"Look-alike spelling of {b} ({d})."); break
            if brand: break
    if ".gov.ng" in host[:-7] or ".edu.ng" in host[:-7]:
        add(30, "Fake government/education suffix used inside the domain.")
    score = min(score, 100)
    verdict = "phishing" if score >= 60 else "suspicious" if score >= 30 else "safe"
    if not why: why.append("No phishing signals found. Still verify before entering details.")
    return {"url": raw, "host": host, "score": score, "verdict": verdict, "brand": brand, "reasons": why}
