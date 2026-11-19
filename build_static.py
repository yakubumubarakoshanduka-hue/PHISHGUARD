"""Regenerates static/data.js (used when the app runs without Python) from detector.py, institutions.json and data/dataset.csv.
Run:  python build_static.py   after you edit institutions.json or data/dataset.csv"""
import csv, json, os
import detector
here = os.path.dirname(os.path.abspath(__file__))
rows = [[r["url"].strip().lower(), r["label"].strip() == "phishing"]
        for r in csv.DictReader(open(os.path.join(here, "data", "dataset.csv"), encoding="utf-8"))]
d = {"brands": detector.BRANDS, "tokens": detector.TOKENS, "rows": rows, "bad": sorted(detector.BAD_TLDS),
     "short": sorted(detector.SHORTENERS), "words": detector.WORDS}
open(os.path.join(here, "static", "data.js"), "w", encoding="utf-8").write("window.PG=" + json.dumps(d) + ";")
print("static/data.js written:", len(rows), "dataset rows,", len(d["brands"]), "organisations")
