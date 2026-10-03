"""
Vulnerability snapshot - a dated, frozen copy of real vulnerability data.

Gridwolf matches devices against this snapshot instead of a hand-written list, so
every CVE it reports can be traced to NVD, and a re-run on the same snapshot gives
the same answer (reproducibility).

Sources:
  * NVD CVE API 2.0           - CVE text, CVSS, CWE and affected CPEs (vendor/product/versions)
  * CISA KEV catalogue        - whether a CVE is known to be exploited in the wild
  * FIRST EPSS API            - probability of exploitation in the next 30 days

Build a snapshot (needs internet; takes a few minutes without an NVD API key):
    python -m app.engine.vuln_snapshot --out app/vulndata/vuln_snapshot.json.gz
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

DEFAULT_SNAPSHOT = Path(__file__).resolve().parent.parent / "vulndata" / "vuln_snapshot.json.gz"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# NVD vendor names in scope, with a display name. Scope = OT/ICS device vendors
# seen in the thesis captures. Only CPE parts 'o' (firmware) and 'h' (hardware)
# are fetched, because passive discovery identifies devices, not installed software.
VENDORS = {
    "siemens": "Siemens",
    "rockwellautomation": "Rockwell Automation",
    "schneider-electric": "Schneider Electric",
    "johnsoncontrols": "Johnson Controls",
    "moxa": "Moxa",
    "sick": "SICK",
}
CPE_PARTS = ("o", "h")


# ─── Parsing (pure functions, unit-tested) ─────────────────────────────────


def _cvss(metrics: dict) -> tuple[Optional[float], str, str]:
    """Best available CVSS: v3.1, then v3.0, then v4.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer the NVD ('Primary') score when several sources scored it
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
        return score, severity.lower(), data.get("vectorString", "")
    return None, "", ""


def _cpe_fields(criteria: str) -> dict:
    # cpe:2.3:part:vendor:product:version:...
    parts = criteria.split(":")
    return {
        "part": parts[2] if len(parts) > 2 else "",
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4].replace("\\", "") if len(parts) > 4 else "",
        "version": parts[5] if len(parts) > 5 else "*",
    }


def parse_nvd_item(item: dict, vendors: Iterable[str] = VENDORS) -> Optional[dict]:
    """Reduce one NVD API 'vulnerabilities[]' entry to what Gridwolf needs.

    Keeps only vulnerable CPE matches for in-scope vendors. Returns None if the CVE
    has no such CPE (e.g. rejected or only affects out-of-scope software).
    """
    cve = item.get("cve", item)
    if cve.get("vulnStatus") == "Rejected":
        return None
    vendors = set(vendors)
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                f = _cpe_fields(m.get("criteria", ""))
                if f["vendor"] not in vendors or f["part"] not in CPE_PARTS:
                    continue
                affected.append(
                    {
                        "vendor": f["vendor"],
                        "product": f["product"],
                        "version": f["version"],
                        "start_incl": m.get("versionStartIncluding"),
                        "start_excl": m.get("versionStartExcluding"),
                        "end_incl": m.get("versionEndIncluding"),
                        "end_excl": m.get("versionEndExcluding"),
                    }
                )
    if not affected:
        return None
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    score, severity, vector = _cvss(cve.get("metrics", {}))
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )
    return {
        "cve_id": cve["id"],
        "published": (cve.get("published") or "")[:10],
        "description": desc[:500],
        "cvss_score": score,
        "severity": severity,
        "cvss_vector": vector,
        "cwe": cwes,
        "affected": affected,
        "kev": False,
        "kev_date_added": "",
        "epss": None,
        "epss_percentile": None,
    }


def apply_kev(records: list[dict], kev_json: dict) -> int:
    kev = {v["cveID"]: v for v in kev_json.get("vulnerabilities", [])}
    n = 0
    for r in records:
        if r["cve_id"] in kev:
            r["kev"] = True
            r["kev_date_added"] = kev[r["cve_id"]].get("dateAdded", "")
            n += 1
    return n


def apply_epss(records: list[dict], epss_rows: Iterable[dict]) -> int:
    scores = {e["cve"]: e for e in epss_rows}
    n = 0
    for r in records:
        e = scores.get(r["cve_id"])
        if e:
            r["epss"] = float(e["epss"])
            r["epss_percentile"] = float(e["percentile"])
            n += 1
    return n


# ─── Loading ──────────────────────────────────────────────────────────────


def load_snapshot(path: Optional[os.PathLike | str] = None) -> dict:
    """Load a snapshot. Returns an empty snapshot (no CVEs) if the file is missing."""
    path = Path(path or os.environ.get("GRIDWOLF_VULN_SNAPSHOT") or DEFAULT_SNAPSHOT)
    if not path.exists():
        logger.warning(
            "No vulnerability snapshot at %s - CVE matching disabled. "
            "Build one with: python -m app.engine.vuln_snapshot",
            path,
        )
        return {"meta": {"missing": True, "path": str(path)}, "cves": []}
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


# ─── Building (network) ───────────────────────────────────────────────────


def _get_json(client: Any, url: str, params: dict, headers: dict, tries: int = 5) -> dict:
    for attempt in range(tries):
        resp = client.get(url, params=params, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        wait = 10 * (attempt + 1)
        logger.warning("HTTP %s from %s - retrying in %ss", resp.status_code, url, wait)
        time.sleep(wait)
    raise RuntimeError(f"Failed to fetch {url} with {params}")


def build_snapshot(out: Path, api_key: Optional[str] = None) -> dict:
    import httpx  # imported here so loading a snapshot never needs network libraries

    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5  # NVD: 50 or 5 requests per rolling 30 s
    records: dict[str, dict] = {}
    queries = []
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        for vendor in VENDORS:
            for part in CPE_PARTS:
                match = f"cpe:2.3:{part}:{vendor}"
                start, total = 0, None
                while total is None or start < total:
                    params = {
                        "virtualMatchString": match,
                        "resultsPerPage": 2000,
                        "startIndex": start,
                    }
                    data = _get_json(client, NVD_URL, params, headers)
                    total = data.get("totalResults", 0)
                    for item in data.get("vulnerabilities", []):
                        rec = parse_nvd_item(item)
                        if rec:
                            prev = records.get(rec["cve_id"])
                            if prev:
                                seen = {json.dumps(a, sort_keys=True) for a in prev["affected"]}
                                prev["affected"] += [
                                    a
                                    for a in rec["affected"]
                                    if json.dumps(a, sort_keys=True) not in seen
                                ]
                            else:
                                records[rec["cve_id"]] = rec
                    start += data.get("resultsPerPage", 2000) or 2000
                    print(f"  NVD {match}: {min(start, total)}/{total}")
                    time.sleep(delay)
                queries.append({"virtualMatchString": match, "totalResults": total})

        recs = sorted(records.values(), key=lambda r: r["cve_id"])
        kev_json = _get_json(client, KEV_URL, {}, {})
        n_kev = apply_kev(recs, kev_json)

        epss_rows: list[dict] = []
        ids = [r["cve_id"] for r in recs]
        for i in range(0, len(ids), 100):
            data = _get_json(client, EPSS_URL, {"cve": ",".join(ids[i : i + 100])}, {})
            epss_rows += data.get("data", [])
            time.sleep(0.5)
        n_epss = apply_epss(recs, epss_rows)

    meta = {
        "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "nvd": NVD_URL,
            "kev": KEV_URL,
            "kev_catalog_version": kev_json.get("catalogVersion", ""),
            "epss": EPSS_URL,
        },
        "vendors": VENDORS,
        "cpe_parts": list(CPE_PARTS),
        "queries": queries,
        "cve_count": len(recs),
        "kev_count": n_kev,
        "epss_count": n_epss,
    }
    snapshot = {"meta": meta, "cves": recs}
    out.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0 keeps the gzip bytes identical for identical content
    with open(out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        gz.write(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode())
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    meta_out = out.with_name(out.name.replace(".json.gz", ".meta.json"))
    meta_out.write_text(json.dumps({**meta, "sha256": digest}, indent=2), encoding="utf-8")
    print(f"Snapshot: {len(recs)} CVEs, {n_kev} in KEV, {n_epss} with EPSS -> {out}")
    print(f"SHA-256: {digest}")
    return snapshot


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the Gridwolf vulnerability snapshot")
    ap.add_argument("--out", default=str(DEFAULT_SNAPSHOT))
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)
    build_snapshot(Path(args.out), args.api_key)


if __name__ == "__main__":
    main()
