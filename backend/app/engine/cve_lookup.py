"""
CVE Lookup Engine - correlate discovered devices with real vulnerability data.

Devices are matched against a dated vulnerability snapshot (see vuln_snapshot.py)
built from NVD, CISA KEV and FIRST EPSS. Nothing is hard-coded: if no snapshot is
present, no CVEs are reported.

Correlation tiers (what the passive evidence supports):
  * Tier A  - product and firmware known: CVEs whose affected CPE product matches
              and whose version range includes the firmware.
  * Tier A- - product known, firmware unknown: product matches, version unchecked.
  * Tier B  - vendor known only: no per-CVE claims, only the vendor's exposure
              (count of CVEs / KEV entries), to avoid flooding with false positives.
  * Tier C  - nothing known.

Matches are ranked by exploitation evidence first, then severity:
known-exploited (KEV) > EPSS probability > CVSS base score.
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from typing import Optional

from app.engine.vuln_snapshot import load_snapshot

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)

# Vendor strings seen in traffic (MAC OUI names, protocol identity fields) mapped to
# NVD vendor names. Matching is on whole words, case-insensitive.
VENDOR_ALIASES: list[tuple[str, str]] = [
    (r"siemens", "siemens"),
    (r"rockwell", "rockwellautomation"),
    (r"allen[- ]?bradley", "rockwellautomation"),
    (r"schneider", "schneider-electric"),
    (r"modicon", "schneider-electric"),
    (r"telemecanique", "schneider-electric"),
    (r"johnson controls", "johnsoncontrols"),
    (r"jci", "johnsoncontrols"),
    (r"moxa", "moxa"),
    (r"sick", "sick"),
]


def normalise_vendor(vendor: Optional[str]) -> Optional[str]:
    """Map a vendor string to its NVD vendor name, or None if not in scope."""
    if not vendor:
        return None
    v = vendor.lower()
    for pattern, nvd_vendor in VENDOR_ALIASES:
        if re.search(rf"\b{pattern}\b", v):
            return nvd_vendor
    return None


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def product_candidates(product: Optional[str]) -> list[str]:
    """Split a product string such as 'CPU 315-2 PN/DP (6ES7 315-2EH14-0AB0)'
    into normalised candidates: ['cpu3152pndp', '6es73152eh140ab0']."""
    if not product:
        return []
    parts = re.split(r"[();,]", product)
    out = []
    for p in parts:
        n = _norm(p.replace("firmware", ""))
        if len(n) >= 4 and n not in out:
            out.append(n)
    return out


def _vtuple(version: Optional[str]) -> Optional[tuple[int, ...]]:
    if not version or version in ("*", "-"):
        return None
    nums = re.findall(r"\d+", version)
    return tuple(int(n) for n in nums) if nums else None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_affected(firmware: Optional[str], affected: dict) -> Optional[bool]:
    """True/False if the firmware is inside/outside the affected range; None if unknown."""
    fw = _vtuple(firmware)
    if fw is None:
        return None
    exact = _vtuple(affected.get("version"))
    if exact is not None:
        return _cmp(fw, exact) == 0
    bounds = [
        ("start_incl", lambda c: c >= 0),
        ("start_excl", lambda c: c > 0),
        ("end_incl", lambda c: c <= 0),
        ("end_excl", lambda c: c < 0),
    ]
    for key, ok in bounds:
        limit = _vtuple(affected.get(key))
        if limit is not None and not ok(_cmp(fw, limit)):
            return False
    return True  # inside every stated bound (or the CPE covers all versions)


def rank_key(rec: dict) -> tuple:
    return (
        0 if rec.get("kev") else 1,
        -(rec.get("epss") or 0.0),
        -(rec.get("cvss_score") or 0.0),
        rec.get("cve_id", ""),
    )


class CVELookup:
    """Look up CVEs for discovered devices using the vulnerability snapshot."""

    def __init__(self, nvd_api_key: Optional[str] = None, snapshot_path: Optional[str] = None):
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
        snapshot = load_snapshot(snapshot_path)
        self.meta: dict = snapshot.get("meta", {})
        self.cves: list[dict] = snapshot.get("cves", [])
        self._by_vendor: dict[str, list[dict]] = defaultdict(list)
        for rec in self.cves:
            for v in {a["vendor"] for a in rec.get("affected", [])}:
                self._by_vendor[v].append(rec)

    # ── correlation ────────────────────────────────────────────────────────

    def correlate(
        self,
        vendor: Optional[str],
        product: Optional[str] = None,
        firmware: Optional[str] = None,
    ) -> dict:
        """Correlate one device. Returns the tier, the NVD vendor and ranked matches."""
        nvd_vendor = normalise_vendor(vendor)
        candidates = product_candidates(product)
        result = {
            "tier": "C",
            "nvd_vendor": nvd_vendor,
            "matches": [],
            "vendor_cve_count": 0,
            "vendor_kev_count": 0,
            "snapshot": self.meta.get("built_utc", "none"),
        }
        if nvd_vendor is None:
            return result

        vendor_cves = self._by_vendor.get(nvd_vendor, [])
        result["vendor_cve_count"] = len(vendor_cves)
        result["vendor_kev_count"] = sum(1 for r in vendor_cves if r.get("kev"))
        if not candidates:
            result["tier"] = "B"
            return result

        result["tier"] = "A" if _vtuple(firmware) else "A-"
        matches = []
        for rec in vendor_cves:
            best = None
            for a in rec["affected"]:
                if a["vendor"] != nvd_vendor:
                    continue
                cpe_product = _norm(a["product"])
                if not any(c in cpe_product for c in candidates):
                    continue
                verdict = version_affected(firmware, a)
                if verdict is False:
                    continue
                best = {
                    "cpe_product": a["product"],
                    "version_check": "affected" if verdict else "unknown",
                }
                if verdict:
                    break
            if best:
                matches.append({**self._public(rec), "match": best})
        matches.sort(key=rank_key)
        result["matches"] = matches
        return result

    def match_device(
        self,
        vendor: Optional[str],
        product: Optional[str] = None,
        firmware: Optional[str] = None,
    ) -> list[dict]:
        """Ranked CVE matches for a device (empty unless the product is known)."""
        return self.correlate(vendor, product, firmware)["matches"]

    @staticmethod
    def _public(rec: dict) -> dict:
        return {
            "cve_id": rec["cve_id"],
            "description": rec.get("description", ""),
            "cvss_score": rec.get("cvss_score"),
            "severity": rec.get("severity", ""),
            "cvss_vector": rec.get("cvss_vector", ""),
            "cwe": rec.get("cwe", []),
            "kev": rec.get("kev", False),
            "epss": rec.get("epss"),
            "epss_percentile": rec.get("epss_percentile"),
            "published": rec.get("published", ""),
            "references": [f"https://nvd.nist.gov/vuln/detail/{rec['cve_id']}"],
        }

    # ── keyword search ─────────────────────────────────────────────────────

    async def search_nvd(self, keyword: str) -> list[dict]:
        """Search NVD live (needs internet); falls back to the snapshot."""
        if not HTTPX_AVAILABLE:
            return self._offline_search(keyword)
        try:
            headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": keyword, "resultsPerPage": 20},
                    headers=headers,
                )
            if resp.status_code != 200:
                logger.warning(f"NVD API returned {resp.status_code}, using snapshot")
                return self._offline_search(keyword)
            results = []
            for vuln in resp.json().get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                metrics = cve.get("metrics", {})
                v31 = metrics.get("cvssMetricV31") or [{}]
                score = v31[0].get("cvssData", {}).get("baseScore", 0) if v31 else 0
                results.append(
                    {
                        "cve_id": cve.get("id", ""),
                        "description": (cve.get("descriptions") or [{}])[0].get("value", ""),
                        "cvss_score": score,
                        "severity": self._cvss_to_severity(score),
                        "references": [r.get("url", "") for r in cve.get("references", [])[:3]],
                    }
                )
            return results
        except Exception as e:
            logger.error(f"NVD API error: {e}")
            return self._offline_search(keyword)

    def _offline_search(self, keyword: str) -> list[dict]:
        """Search the snapshot by CVE id, product or description text."""
        k = keyword.lower()
        hits = [
            rec
            for rec in self.cves
            if k in rec["cve_id"].lower()
            or k in rec.get("description", "").lower()
            or any(k in a["product"].lower() for a in rec.get("affected", []))
        ]
        return [self._public(r) for r in sorted(hits, key=rank_key)[:50]]

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score > 0:
            return "low"
        return "info"
