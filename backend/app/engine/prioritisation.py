"""
Urgency tiers for correlated vulnerabilities (iteration 2c, rule 4; Table 4.3).

The first matching rule applies:

  act_now     KEV-listed; or CVSS >= 9.0 with a network (or unstated) attack vector;
              or EPSS probability > 0.10
  plan_patch  CVSS >= 7.0 with a fix available; or CVSS >= 8.0
  monitor     CVSS >= 4.0
  low_risk    everything else (CVSS < 4.0, or no score)

"Fix available" is read from the snapshot: the matched NVD CPE entry states a
first fixed version (versionEndExcluding). The same function is used by the
advisory feed and by device correlation, so both apply identical rules.
"""

from __future__ import annotations

from typing import Optional

TIERS = ("act_now", "plan_patch", "monitor", "low_risk")
EPSS_THRESHOLD = 0.10


def attack_vector(vector: Optional[str]) -> str:
    """Attack vector from a CVSS v2, v3.x or v4.0 vector string ('' if unstated)."""
    for part in (vector or "").split("/"):
        if part.startswith("AV:"):
            return {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}.get(
                part[3:4], ""
            )
    return ""


def urgency_tier(
    cvss: Optional[float],
    vector: Optional[str] = "",
    kev: bool = False,
    epss: Optional[float] = None,
    fix_available: bool = False,
) -> tuple[str, str]:
    """Return (tier, reason) for one vulnerability, following Table 4.3."""
    score = cvss or 0.0
    av = attack_vector(vector)
    if kev:
        return "act_now", "listed in CISA KEV"
    if score >= 9.0 and av in ("network", ""):
        return "act_now", f"CVSS {score} with {'network' if av else 'unstated'} attack vector"
    if epss is not None and epss > EPSS_THRESHOLD:
        return "act_now", f"EPSS {epss:.3f} > {EPSS_THRESHOLD}"
    if score >= 7.0 and fix_available:
        return "plan_patch", f"CVSS {score} with a fixed version available"
    if score >= 8.0:
        return "plan_patch", f"CVSS {score} >= 8.0"
    if score >= 4.0:
        return "monitor", f"CVSS {score} >= 4.0"
    return "low_risk", f"CVSS {score} < 4.0" if cvss is not None else "no CVSS score"
