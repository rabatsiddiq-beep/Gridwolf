\# Thesis research log



\## Thu 1 Oct 2026

\- Baseline frozen: tag v-baseline (commit 28feff2)

\- Working branch: thesisgrids

\- Environment: Windows 11, Python <version>, Docker Desktop <version>

\- Backend tests: 50 passed

\- App runs via docker compose (UI :3000, API :8000)

\- Known issues to fix (found in review): device role inversion,

&#x20; invalid offline CVE list, vendor-only CVE matching





&#x20;  ## Sun 4 Oct 2026

&#x20;  - Ground truth complete: 11 captures, 87 rows, 83 devices (64 in independent set)

&#x20;  - Codebook amended to v1.1 (amendments table with reasons)

&#x20;  - l2\_devices.csv: 30 non-IP devices across PROFINET-RT, Plant1, cip\_unclean

&#x20;  - Labels produced with AI assistance (Claude, using tshark) and spot-checked by the author



\## Mon 5 Oct 2026

\- Evaluation scripts added (run\_engine.py, evaluate.py); baseline measured on v-baseline engine

\- Baseline: P 0.800 / R 1.000 / F1 0.889; role 21.7%; class 20.6% (64 devices, independent set)

\- Engine fix: port-based server/client roles, data-bearing packets only, sender-only discovery,

&#x20; broadcast/multicast excluded; 13 regression tests (63 total passing)

\- After fix: P/R/F1 1.000; role 100%; class 74.6%; recall incl. Layer-2 0.681

\- Caveat noted: discovery/role metrics share operational definitions with codebook R1/R2

\- Code changes developed with AI assistance (Claude) and reviewed/tested by the author





\## Tue 6 Oct 2026

\- Fabricated offline CVE list removed (10 of 12 entries were wrong or non-existent)

\- Vulnerability snapshot built <date>: <N> CVEs, <K> KEV, <E> EPSS (NVD o/h CPEs for 6 OT vendors)

\- Snapshot SHA-256: <hash>  (vuln\_snapshot.meta.json)

\- Tiered correlation implemented (A product+firmware, A- product only, B vendor count, C none)

\- Ranking: KEV > EPSS > CVSS; 86 tests passing

\- Tier A check saved to results/tier\_a\_check.txt

