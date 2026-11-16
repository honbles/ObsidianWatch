-- 043: CVE matching for hosts without a distro feed (Windows, macOS, other).
-- Installed software is mapped to a CPE and checked against NVD on the exact
-- installed version. NVD is slow (5 requests / 30 s without an API key), so
-- each (cpe, version) answer is cached, and each host's latest result is kept
-- so the Vulnerability page can show it immediately on load.
CREATE TABLE IF NOT EXISTS vuln_cpe_cache (
    cpe        TEXT PRIMARY KEY,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    total      INT         NOT NULL DEFAULT 0,
    findings   JSONB       NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vuln_host_cve (
    host        TEXT PRIMARY KEY,
    scan_at     TIMESTAMPTZ,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    result      JSONB       NOT NULL
);
