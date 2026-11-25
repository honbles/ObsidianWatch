-- Code step 2: which engines ran for a SAST result, and the repository SBOM
-- (CycloneDX 1.5 JSON) produced by the same scan.
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS engines JSONB;
ALTER TABLE sast_results ADD COLUMN IF NOT EXISTS sbom JSONB;
