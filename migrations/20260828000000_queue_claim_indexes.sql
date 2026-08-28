-- Replace partial indexes with btree indexes that support range scans.
-- The old partial indexes (WHERE claimed_until IS NULL) could not be used
-- when the claim query also matched expired claims via OR.
-- The new composite indexes support COALESCE(claimed_until, ...) < $2 ORDER BY id.

DROP INDEX IF EXISTS idx_host_scans_unclaimed;
DROP INDEX IF EXISTS idx_service_probes_unclaimed;
DROP INDEX IF EXISTS idx_enrichments_unclaimed;

CREATE INDEX idx_host_scans_claimable ON queue_host_scans(claimed_until, id);
CREATE INDEX idx_service_probes_claimable ON queue_service_probes(claimed_until, id);
CREATE INDEX idx_enrichments_claimable ON queue_enrichments(claimed_until, id);
