DO $$ BEGIN
    ALTER TABLE hosts ADD COLUMN is_honeypot boolean NOT NULL DEFAULT false;
EXCEPTION WHEN duplicate_column THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS idx_hosts_honeypot ON hosts (is_honeypot) WHERE is_honeypot;

-- Mark existing hosts with >50 services as honeypots
UPDATE hosts SET is_honeypot = true
WHERE id IN (
    SELECT host_id FROM services GROUP BY host_id HAVING count(*) > 50
);
