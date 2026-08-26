-- Fix unique constraint to handle NULL sni (NULL != NULL in UNIQUE)
-- Deduplicate existing data first
DELETE FROM services
WHERE id NOT IN (
  SELECT DISTINCT ON (host_id, port, transport, COALESCE(sni, ''))
    id
  FROM services
  ORDER BY host_id, port, transport, COALESCE(sni, ''), last_seen DESC
);

-- Drop the old UNIQUE constraint if it still exists
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'services_host_id_port_transport_sni_key') THEN
    ALTER TABLE services DROP CONSTRAINT services_host_id_port_transport_sni_key;
  END IF;
END $$;

-- Create a proper unique index that handles NULL sni (create only if not exists)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_services_unique') THEN
    CREATE UNIQUE INDEX idx_services_unique ON services (host_id, port, transport, COALESCE(sni, ''));
  END IF;
END $$;
