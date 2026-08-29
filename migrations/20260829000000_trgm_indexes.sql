CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX idx_services_banner_trgm ON services USING GIN ((data->>'banner') gin_trgm_ops);
CREATE INDEX idx_services_title_trgm  ON services USING GIN ((data->'http'->>'title') gin_trgm_ops);
CREATE INDEX idx_services_product_trgm ON services USING GIN ((data->>'product') gin_trgm_ops);
CREATE INDEX idx_services_server_trgm  ON services USING GIN ((data->'http'->>'server') gin_trgm_ops);
