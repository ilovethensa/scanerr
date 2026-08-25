pub struct QueryBuilder {
    conditions: Vec<String>,
    params: Vec<String>,
    param_index: usize,
}

impl QueryBuilder {
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
            params: Vec::new(),
            param_index: 1,
        }
    }

    pub fn add_jsonb_condition(&mut self, path: &str, value: &str) {
        self.conditions
            .push(format!("data @> '{}'::jsonb", format_json_path(path, value)));
    }

    pub fn add_tag(&mut self, tag: &str) {
        self.params.push(tag.to_string());
        self.conditions
            .push(format!("data->'tags' ? ${}", self.param_index));
        self.param_index += 1;
    }

    pub fn add_port(&mut self, port: u16) {
        self.params.push(port.to_string());
        self.conditions
            .push(format!("port = ${}::int", self.param_index));
        self.param_index += 1;
    }

    pub fn add_country(&mut self, country: &str) {
        self.params.push(country.to_string());
        self.conditions
            .push(format!("h.country_code = ${}", self.param_index));
        self.param_index += 1;
    }

    pub fn build_where(&self) -> String {
        if self.conditions.is_empty() {
            "TRUE".to_string()
        } else {
            self.conditions.join(" AND ")
        }
    }

    pub fn build_query(&self) -> String {
        let where_clause = self.build_where();
        format!(
            "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
             host(h.ip), h.country_code, h.asn, h.org \
             FROM services s \
             JOIN hosts h ON s.host_id = h.id \
             WHERE {} \
             ORDER BY s.last_seen DESC \
             LIMIT 100",
            where_clause
        )
    }

    pub fn params(&self) -> &[String] {
        &self.params
    }

    pub fn parse_filter(filter: &str) -> Vec<FilterTerm> {
        let mut terms = Vec::new();
        let mut remaining = filter;

        while !remaining.is_empty() {
            remaining = remaining.trim_start();

            if let Some(colon_pos) = remaining.find(':') {
                let key = remaining[..colon_pos].trim().to_string();
                remaining = &remaining[colon_pos + 1..];

                if remaining.starts_with('"') {
                    remaining = &remaining[1..];
                    if let Some(end_quote) = remaining.find('"') {
                        let value = remaining[..end_quote].to_string();
                        remaining = &remaining[end_quote + 1..];
                        terms.push(FilterTerm { key, value });
                    } else {
                        let value = remaining.trim().to_string();
                        terms.push(FilterTerm { key, value });
                        break;
                    }
                } else {
                    let end = remaining.find(char::is_whitespace).unwrap_or(remaining.len());
                    let value = remaining[..end].to_string();
                    remaining = &remaining[end..];
                    terms.push(FilterTerm { key, value });
                }
            } else {
                break;
            }
        }

        terms
    }
}

#[derive(Debug)]
pub struct FilterTerm {
    pub key: String,
    pub value: String,
}

fn format_json_path(path: &str, value: &str) -> String {
    let parts: Vec<&str> = path.split('.').collect();
    let mut json = serde_json::Map::new();
    let mut current = &mut json;

    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            current.insert(
                part.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        } else {
            let next = serde_json::Map::new();
            current.insert(part.to_string(), serde_json::Value::Object(next));
            current = current.get_mut(*part).unwrap().as_object_mut().unwrap();
        }
    }

    serde_json::Value::Object(json).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_filter() {
        let terms = QueryBuilder::parse_filter("http.title:\"Proxmox VE\" port:443");
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].key, "http.title");
        assert_eq!(terms[0].value, "Proxmox VE");
        assert_eq!(terms[1].key, "port");
        assert_eq!(terms[1].value, "443");
    }

    #[test]
    fn test_format_json_path() {
        let json = format_json_path("http.title", "nginx");
        assert!(json.contains("http"));
        assert!(json.contains("title"));
        assert!(json.contains("nginx"));
    }

    #[test]
    fn test_build_query() {
        let mut qb = QueryBuilder::new();
        qb.add_port(443);
        let query = qb.build_query();
        assert!(query.contains("port = $1"));
        assert!(query.contains("JOIN hosts"));
    }

    #[test]
    fn test_params_returned() {
        let mut qb = QueryBuilder::new();
        qb.add_port(443);
        qb.add_tag("iot");
        qb.add_country("DE");
        assert_eq!(qb.params(), &["443", "iot", "DE"]);
    }

    #[test]
    fn test_jsonb_condition_no_params() {
        let mut qb = QueryBuilder::new();
        qb.add_jsonb_condition("http.title", "nginx");
        assert!(qb.params().is_empty());
        let query = qb.build_query();
        assert!(query.contains("@>"));
    }

    #[test]
    fn test_parse_filter_no_colon() {
        let terms = QueryBuilder::parse_filter("port");
        assert!(terms.is_empty());
    }

    #[test]
    fn test_parse_filter_empty() {
        let terms = QueryBuilder::parse_filter("");
        assert!(terms.is_empty());
    }

    #[test]
    fn test_parse_filter_multiple_quoted() {
        let terms = QueryBuilder::parse_filter("http.title:\"Hello World\" http.server:\"nginx\"");
        assert_eq!(terms.len(), 2);
        assert_eq!(terms[0].value, "Hello World");
        assert_eq!(terms[1].value, "nginx");
    }
}
