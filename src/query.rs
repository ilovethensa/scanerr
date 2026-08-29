#[derive(Debug, Clone, PartialEq)]
pub enum FilterOp {
    Default,
    Contains,
    IContains,
    Regex,
    Equals,
    Startswith,
    Endswith,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QueryNode {
    Filter(FilterTerm),
    And(Box<QueryNode>, Box<QueryNode>),
    Or(Box<QueryNode>, Box<QueryNode>),
    Not(Box<QueryNode>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilterTerm {
    pub key: String,
    pub op: FilterOp,
    pub value: String,
    pub negate: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    KeyVal(String, FilterOp, String),
    BareWord(String),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn next_token(&mut self) -> Option<Token> {
        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return None;
        }
        let ch = self.current()?;

        if ch == '(' {
            self.pos += 1;
            return Some(Token::LParen);
        }
        if ch == ')' {
            self.pos += 1;
            return Some(Token::RParen);
        }
        if ch == '-' {
            self.pos += 1;
            if self.pos < self.input.len() && !self.current().unwrap().is_whitespace() {
                return Some(Token::Not);
            }
            return Some(Token::BareWord("-".to_string()));
        }

        if ch == '"' {
            return Some(Token::BareWord(self.read_quoted()));
        }

        if ch.is_alphanumeric() || ch == '_' {
            let word = self.read_word();
            match word.to_lowercase().as_str() {
                "and" => return Some(Token::And),
                "or" => return Some(Token::Or),
                "not" => return Some(Token::Not),
                _ => {}
            }
            if self.current() == Some(':') || self.current() == Some('.') {
                return Some(self.read_key_val(&word));
            }
            return Some(Token::BareWord(word));
        }

        self.pos += 1;
        Some(Token::BareWord(ch.to_string()))
    }

    fn read_key_val(&mut self, key: &str) -> Token {
        if self.current() == Some('.') {
            self.pos += 1;
            let suffix = self.read_word();
            match suffix.as_str() {
                "contains" | "icontains" | "regex" | "equals" | "startswith" | "endswith" => {
                    let op = match suffix.as_str() {
                        "contains" => FilterOp::Contains,
                        "icontains" => FilterOp::IContains,
                        "regex" => FilterOp::Regex,
                        "equals" => FilterOp::Equals,
                        "startswith" => FilterOp::Startswith,
                        "endswith" => FilterOp::Endswith,
                        _ => unreachable!(),
                    };
                    self.skip_whitespace();
                    let value = if self.current() == Some(':') {
                        self.pos += 1;
                        self.skip_whitespace();
                        self.read_value()
                    } else {
                        self.read_value()
                    };
                    Token::KeyVal(key.to_string(), op, value)
                }
                _ => {
                    let full_key = format!("{}.{}", key, suffix);
                    if self.current() == Some('.') || self.current() == Some(':') {
                        return self.read_key_val(&full_key);
                    }
                    Token::KeyVal(full_key, FilterOp::Default, String::new())
                }
            }
        } else {
            self.pos += 1;
            self.skip_whitespace();
            let value = self.read_value();
            Token::KeyVal(key.to_string(), FilterOp::Default, value)
        }
    }

    fn read_value(&mut self) -> String {
        self.skip_whitespace();
        if self.current() == Some('"') {
            return self.read_quoted();
        }
        self.read_word()
    }

    fn read_quoted(&mut self) -> String {
        self.pos += 1;
        let mut result = String::new();
        while let Some(ch) = self.current() {
            if ch == '"' {
                self.pos += 1;
                return result;
            }
            if ch == '\\' {
                self.pos += 1;
                if let Some(next) = self.current() {
                    result.push(next);
                    self.pos += 1;
                }
            } else {
                result.push(ch);
                self.pos += 1;
            }
        }
        result
    }

    fn read_word(&mut self) -> String {
        let start = self.pos;
        while let Some(ch) = self.current() {
            if ch.is_whitespace() || ch == '(' || ch == ')' || ch == ':' || ch == '"' || ch == '.' {
                break;
            }
            self.pos += 1;
        }
        self.input[start..self.pos].to_string()
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.current() {
            if ch.is_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn current(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn tokenize(mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        while let Some(token) = self.next_token() {
            tokens.push(token);
        }
        tokens
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn parse(mut self) -> QueryNode {
        if self.tokens.is_empty() {
            return QueryNode::Filter(FilterTerm {
                key: String::new(),
                op: FilterOp::Default,
                value: String::new(),
                negate: false,
            });
        }
        let node = self.parse_or();
        node
    }

    fn parse_or(&mut self) -> QueryNode {
        let mut left = self.parse_and();
        while self.peek() == Some(&Token::Or) {
            self.pos += 1;
            let right = self.parse_and();
            left = QueryNode::Or(Box::new(left), Box::new(right));
        }
        left
    }

    fn parse_and(&mut self) -> QueryNode {
        let mut left = self.parse_not();
        while self.peek().is_some()
            && !matches!(self.peek(), Some(Token::Or) | Some(Token::RParen))
        {
            let right = self.parse_not();
            left = QueryNode::And(Box::new(left), Box::new(right));
        }
        left
    }

    fn parse_not(&mut self) -> QueryNode {
        if self.peek() == Some(&Token::Not) {
            self.pos += 1;
            let inner = self.parse_atom();
            return QueryNode::Not(Box::new(inner));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> QueryNode {
        match self.peek().cloned() {
            Some(Token::LParen) => {
                self.pos += 1;
                let node = self.parse_or();
                if self.peek() == Some(&Token::RParen) {
                    self.pos += 1;
                }
                node
            }
            Some(Token::KeyVal(key, op, value)) => {
                self.pos += 1;
                QueryNode::Filter(FilterTerm {
                    key,
                    op,
                    value,
                    negate: false,
                })
            }
            Some(Token::BareWord(word)) => {
                self.pos += 1;
                QueryNode::Filter(FilterTerm {
                    key: String::new(),
                    op: FilterOp::Default,
                    value: word,
                    negate: false,
                })
            }
            _ => {
                self.pos += 1;
                QueryNode::Filter(FilterTerm {
                    key: String::new(),
                    op: FilterOp::Default,
                    value: String::new(),
                    negate: false,
                })
            }
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FilterKind {
    Tag,
    Port,
    Country,
    FullText,
    JsonContains,
    JsonText,
}

fn classify_filter(term: &FilterTerm) -> FilterKind {
    if term.key.is_empty() {
        return FilterKind::FullText;
    }
    match term.key.as_str() {
        "tag" => FilterKind::Tag,
        "port" => FilterKind::Port,
        "country" => FilterKind::Country,
        _ => {
            if matches!(
                term.op,
                FilterOp::Contains
                    | FilterOp::IContains
                    | FilterOp::Regex
                    | FilterOp::Equals
                    | FilterOp::Startswith
                    | FilterOp::Endswith
            ) {
                FilterKind::JsonText
            } else {
                FilterKind::JsonContains
            }
        }
    }
}

fn json_text_col(key: &str) -> String {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.len() == 1 {
        return format!("data->>'{}'", parts[0]);
    }
    let mut result = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            result.push_str("data->'");
            result.push_str(part);
            result.push('\'');
        } else if i == parts.len() - 1 {
            result.push_str("->>'");
            result.push_str(part);
            result.push('\'');
        } else {
            result.push_str("->'");
            result.push_str(part);
            result.push('\'');
        }
    }
    result
}



pub fn parse_query(input: &str) -> QueryNode {
    let tokens = Tokenizer::new(input).tokenize();
    Parser::new(&tokens).parse()
}

pub fn compile_to_sql(node: &QueryNode) -> (String, Vec<String>) {
    let mut conditions = Vec::new();
    let mut params = Vec::new();
    compile_node(node, &mut conditions, &mut params);
    let where_clause = if conditions.is_empty() {
        "TRUE".to_string()
    } else {
        conditions.join(" AND ")
    };
    (where_clause, params)
}

fn compile_node(node: &QueryNode, conditions: &mut Vec<String>, params: &mut Vec<String>) {
    match node {
        QueryNode::And(l, r) => {
            compile_node(l, conditions, params);
            compile_node(r, conditions, params);
        }
        QueryNode::Or(l, r) => {
            let mut left_conds = Vec::new();
            let mut left_params = Vec::new();
            compile_node(l, &mut left_conds, &mut left_params);

            let mut right_conds = Vec::new();
            let mut right_params = Vec::new();
            compile_node(r, &mut right_conds, &mut right_params);

            if left_conds.is_empty() || right_conds.is_empty() {
                return;
            }

            let left_sql = left_conds.join(" AND ");
            let right_sql = right_conds.join(" AND ");
            let combined_params = [left_params, right_params].concat();

            let idx = params.len();
            for p in &combined_params {
                params.push(p.clone());
            }

            if left_conds.len() == 1 && right_conds.len() == 1 {
                conditions.push(format!("({} OR {})", left_sql, right_sql));
            } else if left_conds.len() == 1 {
                conditions.push(format!("({} OR ({}))", left_sql, right_sql));
            } else if right_conds.len() == 1 {
                conditions.push(format!("(({}) OR {})", left_sql, right_sql));
            } else {
                conditions.push(format!("(({}) OR ({}))", left_sql, right_sql));
            }
            let _ = idx;
        }
        QueryNode::Not(inner) => {
            let mut inner_conds = Vec::new();
            let mut inner_params = Vec::new();
            compile_node(inner, &mut inner_conds, &mut inner_params);

            if inner_conds.is_empty() {
                return;
            }

            let inner_sql = inner_conds.join(" AND ");
            let idx = params.len();
            for p in &inner_params {
                params.push(p.clone());
            }

            if inner_conds.len() == 1 {
                conditions.push(format!("NOT ({})", inner_sql));
            } else {
                conditions.push(format!("NOT ({})", inner_sql));
            }
            let _ = idx;
        }
        QueryNode::Filter(term) => {
            if term.key.is_empty() && term.value.is_empty() {
                return;
            }

            let kind = classify_filter(term);
            let sql = match kind {
                FilterKind::Tag => compile_tag(term, params),
                FilterKind::Port => compile_port(term, params),
                FilterKind::Country => compile_country(term, params),
                FilterKind::FullText => compile_full_text(term, params),
                FilterKind::JsonContains => compile_json_contains(term, params),
                FilterKind::JsonText => compile_json_text(term, params),
            };

            if sql.is_empty() {
                return;
            }

            if term.negate {
                conditions.push(format!("NOT ({})", sql));
            } else {
                conditions.push(sql);
            }
        }
    }
}

fn compile_full_text(term: &FilterTerm, params: &mut Vec<String>) -> String {
    params.push(term.value.clone());
    let p = params.len();
    let fields = [
        "data->>'banner'",
        "data->'http'->>'title'",
        "data->'http'->>'server'",
        "data->>'product'",
        "data->>'version'",
        "data->>'kind'",
    ];
    let conditions: Vec<String> = fields
        .iter()
        .map(|f| format!("{} ILIKE '%' || ${} || '%'", f, p))
        .collect();
    conditions.join(" OR ")
}

fn compile_tag(term: &FilterTerm, _params: &mut Vec<String>) -> String {
    let json = format!("{{\"tags\":[\"{}\"]}}", escape_json_string(&term.value));
    format!("data @> '{}'::jsonb", json)
}

fn compile_port(term: &FilterTerm, params: &mut Vec<String>) -> String {
    if let Ok(port) = term.value.parse::<u16>() {
        params.push(port.to_string());
        let p = params.len();
        format!("s.port = ${}::int", p)
    } else {
        "FALSE".to_string()
    }
}

fn compile_country(term: &FilterTerm, params: &mut Vec<String>) -> String {
    params.push(term.value.clone().to_uppercase());
    let p = params.len();
    format!("h.country_code = ${}", p)
}

fn build_nested_json(key: &str, value: &str) -> String {
    let parts: Vec<&str> = key.split('.').collect();
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

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn compile_json_contains(term: &FilterTerm, _params: &mut Vec<String>) -> String {
    let json = build_nested_json(&term.key, &term.value);
    format!("data @> '{}'::jsonb", json)
}

fn compile_json_text(term: &FilterTerm, params: &mut Vec<String>) -> String {
    let col = json_text_col(&term.key);

    match term.op {
        FilterOp::Contains => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} LIKE '%' || ${} || '%'", col, p)
        }
        FilterOp::IContains => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} ILIKE '%' || ${} || '%'", col, p)
        }
        FilterOp::Regex => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} ~ ${}", col, p)
        }
        FilterOp::Equals => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} = ${}", col, p)
        }
        FilterOp::Startswith => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} LIKE ${} || '%'", col, p)
        }
        FilterOp::Endswith => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} LIKE '%' || ${}", col, p)
        }
        FilterOp::Default => {
            params.push(term.value.clone());
            let p = params.len();
            format!("{} = ${}", col, p)
        }
    }
}

pub fn build_search_query(node: &QueryNode) -> (String, Vec<String>) {
    let (where_clause, params) = compile_to_sql(node);
    let query = format!(
        "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
         host(h.ip), h.country_code, h.asn, h.org \
         FROM services s \
         JOIN hosts h ON s.host_id = h.id \
         WHERE {} \
         ORDER BY s.last_seen DESC \
         LIMIT 100",
        where_clause
    );
    (query, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_key_val() {
        let node = parse_query("tag:web");
        match node {
            QueryNode::Filter(t) => {
                assert_eq!(t.key, "tag");
                assert_eq!(t.value, "web");
                assert_eq!(t.op, FilterOp::Default);
                assert!(!t.negate);
            }
            _ => panic!("expected filter"),
        }
    }

    #[test]
    fn test_implicit_and() {
        let node = parse_query("tag:web port:443");
        assert!(matches!(node, QueryNode::And(_, _)));
    }

    #[test]
    fn test_explicit_or() {
        let node = parse_query("tag:web OR kind:ssh");
        assert!(matches!(node, QueryNode::Or(_, _)));
    }

    #[test]
    fn test_not_prefix() {
        let node = parse_query("-tag:web");
        match node {
            QueryNode::Not(inner) => {
                assert!(matches!(*inner, QueryNode::Filter(_)));
            }
            _ => panic!("expected not"),
        }
    }

    #[test]
    fn test_parens() {
        let node = parse_query("(tag:web OR tag:iot) port:80");
        match node {
            QueryNode::And(left, right) => {
                assert!(matches!(*left, QueryNode::Or(_, _)));
                assert!(matches!(*right, QueryNode::Filter(_)));
            }
            _ => panic!("expected and(or, filter)"),
        }
    }

    #[test]
    fn test_dot_operator() {
        let node = parse_query("http.title.contains:\"nginx\"");
        match node {
            QueryNode::Filter(t) => {
                assert_eq!(t.key, "http.title");
                assert_eq!(t.op, FilterOp::Contains);
                assert_eq!(t.value, "nginx");
            }
            _ => panic!("expected filter"),
        }
    }

    #[test]
    fn test_bare_word() {
        let node = parse_query("nginx");
        match node {
            QueryNode::Filter(t) => {
                assert!(t.key.is_empty());
                assert_eq!(t.value, "nginx");
            }
            _ => panic!("expected filter"),
        }
    }

    #[test]
    fn test_compile_simple_tag() {
        let node = parse_query("tag:web");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("data @>"));
        assert!(where_clause.contains("tags"));
        assert!(params.is_empty());
    }

    #[test]
    fn test_compile_and() {
        let node = parse_query("tag:web port:443");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("AND"));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_compile_or() {
        let node = parse_query("tag:web OR tag:iot");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("OR"));
        assert!(params.is_empty());
    }

    #[test]
    fn test_compile_not() {
        let node = parse_query("-tag:web");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.starts_with("NOT"));
        assert!(params.is_empty());
    }

    #[test]
    fn test_compile_contains() {
        let node = parse_query("http.title.contains:\"nginx\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("LIKE"));
        assert_eq!(params, vec!["nginx"]);
    }

    #[test]
    fn test_compile_icontains() {
        let node = parse_query("http.server.icontains:\"Apache\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("ILIKE"));
        assert_eq!(params, vec!["Apache"]);
    }

    #[test]
    fn test_compile_regex() {
        let node = parse_query("banner.regex:\"^SSH-2.0\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("~"));
        assert_eq!(params, vec!["^SSH-2.0"]);
    }

    #[test]
    fn test_compile_startswith() {
        let node = parse_query("http.title.startswith:\"Hello\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("LIKE"));
        assert!(params[0].starts_with("Hello"));
    }

    #[test]
    fn test_compile_endswith() {
        let node = parse_query("http.title.endswith:\"World\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("LIKE"));
        assert!(params[0].ends_with("World"));
    }

    #[test]
    fn test_full_query() {
        let node = parse_query("tag:web port:443 http.title.contains:\"nginx\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("AND"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_complex_query() {
        let node = parse_query("(tag:web OR tag:iot) -http.title.contains:\"test\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("OR"));
        assert!(where_clause.contains("NOT"));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_search_query_generation() {
        let node = parse_query("tag:web");
        let (query, params) = build_search_query(&node);
        assert!(query.contains("SELECT"));
        assert!(query.contains("JOIN hosts"));
        assert!(query.contains("LIMIT 100"));
        assert!(params.is_empty());
    }

    #[test]
    fn test_empty_query() {
        let node = parse_query("");
        let (where_clause, _params) = compile_to_sql(&node);
        assert_eq!(where_clause, "TRUE");
    }

    #[test]
    fn test_json_text_col() {
        assert_eq!(json_text_col("http.title"), "data->'http'->>'title'");
        assert_eq!(json_text_col("banner"), "data->>'banner'");
        assert_eq!(json_text_col("ssl.subject_cn"), "data->'ssl'->>'subject_cn'");
    }

    #[test]
    fn test_user_example_query() {
        let node = parse_query("tag:web -http.title.contains \"Please wait, the page is opening... ipacct\"");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("AND"));
        assert!(where_clause.contains("NOT"));
        assert!(where_clause.contains("LIKE"));
        assert!(params.iter().any(|p| p.contains("Please wait")));
    }

    #[test]
    fn test_nested_parens() {
        let node = parse_query("((tag:web OR tag:iot) AND port:443)");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("OR"));
        assert!(where_clause.contains("AND"));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_not_with_group() {
        let node = parse_query("-(tag:web OR tag:iot)");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.starts_with("NOT"));
        assert!(where_clause.contains("OR"));
        assert!(params.is_empty());
    }

    #[test]
    fn test_multi_level_dot_key() {
        let node = parse_query("ssl.subject_cn.contains:\"example\"");
        match &node {
            QueryNode::Filter(t) => {
                assert_eq!(t.key, "ssl.subject_cn");
                assert_eq!(t.op, FilterOp::Contains);
                assert_eq!(t.value, "example");
            }
            _ => panic!("expected filter"),
        }
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("data->'ssl'->>'subject_cn'"));
        assert!(where_clause.contains("LIKE"));
        assert_eq!(params, vec!["example"]);
    }

    #[test]
    fn test_bare_word_in_and() {
        let node = parse_query("nginx port:80");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("AND"));
        assert!(where_clause.contains("ILIKE"));
        assert_eq!(params, vec!["nginx", "80"]);
    }

    #[test]
    fn test_bare_word_in_or() {
        let node = parse_query("nginx OR apache");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("OR"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_compound_not_and_or() {
        let node = parse_query("tag:web port:443 OR kind:ssh -banner.contains:\"test\"");
        let (where_clause, _params) = compile_to_sql(&node);
        assert!(where_clause.contains("OR"));
        assert!(where_clause.contains("NOT"));
    }

    #[test]
    fn test_quoted_value_with_spaces() {
        let node = parse_query("http.title:\"Hello World\"");
        match &node {
            QueryNode::Filter(t) => {
                assert_eq!(t.key, "http.title");
                assert_eq!(t.value, "Hello World");
            }
            _ => panic!("expected filter"),
        }
    }

    #[test]
    fn test_empty_parens() {
        let node = parse_query("()");
        let (where_clause, _) = compile_to_sql(&node);
        assert_eq!(where_clause, "TRUE");
    }

    #[test]
    fn test_country_filter() {
        let node = parse_query("country:DE");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("h.country_code"));
        assert_eq!(params, vec!["DE"]);
    }

    #[test]
    fn test_port_filter() {
        let node = parse_query("port:443");
        let (where_clause, params) = compile_to_sql(&node);
        assert!(where_clause.contains("s.port"));
        assert_eq!(params, vec!["443"]);
    }
}
