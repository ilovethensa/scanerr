use std::collections::BTreeMap;

pub fn detect(headers: &BTreeMap<String, serde_json::Value>, body: &str) -> Vec<String> {
    let mut tags = Vec::new();

    // Server header → "name/version" tag
    if let Some(server) = header_str(headers, "server") {
        parse_server_header(&server, &mut tags);
    }

    // x-powered-by → "name/version" tag
    if let Some(powered) = header_str(headers, "x-powered-by") {
        parse_powered_by(&powered, &mut tags);
    }

    // ASP.NET detection
    if header_str(headers, "x-aspnet-version").is_some() || header_str(headers, "x-aspnetmvc-version").is_some() {
        push_unique(&mut tags, "ASP.NET");
    }

    // Version extraction from body (frameworks where YAML can't capture the version)
    detect_versions_from_body(body, &mut tags);

    tags
}

fn detect_versions_from_body(body: &str, out: &mut Vec<String>) {
    // jQuery
    if let Some(ver) = extract_version_from(body, "jquery", "jquery[/.]") {
        push_unique(out, &format!("jQuery/{}", ver));
    }

    // Bootstrap
    if body.contains("bootstrap.min.css") || body.contains("bootstrap.min.js") {
        if let Some(ver) = extract_version_from(body, "bootstrap", r"bootstrap[/.]") {
            push_unique(out, &format!("Bootstrap/{}", ver));
        } else {
            push_unique(out, "Bootstrap");
        }
    }

    // React
    if body.contains("react.min.js") || body.contains("react.production.min.js") || body.contains("__REACT") {
        if let Some(ver) = extract_version_from(body, "react", r"react[/.]") {
            push_unique(out, &format!("React/{}", ver));
        } else {
            push_unique(out, "React");
        }
    }

    // Vue.js
    if body.contains("vue.min.js") || body.contains("vue.js") || body.contains("data-v-") {
        if let Some(ver) = extract_version_from(body, "vue", r"vue[/.]") {
            push_unique(out, &format!("Vue.js/{}", ver));
        } else {
            push_unique(out, "Vue.js");
        }
    }

    // Angular
    if body.contains("angular.min.js") || body.contains("ng-app") || body.contains("ng-controller") {
        if let Some(ver) = extract_version_from(body, "angular", r"angular[/.]") {
            push_unique(out, &format!("Angular/{}", ver));
        } else {
            push_unique(out, "Angular");
        }
    }
}

fn parse_server_header(server: &str, out: &mut Vec<String>) {
    let (name, ver) = if let Some(pos) = server.find('/') {
        (&server[..pos], Some(server[pos+1..].trim().to_string()))
    } else {
        (server, None)
    };

    let name = name.trim();
    if name.is_empty() { return; }

    // Skip generic names that don't identify the product
    match name.to_lowercase().as_str() {
        "webs" | "httpd" | "web" | "server" => return,
        _ => {}
    }

    let tag = match ver {
        Some(v) => format!("{}/{}", name, v),
        None => name.to_string(),
    };
    push_unique(out, &tag);
}

fn parse_powered_by(val: &str, out: &mut Vec<String>) {
    let val = val.trim();
    let (name, ver) = if let Some(pos) = val.find('/') {
        (&val[..pos], Some(val[pos+1..].trim().to_string()))
    } else {
        (val, None)
    };

    let name = name.trim();
    if name.is_empty() { return; }

    let tag = match ver {
        Some(v) => format!("{}/{}", name, v),
        None => name.to_string(),
    };
    push_unique(out, &tag);
}

fn extract_version_from(body: &str, name: &str, pattern: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let pat = pattern.to_lowercase();

    // Pattern: name-X.Y.Z or name/X.Y.Z
    if let Some(pos) = lower.find(&pat) {
        let after = &body[pos + name.len()..];
        let after_lower = after.to_lowercase();
        let ver_start = after_lower.find(|c: char| c == '/' || c == '-' || c == '.');
        if let Some(vs) = ver_start {
            let ver_str = &after[vs+1..];
            let ver: String = ver_str.chars().take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '_').collect();
            if !ver.is_empty() && ver.len() < 20 {
                return Some(ver);
            }
        }
    }

    // Pattern: ?ver=X.Y.Z
    if let Some(qpos) = lower.find(&format!("{}?", name)) {
        let after = &body[qpos..];
        if let Some(verpos) = after.to_lowercase().find("ver=") {
            let ver_str = &after[verpos+4..];
            let ver: String = ver_str.chars().take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '_').collect();
            if !ver.is_empty() && ver.len() < 20 {
                return Some(ver);
            }
        }
    }

    None
}

fn push_unique(out: &mut Vec<String>, tag: &str) {
    if !out.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
        out.push(tag.to_string());
    }
}

fn header_str<'a>(headers: &'a BTreeMap<String, serde_json::Value>, key: &str) -> Option<String> {
    headers.get(key).and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => arr.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    })
}
