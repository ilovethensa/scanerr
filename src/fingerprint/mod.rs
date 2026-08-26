pub mod loader;
pub mod score;
pub mod signature;

use std::sync::Arc;

use crate::evidence::Evidence;
use crate::models::ServiceData;
use signature::{CompiledMatcher, CompiledSignature};

/// The fingerprint engine. Built once at startup, shared across all probes.
#[derive(Clone)]
pub struct Engine {
    signatures: Arc<Vec<CompiledSignature>>,
}

impl Engine {
    /// Load signatures from a directory tree.
    pub fn from_dir(path: impl AsRef<std::path::Path>) -> Self {
        let sigs = loader::load_dir(path).unwrap_or_else(|e| {
            tracing::error!("failed to load signatures: {}", e);
            Vec::new()
        });
        Self::from_signatures(sigs)
    }

    /// Build from pre-loaded raw signatures (useful for tests).
    pub fn from_signatures(raw: Vec<signature::Signature>) -> Self {
        let signatures: Vec<CompiledSignature> = raw.into_iter().map(compile).collect();
        tracing::info!("loaded {} fingerprints", signatures.len());
        Self { signatures: Arc::new(signatures) }
    }

    /// Identify the best matching signature for the given service data.
    /// Sets `product`, `version`, `confidence`, and merges tags.
    pub fn identify(&self, data: &mut ServiceData) {
        let evidence = Evidence::from(&*data);
        if let Some(result) = score::resolve(&self.signatures, &evidence) {
            if let Some(sig) = self.signatures.iter().find(|s| s.id == result.signature_id) {
                data.product = Some(sig.name.clone());
                data.confidence = Some(result.confidence);
                // Merge tags (don't overwrite existing)
                for tag in &sig.tags {
                    if !data.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
                        data.tags.push(tag.clone());
                    }
                }
            }
        }
    }
}

fn compile(raw: signature::Signature) -> CompiledSignature {
    let matchers: Vec<CompiledMatcher> = raw.matchers.iter()
        .map(CompiledMatcher::compile)
        .collect();

    CompiledSignature {
        id: raw.id,
        name: raw.name,
        tags: raw.tags,
        priority: raw.priority,
        condition: raw.condition,
        matchers,
    }
}

/// Convenience for `test-probe` and simple use: identify inline with default engine.
pub fn identify(data: &mut ServiceData) {
    // Falls back to empty corpus if no signatures dir exists.
    // For production, use Engine::from_dir() instead.
    let engine = Engine::from_signatures(Vec::new());
    engine.identify(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HttpData;
    use std::collections::BTreeMap;

    #[test]
    fn test_identify_nginx() {
        let sig = signature::Signature {
            id: "nginx".into(),
            name: "nginx".into(),
            category: "server".into(),
            tags: vec!["web".into(), "server".into()],
            priority: 50,
            condition: signature::MatchCondition::Any,
            matchers: vec![signature::MatcherDef {
                field: "http.header.server".into(),
                op: signature::Operator::Icontains,
                value: "nginx".into(),
                weight: 5,
            }],
        };

        let engine = Engine::from_signatures(vec![sig]);

        let mut data = ServiceData {
            kind: "http".into(),
            http: Some(HttpData {
                status: 200,
                title: None,
                body: None,
                headers: {
                    let mut h = BTreeMap::new();
                    h.insert("server".into(), serde_json::Value::String("nginx/1.18.0".into()));
                    h
                },
                favicon_hash: None,
                server: Some("nginx/1.18.0".into()),
                host: None,
                rdns: None,
                html_hash: None,
                headers_hash: None,
                robots: None,
                securitytxt: None,
                tags: Vec::new(),
                waf: None,
                redirects: Vec::new(),
            }),
            ..Default::default()
        };

        engine.identify(&mut data);
        assert_eq!(data.product.as_deref(), Some("nginx"));
        assert!(data.tags.contains(&"web".to_string()));
    }
}
