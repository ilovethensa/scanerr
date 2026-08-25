use serde::Deserialize;

use crate::models::ServiceData;

const BUILTIN_SIGNATURES: &str = include_str!("signatures.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub tags: Vec<String>,
    pub matchers: Vec<Matcher>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum Matcher {
    Title(String),
    HeaderServer(String),
    Body(String),
    FaviconHash(i64),
}

#[derive(Debug)]
pub struct Corpus {
    signatures: Vec<Signature>,
}

impl Corpus {
    pub fn new(overlay_path: Option<&str>) -> Self {
        let mut signatures: Vec<Signature> =
            serde_json::from_str(BUILTIN_SIGNATURES).unwrap_or_default();

        if let Some(path) = overlay_path {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(overlay) = serde_json::from_str::<Vec<Signature>>(&text) {
                    signatures.extend(overlay);
                }
            }
        }

        Self { signatures }
    }

    pub fn identify(&self, data: &mut ServiceData) {
        for sig in &self.signatures {
            if self.matches(sig, data) {
                data.product = sig.product.clone();
                data.version = sig.version.clone();
                for tag in &sig.tags {
                    if !data.tags.contains(tag) {
                        data.tags.push(tag.clone());
                    }
                }
            }
        }
    }

    fn matches(&self, sig: &Signature, data: &ServiceData) -> bool {
        sig.matchers.iter().all(|m| self.matches_single(m, data))
    }

    fn matches_single(&self, matcher: &Matcher, data: &ServiceData) -> bool {
        match matcher {
            Matcher::Title(pattern) => data
                .http
                .as_ref()
                .and_then(|h| h.title.as_ref())
                .map(|t| t.contains(pattern))
                .unwrap_or(false),
            Matcher::HeaderServer(pattern) => data
                .http
                .as_ref()
                .and_then(|h| h.headers.get("server"))
                .and_then(|v| v.first())
                .map(|s| s.contains(pattern))
                .unwrap_or(false),
            Matcher::Body(pattern) => data
                .http
                .as_ref()
                .and_then(|h| h.body.as_ref())
                .map(|b| b.contains(pattern))
                .unwrap_or(false),
            Matcher::FaviconHash(hash) => data
                .http
                .as_ref()
                .and_then(|h| h.favicon_hash)
                .map(|h| h == *hash)
                .unwrap_or(false),
        }
    }
}

pub fn identify(data: &mut ServiceData) {
    let corpus = Corpus::new(None);
    corpus.identify(data);
}

#[cfg(test)]
mod tests {
use super::*;
use crate::models::HttpData;
use std::collections::BTreeMap;

    #[test]
    fn test_identify_nginx() {
        let mut data = ServiceData {
            kind: "http".into(),
            http: Some(HttpData {
                status: 200,
                title: Some("Welcome to nginx!".into()),
                body: None,
                headers: {
                    let mut h = BTreeMap::new();
                    h.insert("server".into(), vec!["nginx/1.18.0".into()]);
                    h
                },
                favicon_hash: None,
            }),
            tags: vec!["http".into()],
            ..Default::default()
        };

        let corpus = Corpus::new(None);
        corpus.identify(&mut data);

        assert!(data.tags.contains(&"http".to_string()));
        assert_eq!(data.product.as_deref(), Some("nginx"));
    }

    #[test]
    fn test_matcher_title() {
        let matcher = Matcher::Title("nginx".into());
        let data = ServiceData {
            http: Some(HttpData {
                status: 200,
                title: Some("Welcome to nginx!".into()),
                body: None,
                headers: BTreeMap::new(),
                favicon_hash: None,
            }),
            ..Default::default()
        };

        let corpus = Corpus::new(None);
        assert!(corpus.matches_single(&matcher, &data));
    }

    #[test]
    fn test_matcher_no_match() {
        let matcher = Matcher::Title("apache".into());
        let data = ServiceData {
            http: Some(HttpData {
                status: 200,
                title: Some("Welcome to nginx!".into()),
                body: None,
                headers: BTreeMap::new(),
                favicon_hash: None,
            }),
            ..Default::default()
        };

        let corpus = Corpus::new(None);
        assert!(!corpus.matches_single(&matcher, &data));
    }
}
