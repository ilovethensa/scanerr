use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_priority")]
    pub priority: u16,
    #[serde(default)]
    pub condition: MatchCondition,
    pub matchers: Vec<MatcherDef>,
}

fn default_priority() -> u16 { 50 }

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchCondition {
    Any,
    All,
}

impl Default for MatchCondition {
    fn default() -> Self { MatchCondition::Any }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherDef {
    pub field: String,
    pub op: Operator,
    pub value: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 { 1 }

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operator {
    Contains,
    Icontains,
    Regex,
    Equals,
    StartsWith,
    EndsWith,
    HashEquals,
    Exists,
    NotContains,
    NotIcontains,
    NotRegex,
    NotEquals,
    NotStartsWith,
    NotEndsWith,
}

// ─── Compiled matcher ─────────────────────────────────────────────────────────

pub struct CompiledMatcher {
    pub field: String,
    pub op: Operator,
    pub value: String,
    pub weight: u32,
    pub regex: Option<Regex>,
}

impl CompiledMatcher {
    pub fn compile(def: &MatcherDef) -> Self {
        let regex = match def.op {
            Operator::Regex | Operator::NotRegex => Regex::new(&def.value).ok(),
            _ => None,
        };
        CompiledMatcher {
            field: def.field.clone(),
            op: def.op.clone(),
            value: def.value.clone(),
            weight: def.weight,
            regex,
        }
    }

    pub fn matches(&self, values: &[String]) -> (bool, u32) {
        // Negative operators: absence satisfies negation
        let is_negative = matches!(self.op,
            Operator::NotContains | Operator::NotIcontains | Operator::NotRegex |
            Operator::NotEquals | Operator::NotStartsWith | Operator::NotEndsWith
        );
        if values.is_empty() {
            return if is_negative { (true, self.weight) } else { (false, 0) };
        }
        let hit = match self.op {
            Operator::Contains => values.iter().any(|v| v.contains(&self.value)),
            Operator::Icontains => {
                let needle = self.value.to_lowercase();
                values.iter().any(|v| v.to_lowercase().contains(&needle))
            }
            Operator::Regex => {
                if let Some(ref re) = self.regex {
                    values.iter().any(|v| re.is_match(v))
                } else {
                    false
                }
            }
            Operator::Equals => values.iter().any(|v| v == &self.value),
            Operator::StartsWith => values.iter().any(|v| v.starts_with(&self.value)),
            Operator::EndsWith => values.iter().any(|v| v.ends_with(&self.value)),
            Operator::HashEquals => {
                values.iter().any(|v| {
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(v.as_bytes());
                    let hash: i64 = {
                        let result = hasher.finalize();
                        let bytes: [u8; 8] = result[..8].try_into().unwrap_or([0; 8]);
                        i64::from_be_bytes(bytes)
                    };
                    self.value.parse::<i64>().map_or(false, |h| h == hash)
                })
            }
            Operator::Exists => !values.is_empty(),
            Operator::NotContains => !values.iter().any(|v| v.contains(&self.value)),
            Operator::NotIcontains => {
                let needle = self.value.to_lowercase();
                !values.iter().any(|v| v.to_lowercase().contains(&needle))
            }
            Operator::NotRegex => {
                if let Some(ref re) = self.regex {
                    !values.iter().any(|v| re.is_match(v))
                } else {
                    true
                }
            }
            Operator::NotEquals => !values.iter().any(|v| v == &self.value),
            Operator::NotStartsWith => !values.iter().any(|v| v.starts_with(&self.value)),
            Operator::NotEndsWith => !values.iter().any(|v| v.ends_with(&self.value)),
        };
        if hit { (true, self.weight) } else { (false, 0) }
    }
}

// ─── Compiled signature ───────────────────────────────────────────────────────

pub struct CompiledSignature {
    pub id: String,
    pub name: String,
    pub tags: Vec<String>,
    pub priority: u16,
    pub condition: MatchCondition,
    pub matchers: Vec<CompiledMatcher>,
}

impl CompiledSignature {
    pub fn total_weight(&self) -> u32 {
        self.matchers.iter().map(|m| m.weight).sum()
    }
}
