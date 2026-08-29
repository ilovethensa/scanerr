use super::signature::{CompiledSignature, MatchCondition};

/// The result of evaluating a single signature against evidence.
pub struct MatchResult {
    pub signature_id: String,
    pub score: u32,
    pub confidence: u8,
    pub matched: bool,
}

/// Evaluate all signatures against evidence and return the best match, if any.
pub fn resolve(
    signatures: &[CompiledSignature],
    evidence: &crate::evidence::Evidence,
) -> Option<MatchResult> {
    let mut best: Option<MatchResult> = None;

    for sig in signatures {
        let result = evaluate(sig, evidence);
        if !result.matched {
            continue;
        }

        match &best {
            None => best = Some(result),
            Some(current) => {
                // Higher score wins
                if result.score > current.score {
                    best = Some(result);
                } else if result.score == current.score {
                    // Higher priority wins
                    let sig_prio = signatures.iter()
                        .find(|s| s.id == result.signature_id)
                        .map(|s| s.priority)
                        .unwrap_or(0);
                    let cur_prio = signatures.iter()
                        .find(|s| s.id == current.signature_id)
                        .map(|s| s.priority)
                        .unwrap_or(0);
                    if sig_prio > cur_prio {
                        best = Some(result);
                    }
                }
            }
        }
    }

    best
}

fn evaluate(sig: &CompiledSignature, evidence: &crate::evidence::Evidence) -> MatchResult {
    let mut total_score = 0u32;
    let mut matched_count = 0u32;
    let mut best_match_weight = 0u32;

    for m in &sig.matchers {
        let values = evidence.values(&m.field);
        let (hit, weight) = m.matches(values);
        if hit {
            total_score += weight;
            matched_count += 1;
            if weight > best_match_weight {
                best_match_weight = weight;
            }
        }
    }

    let sig_matched = match sig.condition {
        MatchCondition::Any => matched_count > 0,
        MatchCondition::All => matched_count == sig.matchers.len() as u32,
    };

    let confidence = if sig_matched {
        match sig.condition {
            MatchCondition::Any => {
                // For "any" condition: confidence driven by the strongest single match.
                // A definitive matcher (e.g. brand name in a header) should stand on its own.
                let max_weight = sig.matchers.iter().map(|m| m.weight).max().unwrap_or(1);
                ((best_match_weight as f64 / max_weight as f64) * 100.0) as u8
            }
            MatchCondition::All => {
                // For "all" condition: confidence is coverage across all matchers.
                let total = sig.total_weight();
                if total > 0 {
                    ((total_score as f64 / total as f64) * 100.0) as u8
                } else {
                    0
                }
            }
        }
    } else {
        0
    };

    MatchResult {
        signature_id: sig.id.clone(),
        score: total_score,
        confidence,
        matched: sig_matched,
    }
}
