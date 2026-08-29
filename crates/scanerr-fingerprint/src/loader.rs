use anyhow::{Context, Result};
use std::path::Path;

use super::signature::Signature;

/// Recursively load all `.yaml` / `.yml` signature files from a directory tree.
pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<Signature>> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        anyhow::bail!("signatures directory not found: {}", dir.display());
    }

    let mut sigs = Vec::new();
    load_recursive(dir, &mut sigs)?;

    if sigs.is_empty() {
        tracing::warn!("no signature files found in {}", dir.display());
    }

    Ok(sigs)
}

fn load_recursive(dir: &Path, out: &mut Vec<Signature>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            load_recursive(&path, out)?;
        } else if is_signature_file(&path) {
            match load_file(&path) {
                Ok(sig) => out.push(sig),
                Err(e) => {
                    tracing::warn!("skipping {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(())
}

fn load_file(path: &Path) -> Result<Signature> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let sig: Signature = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(sig)
}

fn is_signature_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e, "yaml" | "yml"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let sigs = load_dir(tmp.path()).unwrap();
        assert!(sigs.is_empty());
    }

    #[test]
    fn test_load_valid_sig() {
        let tmp = TempDir::new().unwrap();
        let yaml = r#"
id: test-sig
name: Test Signature
category: test
tags: [test]
matchers:
  - field: http.title
    op: contains
    value: Test
"#;
        std::fs::write(tmp.path().join("test.yaml"), yaml).unwrap();
        let sigs = load_dir(tmp.path()).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].id, "test-sig");
    }

    #[test]
    fn test_load_invalid_sig() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("bad.yaml"), "not: valid: yaml: [").unwrap();
        // Should not fail — just warn
        let _sigs = load_dir(tmp.path()).unwrap();
    }
}
