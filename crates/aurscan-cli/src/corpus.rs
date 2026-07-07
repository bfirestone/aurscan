//! Opt-in feature-corpus recording: appends each report's `FeatureVector`s as
//! schema-versioned JSONL under `{data_dir}/aurscan/corpus/`, for later
//! phase-2 classifier training. Best-effort -- a write failure never fails
//! the scan that produced the reports.

use aurscan_core::{PackageReport, Verdict};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

#[derive(Serialize)]
struct CorpusLine<'a> {
    package: &'a str,
    schema_version: u16,
    verdict: &'static str,
    values: &'a [(aurscan_core::FeatureId, f32)],
    ts: i64,
}

/// Append one JSON line per `FeatureVector` across `reports` to
/// `{data_dir}/aurscan/corpus/features-{schema_version}.jsonl`. Reports with
/// no features are skipped. Never returns an error -- I/O failures are
/// logged and swallowed so a corpus-recording hiccup never turns a clean
/// scan into a failed one.
pub fn record(reports: &[PackageReport], data_dir: &Path) {
    let dir = data_dir.join("aurscan/corpus");
    for report in reports {
        for features in &report.features {
            let line = CorpusLine {
                package: &report.package,
                schema_version: features.schema_version,
                verdict: verdict_name(&report.verdict),
                values: &features.values,
                ts: epoch_now(),
            };
            append_line(&dir, features.schema_version, &line);
        }
    }
}

fn append_line(dir: &Path, schema_version: u16, line: &CorpusLine) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(json) = serde_json::to_string(line) else {
        return;
    };
    let path = dir.join(format!("features-{schema_version}.jsonl"));
    let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let _ = writeln!(file, "{json}");
}

fn verdict_name(v: &Verdict) -> &'static str {
    match v {
        Verdict::Clean => "clean",
        Verdict::Advisory(_) => "advisory",
        Verdict::Block(_) => "block",
    }
}

fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurscan_core::{FeatureId, FeatureVector};

    #[test]
    fn record_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let report = PackageReport {
            package: "pkg".into(),
            verdict: Verdict::Clean,
            findings: vec![],
            features: vec![FeatureVector {
                schema_version: 2,
                values: vec![(FeatureId(100), 1.5), (FeatureId(101), 2.0)],
            }],
        };

        record(&[report], dir.path());

        let path = dir.path().join("aurscan/corpus/features-2.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let line = content.lines().next().expect("one recorded line");
        let value: serde_json::Value = serde_json::from_str(line).unwrap();

        assert_eq!(value["package"], "pkg");
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["verdict"], "clean");
        assert_eq!(value["values"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn reports_with_no_features_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let report = PackageReport {
            package: "pkg".into(),
            verdict: Verdict::Clean,
            findings: vec![],
            features: vec![],
        };

        record(&[report], dir.path());

        assert!(!dir.path().join("aurscan/corpus").exists());
    }
}
