use std::fs;
use std::path::Path;

use android_log_analyzer::{FindingKind, analyze_text};

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    fs::read_to_string(path).expect("fixture to load")
}

#[test]
fn detects_java_crash_from_fixture() {
    let report = analyze_text(&fixture("java_fatal_exception.log"));

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::FatalException);
    assert_eq!(
        report.findings[0].package.as_deref(),
        Some("com.example.demo")
    );
}

#[test]
fn detects_native_crash_from_fixture() {
    let report = analyze_text(&fixture("native_sigsegv.log"));

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::NativeCrash);
}

#[test]
fn ignores_noise_only_fixture() {
    let report = analyze_text(&fixture("noise_only.log"));

    assert!(report.findings.is_empty());
}

#[test]
fn preserves_parse_warnings_without_panicking() {
    let report = analyze_text(&fixture("malformed_fragment.log"));

    assert_eq!(report.findings.len(), 1);
    assert!(!report.parse_warnings.is_empty());
}
