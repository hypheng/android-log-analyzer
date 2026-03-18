use std::fs;
use std::path::Path;

use android_log_analyzer::{OutputFormat, analyze_text, render_report};

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    fs::read_to_string(path).expect("fixture to load")
}

#[test]
fn json_output_includes_summary_and_occurrence_count() {
    let report = analyze_text(&fixture("repeated_fatal_exception.log"));
    let json = render_report(&report, OutputFormat::Json).expect("json render");

    assert!(json.contains("\"summary\""));
    assert!(json.contains("\"occurrence_count\": 2"));
}

#[test]
fn text_output_mentions_occurrences_and_root_cause() {
    let report = analyze_text(&fixture("repeated_fatal_exception.log"));
    let text = render_report(&report, OutputFormat::Text).expect("text render");

    assert!(text.contains("Occurrences: 2"));
    assert!(text.contains("Root cause:"));
    assert!(text.contains("Likely root causes:"));
}
