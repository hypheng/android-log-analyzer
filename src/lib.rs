mod analyzer;
mod model;
mod parser;

pub use model::{AnalysisReport, EvidenceLine, Finding, FindingKind, ParseWarning, Severity};

pub fn analyze_text(input: &str) -> AnalysisReport {
    let parsed = parser::parse_lines(input);
    analyzer::analyze(parsed)
}
