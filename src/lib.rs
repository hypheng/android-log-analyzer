mod analyzer;
mod model;
mod parser;
mod report;

pub use model::{
    AnalysisReport, EvidenceLine, Finding, FindingKind, ParseWarning, ReportSummary, Severity,
};
pub use report::{OutputFormat, render_report};

pub fn analyze_text(input: &str) -> AnalysisReport {
    let parsed = parser::parse_lines(input);
    analyzer::analyze(parsed)
}
