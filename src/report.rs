use crate::model::{AnalysisReport, Finding};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

pub fn render_report(
    report: &AnalysisReport,
    format: OutputFormat,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Text => Ok(render_text(report)),
        OutputFormat::Json => serde_json::to_string_pretty(report),
    }
}

fn render_text(report: &AnalysisReport) -> String {
    let mut output = String::new();

    if report.findings.is_empty() {
        output.push_str("No high-confidence crash findings detected.\n");
    } else {
        output.push_str("Summary\n");
        output.push_str(&format!("Findings: {}\n", report.summary.total_findings));
        output.push_str(&format!(
            "Top severity: {}\n",
            report
                .summary
                .top_severity
                .map(severity_label)
                .unwrap_or("unknown")
        ));

        if !report.summary.root_cause_candidates.is_empty() {
            output.push_str("Likely root causes:\n");
            for candidate in &report.summary.root_cause_candidates {
                output.push_str(&format!("- {candidate}\n"));
            }
        }

        output.push_str("\nFindings\n");
        for (index, finding) in report.findings.iter().enumerate() {
            write_finding(&mut output, index, finding);
        }
    }

    if !report.parse_warnings.is_empty() {
        output.push_str(&format!(
            "\nParse warnings: {} line(s) did not match a structured logcat format.\n",
            report.parse_warnings.len()
        ));
    }

    output
}

fn write_finding(output: &mut String, index: usize, finding: &Finding) {
    output.push_str(&format!(
        "\n{}. [{}] {:?} at lines {}-{}\n",
        index + 1,
        severity_label(finding.severity),
        finding.kind,
        finding.line_start,
        finding.line_end
    ));
    output.push_str(&format!("   Title: {}\n", finding.title));
    output.push_str(&format!("   Why: {}\n", finding.rationale));
    output.push_str(&format!("   Signature: {}\n", finding.signature));
    output.push_str(&format!("   Occurrences: {}\n", finding.occurrence_count));

    if let Some(process) = &finding.process {
        output.push_str(&format!("   Process: {process}\n"));
    }

    if let Some(thread) = &finding.thread {
        output.push_str(&format!("   Thread: {thread}\n"));
    }

    if let Some(root_cause) = &finding.root_cause {
        output.push_str(&format!("   Root cause: {root_cause}\n"));
    }

    output.push_str("   Evidence:\n");
    for evidence in &finding.evidence {
        output.push_str(&format!(
            "     L{} {}\n",
            evidence.line_number, evidence.message
        ));
    }
}

fn severity_label(severity: crate::model::Severity) -> &'static str {
    match severity {
        crate::model::Severity::Low => "low",
        crate::model::Severity::Medium => "medium",
        crate::model::Severity::High => "high",
        crate::model::Severity::Critical => "critical",
    }
}
