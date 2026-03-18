use std::fmt;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogLine {
    pub line_number: usize,
    pub timestamp: Option<String>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub level: Option<LogLevel>,
    pub tag: Option<String>,
    pub message: String,
    pub raw: String,
    pub structured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LogLevel {
    Verbose,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParseWarning {
    pub line_number: usize,
    pub raw: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceLine {
    pub line_number: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub rationale: String,
    pub line_start: usize,
    pub line_end: usize,
    pub package: Option<String>,
    pub process: Option<String>,
    pub thread: Option<String>,
    pub exception: Option<String>,
    pub evidence: Vec<EvidenceLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FindingKind {
    FatalException,
    Anr,
    NativeCrash,
    Abort,
    OutOfMemory,
    JniError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisReport {
    pub findings: Vec<Finding>,
    pub parse_warnings: Vec<ParseWarning>,
}

impl fmt::Display for AnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.findings.is_empty() {
            writeln!(f, "No high-confidence crash findings detected.")?;
        } else {
            writeln!(f, "Likely crash findings: {}", self.findings.len())?;

            for (index, finding) in self.findings.iter().enumerate() {
                writeln!(
                    f,
                    "\n{}. [{:?}] {:?} at lines {}-{}",
                    index + 1,
                    finding.severity,
                    finding.kind,
                    finding.line_start,
                    finding.line_end
                )?;
                writeln!(f, "   Title: {}", finding.title)?;
                writeln!(f, "   Why: {}", finding.rationale)?;

                if let Some(process) = &finding.process {
                    writeln!(f, "   Process: {process}")?;
                }

                if let Some(thread) = &finding.thread {
                    writeln!(f, "   Thread: {thread}")?;
                }

                if let Some(exception) = &finding.exception {
                    writeln!(f, "   Exception: {exception}")?;
                }

                writeln!(f, "   Evidence:")?;
                for evidence in &finding.evidence {
                    writeln!(f, "     L{} {}", evidence.line_number, evidence.message)?;
                }
            }
        }

        if !self.parse_warnings.is_empty() {
            writeln!(
                f,
                "\nParse warnings: {} line(s) did not match a structured logcat format.",
                self.parse_warnings.len()
            )?;
        }

        Ok(())
    }
}
