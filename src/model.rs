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
    pub root_cause: Option<String>,
    pub signature: String,
    pub occurrence_count: usize,
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
pub struct ReportSummary {
    pub total_findings: usize,
    pub parse_warning_count: usize,
    pub top_severity: Option<Severity>,
    pub root_cause_candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisReport {
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
    pub parse_warnings: Vec<ParseWarning>,
}
