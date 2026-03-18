use std::collections::{BTreeMap, BTreeSet};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::model::{
    AnalysisReport, EvidenceLine, Finding, FindingKind, LogLine, ParseWarning, ReportSummary,
    Severity,
};
use crate::parser::ParsedLog;

static PROCESS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Process:\s+([^,]+),\s+PID:\s+(\d+)").expect("valid process regex"));
static HEX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{8,}\b").expect("valid hex regex"));
static NUMBER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d+\b").expect("valid numeric regex"));
static WHITESPACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\s+").expect("valid whitespace regex"));

pub fn analyze(parsed: ParsedLog) -> AnalysisReport {
    let findings = deduplicate_findings(collect_findings(&parsed.lines));
    let summary = build_summary(&findings, &parsed.warnings);

    AnalysisReport {
        summary,
        findings,
        parse_warnings: parsed.warnings,
    }
}

fn collect_findings(lines: &[LogLine]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut last_consumed_line = 0usize;

    for (index, line) in lines.iter().enumerate() {
        if line.line_number <= last_consumed_line {
            continue;
        }

        if let Some(kind) = detect_anchor(line) {
            let (line_start, line_end, evidence) = collect_evidence(lines, index);
            let exception = extract_exception(&evidence);
            let root_cause = extract_root_cause(&evidence, line, exception.clone());
            let finding = Finding {
                kind,
                severity: severity_for(kind),
                title: title_for(kind, line),
                rationale: rationale_for(kind, line),
                line_start,
                line_end,
                package: extract_package(&evidence),
                process: extract_process(&evidence),
                thread: extract_thread(&evidence),
                exception,
                root_cause,
                signature: String::new(),
                occurrence_count: 1,
                evidence,
            };
            last_consumed_line = finding.line_end;
            findings.push(finding);
        }
    }

    findings
}

fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut grouped: BTreeMap<String, Finding> = BTreeMap::new();

    for mut finding in findings {
        let signature = build_signature(&finding);
        finding.signature = signature.clone();

        if let Some(existing) = grouped.get_mut(&signature) {
            merge_findings(existing, finding);
        } else {
            grouped.insert(signature, finding);
        }
    }

    let mut deduped: Vec<Finding> = grouped.into_values().collect();
    deduped.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(right.occurrence_count.cmp(&left.occurrence_count))
            .then(left.line_start.cmp(&right.line_start))
    });

    for finding in &mut deduped {
        if finding.occurrence_count > 1 {
            finding.rationale = format!(
                "{} This normalized signature appeared {} times.",
                finding.rationale, finding.occurrence_count
            );
        }
    }

    deduped
}

fn build_summary(findings: &[Finding], warnings: &[ParseWarning]) -> ReportSummary {
    let mut root_cause_candidates = Vec::new();
    let mut seen = BTreeSet::new();

    for finding in findings {
        let candidate = finding
            .root_cause
            .as_deref()
            .or(finding.exception.as_deref())
            .unwrap_or(finding.title.as_str())
            .to_string();

        if seen.insert(candidate.clone()) {
            root_cause_candidates.push(candidate);
        }

        if root_cause_candidates.len() == 3 {
            break;
        }
    }

    ReportSummary {
        total_findings: findings.len(),
        parse_warning_count: warnings.len(),
        top_severity: findings.first().map(|finding| finding.severity),
        root_cause_candidates,
    }
}

fn merge_findings(existing: &mut Finding, incoming: Finding) {
    existing.occurrence_count += 1;
    existing.line_start = existing.line_start.min(incoming.line_start);
    existing.line_end = existing.line_end.max(incoming.line_end);

    if existing.root_cause.is_none() {
        existing.root_cause = incoming.root_cause.clone();
    }

    if existing.exception.is_none() {
        existing.exception = incoming.exception.clone();
    }

    if existing.process.is_none() {
        existing.process = incoming.process.clone();
    }

    if existing.package.is_none() {
        existing.package = incoming.package.clone();
    }

    if existing.thread.is_none() {
        existing.thread = incoming.thread.clone();
    }

    let mut seen_messages: BTreeSet<String> = existing
        .evidence
        .iter()
        .map(|line| normalized_message(&line.message))
        .collect();
    for line in incoming.evidence {
        if existing.evidence.len() >= 12 {
            break;
        }

        let normalized = normalized_message(&line.message);
        if seen_messages.insert(normalized) {
            existing.evidence.push(line);
        }
    }
}

fn build_signature(finding: &Finding) -> String {
    let scope = finding
        .package
        .as_deref()
        .or(finding.process.as_deref())
        .unwrap_or("unknown-process");
    let root_cause = finding
        .root_cause
        .as_deref()
        .or(finding.exception.as_deref())
        .unwrap_or(finding.title.as_str());
    let frame = signature_frame(finding).unwrap_or_else(|| finding.title.clone());

    format!(
        "{}|{}|{}|{}",
        kind_token(finding.kind),
        normalized_message(scope),
        normalized_message(root_cause),
        normalized_message(&frame)
    )
}

fn signature_frame(finding: &Finding) -> Option<String> {
    let mut fallback = None;

    for line in &finding.evidence {
        let message = evidence_message(line).trim();
        if message.starts_with("at ") {
            if is_app_frame(message) {
                return Some(message.to_string());
            }

            if fallback.is_none() {
                fallback = Some(message.to_string());
            }
        } else if message.starts_with('#') && fallback.is_none() {
            fallback = Some(message.to_string());
        }
    }

    fallback
}

fn is_app_frame(frame: &str) -> bool {
    !(frame.contains(" android.")
        || frame.contains(" java.")
        || frame.contains(" kotlin.")
        || frame.contains(" androidx.")
        || frame.contains(" com.android."))
}

fn normalized_message(value: &str) -> String {
    let normalized = HEX_RE.replace_all(value, "<hex>");
    let normalized = NUMBER_RE.replace_all(&normalized, "<num>");
    WHITESPACE_RE
        .replace_all(&normalized.to_lowercase(), " ")
        .trim()
        .to_string()
}

fn detect_anchor(line: &LogLine) -> Option<FindingKind> {
    let message = line.message.as_str();

    if message.contains("FATAL EXCEPTION") {
        return Some(FindingKind::FatalException);
    }

    if message.contains("ANR in ") || message.contains("Application Not Responding") {
        return Some(FindingKind::Anr);
    }

    if message.contains("Fatal signal")
        || message.contains("SIGSEGV")
        || message.contains("SIGABRT")
    {
        return Some(FindingKind::NativeCrash);
    }

    if message.contains("Abort message:") {
        return Some(FindingKind::Abort);
    }

    if message.contains("OutOfMemoryError") {
        return Some(FindingKind::OutOfMemory);
    }

    if message.contains("JNI DETECTED ERROR IN APPLICATION") {
        return Some(FindingKind::JniError);
    }

    None
}

fn is_primary_anchor(line: &LogLine) -> bool {
    matches!(
        detect_anchor(line),
        Some(
            FindingKind::FatalException
                | FindingKind::Anr
                | FindingKind::NativeCrash
                | FindingKind::JniError
        )
    )
}

fn collect_evidence(lines: &[LogLine], anchor_index: usize) -> (usize, usize, Vec<EvidenceLine>) {
    let start = anchor_index;
    let mut end = anchor_index;
    let mut evidence = Vec::new();
    let anchor = &lines[anchor_index];
    let anchor_pid = anchor.pid;
    let mut trailing_non_matches = 0usize;

    for line in &lines[start..=anchor_index] {
        evidence.push(to_evidence(line));
    }

    for (offset, line) in lines.iter().enumerate().skip(anchor_index + 1).take(24) {
        if is_primary_anchor(line) {
            break;
        }

        if should_include_following_line(anchor, line, anchor_pid) {
            evidence.push(to_evidence(line));
            end = offset;
            trailing_non_matches = 0;
        } else {
            trailing_non_matches += 1;
            if trailing_non_matches >= 2 {
                break;
            }
        }
    }

    (lines[start].line_number, lines[end].line_number, evidence)
}

fn should_include_following_line(
    anchor: &LogLine,
    candidate: &LogLine,
    anchor_pid: Option<u32>,
) -> bool {
    if candidate.message.is_empty() {
        return false;
    }

    if anchor_pid.is_some() && anchor_pid == candidate.pid {
        return is_stack_or_context_line(&candidate.message) || candidate.tag == anchor.tag;
    }

    is_stack_or_context_line(&candidate.message)
}

fn is_stack_or_context_line(message: &str) -> bool {
    let trimmed = message.trim_start();

    trimmed.starts_with("Process:")
        || trimmed.starts_with("java.")
        || trimmed.starts_with("kotlin.")
        || trimmed.starts_with("android.")
        || trimmed.starts_with("Caused by:")
        || trimmed.starts_with("at ")
        || trimmed.starts_with("...")
        || trimmed.starts_with('#')
        || trimmed.starts_with("backtrace:")
        || trimmed.starts_with("Abort message:")
        || trimmed.starts_with("Reason:")
        || trimmed.starts_with("Cmd line:")
        || trimmed.starts_with("Build fingerprint:")
}

fn severity_for(kind: FindingKind) -> Severity {
    match kind {
        FindingKind::FatalException | FindingKind::NativeCrash | FindingKind::Abort => {
            Severity::Critical
        }
        FindingKind::Anr | FindingKind::OutOfMemory | FindingKind::JniError => Severity::High,
    }
}

fn title_for(kind: FindingKind, line: &LogLine) -> String {
    match kind {
        FindingKind::FatalException => format!("Fatal exception detected: {}", line.message),
        FindingKind::Anr => format!("ANR detected: {}", line.message),
        FindingKind::NativeCrash => format!("Native crash signal detected: {}", line.message),
        FindingKind::Abort => format!("Abort message detected: {}", line.message),
        FindingKind::OutOfMemory => format!("OutOfMemoryError detected: {}", line.message),
        FindingKind::JniError => format!("JNI application error detected: {}", line.message),
    }
}

fn rationale_for(kind: FindingKind, line: &LogLine) -> String {
    match kind {
        FindingKind::FatalException => format!(
            "The log contains an explicit Android fatal exception marker: `{}`.",
            line.message
        ),
        FindingKind::Anr => format!(
            "The log indicates the app stopped responding, which commonly precedes or explains user-visible failure: `{}`.",
            line.message
        ),
        FindingKind::NativeCrash => format!(
            "The log contains a native crash signal or fatal signal marker: `{}`.",
            line.message
        ),
        FindingKind::Abort => format!(
            "The log contains an abort message that usually accompanies a fatal native termination: `{}`.",
            line.message
        ),
        FindingKind::OutOfMemory => format!(
            "The log contains an OutOfMemoryError, which is a strong crash candidate: `{}`.",
            line.message
        ),
        FindingKind::JniError => format!(
            "The log contains a JNI runtime error marker that often terminates the process: `{}`.",
            line.message
        ),
    }
}

fn extract_thread(evidence: &[EvidenceLine]) -> Option<String> {
    evidence.iter().find_map(|line| {
        evidence_message(line)
            .strip_prefix("FATAL EXCEPTION: ")
            .map(|thread| thread.trim().to_string())
    })
}

fn extract_process(evidence: &[EvidenceLine]) -> Option<String> {
    evidence.iter().find_map(|line| {
        PROCESS_RE.captures(evidence_message(line)).map(|captures| {
            format!(
                "{} (PID {})",
                captures
                    .get(1)
                    .map(|value| value.as_str())
                    .unwrap_or_default(),
                captures
                    .get(2)
                    .map(|value| value.as_str())
                    .unwrap_or_default()
            )
        })
    })
}

fn extract_package(evidence: &[EvidenceLine]) -> Option<String> {
    evidence.iter().find_map(|line| {
        evidence_message(line)
            .strip_prefix("Process: ")
            .and_then(|message| message.split(',').next())
            .map(|value| value.trim().to_string())
    })
}

fn extract_exception(evidence: &[EvidenceLine]) -> Option<String> {
    evidence.iter().find_map(|line| {
        let message = evidence_message(line).trim();
        if message.starts_with("java.")
            || message.starts_with("kotlin.")
            || message.starts_with("android.")
            || message.starts_with("Caused by:")
        {
            Some(message.to_string())
        } else {
            None
        }
    })
}

fn extract_root_cause(
    evidence: &[EvidenceLine],
    anchor: &LogLine,
    exception: Option<String>,
) -> Option<String> {
    evidence
        .iter()
        .rev()
        .find_map(|line| {
            let message = evidence_message(line).trim();
            if message.starts_with("Caused by:") {
                Some(message.to_string())
            } else {
                None
            }
        })
        .or(exception)
        .or_else(|| Some(anchor.message.clone()))
}

fn to_evidence(line: &LogLine) -> EvidenceLine {
    EvidenceLine {
        line_number: line.line_number,
        message: line.raw.clone(),
    }
}

fn evidence_message(line: &EvidenceLine) -> &str {
    line.message
        .split_once(": ")
        .map(|(_, message)| message)
        .unwrap_or(line.message.as_str())
}

fn kind_token(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::FatalException => "fatal_exception",
        FindingKind::Anr => "anr",
        FindingKind::NativeCrash => "native_crash",
        FindingKind::Abort => "abort",
        FindingKind::OutOfMemory => "oom",
        FindingKind::JniError => "jni_error",
    }
}

#[cfg(test)]
mod tests {
    use crate::analyze_text;
    use crate::model::{FindingKind, Severity};

    #[test]
    fn detects_java_fatal_exception() {
        let input = r#"03-18 10:15:09.123  2456  2456 E AndroidRuntime: FATAL EXCEPTION: main
03-18 10:15:09.124  2456  2456 E AndroidRuntime: Process: com.example.demo, PID: 2456
03-18 10:15:09.125  2456  2456 E AndroidRuntime: java.lang.IllegalStateException: boom
03-18 10:15:09.126  2456  2456 E AndroidRuntime:     at com.example.demo.MainActivity.onCreate(MainActivity.kt:42)"#;
        let report = analyze_text(input);

        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.kind, FindingKind::FatalException);
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.thread.as_deref(), Some("main"));
        assert_eq!(finding.package.as_deref(), Some("com.example.demo"));
        assert_eq!(finding.occurrence_count, 1);
        assert!(!finding.signature.is_empty());
        assert!(
            finding
                .root_cause
                .as_deref()
                .unwrap_or_default()
                .contains("IllegalStateException")
        );
    }

    #[test]
    fn deduplicates_repeated_exception_signatures() {
        let input = r#"03-18 10:15:09.123  2456  2456 E AndroidRuntime: FATAL EXCEPTION: main
03-18 10:15:09.124  2456  2456 E AndroidRuntime: Process: com.example.demo, PID: 2456
03-18 10:15:09.125  2456  2456 E AndroidRuntime: java.lang.IllegalStateException: boom 123
03-18 10:15:09.126  2456  2456 E AndroidRuntime:     at com.example.demo.MainActivity.onCreate(MainActivity.kt:42)
03-18 10:15:10.123  3456  3456 E AndroidRuntime: FATAL EXCEPTION: main
03-18 10:15:10.124  3456  3456 E AndroidRuntime: Process: com.example.demo, PID: 3456
03-18 10:15:10.125  3456  3456 E AndroidRuntime: java.lang.IllegalStateException: boom 999
03-18 10:15:10.126  3456  3456 E AndroidRuntime:     at com.example.demo.MainActivity.onCreate(MainActivity.kt:108)"#;
        let report = analyze_text(input);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].occurrence_count, 2);
    }

    #[test]
    fn keeps_distinct_root_causes_separate() {
        let input = r#"03-18 10:15:09.123  2456  2456 E AndroidRuntime: FATAL EXCEPTION: main
03-18 10:15:09.124  2456  2456 E AndroidRuntime: Process: com.example.demo, PID: 2456
03-18 10:15:09.125  2456  2456 E AndroidRuntime: java.lang.IllegalStateException: boom
03-18 10:15:09.126  2456  2456 E AndroidRuntime:     at com.example.demo.MainActivity.onCreate(MainActivity.kt:42)
03-18 10:16:09.123  2456  2456 E AndroidRuntime: FATAL EXCEPTION: main
03-18 10:16:09.124  2456  2456 E AndroidRuntime: Process: com.example.demo, PID: 2456
03-18 10:16:09.125  2456  2456 E AndroidRuntime: java.lang.NullPointerException: missing view
03-18 10:16:09.126  2456  2456 E AndroidRuntime:     at com.example.demo.DetailsActivity.bind(DetailsActivity.kt:84)"#;
        let report = analyze_text(input);

        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn detects_native_crash_signal() {
        let input = r#"03-18 11:20:11.001  3333  3333 F libc    : Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0
03-18 11:20:11.002  3333  3333 F DEBUG   : Abort message: 'terminating due to signal 11'
03-18 11:20:11.003  3333  3333 F DEBUG   : backtrace:
03-18 11:20:11.004  3333  3333 F DEBUG   :       #00 pc 0000000000012345  /apex/libfoo.so"#;
        let report = analyze_text(input);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, FindingKind::NativeCrash);
        assert_eq!(report.findings[0].severity, Severity::Critical);
        assert!(report.findings[0].evidence.len() >= 3);
    }

    #[test]
    fn does_not_flag_plain_noise() {
        let input = r#"03-18 11:20:11.001  3333  3333 I ActivityManager: Start proc 1234:com.example.demo/u0a321 for activity
03-18 11:20:11.002  3333  3333 D DemoTag: just a normal debug line"#;
        let report = analyze_text(input);

        assert!(report.findings.is_empty());
    }
}
