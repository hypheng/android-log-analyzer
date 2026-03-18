use regex::Regex;

use crate::model::{AnalysisReport, EvidenceLine, Finding, FindingKind, LogLine, Severity};
use crate::parser::ParsedLog;

pub fn analyze(parsed: ParsedLog) -> AnalysisReport {
    let lines = parsed.lines;
    let mut findings = Vec::new();
    let mut last_consumed_line = 0usize;

    for (index, line) in lines.iter().enumerate() {
        if line.line_number <= last_consumed_line {
            continue;
        }

        if let Some(kind) = detect_anchor(line) {
            let (line_start, line_end, evidence) = collect_evidence(&lines, index);
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
                exception: extract_exception(&evidence),
                evidence,
            };
            last_consumed_line = finding.line_end;
            findings.push(finding);
        }
    }

    AnalysisReport {
        findings,
        parse_warnings: parsed.warnings,
    }
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

fn collect_evidence(lines: &[LogLine], anchor_index: usize) -> (usize, usize, Vec<EvidenceLine>) {
    let start = anchor_index.saturating_sub(2);
    let mut end = anchor_index;
    let mut evidence = Vec::new();
    let anchor = &lines[anchor_index];
    let anchor_pid = anchor.pid;
    let mut trailing_non_matches = 0usize;

    for line in &lines[start..=anchor_index] {
        evidence.push(to_evidence(line));
    }

    for (offset, line) in lines.iter().enumerate().skip(anchor_index + 1).take(24) {
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
    static PROCESS_RE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r"Process:\s+([^,]+),\s+PID:\s+(\d+)").expect("valid process regex")
    });

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
        assert!(
            finding
                .exception
                .as_deref()
                .unwrap_or_default()
                .contains("IllegalStateException")
        );
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
