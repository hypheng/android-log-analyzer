use once_cell::sync::Lazy;
use regex::Regex;

use crate::model::{LogLevel, LogLine, ParseWarning};

static LOGCAT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^(?P<timestamp>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3,6})\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEAF])\s+(?P<tag>[^:]+):\s?(?P<message>.*)$",
    )
    .expect("valid logcat pattern")
});

pub struct ParsedLog {
    pub lines: Vec<LogLine>,
    pub warnings: Vec<ParseWarning>,
}

pub fn parse_lines(input: &str) -> ParsedLog {
    let mut lines = Vec::new();
    let mut warnings = Vec::new();

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let raw = raw_line.to_string();

        if raw.trim().is_empty() {
            lines.push(LogLine {
                line_number,
                timestamp: None,
                pid: None,
                tid: None,
                level: None,
                tag: None,
                message: String::new(),
                raw,
                structured: false,
            });
            continue;
        }

        if let Some(captures) = LOGCAT_PATTERN.captures(raw_line) {
            lines.push(LogLine {
                line_number,
                timestamp: captures
                    .name("timestamp")
                    .map(|value| value.as_str().to_string()),
                pid: captures
                    .name("pid")
                    .and_then(|value| value.as_str().parse::<u32>().ok()),
                tid: captures
                    .name("tid")
                    .and_then(|value| value.as_str().parse::<u32>().ok()),
                level: captures
                    .name("level")
                    .and_then(|value| parse_level(value.as_str())),
                tag: captures
                    .name("tag")
                    .map(|value| value.as_str().trim().to_string()),
                message: captures
                    .name("message")
                    .map(|value| value.as_str().trim_end().to_string())
                    .unwrap_or_default(),
                raw,
                structured: true,
            });
            continue;
        }

        warnings.push(ParseWarning {
            line_number,
            raw: raw.clone(),
            reason: "unstructured log line".to_string(),
        });
        lines.push(LogLine {
            line_number,
            timestamp: None,
            pid: None,
            tid: None,
            level: None,
            tag: None,
            message: raw.clone(),
            raw,
            structured: false,
        });
    }

    ParsedLog { lines, warnings }
}

fn parse_level(value: &str) -> Option<LogLevel> {
    match value {
        "V" => Some(LogLevel::Verbose),
        "D" => Some(LogLevel::Debug),
        "I" => Some(LogLevel::Info),
        "W" => Some(LogLevel::Warn),
        "E" => Some(LogLevel::Error),
        "F" | "A" => Some(LogLevel::Fatal),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_lines;
    use crate::model::LogLevel;

    #[test]
    fn parses_structured_logcat_line() {
        let parsed =
            parse_lines("03-18 10:15:09.123  2456  2456 E AndroidRuntime: FATAL EXCEPTION: main");
        let line = &parsed.lines[0];

        assert_eq!(line.line_number, 1);
        assert_eq!(line.timestamp.as_deref(), Some("03-18 10:15:09.123"));
        assert_eq!(line.pid, Some(2456));
        assert_eq!(line.tid, Some(2456));
        assert_eq!(line.level, Some(LogLevel::Error));
        assert_eq!(line.tag.as_deref(), Some("AndroidRuntime"));
        assert_eq!(line.message, "FATAL EXCEPTION: main");
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn keeps_unstructured_lines_and_records_warning() {
        let parsed = parse_lines("java.lang.RuntimeException: boom");

        assert_eq!(parsed.lines[0].message, "java.lang.RuntimeException: boom");
        assert!(!parsed.lines[0].structured);
        assert_eq!(parsed.warnings.len(), 1);
        assert_eq!(parsed.warnings[0].line_number, 1);
    }
}
