use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    path.display().to_string()
}

#[test]
fn help_lists_input_and_output_options() {
    let output = Command::new(env!("CARGO_BIN_EXE_android-log-analyzer"))
        .arg("--help")
        .output()
        .expect("help to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--output"));
}

#[test]
fn supports_file_input_with_json_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_android-log-analyzer"))
        .arg("--format")
        .arg("json")
        .arg(fixture("java_fatal_exception.log"))
        .output()
        .expect("binary to run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"kind\": \"FatalException\""));
}

#[test]
fn supports_stdin_and_output_file() {
    let output_path = std::env::temp_dir().join(format!(
        "android-log-analyzer-cli-{}.txt",
        std::process::id()
    ));
    let input = fs::read_to_string(fixture("repeated_fatal_exception.log")).expect("fixture");

    let mut child = Command::new(env!("CARGO_BIN_EXE_android-log-analyzer"))
        .arg("--output")
        .arg(&output_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("binary to spawn");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("stdin write");

    let status = child.wait().expect("status");
    assert!(status.success());

    let rendered = fs::read_to_string(&output_path).expect("rendered output");
    assert!(rendered.contains("Occurrences: 2"));

    let _ = fs::remove_file(output_path);
}
