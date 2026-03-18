# android-log-analyzer

Rust CLI for analyzing Android logs and surfacing likely crash causes with smart deduplication.

This repository is developed through an observable GitHub workflow driven by three roles:

- Architect: requirement analysis, issue breakdown, architecture, engineering workflow, PR review
- Developer: pick unfinished `requirement` and `bug` issues in order, implement, test, and open PRs
- Acceptance: define acceptance scenarios, validate delivered issues, and create `bug` issues for failures

The first functional milestone is an MVP that:

- ingests Android `logcat` text from files or `stdin`
- detects likely crash-related signals
- groups evidence into findings
- intelligently deduplicates repeated signals
- emits human-readable text and JSON reports

## Supported Signals

- `FATAL EXCEPTION`
- `ANR in ...`
- native fatal signals such as `SIGSEGV` and `SIGABRT`
- `Abort message:`
- `OutOfMemoryError`
- `JNI DETECTED ERROR IN APPLICATION`

## Usage

Build locally:

```bash
cargo build
```

Analyze a saved `logcat` file:

```bash
cargo run -- tests/fixtures/java_fatal_exception.log
```

Emit JSON instead of text:

```bash
cargo run -- --format json tests/fixtures/repeated_fatal_exception.log
```

Pipe `adb logcat` directly through `stdin` and write the report to a file:

```bash
adb logcat -d | cargo run -- --format json --output report.json
```

Install the CLI into your cargo bin directory:

```bash
cargo install --path .
```

## Workflow

- Architect drives issue breakdown, architecture, and PR review
- Developer picks the next unfinished `requirement` or `bug` issue and ships it with tests
- Acceptance validates delivered requirements and opens `bug` issues for failures

See [workflow.md](docs/workflow.md), [architecture.md](docs/architecture.md), and [acceptance.md](docs/acceptance.md).
