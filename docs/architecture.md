# Architecture

## MVP Scope

The first shippable version is a Rust CLI that ingests Android log text from a file or `stdin`, detects likely crash-related signals, groups supporting evidence, and emits a concise report with smart deduplication.

## Planned Module Layout

- `src/main.rs`: CLI entrypoint
- `src/lib.rs`: public API surface
- `src/cli.rs`: argument parsing and input selection
- `src/model.rs`: domain model for parsed lines, evidence, and findings
- `src/parser/`: log line parsing and signal extraction
- `src/analyzer/`: grouping, scoring, deduplication, and ranking
- `src/report/`: text and JSON report rendering
- `tests/fixtures/`: representative Android log samples

## Engineering Rules

- parsing and rules must degrade safely on malformed input
- every detection rule must have fixture-backed tests
- deduplication must be conservative and explainable
- report fields must remain stable once introduced
