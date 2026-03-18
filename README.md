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

## Workflow

- Architect drives issue breakdown, architecture, and PR review
- Developer picks the next unfinished `requirement` or `bug` issue and ships it with tests
- Acceptance validates delivered requirements and opens `bug` issues for failures

See [workflow.md](docs/workflow.md), [architecture.md](docs/architecture.md), and [acceptance.md](docs/acceptance.md).
