# Workflow

## Roles

### Architect

- owns requirement analysis and phase breakdown
- creates or refines `requirement` issues
- maintains the architecture and engineering workflow
- reviews developer PRs and records architectural concerns

### Developer

- picks the next unfinished `requirement` or `bug` issue in priority order
- implements the change with tests
- opens a PR that links the issue and describes testing

### Acceptance

- defines acceptance scenarios for each requirement
- validates delivered issues after PR review and merge readiness
- creates `bug` issues for failed scenarios and links them back to the source requirement

## Delivery Loop

1. Architect creates or updates prioritized issues.
2. Developer selects the next unfinished issue and opens a branch and PR.
3. Architect reviews the PR and leaves comments or approval feedback.
4. Acceptance validates against documented scenarios.
5. If acceptance fails, a `bug` issue is created and prioritized ahead of later requirements.
6. If acceptance passes, the requirement issue is closed and the next issue starts.

## GitHub Observability Rules

- Every delivery branch must link to a GitHub issue.
- Every PR must include testing evidence.
- Acceptance results must be recorded in GitHub comments or linked issues.
- `main` should accept merges only after CI succeeds.
