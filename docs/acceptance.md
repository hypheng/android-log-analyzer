# Acceptance

## Acceptance Dimensions

- input handling from file and `stdin`
- detection of Java, native, ANR, OOM, and JNI-related crash signals
- smart deduplication of repeated incidents without losing root-cause distinctions
- stable and explainable text and JSON reports
- resilience against malformed or noisy logs

## Phase Gates

### Phase 0

- repository workflow, CI, templates, and role documentation exist

### Phase 1

- log parsing extracts structured fields from common `logcat` lines

### Phase 2

- crash-related findings are identified with supporting evidence

### Phase 3

- repeated incidents collapse into aggregated findings with counts

### Phase 4

- end-to-end fixtures, CLI usability, and README usage are complete

## Failure Policy

If an acceptance scenario fails, create a `bug` issue with the failing input, expected behavior, actual behavior, and the requirement or PR that introduced the gap.
