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

## Phase 4 Scenario Matrix

- `java_fatal_exception.log`: Java/Kotlin crash is detected and explained
- `native_sigsegv.log`: native crash is detected and explained
- `anr_trace.log`: ANR is detected
- `oom_exception.log`: OOM is detected
- `jni_error.log`: JNI runtime failure is detected
- `repeated_fatal_exception.log`: duplicate crash chains collapse into one finding with count
- `distinct_fatal_exceptions.log`: distinct root causes remain separate
- `noise_only.log`: no crash finding is emitted
- `malformed_fragment.log`: parse warnings are recorded without analyzer failure

## CLI Acceptance

- `--help` documents `LOG_FILE`, `--format`, and `--output`
- file input and `stdin` input both work
- `--output` writes the rendered report to disk
- README includes at least one file example and one `stdin` example

## Failure Policy

If an acceptance scenario fails, create a `bug` issue with the failing input, expected behavior, actual behavior, and the requirement or PR that introduced the gap.
