# JSON Reporting

Intruder Hunter uses a shared JSON shape for Go CLI commands and normalized scan reports. The schema is available today for `version`, `doctor`, and `scan`; `scan` runs registered Go-native checks for the current platform, can write an additional report JSON file, and writes a private snapshot by default unless disabled.

## What works today

```bash
go run ./cmd/intruder-hunter version --output json
go run ./cmd/intruder-hunter doctor --output json
go run ./cmd/intruder-hunter scan --output json
go run ./cmd/intruder-hunter scan --report-json scan-report.json
go run ./cmd/intruder-hunter scan --no-snapshot
```

The global output flag is `--output` or `-o` and accepts only:

- `text` (default)
- `json`

Unsupported formats return a stable `IH_UNSUPPORTED_OUTPUT_FORMAT` error.

Platform status for `scan` is intentionally scoped: Linux retained-script diagnostic signal coverage is implemented in native Go; macOS and Windows scan orchestration exists, but retained-script parity is still migrating. The retained Bash/PowerShell scripts remain available directly and through the guarded `legacy` bridge when you need original script behavior or platform coverage that has not migrated yet.

## CLI envelope

Go CLI commands render an envelope like this:

```json
{
  "schema_version": "1.0",
  "tool": "intruder-hunter",
  "platform": "linux",
  "started_at": "2026-05-27T12:00:00Z",
  "completed_at": "2026-05-27T12:00:01Z",
  "summary": {
    "critical_count": 0,
    "warning_count": 1,
    "ok_count": 4,
    "info_count": 2
  },
  "findings": [],
  "error": null
}
```

Top-level fields:

| Field | Description |
|-------|-------------|
| `schema_version` | JSON contract version. Current value is `1.0`. |
| `tool` | Always `intruder-hunter`. |
| `platform` | Normalized platform such as `linux`, `macos`, or `windows`. Go converts `darwin` to `macos`. |
| `started_at` / `completed_at` | UTC timestamps for the command run. |
| `summary` | Counts findings by severity. |
| `findings` | Ordered list of structured results. Empty for commands without findings. |
| `error` | Present when a command renders a structured error. It is normally `null` for successful `scan` runs. |

## Severity levels

The Go report model uses the same small set of severities for native checks:

| Severity | Meaning |
|----------|---------|
| `critical` | Strong indicator of compromise or high-risk state that needs prompt review. |
| `warning` | Missing prerequisite, suspicious condition, weak setting, or context-dependent risk. |
| `ok` | Check completed and did not find an issue for that item. |
| `info` | Context or optional hint, not a problem by itself. |

Do not treat `ok` or `info` as proof that a host is clean. `doctor` checks prerequisites only; `scan` runs diagnostics, but it is still a local checklist rather than a full incident-response investigation.

## Finding shape

A finding has this structure:

```json
{
  "id": "linux.doctor.admin_capability",
  "platform": "linux",
  "module": "doctor",
  "check": "admin_capability",
  "severity": "warning",
  "title": "Admin/root capability is not available",
  "finding": "Some diagnostics may be incomplete without elevated privileges.",
  "evidence": ["effective user id is 1000"],
  "remediation": "Re-run with sudo, as root, or from an Administrator PowerShell when performing full diagnostics.",
  "references": [],
  "metadata": {
    "status": "missing"
  }
}
```

Required fields in Go report types:

| Field | Description |
|-------|-------------|
| `id` | Stable lowercase identifier, usually `<platform>.<module>.<check>`. |
| `platform` | Platform that produced the finding. |
| `module` | Current module name, for example `doctor`, `version`, `processes`, or `network`. |
| `check` | Specific check name inside the module. |
| `severity` | One of `critical`, `warning`, `ok`, or `info`. |
| `title` | Short human-readable label. |
| `finding` | Plain-language result. |
| `remediation` | Action to take. Empty when no action is needed. |

Optional fields:

| Field | Description |
|-------|-------------|
| `evidence` | Sanitized command output, path, username, port, or setting that supports the finding. |
| `references` | Documentation URLs or internal notes. |
| `metadata` | Extra structured values such as status, tool names, package counts, or OS details. |

## Error shape

When a command fails after choosing JSON output, the envelope can include an `error` object:

```json
{
  "code": "IH_UNSUPPORTED_OUTPUT_FORMAT",
  "message": "unsupported output format \"yaml\"",
  "details": "supported formats: text, json"
}
```

Known stable error codes include:

| Code | Meaning |
|------|---------|
| `IH_COMMAND_FAILED` | Generic wrapper for an unexpected command failure. |
| `IH_UNSUPPORTED_OUTPUT_FORMAT` | The requested output format was not `text` or `json`. |
| `IH_SCAN_NOT_IMPLEMENTED` | Historical/reserved code from the earlier scan stub. Current `scan` runs registered checks and should not normally emit this. |
| `IH_DOCTOR_STUB` | Reserved from earlier doctor scaffolding; current doctor is implemented and should not normally emit it. |

## Implemented command notes

### `version --output json`

`version` returns one `info` finding with version, commit, Go OS, and Go architecture metadata.

```bash
go run ./cmd/intruder-hunter version --output json
```

### `doctor --output json`

`doctor` is read-only and reports local prerequisites. It checks:

- detected platform
- root/admin capability
- Go runtime and whether the `go` tool is on `PATH`
- Linux shell/process/network/package/firewall tool hints
- macOS process, persistence, trust, FileVault, and firewall tool availability
- Windows PowerShell, `netsh`, `schtasks`, and Defender cmdlet availability when possible

Missing required tools are warnings. Missing optional Linux package/firewall hints are informational.

```bash
go run ./cmd/intruder-hunter doctor --output json > doctor-report.json
```

### `scan --output json`

`scan` runs the registered Go-native checks for the detected platform and writes the same envelope to stdout when `--output json` is selected:

```bash
go run ./cmd/intruder-hunter scan --output json > scan-envelope.json
```

Use `--timeout` to bound scan runtime:

```bash
go run ./cmd/intruder-hunter scan --output json --timeout 2m
```

Linux retained-script diagnostic signals are covered by native Go checks. macOS and Windows scan parity is still migrating, so use the retained platform scripts or `legacy` bridge for original script behavior on those platforms.

## Report JSON files

`--output json` controls stdout. `--report-json PATH` writes the normalized scan report body to a separate file, independent of the stdout format:

```bash
go run ./cmd/intruder-hunter scan --report-json scan-report.json
go run ./cmd/intruder-hunter scan --output json --report-json scan-report.json
```

The report JSON uses the normalized report model from `internal/report` and contains the same schema version, tool name, platform, timestamps, summary counts, and findings that are rendered in the CLI envelope. If writing the report path fails, `scan` returns an error after assembling the report.

## Snapshot storage layout

The Go `scan` command writes a private snapshot by default. The layout under the current working directory is:

```text
.intruder-hunter/runs/<utc-timestamp>/metadata.json
.intruder-hunter/runs/<utc-timestamp>/report.json
.intruder-hunter/runs/<utc-timestamp>/raw/...
.intruder-hunter/latest/report.json
```

Use `--no-snapshot` to skip these files:

```bash
go run ./cmd/intruder-hunter scan --no-snapshot
```

Behavior of the snapshot writer:

- directories are created with private `0700` permissions
- report and metadata files are written with private `0600` permissions
- writes use temporary files and rename for safer updates
- same-second run IDs receive deterministic suffixes such as `2026-05-27T12-00-00Z-1`
- optional raw artifacts must use safe relative paths
- `.intruder-hunter/` is ignored by git

## Relationship to legacy logs

Legacy scripts still write or display their existing outputs:

| Platform | Current behavior |
|----------|------------------|
| Linux | Console output plus `/var/log/intruder-hunter.log` |
| macOS | Console output plus `/var/log/intruder-hunter-macos.log` |
| Windows | Console output from PowerShell |

Those logs are useful for users today, but they are not machine-readable JSON and are not normalized across platforms.

## Migration status

1. Keep `version`, `doctor`, `scan`, and error envelopes stable.
2. Continue registering Go-native checks by platform using the `internal/check` contract.
3. Maintain `scan --output json`, `--report-json PATH`, default snapshots, and `--no-snapshot` as the public scan reporting surface.
4. Complete retained-script parity migration for macOS and Windows while preserving Linux retained diagnostic signal coverage.
5. Preserve the legacy script bridge until Go-native scans cover the same practical checks across platforms.
6. Avoid over-severity: weak strings such as `miner`, `xmr`, a single port number, or a third-party LaunchAgent filename should not become high-confidence findings without context.

## Compatibility guidance

- Keep `schema_version` stable unless field meanings change.
- Add optional fields instead of renaming existing fields.
- Evidence must avoid secrets: redact private keys, tokens, cookies, and unnecessary personal data.
- Prefer stable IDs and deterministic ordering so users can diff reports.
- Clearly separate compromise indicators from configuration exposure and hygiene recommendations.
