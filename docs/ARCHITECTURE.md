# Architecture

## Overview

`dotnet-secrets-scan` is a **class library** (`DotnetSecretsScan`, net10.0) for detecting leaked secrets in .NET solutions: source files, appsettings, config files and connection strings. There is no CLI entry point yet - the `System.CommandLine` package is referenced but unused; consumers call the library API directly (see the smoke-test style usage at the bottom).

Detection combines two mechanisms:

1. **Regex rules** (`SecretRule`) - curated patterns for known secret formats (AWS keys, GitHub/Slack/Stripe tokens, connection strings, PEM keys, ...).
2. **Entropy analysis** (`EntropyDetector`) - Shannon-entropy heuristic over string literals to catch secrets no rule knows about.

## Component breakdown

| Component | File | Responsibility |
|---|---|---|
| `SolutionScanner` | `src/SolutionScanner.cs` | Orchestrates a scan: walks files, applies rules + entropy detection per file, filters ignored lines, returns a `ScanResult`. |
| `FileWalker` | `src/FileWalker.cs` | Recursive file enumeration. Excludes `bin`, `obj`, `node_modules`, `.git` (plus caller-supplied patterns); only yields `.cs .json .config .xml .yml .yaml .env`. Skips inaccessible entries and reparse points. |
| `SecretRule` / `SecretSeverity` | `src/BuiltInRules.cs` | Immutable rule definition: id, name, regex pattern, description, severity (Low/Medium/High). Constructor-initialized; no setters. |
| `BuiltInRules` | `src/BuiltInRules.cs` | 18 rules `SS001`-`SS018` for common token formats. |
| `CloudProviderRules` | `src/CloudProviderRules.cs` | 8 additional cloud-focused rules (Azure storage/SAS, GCP service accounts, Stripe, SendGrid, Slack, PEM). Not merged with `BuiltInRules` - the caller chooses which rule sets to pass to `SolutionScanner`. Some patterns overlap with `BuiltInRules` (Stripe live key, Slack, PEM), so passing both sets can double-report a secret under two rule ids. |
| `EntropyDetector` | `src/EntropyDetector.cs` | Extracts quoted string literals from each line, computes Shannon entropy, reports literals >= 20 chars with entropy >= 4.5 bits as `Rule = "EntropyDetector"`, severity High. |
| `IgnoreCommentParser` | `src/IgnoreCommentParser.cs` | Suppression mechanism: `// secrets-scan:ignore`, `# secrets-scan:ignore`, or `<!-- secrets-scan:ignore -->` on the flagged line or the line above removes the finding. Applied by `SolutionScanner` per file. |
| `SecretFinding` | `src/BaselineFile.cs` | A single detection: file path, 1-based line number, rule id, raw secret, severity string. Value equality plus SHA-256 fingerprint over `FilePath|LineNumber|Rule|Secret`. |
| `BaselineFile` | `src/BaselineFile.cs` | Accepted-findings store persisted as JSON. Deduplicates by fingerprint; `FilterNew` returns only findings not in the baseline - the mechanism for "fail CI only on new secrets". |
| `ScanResult` / `ReportWriter` | `src/ReportWriter.cs` | Scan summary (findings, file/line counts, timestamp) and writers: colored console output, JSON, SARIF 2.1.0 for CI annotation. |
| `HtmlReportWriter` | `src/HtmlReportWriter.cs` | Standalone HTML report with per-rule summary; masks secrets to first 4 chars + asterisks. |
| Extensions | `src/SecretRuleExtensions.cs`, `src/SecretFindingExtensions.cs` | Convenience helpers: severity predicates, `WithSeverity`/`WithSecret`/`WithRedactedSecret` copies, fingerprint grouping, test-file detection, display formatting. |
| JSON extensions | `src/*JsonExtensions.cs` | camelCase System.Text.Json serialization helpers for `SecretRule`, `SecretFinding`, `IgnoreCommentSettings`. |
| Validation | `src/SecretRuleValidation.cs`, `src/SecretFindingValidation.cs` | Static validators for rule/finding well-formedness. |

## Data flow

```
rootPath
   │
   ▼
FileWalker.EnumerateFiles ── excludes bin/obj/node_modules/.git, filters by extension
   │  (one file at a time)
   ▼
SolutionScanner.ProcessFile
   ├─ File.ReadAllText / ReadAllLines (whole file in memory)
   ├─ per SecretRule: Regex over full file content ─► SecretFinding (line number
   │     recovered by walking line lengths against match index)
   ├─ EntropyDetector.Scan over lines ─► SecretFinding
   └─ IgnoreCommentParser.Filter ─► drops findings marked secrets-scan:ignore
   │
   ▼
ScanResult { Findings, TotalFilesScanned, TotalLinesScanned, Timestamp }
   │
   ├─ BaselineFile.FilterNew(findings)      (optional: only new secrets)
   ├─ ReportWriter.WriteConsole / ToJson / ToSarif
   └─ HtmlReportWriter.Generate / WriteToFile
```

## Key design decisions

- **Rules are data, not code.** A rule is just `(id, name, regex, description, severity)`. Adding detection for a new token type means adding one `SecretRule` - no scanner changes. Trade-off: no per-rule custom validation logic (e.g. checksum verification of AWS keys), so false positives are handled downstream via ignore comments and baselines.
- **Regex over full file content, entropy over lines.** Rules can match multi-line constructs (connection strings, PEM headers); the line number is reconstructed from the match offset. Entropy detection is inherently per-string-literal, so it works line by line.
- **Raw secret stored in the finding.** `SecretFinding.Secret` holds the actual matched value. This makes fingerprinting and baselines exact, but means JSON/SARIF reports contain the secret in cleartext (SARIF even includes it in `properties.secretValue`). Only the HTML writer masks. Treat report files as sensitive.
- **Fingerprint includes line number.** Fingerprint = SHA-256 of `FilePath|LineNumber|Rule|Secret`. Precise, but a baseline entry breaks when unrelated edits shift the secret to a different line - the finding reappears as "new".
- **Fail-open error handling.** Unreadable files are skipped (scan continues); if the ignore-comment filter cannot read a file it keeps the finding (fail toward reporting, never toward silently dropping a secret).
- **Sequential, synchronous scanning.** One file at a time, whole file in memory. Simple and deterministic; large repos pay in wall-clock time and large single files in memory.

## Extension points

- **Custom rules:** pass any `IEnumerable<SecretRule>` to `new SolutionScanner(rules)` - built-in sets are just defaults you can combine or replace.
- **Custom exclusions:** `new FileWalker(excludeGlobs)` accepts extra directory names/relative paths to skip (exact segment/path match, despite the parameter name - not full glob syntax).
- **Entropy tuning:** `EntropyDetector.Scan(path, lines, threshold, minLength)` exposes both knobs (defaults 4.5 / 20).
- **Output formats:** `ScanResult` is a plain object; new writers only need to consume `IReadOnlyList<SecretFinding>`.

## Known limitations

- **No CLI.** Library only; `System.CommandLine` is referenced in the csproj but nothing uses it yet.
- **Entropy detector suppresses most real secrets.** `IsBase64Like` filters out any literal where >85% of characters are alphanumeric/base64 - which describes almost every actual token. In practice the entropy path mostly catches secrets containing symbols/punctuation; format-based rules do the heavy lifting.
- **`FileWalker` extension list is fixed.** `.env` variants like `.env.local` (extension `.local`) are not scanned; neither are `.txt`, `.ps1`, `.sh`, etc.
- **Line-oriented entropy extraction** misses multi-line raw string literals and verbatim strings spanning lines.
- **`SolutionScanner` uses the default `FileWalker`** - custom exclude patterns can't currently be passed through `Scan()`.
- **Duplicate reporting** when both `BuiltInRules.All` and `CloudProviderRules.All` are supplied (overlapping Stripe/Slack/PEM patterns).
- Rule regexes are recompiled per file (`new Regex(..., RegexOptions.Compiled)` inside the match loop) - correctness is unaffected, but it wastes the compilation cost.

## Minimal usage

```csharp
using DotnetSecretsScan;

var scanner = new SolutionScanner(BuiltInRules.All);
ScanResult result = scanner.Scan("/path/to/solution");

var baseline = BaselineFile.Load(".secrets-baseline.json");
var newFindings = baseline.FilterNew(result.Findings);

ReportWriter.WriteConsole(result, verbose: true);
File.WriteAllText("scan.sarif", ReportWriter.ToSarif(result));
```
