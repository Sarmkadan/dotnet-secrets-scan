# CLAUDE.md

.NET 10 console tool (`DotnetSecretsScan`) that scans a .NET solution for leaked secrets in source, appsettings, config files and connection strings using regex rules plus Shannon-entropy detection.

## Build

```bash
dotnet build                # single project, no .sln; root csproj is dotnet-secrets-scan.csproj
dotnet run -- <path> [-f console|json|csv|sarif|junit] [-o out] [--baseline file] [--prune-baseline] [--verify] [-v]
```

Exit codes (`src/ExitCodes.cs`): 0 clean, 1 findings, 2 scan error.

## Tests

None exist. No test project, no CI. Verify changes by `dotnet build` and running the CLI against a sample directory.

## Lint / format

No `.editorconfig`, no analyzers. `Nullable` and `ImplicitUsings` enabled, `GenerateDocumentationFile` true - all public members need XML doc comments or the build warns.

## Layout

- `src/Program.cs` - entry point; `System.CommandLine` root command, `RunScan` orchestration.
- `src/SolutionScanner.cs` - scan orchestration: `FileWalker` -> rules + `EntropyDetector` -> `IgnoreCommentParser` filter -> `ScanResult`.
- `src/FileWalker.cs` - file enumeration; fixed extension list, excludes `bin/obj/node_modules/.git`.
- `src/BuiltInRules.cs` - `SecretRule`, `SecretSeverity`, 18 rules `SS001`-`SS018`.
- `src/CloudProviderRules.cs` - 8 cloud rules; overlaps BuiltInRules on Stripe/Slack/PEM.
- `src/EntropyDetector.cs` - entropy heuristic (default threshold 4.5 bits, min length 20).
- `src/BaselineFile.cs` - `SecretFinding` + JSON baseline (SHA-256 fingerprint of `FilePath|LineNumber|Rule|Secret`).
- `src/*ReportWriter.cs` - `IReportWriter` implementations: Console, Csv, Sarif, JUnit, Html.
- `src/Verification/SecretVerifier.cs` - opt-in live credential checks (`--verify`) for AWS/GitHub/Slack.
- `src/*Extensions.cs`, `src/*JsonExtensions.cs` - helper/serialization extensions on core types.
- `docs/ARCHITECTURE.md` - data flow, design decisions, known limitations; `docs/*.md` - per-type API notes.
- `Severity.cs` in repo root is a stray enum outside `src/` (duplicates `SecretSeverity`); root also contains junk files with sentence-like names from an aider session - do not treat them as source.

## Conventions

- Single namespace `DotnetSecretsScan` (`DotnetSecretsScan.Verification` for verifier), file-scoped namespaces, one type per file named after the type.
- Rule ids `SSnnn`; rules are immutable, constructor-initialized.
- Ignore suppression: `secrets-scan:ignore` comment on the flagged line or the line above.
- Fail-open: unreadable files are skipped; if ignore-filtering fails the finding is kept.
- Findings hold the raw secret; only the HTML writer masks it - treat reports as sensitive.
- Commit messages: conventional prefixes (`docs:`, `chore:`, `feat:`, `fix:`).
