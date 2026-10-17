# dotnet-secrets-scan

Scans a .NET solution for leaked secrets in appsettings, code and connection strings.

## Getting Started

### Install as a global tool

Requires the .NET 10 SDK. From the repository root, pack the tool and install it globally:

```bash
dotnet pack -c Release -o ./nupkg
dotnet tool install -g --add-source ./nupkg DotnetSecretsScan
```

The installed command is `dotnet-secrets-scan`. Run `dotnet-secrets-scan --help` to see all options.

### Scan the current directory

```bash
cd /path/to/your/solution
dotnet-secrets-scan .
```

Exit codes: `0` clean, `1` findings, `2` scan error.

### Scan with SARIF output

```bash
dotnet-secrets-scan . --format sarif --output secrets.sarif
```

Short forms work too: `dotnet-secrets-scan . -f sarif -o secrets.sarif`. Findings contain the raw secret value, so treat the output file as sensitive and do not commit it.

Expected console output for the default format:

```text
Scan completed: 2 files, 7 lines, 4 findings
Timestamp: 2026-10-17 15:13:18 +00:00

High: 4 findings

Summary: 2 files, 7 lines scanned, 4 findings (High: 4)
```

Add `-v` (`--verbose`) to list each finding with its file, line, rule and secret, plus diagnostic output on stderr.

### Tuning entropy detection

The CLI has no options for the entropy threshold or for excluding paths. The current behavior is:

- **Entropy threshold:** fixed at `4.5` bits per character, with a minimum string length of `20`. These values come from `EntropyDetectionSettings` in `src/EntropyDetector.cs`, but `SolutionScanner` does not pass custom settings, so the defaults always apply.
- **File types:** only `.cs`, `.json`, `.config`, `.xml`, `.yml`, `.yaml` and `.env` files are scanned. Other extensions are ignored.
- **File size:** files larger than 1 MB are skipped.
- **Directory exclusions:** `FileWalker` is written to skip `bin`, `obj`, `.git` and `node_modules`, but this does not take effect during directory scans, so those folders are scanned too. To avoid them, scan the source folders directly, for example `dotnet-secrets-scan ./src`.

## Architecture

Class library combining regex rule sets (`BuiltInRules`, `CloudProviderRules`) with entropy-based detection, plus baselining, ignore comments, and console/JSON/SARIF/HTML report writers. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component breakdown, data flow, and known limitations.

## SecretRule

Represents a rule for detecting secrets in code. It defines a pattern to match against and a severity level for the finding.

## SecretFinding

The `SecretFinding` type represents a single detected secret in a source file. It stores the file path, line number, the rule that matched, the secret value, and the severity level. It also provides helper methods for fingerprinting and equality comparison, and can be persisted via the `BaselineFile` helper.

## SecretRuleExtensions

Provides extension methods for `SecretRule` to enable common operations and enhance usability when working with secret detection rules in .NET applications.

Example usage:

## SecretFindingExtensions

Provides extension methods for `SecretFinding` to enable common operations and enhance usability when working with individual secret findings in .NET applications. These extensions allow you to check severity levels, group related findings, filter new secrets, format findings for display, and create modified copies of findings.

Example usage:

```csharp
using DotnetSecretsScan;
using System;
using System.Collections.Generic;

// Assume we have a collection of secret findings from scanning a solution
var findings = new List<SecretFinding>
{
    new SecretFinding
    {
        FilePath = "appsettings.json",
        LineNumber = 42,
        Rule = "AzureStorageAccountKey",
        Secret = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123xyz789==;EndpointSuffix=core.windows.net",
        Severity = "High"
    },
    new SecretFinding
    {
        FilePath = "Program.cs",
        LineNumber = 15,
        Rule = "GitHubPersonalAccessToken",
        Secret = "ghp_abc123def456ghi789jkl012mno345pqr678",
        Severity = "Critical"
    }
};

// Check severity levels
bool hasHighSeverity = findings[0].IsHighSeverity(); // true
bool hasLowSeverity = findings[0].IsLowSeverity(); // false

// Group findings by fingerprint to identify duplicate secrets
var groupedFindings = findings.GroupByFingerprint();

// Filter new findings against a baseline
var baseline = new BaselineFile(); // Assume baseline is loaded
var newFindings = findings.FilterNew(baseline);

// Format findings for display
string displayString = findings[0].ToDisplayString();
// Output: "[High] appsettings.json:42 - AzureStorageAccountKey: ****789=="

// Format findings for machine parsing
string machineString = findings[0].ToMachineString();
// Output: "appsettings.json|42|AzureStorageAccountKey|DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123xyz789==;EndpointSuffix=core.windows.net|High|...fingerprint..."

// Check if finding is in a test file
bool isTestFile = findings[0].IsInTestFile(); // false

// Get file extension
string extension = findings[0].GetFileExtension(); // ".json"

// Create modified copies of findings
var redactedFinding = findings[0].WithRedactedSecret();
var highSeverityFinding = findings[0].WithSeverity("Critical");
var customSecretFinding = findings[0].WithSecret("modified-secret-value");

// Check if finding matches a specific rule
bool matchesAzureRule = findings[0].MatchesRule("AzureStorageAccountKey"); // true
```

## SecretFindingValidationJsonExtensions

The `SecretFindingValidationJsonExtensions` class provides JSON serialization and deserialization extensions for secret finding validation results. It allows you to convert validation problems to and from JSON strings, and also supports serialization and deserialization of boolean validation results. Here's an example of how to use it:

## ScanResult

`ScanResult` aggregates the outcome of a secret scan. It contains the list of `SecretFinding` objects, counts of scanned files and lines, and the timestamp of the scan. The type is intended to be passed to the `ReportWriter` helpers to produce console, JSON, or SARIF output.

```csharp
using DotnetSecretsScan;
using System;
using System.Collections.Generic;

// Assume we have performed a scan and collected findings
var findings = new List<SecretFinding>
{
    new SecretFinding
    {
        FilePath = "appsettings.json",
        LineNumber = 10,
        Rule = "AzureStorageAccountKey",
        Secret = "AccountKey=abc123...",
        Severity = "High"
    }
};

var result = new ScanResult
{
    Findings = findings,
    TotalFilesScanned = 42,
    TotalLinesScanned = 1234,
    ScanTimestamp = DateTimeOffset.UtcNow
};

// Write a colour‑coded console report
ReportWriter.WriteConsole(result, verbose: true);

// Serialize to JSON
string json = ReportWriter.ToJson(result);

// Convert to SARIF for CI integration
string sarif = ReportWriter.ToSarif(result);
```

