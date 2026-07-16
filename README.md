# dotnet-secrets-scan

Scans a .NET solution for leaked secrets in appsettings, code and connection strings.

## Architecture

Class library combining regex rule sets (`BuiltInRules`, `CloudProviderRules`) with entropy-based detection, plus baselining, ignore comments, and console/JSON/SARIF/HTML report writers. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component breakdown, data flow, and known limitations.

## SecretRule

Represents a rule for detecting secrets in code. It defines a pattern to match against and a severity level for the finding.

## SecretFinding

The `SecretFinding` type represents a single detected secret in a source file. It stores the file path, line number, the rule that matched, the secret value, and the severity level. It also provides helper methods for fingerprinting and equality comparison, and can be persisted via the `BaselineFile` helper.

Example usage:

