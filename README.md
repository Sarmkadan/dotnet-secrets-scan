# dotnet-secrets-scan

Scans a .NET solution for leaked secrets in appsettings, code and connection strings.

## Architecture

Class library combining regex rule sets (`BuiltInRules`, `CloudProviderRules`) with entropy-based detection, plus baselining, ignore comments, and console/JSON/SARIF/HTML report writers. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the component breakdown, data flow, and known limitations.

## SecretRule

Represents a rule for detecting secrets in code. It defines a pattern to match against and a severity level for the finding.

## SecretFinding

The `SecretFinding` type represents a single detected secret in a source file. It stores the file path, line number, the rule that matched, the secret value, and the severity level. It also provides helper methods for fingerprinting and equality comparison, and can be persisted via the `BaselineFile` helper.

## SecretRuleExtensions

Provides extension methods for `SecretRule` to enable common operations and enhance usability when working with secret detection rules in .NET applications.

Example usage:

## SecretFindingValidationJsonExtensions

The `SecretFindingValidationJsonExtensions` class provides JSON serialization and deserialization extensions for secret finding validation results. It allows you to convert validation problems to and from JSON strings, and also supports serialization and deserialization of boolean validation results. Here's an example of how to use it:
