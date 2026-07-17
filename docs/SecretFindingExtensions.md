# SecretFindingExtensions
The `SecretFindingExtensions` class provides a set of extension methods for working with `SecretFinding` objects, allowing for easier filtering, grouping, and manipulation of secret findings in a .NET application. These methods can be used to simplify the process of handling and processing secret findings, making it easier to integrate secret scanning into an application.

## API
The following members are available on the `SecretFindingExtensions` class:
* `IsHighSeverity`: Returns a boolean indicating whether the severity of the secret finding is high.
* `IsLowSeverity`: Returns a boolean indicating whether the severity of the secret finding is low.
* `GroupByFingerprint`: Returns a dictionary where the keys are the fingerprints of the secret findings and the values are lists of secret findings with the same fingerprint.
* `FilterNew`: Returns a list of secret findings that are considered new.
* `ToDisplayString`: Returns a string representation of the secret finding, suitable for display to the user.
* `ToMachineString`: Returns a string representation of the secret finding, suitable for machine processing.
* `IsInTestFile`: Returns a boolean indicating whether the secret finding is located in a test file.
* `GetFileExtension`: Returns the file extension of the file where the secret finding is located.
* `WithSeverity`: Returns a new `SecretFinding` object with the specified severity.
* `WithRedactedSecret`: Returns a new `SecretFinding` object with the secret redacted.
* `WithSecret`: Returns a new `SecretFinding` object with the specified secret.
* `MatchesRule`: Returns a boolean indicating whether the secret finding matches the specified rule.

## Usage
Here are some examples of how to use the `SecretFindingExtensions` class:
```csharp
// Example 1: Filtering secret findings by severity
var secretFindings = new List<SecretFinding> { /* initialize with secret findings */ };
var highSeverityFindings = secretFindings.Where(f => f.IsHighSeverity()).ToList();

// Example 2: Grouping secret findings by fingerprint
var groupedFindings = secretFindings.GroupByFingerprint();
foreach (var group in groupedFindings)
{
    Console.WriteLine($"Fingerprint: {group.Key}");
    foreach (var finding in group.Value)
    {
        Console.WriteLine($"  {finding.ToDisplayString()}");
    }
}
```

## Notes
When using the `SecretFindingExtensions` class, note that the `GroupByFingerprint` method returns a dictionary where the keys are the fingerprints of the secret findings and the values are lists of secret findings with the same fingerprint. This can be useful for identifying duplicate secret findings.

Additionally, the `WithSeverity`, `WithRedactedSecret`, and `WithSecret` methods return new `SecretFinding` objects, they do not modify the original object. This is to ensure thread-safety and to avoid unintended side effects.

It's also worth noting that the `MatchesRule` method will throw an exception if the rule is null, and the `GetFileExtension` method will return an empty string if the file path is null or empty. The `IsInTestFile` method will return false if the file path is null or empty.
