# SecretRule
The `SecretRule` type represents a rule for identifying secrets in a given context. It encapsulates the characteristics of a secret, such as its identifier, name, pattern, and severity, allowing for the creation of custom rules to detect sensitive information.

## API
All properties are get-only; a rule is fully initialized through its constructor and is immutable afterwards.

* `public string Id { get; }`: A unique identifier for the secret rule (e.g. `SS001`).
* `public string Name { get; }`: The human-readable name of the rule.
* `public string Pattern { get; }`: The regex pattern used to identify the secret.
* `public string Description { get; }`: A description of what the rule matches.
* `public SecretSeverity Severity { get; }`: The severity level (`Low`, `Medium`, `High`).
* `public SecretRule(string id, string name, string pattern, string description, SecretSeverity severity)`: The only constructor; there is no parameterless constructor and no object-initializer support.

## Usage
The following examples demonstrate how to create and use `SecretRule` instances:
```csharp
// Example 1: Creating a new SecretRule instance
var rule = new SecretRule(
    id: "SR-001",
    name: "API Key",
    pattern: "api_key_.*",
    description: "Identifies API keys",
    severity: SecretSeverity.High);

// Example 2: Combining custom rules with the built-in sets
var rules = new List<SecretRule>(BuiltInRules.All)
{
    new SecretRule("SR-002", "Database Connection String", "Data Source=.*",
        "Detects connection strings", SecretSeverity.High),
};
var scanner = new SolutionScanner(rules);
var result = scanner.Scan("/path/to/solution");
```

## Notes
When working with `SecretRule` instances, consider the following:
* The `Id` property should be unique across all rules to avoid conflicts.
* The `Pattern` property uses a regular expression to match secrets, so ensure that the pattern is correctly formatted to avoid errors.
* The `Severity` property determines the severity level of the secret, which can impact how it is handled in a secrets scanning context.
* `SecretRule` instances are immutable (get-only properties), so they are safe to share across threads. Use `SecretRuleExtensions.WithSeverity` to derive a modified copy.
