# SecretRule
The `SecretRule` type represents a rule for identifying secrets in a given context. It encapsulates the characteristics of a secret, such as its identifier, name, pattern, and severity, allowing for the creation of custom rules to detect sensitive information.

## API
* `public string Id`: A unique identifier for the secret rule.
* `public string Name`: The name of the secret rule.
* `public string Pattern`: The pattern used to identify the secret.
* `public string Description`: A description of the secret rule.
* `public SecretSeverity Severity`: The severity level of the secret.
* `public SecretRule()`: The default constructor for creating a new instance of the `SecretRule` type.

## Usage
The following examples demonstrate how to create and use `SecretRule` instances:
```csharp
// Example 1: Creating a new SecretRule instance
var rule = new SecretRule
{
    Id = "SR-001",
    Name = "API Key",
    Pattern = "api_key_.*",
    Description = "Identifies API keys",
    Severity = SecretSeverity.High
};

// Example 2: Using SecretRule instances in a secrets scanning context
var rules = new List<SecretRule>
{
    new SecretRule { Id = "SR-002", Name = "Database Connection String", Pattern = "Data Source=.*" },
    new SecretRule { Id = "SR-003", Name = "Encryption Key", Pattern = "encryption_key_.*" }
};
foreach (var rule in rules)
{
    // Use the rule to scan for secrets
}
```

## Notes
When working with `SecretRule` instances, consider the following:
* The `Id` property should be unique across all rules to avoid conflicts.
* The `Pattern` property uses a regular expression to match secrets, so ensure that the pattern is correctly formatted to avoid errors.
* The `Severity` property determines the severity level of the secret, which can impact how it is handled in a secrets scanning context.
* `SecretRule` instances are not thread-safe by default, so synchronization mechanisms should be employed when accessing or modifying instances from multiple threads.
