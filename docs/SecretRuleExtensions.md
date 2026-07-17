# SecretRuleExtensions

The `SecretRuleExtensions` class provides a set of static extension methods and utility functions designed to simplify the manipulation, evaluation, and formatting of `SecretRule` instances within the `dotnet-secrets-scan` library. It enables developers to filter rules by severity levels, validate secrets against specific rules, transform rule severities, and generate human-readable representations without modifying the underlying `SecretRule` data structure directly.

## API

### `IsHighSeverity`
Determines whether a specific `SecretRule` is classified as having high severity.
*   **Parameters**: `this SecretRule rule` – The rule instance to evaluate.
*   **Returns**: `bool` – `true` if the rule's severity is High; otherwise, `false`.
*   **Throws**: `ArgumentNullException` if `rule` is `null`.

### `IsMediumSeverity`
Determines whether a specific `SecretRule` is classified as having medium severity.
*   **Parameters**: `this SecretRule rule` – The rule instance to evaluate.
*   **Returns**: `bool` – `true` if the rule's severity is Medium; otherwise, `false`.
*   **Throws**: `ArgumentNullException` if `rule` is `null`.

### `IsLowSeverity`
Determines whether a specific `SecretRule` is classified as having low severity.
*   **Parameters**: `this SecretRule rule` – The rule instance to evaluate.
*   **Returns**: `bool` – `true` if the rule's severity is Low; otherwise, `false`.
*   **Throws**: `ArgumentNullException` if `rule` is `null`.

### `WithSeverity`
Creates a new `SecretRule` instance based on the current rule but with an updated severity level. This method supports immutability patterns by returning a modified copy rather than altering the original instance.
*   **Parameters**:
    *   `this SecretRule rule` – The source rule instance.
    *   `SecretSeverity severity` – The new severity level to apply.
*   **Returns**: `SecretRule` – A new rule instance with the specified severity.
*   **Throws**: `ArgumentNullException` if `rule` is `null`.

### `MatchesSecret`
Evaluates whether a given string content matches the pattern or criteria defined within the `SecretRule`.
*   **Parameters**:
    *   `this SecretRule rule` – The rule containing the matching logic.
    *   `string content` – The string value to test against the rule.
*   **Returns**: `bool` – `true` if the content matches the rule; otherwise, `false`.
*   **Throws**: `ArgumentNullException` if `rule` or `content` is `null`.

### `GetRulesWithSameSeverity`
Filters a collection of `SecretRule` objects, returning only those that share the same severity level as the source rule.
*   **Parameters**:
    *   `this SecretRule rule` – The reference rule used to determine the target severity.
    *   `IEnumerable<SecretRule> rules` – The collection of rules to filter.
*   **Returns**: `IEnumerable<SecretRule>` – A subset of rules matching the source rule's severity.
*   **Throws**: `ArgumentNullException` if `rule` or `rules` is `null`.

### `ToDisplayString`
Generates a formatted string representation of the `SecretRule`, suitable for logging, console output, or UI display.
*   **Parameters**: `this SecretRule rule` – The rule instance to format.
*   **Returns**: `string` – A human-readable description of the rule.
*   **Throws**: `ArgumentNullException` if `rule` is `null`.

## Usage

### Filtering and Grouping Rules by Severity
The following example demonstrates how to retrieve all rules from a configuration that match the severity of a specific high-priority rule, utilizing the filtering and severity check extensions.

```csharp
using DotNetSecretsScan;
using System.Linq;
using System.Collections.Generic;

public class SeverityFilterExample
{
    public void ProcessRules(IEnumerable<SecretRule> allRules)
    {
        // Assume we have a specific rule we are interested in
        var criticalRule = allRules.FirstOrDefault(r => r.Id == "AWS_ACCESS_KEY");

        if (criticalRule != null && criticalRule.IsHighSeverity())
        {
            // Get all other rules that are also High Severity
            var highSeverityRules = criticalRule.GetRulesWithSameSeverity(allRules);

            foreach (var rule in highSeverityRules)
            {
                System.Console.WriteLine($"Processing critical rule: {rule.ToDisplayString()}");
            }
        }
    }
}
```

### Validating Content and Adjusting Severity
This example shows how to test a string against a rule and dynamically create a modified version of that rule with a different severity level if specific conditions are met.

```csharp
using DotNetSecretsScan;

public class ValidationExample
{
    public void ValidateAndAdjust(SecretRule rule, string potentialSecret)
    {
        if (rule.MatchesSecret(potentialSecret))
        {
            System.Console.WriteLine($"Secret detected: {rule.ToDisplayString()}");

            // If the rule is currently Low severity but we found a match in a sensitive file,
            // we can create a temporary instance with higher severity for reporting.
            if (rule.IsLowSeverity())
            {
                var escalatedRule = rule.WithSeverity(SecretSeverity.High);
                ReportFinding(escalatedRule);
            }
            else
            {
                ReportFinding(rule);
            }
        }
    }

    private void ReportFinding(SecretRule rule)
    {
        // Implementation of reporting logic
    }
}
```

## Notes

*   **Immutability**: The `WithSeverity` method does not modify the existing `SecretRule` instance. It returns a new instance. Callers must capture the return value to utilize the updated severity.
*   **Null Safety**: All extension methods in this class perform null checks on the `this` parameter (the source `SecretRule`). Methods accepting additional reference types (such as `MatchesSecret` with `content` or `GetRulesWithSameSeverity` with `rules`) also validate these arguments. `ArgumentNullException` will be thrown immediately upon detecting a `null` input.
*   **Thread Safety**: As this class consists entirely of stateless static methods operating on immutable data patterns or passed-in parameters, it is inherently thread-safe. Multiple threads can safely call these extensions concurrently against the same or different `SecretRule` instances.
*   **Severity Logic**: The `IsHighSeverity`, `IsMediumSeverity`, and `IsLowSeverity` methods are mutually exclusive assuming a standard `SecretSeverity` enum implementation. A rule cannot return `true` for more than one of these checks simultaneously.
*   **Enumeration**: `GetRulesWithSameSeverity` uses deferred execution. The filtering logic runs when the resulting `IEnumerable<SecretRule>` is enumerated, not when the method is called. Ensure the source collection is not modified during enumeration.
