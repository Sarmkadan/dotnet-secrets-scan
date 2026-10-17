namespace DotnetSecretsScan;

/// <summary>
/// A user-supplied, unvalidated rule definition. Fields are raw strings so that every problem can be reported
/// by <see cref="RuleConfigurationValidator"/> instead of failing on the first malformed value.
/// </summary>
/// <param name="Id">Rule identifier (e.g., SS100). Must be unique across all rules.</param>
/// <param name="Name">Human-readable rule name.</param>
/// <param name="Pattern">Regular expression to match. Must compile within the match timeout.</param>
/// <param name="Description">Description of what the rule matches. May be empty.</param>
/// <param name="Severity">Severity name: one of the <see cref="SecretSeverity"/> values, case-insensitive.</param>
public sealed record RuleDefinition(
    string? Id,
    string? Name,
    string? Pattern,
    string? Description,
    string? Severity);
