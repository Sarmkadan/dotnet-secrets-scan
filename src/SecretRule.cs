using System;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan;

/// <summary>
/// Represents the severity level of a detected secret.
/// </summary>
public enum SecretSeverity
{
    /// <summary>
    /// Low severity - informational only.
    /// </summary>
    Low,

    /// <summary>
    /// Medium severity - potential issue.
    /// </summary>
    Medium,

    /// <summary>
    /// High severity - confirmed secret that should be rotated.
    /// </summary>
    High
}

/// <summary>
/// Represents an immutable secret detection rule.
/// </summary>
/// <remarks>
/// Rules are immutable and compiled with a 2-second timeout to prevent ReDoS attacks.
/// </remarks>
public sealed record SecretRule
{
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Gets the rule identifier (e.g., SS001).
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets the human-readable name of the rule.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the regex pattern used to match secrets.
    /// </summary>
    public string Pattern { get; }

    /// <summary>
    /// Gets the compiled regular expression used to match secrets.
    /// </summary>
    public Regex Regex { get; }

    /// <summary>
    /// Gets the description of what this rule matches.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Gets the severity level of matches.
    /// </summary>
    public SecretSeverity Severity { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecretRule"/> class.
    /// </summary>
    /// <param name="id">The unique rule identifier (e.g., SS001).</param>
    /// <param name="name">The human-readable name of the rule.</param>
    /// <param name="pattern">The regular expression pattern to match secrets.</param>
    /// <param name="description">A human-readable description of the pattern.</param>
    /// <param name="severity">The severity level assigned to matches.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="description"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/>, <paramref name="name"/>, or <paramref name="pattern"/> is whitespace, or <paramref name="pattern"/> is not a valid regular expression, or <paramref name="severity"/> is not a defined <see cref="SecretSeverity"/> value.</exception>
    public SecretRule(string id, string name, string pattern, string description, SecretSeverity severity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        ArgumentNullException.ThrowIfNull(description);

        if (!Enum.IsDefined(typeof(SecretSeverity), severity))
        {
            throw new ArgumentException($"Severity '{severity}' is not a defined {nameof(SecretSeverity)} value.", nameof(severity));
        }

        try
        {
            Regex = new Regex(pattern, RegexOptions.Compiled, MatchTimeout);
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException($"Pattern is not a valid regular expression: {ex.Message}", nameof(pattern), ex);
        }

        Id = id;
        Name = name;
        Pattern = pattern;
        Description = description;
        Severity = severity;
    }
}
