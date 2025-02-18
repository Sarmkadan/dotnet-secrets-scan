namespace DotnetSecretsScan;

/// <summary>
/// Provides validation helpers for <see cref="SecretFinding"/> instances.
/// </summary>
public static class SecretFindingValidation
{
    /// <summary>
    /// Validates a secret finding and returns a list of human-readable problems.
    /// </summary>
    /// <param name="value">The secret finding to validate.</param>
    /// <returns>A list of validation problems; empty if valid.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<string> Validate(this SecretFinding? value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var problems = new List<string>();

        // Validate FilePath
        if (string.IsNullOrWhiteSpace(value.FilePath))
        {
            problems.Add("FilePath is null or empty");
        }

        // Validate LineNumber
        if (value.LineNumber < 1)
        {
            problems.Add("LineNumber must be at least 1");
        }

        // Validate Rule
        if (string.IsNullOrWhiteSpace(value.Rule))
        {
            problems.Add("Rule is null or empty");
        }

        // Validate Secret
        if (string.IsNullOrWhiteSpace(value.Secret))
        {
            problems.Add("Secret is null or empty");
        }

        // Validate Severity
        if (string.IsNullOrWhiteSpace(value.Severity))
        {
            problems.Add("Severity is null or empty");
        }

        return problems.AsReadOnly();
    }

    /// <summary>
    /// Determines whether a secret finding is valid.
    /// </summary>
    /// <param name="value">The secret finding to check.</param>
    /// <returns>True if the finding is valid; otherwise, false.</returns>
    public static bool IsValid(this SecretFinding? value) => value?.Validate().Count == 0;

    /// <summary>
    /// Ensures that a secret finding is valid, throwing an exception if it is not.
    /// </summary>
    /// <param name="value">The secret finding to validate.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when the finding is invalid.</exception>
    public static void EnsureValid(this SecretFinding? value)
    {
        var problems = value.Validate();

        if (problems.Count > 0)
        {
            throw new ArgumentException(
                $"SecretFinding is invalid:{Environment.NewLine}{string.Join(Environment.NewLine, problems)}");
        }
    }
}
