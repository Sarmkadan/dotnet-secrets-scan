using System;
using System.Collections.Generic;
using System.Linq;

namespace DotnetSecretsScan
{
    /// <summary>
    /// Provides extension methods for <see cref="SecretFinding"/> to enable common operations
    /// and enhance usability when working with secret findings in .NET applications.
    /// </summary>
    public static class SecretFindingExtensions
    {
        /// <summary>
        /// Determines whether the secret finding represents a high severity issue.
        /// </summary>
        /// <param name="finding">The secret finding to check.</param>
        /// <returns><see langword="true"/> if the severity is "High" or "Critical"; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static bool IsHighSeverity(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            return string.Equals(finding.Severity, "High", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(finding.Severity, "Critical", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether the secret finding represents a low severity issue.
        /// </summary>
        /// <param name="finding">The secret finding to check.</param>
        /// <returns><see langword="true"/> if the severity is "Low" or "Info"; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static bool IsLowSeverity(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            return string.Equals(finding.Severity, "Low", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(finding.Severity, "Info", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Groups secret findings by their computed fingerprint, which uniquely identifies
        /// secrets that are effectively the same across different locations.
        /// </summary>
        /// <param name="findings">The collection of secret findings to group.</param>
        /// <returns>A dictionary mapping fingerprints to collections of findings with that fingerprint.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="findings"/> is <see langword="null"/>.</exception>
        public static IReadOnlyDictionary<string, IReadOnlyList<SecretFinding>> GroupByFingerprint(
            this IEnumerable<SecretFinding> findings)
        {
            ArgumentNullException.ThrowIfNull(findings);

            return findings
                .Where(f => f is not null)
                .GroupBy(f => f.ComputeFingerprint())
                .ToDictionary(
                    g => g.Key,
                    g => (IReadOnlyList<SecretFinding>)g.ToList().AsReadOnly(),
                    StringComparer.Ordinal)
                .AsReadOnly();
        }

        /// <summary>
        /// Filters the collection to include only findings that are new (not previously seen).
        /// </summary>
        /// <param name="findings">The collection of secret findings to filter.</param>
        /// <param name="baseline">The baseline file containing previously seen findings.</param>
        /// <returns>A new collection containing only findings that are not in the baseline.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="findings"/> or <paramref name="baseline"/> is <see langword="null"/>.
        /// </exception>
        public static IReadOnlyList<SecretFinding> FilterNew(
            this IEnumerable<SecretFinding> findings,
            BaselineFile baseline)
        {
            ArgumentNullException.ThrowIfNull(findings);
            ArgumentNullException.ThrowIfNull(baseline);

            var result = new List<SecretFinding>();

            foreach (var finding in findings)
            {
                if (finding is not null && !baseline.Contains(finding))
                {
                    result.Add(finding);
                }
            }

            return result.AsReadOnly();
        }

        /// <summary>
        /// Formats the secret finding as a human-readable string for display purposes.
        /// Includes file path, line number, rule, severity, and a redacted secret.
        /// </summary>
        /// <param name="finding">The secret finding to format.</param>
        /// <returns>A formatted string representation of the finding.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static string ToDisplayString(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            var secret = RedactSecret(finding.Secret);
            return $"[{finding.Severity}] {finding.FilePath}:{finding.LineNumber} - {finding.Rule}: {secret}";
        }

        /// <summary>
        /// Formats the secret finding as a machine-readable string for logging or serialization.
        /// Includes all properties separated by pipes for easy parsing.
        /// </summary>
        /// <param name="finding">The secret finding to format.</param>
        /// <returns>A pipe-separated string representation of the finding.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static string ToMachineString(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            return $"{finding.FilePath}|{finding.LineNumber}|{finding.Rule}|{finding.Secret}|{finding.Severity}|{finding.ComputeFingerprint()}";
        }

        /// <summary>
        /// Determines whether the secret finding is located in a test file.
        /// </summary>
        /// <param name="finding">The secret finding to check.</param>
        /// <returns><see langword="true"/> if the file path indicates a test file; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static bool IsInTestFile(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            var fileName = System.IO.Path.GetFileName(finding.FilePath);
            return fileName.StartsWith("test", StringComparison.OrdinalIgnoreCase) ||
                   fileName.StartsWith("tests", StringComparison.OrdinalIgnoreCase) ||
                   fileName.EndsWith(".Tests.cs", StringComparison.Ordinal) ||
                   fileName.EndsWith("Test.cs", StringComparison.Ordinal) ||
                   finding.FilePath.Contains("/test/", StringComparison.Ordinal) ||
                   finding.FilePath.Contains("\\test\\", StringComparison.Ordinal);
        }

        /// <summary>
        /// Gets the file extension of the finding's file path.
        /// </summary>
        /// <param name="finding">The secret finding.</param>
        /// <returns>The file extension including the dot, or an empty string if none.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static string GetFileExtension(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            return System.IO.Path.GetExtension(finding.FilePath);
        }

        /// <summary>
        /// Creates a new <see cref="SecretFinding"/> with updated severity.
        /// </summary>
        /// <param name="finding">The original finding.</param>
        /// <param name="newSeverity">The new severity level.</param>
        /// <returns>A new <see cref="SecretFinding"/> instance with the updated severity.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="finding"/> or <paramref name="newSeverity"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="newSeverity"/> is empty or whitespace.</exception>
        public static SecretFinding WithSeverity(
            this SecretFinding finding,
            string newSeverity)
        {
            ArgumentNullException.ThrowIfNull(finding);
            ArgumentException.ThrowIfNullOrWhiteSpace(newSeverity);

            return new SecretFinding
            {
                FilePath = finding.FilePath,
                LineNumber = finding.LineNumber,
                Rule = finding.Rule,
                Secret = finding.Secret,
                Severity = newSeverity.Trim(),
            };
        }

        /// <summary>
        /// Creates a new <see cref="SecretFinding"/> with the secret redacted.
        /// </summary>
        /// <param name="finding">The original finding.</param>
        /// <returns>A new <see cref="SecretFinding"/> instance with the secret redacted.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
        public static SecretFinding WithRedactedSecret(this SecretFinding finding)
        {
            ArgumentNullException.ThrowIfNull(finding);

            return finding.WithSecret(RedactSecret(finding.Secret));
        }

        /// <summary>
        /// Creates a new <see cref="SecretFinding"/> with a modified secret value.
        /// </summary>
        /// <param name="finding">The original finding.</param>
        /// <param name="newSecret">The new secret value.</param>
        /// <returns>A new <see cref="SecretFinding"/> instance with the updated secret.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="finding"/> or <paramref name="newSecret"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="newSecret"/> is empty or whitespace.</exception>
        public static SecretFinding WithSecret(
            this SecretFinding finding,
            string newSecret)
        {
            ArgumentNullException.ThrowIfNull(finding);
            ArgumentException.ThrowIfNullOrWhiteSpace(newSecret);

            return new SecretFinding
            {
                FilePath = finding.FilePath,
                LineNumber = finding.LineNumber,
                Rule = finding.Rule,
                Secret = newSecret.Trim(),
                Severity = finding.Severity,
            };
        }

        /// <summary>
        /// Determines whether the finding matches a specific rule by name.
        /// </summary>
        /// <param name="finding">The secret finding.</param>
        /// <param name="ruleName">The rule name to match (case-insensitive).</param>
        /// <returns><see langword="true"/> if the rule names match; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="finding"/> or <paramref name="ruleName"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="ruleName"/> is empty or whitespace.</exception>
        public static bool MatchesRule(
            this SecretFinding finding,
            string ruleName)
        {
            ArgumentNullException.ThrowIfNull(finding);
            ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);

            return string.Equals(
                finding.Rule,
                ruleName.Trim(),
                StringComparison.OrdinalIgnoreCase);
        }

        private static string RedactSecret(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                return string.Empty;
            }

            if (secret.Length <= 4)
            {
                return "****";
            }

            return $"****{secret.Substring(secret.Length - 4)}";
        }
    }
}