using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan
{
    /// <summary>
    /// Provides extension methods for <see cref="SecretRule"/> to enable common operations
    /// and enhance usability when working with secret detection rules in .NET applications.
    /// </summary>
    public static class SecretRuleExtensions
    {
        /// <summary>
        /// Determines whether the secret rule represents a high severity issue.
        /// </summary>
        /// <param name="rule">The secret rule to check.</param>
        /// <returns><see langword="true"/> if the severity is <see cref="SecretSeverity.High"/>; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rule"/> is <see langword="null"/>.</exception>
        public static bool IsHighSeverity(this SecretRule rule)
        {
            ArgumentNullException.ThrowIfNull(rule);
            return rule.Severity == SecretSeverity.High;
        }

        /// <summary>
        /// Determines whether the secret rule represents a medium severity issue.
        /// </summary>
        /// <param name="rule">The secret rule to check.</param>
        /// <returns><see langword="true"/> if the severity is <see cref="SecretSeverity.Medium"/>; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rule"/> is <see langword="null"/>.</exception>
        public static bool IsMediumSeverity(this SecretRule rule)
        {
            ArgumentNullException.ThrowIfNull(rule);
            return rule.Severity == SecretSeverity.Medium;
        }

        /// <summary>
        /// Determines whether the secret rule represents a low severity issue.
        /// </summary>
        /// <param name="rule">The secret rule to check.</param>
        /// <returns><see langword="true"/> if the severity is <see cref="SecretSeverity.Low"/>; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rule"/> is <see langword="null"/>.</exception>
        public static bool IsLowSeverity(this SecretRule rule)
        {
            ArgumentNullException.ThrowIfNull(rule);
            return rule.Severity == SecretSeverity.Low;
        }

        /// <summary>
        /// Creates a new <see cref="SecretRule"/> instance with updated severity.
        /// </summary>
        /// <param name="rule">The original rule.</param>
        /// <param name="newSeverity">The new severity level.</param>
        /// <returns>A new <see cref="SecretRule"/> instance with the updated severity.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="rule"/> or <paramref name="newSeverity"/> is <see langword="null"/>.
        /// </exception>
        public static SecretRule WithSeverity(this SecretRule rule, SecretSeverity newSeverity)
        {
            ArgumentNullException.ThrowIfNull(rule);
            ArgumentNullException.ThrowIfNull(newSeverity);

            return new SecretRule(
                id: rule.Id,
                name: rule.Name,
                pattern: rule.Pattern,
                description: rule.Description,
                severity: newSeverity);
        }

        /// <summary>
        /// Determines whether the rule pattern matches a given secret value.
        /// </summary>
        /// <param name="rule">The secret rule with the pattern to match against.</param>
        /// <param name="secret">The secret value to test.</param>
        /// <returns><see langword="true"/> if the secret matches the rule pattern; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="rule"/> or <paramref name="secret"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="secret"/> is empty or whitespace.</exception>
        public static bool MatchesSecret(this SecretRule rule, string secret)
        {
            ArgumentNullException.ThrowIfNull(rule);
            ArgumentException.ThrowIfNullOrWhiteSpace(secret);

            return Regex.IsMatch(secret, rule.Pattern, RegexOptions.CultureInvariant);
        }

        /// <summary>
        /// Gets all built-in secret rules that share the same severity level as this rule.
        /// </summary>
        /// <param name="rule">The secret rule to use as a severity filter.</param>
        /// <returns>An enumerable of all built-in rules with matching severity.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rule"/> is <see langword="null"/>.</exception>
        public static IEnumerable<SecretRule> GetRulesWithSameSeverity(this SecretRule rule)
        {
            ArgumentNullException.ThrowIfNull(rule);

            return BuiltInRules.All.Where(r => r.Severity == rule.Severity);
        }

        /// <summary>
        /// Creates a display-friendly string representation of the secret rule.
        /// Includes rule identifier, name, severity, and a brief description.
        /// </summary>
        /// <param name="rule">The secret rule to format.</param>
        /// <returns>A formatted string representation of the rule.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="rule"/> is <see langword="null"/>.</exception>
        public static string ToDisplayString(this SecretRule rule)
        {
            ArgumentNullException.ThrowIfNull(rule);

            return $"[{rule.Severity}] {rule.Id} - {rule.Name}: {rule.Description}";
        }
    }
}
