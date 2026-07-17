using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace DotnetSecretsScan
{
    /// <summary>
    /// Provides validation helpers for <see cref="SecretRule"/>.
    /// </summary>
    public static class SecretRuleValidation
    {
        /// <summary>
        /// Validates the supplied <see cref="SecretRule"/> and returns a list of human‑readable problems.
        /// </summary>
        /// <param name="value">The rule to validate.</param>
        /// <returns>An <see cref="IReadOnlyList{T}"/> of validation error messages. The list is empty when the rule is valid.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        public static IReadOnlyList<string> Validate(this SecretRule value)
        {
            ArgumentNullException.ThrowIfNull(value);

            var problems = new List<string>();

            // Id must be non‑null, non‑empty, non‑whitespace.
            if (string.IsNullOrWhiteSpace(value.Id))
            {
                problems.Add("Id must be a non‑empty string.");
            }

            // Name must be non‑null, non‑empty, non‑whitespace.
            if (string.IsNullOrWhiteSpace(value.Name))
            {
                problems.Add("Name must be a non‑empty string.");
            }

            // Pattern must be a valid regular expression.
            if (string.IsNullOrWhiteSpace(value.Pattern))
            {
                problems.Add("Pattern must be a non‑empty string.");
            }
            else
            {
                try
                {
                    // Attempt to compile the regex; use InvariantCulture for any culture‑specific options.
                    _ = new Regex(value.Pattern, RegexOptions.Compiled, TimeSpan.FromSeconds(1));
                }
                catch (ArgumentException ex)
                {
                    problems.Add($"Pattern is not a valid regular expression: {ex.Message}");
                }
            }

            // Description is optional but must not be null.
            if (value.Description is null)
            {
                problems.Add("Description must not be null (empty string is allowed).");
            }

            // Severity must be a defined enum value.
            if (!Enum.IsDefined(typeof(SecretSeverity), value.Severity))
            {
                problems.Add($"Severity '{value.Severity}' is not a defined {nameof(SecretSeverity)} value.");
            }

            return problems.AsReadOnly();
        }

        /// <summary>
        /// Determines whether the supplied <see cref="SecretRule"/> is valid.
        /// </summary>
        /// <param name="value">The rule to test.</param>
        /// <returns><c>true</c> if the rule has no validation problems; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        public static bool IsValid(this SecretRule value)
        {
            ArgumentNullException.ThrowIfNull(value);
            return value.Validate().Count == 0;
        }

        /// <summary>
        /// Ensures that the supplied <see cref="SecretRule"/> is valid.
        /// </summary>
        /// <param name="value">The rule to validate.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the rule contains one or more validation problems. The exception message lists all problems.</exception>
        public static void EnsureValid(this SecretRule value)
        {
            ArgumentNullException.ThrowIfNull(value);

            var problems = value.Validate();
            if (problems.Count > 0)
            {
                throw new ArgumentException(string.Join("; ", problems), nameof(value));
            }
        }
    }
}
